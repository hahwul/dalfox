//! Background scan execution: spawning isolated runtimes, running the scan
//! pipeline, recording terminal state, and firing completion webhooks. Also
//! hosts `hydrate_preflight_target`, shared with the preflight handler.

use super::*;
use crate::job::spec::ScanRequestSpec;

/// Spawn `run_scan_job` on the blocking pool with full panic / runtime-build
/// isolation. Without this wrapper, a panic inside the spawned task — or a
/// failure to build the inner current-thread runtime — silently drops the
/// `JoinHandle` and leaves the job pinned in `Queued`/`Running` forever.
/// `purge_expired_jobs` only collects terminal jobs, so the orphan also
/// leaks the job slot indefinitely.
///
/// `lease` is the job's liveness handle: it is moved into the spawned task and
/// dropped when the task ends (including on panic), which is what tells job
/// retention this entry is finally safe to evict. Without it, cancelling a scan
/// — which stamps the terminal state immediately while the worker drains —
/// makes the job look collectable, and an eviction in that window drops the
/// partial results and the terminal webhook on the floor.
pub(crate) fn spawn_scan_task(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
    lease: WorkerLease,
) {
    tokio::task::spawn_blocking(move || {
        // Held for the whole task; dropping it releases the job to retention.
        let _lease = lease;
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("scan runtime build failed: {}", e);
                log(&state, "ERR", &format!("{} for job {}", msg, job_id));
                fail_job_via_fresh_runtime(&state, &job_id, &url, msg);
                return;
            }
        };

        let state_for_recovery = state.clone();
        let job_id_for_recovery = job_id.clone();
        let url_for_recovery = url.clone();

        let rt_ref = &rt;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            rt_ref.block_on(run_scan_job(
                state,
                job_id,
                url,
                opts,
                include_request,
                include_response,
            ));
        }));

        if let Err(panic) = result {
            let msg = format!("scan task panicked: {}", crate::job::panic_message(panic));
            log(
                &state_for_recovery,
                "ERR",
                &format!("{} (job_id={})", msg, job_id_for_recovery),
            );
            // The scan runtime itself is still valid after a panic inside the
            // future, so reuse it for the recovery write rather than spinning
            // up a second runtime just to update one map entry.
            rt.block_on(async {
                mark_job_error(
                    &state_for_recovery,
                    &job_id_for_recovery,
                    &url_for_recovery,
                    msg,
                    // Panic recovery: no scan target was built, so fall back to
                    // the default client for the terminal webhook.
                    None,
                )
                .await;
            });
        }
    });
}

/// Best-effort recovery path used when the scan runtime could not be built at
/// all. Builds a tiny one-shot runtime just to update the job map and fire
/// the terminal webhook; if even that fails, the job is unrecoverable from
/// this thread.
fn fail_job_via_fresh_runtime(state: &AppState, job_id: &str, url: &str, msg: String) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        log(
            state,
            "ERR",
            &format!(
                "could not build recovery runtime to fail job {}; marking it error \
                 synchronously to reclaim its slot",
                job_id
            ),
        );
        // Even the recovery runtime failed (typically FD/thread exhaustion).
        // We can't fire the terminal webhook without a runtime, but we MUST
        // still move the job out of Queued — otherwise purge_expired_jobs never
        // collects it (it only reaps terminal jobs) and it counts against
        // max_concurrent_scans permanently until a manual DELETE or restart.
        // `state.jobs` is a tokio Mutex, but this runs on a spawn_blocking
        // thread with no runtime entered, so `blocking_lock` is safe here.
        if let Some(job) = state.jobs.blocking_lock().get_mut(job_id) {
            job.fail(msg);
        }
        return;
    };
    let state = state.clone();
    let job_id = job_id.to_string();
    let url = url.to_string();
    rt.block_on(async move {
        mark_job_error(&state, &job_id, &url, msg, None).await;
    });
}

/// Transition a non-terminal job into `Error` and fire the terminal webhook
/// if the job had a callback_url. Safe to call even after the job has
/// reached a terminal state (the update is gated on `!is_terminal()`), so
/// panic / cancel races don't clobber a real outcome — and because we only
/// fire the webhook when the transition actually happened, subscribers
/// don't receive duplicate notifications.
///
/// The webhook is dispatched after the jobs lock is released so a slow
/// callback URL can't block concurrent job updates. `client` lets a caller
/// that already built the scan's target hand in a proxy/TLS/redirect-aware
/// reqwest client so the webhook honors the same network boundary as the scan
/// (see the unreachable path in `run_scan_job`); the panic / parse-error paths
/// have no usable target and pass `None`, falling back to a default client.
/// Either way this mirrors the contract that every terminal state fires the
/// webhook (see commit aeb8cdb).
pub(crate) async fn mark_job_error(
    state: &AppState,
    job_id: &str,
    url: &str,
    msg: String,
    client: Option<reqwest::Client>,
) {
    let reason = msg.clone();
    let transitioned = (state.jobs.lock().await.get_mut(job_id))
        .and_then(|job| job.fail(msg).then(|| job.callback_url.clone()));
    if let Some(callback_url) = transitioned {
        send_terminal_webhook(
            state,
            callback_url,
            job_id,
            url,
            TerminalOutcome {
                status_label: "error",
                results: &[],
                error_message: Some(&reason),
            },
            client,
        )
        .await;
    }
}

/// Decision made by the run_scan_job preamble after looking up the job.
/// Capturing it in a value type lets us release the jobs lock before any
/// awaits — important because the pre-cancelled path needs to fire a
/// webhook and we don't want to hold the lock across that network call.
enum StartDecision {
    Run {
        progress: JobProgress,
        cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    },
    /// Job was cancelled (or its cancel flag set) before the scan task got
    /// a chance to start. Caller must still fire the webhook so subscribers
    /// see a terminal callback for this scan_id.
    PreCancelled { callback_url: Option<String> },
    /// Job was deleted from the map between submission and dispatch.
    Missing,
}

pub(crate) async fn run_scan_job(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    // Grab progress counters and cancellation flag
    let decision = {
        let mut jobs = state.jobs.lock().await;
        match jobs.get_mut(&job_id) {
            Some(job) => match job.start() {
                Some((progress, cancel_flag)) => StartDecision::Run {
                    progress,
                    cancel_flag,
                },
                None => StartDecision::PreCancelled {
                    callback_url: job.callback_url.clone(),
                },
            },
            None => StartDecision::Missing,
        }
    };

    let (progress, cancel_flag) = match decision {
        StartDecision::Run {
            progress,
            cancel_flag,
        } => (progress, cancel_flag),
        StartDecision::PreCancelled { callback_url } => {
            // Previously this branch returned silently, so any subscriber
            // wired to the webhook never received a terminal callback for
            // scans that were cancelled before the task got a chance to
            // run. Mirror the mid-flight cancellation contract here so the
            // webhook fires for every terminal state, not just some.
            log(
                &state,
                "JOB",
                &format!("cancelled-pre-start id={} url={}", job_id, url),
            );
            // Honor opts.proxy / follow_redirects / TLS settings on this
            // path the same way the mid-flight cancel path does — otherwise
            // a webhook behind a corporate proxy would silently fail only
            // for "cancel-before-start" scans. Fall back to the default
            // client when parse_target can't make sense of the URL (the
            // user-submitted url may be invalid; we still want the
            // webhook to fire so subscribers see the terminal callback).
            let timeout_secs = opts
                .timeout
                .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS);
            let cb_client = hydrate_preflight_target(&url, &opts, timeout_secs)
                .ok()
                .map(|t| t.build_client_or_default());
            send_terminal_webhook(
                &state,
                callback_url,
                &job_id,
                &url,
                TerminalOutcome {
                    status_label: "cancelled",
                    results: &[],
                    error_message: None,
                },
                cb_client,
            )
            .await;
            return;
        }
        StartDecision::Missing => return,
    };

    // Built once behind an `Arc` so the scan future and `run_scanning` share it
    // by refcount bump instead of deep-cloning this ~70-field struct (mirrors
    // the MCP path, which already uses `Arc<ScanArgs>`).
    //
    // The mapping from request to `ScanArgs` lives in `job::spec` so this path
    // and MCP's cannot drift; only the two server-wide ceilings and the WAF
    // name normalization are applied here, because they need `state`.
    let args = Arc::new(
        ScanRequestSpec::from_rest_options(
            url.clone(),
            &opts,
            include_request,
            include_response,
            // Capped by the server-wide `--scan-timeout` when set. Enforced
            // below by wrapping the scan future.
            effective_scan_timeout(opts.scan_timeout, state.scan_timeout),
            // Capped by the server-wide `--rate-limit` when set.
            effective_rate_limit(opts.rate_limit, state.rate_limit),
            // Normalize to the canonical (lowercased) WAF name like the CLI/MCP
            // do; `validate_scan_options` already rejected unknown names before
            // queuing, so the fallback is defensive only.
            opts.force_waf.as_deref().map(|s| {
                crate::cmd::scan::parse_force_waf_arg(s).unwrap_or_else(|_| s.to_string())
            }),
        )
        .into_scan_args(),
    );

    let mut target = match crate::job::runner::hydrate_target(&url, &args) {
        Ok(t) => t,
        Err(msg) => {
            // Webhook subscribers expect a terminal callback for every scan;
            // before, this branch transitioned the job to Error but never
            // fired the webhook, so a malformed URL silently left the
            // subscriber waiting indefinitely. mark_job_error now handles
            // both the status update and the webhook dispatch.
            mark_job_error(&state, &job_id, &url, msg, None).await;
            return;
        }
    };

    // Insecure-TLS posture signal. The CLI prints a one-shot stderr warning;
    // server jobs run silenced, so surface the same fact in the job log when an
    // https target is scanned with certificate validation disabled (the
    // default unless the request sent `insecure=false`). Ops triaging a MITM
    // scenario can then see it per job.
    if target.insecure && target.url.scheme().eq_ignore_ascii_case("https") {
        log(
            &state,
            "JOB",
            &format!(
                "insecure-tls id={} url={} (TLS certificate validation disabled; send insecure=false to enforce)",
                job_id, url
            ),
        );
    }

    // The shared execution path performs the reachability gate inside the
    // job's request-counter and rate-limiter scopes, before any scan work.
    let run = crate::job::runner::execute_scan(
        &mut target,
        &args,
        &progress,
        &cancel_flag,
        &|msg: &str| log(&state, "WRN", &format!("id={} {}", job_id, msg)),
    )
    .await;

    if run.reachability_failed {
        // The target is fully hydrated here, so deliver the terminal webhook
        // through its proxy/TLS-aware client just like other job errors.
        let cb_client = target.build_client_or_default();
        mark_job_error(
            &state,
            &job_id,
            &url,
            unreachable_error_message(),
            Some(cb_client),
        )
        .await;
        return;
    }

    let final_results_arc = run
        .sanitized_results(&progress, include_request, include_response)
        .await;
    let (callback_url, final_status, error_message) = match state.jobs.lock().await.get_mut(&job_id)
    {
        Some(job) => {
            let status = run.settle(job, final_results_arc.clone(), args.scan_timeout, false);
            (
                job.callback_url.clone(),
                Some(status),
                job.error_message.clone(),
            )
        }
        None => (None, None, None),
    };
    // Derive the webhook/log label from the status actually stored, not from the
    // pre-lock `was_cancelled`/`panicked` snapshot: a DELETE cancel landing in
    // the window between those reads and this lock flips the job to `cancelled`,
    // and the webhook payload (which subscribers branch on) and the JOB log must
    // agree with what GET /scan/{id} now reports rather than announcing `done`
    // for a job stored as cancelled.
    let status_label = match final_status {
        Some(JobStatus::Cancelled) => "cancelled",
        Some(JobStatus::Error) => "error",
        _ => "done",
    };
    log(
        &state,
        "JOB",
        &format!(
            "{}{} id={} url={}",
            status_label,
            if run.timed_out { " (scan_timeout)" } else { "" },
            job_id,
            url
        ),
    );

    // Reuse the target's HTTP configuration (proxy, TLS relaxation, redirect
    // policy) so webhook delivery respects the same network boundary as the
    // scan itself.
    let cb_client = target.build_client_or_default();
    send_terminal_webhook(
        &state,
        callback_url,
        &job_id,
        &url,
        TerminalOutcome {
            status_label,
            results: &final_results_arc,
            error_message: error_message.as_deref(),
        },
        Some(cb_client),
    )
    .await;
}

/// What the terminal webhook reports about how the scan ended.
pub(crate) struct TerminalOutcome<'a> {
    pub(crate) status_label: &'a str,
    pub(crate) results: &'a [SanitizedResult],
    pub(crate) error_message: Option<&'a str>,
}

/// POST the scan-completion payload to the configured webhook, if any.
///
/// Only `http`/`https` URLs are dialed, which blocks non-network schemes such
/// as `file://`. NOTE: this is *not* a host-based SSRF guard — the callback
/// host is whatever the scan submitter supplied, so loopback, link-local
/// (e.g. cloud metadata at 169.254.169.254), and RFC1918 addresses are all
/// reachable, and the full result JSON is POSTed there. This is inherent to
/// the server being a URL scanner (the scan target itself is unrestricted in
/// the same way), so host filtering is intentionally left to deployment: run
/// `dalfox server` with `--api-key` and appropriate network egress controls
/// when exposing it to untrusted submitters.
///
/// The status string is the same one we put in the response payload
/// (`"done"` / `"cancelled"` / `"error"`) so downstream consumers can branch
/// on it without re-deriving terminal state. `error_message` is the job's
/// stored reason (`null` when there is none): it is the only thing that tells a
/// `scan_timeout` expiry from a user cancel, or an unreachable target from a
/// worker panic, for a subscriber that never polls `GET /scan/{id}`.
pub(crate) async fn send_terminal_webhook(
    state: &AppState,
    callback_url: Option<String>,
    job_id: &str,
    url: &str,
    outcome: TerminalOutcome<'_>,
    client: Option<reqwest::Client>,
) {
    let TerminalOutcome {
        status_label,
        results,
        error_message,
    } = outcome;
    let Some(cb_url) = callback_url else { return };
    // Same scheme test `validate_scan_options` gates submission on, so a URL it
    // accepted can't be silently dropped here. Spelled with the shared helper
    // rather than a literal `starts_with`: schemes are case-insensitive, so the
    // old byte-exact prefix compare would have discarded a `HTTPS://…` callback
    // the boundary check had just approved.
    if !has_http_scheme(&cb_url) {
        return;
    }
    let payload = serde_json::json!({
        "scan_id": job_id,
        "status": status_label,
        "url": url,
        "results": results,
        "error_message": error_message,
    });
    // When the caller has no parsed target (e.g. pre-start cancellation),
    // fall back to a default client. Webhook delivery should not silently
    // drop just because the scan never got far enough to build a target.
    let client = client.unwrap_or_default();
    let result = client
        .post(&cb_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    match result {
        Ok(resp) => log(
            state,
            "CALLBACK",
            &format!("POST {} -> {}", cb_url, resp.status()),
        ),
        Err(e) => log(state, "CALLBACK", &format!("POST {} failed: {}", cb_url, e)),
    }
}

/// Worker count `/preflight` runs discovery/mining at when the request does not
/// ask for one. Re-exported from `cmd::scan` so this and
/// [`crate::cmd::scan::ScanArgs::for_preflight`] cannot disagree — they were two
/// independent `10` literals before.
pub(crate) use crate::cmd::scan::PREFLIGHT_DEFAULT_WORKERS;

/// Build a hydrated Target from the preflight request options.
pub(crate) fn hydrate_preflight_target(
    target_url: &str,
    opts: &ScanOptions,
    timeout_secs: u64,
) -> Result<crate::target_parser::Target, String> {
    let mut t = parse_target(target_url).map_err(|e| format!("parse_target failed: {}", e))?;
    t.method = opts.method.clone().unwrap_or_else(|| "GET".to_string());
    t.timeout = timeout_secs;
    // Pacing and concurrency are read off the *target*, not off `ScanArgs`:
    // `analyze_parameters` sizes its semaphores from `target.workers` and every
    // discovery/mining probe sleeps `target.delay` afterwards. Leaving both at
    // `parse_target`'s defaults meant `/preflight` accepted `delay` and
    // `worker` (they are the same `ScanOptions` `/scan` validates) and then
    // discarded them — so the one per-request pacing control a caller has was
    // silently removed on this route, while the CLI's preflight honors `--delay`
    // because it runs against a target hydrated from the same args
    // (`cmd::scan::input` sets `target.delay`).
    t.delay = opts.delay.unwrap_or(crate::cmd::scan::DEFAULT_DELAY_MS);
    t.workers = opts.worker.unwrap_or(PREFLIGHT_DEFAULT_WORKERS);
    t.user_agent = opts.user_agent.clone();
    t.proxy = opts.proxy.clone();
    t.insecure = opts.insecure.unwrap_or(true);
    t.follow_redirects = opts.follow_redirects.unwrap_or(false);
    // Parse via the shared helper so preflight rejects empty header names the
    // same way the scan path does (a bare `:value` is dropped, not forwarded).
    t.headers = opts
        .header
        .as_ref()
        .map(|h| {
            h.iter()
                .filter_map(|s| crate::utils::http::parse_header_line(s))
                .collect()
        })
        .unwrap_or_default();
    // Reuse the shared cookie splitter so preflight parses the `cookie`
    // option exactly like `run_scan_job` / `/scan` does — both trim
    // whitespace around each `name=value` pair. The earlier inline version
    // here left `=`-adjacent whitespace in, so the same cookie option could
    // produce different cookies on the preflight vs. scan paths.
    t.cookies = opts
        .cookie
        .as_ref()
        .map(|c| split_cookie_pairs(c))
        .unwrap_or_default();
    crate::job::lift_cookie_headers(&mut t.headers, &mut t.cookies);
    t.data = opts.data.clone();
    Ok(t)
}
