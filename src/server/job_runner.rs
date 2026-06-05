//! Background scan execution: spawning isolated runtimes, running the scan
//! pipeline, recording terminal state, and firing completion webhooks. Also
//! hosts `hydrate_preflight_target`, shared with the preflight handler.

use super::*;

/// Spawn `run_scan_job` on the blocking pool with full panic / runtime-build
/// isolation. Without this wrapper, a panic inside the spawned task — or a
/// failure to build the inner current-thread runtime — silently drops the
/// `JoinHandle` and leaves the job pinned in `Queued`/`Running` forever.
/// `purge_expired_jobs` only collects terminal jobs, so the orphan also
/// leaks the job slot indefinitely.
pub(crate) fn spawn_scan_task(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    tokio::task::spawn_blocking(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("scan runtime build failed: {}", e);
                eprintln!("[server] {} for job {}", msg, job_id);
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
            let payload = if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic.downcast_ref::<&str>() {
                (*s).to_string()
            } else {
                "unknown panic payload".to_string()
            };
            let msg = format!("scan task panicked: {}", payload);
            eprintln!("[server] {} (job_id={})", msg, job_id_for_recovery);
            // The scan runtime itself is still valid after a panic inside the
            // future, so reuse it for the recovery write rather than spinning
            // up a second runtime just to update one map entry.
            rt.block_on(async {
                mark_job_error(
                    &state_for_recovery,
                    &job_id_for_recovery,
                    &url_for_recovery,
                    msg,
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
        eprintln!(
            "[server] could not build recovery runtime to fail job {}",
            job_id
        );
        return;
    };
    let state = state.clone();
    let job_id = job_id.to_string();
    let url = url.to_string();
    rt.block_on(async move {
        mark_job_error(&state, &job_id, &url, msg).await;
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
/// callback URL can't block concurrent job updates. We use the default
/// reqwest client because the panic / parse-error paths may not have a
/// fully-built target available; this still mirrors the contract that
/// every terminal state fires the webhook (see commit aeb8cdb).
pub(crate) async fn mark_job_error(state: &AppState, job_id: &str, url: &str, msg: String) {
    let (transitioned, callback_url) = {
        let mut jobs = state.jobs.lock().await;
        if let Some(job) = jobs.get_mut(job_id)
            && !job.is_terminal()
        {
            job.status = JobStatus::Error;
            job.error_message = Some(msg);
            if job.finished_at_ms.is_none() {
                job.finished_at_ms = Some(now_ms());
            }
            (true, job.callback_url.clone())
        } else {
            (false, None)
        }
    };
    if transitioned {
        send_terminal_webhook(state, callback_url, job_id, url, "error", &[], None).await;
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
            Some(job) => {
                if job.status == JobStatus::Cancelled
                    || job.cancelled.load(std::sync::atomic::Ordering::Relaxed)
                {
                    StartDecision::PreCancelled {
                        callback_url: job.callback_url.clone(),
                    }
                } else {
                    job.status = JobStatus::Running;
                    job.started_at_ms = Some(now_ms());
                    StartDecision::Run {
                        progress: job.progress.clone(),
                        cancel_flag: job.cancelled.clone(),
                    }
                }
            }
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
                "cancelled",
                &[],
                cb_client,
            )
            .await;
            return;
        }
        StartDecision::Missing => return,
    };

    let args = ScanArgs {
        detect_outdated_libs: opts.detect_outdated_libs.unwrap_or(false),
        // Each REST job scans exactly one caller-supplied URL, with method,
        // headers, cookies, and body provided as explicit request fields — the
        // same fidelity a single HAR entry carries. The multi-target input
        // shapes (`file`, `pipe`, `raw-http`, `har`) are CLI-only because they
        // fan one input out into many targets, which the one-job-one-URL model
        // here doesn't express; callers replay a HAR by POSTing /scan per entry.
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: None,
        include_request,
        include_response,
        include_all: false,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],

        param: opts.param.clone().unwrap_or_default(),
        data: opts.data.clone(),
        headers: opts.header.clone().unwrap_or_default(),
        cookies: {
            let mut v = vec![];
            if let Some(c) = &opts.cookie
                && !c.trim().is_empty()
            {
                v.push(c.clone());
            }
            v
        },
        method: opts.method.clone().unwrap_or_else(|| "GET".to_string()),
        user_agent: opts.user_agent.clone(),
        cookie_from_raw: None,
        no_color: true,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,

        only_discovery: false,
        skip_discovery: opts.skip_discovery.unwrap_or(false),
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,

        mining_dict_word: None,
        skip_mining: opts.skip_mining.unwrap_or(false),
        skip_mining_dict: opts.skip_mining.unwrap_or(false),
        skip_mining_dom: opts.skip_mining.unwrap_or(false),

        timeout: opts
            .timeout
            .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS),
        scan_timeout: 0,
        delay: opts.delay.unwrap_or(0),
        proxy: opts.proxy.clone(),
        follow_redirects: opts.follow_redirects.unwrap_or(false),
        ignore_return: vec![],

        workers: opts.worker.unwrap_or(50),
        max_concurrent_targets: 50,
        max_targets_per_host: 100,

        encoders: opts
            .encoders
            .clone()
            .unwrap_or_else(|| vec!["url".to_string(), "html".to_string()]),

        custom_blind_xss_payload: None,
        blind_callback_url: opts.blind.clone(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: opts.deep_scan.unwrap_or(false),
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: opts.skip_ast_analysis.unwrap_or(false),
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
        remote_payloads: opts.remote_payloads.clone().unwrap_or_default(),
        remote_wordlists: opts.remote_wordlists.clone().unwrap_or_default(),

        targets: vec![url.clone()],
    };

    // Initialize remote resources if requested (honor timeout/proxy)
    if !args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty() {
        let _ = crate::utils::init_remote_resources_with_options(
            &args.remote_payloads,
            &args.remote_wordlists,
            Some(args.timeout),
            args.proxy.clone(),
        )
        .await;
    }
    let results = Arc::new(Mutex::new(Vec::<ScanResult>::new()));

    let mut target = match parse_target(&url) {
        Ok(mut t) => {
            t.data = args.data.clone();
            t.headers = args
                .headers
                .iter()
                .filter_map(|h| {
                    let mut parts = h.splitn(2, ':');
                    let name = parts.next()?.trim();
                    let value = parts.next()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    Some((name.to_string(), value.to_string()))
                })
                .collect();
            t.method = args.method.clone();
            if let Some(ua) = &args.user_agent {
                t.headers.push(("User-Agent".to_string(), ua.clone()));
                t.user_agent = Some(ua.clone());
            } else {
                t.user_agent = Some("".to_string());
            }
            t.cookies = args
                .cookies
                .iter()
                .flat_map(|c| split_cookie_pairs(c))
                .collect();
            t.timeout = args.timeout;
            t.delay = args.delay;
            t.proxy = args.proxy.clone();
            t.follow_redirects = args.follow_redirects;
            t.ignore_return = args.ignore_return.clone();
            t.workers = args.workers;
            t
        }
        Err(e) => {
            // Webhook subscribers expect a terminal callback for every scan;
            // before, this branch transitioned the job to Error but never
            // fired the webhook, so a malformed URL silently left the
            // subscriber waiting indefinitely. mark_job_error now handles
            // both the status update and the webhook dispatch.
            let msg = format!("parse_target failed: {}", e);
            mark_job_error(&state, &job_id, &url, msg).await;
            return;
        }
    };

    // Reachability gate. A parseable-but-unreachable target (connection
    // refused, DNS failure, TLS error, timeout) otherwise runs the full
    // pipeline and finishes `done` with 0 findings — indistinguishable from
    // "scanned, found no XSS". /preflight already probes reachability and
    // returns reachable:false; mirror that here so /scan clients can tell the
    // two apart. Any HTTP response (including 4xx/5xx) counts as reachable.
    if !send_reachability_probe(&target).await {
        mark_job_error(&state, &job_id, &url, unreachable_error_message()).await;
        return;
    }

    // Per-job WAF consecutive-block counter so one scan's WAF backoff doesn't
    // throttle an unrelated scan.
    //
    // For the request counter, we scope `progress.requests_sent` directly
    // instead of a private local atomic — every `crate::tick_request_count()`
    // call then writes through to the publicly visible progress field, so
    // GET /scan/{id} returns a live `requests_sent` value during the scan
    // instead of `0` until completion.
    let job_waf_consecutive = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // `run_scanning`'s 6th argument is the running findings tally, not a
    // parameter counter (see scanning/mod.rs:findings_count). Older code
    // here called it `param_counter` and stored it into `params_tested`,
    // which conflated two unrelated metrics.
    let findings_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Mirror the in-flight findings tally into `progress.findings_so_far`
    // periodically so pollers see a non-zero value before the scan finishes.
    // The types differ (`AtomicUsize` inside scanning, `AtomicU64` in the
    // public progress struct), which is why a copying task is needed.
    let progress_findings = progress.findings_so_far.clone();
    let findings_count_for_updater = findings_count.clone();
    // RAII abort — covers the panic path too, not just the manual abort below.
    let findings_updater = AbortOnDrop(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            progress_findings.store(
                findings_count_for_updater.load(std::sync::atomic::Ordering::Relaxed) as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }));

    crate::REQUEST_COUNT_JOB
        .scope(progress.requests_sent.clone(), async {
            crate::WAF_CONSECUTIVE_BLOCKS_JOB
                .scope(job_waf_consecutive.clone(), async {
                    if let Some(callback_url) = &args.blind_callback_url {
                        crate::scanning::blind_scanning(
                            &target,
                            callback_url,
                            args.custom_blind_xss_payload.as_deref(),
                        )
                        .await;
                    }

                    // Initial AST DOM-XSS pass on the GET response, mirroring
                    // the CLI flow. Server used to skip this because it
                    // didn't run preflight, so identical targets reported
                    // 0 findings via API even when CLI saw multiple
                    // DOM-XSS sinks (e.g. xss-game level3 with
                    // location.hash → html). Best-effort fetch — if it
                    // fails the regular scan path below still runs.
                    if !args.skip_ast_analysis {
                        let client = target.build_client_or_default();
                        if let Ok(resp) = client.get(target.url.clone()).send().await
                            && let Ok(body) = resp.text().await
                        {
                            let ast_batch =
                                crate::scanning::ast_integration::run_initial_ast_dom_analysis(
                                    &body,
                                    target.url.as_str(),
                                    &target.method,
                                );
                            if !ast_batch.is_empty() {
                                let added = ast_batch.len();
                                let mut guard = results.lock().await;
                                guard.extend(ast_batch);
                                findings_count
                                    .fetch_add(added, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }

                    let mut silent_args = args.clone();
                    silent_args.silence = true;
                    analyze_parameters(&mut target, &silent_args, None).await;

                    progress.params_total.store(
                        target.reflection_params.len() as u32,
                        std::sync::atomic::Ordering::Relaxed,
                    );

                    crate::scanning::run_scanning(
                        &target,
                        Arc::new(args.clone()),
                        results.clone(),
                        None,
                        None,
                        findings_count.clone(),
                        Some(cancel_flag.clone()),
                        None,
                        // Feed the live per-parameter completion counter so
                        // GET /scan/{id} reports `params_tested` climbing
                        // during the scan instead of staying at 0 until done.
                        Some(progress.params_tested.clone()),
                    )
                    .await;
                })
                .await;
        })
        .await;

    drop(findings_updater);

    let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

    if !was_cancelled {
        // After natural completion, every discovered parameter has been
        // processed by `run_scanning`, so reflect that in `params_tested`.
        // Skip this on cancellation: the scan stopped early and promoting
        // params_tested to params_total would falsely report 100%
        // completion to API pollers computing estimated_completion_pct.
        progress.params_tested.store(
            progress
                .params_total
                .load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    let final_results = {
        let locked = results.lock().await;
        progress
            .findings_so_far
            .store(locked.len() as u64, std::sync::atomic::Ordering::Relaxed);
        locked
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect::<Vec<_>>()
    };

    let final_results_arc = Arc::new(final_results);
    let callback_url = {
        let mut jobs = state.jobs.lock().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.results = Some(final_results_arc.clone());
            if job.status != JobStatus::Cancelled {
                job.status = if was_cancelled {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Done
                };
            }
            // Preserve an earlier finished_at_ms set by cancel_scan_handler
            // (which records when the user asked to stop, not when the task noticed).
            if job.finished_at_ms.is_none() {
                job.finished_at_ms = Some(now_ms());
            }
            job.callback_url.clone()
        } else {
            None
        }
    };
    let status_label = if was_cancelled { "cancelled" } else { "done" };
    log(
        &state,
        "JOB",
        &format!("{} id={} url={}", status_label, job_id, url),
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
        status_label,
        &final_results_arc,
        Some(cb_client),
    )
    .await;
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
/// on it without re-deriving terminal state.
pub(crate) async fn send_terminal_webhook(
    state: &AppState,
    callback_url: Option<String>,
    job_id: &str,
    url: &str,
    status_label: &str,
    results: &[SanitizedResult],
    client: Option<reqwest::Client>,
) {
    let Some(cb_url) = callback_url else { return };
    if !(cb_url.starts_with("http://") || cb_url.starts_with("https://")) {
        return;
    }
    let payload = serde_json::json!({
        "scan_id": job_id,
        "status": status_label,
        "url": url,
        "results": results,
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

/// Build a hydrated Target from the preflight request options.
pub(crate) fn hydrate_preflight_target(
    target_url: &str,
    opts: &ScanOptions,
    timeout_secs: u64,
) -> Result<crate::target_parser::Target, String> {
    let mut t = parse_target(target_url).map_err(|e| format!("parse_target failed: {}", e))?;
    t.method = opts.method.clone().unwrap_or_else(|| "GET".to_string());
    t.timeout = timeout_secs;
    t.user_agent = opts.user_agent.clone();
    t.proxy = opts.proxy.clone();
    t.follow_redirects = opts.follow_redirects.unwrap_or(false);
    t.headers = opts
        .header
        .as_ref()
        .map(|h| {
            h.iter()
                .filter_map(|s| s.split_once(":"))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
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
    t.data = opts.data.clone();
    Ok(t)
}
