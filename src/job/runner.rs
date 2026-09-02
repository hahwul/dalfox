//! The scan-execution core shared by the REST server and the MCP runtime.
//!
//! Both interfaces used to carry their own copy of this: ~280 lines that were
//! character-for-character identical apart from one log call, kept in step by
//! comments telling each side to mirror the other. That worked until it did
//! not — a run of parity fixes (blind-XSS dispatch, the initial AST pass,
//! session-loss detection, per-job WAF backoff) each had to be applied twice,
//! and each was reported because one side had been missed.
//!
//! What genuinely differs between the two stays with them: how a job record is
//! claimed and stored (the REST server holds jobs behind a `tokio::sync::Mutex`,
//! MCP behind a `std::sync::Mutex`), and the REST-only completion webhook.
//! Everything from "hydrate the target" to "the scan finished and here is what
//! it left behind" lives here. Turning a request into `ScanArgs` used to be on
//! that "differs" list and drifted the same way; it now lives in
//! [`super::spec`], leaving each surface only the mapping out of its own
//! request type.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::Mutex;

use super::{AbortOnDrop, JobProgress, cap_reflection_params, run_within_scan_budget};
use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::Result as ScanResult;
use crate::target_parser::{Target, parse_target};

/// Ceiling on parameters carried into the scan phase, named in the warning
/// below. Defined one level up in `job`; the REST server only re-exports it.
use super::MAX_DISCOVERED_PARAMS;

/// Build the `Target` a job scans from its `ScanArgs`.
///
/// `Err` carries the operator-facing message; the caller decides how its own
/// job store records the failure.
///
/// `user_agent` is normalized to `Some("")` when none was supplied, which is
/// this codebase's sentinel for "no override" — the CLI sets it the same way
/// (`cmd::scan::input`). Consumers must empty-check before putting it on the
/// wire; `utils::http::apply_headers_ua_cookies` does.
pub(crate) fn hydrate_target(url: &str, args: &ScanArgs) -> Result<Target, String> {
    let mut t = parse_target(url).map_err(|e| format!("parse_target failed: {}", e))?;
    t.method = args.method.clone();
    t.timeout = args.timeout;
    t.delay = args.delay;
    t.proxy = args.proxy.clone();
    t.insecure = args.insecure.unwrap_or(true);
    t.follow_redirects = args.follow_redirects;
    t.ignore_return = args.ignore_return.clone();
    t.workers = args.workers;
    t.data = args.data.clone();
    t.headers = args
        .headers
        .iter()
        .filter_map(|h| crate::utils::http::parse_header_line(h))
        .collect();
    // A supplied User-Agent is also pushed as a header so the header-reflection
    // probe exercises it even on blanket-echo targets, where the common header
    // sweep is suppressed. An empty value means "no override", so it must not
    // become a literal `User-Agent:` on every request.
    if let Some(ua) = args.user_agent.as_deref().filter(|s| !s.is_empty()) {
        t.headers.push(("User-Agent".to_string(), ua.to_string()));
        t.user_agent = Some(ua.to_string());
    } else {
        t.user_agent = Some(String::new());
    }
    t.cookies = args
        .cookies
        .iter()
        .flat_map(|c| super::split_cookie_pairs(c))
        .collect();
    Ok(t)
}

/// What a finished scan left behind, for the caller to record in its own job
/// store. `results` is the live accumulator the scan wrote into.
pub(crate) struct ScanRun {
    pub(crate) results: Arc<Mutex<Vec<ScanResult>>>,
    /// The whole-scan wall-clock budget expired (`scan_timeout`).
    pub(crate) timed_out: bool,
    /// The cancellation flag was set — by the caller, or by the budget above.
    pub(crate) was_cancelled: bool,
    /// A worker task panicked, so at least one parameter is unfinished. Never
    /// set together with `was_cancelled`, which is partial by design and wins.
    pub(crate) panicked: bool,
    /// How many worker tasks panicked, for the operator-facing message.
    pub(crate) worker_panics: usize,
    /// The authenticated session was gone, with the signal that fired.
    pub(crate) session_lost: Option<String>,
}

impl ScanRun {
    /// The scan completed but its findings cannot be trusted, so it must not
    /// settle as a clean `done`. Cancellation still takes precedence.
    pub(crate) fn lost_session(&self) -> bool {
        !self.was_cancelled && self.session_lost.is_some()
    }
}

/// Run one job's scan to completion and report what it left behind.
///
/// `warn` receives operator-facing warnings so each interface can route them
/// through its own logger — the single line that differed between the two
/// copies this replaces.
pub(crate) async fn execute_scan(
    target: &mut Target,
    args: &Arc<ScanArgs>,
    progress: &JobProgress,
    cancel_flag: &Arc<AtomicBool>,
    warn: &(dyn Fn(&str) + Send + Sync),
) -> ScanRun {
    let args = args.clone();
    let cancel_flag = cancel_flag.clone();
    let results = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
    // Per-job WAF consecutive-block counter so one scan's WAF backoff doesn't
    // throttle an unrelated scan.
    //
    // For the request counters, we scope `progress.requests_sent` /
    // `progress.requests_failed` directly instead of private local atomics —
    // every `crate::tick_request_count()` / `crate::tick_request_failure()`
    // call then writes through to the publicly visible progress fields, so
    // GET /scan/{id} returns live values during the scan instead of `0` until
    // completion. Scoping the failure counter is also what keeps a daemon's
    // concurrent jobs from inheriting each other's transport failures: without
    // it `tick_request_failure` only reaches the process-global tally.
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

    // Captured from inside the scoped/async blocks below so worker-panic count
    // survives past the scan; assigned by the run_scanning call.
    let mut scan_report = crate::scanning::ScanRunReport::default();
    // Set (from inside the scoped block below) when this job's authenticated
    // session was gone — either before the scan began or by the time it ended.
    // Carries the signal that fired, verbatim into `error_message`.
    let mut session_lost: Option<String> = None;
    let scan_fut = crate::with_job_rate_limiter(
        args.rate_limit,
        crate::REQUEST_COUNT_JOB.scope(progress.requests_sent.clone(), async {
        crate::REQUEST_FAILURE_COUNT_JOB.scope(progress.requests_failed.clone(), async {
            crate::WAF_CONSECUTIVE_BLOCKS_JOB
                .scope(job_waf_consecutive.clone(), async {
                    // Remote payload / wordlist fetch. Inside the budget on
                    // purpose: `scan_timeout` is a promise about the whole job,
                    // and both front ends used to do this fetch *before*
                    // `run_within_scan_budget`, so a slow provider stretched a
                    // job past a bound the caller had set. Each request is
                    // capped by `--timeout`, but N provider URLs are not.
                    //
                    // A failure is not cosmetic: the scan proceeds without the
                    // list the caller explicitly asked for and still settles
                    // `done`, which reads as "scanned, found nothing" — so it
                    // goes through `warn` rather than being swallowed.
                    if (!args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty())
                        && let Err(e) = crate::utils::init_remote_resources_with_options(
                            &args.remote_payloads,
                            &args.remote_wordlists,
                            Some(args.timeout),
                            args.proxy.clone(),
                        )
                        .await
                    {
                        warn(&format!(
                            "remote resource fetch failed ({e}); scanning without the requested remote lists"
                        ));
                    }

                    if let Some(callback_url) = &args.blind_callback_url {
                        crate::scanning::blind_scanning(
                            target,
                            callback_url,
                            args.custom_blind_xss_payload.as_deref(),
                        )
                        .await;
                    }

                    // Session-loss detection (issue #1273), the server half.
                    // A `dalfox server` job carrying credentials has exactly
                    // the CLI's exposure: the session dies mid-scan, every
                    // later request is answered by a login page, nothing
                    // reflects, and the job settles `done` with zero findings —
                    // indistinguishable from a clean target. Off, and free,
                    // when no credentials were supplied.
                    let monitor_session =
                        crate::cmd::scan::session::monitoring_enabled(&args, target);
                    let session_check_re =
                        crate::cmd::scan::session::compile_session_check(&args)
                            .ok()
                            .flatten();
                    let mut session_baseline = None;

                    // Initial AST DOM-XSS pass on the GET response, mirroring
                    // the CLI flow. Server used to skip this because it
                    // didn't run preflight, so identical targets reported
                    // 0 findings via API even when CLI saw multiple
                    // DOM-XSS sinks (e.g. xss-game level3 with
                    // location.hash → html). Best-effort fetch — if it
                    // fails the regular scan path below still runs.
                    if !args.skip_ast_analysis {
                        let client = target.build_client_or_default();
                        // Mirror the CLI preflight: carry the target's
                        // headers/cookies/User-Agent (so auth/header/UA-gated
                        // SPAs are analyzed logged-in, matching CLI findings —
                        // a bare GET dropped them and analyzed the logged-out
                        // page) and cap the body with `Range: 0-8191` so a large
                        // response can't buffer unbounded into server memory.
                        let preflight = crate::utils::build_preflight_request(
                            &client,
                            target,
                            false,
                            Some(8192),
                        );
                        // Count + rate-limit the preflight GET like the CLI
                        // (record_outbound_request), so it isn't missing from the
                        // job's requests_sent tally.
                        crate::record_outbound_request().await;
                        if let Ok(resp) = preflight.send().await {
                            // Clone the headers before `read_body` consumes the
                            // response: the posture needs both them and the
                            // document (a page can declare its CSP with
                            // `<meta http-equiv>`), so Trusted Types awareness
                            // and the confidence grading's CSP signal match what
                            // the CLI derives from preflight.
                            let resp_headers = resp.headers().clone();
                            // Captured before `read_body` consumes the response.
                            // Under `follow_redirects` this is where the chain
                            // actually ended, which is the only thing a session
                            // baseline can meaningfully compare against.
                            let resp_status = resp.status().as_u16();
                            let resp_final_url = resp.url().clone();
                            if let Ok(body) = crate::utils::http::read_body(resp).await {
                                // Authenticated-state fingerprint, derived from
                                // this same response so monitoring costs the
                                // job no extra request (mirrors the CLI).
                                // `--session-check-url` is the exception: its
                                // baseline has to come from that endpoint, so
                                // it falls through to the capture below.
                                if monitor_session && args.session_check_url.is_none() {
                                    session_baseline =
                                        Some(crate::cmd::scan::session::baseline_from_preflight(
                                            &target.url,
                                            &resp_final_url,
                                            resp_status,
                                            &resp_headers,
                                            &body,
                                            session_check_re.as_ref(),
                                        ));
                                }
                                let posture =
                                    crate::scanning::ast_integration::PageSecurityPosture::from_response(
                                        &resp_headers,
                                        &body,
                                    );
                                let ast_batch =
                                    crate::scanning::ast_integration::run_initial_ast_dom_analysis(
                                        &body,
                                        target.url.as_str(),
                                        &target.method,
                                        posture,
                                    );
                                if !ast_batch.is_empty() {
                                    let added = crate::scanning::count_matching_results(
                                        &ast_batch,
                                        &args.limit_result_type.to_uppercase(),
                                    );
                                    let mut guard = results.lock().await;
                                    guard.extend(ast_batch);
                                    findings_count
                                        .fetch_add(added, std::sync::atomic::Ordering::Relaxed);
                                }
                                let ext_batch = crate::scanning::fetch_and_analyze_external_js(
                                    &client,
                                    target,
                                    &body,
                                    args.as_ref(),
                                )
                                .await;
                                crate::scanning::accumulate_findings(
                                    &results,
                                    &findings_count,
                                    ext_batch,
                                    &args.limit_result_type.to_uppercase(),
                                )
                                .await;
                            }
                        }
                    }

                    // The AST pass above is skipped entirely under
                    // `skip_ast_analysis`, and `--session-check-url` needs its
                    // baseline from that endpoint rather than from the target.
                    // Either way there is no response to reuse, so pay for one
                    // request — but only for a job that actually has a session.
                    if monitor_session && session_baseline.is_none() {
                        session_baseline =
                            crate::cmd::scan::session::capture_baseline(target, &args).await;
                    }
                    // Credentials that were already dead when the job started:
                    // no later probe can detect a *change* from that baseline,
                    // so it is recorded now rather than settling as `done`.
                    session_lost = session_baseline
                        .as_ref()
                        .and_then(crate::cmd::scan::session::baseline_warning);

                    // `args.silence` is already `true` (set at construction), and
                    // `analyze_parameters` takes `&ScanArgs`, so pass the shared
                    // Arc directly instead of deep-cloning it just to re-set a
                    // field that already holds the desired value.
                    analyze_parameters(target, args.as_ref(), None).await;

                    // Bound the per-scan fan-out: a sprawling/hostile target can
                    // expose thousands of params, and scanning spawns O(params ×
                    // payloads) workers. Truncate with a warning past the cap.
                    let dropped = cap_reflection_params(target);
                    if dropped > 0 {
                        warn(&format!(
                            "discovered params capped to {} (dropped {})",
                            MAX_DISCOVERED_PARAMS, dropped
                        ));
                    }

                    // Count only the params the HTTP scan phase will actually
                    // test (Fragment params are client-side only and spawn no
                    // worker), so `params_total` matches the per-parameter
                    // workers and `estimated_completion_pct` stays honest.
                    progress.params_total.store(
                        crate::scanning::http_scannable_param_count(target) as u32,
                        std::sync::atomic::Ordering::Relaxed,
                    );

                    scan_report = crate::scanning::run_scanning(
                        target,
                        args.clone(),
                        crate::scanning::ScanRunHandles::new(
                            results.clone(),
                            findings_count.clone(),
                        )
                        .with_cancel(cancel_flag.clone())
                        // Feed the live per-parameter completion counter so
                        // GET /scan/{id} reports `params_tested` climbing
                        // during the scan instead of staying at 0 until done.
                        .with_params_done(progress.params_tested.clone()),
                    )
                    .await;

                    // The probe that catches the reported failure: a session
                    // that survived the job's start and died during the
                    // injection stage. Skipped when the run was cut short
                    // anyway (cancel / scan_timeout), where a login-page probe
                    // would only add noise to an already-partial result.
                    if session_lost.is_none()
                        && !cancel_flag.load(std::sync::atomic::Ordering::Relaxed)
                        && let Some(baseline) = &session_baseline
                    {
                        session_lost = crate::cmd::scan::session::session_lost_after_scan(
                            target, baseline, &args,
                        )
                        .await;
                    }
                })
                .await;
        })
        .await;
        }),
    );

    // Enforce the whole-scan wall-clock budget. On expiry the cancel flag is
    // tripped so any in-flight workers wind down at their next checkpoint, and
    // the job settles as `cancelled` with whatever partial results it gathered
    // (plus an explanatory error_message) — the same shape as a user cancel.
    let timed_out = run_within_scan_budget(args.scan_timeout, &cancel_flag, scan_fut).await;

    drop(findings_updater);

    let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);
    // A worker-task panic means at least one parameter's findings are
    // incomplete. Surface that as `error` (with the partial results still
    // attached) so a poller can't mistake a crashed scan for a clean `done`.
    // Cancellation takes precedence (it's already a partial-by-design state).
    let panicked = !was_cancelled && scan_report.worker_panics > 0;

    if !was_cancelled && !panicked {
        // After a clean, complete run every discovered parameter was processed
        // by `run_scanning`, so pin `params_tested` to `params_total` (exactly
        // 100%). Skip this on cancellation AND on a worker panic: both stop
        // short of finishing every parameter — a panicked worker never bumps
        // the live counter — so promoting to params_total would report
        // estimated_completion_pct = 100 for a job whose status is
        // cancelled/error, making a partial scan read as a clean finish.
        progress.params_tested.store(
            progress
                .params_total
                .load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    ScanRun {
        results,
        worker_panics: scan_report.worker_panics,
        timed_out,
        was_cancelled,
        panicked,
        session_lost,
    }
}
