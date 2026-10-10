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

use super::{AbortOnDrop, JobProgress, JobStatus, cap_reflection_params, run_within_scan_budget};
use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::{Result as ScanResult, SanitizedResult};
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
    super::lift_cookie_headers(&mut t.headers, &mut t.cookies);
    Ok(t)
}

/// What a finished scan left behind, for the caller to record in its own job
/// store. `results` is the live accumulator the scan wrote into.
pub(crate) struct ScanRun {
    pub(crate) results: Arc<Mutex<Vec<ScanResult>>>,
    /// The reachability request failed before any scan work began.
    pub(crate) reachability_failed: bool,
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
    /// The scan stopped at [`super::MAX_FINDINGS_PER_JOB`] (`deep_scan` only).
    pub(crate) findings_capped: bool,
    /// Every warning the run raised, for [`super::Job::warnings`].
    pub(crate) warnings: Vec<String>,
    /// The request's `min_confidence`; findings it drops never reach the
    /// stored results or the settled tally.
    pub(crate) min_confidence: Option<String>,
}

impl ScanRun {
    /// The scan completed but its findings cannot be trusted, so it must not
    /// settle as a clean `done`. Cancellation still takes precedence.
    pub(crate) fn lost_session(&self) -> bool {
        !self.was_cancelled && self.session_lost.is_some()
    }

    /// The findings as the job stores them, publishing the final tally to
    /// `progress.findings_so_far` on the way.
    pub(crate) async fn sanitized_results(
        &self,
        progress: &JobProgress,
        include_request: bool,
        include_response: bool,
    ) -> Arc<Vec<SanitizedResult>> {
        // The same AST fold the CLI report applies: one DOM sink is found by
        // the preflight pass and again once per parameter, and without it the
        // job lists (and counts, and caps) the same sink several times. The
        // confidence filter runs first, as in the CLI, so the fold picks the
        // strongest *surviving* claim rather than a low-graded winner the
        // filter then drops along with the duplicate it beat.
        let kept: Vec<ScanResult> = self
            .results
            .lock()
            .await
            .iter()
            .filter(|r| !r.below_min_confidence(self.min_confidence.as_deref()))
            .cloned()
            .collect();
        let kept: Vec<SanitizedResult> = crate::cmd::scan::dedupe_ast_results(kept)
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect();
        progress
            .findings_so_far
            .store(kept.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Arc::new(kept)
    }

    /// Record this run's results and final status on `job`, returning the
    /// status stored. A cancel that already landed stays; otherwise the run's
    /// cancel flag (also tripped by `scan_timeout`) → `Cancelled`, a worker
    /// panic or lost session → `Error`, else `Done`.
    ///
    /// Why an incomplete run is incomplete goes into `error_message`, prefixed
    /// with the shared error code where one exists so a poller can match on it
    /// the way the CLI's `target_summary[].error_code` is matched. REST only
    /// fills an empty message; MCP passes `append_note` because its
    /// client-cancelled `wait=true` path records a reason *before* the worker
    /// winds down, and dropping the note would hide that a worker died.
    pub(crate) fn settle(
        &self,
        job: &mut super::Job,
        results: Arc<Vec<SanitizedResult>>,
        scan_timeout: u64,
        append_note: bool,
    ) -> JobStatus {
        job.results = Some(results);
        for w in &self.warnings {
            super::push_job_warning(&mut job.warnings, w);
        }
        if job.status != JobStatus::Cancelled {
            job.status = if self.was_cancelled {
                JobStatus::Cancelled
            } else if self.panicked || self.lost_session() {
                JobStatus::Error
            } else {
                JobStatus::Done
            };
        }
        // Session loss, a worker panic and a timeout are mutually exclusive in
        // practice (a timeout trips the cancel flag, so `panicked` is false).
        let note = if self.lost_session() {
            Some(format!(
                "{}: {}",
                crate::cmd::error_codes::SESSION_LOST,
                self.session_lost.clone().unwrap_or_default()
            ))
        } else if self.panicked {
            Some(format!(
                "{} scan worker task(s) panicked; results are partial",
                self.worker_panics
            ))
        } else if self.timed_out {
            Some(format!(
                "scan exceeded scan_timeout ({}s); returning partial results",
                scan_timeout
            ))
        } else if self.findings_capped {
            Some(format!(
                "findings reached the per-scan cap ({}); scan stopped early, results are partial",
                super::MAX_FINDINGS_PER_JOB
            ))
        } else {
            None
        };
        match (note, &mut job.error_message) {
            (Some(note), None) => job.error_message = Some(note),
            (Some(note), Some(existing)) if append_note => {
                existing.push_str("; ");
                existing.push_str(&note);
            }
            _ => {}
        }
        // An earlier finished_at_ms (set at cancel time) is kept: it records
        // when the user asked to stop, not when the task noticed.
        job.finished_at_ms.get_or_insert_with(super::now_ms);
        job.status.clone()
    }
}

/// The preflight body shared by REST `/preflight` and MCP `preflight_dalfox`.
///
/// Reachability is a bodyless HEAD through the hydrated target's HTTP stack
/// (proxy, TLS, headers, cookies, User-Agent) so the caller's scan method/body
/// is not sent prematurely. Discovery is capped like a real scan, and each
/// parameter's request estimate mirrors the scan's encoder fan-out and
/// per-parameter payload cap — shared with the CLI's `--dry-run` estimate so
/// the three cannot quote different numbers for the same target.
pub(crate) async fn preflight(
    target: &mut Target,
    target_url: &str,
    scan_args: &ScanArgs,
    max_payloads_per_param: usize,
    deep_scan: bool,
) -> serde_json::Value {
    if !super::send_reachability_probe(target).await {
        return serde_json::json!({
            "target": target_url,
            "reachable": false,
            "error_code": crate::cmd::error_codes::CONNECTION_FAILED,
            "params_discovered": 0,
            "estimated_total_requests": 0,
            "params": [],
        });
    }

    analyze_parameters(target, scan_args, None).await;
    cap_reflection_params(target);

    let enc_factor = crate::encoding::encoder_expansion_factor(&scan_args.encoders);
    let cap = crate::scanning::effective_payload_cap(max_payloads_per_param, deep_scan);
    let apply_cap = |n: usize| -> usize { if cap == 0 { n } else { n.min(cap) } };
    let mut estimated_requests: usize = 0;
    let params: Vec<serde_json::Value> = target
        .reflection_params
        .iter()
        .map(|p| {
            // Fragment params are client-side only: the HTTP scan phase sends
            // no requests for them, so the estimate bills none (they stay
            // listed as discovered).
            let payload_count = if crate::scanning::param_is_http_scannable(p) {
                crate::scanning::estimate_param_requests(p, scan_args, enc_factor, &apply_cap)
            } else {
                0
            };
            estimated_requests = estimated_requests.saturating_add(payload_count);
            serde_json::json!({
                "name": p.name,
                "location": format!("{:?}", p.location),
                "estimated_requests": payload_count,
            })
        })
        .collect();

    serde_json::json!({
        "target": target_url,
        "reachable": true,
        "method": target.method,
        "params_discovered": params.len(),
        "estimated_total_requests": estimated_requests,
        "params": params,
    })
}

/// The OOB drain window: `blind_oob_wait`, clipped to what is left of a
/// `scan_timeout` budget (0 = unbounded). The wait counts against the budget —
/// the documented contract, and what keeps a request inside the server-wide
/// `--scan-timeout` cap. Only the wait is clipped; the final sweep and the
/// deregister still run.
fn oob_drain_wait(
    wait_secs: u64,
    scan_timeout: u64,
    elapsed: std::time::Duration,
) -> std::time::Duration {
    let wait = std::time::Duration::from_secs(wait_secs);
    match scan_timeout {
        0 => wait,
        budget => wait.min(std::time::Duration::from_secs(budget).saturating_sub(elapsed)),
    }
}

#[cfg(test)]
#[test]
fn oob_drain_wait_counts_against_scan_timeout() {
    use std::time::Duration;
    assert_eq!(
        oob_drain_wait(600, 0, Duration::from_secs(5)),
        Duration::from_secs(600)
    );
    assert_eq!(
        oob_drain_wait(600, 10, Duration::from_secs(4)),
        Duration::from_secs(6)
    );
    assert_eq!(
        oob_drain_wait(3, 10, Duration::from_secs(4)),
        Duration::from_secs(3)
    );
    assert_eq!(
        oob_drain_wait(30, 10, Duration::from_secs(12)),
        Duration::ZERO
    );
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
    // Every warning is also recorded for the job record (`Job::warnings`), not
    // only logged: a server/MCP caller never sees the operator log, so "OOB
    // never armed" or "session monitoring inactive" would otherwise read as a
    // clean scan. Shadows the parameter so every call site below does both.
    let job_warnings = std::sync::Mutex::new(Vec::<String>::new());
    let warn = |msg: &str| {
        warn(msg);
        super::push_job_warning(
            &mut job_warnings.lock().unwrap_or_else(|e| e.into_inner()),
            msg,
        );
    };
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
    // The OOB session and its poller are declared out here, assigned inside the
    // budget-scoped block, and drained *after* the budget below — so a
    // `scan_timeout` expiry can never drop the drain future mid-`finish` and
    // skip deregistration, nor make a scan whose injections all completed
    // settle `cancelled`.
    let mut oob_session: Option<Arc<crate::oob::OobSession>> = None;
    let mut oob_poller: Option<crate::oob::PollerHandle> = None;
    let reachability_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reachability_failed_for_scan = reachability_failed.clone();
    let scan_fut = crate::with_job_rate_limiter(
        args.rate_limit,
        crate::REQUEST_COUNT_JOB.scope(progress.requests_sent.clone(), async {
        crate::REQUEST_FAILURE_COUNT_JOB.scope(progress.requests_failed.clone(), async {
            crate::WAF_CONSECUTIVE_BLOCKS_JOB
                .scope(job_waf_consecutive.clone(), async {
                    // Reachability belongs to this scoped phase: its request
                    // must count toward live job progress and share the same
                    // rate-limit budget as preflight and scan requests. A
                    // cancelled job must not send the preliminary request.
                    if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    match crate::job::send_job_reachability_probe(
                        target,
                        progress,
                        cancel_flag.as_ref(),
                    )
                    .await
                    {
                        Some(true) => {}
                        Some(false) => {
                            reachability_failed_for_scan
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        None => return,
                    }
                    if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }

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

                    // Blind XSS: the static `-b` callback and/or the OOB/OAST
                    // (interactsh) channel. Start the OOB session first — it
                    // fails soft, so a registration outage warns and the scan
                    // proceeds without it. The poller is bound to THIS job's
                    // results/findings/cancel (nothing process-global), spawned
                    // below just before the scan and drained right after, so it
                    // can never outlive the job or leak across concurrent jobs.
                    if args.blind_oob_enabled() {
                        // Registration walks up to N servers × `timeout`; a
                        // cancel must not wait that out (it would also outlive
                        // the drain grace and free the job's capacity slot
                        // while this worker still runs).
                        let oob_config = args.oob_config();
                        let started = tokio::select! {
                            r = crate::oob::OobSession::start(&oob_config) => r,
                            _ = super::wait_for_cancellation(Some(cancel_flag.as_ref())) => return,
                        };
                        match started {
                            Ok(session) => {
                                // Successful arming is diagnostic, not a
                                // warning; the OOB finding is the real signal.
                                crate::dbg_log!(
                                    "OOB blind XSS armed via interactsh server: {}",
                                    session.server_domain()
                                );
                                oob_session = Some(Arc::new(session));
                            }
                            // A registration outage is surfaced on the job's
                            // warning channel so "never armed" is not mistaken
                            // for "armed, no callbacks". The scan still runs.
                            Err(e) => warn(&format!(
                                "blind_oob disabled (could not register with any server): {e}"
                            )),
                        }
                    }

                    // Blind injection source: the static `-b` callback, the OOB
                    // channel, or both. `blind_scan_forms_with` runs for every
                    // source, matching the CLI's `-b`/`--blind-oob` behavior
                    // (`cmd::scan::blind::arm_and_dispatch` injects forms for a
                    // callback-only run too).
                    let source = match (&args.blind_callback_url, &oob_session) {
                        (Some(url), Some(session)) => Some(crate::scanning::CallbackSource::Both {
                            url: url.as_str(),
                            session: session.as_ref(),
                        }),
                        (Some(url), None) => Some(crate::scanning::CallbackSource::Static(url.as_str())),
                        (None, Some(session)) => {
                            Some(crate::scanning::CallbackSource::Oob(session.as_ref()))
                        }
                        (None, None) => None,
                    };
                    // Cancelled during OOB registration (up to N servers ×
                    // timeout): do not write stored attack payloads into the
                    // target for a job nobody is waiting on.
                    let mut oob_injected = false;
                    if let Some(source) = source
                        && !cancel_flag.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        // Params × templates × channels, each paced by
                        // `delay`: a cancel mid-pass stops the stored writes.
                        let inject = async {
                            crate::scanning::blind_scanning_with(target, source, args.as_ref()).await;
                            crate::scanning::blind_scan_forms_with(target, source, args.as_ref()).await;
                        };
                        tokio::select! {
                            _ = inject => {}
                            _ = super::wait_for_cancellation(Some(cancel_flag.as_ref())) => return,
                        }
                        oob_injected = oob_session.is_some();
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

                    // Preflight GET, mirroring the CLI flow. The landing page
                    // feeds everything the CLI's preflight stores on the
                    // target before any payload is built: WAF fingerprints,
                    // CSP (bypass payloads + Trusted Types posture for the
                    // scan-phase AST), stack fingerprints (tech-specific
                    // payloads), outdated-library findings, the session
                    // baseline, and the initial AST DOM-XSS pass. The runner
                    // used to fetch it only for the AST pass and derive none
                    // of the rest, so `force_waf`, `waf_bypass`,
                    // `waf_min_confidence` and `detect_outdated_libs` were
                    // accepted over REST / MCP and silently did nothing, and
                    // a job scanned a WAF- or CSP-fronted page with fewer
                    // payloads than the CLI would for the same target.
                    let client = target.build_client_or_default();
                    let mut waf_seed = crate::waf::WafDetectionResult::default();
                    // The landing page's own status, the WAF probe's baseline
                    // (see `fingerprint_with_probe`).
                    let mut baseline_status: Option<u16> = None;
                    // Mirror the CLI preflight: carry the target's
                    // headers/cookies/User-Agent (so auth/header/UA-gated
                    // SPAs are analyzed logged-in, matching CLI findings —
                    // a bare GET dropped them and analyzed the logged-out
                    // page) and cap the body with `Range: 0-8191` so a large
                    // response can't buffer unbounded into server memory.
                    let preflight =
                        crate::utils::build_preflight_request(&client, target, false, Some(8192));
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
                        let response_content_type = resp_headers
                            .get(reqwest::header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("");
                        // Captured before `read_body` consumes the response.
                        // Under `follow_redirects` this is where the chain
                        // actually ended, which is the only thing a session
                        // baseline can meaningfully compare against.
                        let resp_status = resp.status().as_u16();
                        baseline_status = Some(resp_status);
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

                            waf_seed = crate::waf::fingerprint_from_response(
                                &resp_headers,
                                Some(&body),
                                resp_status,
                            );
                            let tech = crate::scanning::tech_detect::detect_technologies(
                                &resp_headers,
                                Some(&body),
                            );
                            if !tech.is_empty() {
                                target.tech_info = Some(tech);
                            }
                            if let Some((name, policy)) =
                                crate::scanning::csp_header_from_response(&resp_headers, &body)
                            {
                                target.csp_analysis = Some(
                                    crate::payload::xss_csp_bypass::analyze_csp_from(
                                        &name, &policy,
                                    ),
                                );
                            }

                            crate::cmd::scan::detect_outdated_libs(
                                target,
                                args.as_ref(),
                                Some(&body),
                                &results,
                                &findings_count,
                            )
                            .await;

                            // Initial AST DOM-XSS pass on the GET response.
                            // Server used to skip this because it didn't run
                            // preflight, so identical targets reported 0
                            // findings via API even when CLI saw multiple
                            // DOM-XSS sinks (e.g. xss-game level3 with
                            // location.hash → html).
                            if !args.skip_ast_analysis {
                                let posture =
                                    crate::scanning::ast_integration::PageSecurityPosture::from_target(
                                        target,
                                    );
                                let ast_batch =
                                    crate::scanning::ast_integration::run_initial_ast_dom_analysis_for_response(
                                        &body,
                                        response_content_type,
                                        target.url.as_str(),
                                        &target.method,
                                        posture,
                                    );
                                crate::scanning::accumulate_findings(
                                    &results,
                                    &findings_count,
                                    ast_batch,
                                    &args.limit_count_filter(),
                                    args.min_confidence.as_deref(),
                                )
                                .await;
                                if crate::utils::response_has_markup_document(
                                    response_content_type,
                                    &body,
                                ) {
                                    let ext_batch =
                                        crate::scanning::fetch_and_analyze_external_js(
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
                                        &args.limit_count_filter(),
                                        args.min_confidence.as_deref(),
                                    )
                                    .await;
                                }
                            }
                        }
                    }

                    // Probe / `force_waf` / `waf_min_confidence`, then the
                    // same target state the CLI preflight sets from them.
                    let waf =
                        crate::cmd::scan::finish_waf_detection(
                            waf_seed,
                            baseline_status,
                            target,
                            &client,
                            &args,
                        )
                            .await;
                    if !waf.is_empty() {
                        if args.waf_bypass != "off" {
                            let strategy =
                                crate::waf::bypass::merge_strategies(&waf.waf_types());
                            // Pace the injection paths for rate-limiting WAFs.
                            target.waf_extra_delay_ms = strategy.extra_delay_hint_ms;
                            target.mutation_stats =
                                Some(Arc::new(crate::waf::bypass::MutationStats::default()));
                        }
                        target.waf_info = Some(waf);
                    }

                    // `--session-check-url` needs its baseline from that
                    // endpoint rather than from the target, and a failed
                    // preflight left nothing to reuse. Either way pay for one
                    // request — but only for a job that actually has a session.
                    if monitor_session && session_baseline.is_none() {
                        session_baseline =
                            crate::cmd::scan::session::capture_baseline(target, &args).await;
                    }
                    // An explicit `session_check` / `session_check_url` whose
                    // baseline could not be captured (unreachable probe URL,
                    // failed preflight) means the monitoring the caller asked
                    // for is NOT running — surface it rather than let a silent
                    // unmonitored scan read as a monitored one (mirrors the
                    // CLI's scan_loop warning).
                    if session_baseline.is_none()
                        && (args.session_check.is_some() || args.session_check_url.is_some())
                    {
                        warn(
                            "session_check requested but no baseline could be captured; \
                             session-loss monitoring is INACTIVE for this scan",
                        );
                    }
                    // Credentials that were already dead when the job started:
                    // no later probe can detect a *change* from that baseline,
                    // so it is recorded now rather than settling as `done`.
                    session_lost = session_baseline
                        .as_ref()
                        .and_then(crate::cmd::scan::session::baseline_warning);
                    // The CLI's print-only `SESSION?` heads-up; a silenced job
                    // has no stderr, so it goes on the warning channel.
                    if let Some(note) = session_baseline
                        .as_ref()
                        .and_then(crate::cmd::scan::session::baseline_advisory)
                    {
                        warn(&note);
                    }

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

                    // Spawn the job's OOB poller now, so callbacks that fire
                    // mid-scan land in `results` as they arrive. Only when OOB
                    // payloads were actually injected (not a callback-only run,
                    // not a run cancelled during registration). Silenced
                    // (server/MCP never write the CLI's live stderr line), and
                    // tied to this job's cancel flag — set by cancel/delete or
                    // by `scan_timeout` — so it stops when the job does. The
                    // poller drains *after* the budget (below), not here.
                    if oob_injected && let Some(session) = &oob_session {
                        oob_poller = Some(crate::oob::spawn_poller(
                            session.clone(),
                            results.clone(),
                            findings_count.clone(),
                            &args.limit_count_filter(),
                            cancel_flag.clone(),
                            true,
                        ));
                    }

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
    let scan_started = std::time::Instant::now();
    let timed_out = run_within_scan_budget(args.scan_timeout, &cancel_flag, scan_fut).await;

    // Drain late OOB callbacks and deregister — OUTSIDE the budget, so a
    // `scan_timeout` expiry cannot drop this future mid-`finish` (which would
    // skip the final poll and the deregister) and a scan whose injections all
    // completed is not retroactively marked `cancelled` by drain time. A
    // tripped cancel flag still cuts the grace window short inside `finish`.
    // The poll traffic goes to the OAST server, not the target, so it is
    // correctly outside the per-target rate-limit / request-count scopes too.
    if let Some(poller) = oob_poller.take() {
        // Nothing injected over OOB ⇒ nothing can call back ⇒ no wait, just a
        // final sweep and deregister.
        let grace = if oob_session
            .as_ref()
            .is_some_and(|s| s.registry().is_empty())
        {
            std::time::Duration::ZERO
        } else {
            oob_drain_wait(
                args.blind_oob_wait(),
                args.scan_timeout,
                scan_started.elapsed(),
            )
        };
        // The poller is silenced here, so what it would have printed goes on
        // the job's warning channel: a dead OAST poll path is not a clean scan.
        for w in poller.finish(grace).await {
            warn(&w);
        }
    } else if let Some(session) = &oob_session {
        // Registered but never polled (e.g. cancelled during registration):
        // still release the session so it is not left armed on the server.
        session.deregister().await;
    }

    // Stop the live mirror and wait for it to finish, so a store already in
    // flight cannot land after `sanitized_results` publishes the settled tally.
    let mut findings_updater = findings_updater;
    findings_updater.0.abort();
    let _ = (&mut findings_updater.0).await;
    drop(findings_updater);

    let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);
    // A worker-task panic means at least one parameter's findings are
    // incomplete. Surface that as `error` (with the partial results still
    // attached) so a poller can't mistake a crashed scan for a clean `done`.
    // Cancellation takes precedence (it's already a partial-by-design state).
    let panicked = !was_cancelled && scan_report.worker_panics > 0;

    if !was_cancelled && !panicked && !scan_report.limit_stopped {
        // After a clean, complete run every discovered parameter was processed
        // by `run_scanning`, so pin `params_tested` to `params_total` (exactly
        // 100%). Skip this on cancellation, a findings-cap stop, AND on a
        // worker panic: all three stop
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
        reachability_failed: reachability_failed.load(std::sync::atomic::Ordering::Relaxed),
        worker_panics: scan_report.worker_panics,
        timed_out,
        was_cancelled,
        panicked,
        session_lost,
        findings_capped: scan_report.limit_stopped,
        warnings: std::mem::take(&mut *job_warnings.lock().unwrap_or_else(|e| e.into_inner())),
        min_confidence: args.min_confidence.clone(),
    }
}
