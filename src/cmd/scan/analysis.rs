//! Preflight + parameter-analysis stage. For every target (bounded by
//! `--max-concurrent-targets`) this runs the content-type/CSP/WAF preflight,
//! parameter discovery + mining, and initial-response AST DOM analysis,
//! replacing each host group with the targets that survived preflight. Lifted
//! verbatim out of `run_scan`; the shared handles arrive via [`ScanState`].

use super::ScanState;
use super::args::ScanArgs;
use super::logging::start_spinner;
use super::preflight::{PreflightOutcome, is_allowed_content_type, preflight_content_type};
use super::session::SessionBaseline;
use crate::parameter_analysis::analyze_parameters;
use crate::target_parser::Target;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::task::LocalSet;

/// File the authenticated-state baseline for `target`, and decide up front
/// whether it is usable at all.
///
/// An unusable baseline — stale credentials, or a `--session-check` marker that
/// never matched — is recorded as a real `SESSION_LOST`, not merely logged.
/// From such a baseline no later probe can ever detect a *change*, so without
/// this the run ends `"status": "clean"`, `"incomplete": false`, exit 0: the
/// exact silent false negative issue #1273 is about, just moved one step
/// earlier. Marking it here routes the case through the same reporting the
/// mid-scan probes use, and `SessionMonitor::check` then skips probing a target
/// already known to be lost.
///
/// The target is still scanned. At preflight we cannot tell "the credentials
/// expired" from "this page legitimately renders a login form", and a login
/// page can carry reflected XSS of its own — the exit code and `incomplete`
/// flag are what make the run honest, not refusing to look.
async fn record_session_baseline(
    args: &ScanArgs,
    target: &Target,
    baseline: SessionBaseline,
    session_baselines: &Arc<Mutex<HashMap<String, SessionBaseline>>>,
    session_lost: &Arc<Mutex<HashMap<String, String>>>,
) {
    if let Some(reason) = super::session::baseline_warning(&baseline) {
        if !args.silence {
            super::session::report_loss(
                target.url.as_str(),
                &reason,
                super::session::aborts_on_loss(args),
            );
        }
        session_lost
            .lock()
            .await
            .insert(target.url.to_string(), reason);
    } else if let Some(note) = super::session::baseline_advisory(&baseline)
        && !args.silence
    {
        // Print-only: the baseline is ambiguous, not condemned. See
        // `session::baseline_advisory` for why this one does not become a
        // `SESSION_LOST` entry.
        super::session::report_baseline_advisory(target.url.as_str(), &note);
    }
    session_baselines
        .lock()
        .await
        .insert(target.url.to_string(), baseline);
}

pub(crate) async fn run_preflight_and_analysis(
    args: &ScanArgs,
    host_groups: &mut std::collections::BTreeMap<String, Vec<Target>>,
    state: &ScanState,
) {
    // Rebind the shared state to owned locals so the loop body below is
    // identical to the pre-split `run_scan` (it threads these through nested
    // `spawn_local` tasks via `.clone()`).
    let results = state.results.clone();
    let findings_count = state.findings_count.clone();
    let skipped_targets = state.skipped_targets.clone();
    let target_meta = state.target_meta.clone();
    let target_mutation_stats = state.target_mutation_stats.clone();
    let session_baselines = state.session_baselines.clone();
    let session_lost = state.session_lost.clone();
    let multi_pb = state.multi_pb.clone();
    let preflight_idx = state.preflight_idx.clone();
    let analyze_idx = state.analyze_idx.clone();
    let total_targets = state.total_targets;
    let spinner_allowed = state.spinner_allowed;

    for group in host_groups.values_mut() {
        // Limit targets per host. Targets above the cap aren't silently dropped
        // — record them in skipped_targets so target_summary surfaces the skip
        // with the TRUNCATED_PER_HOST_CAP error code instead of "clean".
        if group.len() > args.max_targets_per_host {
            let dropped: Vec<String> = group
                .iter()
                .skip(args.max_targets_per_host)
                .map(|t| t.url.to_string())
                .collect();
            if !dropped.is_empty() {
                if !args.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    crate::ceprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[33mWARN\x1b[0m max-targets-per-host cap ({}) reached; {} target(s) skipped",
                        ts,
                        args.max_targets_per_host,
                        dropped.len()
                    );
                }
                let mut guard = skipped_targets.lock().await;
                for url in dropped {
                    guard.insert(url, crate::cmd::error_codes::TRUNCATED_PER_HOST_CAP);
                }
            }
            group.truncate(args.max_targets_per_host);
        }

        // Bound overall concurrency for preflight + analysis with the same cap as scanning
        let pre_analyze_semaphore = Arc::new(tokio::sync::Semaphore::new(
            crate::utils::semaphore_permits(args.max_concurrent_targets),
        ));

        // Move targets out of the group to own them in spawned tasks
        let mut drained: Vec<Target> = Vec::new();
        drained.append(group);

        let processed: Vec<Target> = {
            let local = LocalSet::new();
            // Clone shared indices and config for this LocalSet to avoid moving them
            let preflight_idx_outer = preflight_idx.clone();
            let analyze_idx_outer = analyze_idx.clone();
            let args_outer = args.clone();
            let pre_analyze_semaphore_outer = pre_analyze_semaphore.clone();
            let total_targets_outer = total_targets;
            let multi_pb_outer = multi_pb.clone();
            let results_outer = results.clone();
            let findings_count_outer = findings_count.clone();
            let skipped_targets_outer = skipped_targets.clone();
            let target_meta_outer = target_meta.clone();
            let target_mutation_stats_outer = target_mutation_stats.clone();
            let session_baselines_outer = session_baselines.clone();
            let session_lost_outer = session_lost.clone();
            local
                .run_until(async move {
                    let mut handles = vec![];

                    for target in drained {
                        // Kept outside the task so a panicking task can still be reported
                        // against its target instead of vanishing (see the collector).
                        let panic_target_url = target.url.to_string();
                        let ctx = TargetTaskCtx {
                            args_clone: args_outer.clone(),
                            sem: pre_analyze_semaphore_outer.clone(),
                            preflight_idx_clone: preflight_idx_outer.clone(),
                            analyze_idx_clone: analyze_idx_outer.clone(),
                            total_targets_copy: total_targets_outer,
                            spinner_allowed,
                            multi_pb_clone: multi_pb_outer.clone(),
                            results_clone: results_outer.clone(),
                            findings_count_clone: findings_count_outer.clone(),
                            skipped_targets_clone: skipped_targets_outer.clone(),
                            target_meta_clone: target_meta_outer.clone(),
                            target_mutation_stats_clone: target_mutation_stats_outer.clone(),
                            session_baselines_clone: session_baselines_outer.clone(),
                            session_lost_clone: session_lost_outer.clone(),
                        };

                        handles.push((
                            panic_target_url,
                            tokio::task::spawn_local(preflight_and_analyze_target(target, ctx)),
                        ));
                    }

                    // Collect processed targets (skipping those filtered by preflight)
                    let mut processed: Vec<Target> = Vec::new();
                    for (target_url, handle) in handles {
                        match handle.await {
                            Ok(Some(t)) => processed.push(t),
                            // Preflight deliberately dropped this target; it has
                            // already recorded its own `skipped_targets` entry.
                            Ok(None) => {}
                            // A panic in here used to be swallowed whole: the
                            // target silently disappeared from `processed`, never
                            // reached the injection stage, and the run finished
                            // `0 XSS` with exit 0 — a scanner reporting "clean" for
                            // a target it crashed on. Surface it and record the
                            // target as skipped so `target_summary` says
                            // INTERNAL_ERROR instead of clean. The injection
                            // stage in `scan_loop.rs` does the same.
                            Err(e) => {
                                // Sanitized: a `JoinError`'s Display carries the
                                // panic message, and panic messages quote the data
                                // that caused them — a slice-boundary panic embeds
                                // bytes straight from the scanned response. A raw
                                // CR/LF there would let a target forge log lines.
                                eprintln!(
                                    "[scan] preflight/analysis task failed for {}: {}",
                                    crate::utils::log::sanitize_log_message(&target_url),
                                    crate::utils::log::sanitize_log_message(&e.to_string())
                                );
                                skipped_targets_outer
                                    .lock()
                                    .await
                                    .insert(target_url, crate::cmd::error_codes::INTERNAL_ERROR);
                            }
                        }
                    }
                    processed
                })
                .await
        };

        // Replace group with processed targets
        *group = processed;
    }
}

/// The per-target handles the preflight/analysis task needs.
///
/// Bundled rather than passed positionally: the task body used to capture
/// fourteen separately-cloned locals, and every new one meant another
/// `let x_clone = x_outer.clone();` line at the spawn site. `Clone` here is a
/// handful of refcount bumps, the same cost as before.
#[derive(Clone)]
pub(crate) struct TargetTaskCtx {
    pub(crate) args_clone: ScanArgs,
    pub(crate) sem: Arc<tokio::sync::Semaphore>,
    pub(crate) preflight_idx_clone: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) analyze_idx_clone: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) total_targets_copy: usize,
    pub(crate) spinner_allowed: bool,
    pub(crate) multi_pb_clone: Option<Arc<indicatif::MultiProgress>>,
    pub(crate) results_clone: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    pub(crate) findings_count_clone: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) skipped_targets_clone: Arc<Mutex<HashMap<String, &'static str>>>,
    pub(crate) target_meta_clone: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    pub(crate) target_mutation_stats_clone:
        Arc<Mutex<HashMap<String, Arc<crate::waf::bypass::MutationStats>>>>,
    pub(crate) session_baselines_clone: Arc<Mutex<HashMap<String, SessionBaseline>>>,
    pub(crate) session_lost_clone: Arc<Mutex<HashMap<String, String>>>,
}

/// Preflight one target and analyze its parameters, returning it enriched — or
/// `None` when preflight dropped it (unreachable, content-type mismatch, …),
/// in which case the reason has been recorded in `skipped_targets`.
pub(crate) async fn preflight_and_analyze_target(
    mut target: Target,
    ctx: TargetTaskCtx,
) -> Option<Target> {
    let TargetTaskCtx {
        args_clone,
        sem,
        preflight_idx_clone,
        analyze_idx_clone,
        total_targets_copy,
        spinner_allowed,
        multi_pb_clone,
        results_clone,
        findings_count_clone,
        skipped_targets_clone,
        target_meta_clone,
        target_mutation_stats_clone,
        session_baselines_clone,
        session_lost_clone,
    } = ctx;
    // Bound concurrency across targets for preflight + analysis
    let Ok(_permit) = sem.acquire_owned().await else {
        return None;
    };
    let PreflightCapture {
        csp_present: __preflight_csp_present,
        csp_header: __preflight_csp_header,
        response_body: preflight_response_body,
    } = run_target_preflight(
        &mut target,
        &args_clone,
        &preflight_idx_clone,
        total_targets_copy,
        spinner_allowed,
        &skipped_targets_clone,
        &target_meta_clone,
        &target_mutation_stats_clone,
        &session_baselines_clone,
        &session_lost_clone,
    )
    .await?;

    // Pretty start log per target (plain only)
    if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
        if total_targets_copy > 1 {
            let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(target.url.as_ref()));
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            crate::cprintln!(
                "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} start scan to {}",
                ts,
                sid,
                target.url
            );
        } else {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            crate::cprintln!(
                "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m start scan to {}",
                ts,
                target.url
            );
            if __preflight_csp_present {
                crate::cprintln!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m CSP: enabled", ts);
                if let Some((hn, hv)) = &__preflight_csp_header {
                    crate::cprintln!(
                        "  \x1b[90m└──\x1b[0m \x1b[38;5;247m{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m",
                        hn,
                        hv
                    );
                }
            }
            // Log WAF detection
            if let Some(ref waf_info) = target.waf_info {
                for fp in &waf_info.detected {
                    crate::cprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[33mWAF\x1b[0m {} detected (confidence: {:.0}%, evidence: {})",
                        ts,
                        fp.waf_type,
                        fp.confidence * 100.0,
                        fp.evidence
                    );
                }
                if args_clone.waf_bypass != "off" {
                    let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
                    let strategy = crate::waf::bypass::merge_strategies(&waf_types);
                    if !strategy.extra_encoders.is_empty() {
                        crate::cprintln!(
                            "  \x1b[90m└──\x1b[0m \x1b[38;5;247mbypass encoders: {}\x1b[0m",
                            strategy.extra_encoders.join(", ")
                        );
                    }
                    if !strategy.mutations.is_empty() {
                        crate::cprintln!(
                            "  \x1b[90m└──\x1b[0m \x1b[38;5;247mbypass mutations: {} types\x1b[0m",
                            strategy.mutations.len()
                        );
                    }
                }
            }
            // Log detected technologies
            if let Some(ref tech_info) = target.tech_info {
                let tech_names: Vec<String> = tech_info
                    .detected
                    .iter()
                    .map(|d| format!("{}", d.tech))
                    .collect();
                if !tech_names.is_empty() {
                    crate::cprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m tech: {}",
                        ts,
                        tech_names.join(", ")
                    );
                }
            }
        }
    }

    // Silence parameter analysis logs and progress; show spinner for single-target runs.
    // When multi_pb_clone is active, analyze_parameters renders its own indicatif
    // spinner via that MultiProgress — skip the stdout spinner so we don't double up.
    let current = analyze_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
    let __analyze_spinner = if total_targets_copy == 1 && multi_pb_clone.is_none() {
        start_spinner(
            spinner_allowed,
            !args_clone.silence,
            if total_targets_copy > 1 {
                format!(
                    "[{}/{}] analyzing: {}",
                    current, total_targets_copy, target.url
                )
            } else {
                format!("analyzing: {}", target.url)
            },
        )
    } else {
        None
    };
    let mut __analysis_args = args_clone.clone();
    __analysis_args.silence = true;
    if let Some(ref marker) = args_clone.inject_marker {
        // Custom injection marker mode: skip normal discovery/mining
        // and create params from marker positions in URL/headers/body
        use crate::parameter_analysis::{Location, Param};
        let mut marker_params = Vec::new();

        // Check URL query params
        for (k, v) in target.url.query_pairs() {
            if v.contains(marker.as_str()) {
                marker_params.push(Param::new(k.to_string(), v.to_string(), Location::Query));
            }
        }

        // Check body params
        if let Some(ref data) = target.data {
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(obj) = json_val.as_object() {
                    for (k, v) in obj {
                        if let Some(s) = v.as_str()
                            && s.contains(marker.as_str())
                        {
                            marker_params.push(Param::new(
                                k.clone(),
                                s.to_string(),
                                Location::JsonBody,
                            ));
                        }
                    }
                }
            } else {
                for pair in data.split('&') {
                    if let Some((k, v)) = pair.split_once('=')
                        && v.contains(marker.as_str())
                    {
                        marker_params.push(Param::new(
                            k.to_string(),
                            v.to_string(),
                            Location::Body,
                        ));
                    }
                }
            }
        }

        // Check headers
        for (k, v) in &target.headers {
            if v.contains(marker.as_str()) {
                marker_params.push(Param::new(k.clone(), v.clone(), Location::Header));
            }
        }

        // Check cookies
        for (k, v) in &target.cookies {
            if v.contains(marker.as_str()) {
                marker_params.push(Param::new(k.clone(), v.clone(), Location::Header));
            }
        }

        target.reflection_params = marker_params;
    } else {
        analyze_parameters(&mut target, &__analysis_args, multi_pb_clone).await;
    }
    if let Some((tx, done_rx)) = __analyze_spinner {
        let _ = tx.send(());
        let _ = done_rx.await;
    }

    detect_outdated_libs(
        &target,
        &args_clone,
        preflight_response_body.as_ref(),
        &results_clone,
        &findings_count_clone,
    )
    .await;

    run_initial_ast_pass(
        &target,
        &args_clone,
        preflight_response_body.as_ref(),
        &results_clone,
        &findings_count_clone,
    )
    .await;

    // Pretty reflection summary (plain only)
    if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
        let n = target.reflection_params.len();
        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
        if total_targets_copy > 1 {
            let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(target.url.as_ref()));
            crate::cprintln!(
                "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} found reflected \x1b[33m{}\x1b[0m params",
                ts,
                sid,
                n
            );
        } else {
            crate::cprintln!(
                "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m found reflected \x1b[33m{}\x1b[0m params",
                ts,
                n
            );
        }
        for (i, p) in target.reflection_params.iter().enumerate() {
            let bullet = if i + 1 == n { "└──" } else { "├──" };
            let valid = p
                .valid_specials
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
            let invalid = p
                .invalid_specials
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
            crate::cprintln!(
                "  \x1b[90m{}\x1b[0m \x1b[38;5;247m{}\x1b[0m \x1b[38;5;247mvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\" \x1b[38;5;247minvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\"",
                bullet,
                p.name,
                valid,
                invalid
            );
        }
        // Debug: estimate total test cases (requests) to be run during scanning
        if crate::DEBUG.load(Ordering::Relaxed)
            && args_clone.format == "plain"
            && !args_clone.silence
        {
            // Encoder expansion factor, taken from the encoder pipeline so it
            // can't drift from the expansion the scan actually performs.
            let enc_factor = crate::encoding::encoder_expansion_factor(&args_clone.encoders);
            // Match the scan-time effective cap so the preflight
            // request estimate reflects the built-in safety cap.
            let cap = crate::scanning::effective_payload_cap(
                args_clone.max_payloads_per_param,
                args_clone.deep_scan,
            );
            let apply_cap = |n: usize| -> usize { if cap == 0 { n } else { n.min(cap) } };
            let mut total: usize = 0;
            for p in &target.reflection_params {
                // Scan loop is additive (one reflection request + one DOM request
                // per payload), not cartesian, and each half is capped
                // separately — mirrored by the shared estimator, which the REST
                // `/preflight` endpoint and the MCP preflight tool also use so
                // the three can't quote different numbers for the same target.
                // WAF mutation/encoder expansion isn't reflected there yet, so
                // this remains a lower bound.
                total = total.saturating_add(crate::scanning::estimate_param_requests(
                    p,
                    &args_clone,
                    enc_factor,
                    &apply_cap,
                ));
            }
            if args_clone.format == "plain" && !args_clone.silence {
                crate::dbg_log!("{} test cases (reqs) estimated", total);
            }
        }
    }

    Some(target)
}

/// What the preflight probe captured for one target, beyond the enrichment it
/// writes straight onto the `Target` (WAF, CSP, tech, mutation stats).
pub(crate) struct PreflightCapture {
    /// A CSP was present on the response (header or `<meta>`).
    pub(crate) csp_present: bool,
    /// The CSP the response carried, as `(header-name, value)` — *not*
    /// necessarily an enforcing one. `preflight` fills this from
    /// `content-security-policy-report-only` too, and synthesizes a name for a
    /// `<meta>`-sourced policy. The consumer re-checks the name for exactly
    /// that reason: treating a report-only `require-trusted-types-for` as
    /// enforcing would suppress Trusted Types findings that do fire.
    pub(crate) csp_header: Option<(String, String)>,
    /// The landing-page body, reused by the AST DOM pass so it is fetched once.
    pub(crate) response_body: Option<String>,
}

/// Fetch the landing page once and derive everything the later phases need from
/// it: content-type gating, CSP, WAF fingerprint, and technology detection.
///
/// `None` means this target is out — unreachable, or a content type the scan
/// does not apply to — and the reason has already been recorded in
/// `skipped_targets`. Runs for every scan, `--deep-scan` included.
#[allow(clippy::too_many_arguments)]
async fn run_target_preflight(
    target: &mut Target,
    args_clone: &ScanArgs,
    preflight_idx_clone: &Arc<std::sync::atomic::AtomicUsize>,
    total_targets_copy: usize,
    spinner_allowed: bool,
    skipped_targets_clone: &Arc<Mutex<HashMap<String, &'static str>>>,
    target_meta_clone: &Arc<Mutex<HashMap<String, serde_json::Value>>>,
    target_mutation_stats_clone: &Arc<
        Mutex<HashMap<String, Arc<crate::waf::bypass::MutationStats>>>,
    >,
    session_baselines_clone: &Arc<Mutex<HashMap<String, SessionBaseline>>>,
    session_lost_clone: &Arc<Mutex<HashMap<String, String>>>,
) -> Option<PreflightCapture> {
    let mut __preflight_csp_present = false;
    let mut __preflight_csp_header: Option<(String, String)> = None;
    let mut preflight_response_body: Option<String> = None;
    // Preflight probe: fetch the landing page for content-type, CSP,
    // WAF, and tech detection, and capture the body (which feeds the
    // initial AST DOM-XSS pass and outdated-lib detection below).
    // This runs for EVERY scan, including `--deep-scan`. `--deep-scan`
    // only lifts the per-parameter payload cap and the content-type
    // *denylist skip* (gated below) — it must NOT skip the preflight
    // itself. Wrapping the whole probe in `if !deep_scan` silently
    // disabled WAF fingerprinting/bypass, CSP-bypass, tech detection,
    // and the initial-response AST DOM analysis under `--deep-scan`,
    // making the "more thorough" mode strictly weaker.
    {
        let current = preflight_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
        // Print an ephemeral spinner and auto-clear when finished
        let label = if total_targets_copy > 1 {
            format!(
                "[{}/{}] preflight: {}",
                current, total_targets_copy, target.url
            )
        } else {
            format!("preflight: {}", target.url)
        };
        let __preflight_spinner = if total_targets_copy == 1 {
            start_spinner(spinner_allowed, !args_clone.silence, label)
        } else {
            None
        };

        let __preflight_info = preflight_content_type(target, args_clone).await;
        if let Some((tx, done_rx)) = __preflight_spinner {
            let _ = tx.send(());
            let _ = done_rx.await;
        }

        let __preflight_info = match __preflight_info {
            PreflightOutcome::Unreachable(code) => {
                // Hard reachability failure (DNS, TCP refused,
                // TLS handshake timeout). preflight_content_type
                // already surfaced the UNREACHABLE diagnostic.
                // Mark the target as skipped with the *specific*
                // error_code we classified — DNS_RESOLUTION_FAILED
                // vs TLS_HANDSHAKE_FAILED vs REQUEST_TIMEOUT vs
                // CONNECTION_FAILED — so target_summary tells
                // ops *which* layer broke instead of lumping.
                skipped_targets_clone
                    .lock()
                    .await
                    .insert(target.url.to_string(), code);
                return None;
            }
            // NoContentType (e.g. GET preflight on a POST-only
            // endpoint that 405s without a Content-Type header)
            // — keep scanning, just skip the preflight metadata
            // population below. Preserves the v3.0 behavior
            // that body-param scans of /post-only endpoints
            // still work. The session baseline is the one piece
            // that must survive: the target still gets scanned, so
            // it still has a session that can die mid-run.
            PreflightOutcome::NoContentType(baseline) => {
                if let Some(baseline) = baseline {
                    record_session_baseline(
                        args_clone,
                        target,
                        baseline,
                        session_baselines_clone,
                        session_lost_clone,
                    )
                    .await;
                }
                None
            }
            PreflightOutcome::WithContentType(r) => Some(r),
        };

        if let Some(preflight) = __preflight_info {
            preflight_response_body = preflight.response_body;
            // Authenticated-state fingerprint for mid-scan
            // session-loss detection. Present only when the target
            // carries credentials (or the operator asked for a
            // check explicitly).
            if let Some(baseline) = preflight.session_baseline {
                record_session_baseline(
                    args_clone,
                    target,
                    baseline,
                    session_baselines_clone,
                    session_lost_clone,
                )
                .await;
            }
            if let Some((hn, hv)) = preflight.csp_header {
                __preflight_csp_present = true;
                // Analyze CSP and store on target for bypass payload generation
                let mut csp = crate::payload::xss_csp_bypass::analyze_csp(&hv);
                // A report-only CSP enforces nothing — it only emits
                // violation reports — so `require-trusted-types-for`
                // there must not drive Trusted Types suppression in
                // the AST analyzer (that would be a false negative).
                // Bypass-payload fields stay as parsed.
                if !hn.eq_ignore_ascii_case("content-security-policy") {
                    csp.report_only = true;
                    csp.require_trusted_types_for = false;
                }
                if crate::DEBUG.load(Ordering::Relaxed) {
                    let class = if csp.is_hardened() {
                        "hardened (nonce/hash-only)"
                    } else if csp.is_gadget_bypassable() {
                        "gadget-bypassable"
                    } else {
                        "no script-execution bypass surface"
                    };
                    crate::ceprintln!(
                        "[csp] {} classified {} (strict-dynamic={}, nonces={}, trusted-types-enforced={})",
                        hn,
                        class,
                        csp.has_strict_dynamic,
                        csp.nonce_values.len(),
                        csp.require_trusted_types_for
                    );
                }
                target.csp_analysis = Some(csp);
                __preflight_csp_header = Some((hn, hv));
            }
            // Store WAF detection result on target
            if !preflight.waf_result.is_empty() {
                target.waf_info = Some(preflight.waf_result);
                // Allocate per-target effectiveness counters when
                // bypass is going to run; the scanning loop and
                // check_reflection both update this Arc, and the
                // target_mutation_stats side-map keeps it alive
                // until target_summary is built.
                if args_clone.waf_bypass != "off" {
                    let stats = std::sync::Arc::new(crate::waf::bypass::MutationStats::default());
                    target.mutation_stats = Some(stats.clone());
                    target_mutation_stats_clone
                        .lock()
                        .await
                        .insert(target.url.to_string(), stats);
                }

                // Snapshot WAF + applied bypass for target_summary
                // (JSON/JSONL output). Plain mode logs the same
                // info to the console below; JSON consumers
                // would otherwise have no visibility.
                let mut detected_waf_extra_delay_ms = 0u64;
                if let Some(ref waf_info) = target.waf_info {
                    let detected_json: Vec<serde_json::Value> = waf_info
                        .detected
                        .iter()
                        .map(|fp| {
                            serde_json::json!({
                                "type": fp.waf_type.to_string(),
                                "confidence": fp.confidence,
                                "evidence": fp.evidence,
                            })
                        })
                        .collect();
                    let mut meta_json = serde_json::json!({
                        "detected": detected_json,
                    });
                    if args_clone.waf_bypass != "off" {
                        let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
                        let strategy = crate::waf::bypass::merge_strategies(&waf_types);
                        // Carry the per-WAF pacing hint onto the target so the
                        // injection paths actually slow down for rate-limiting
                        // WAFs — previously this only landed in JSON meta.
                        detected_waf_extra_delay_ms = strategy.extra_delay_hint_ms;
                        meta_json["bypass"] = serde_json::json!({
                            "encoders": strategy.extra_encoders,
                            "mutation_count": strategy.mutations.len(),
                            "extra_delay_hint_ms": strategy.extra_delay_hint_ms,
                        });
                    }
                    target_meta_clone
                        .lock()
                        .await
                        .insert(target.url.to_string(), meta_json);
                }

                // Apply the WAF pacing hint so detected rate-limiting
                // WAFs slow the injection cadence even without
                // --waf-evasion (0 when no WAF / --waf-bypass off).
                target.waf_extra_delay_ms = detected_waf_extra_delay_ms;

                // Adaptive WAF evasion: randomized inter-request jitter
                // plus an escalating cooldown on block clusters, applied
                // in the injection paths via `args.waf_evasion` and
                // `target.waf_extra_delay_ms`. This replaces the old blunt
                // workers=1 / delay=3000 preset, which throttled far harder
                // than necessary and was trivially fingerprintable.
                if args_clone.waf_evasion && !args_clone.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    crate::cprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[33mWAF\x1b[0m evasion activated: adaptive jitter + cooldown",
                        ts
                    );
                }
            }
            // Store technology detection result on target
            if !preflight.tech_result.is_empty() {
                target.tech_info = Some(preflight.tech_result);
            }
            // Content-type denylist skip stays gated on !deep_scan:
            // `--deep-scan` deliberately scans every content type,
            // whereas a normal scan drops denylisted types (images,
            // fonts, etc.) that can't carry reflected/DOM XSS.
            if !args_clone.deep_scan && !is_allowed_content_type(&preflight.content_type) {
                // Skip this target early
                skipped_targets_clone.lock().await.insert(
                    target.url.to_string(),
                    crate::cmd::error_codes::CONTENT_TYPE_MISMATCH,
                );
                return None;
            }
        }
    }

    Some(PreflightCapture {
        csp_present: __preflight_csp_present,
        csp_header: __preflight_csp_header,
        response_body: preflight_response_body,
    })
}

/// `--detect-outdated-libs` (opt-in): flag known-vulnerable JS libraries on the
/// landing page as informational (CWE-1104) findings.
async fn detect_outdated_libs(
    target: &Target,
    args_clone: &ScanArgs,
    preflight_response_body: Option<&String>,
    results_clone: &Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    findings_count_clone: &Arc<std::sync::atomic::AtomicUsize>,
) {
    // Outdated / known-vulnerable JS library detection (issue #1074).
    // OPT-IN (`--detect-outdated-libs`, default off): dalfox's default
    // output is verified XSS, so this informational (CWE-1104) add-on
    // is gated behind a flag. Emits once per target from the initial
    // response; borrows the body so the AST block below can still use it.
    if args_clone.detect_outdated_libs
        && let Some(body) = preflight_response_body
    {
        let lib_findings = crate::scanning::vuln_libs::library_findings(
            crate::scanning::vuln_libs::detect_vulnerable_libraries(body),
            target.url.as_str(),
            &target.method,
        );
        if !lib_findings.is_empty() {
            // Count only findings matching --limit-result-type so a
            // CWE-1104 (informational) batch can't trip --limit when
            // the user is limiting on a different result type.
            let added = crate::scanning::count_matching_results(
                &lib_findings,
                &args_clone.limit_result_type.to_uppercase(),
            );
            let mut guard = results_clone.lock().await;
            guard.extend(lib_findings);
            findings_count_clone.fetch_add(added, Ordering::Relaxed);
        }
    }
}

/// Run the AST DOM-XSS pass over the landing page captured by preflight.
///
/// CLI-only. The analyzer it calls
/// (`scanning::ast_integration::run_initial_ast_dom_analysis`) is what the
/// `server` and MCP paths share, so all three surfaces report the same DOM-XSS
/// findings for the same page — but editing *this* wrapper moves the CLI alone.
/// Security posture comes from the `Target`, which preflight already enriched.
async fn run_initial_ast_pass(
    target: &Target,
    args_clone: &ScanArgs,
    preflight_response_body: Option<&String>,
    results_clone: &Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    findings_count_clone: &Arc<std::sync::atomic::AtomicUsize>,
) {
    // Run AST-based DOM XSS analysis on the initial response
    // (enabled by default). The helper is shared with the
    // server (`dalfox server`) and MCP (`scan_with_dalfox`)
    // paths so all three surfaces produce the same DOM-XSS
    // findings for an identical target.
    if !args_clone.skip_ast_analysis
        && let Some(response_text) = preflight_response_body
    {
        let ast_batch = crate::scanning::ast_integration::run_initial_ast_dom_analysis(
            response_text,
            target.url.as_str(),
            &target.method,
            crate::scanning::ast_integration::PageSecurityPosture::from_target(target),
        );
        if !ast_batch.is_empty() {
            let added = crate::scanning::count_matching_results(
                &ast_batch,
                &args_clone.limit_result_type.to_uppercase(),
            );
            let mut guard = results_clone.lock().await;
            guard.extend(ast_batch);
            findings_count_clone.fetch_add(added, Ordering::Relaxed);
        }
        if args_clone.analyze_external_js {
            let ext_client = target.build_client_or_default();
            let ext_batch = crate::scanning::fetch_and_analyze_external_js(
                &ext_client,
                target,
                response_text,
                args_clone,
            )
            .await;
            crate::scanning::accumulate_findings(
                results_clone,
                findings_count_clone,
                ext_batch,
                &args_clone.limit_result_type.to_uppercase(),
            )
            .await;
        }
    }
}
