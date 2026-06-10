//! Preflight + parameter-analysis stage. For every target (bounded by
//! `--max-concurrent-targets`) this runs the content-type/CSP/WAF preflight,
//! parameter discovery + mining, and initial-response AST DOM analysis,
//! replacing each host group with the targets that survived preflight. Lifted
//! verbatim out of `run_scan`; the shared handles arrive via [`ScanState`].

use super::ScanState;
use super::args::ScanArgs;
use super::logging::{log_dbg, start_spinner};
use super::preflight::{PreflightOutcome, is_allowed_content_type, preflight_content_type};
use crate::parameter_analysis::analyze_parameters;
use crate::target_parser::Target;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::task::LocalSet;

pub(crate) async fn run_preflight_and_analysis(
    args: &ScanArgs,
    host_groups: &mut std::collections::HashMap<String, Vec<Target>>,
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
        let pre_analyze_semaphore =
            Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));

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
            local.run_until(async move {
                let mut handles = vec![];

                for mut target in drained {
            let args_clone = args_outer.clone();
            let sem = pre_analyze_semaphore_outer.clone();
            let preflight_idx_clone = preflight_idx_outer.clone();
            let analyze_idx_clone = analyze_idx_outer.clone();
            let total_targets_copy = total_targets_outer;
            let multi_pb_clone = multi_pb_outer.clone();
            let results_clone = results_outer.clone();
            let findings_count_clone = findings_count_outer.clone();
            let skipped_targets_clone = skipped_targets_outer.clone();
            let target_meta_clone = target_meta_outer.clone();
            let target_mutation_stats_clone = target_mutation_stats_outer.clone();

            handles.push(tokio::task::spawn_local(async move {
                // Bound concurrency across targets for preflight + analysis
                let Ok(_permit) = sem.acquire_owned().await else {
                    return None;
                };
                let mut __preflight_csp_present = false;
                let mut __preflight_csp_header: Option<(String, String)> = None;
                let mut preflight_response_body: Option<String> = None;

                // Preflight Content-Type check (skip denylisted types unless deep-scan)
                if !args_clone.deep_scan {
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
                    let __preflight_spinner = if total_targets_copy == 1 { start_spinner(spinner_allowed, !args_clone.silence, label) } else { None };

                    let __preflight_info = preflight_content_type(&target, &args_clone).await;
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
                        // still work.
                        PreflightOutcome::NoContentType => None,
                        PreflightOutcome::WithContentType(r) => Some(r),
                    };

                    if let Some(preflight) = __preflight_info {
                        preflight_response_body = preflight.response_body;
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
                                let stats = std::sync::Arc::new(
                                    crate::waf::bypass::MutationStats::default(),
                                );
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
                                    let waf_types: Vec<&crate::waf::WafType> =
                                        waf_info.waf_types();
                                    let strategy =
                                        crate::waf::bypass::merge_strategies(&waf_types);
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
                        if !is_allowed_content_type(&preflight.content_type) {
                            // Skip this target early
                            skipped_targets_clone.lock().await.insert(
                                target.url.to_string(),
                                crate::cmd::error_codes::CONTENT_TYPE_MISMATCH,
                            );
                            return None;
                        }
                    }
                }

                // Pretty start log per target (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            target.url.as_ref(),
                        ));
                        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                        crate::cprintln!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} start scan to {}",
                            ts, sid, target.url
                        );
                    } else {
                        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                        crate::cprintln!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m start scan to {}",
                            ts, target.url
                        );
                        if __preflight_csp_present {
                            crate::cprintln!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m CSP: enabled", ts);
                            if let Some((hn, hv)) = &__preflight_csp_header {
                                crate::cprintln!("  \x1b[90m└──\x1b[0m \x1b[38;5;247m{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m", hn, hv);
                            }
                        }
                        // Log WAF detection
                        if let Some(ref waf_info) = target.waf_info {
                            for fp in &waf_info.detected {
                                crate::cprintln!(
                                    "\x1b[90m{}\x1b[0m \x1b[33mWAF\x1b[0m {} detected (confidence: {:.0}%, evidence: {})",
                                    ts, fp.waf_type, fp.confidence * 100.0, fp.evidence
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
                            let tech_names: Vec<String> = tech_info.detected.iter().map(|d| format!("{}", d.tech)).collect();
                            if !tech_names.is_empty() {
                                crate::cprintln!(
                                    "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m tech: {}",
                                    ts, tech_names.join(", ")
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
                            format!("[{}/{}] analyzing: {}", current, total_targets_copy, target.url)
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
                            marker_params.push(Param {
                                name: k.to_string(),
                                value: v.to_string(),
                                location: Location::Query,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                                framework_sink: None,
                                escaped_specials: None,
                                js_breakout: None,
                            });
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
                                        marker_params.push(Param {
                                            name: k.clone(),
                                            value: s.to_string(),
                                            location: Location::JsonBody,
                                            injection_context: None,
                                            valid_specials: None,
                                            invalid_specials: None,
                                            pre_encoding: None,
                                            pre_encoding_pipeline: None,
                                            wire_name: None,
                                            form_action_url: None,
                                            form_origin_url: None,
                                            framework_sink: None,
                                            escaped_specials: None,
                                            js_breakout: None,
                                        });
                                    }
                                }
                            }
                        } else {
                            for pair in data.split('&') {
                                if let Some((k, v)) = pair.split_once('=')
                                    && v.contains(marker.as_str())
                                {
                                    marker_params.push(Param {
                                        name: k.to_string(),
                                        value: v.to_string(),
                                        location: Location::Body,
                                        injection_context: None,
                                        valid_specials: None,
                                        invalid_specials: None,
                                        pre_encoding: None,
                                        pre_encoding_pipeline: None,
                                        wire_name: None,
                                        form_action_url: None,
                                        form_origin_url: None,
                                        framework_sink: None,
                                        escaped_specials: None,
                                        js_breakout: None,
                                    });
                                }
                            }
                        }
                    }

                    // Check headers
                    for (k, v) in &target.headers {
                        if v.contains(marker.as_str()) {
                            marker_params.push(Param {
                                name: k.clone(),
                                value: v.clone(),
                                location: Location::Header,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                                framework_sink: None,
                                escaped_specials: None,
                                js_breakout: None,
                            });
                        }
                    }

                    // Check cookies
                    for (k, v) in &target.cookies {
                        if v.contains(marker.as_str()) {
                            marker_params.push(Param {
                                name: k.clone(),
                                value: v.clone(),
                                location: Location::Header,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                                framework_sink: None,
                                escaped_specials: None,
                                js_breakout: None,
                            });
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

                // Outdated / known-vulnerable JS library detection (issue #1074).
                // OPT-IN (`--detect-outdated-libs`, default off): dalfox's default
                // output is verified XSS, so this informational (CWE-1104) add-on
                // is gated behind a flag. Emits once per target from the initial
                // response; borrows the body so the AST block below can still use it.
                if args_clone.detect_outdated_libs
                    && let Some(body) = preflight_response_body.as_deref()
                {
                    let lib_findings = crate::scanning::vuln_libs::library_findings(
                        crate::scanning::vuln_libs::detect_vulnerable_libraries(body),
                        target.url.as_str(),
                        &target.method,
                    );
                    if !lib_findings.is_empty() {
                        let added = lib_findings.len();
                        let mut guard = results_clone.lock().await;
                        guard.extend(lib_findings);
                        findings_count_clone.fetch_add(added, Ordering::Relaxed);
                    }
                }

                // Run AST-based DOM XSS analysis on the initial response
                // (enabled by default). The helper is shared with the
                // server (`dalfox server`) and MCP (`scan_with_dalfox`)
                // paths so all three surfaces produce the same DOM-XSS
                // findings for an identical target.
                if !args_clone.skip_ast_analysis
                    && let Some(response_text) = preflight_response_body
                {
                    let ast_batch =
                        crate::scanning::ast_integration::run_initial_ast_dom_analysis(
                            &response_text,
                            target.url.as_str(),
                            &target.method,
                            target.trusted_types_enforced(),
                        );
                    if !ast_batch.is_empty() {
                        let added = ast_batch.len();
                        let mut guard = results_clone.lock().await;
                        guard.extend(ast_batch);
                        findings_count_clone.fetch_add(added, Ordering::Relaxed);
                    }
                    if args_clone.analyze_external_js {
                        let ext_client = target.build_client_or_default();
                        let ext_batch = crate::scanning::fetch_and_analyze_external_js(
                            &ext_client,
                            &target,
                            &response_text,
                            &args_clone,
                        )
                        .await;
                        crate::scanning::accumulate_findings(
                            &results_clone,
                            &findings_count_clone,
                            ext_batch,
                        )
                        .await;
                    }
                }

                // Pretty reflection summary (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    let n = target.reflection_params.len();
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            target.url.as_ref(),
                        ));
                        crate::cprintln!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} found reflected \x1b[33m{}\x1b[0m params",
                            ts, sid, n
                        );
                    } else {
                        crate::cprintln!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m found reflected \x1b[33m{}\x1b[0m params",
                            ts, n
                        );
                    }
                    for (i, p) in target.reflection_params.iter().enumerate() {
                        let bullet = if i + 1 == n { "└──" } else { "├──" };
                        let valid = p
                            .valid_specials
                            .as_ref().map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
                        let invalid = p
                            .invalid_specials
                            .as_ref().map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
                        crate::cprintln!(
                            "  \x1b[90m{}\x1b[0m \x1b[38;5;247m{}\x1b[0m \x1b[38;5;247mvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\" \x1b[38;5;247minvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\"",
                            bullet, p.name, valid, invalid
                        );
                    }
                    // Debug: estimate total test cases (requests) to be run during scanning
                    if crate::DEBUG.load(Ordering::Relaxed) && args_clone.format == "plain" && !args_clone.silence {
                        // encoder expansion factor
                        let enc_factor = if args_clone.encoders.iter().any(|e| e == "none") {
                            1
                        } else {
                            let mut f = 1;
                            for e in ["url", "html", "2url", "3url", "4url", "base64"] {
                                if args_clone.encoders.iter().any(|x| x == e) {
                                    f += 1;
                                }
                            }
                            f
                        };
                        let cap = args_clone.max_payloads_per_param;
                        let apply_cap = |n: usize| -> usize {
                            if cap == 0 { n } else { n.min(cap) }
                        };
                        let mut total: usize = 0;
                        for p in &target.reflection_params {
                            let refl_len = if let Some(ctx) = &p.injection_context {
                                crate::scanning::xss_common::get_dynamic_payloads(ctx, &args_clone)
                                    .unwrap_or_else(|_| vec![])
                                    .len()
                            } else {
                                // Fallback estimate: HTML dynamic payloads + JS payloads (with encoders), excluding remote payloads
                                let html_base_len = crate::payload::get_dynamic_xss_html_payloads().len();
                                let html_len = html_base_len * enc_factor;
                                let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
                                html_len + js_len
                            };
                            let dom_len = match &p.injection_context {
                                Some(crate::parameter_analysis::InjectionContext::Javascript(_)) => 0,
                                Some(ctx) => {
                                    // Use locally generated payloads and apply encoder factor; exclude remote payloads
                                    let base = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
                                    base.len() * enc_factor
                                }
                                None => {
                                    // Unknown context: use HTML + Attribute payloads without remote, apply encoder factor
                                    let html = crate::payload::get_dynamic_xss_html_payloads();
                                    let attr = crate::payload::get_dynamic_xss_attribute_payloads();
                                    (html.len() + attr.len()) * enc_factor
                                }
                            };
                            // Scan loop is additive (one reflection request + one DOM request
                            // per payload), not cartesian. Mirrors the `total_tasks` calculation
                            // in src/scanning/mod.rs that drives the progress bar / ETA.
                            // WAF mutation/encoder expansion isn't reflected here yet, so this
                            // remains a lower bound.
                            total = total.saturating_add(
                                apply_cap(refl_len).saturating_add(apply_cap(dom_len)),
                            );
                        }
                        if args_clone.format == "plain" && !args_clone.silence {
                            log_dbg(&format!("{} test cases (reqs) estimated", total));
                        }
                    }
                }

                Some(target)
            }));
        }

        // Collect processed targets (skipping those filtered by preflight)
                let mut processed: Vec<Target> = Vec::new();
                for handle in handles {
                    if let Ok(res) = handle.await
                        && let Some(t) = res {
                            processed.push(t);
                        }
                }
                processed
            }).await
        };

        // Replace group with processed targets
        *group = processed;
    }
}
