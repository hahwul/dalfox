//! Result-rendering stages: the `--dry-run` and `--only-discovery` early-exit
//! reports, and the end-of-scan output path (dedupe → `--only-poc` filter →
//! `--limit` → per-target summary → format-specific render → file/stdout).
//! Lifted verbatim out of `run_scan`; shared handles arrive via [`ScanState`].

use super::ScanOutcome;
use super::ScanState;
use super::args::ScanArgs;
use super::logging::log_warn;
use super::poc::render_finding_block;
use super::postprocess::dedupe_ast_results;
use crate::scanning::result::{FindingType, Result};
use crate::target_parser::Target;

pub(crate) async fn render_dry_run(
    args: &ScanArgs,
    host_groups: &std::collections::HashMap<String, Vec<Target>>,
    state: &ScanState,
) -> ScanOutcome {
    let skipped_targets = &state.skipped_targets;
    let mut dry_run_targets = Vec::new();
    for group in host_groups.values() {
        for target in group {
            let param_count = target.reflection_params.len();
            // Estimate request count per target using encoder expansion
            let enc_factor = if args.encoders.iter().any(|e| e == "none") {
                1usize
            } else {
                let mut f = 1usize;
                for e in ["url", "html", "2url", "3url", "4url", "base64"] {
                    if args.encoders.iter().any(|x| x == e) {
                        f += 1;
                    }
                }
                f
            };
            // Mirror the scan-time effective cap (built-in safety cap unless
            // --deep-scan / explicit --max-payloads-per-param). This is a
            // LOWER-BOUND estimate: it counts the capped base reflection set only,
            // and excludes the shared CSP/tech payloads appended after the cap,
            // the WAF-bypass mutation/encoder expansion, and the DOM-verification
            // set — so a real scan can send more (the preflight estimate in
            // analysis.rs carries the same caveat).
            let cap =
                crate::scanning::effective_payload_cap(args.max_payloads_per_param, args.deep_scan);
            let apply_cap = |n: usize| -> usize { if cap == 0 { n } else { n.min(cap) } };
            let mut estimated_requests: usize = 0;
            for p in &target.reflection_params {
                let payload_count = if let Some(ctx) = &p.injection_context {
                    crate::scanning::xss_common::get_dynamic_payloads(ctx, args)
                        .unwrap_or_else(|_| vec![])
                        .len()
                } else {
                    let html_len =
                        crate::payload::get_dynamic_xss_html_payloads().len() * enc_factor;
                    let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
                    html_len + js_len
                };
                estimated_requests = estimated_requests.saturating_add(apply_cap(payload_count));
            }

            let params: Vec<serde_json::Value> = target
                .reflection_params
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "location": format!("{:?}", p.location),
                    })
                })
                .collect();

            dry_run_targets.push(serde_json::json!({
                "target": target.url.as_str(),
                "method": target.method,
                "params_discovered": param_count,
                "estimated_requests": estimated_requests,
                "params": params,
            }));
        }
    }

    let total_estimated: usize = dry_run_targets
        .iter()
        .filter_map(|t| t["estimated_requests"].as_u64())
        .map(|n| n as usize)
        .sum();
    let total_params: usize = dry_run_targets
        .iter()
        .filter_map(|t| t["params_discovered"].as_u64())
        .map(|n| n as usize)
        .sum();
    let skipped = skipped_targets.lock().await;

    if args.format == "json" || args.format == "jsonl" {
        let output = serde_json::json!({
            "dry_run": true,
            "meta": {
                "dalfox_version": env!("CARGO_PKG_VERSION"),
                "targets_input": args.targets.len(),
                "targets_scannable": dry_run_targets.len(),
                "targets_skipped": skipped.len(),
                "total_params_discovered": total_params,
                "total_estimated_requests": total_estimated,
            },
            "targets": dry_run_targets,
        });
        if args.format == "json" {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        } else {
            println!("{}", serde_json::to_string(&output).unwrap_or_default());
        }
    } else {
        println!("Dry-run summary:");
        println!("  Targets (input):     {}", args.targets.len());
        println!("  Targets (scannable): {}", dry_run_targets.len());
        println!("  Targets (skipped):   {}", skipped.len());
        println!("  Params discovered:   {}", total_params);
        println!("  Estimated requests:  {}", total_estimated);
        println!();
        for t in &dry_run_targets {
            println!(
                "  {} ({}):",
                t["target"].as_str().unwrap_or("?"),
                t["method"].as_str().unwrap_or("?")
            );
            if let Some(params) = t["params"].as_array() {
                for p in params {
                    println!(
                        "    - {} ({})",
                        p["name"].as_str().unwrap_or("?"),
                        p["location"].as_str().unwrap_or("?")
                    );
                }
            }
            println!("    estimated_requests: {}", t["estimated_requests"]);
        }
    }
    ScanOutcome::Clean
}

pub(crate) fn render_only_discovery(
    args: &ScanArgs,
    host_groups: &std::collections::HashMap<String, Vec<Target>>,
) -> ScanOutcome {
    // Collect once so we can render both human-readable plain
    // output and the `{meta, params}` envelope shape that matches
    // every other JSON/JSONL output dalfox emits.
    let mut entries: Vec<serde_json::Value> = Vec::new();
    for group in host_groups.values() {
        for target in group {
            for p in &target.reflection_params {
                entries.push(serde_json::json!({
                    "url": target.url.as_str(),
                    "param": p.name,
                    "location": format!("{:?}", p.location),
                }));
            }
        }
    }
    match args.format.as_str() {
        "json" => {
            let envelope = serde_json::json!({
                "meta": {
                    "dalfox_version": env!("CARGO_PKG_VERSION"),
                    "mode": "only_discovery",
                    "params_discovered": entries.len(),
                },
                "params": entries,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).unwrap_or_default()
            );
        }
        "jsonl" => {
            // Meta line first (consistent with `-f jsonl` for scans),
            // then one param per line.
            let meta = serde_json::json!({
                "meta": {
                    "dalfox_version": env!("CARGO_PKG_VERSION"),
                    "mode": "only_discovery",
                    "params_discovered": entries.len(),
                }
            });
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            for e in &entries {
                println!("{}", serde_json::to_string(e).unwrap_or_default());
            }
        }
        _ => {
            for e in &entries {
                println!(
                    "[{}] {} ({})",
                    e["url"].as_str().unwrap_or(""),
                    e["param"].as_str().unwrap_or(""),
                    e["location"].as_str().unwrap_or("")
                );
            }
        }
    }
    ScanOutcome::Clean
}

pub(crate) async fn render_results(
    args: &ScanArgs,
    state: &ScanState,
    all_target_urls: &[String],
    scan_elapsed: std::time::Duration,
    total_requests: u64,
    stream_findings_enabled: bool,
) -> (Vec<Result>, bool) {
    let results = state.results.clone();
    let skipped_targets = state.skipped_targets.clone();
    let target_meta = state.target_meta.clone();
    let target_mutation_stats = state.target_mutation_stats.clone();
    let mut final_results = dedupe_ast_results(results.lock().await.clone());

    // Apply --only-poc filter: keep only results whose type matches the specified filters
    if !args.only_poc.is_empty() {
        let allowed: Vec<String> = args
            .only_poc
            .iter()
            .map(|s| s.trim().to_uppercase())
            .collect();
        final_results.retain(|r| allowed.iter().any(|a| a == r.result_type.short()));
    }

    // Truncate the displayed findings to `--limit`. `--limit-result-type`
    // makes the scan-time stop condition count ONLY findings of that type
    // (see `count_matching_results` / `limit_reached`), so the display limit
    // must use the same rule: truncate at the prefix ending with the `limit`-th
    // matching finding, not the first `limit` findings of any type. Otherwise a
    // run like `--limit 2 --limit-result-type v` — which keeps scanning until 2
    // Verified findings accrue — could hide those very Verified findings behind
    // Reflected ones recorded earlier. With the default `all`, every finding
    // matches, so this collapses to the original first-`limit` slice.
    let display_results_len = match args.limit {
        None => final_results.len(),
        Some(0) => 0,
        Some(lim) if args.limit_result_type.eq_ignore_ascii_case("all") => {
            std::cmp::min(final_results.len(), lim)
        }
        Some(lim) => {
            // Truncate at the prefix ending with the `lim`-th finding whose
            // type matches `--limit-result-type`. `lim >= 1` here (the `Some(0)`
            // arm handled zero), and fewer than `lim` matches → keep everything
            // (the limit was never reached, so nothing should be dropped).
            let want = args.limit_result_type.to_uppercase();
            final_results
                .iter()
                .enumerate()
                .filter(|(_, r)| r.result_type.short() == want)
                .nth(lim - 1)
                .map_or(final_results.len(), |(i, _)| i + 1)
        }
    };
    let display_results = &final_results[..display_results_len];

    // Build per-target summary for structured output.
    //
    // Attribution uses `finding_belongs_to_target`, the same helper that
    // `collapse_redundant_reflected` uses for per-target dedup. The two
    // MUST agree — if they disagree, a finding can be dropped by dedup but
    // attributed to a different target than where it was actually produced.
    //
    // Limitation: targets that share a path-without-query
    // (e.g. `/search?q=a` and `/search?id=b`) or a parent path for
    // path-injection (e.g. `/api/v1/foo` and `/api/v1/bar`) can both match
    // a single finding. This mirrors prior behavior. Single-target scans
    // are unaffected.
    let target_summary: Vec<serde_json::Value> = {
        let skipped = skipped_targets.lock().await;
        let meta = target_meta.lock().await;
        let stats_map = target_mutation_stats.lock().await;
        let mut summary = Vec::with_capacity(all_target_urls.len());
        for url in all_target_urls {
            let finding_count = display_results
                .iter()
                .filter(|r| crate::utils::finding_belongs_to_target(url, &r.data))
                .count();
            let (status, error_code) = if let Some(code) = skipped.get(url) {
                ("skipped", Some(*code))
            } else if finding_count > 0 {
                ("findings", None)
            } else {
                ("clean", None)
            };
            let mut entry = serde_json::json!({
                "target": url,
                "status": status,
                "findings_count": finding_count,
            });
            if let Some(code) = error_code {
                entry["error_code"] = serde_json::json!(code);
            }
            // Attach preflight metadata (WAF + applied bypass) when present.
            // Omitted entirely for targets where no WAF was detected, to
            // keep the common-case output lean.
            if let Some(m) = meta.get(url) {
                let mut waf_entry = m.clone();
                // Fold per-target effectiveness telemetry into bypass{}.
                // Only present when bypass actually ran (target had stats).
                if let Some(stats) = stats_map.get(url) {
                    let snap = stats.snapshot();
                    let mut applied: Vec<serde_json::Value> = snap
                        .variants
                        .iter()
                        .map(|(m, n)| {
                            serde_json::json!({
                                "type": m.to_string(),
                                "variants_generated": n,
                            })
                        })
                        .collect();
                    // Stable order so re-runs diff cleanly in CI.
                    applied.sort_by(|a, b| {
                        a["type"]
                            .as_str()
                            .unwrap_or("")
                            .cmp(b["type"].as_str().unwrap_or(""))
                    });
                    if let Some(bypass) = waf_entry.get_mut("bypass")
                        && let Some(obj) = bypass.as_object_mut()
                    {
                        obj.insert(
                            "mutations_applied".to_string(),
                            serde_json::Value::Array(applied),
                        );
                        obj.insert(
                            "requests_sent".to_string(),
                            serde_json::json!(snap.bypass_requests),
                        );
                        obj.insert(
                            "requests_blocked".to_string(),
                            serde_json::json!(snap.bypass_blocks),
                        );
                    }
                }
                entry["waf"] = waf_entry;
            }
            summary.push(entry);
        }
        summary
    };

    let output_content = if args.format == "json" {
        let findings_json: Vec<serde_json::Value> = display_results
            .iter()
            .map(|r| r.to_json_value(args.include_request, args.include_response))
            .collect();
        let wrapper = serde_json::json!({
            "meta": {
                "dalfox_version": env!("CARGO_PKG_VERSION"),
                "targets": &args.targets,
                "scan_duration_ms": scan_elapsed.as_millis() as u64,
                "total_requests": total_requests,
                "findings_count": display_results.len(),
                "target_summary": target_summary,
            },
            "findings": findings_json
        });
        serde_json::to_string_pretty(&wrapper).unwrap_or_else(|_| "{}".to_string())
    } else if args.format == "jsonl" {
        // JSONL: first line is meta, then one finding per line
        let meta = serde_json::json!({
            "meta": {
                "dalfox_version": env!("CARGO_PKG_VERSION"),
                "targets": &args.targets,
                "scan_duration_ms": scan_elapsed.as_millis() as u64,
                "total_requests": total_requests,
                "findings_count": display_results.len(),
                "target_summary": target_summary,
            }
        });
        let mut out = serde_json::to_string(&meta).unwrap_or_default();
        out.push('\n');
        for r in display_results {
            let v = r.to_json_value(args.include_request, args.include_response);
            if let Ok(s) = serde_json::to_string(&v) {
                out.push_str(&s);
                out.push('\n');
            }
        }
        out
    } else if args.format == "markdown" {
        let meta = crate::scanning::result::ScanMetadata {
            dalfox_version: env!("CARGO_PKG_VERSION").to_string(),
            targets: args.targets.clone(),
            scan_duration_ms: scan_elapsed.as_millis() as u64,
            total_requests,
            findings_count: display_results.len(),
            target_summary: target_summary.clone(),
        };
        crate::scanning::result::Result::results_to_markdown_with_meta(
            display_results,
            args.include_request,
            args.include_response,
            Some(&meta),
        )
    } else if args.format == "sarif" {
        let meta = crate::scanning::result::ScanMetadata {
            dalfox_version: env!("CARGO_PKG_VERSION").to_string(),
            targets: args.targets.clone(),
            scan_duration_ms: scan_elapsed.as_millis() as u64,
            total_requests,
            findings_count: display_results.len(),
            target_summary: target_summary.clone(),
        };
        crate::scanning::result::Result::results_to_sarif_with_meta(
            display_results,
            args.include_request,
            args.include_response,
            Some(&meta),
        )
    } else if args.format == "toml" {
        let meta = crate::scanning::result::ScanMetadata {
            dalfox_version: env!("CARGO_PKG_VERSION").to_string(),
            targets: args.targets.clone(),
            scan_duration_ms: scan_elapsed.as_millis() as u64,
            total_requests,
            findings_count: display_results.len(),
            target_summary: target_summary.clone(),
        };
        crate::scanning::result::Result::results_to_toml_with_meta(
            display_results,
            args.include_request,
            args.include_response,
            Some(&meta),
        )
    } else if args.format == "plain" {
        let mut output = String::new();

        // Plain logger: XSS summary before POC lines
        let v_count = display_results
            .iter()
            .filter(|r| r.result_type == FindingType::Verified)
            .count();
        log_warn(args, &format!("XSS found \x1b[33m{}\x1b[0m XSS", v_count));

        // When the streaming printer ran (`stream_findings_enabled`), every
        // finding has already been emitted mid-scan with its full block —
        // re-rendering here would produce the duplicate POC headers users
        // reported. Skip per-finding rendering in that case and let the
        // summary line above stand alone.
        if !stream_findings_enabled {
            for result in display_results {
                output.push_str(&render_finding_block(
                    result,
                    &args.poc_type,
                    args.include_request,
                    args.include_response,
                ));
            }
        }
        output
    } else {
        let mut output = String::new();
        for result in display_results {
            output.push_str(&format!(
                "Found XSS: {} - {}\n",
                result.param, result.payload
            ));
        }
        output
    };

    let mut output_write_failed = false;
    if let Some(output_path) = &args.output {
        // Surface `..` traversal so the operator notices before a
        // pipeline silently writes into a parent directory. We don't
        // refuse — there are legitimate uses (`-o ../results.json` from
        // a per-target subdir) — just emit a one-time stderr warning.
        if output_path
            .split(std::path::is_separator)
            .any(|seg| seg == "..")
        {
            eprintln!(
                "Warning: --output path '{}' contains parent-dir references — final path will be resolved by the OS",
                output_path
            );
        }
        match std::fs::write(output_path, &output_content) {
            Ok(_) => {
                if !args.silence {
                    println!("Results written to {}", output_path);
                }
            }
            Err(e) => {
                // A failed `--output` write is a hard failure, not a log line:
                // the operator asked for the results in a file and won't get
                // them. Surface it even under `--silence` (it goes to stderr, so
                // machine stdout stays clean) and propagate so the exit code
                // becomes Error instead of a misleading success — otherwise a
                // CI step like `dalfox -o out.json -S && use out.json` proceeds
                // against a missing or stale file with zero indication.
                eprintln!("Error writing to file {}: {}", output_path, e);
                output_write_failed = true;
            }
        }
    } else {
        // output_content may carry baked-in ANSI escapes from the plain
        // builder above — cprintln strips them when --no-color / NO_COLOR
        // is in effect so the final POC/finding block stays plain.
        crate::cprintln!("{}", output_content);
    }

    (final_results, output_write_failed)
}
