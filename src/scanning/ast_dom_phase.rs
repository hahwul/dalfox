//! AST/DOM analysis orchestration + external-JS fetch.
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

/// Maximum number of distinct same-origin external JS files fetched per target page fetch.
pub(crate) const MAX_EXTERNAL_JS_FILES: usize = 16;
/// Maximum bytes read from a single external JS file (matches analyzer limit).
pub(crate) const MAX_EXTERNAL_JS_BYTES: usize = 512 * 1024;
/// Run AST-based DOM XSS static analysis on the given response HTML.
///
/// Extracts JavaScript blocks, analyses each for DOM XSS flows, performs
/// lightweight runtime verification, and returns any findings.  De-duplicates
/// against `ast_seen` (shared across calls for the same parameter).
pub(crate) async fn run_ast_dom_analysis(
    client: &reqwest::Client,
    target: &Target,
    param: &Param,
    response_text: &str,
    ast_seen: &mut HashSet<String>,
) -> Vec<crate::scanning::result::Result> {
    let mut results = Vec::new();
    let (js_blocks, script_element_ids) =
        crate::scanning::ast_integration::extract_js_and_script_ids(response_text);
    let posture = crate::scanning::ast_integration::PageSecurityPosture::from_target(target);
    for js_code in js_blocks {
        let findings =
            crate::scanning::ast_integration::analyze_javascript_for_dom_xss_with_html_context(
                &js_code,
                target.url.as_str(),
                &script_element_ids,
                posture.trusted_types_enforced,
            );
        for (vuln, payload, description) in findings {
            let self_bootstrap_verified =
                crate::scanning::ast_integration::has_self_bootstrap_verification(
                    &js_code,
                    &vuln.source,
                );
            let ast_key = format!(
                "{}|{}|{}|{}|{}",
                param.name, vuln.line, vuln.column, vuln.source, vuln.sink
            );
            if ast_seen.contains(&ast_key) {
                continue;
            }
            ast_seen.insert(ast_key);
            let source_uses_url_surface = ast_source_uses_browser_url_surface(&vuln.source);
            let result_url = if source_uses_url_surface {
                crate::scanning::ast_integration::build_dom_xss_poc_url(
                    target.url.as_str(),
                    &vuln.source,
                    &payload,
                )
            } else {
                let base = crate::scanning::url_inject::effective_query_base(&target.url, param);
                crate::scanning::url_inject::build_injected_url(&base, param, &payload)
            };
            // Graded from the flow's own shape, so the light-check and
            // self-bootstrap upgrades below can leave `result_type` at
            // `Verified` while the grade stays `Low`. See
            // `ast_integration::build_ast_dom_xss_result` for why that
            // disagreement is intentional during the tier migration.
            let (confidence, confidence_reason) =
                crate::scanning::ast_integration::grade_ast_finding(
                    &vuln.source,
                    &vuln.sink,
                    vuln.guarded,
                    self_bootstrap_verified,
                    posture,
                );
            let mut ast_result = crate::scanning::result::Result::builder(FindingType::AstDetected)
                .inject_type("DOM-XSS")
                .method(crate::scanning::url_inject::effective_method(
                    &target.method,
                    param,
                ))
                .confidence(confidence, confidence_reason)
                .data(result_url.clone())
                .param(param.name.clone())
                .payload(payload.clone())
                .evidence(format!(
                    "{}:{}:{} - {} (Source: {}, Sink: {})",
                    target.url.as_str(),
                    vuln.line,
                    vuln.column,
                    description,
                    vuln.source,
                    vuln.sink
                ))
                .cwe("CWE-79")
                .severity("Medium")
                .message_id(0)
                // The confirmation status is appended below, once the light
                // check has run — a finding this path promotes to `V` must not
                // also claim it "needs runtime confirmation" (#1238).
                .message_str(description.clone())
                .build();
            ast_result.location = format!("{:?}", param.location);
            // A URL-surface source got its POC URL from
            // `build_dom_xss_poc_url`, which already placed the payload in the
            // fragment / query / path — synthesizing `?param=payload` on top
            // of that would emit a double-injection POC.
            ast_result.poc_url_complete = source_uses_url_surface;
            if !source_uses_url_surface {
                ast_result.request = Some(build_request_text(target, param, &payload));
            }
            ast_result.response = Some(crate::scanning::result::bound_evidence_body(
                response_text.to_string(),
                &payload,
            ));
            // Lightweight runtime verification (non-headless)
            let (verified, rt_resp, note) =
                crate::scanning::light_verify::verify_dom_xss_light_with_client(
                    client, target, param, &payload,
                )
                .await;
            if let Some(runtime_response) = rt_resp {
                ast_result.response = Some(crate::scanning::result::bound_evidence_body(
                    runtime_response,
                    &payload,
                ));
            }
            if verified {
                ast_result.result_type = FindingType::Verified;
                ast_result.severity = "High".to_string();
                ast_result.message_str =
                    format!("{} [light check: confirmed]", ast_result.message_str);
            } else if self_bootstrap_verified {
                ast_result.result_type = FindingType::Verified;
                ast_result.severity = "High".to_string();
                ast_result.message_str = format!(
                    "{} [static self-bootstrap confirmed]",
                    ast_result.message_str
                );
            } else {
                ast_result.message_str = format!(
                    "{} (needs runtime confirmation) [light check: not confirmed]",
                    ast_result.message_str
                );
            }
            // Appended last so the CSP-style caveat trails the verdict instead
            // of splitting the description from it.
            if let Some(n) = note {
                ast_result.message_str = format!("{} [{}]", ast_result.message_str, n);
            }
            results.push(ast_result);
        }
    }
    results
}
/// Append a batch of findings to the shared results vector and bump the
/// running findings counter. No-op when `batch` is empty. Centralizes the
/// lock + extend + counter-update sequence shared by every preflight finding
/// source (libs, initial AST, external JS) across the CLI, server, and MCP
/// surfaces.
///
/// The counter is bumped by the number of findings that match
/// `limit_result_type` (already-uppercased `--limit-result-type`), mirroring
/// [`ScanWorkerCtx::flush_results`] — otherwise N preflight findings of a
/// non-matching type would trip `--limit N` and short-circuit the injection
/// phase before any matching finding is produced.
pub(crate) async fn accumulate_findings(
    results: &tokio::sync::Mutex<Vec<crate::scanning::result::Result>>,
    findings_count: &std::sync::atomic::AtomicUsize,
    batch: Vec<crate::scanning::result::Result>,
    limit_result_type: &str,
) {
    if batch.is_empty() {
        return;
    }
    let added = count_matching_results(&batch, limit_result_type);
    results.lock().await.extend(batch);
    findings_count.fetch_add(added, std::sync::atomic::Ordering::Relaxed);
}
/// Fetch all same-origin `<script src>` bundles referenced by `html` and run
/// AST DOM-XSS analysis on each one. Called once per target at the pre-scan
/// (preflight) stage so it fires even for SPAs that have no server-side
/// parameter reflection (where the per-param probe loop never executes).
///
/// Returns an empty `Vec` when `--analyze-external-js` is not set.
pub(crate) async fn fetch_and_analyze_external_js(
    client: &reqwest::Client,
    target: &Target,
    html: &str,
    scan_args: &ScanArgs,
) -> Vec<crate::scanning::result::Result> {
    if !scan_args.analyze_external_js {
        return Vec::new();
    }

    // Compile scope filters once rather than per-URL.
    let include_patterns: Vec<regex::Regex> = scan_args
        .include_url
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();
    let exclude_patterns: Vec<regex::Regex> = scan_args
        .exclude_url
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();

    let script_urls =
        crate::scanning::ast_integration::extract_same_origin_script_srcs(html, &target.url);

    let script_element_ids = crate::scanning::ast_integration::extract_script_element_ids(html);
    // The posture comes from the *page's* CSP, not each script's response: the
    // policy that governs whether an injected handler runs is the document's.
    let posture = crate::scanning::ast_integration::PageSecurityPosture::from_target(target);
    let trusted_types_enforced = posture.trusted_types_enforced;
    let mut results: Vec<crate::scanning::result::Result> = Vec::new();

    // extract_same_origin_script_srcs already deduplicates; just cap the count.
    for script_url in script_urls.into_iter().take(MAX_EXTERNAL_JS_FILES) {
        let url_str = script_url.as_str().to_owned();

        // Apply --include-url / --exclude-url scope to external script URLs.
        if !include_patterns.is_empty() && !include_patterns.iter().any(|r| r.is_match(&url_str)) {
            continue;
        }
        if exclude_patterns.iter().any(|r| r.is_match(&url_str)) {
            continue;
        }

        let rb =
            crate::utils::build_request(client, target, reqwest::Method::GET, script_url, None);
        let send_result =
            crate::utils::send_with_retry(rb, scan_args.retries, scan_args.retry_delay).await;
        // Count this external-JS fetch (up to MAX_EXTERNAL_JS_FILES per page);
        // its retries, if any, are counted inside send_with_retry. These GETs
        // were previously missing from REQUEST_COUNT / the live req/s rate.
        crate::tick_request_count();
        let resp = match send_result {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        let body = match crate::utils::http::read_body(resp).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        if body.len() > MAX_EXTERNAL_JS_BYTES {
            continue;
        }

        let findings =
            crate::scanning::ast_integration::analyze_javascript_for_dom_xss_with_html_context(
                &body,
                target.url.as_str(),
                &script_element_ids,
                trusted_types_enforced,
            );

        for (vuln, payload, description) in findings {
            let self_bootstrap_verified =
                crate::scanning::ast_integration::has_self_bootstrap_verification(
                    &body,
                    &vuln.source,
                );
            let message =
                format!("{description} (needs runtime confirmation) [external JS: {url_str}]");
            let evidence = format!(
                "{}:{}:{} - {} (Source: {}, Sink: {}) [script: {}]",
                target.url.as_str(),
                vuln.line,
                vuln.column,
                description,
                vuln.source,
                vuln.sink,
                url_str,
            );
            results.push(crate::scanning::ast_integration::build_ast_dom_xss_result(
                crate::scanning::ast_integration::AstDomFinding {
                    target_url: target.url.as_str(),
                    target_method: &target.method,
                    vuln: &vuln,
                    payload,
                    evidence,
                    message,
                    self_bootstrap_verified,
                    posture,
                },
            ));
        }
    }

    results
}
pub(crate) fn ast_source_uses_browser_url_surface(source: &str) -> bool {
    source.contains("location.hash")
        || source.contains("location.search")
        || source.contains("URLSearchParams.get(")
        || source.contains("location.href")
        || source.contains("location.pathname")
        || source.contains("document.URL")
        || source.contains("window.opener")
        || source.contains("event.newValue")
        || source.contains("event.oldValue")
}
