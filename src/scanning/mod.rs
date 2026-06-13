//! # Scanning (Stages 4–6)
//!
//! Drives payload generation, reflection checking, and DOM verification for
//! each probed parameter. [`run_scanning`] is the orchestrator: it builds the
//! per-parameter jobs (`generate_param_jobs`) and fans them out across
//! `ScanWorkerCtx::scan_param` workers.
//!
//! ## Stage 4: Payload Generation (`generate_param_jobs`)
//! Builds per-parameter payload sets based on `injection_context`, CSP bypass,
//! technology-specific payloads, and WAF bypass mutations/encoders.
//! Output: `ParamPayloadJob` tuples fed into the concurrent scan loop.
//!
//! ## Stage 5: Reflection Check (`ScanWorkerCtx::run_reflection_phase`, see
//! also the `check_reflection` module)
//! Each payload is injected and the response is checked for reflection.
//!
//! ## Stage 6: DOM Verification (`ScanWorkerCtx::run_dom_phase`, see also
//! the `check_dom_verification` module)
//! Reflected payloads are verified for actual DOM evidence to upgrade
//! findings from "R" (Reflected) to "V" (DOM-verified).

pub mod ast_dom_analysis;
pub mod ast_integration;
pub mod check_dom_verification;
pub mod check_reflection;
/// Shared test-only fixtures modelling server-side reflection transforms.
#[cfg(test)]
pub(crate) mod dom_evidence_fixtures;
pub mod js_context_verify;
pub mod light_verify;
pub mod markers;
pub mod result;
pub mod selectors;
pub mod tech_detect;
pub mod url_inject;
pub mod vuln_libs;
pub mod xss_blind;
pub mod xss_common;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification_with_client;
use crate::scanning::check_reflection::check_reflection_with_response_tracked;
use crate::scanning::result::FindingType;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, Semaphore};

/// Maximum number of WAF mutation variants generated per base payload.
/// Prevents payload explosion when WAF bypass mutations are applied. This cap
/// only takes effect when a WAF is detected and bypass is on (the only path
/// that calls `expand_waf_payloads`), so it scales effort exactly on the scans
/// that want more bypass attempts — not the common no-WAF path. Sized to give
/// the attribute-decode-layer mutations (KeywordEntityEncode / MultiSlash /
/// SchemeBreak) a slot alongside the proven structural ones for payloads where
/// many mutations shape-match.
const MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD: usize = 4;

/// Maximum number of distinct same-origin external JS files fetched per target page fetch.
const MAX_EXTERNAL_JS_FILES: usize = 16;
/// Maximum bytes read from a single external JS file (matches analyzer limit).
const MAX_EXTERNAL_JS_BYTES: usize = 512 * 1024;

/// Build a `with_key("req_per_sec", …)` tracker for an indicatif progress bar.
///
/// `start` is the value of `crate::REQUEST_COUNT` captured at bar creation;
/// the tracker renders `(REQUEST_COUNT - start) / pb.elapsed()` as
/// `XXXX.X req/s` with a fixed-width field so the bar's trailing columns
/// don't jitter as the rate changes magnitude.
///
/// Caveats baked into the displayed value:
///   - `REQUEST_COUNT` is process-global, so when several targets in the
///     same host group scan concurrently the per-target bar reflects the
///     group's combined HTTP rate (which matches the overall bar). This is
///     intentionally a "combined" view — a strictly per-target counter
///     would need plumbing through every HTTP call site.
///   - `{eta}` next to this field is still computed by indicatif from
///     `pos/len` rate, not request rate. In practice ETA still reads
///     sensibly because the bar finishes the moment the inner loop exits.
pub(crate) fn req_per_sec_tracker(
    start: u64,
) -> impl Fn(&indicatif::ProgressState, &mut dyn std::fmt::Write) + Send + Sync + Clone + 'static {
    move |state, w| {
        let delta = crate::REQUEST_COUNT
            .load(Ordering::Relaxed)
            .saturating_sub(start);
        let _ = write!(
            w,
            "{}",
            format_req_per_sec(delta, state.elapsed().as_secs_f64())
        );
    }
}

/// Format `delta` requests over `elapsed_secs` as the right-aligned
/// `XXXX.X req/s` field rendered by [`req_per_sec_tracker`]. Extracted as
/// a pure helper so the rate / formatting contract can be tested without
/// constructing an `indicatif::ProgressState`.
///
/// `elapsed_secs <= 0.0` yields `0.0 req/s` (avoids div-by-zero on the
/// first tick before the bar has accumulated any duration).
pub(crate) fn format_req_per_sec(delta: u64, elapsed_secs: f64) -> String {
    let rate = if elapsed_secs > 0.0 {
        delta as f64 / elapsed_secs
    } else {
        0.0
    };
    format!("{:>7.1} req/s", rate)
}

/// A per-parameter work unit for the scan loop: the parameter, its reflection
/// payloads (checked in Stage 5), and its DOM payloads (verified in Stage 6).
pub type ParamPayloadJob = (Param, Vec<String>, Vec<String>);

/// Count how many results in `results` match the `--limit-result-type` filter.
/// Returns `results.len()` when filter is `"all"` (default).
/// `filter` must already be uppercased (normalised once at scan start).
pub(crate) fn count_matching_results(
    results: &[crate::scanning::result::Result],
    filter: &str,
) -> usize {
    if filter == "ALL" {
        return results.len();
    }
    results
        .iter()
        .filter(|r| r.result_type.short() == filter)
        .count()
}

struct FoundParams {
    reflection: HashSet<String>,
    dom: HashSet<String>,
}

/// Label written to `Result.inject_type` for findings produced by the scan
/// loop. Findings under `--sxss` are prefixed so JSON / markdown / plain
/// reports distinguish stored from reflected results — downstream tooling
/// parses this field, so the contract is pinned by `tests::test_inject_type_label_for_sxss`.
fn inject_type_label_for(sxss: bool) -> &'static str {
    if sxss { "sxss-inHTML" } else { "inHTML" }
}

/// True when the payload that produced the finding looks like a
/// client-side template interpolation. `{{` / `}}` is sufficient on its
/// own — Mustache, Handlebars, AngularJS, Vue and Ember all share that
/// delimiter. Used to refine `inject_type` to `*-CSTI` so plain / JSON
/// output makes the framework-injection finding distinguishable from a
/// generic HTML reflection.
fn is_template_shaped_payload(payload: &str) -> bool {
    payload.contains("{{") && payload.contains("}}")
}

/// Map a framework innerHTML-sink directive name (recorded on
/// `Param.framework_sink` during discovery) to the short suffix used in
/// `inject_type`. Anything unrecognised falls back to a generic
/// `-FrameworkSink` so the user still sees the class of finding even if
/// dalfox grows support for a new directive name later.
fn framework_sink_suffix(sink: &str) -> &'static str {
    match sink {
        "v-html" => "-VHtml",
        "data-bind" => "-DataBind",
        "ng-bind-html" => "-NgBindHtml",
        "dangerouslySetInnerHTML" => "-DangerouslySetInnerHTML",
        _ => "-FrameworkSink",
    }
}

/// Refine the base `inject_type` label. Order of precedence:
///   1. `-VHtml` / `-DataBind` / `-NgBindHtml` from a discovered
///      framework innerHTML sink (highest signal — entity-encoded
///      reflections in these attributes still execute).
///   2. `-CSTI` for client-side template payloads (`{{ … }}`).
///   3. base label only.
///
/// Mirrors the SXSS prefixing convention (`sxss-inHTML-VHtml`) so
/// downstream parsers don't have to special-case ordering.
#[cfg(test)]
fn inject_type_for_payload(sxss: bool, payload: &str) -> String {
    inject_type_for_payload_with_sink(sxss, payload, None)
}

fn inject_type_for_payload_with_sink(
    sxss: bool,
    payload: &str,
    framework_sink: Option<&str>,
) -> String {
    let base = inject_type_label_for(sxss);
    if let Some(sink) = framework_sink {
        return format!("{}{}", base, framework_sink_suffix(sink));
    }
    if is_template_shaped_payload(payload) {
        format!("{}-CSTI", base)
    } else {
        base.to_string()
    }
}

fn reflection_kind_note(kind: crate::scanning::check_reflection::ReflectionKind) -> &'static str {
    match kind {
        crate::scanning::check_reflection::ReflectionKind::Raw => "reflected",
        crate::scanning::check_reflection::ReflectionKind::HtmlEntityDecoded => {
            "reflected after HTML-entity decoding"
        }
        crate::scanning::check_reflection::ReflectionKind::UrlDecoded => {
            "reflected after URL/form decoding"
        }
        crate::scanning::check_reflection::ReflectionKind::HtmlThenUrlDecoded => {
            "reflected after HTML-entity and URL/form decoding"
        }
    }
}

/// Drop payloads whose raw bytes carry an HTML-structural character the
/// server has been observed to filter (recorded in
/// `Param.invalid_specials` by Stage 3 active probing). Raw `<`/`>` cannot
/// pass through a server-side blocklist that strips those bytes after
/// decoding, so the corresponding payload has no chance to reflect — every
/// HTTP request spent on it is wasted. The encoded variants of the same
/// payload (`%3Csvg%3E`, `&lt;svg&gt;`, multi-URL-encoded forms) carry no
/// raw `<`/`>` themselves and survive this pass, preserving the bypass
/// surface for naive filters that decode only once.
///
/// Conservative on quotes: attribute-breakout payloads intentionally lead
/// with the same delimiter character the surrounding HTML attribute uses,
/// and that delimiter must already be a "valid" special (the server
/// emitted it), so pruning on `"`/`'` would mistakenly drop the very
/// payloads that exploit attribute injection.
fn prune_blocked_raw_angles(payloads: Vec<String>, invalid_specials: &[char]) -> Vec<String> {
    let block_lt = invalid_specials.contains(&'<');
    let block_gt = invalid_specials.contains(&'>');
    if !block_lt && !block_gt {
        return payloads;
    }
    payloads
        .into_iter()
        .filter(|p| !((block_lt && p.contains('<')) || (block_gt && p.contains('>'))))
        .collect()
}

/// Common encoded forms of `<` / `>` we look for when deciding whether a
/// payload depends on angle brackets. A payload that carries any of these
/// forms is hoping the server single-pass-decodes the input — when the
/// server filters `<` after decode (the common case), the bypass fails.
/// Hoisting payloads that carry no angle bracket in any form (event-
/// handler quote-breakouts, protocol-URI payloads) ahead of these
/// angle-dependent variants lets the scanner hit a working payload first
/// and short-circuit the rest of the loop via `reflection_found_locally`.
const ANGLE_ENCODED_NEEDLES_LT: &[&str] = &[
    "%3C", "%3c", "%253C", "%253c", "&lt;", "&LT;", "&#60;", "&#x3c;", "&#x3C;", "&#x003c;",
    "&#x003C;",
];
const ANGLE_ENCODED_NEEDLES_GT: &[&str] = &[
    "%3E", "%3e", "%253E", "%253e", "&gt;", "&GT;", "&#62;", "&#x3e;", "&#x3E;", "&#x003e;",
    "&#x003E;",
];

/// True when the payload carries no `<` or `>` in any of: raw bytes,
/// percent-encoded form (single or double), or HTML entity (named,
/// decimal, hex). Used to hoist angle-free payloads to the front of the
/// payload list when `Param.invalid_specials` flags angle brackets — those
/// payloads (event-handler quote-breakouts, `javascript:` protocol URIs)
/// are the ones that actually reflect through an angle-stripping filter,
/// and the loop's `reflection_found_locally` short-circuit means the
/// first hit zeros out the rest of the budget.
fn payload_is_angle_free(p: &str) -> bool {
    if p.contains('<') || p.contains('>') {
        return false;
    }
    for n in ANGLE_ENCODED_NEEDLES_LT {
        if p.contains(n) {
            return false;
        }
    }
    for n in ANGLE_ENCODED_NEEDLES_GT {
        if p.contains(n) {
            return false;
        }
    }
    true
}

/// Stable-partition the payload list so payloads that don't depend on
/// `<`/`>` (in any encoded form) come first when active probing has
/// flagged angles as invalid. Pairs with [`prune_blocked_raw_angles`]:
/// pruning kills raw-angle payloads outright, hoisting reorders the
/// remaining list so the angle-free survivors get tested before the
/// encoded-angle variants whose only hope is a naive single-pass-decode
/// filter (rare in practice). Net effect: the first reflection-finding
/// request usually comes from an angle-free payload, the loop short-
/// circuits, and the budget for the param collapses from thousands of
/// requests to dozens.
fn hoist_angle_free_payloads(payloads: Vec<String>, invalid_specials: &[char]) -> Vec<String> {
    let block_lt = invalid_specials.contains(&'<');
    let block_gt = invalid_specials.contains(&'>');
    if !block_lt && !block_gt {
        return payloads;
    }
    let mut clean: Vec<String> = Vec::with_capacity(payloads.len());
    let mut rest: Vec<String> = Vec::with_capacity(payloads.len());
    for p in payloads {
        if payload_is_angle_free(&p) {
            clean.push(p);
        } else {
            rest.push(p);
        }
    }
    clean.extend(rest);
    clean
}

fn get_fallback_reflection_payloads(
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    } else {
        // HTML/attribute payloads first — they break out of attribute contexts
        // and create real DOM elements. JS-only payloads (alert(1), etc.) are
        // excluded from the reflection list because they cause false-positive R
        // findings when reflected inside quoted attribute values, blocking the
        // attribute-breakout payloads that follow.
        base_payloads.extend(crate::payload::get_dynamic_xss_html_payloads());
        base_payloads.extend(crate::payload::get_dynamic_xss_attribute_payloads());
        base_payloads.extend(crate::payload::get_mxss_payloads());
        base_payloads.extend(crate::payload::get_protocol_injection_payloads());
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    }

    // Apply encoder policy to unique base payloads
    let payloads = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);

    Ok(payloads)
}

fn get_js_breakout_payloads() -> Vec<String> {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let base_templates = [
        format!("</script><img src=x onerror={{JS}} class={}>", class_marker),
        format!("</script><svg onload={{JS}} class={}>", class_marker),
        format!("</script><img src=x onerror={{JS}} id={}>", id_marker),
    ];

    let breakout_prefixes: &[&str] = &["", "';", "\";", "*/"];

    let mut payloads = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
        for tmpl in &base_templates {
            for &prefix in breakout_prefixes {
                let payload = format!("{}{}", prefix, tmpl.replace("{JS}", js));
                payloads.push(payload);
            }
        }
    }
    payloads
}

pub(crate) fn get_dom_payloads(
    param: &Param,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match &param.injection_context {
        // JS context: script breakout payloads with markers for DOM verification
        Some(crate::parameter_analysis::InjectionContext::Javascript(_)) => {
            let base_payloads = get_js_breakout_payloads();
            let out = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);
            Ok(out)
        }
        // Known non-JS contexts: use locally generated payloads only (exclude remote) to avoid large cross-product
        Some(ctx) => {
            // If param has analysis data, use adaptive encoding for better bypass
            if param.invalid_specials.is_some() || param.valid_specials.is_some() {
                let invalid = param.invalid_specials.as_deref().unwrap_or_default();
                let valid = param.valid_specials.as_deref().unwrap_or_default();
                let payloads =
                    crate::scanning::xss_common::generate_adaptive_payloads(ctx, invalid, valid);
                return Ok(payloads);
            }
            // Use locally generated payloads only (no remote) to avoid large cross-product in DOM verification
            let base_payloads = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
            // Expand with shared encoder policy helper
            let out = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);
            Ok(out)
        }
        // Unknown context: use HTML + Attribute payloads (+ custom if provided), never error
        None => {
            // Use only local HTML/Attribute payloads (exclude remote) for DOM verification in unknown contexts
            let mut base_payloads = vec![];

            if args.only_custom_payload {
                if let Some(path) = &args.custom_payload {
                    // Avoid erroring when custom payload file is missing
                    base_payloads.extend(
                        crate::scanning::xss_common::load_custom_payloads(path)
                            .unwrap_or_else(|_| vec![]),
                    );
                }
            } else {
                base_payloads.extend(crate::payload::get_dynamic_xss_html_payloads());
                base_payloads.extend(crate::payload::get_dynamic_xss_attribute_payloads());
                base_payloads.extend(crate::payload::get_mxss_payloads());
                base_payloads.extend(crate::payload::get_dom_clobbering_payloads());
                base_payloads.extend(crate::payload::get_protocol_injection_payloads());
                if let Some(path) = &args.custom_payload {
                    base_payloads.extend(
                        crate::scanning::xss_common::load_custom_payloads(path)
                            .unwrap_or_else(|_| vec![]),
                    );
                }
            }

            // Ensure we always have DOM-capable payloads for non-JS contexts
            if base_payloads.is_empty() {
                base_payloads.extend(crate::payload::get_dynamic_xss_html_payloads());
                base_payloads.extend(crate::payload::get_dynamic_xss_attribute_payloads());
            }

            // Expand with shared encoder policy helper
            let out = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);
            Ok(out)
        }
    }
}

/// Run AST-based DOM XSS static analysis on the given response HTML.
///
/// Extracts JavaScript blocks, analyses each for DOM XSS flows, performs
/// lightweight runtime verification, and returns any findings.  De-duplicates
/// against `ast_seen` (shared across calls for the same parameter).
async fn run_ast_dom_analysis(
    client: &reqwest::Client,
    target: &Target,
    param: &Param,
    response_text: &str,
    ast_seen: &mut HashSet<String>,
) -> Vec<crate::scanning::result::Result> {
    let mut results = Vec::new();
    let js_blocks = crate::scanning::ast_integration::extract_javascript_from_html(response_text);
    let script_element_ids =
        crate::scanning::ast_integration::extract_script_element_ids(response_text);
    let trusted_types_enforced = target.trusted_types_enforced();
    for js_code in js_blocks {
        let findings =
            crate::scanning::ast_integration::analyze_javascript_for_dom_xss_with_html_context(
                &js_code,
                target.url.as_str(),
                &script_element_ids,
                trusted_types_enforced,
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
            let mut ast_result = crate::scanning::result::Result::builder(FindingType::AstDetected)
                .inject_type("DOM-XSS")
                .method(crate::scanning::url_inject::effective_method(
                    &target.method,
                    param,
                ))
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
                .message_str(format!("{} (needs runtime confirmation)", description))
                .build();
            ast_result.location = format!("{:?}", param.location);
            if !source_uses_url_surface {
                ast_result.request = Some(build_request_text(target, param, &payload));
            }
            ast_result.response = Some(response_text.to_string());
            // Lightweight runtime verification (non-headless)
            let (verified, rt_resp, note) =
                crate::scanning::light_verify::verify_dom_xss_light_with_client(
                    client, target, param, &payload,
                )
                .await;
            if let Some(runtime_response) = rt_resp {
                ast_result.response = Some(runtime_response);
            }
            if let Some(n) = note {
                ast_result.message_str = format!("{} [{}]", ast_result.message_str, n);
            }
            if verified {
                ast_result.result_type = FindingType::Verified;
                ast_result.severity = "High".to_string();
                ast_result.message_str =
                    format!("{} [light check: verified]", ast_result.message_str);
            } else if self_bootstrap_verified {
                ast_result.result_type = FindingType::Verified;
                ast_result.severity = "High".to_string();
                ast_result.message_str = format!(
                    "{} [static self-bootstrap confirmed]",
                    ast_result.message_str
                );
            } else {
                ast_result.message_str =
                    format!("{} [light check: unverified]", ast_result.message_str);
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
    let trusted_types_enforced = target.trusted_types_enforced();
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
                target.url.as_str(),
                &target.method,
                &vuln.source,
                payload,
                evidence,
                message,
                self_bootstrap_verified,
            ));
        }
    }

    results
}

fn build_request_text(target: &Target, param: &Param, payload: &str) -> String {
    use crate::parameter_analysis::Location;
    let url = match param.location {
        Location::Query => {
            // Show the request against the actual sink URL — form action when
            // the param came from form discovery, otherwise target.url. The
            // displayed PoC must match the URL that scanning actually hits.
            let base = crate::scanning::url_inject::effective_query_base(&target.url, param);
            let mut pairs: Vec<(String, String)> = base
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param.name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param.name.clone(), payload.to_string()));
            }
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = base;
            url.set_query(Some(&query));
            url
        }
        Location::Path => {
            // Inject into a specific path segment (param.name pattern: path_segment_{idx})
            let mut url = target.url.clone();
            if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                let original_path = url.path();
                let mut segments: Vec<&str> = if original_path == "/" {
                    Vec::new()
                } else {
                    original_path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .collect()
                };
                if idx < segments.len() {
                    segments[idx] = payload;
                    let new_path = if segments.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", segments.join("/"))
                    };
                    url.set_path(&new_path);
                }
            }
            url
        }
        Location::Body | Location::JsonBody | Location::MultipartBody => {
            // Body params use the form action URL when discovered from a form,
            // so the displayed request matches the POST actually sent.
            crate::scanning::url_inject::effective_query_base(&target.url, param)
        }
        _ => target.url.clone(),
    };

    let method = crate::scanning::url_inject::effective_method(&target.method, param);
    // Body-bearing locations always send a body; synthesize one when the
    // target has no original `data`, so the displayed PoC isn't an empty POST.
    let (body, content_type): (Option<String>, Option<&'static str>) = match param.location {
        Location::Body => {
            let body = if let Some(data) = &target.data {
                let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(data.as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                let mut found = false;
                for pair in &mut pairs {
                    if pair.0 == param.name {
                        pair.1 = payload.to_string();
                        found = true;
                        break;
                    }
                }
                if !found {
                    pairs.push((param.name.clone(), payload.to_string()));
                }
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(&pairs)
                    .finish()
            } else {
                format!(
                    "{}={}",
                    urlencoding::encode(&param.name),
                    urlencoding::encode(payload)
                )
            };
            (Some(body), Some("application/x-www-form-urlencoded"))
        }
        Location::JsonBody => {
            let body = if let Some(data) = &target.data {
                if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(obj) = json_val.as_object_mut() {
                        obj.insert(
                            param.name.clone(),
                            serde_json::Value::String(payload.to_string()),
                        );
                    }
                    serde_json::to_string(&json_val).unwrap_or_else(|_| data.clone())
                } else if param.value.is_empty() {
                    // An empty `param.value` would make `str::replace` splice the
                    // payload between every byte of `data` (empty-pattern match),
                    // producing a garbled PoC. Re-serialize as `{name: payload}`
                    // instead — identical to the no-data branch below and to what
                    // `inject_payload` actually sends for invalid-JSON bodies.
                    serde_json::json!({ &param.name: payload }).to_string()
                } else {
                    data.replace(&param.value, payload)
                }
            } else {
                serde_json::json!({ &param.name: payload }).to_string()
            };
            (Some(body), Some("application/json"))
        }
        Location::MultipartBody => (target.data.clone(), Some("multipart/form-data")),
        _ => (target.data.clone(), None),
    };

    let mut buf = String::with_capacity(512);

    // Request line
    buf.push_str(&method);
    buf.push(' ');
    buf.push_str(url.path());
    if let Some(q) = url.query() {
        buf.push('?');
        buf.push_str(q);
    }
    buf.push_str(" HTTP/1.1\r\nHost: ");
    buf.push_str(url.host_str().unwrap_or(""));

    let has_ct_header = target
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    for (k, v) in &target.headers {
        buf.push_str("\r\n");
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(v);
    }
    if !has_ct_header && let Some(ct) = content_type {
        buf.push_str("\r\nContent-Type: ");
        buf.push_str(ct);
    }

    if !target.cookies.is_empty() {
        buf.push_str("\r\nCookie: ");
        for (i, (k, v)) in target.cookies.iter().enumerate() {
            if i > 0 {
                buf.push_str("; ");
            }
            buf.push_str(k);
            buf.push('=');
            buf.push_str(v);
        }
    }

    if let Some(data) = &body {
        buf.push_str("\r\nContent-Length: ");
        buf.push_str(&data.len().to_string());
        buf.push_str("\r\n\r\n");
        buf.push_str(data);
    } else {
        buf.push_str("\r\n");
    }

    buf
}

fn ast_source_uses_browser_url_surface(source: &str) -> bool {
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

/// Compute the WAF bypass strategy for this scan. Returns `None` when WAF
/// bypass is disabled (`--waf-bypass off`), no WAF was fingerprinted, or the
/// fingerprint set is empty — in which case payload generation skips the
/// mutation / extra-encoder expansion entirely.
fn compute_waf_strategy(
    target: &Target,
    args: &ScanArgs,
) -> Option<crate::waf::bypass::BypassStrategy> {
    if args.waf_bypass == "off" {
        return None;
    }
    target.waf_info.as_ref().and_then(|waf_info| {
        if waf_info.is_empty() {
            None
        } else {
            let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
            Some(crate::waf::bypass::merge_strategies(&waf_types))
        }
    })
}

/// Whether the response headers carry an **enforcing** CSP with
/// `require-trusted-types-for 'script'`. Used by the server / MCP surfaces —
/// which fetch the page directly rather than through the preflight stage — to
/// give the initial AST DOM analysis the same Trusted Types awareness the CLI
/// path derives from `target.csp_analysis`.
///
/// The report-only variant (`Content-Security-Policy-Report-Only`) is
/// deliberately ignored: it only emits violation reports and enforces nothing,
/// so the browser does not route sinks through the default policy. Treating it
/// as enforcement would suppress genuine findings (a false negative).
pub fn csp_requires_trusted_types(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|v| crate::payload::xss_csp_bypass::analyze_csp(v).require_trusted_types_for)
        .unwrap_or(false)
}

/// Pre-merge the payloads shared across every parameter: CSP-bypass payloads
/// (when CSP was analysed) followed by technology-specific payloads (when a
/// stack was fingerprinted). Built once per scan so [`generate_param_jobs`]
/// can clone the merged set per parameter instead of recomputing it.
fn build_shared_payloads(target: &Target) -> Vec<String> {
    let csp_bypass_payloads: Vec<String> = target
        .csp_analysis
        .as_ref()
        .map(crate::payload::xss_csp_bypass::get_csp_bypass_payloads)
        .unwrap_or_default();
    let tech_payloads: Vec<String> = target
        .tech_info
        .as_ref()
        .map(crate::scanning::tech_detect::get_tech_specific_payloads)
        .unwrap_or_default();
    let mut shared = Vec::with_capacity(csp_bypass_payloads.len() + tech_payloads.len());
    shared.extend(csp_bypass_payloads);
    shared.extend(tech_payloads);
    shared
}

/// Expand a parameter's base payload set into its WAF-bypass variants,
/// keeping the two bypass axes orthogonal instead of multiplying them.
///
/// Output order (front to back), de-duplicated while preserving first
/// occurrence:
///   1. the originals — cheapest, browser-native; they reflect first so a
///      param whose base shape isn't filtered short-circuits immediately;
///   2. raw structural mutations (`<scr<!---->ipt>`, `<ScRiPt>`, …) — the
///      highest-probability WAF bypass that needs no server-side decode,
///      front-loaded so an actively-blocking WAF surfaces a working bypass
///      before we spend requests on the heavier encoder variants;
///   3. encoder variants of the originals (`%3C…`, fullwidth, zwsp, …) —
///      transport-style evasion that relies on the app decoding the wire
///      bytes back into an executable payload.
///
/// Crucially this does *not* emit `encode(mutate(p))`: cross-encoding a
/// structural mutation buries its bypass under transport encoding and needs
/// both an app-side decode *and* browser tolerance of the mutated shape — a
/// compound condition that rarely lands while costing one request apiece.
/// Skipping it shrinks the per-param request count from `N·(1+m)·(1+k)` to
/// `N·(1+m+k)` with no loss of reach on either axis.
///
/// `stats`, when present, records each generated mutation variant against
/// its `MutationType` for `target_summary.waf.bypass.mutations_applied[]`
/// (counted pre-dedup against the encoder set, matching the prior
/// "did the mutation apply" semantics).
fn expand_waf_payloads(
    base: &[String],
    strategy: &crate::waf::bypass::BypassStrategy,
    stats: Option<&crate::waf::bypass::MutationStats>,
) -> Vec<String> {
    // Size both collections to the orthogonal output estimate
    // (`N·(1+m+k)`) so the mutation/encoder passes don't repeatedly rehash
    // and realloc — `base.len()` alone under-allocates by that whole factor.
    let est = base
        .len()
        .saturating_mul(1 + strategy.mutations.len() + strategy.extra_encoders.len());
    let mut seen: HashSet<String> = HashSet::with_capacity(est);
    let mut out: Vec<String> = Vec::with_capacity(est);

    // 1. Originals (de-duplicated), kept at the front.
    for p in base {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }

    // 2. Raw structural mutations — no transport encoding applied.
    if !strategy.mutations.is_empty() {
        let tagged = crate::waf::bypass::apply_mutations_tagged(
            base,
            &strategy.mutations,
            MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD,
        );
        for (p, origin) in tagged {
            // `None` is the unmodified base, already emitted in step 1.
            if let Some(m) = origin {
                if let Some(stats) = stats {
                    stats.record_variant(m);
                }
                if seen.insert(p.clone()) {
                    out.push(p);
                }
            }
        }
    }

    // 3. Encoder variants of the originals. `apply_encoders_to_payloads`
    //    re-emits each original as the first variant of its base; those
    //    collide with step 1 and are dropped by `seen`, leaving only the
    //    genuinely encoded forms.
    if !strategy.extra_encoders.is_empty() {
        for v in crate::encoding::apply_encoders_to_payloads(base, &strategy.extra_encoders) {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }

    out
}

/// === Stage 4: Payload Generation — build per-parameter payload sets ===
///
/// For each (non-fragment) reflection parameter, build a [`ParamPayloadJob`]
/// of `(param, reflection payloads, DOM payloads)` by applying, in order:
/// context-aware base generation, the shared CSP/tech payloads, WAF bypass
/// mutations + extra encoders, the adaptive angle prune/hoist, and the
/// `--max-payloads-per-param` cap. Returns the jobs plus the total payload
/// count used to size the progress bar (one tick per reflection + DOM
/// payload).
fn generate_param_jobs(
    target: &Target,
    args: &ScanArgs,
    waf_strategy: Option<&crate::waf::bypass::BypassStrategy>,
    shared_payloads: &[String],
) -> (Vec<ParamPayloadJob>, u64) {
    let mut total_tasks = 0u64;
    let mut param_jobs: Vec<ParamPayloadJob> = Vec::with_capacity(target.reflection_params.len());
    for param in &target.reflection_params {
        // URL fragments are client-side only — HTTP servers never see
        // them, so reflection probes for `Location::Fragment` params
        // were pure-waste requests (the dry-run summary said
        // "discovered" but the scan sent 0 reqs with the param actually
        // populated). The AST DOM analyzer detects `location.hash`
        // sources from response JS independently, so skipping the
        // server-side scan here doesn't lose detection coverage.
        if matches!(
            param.location,
            crate::parameter_analysis::Location::Fragment
        ) {
            continue;
        }
        let mut reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args)
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args).unwrap_or_else(|_| vec![])
        };
        let mut dom_payloads = get_dom_payloads(param, args).unwrap_or_else(|_| vec![]);

        // Issue #1075: prepend filter-constrained synthesized payloads to the
        // reflection set when active probing produced a character profile for
        // this parameter. (Non-JS DOM payloads receive synthesis separately
        // inside `get_dom_payloads` → `generate_adaptive_payloads`; JS-context
        // DOM payloads use the dedicated script-breakout set instead.) Placing
        // them first lets the first-hit-wins reflection loop try shapes built
        // for this exact filter before the broad catalog, lifting detection on
        // custom filters; under non-`--deep-scan` runs that ordering can also
        // cut requests by hitting earlier.
        //
        // Note: with an explicit small `--max-payloads-per-param` (< the synth
        // count), the truncation below can evict the catalog entirely in favour
        // of these higher-signal synthesized payloads — intentional, since the
        // user asked for few payloads and these are the ones most likely to fire.
        if let Some(context) = &param.injection_context
            && (param.invalid_specials.is_some() || param.valid_specials.is_some())
        {
            let invalid = param.invalid_specials.as_deref().unwrap_or_default();
            let valid = param.valid_specials.as_deref().unwrap_or_default();
            // #1072: escaped-quote signal (JS string contexts) drives synthesis
            // to emit backslash-prefixed breakouts that survive server escaping.
            let escaped = param.escaped_specials.as_deref().unwrap_or_default();
            // #1073 follow-up: the breakout computed from this site's observed
            // inline-<script> prefix, emitted ahead of the fixed catalog.
            let observed_breakout = param.js_breakout.as_deref();
            let synthesized = crate::payload::synthesis::synthesize_payloads(
                context,
                invalid,
                valid,
                escaped,
                observed_breakout,
            );
            if !synthesized.is_empty() {
                let mut seen: std::collections::HashSet<String> =
                    std::collections::HashSet::with_capacity(
                        synthesized.len() + reflection_payloads.len(),
                    );
                let mut merged = Vec::with_capacity(synthesized.len() + reflection_payloads.len());
                for p in synthesized.into_iter().chain(reflection_payloads) {
                    if seen.insert(p.clone()) {
                        merged.push(p);
                    }
                }
                reflection_payloads = merged;
            }
        }

        // Append shared payloads (CSP bypass + tech-specific)
        reflection_payloads.extend(shared_payloads.iter().cloned());
        dom_payloads.extend(shared_payloads.iter().cloned());

        // Apply WAF bypass expansion if a WAF was detected. The two bypass
        // axes are kept orthogonal rather than multiplied together (see
        // `expand_waf_payloads`): structural mutations are sent raw and
        // encoder variants are applied to the originals only, so we never
        // emit the low-yield `encode(mutate(p))` cross product. The tagged
        // mutation pass still feeds `record_variant`, which powers the
        // per-target effectiveness counter in
        // target_summary.waf.bypass.mutations_applied[].
        if let Some(strategy) = waf_strategy {
            let stats = target.mutation_stats.as_deref();
            reflection_payloads = expand_waf_payloads(&reflection_payloads, strategy, stats);
            dom_payloads = expand_waf_payloads(&dom_payloads, strategy, stats);
        }

        // Adaptive prune + reorder: when active probing recorded that the
        // server strips `<` / `>`, (a) drop reflection/DOM payloads whose
        // raw bytes carry those characters (guaranteed misses), and
        // (b) hoist payloads that carry no `<`/`>` in any encoded form to
        // the front of the list. The reorder is the bigger lever: the
        // loop's `reflection_found_locally` short-circuit means the first
        // reflecting payload zeros out the rest of the budget, so putting
        // angle-free payloads (event-handler / quote-breakout shapes that
        // actually work against an angle-stripping filter) before the
        // angle-encoded variants collapses the per-param request count
        // from thousands to dozens on attribute-context params.
        if let Some(invalid) = param.invalid_specials.as_deref()
            && !invalid.is_empty()
        {
            let refl_before = reflection_payloads.len();
            let dom_before = dom_payloads.len();
            reflection_payloads = prune_blocked_raw_angles(reflection_payloads, invalid);
            dom_payloads = prune_blocked_raw_angles(dom_payloads, invalid);
            reflection_payloads = hoist_angle_free_payloads(reflection_payloads, invalid);
            dom_payloads = hoist_angle_free_payloads(dom_payloads, invalid);
            if crate::DEBUG.load(Ordering::Relaxed)
                && (refl_before != reflection_payloads.len() || dom_before != dom_payloads.len())
            {
                eprintln!(
                    "[DBG] adaptive prune (param={}): reflection {}→{}, dom {}→{} (invalid_specials={:?})",
                    param.name,
                    refl_before,
                    reflection_payloads.len(),
                    dom_before,
                    dom_payloads.len(),
                    invalid,
                );
            }
        }

        // --max-payloads-per-param: cap each payload set independently.
        // 0 means unlimited (default), preserving prior behavior.
        let cap = args.max_payloads_per_param;
        if cap > 0 {
            if reflection_payloads.len() > cap {
                reflection_payloads.truncate(cap);
            }
            if dom_payloads.len() > cap {
                dom_payloads.truncate(cap);
            }
        }

        // One pb.inc(1) per reflection payload plus one per DOM payload.
        // The previous `len * (1 + len)` formula overcounted by orders of
        // magnitude, which made `{eta}` meaningless (it would project hours
        // for a sub-minute scan).
        total_tasks += reflection_payloads.len() as u64 + dom_payloads.len() as u64;
        param_jobs.push((param.clone(), reflection_payloads, dom_payloads));
    }
    (param_jobs, total_tasks)
}

/// Build the per-target indicatif progress bar (one tick per reflection /
/// DOM payload). Returns `None` when no `MultiProgress` is supplied (quiet /
/// embedded runs), in which case the scan loop simply skips the `inc(1)`
/// calls.
fn build_scan_progress_bar(
    multi_pb: &Option<Arc<MultiProgress>>,
    total_tasks: u64,
    target: &Target,
) -> Option<ProgressBar> {
    let mp = multi_pb.as_ref()?;
    let pb = mp.add(ProgressBar::new(total_tasks));
    // `{per_sec}` would measure pb-position rate, not HTTP request rate;
    // many `pb.inc(1)` calls here are "no-op" iterations (param already
    // found, payload skipped), which inflated the rate (e.g. 11.5k/s on
    // a 5k-payload scan that finished in 0.4s). See req_per_sec_tracker
    // for the displayed semantics and caveats.
    //
    // The trailing `{wave}` paints "Scanning <url>" with the shared metallic
    // shimmer, re-evaluated on every steady tick from the bar's elapsed time
    // (no extra timer task). `finish_scan_bar` swaps in a `{msg}` style at the
    // end so the completion line replaces the wave instead of duplicating it.
    let req_start = crate::REQUEST_COUNT.load(Ordering::Relaxed);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.cyan} [{elapsed_precise}] [{bar:28.45/238}] {pos:>5}/{len:5} · {req_per_sec} · {wave}",
            )
            .expect("valid progress bar template")
            .tick_chars(crate::utils::shimmer::TICK_CHARS)
            .with_key("req_per_sec", req_per_sec_tracker(req_start))
            .with_key(
                "wave",
                crate::utils::shimmer::wave_tracker(
                    format!("Scanning {}", target.url),
                    crate::utils::shimmer::BAR_WAVE_RESERVE,
                ),
            )
            .progress_chars("█▉▊▋▌▍▎▏░"),
    );
    pb.enable_steady_tick(Duration::from_millis(
        crate::utils::shimmer::FRAME_MS as u64,
    ));
    Some(pb)
}

/// Render `pb` in its terminal "done" state and stop it.
///
/// The in-progress style paints the label through a `{wave}` shimmer and has
/// no `{msg}` slot, so a plain `finish_with_message` would never show the
/// completion text. Swap in a compact `{prefix} [elapsed] {msg}` style first:
/// a status glyph (green `✓` / yellow `⚠`), the elapsed time, then the final
/// message — replacing the wave rather than printing alongside it.
pub(crate) fn finish_scan_bar(pb: &ProgressBar, prefix: String, msg: String) {
    // Keep the completion line on one row too. The finished template is
    // `{prefix} [elapsed] {msg}` — ~13 cols of furniture before `{msg}` — so
    // trim the message to the leftover stderr width. It's a one-shot render
    // (no `\r` redraw), but a wrapped completion line still reads ragged.
    let avail = crate::utils::term::term_cols_stderr()
        .saturating_sub(14)
        .max(8);
    let msg = console::truncate_str(&msg, avail, "…").into_owned();
    // Set the prefix + message *before* swapping the style: the in-progress
    // template ignores both slots, so this stays invisible until the style
    // swap, which then renders the final line in one shot. Doing it the other
    // way round flashes a `✓ [elapsed]` frame with an empty message first.
    pb.set_prefix(prefix);
    pb.set_message(msg);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} [{elapsed_precise}] {msg}")
            .expect("valid finish template"),
    );
    pb.finish();
}

/// Log WAF block statistics gathered during the scan (debug builds only).
fn log_waf_block_stats(target: &Target) {
    if crate::DEBUG.load(Ordering::Relaxed) {
        let total_waf_blocks = crate::WAF_BLOCK_COUNT.load(Ordering::Relaxed);
        if total_waf_blocks > 0 {
            eprintln!(
                "[*] WAF block stats: {} total blocks detected during scan of {}",
                total_waf_blocks, target.url,
            );
        }
    }
}

/// Collapse this target's R findings that are already proven by one of its
/// own V findings on the same `(param, inject_type)`, adjusting
/// `findings_count` for any dropped duplicates. Multiple per-param payload
/// variants typically surface the same logical issue twice — keep the
/// strongest evidence and drop weaker R duplicates. See
/// [`collapse_redundant_reflected`] for the target-scoping rationale.
async fn collapse_target_results(
    results: &Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    findings_count: &Arc<AtomicUsize>,
    target: &Target,
) {
    let mut guard = results.lock().await;
    let before = guard.len();
    let original = std::mem::take(&mut *guard);
    let target_url_str = target.url.to_string();
    let collapsed = collapse_redundant_reflected(original, &target_url_str);
    let after = collapsed.len();
    *guard = collapsed;
    if after < before {
        findings_count.fetch_sub(before - after, Ordering::Relaxed);
    }
}

/// Outcome of a per-parameter scan phase. `Abort` mirrors the pre-refactor
/// `return` out of the worker task: a global `--limit` was reached mid-phase,
/// so the worker stops immediately and drops any results batched so far (the
/// limit is already hit and the scan is winding down). A `break`-style early
/// exit (cancellation) instead yields `Continue`, so later phases run their
/// own cancellation checks and the batched results are still flushed.
enum PhaseFlow {
    Continue,
    Abort,
}

/// Mutable per-parameter state shared across a single worker's probe,
/// reflection, DOM, and HPP phases.
#[derive(Default)]
struct ParamScanState {
    /// Findings batched locally, flushed to the shared vector once at the
    /// end of the worker (one lock acquisition instead of one per finding).
    local_results: Vec<crate::scanning::result::Result>,
    /// AST findings already recorded for this param (dedup key set).
    ast_seen: HashSet<String>,
    /// AST DOM analysis runs at most once per param.
    ast_analysis_done: bool,
    /// Reflection already confirmed for this param locally — skip the
    /// remaining reflection payloads.
    reflection_found_locally: bool,
    /// DOM XSS already confirmed for this param locally — skip the
    /// remaining DOM payloads.
    dom_found_locally: bool,
    /// Per-worker consecutive-WAF-block streak driving the `--waf-evasion`
    /// backoff escalation. Lives on the per-param scan state (one per worker)
    /// so a single scan's ~50 concurrent workers don't reset each other's
    /// streak — which previously kept the escalation from ever firing. Threaded
    /// into `check_reflection_with_response_tracked`.
    waf_streak: std::sync::atomic::AtomicU32,
}

/// Shared, cheaply-clonable context handed to each spawned worker. Every
/// field is an `Arc`/handle, so `clone()` per worker is just a refcount
/// bump (plus a `ProgressBar` clone, itself an `Arc` internally).
#[derive(Clone)]
struct ScanWorkerCtx {
    args: Arc<ScanArgs>,
    target: Arc<Target>,
    client: Arc<reqwest::Client>,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    found_params: Arc<RwLock<FoundParams>>,
    findings_count: Arc<AtomicUsize>,
    pb: Option<ProgressBar>,
    overall_pb: Option<Arc<indicatif::ProgressBar>>,
    limit_result_type: Arc<str>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    finding_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
    semaphore: Arc<Semaphore>,
    /// Live per-parameter completion counter (see `run_scanning`'s
    /// `params_done`). Bumped once per finished parameter worker.
    params_done: Option<Arc<AtomicU32>>,
}

impl ScanWorkerCtx {
    /// True when a cancellation flag was supplied and is now set.
    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }

    /// True when a global `--limit` was supplied and the running findings
    /// tally has reached it.
    fn limit_reached(&self) -> bool {
        self.args
            .limit
            .is_some_and(|lim| self.findings_count.load(Ordering::Relaxed) >= lim)
    }

    /// Stream a new finding through the channel (if provided) before it is
    /// batched into the shared results — so the CLI can print the full
    /// finding block (POC + Issue + Payload + Line) while the scan is still
    /// running instead of waiting for the end-of-scan flush. The response
    /// body is forwarded so the CLI's `L13:` context line can be extracted
    /// from the actual response; it's dropped from the clone at the receiver
    /// after use. Channel is unbounded but the total payload is bounded by
    /// the (small) finding count.
    fn stream_finding(&self, r: &crate::scanning::result::Result) {
        if let Some(tx) = self.finding_tx.as_ref() {
            let _ = tx.send(r.clone());
        }
    }

    /// Flush locally-batched findings into the shared results vector with a
    /// single lock acquisition, bumping `findings_count` by the number that
    /// match `--limit-result-type`.
    async fn flush_results(&self, local_results: &mut Vec<crate::scanning::result::Result>) {
        if local_results.is_empty() {
            return;
        }
        let batch = std::mem::take(local_results);
        let added = count_matching_results(&batch, &self.limit_result_type);
        let mut guard = self.results.lock().await;
        guard.extend(batch);
        self.findings_count.fetch_add(added, Ordering::Relaxed);
    }

    /// Scan a single parameter end-to-end: acquire a worker permit, probe
    /// for reflection (running a one-shot AST analysis on the probe
    /// response), then run the reflection, DOM, and HPP phases before
    /// flushing the batched findings.
    async fn scan_param(
        &self,
        param: Param,
        reflection_payloads: Vec<String>,
        dom_payloads: Vec<String>,
    ) {
        // `acquire()` only errors if the semaphore has been closed. Nothing
        // closes this one today (it lives for the whole scan), so the error
        // path is currently unreachable — but `expect` would turn any future
        // cooperative-shutdown change into a panic across every waiting
        // worker, which is especially bad when dalfox runs embedded as a
        // library / server / MCP backend. A closed semaphore means there is
        // no work left to do, so wind the worker down cleanly (results are
        // batched into the shared vector, so there is nothing to return).
        let Ok(_permit) = self.semaphore.acquire().await else {
            return;
        };

        let mut state = ParamScanState::default();

        // Stage 0: fast probe to avoid large payload blasts on non-reflective
        // params (also runs one-shot AST DOM analysis on the probe response).
        let probe_reflected = self.probe_param(&param, &mut state).await;

        // If probe found no reflection and not in deep_scan, skip heavy
        // payload loops for this param.
        if !probe_reflected && !self.args.deep_scan {
            self.flush_results(&mut state.local_results).await;
            return;
        }

        // Save a reference copy for the HPP phase (only first 5 payloads)
        // before the reflection phase consumes `reflection_payloads`. Gate on
        // the same condition `run_hpp_phase` checks (Query location) so we don't
        // clone payloads for params whose HPP phase would immediately return.
        let hpp_payloads: Vec<String> =
            if self.args.hpp && param.location == crate::parameter_analysis::Location::Query {
                reflection_payloads.iter().take(5).cloned().collect()
            } else {
                vec![]
            };

        if let PhaseFlow::Abort = self
            .run_reflection_phase(&param, reflection_payloads, &mut state)
            .await
        {
            return;
        }
        if let PhaseFlow::Abort = self.run_dom_phase(&param, dom_payloads, &mut state).await {
            return;
        }
        self.run_hpp_phase(&param, hpp_payloads, &mut state).await;

        self.flush_results(&mut state.local_results).await;
    }

    /// Stage 0 fast probe: detect whether the param reflects at all before
    /// blasting the full payload set. Runs the sandwich marker probe, a
    /// one-shot AST DOM analysis on the probe response, and a numeric-only
    /// fallback probe (to catch letter-stripping filters). Returns whether
    /// any reflection was observed; AST findings are pushed into `state`.
    async fn probe_param(&self, param: &Param, state: &mut ParamScanState) -> bool {
        let client = self.client.as_ref();

        // Sandwich probe (OPEN+INNER+CLOSE) so the response check picks up
        // partial reflections (PrefixOnly / SuffixOnly / InnerOnly) where a
        // server-side filter strips a prefix or suffix off the input before
        // echoing — those cases would slip past a single-token contains().
        let probe_payloads: [&str; 1] = [crate::scanning::markers::bracketed_marker()];
        let mut probe_reflected = false;
        let mut probe_response_text: Option<String> = None;
        for pp in probe_payloads {
            let (kind, response_text) = check_reflection_with_response_tracked(
                Some(client),
                &self.target,
                param,
                pp,
                &self.args,
                &state.waf_streak,
            )
            .await;
            if kind.is_some() {
                probe_reflected = true;
                probe_response_text = response_text;
                break;
            } else if let Some(ref text) = response_text {
                // Even if safe-context suppressed the reflection kind,
                // check if the probe marker actually appears in the response.
                // This ensures breakout payloads get a chance to be tried
                // for params reflected inside safe tags (title, textarea, etc.).
                if crate::scanning::markers::classify_probe_reflection(text).detected() {
                    probe_reflected = true;
                    probe_response_text = response_text;
                    break;
                }
                // Keep one response for AST analysis below.
                probe_response_text = response_text;
            }
        }

        // Run AST-based DOM XSS static analysis once using the probe response (if available)
        if !self.args.skip_ast_analysis
            && let Some(ref response_text) = probe_response_text
        {
            state.ast_analysis_done = true;
            let ast_findings = run_ast_dom_analysis(
                client,
                &self.target,
                param,
                response_text,
                &mut state.ast_seen,
            )
            .await;
            for f in &ast_findings {
                self.stream_finding(f);
            }
            state.local_results.extend(ast_findings);
        }

        // If probe found no reflection, try a numeric-only probe to detect
        // letter-stripping filters (e.g., /[a-zA-Z]/ removal).
        if !probe_reflected {
            let numeric_probe = crate::scanning::check_reflection::NUMERIC_PROBE_MARKER;
            let (kind, _) = check_reflection_with_response_tracked(
                Some(client),
                &self.target,
                param,
                numeric_probe,
                &self.args,
                &state.waf_streak,
            )
            .await;
            if kind.is_some() {
                probe_reflected = true;
            }
        }

        probe_reflected
    }

    /// === Stage 5: Reflection Check ===
    ///
    /// Inject each reflection payload, recording an R (Reflected) finding —
    /// or upgrading to a V (Verified) finding when the reflection response
    /// itself already carries browser-executable DOM evidence (the static V
    /// upgrade). Lazily runs AST analysis if the probe had no usable
    /// response. Returns `Abort` when the global limit was reached mid-loop.
    async fn run_reflection_phase(
        &self,
        param: &Param,
        reflection_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) -> PhaseFlow {
        for reflection_payload in reflection_payloads {
            // Check cancellation
            if self.cancelled() {
                break;
            }
            // Early stop if global limit reached
            if self.limit_reached() {
                return PhaseFlow::Abort;
            }
            // Skip reflection if already found for this param
            let reflection_tuple = if state.reflection_found_locally {
                (None, None)
            } else if self.args.deep_scan {
                // deep_scan never records into `found_params.reflection` (the
                // write path short-circuits to `should_add = true` below), so
                // the shared read would always return false. Skip the awaited
                // lock and run the reflection check directly on every payload.
                check_reflection_with_response_tracked(
                    Some(self.client.as_ref()),
                    &self.target,
                    param,
                    &reflection_payload,
                    &self.args,
                    &state.waf_streak,
                )
                .await
            } else {
                let already = self
                    .found_params
                    .read()
                    .await
                    .reflection
                    .contains(&param.name);
                if already {
                    state.reflection_found_locally = true;
                    (None, None)
                } else {
                    check_reflection_with_response_tracked(
                        Some(self.client.as_ref()),
                        &self.target,
                        param,
                        &reflection_payload,
                        &self.args,
                        &state.waf_streak,
                    )
                    .await
                }
            };
            let reflected_kind = reflection_tuple.0;
            let reflection_response_text = reflection_tuple.1;

            // AST-based DOM XSS analysis (enabled by default unless skipped)
            if !self.args.skip_ast_analysis
                && !state.ast_analysis_done
                && let Some(ref response_text) = reflection_response_text
            {
                state.ast_analysis_done = true;
                let ast_findings = run_ast_dom_analysis(
                    self.client.as_ref(),
                    &self.target,
                    param,
                    response_text,
                    &mut state.ast_seen,
                )
                .await;
                for f in &ast_findings {
                    self.stream_finding(f);
                }
                state.local_results.extend(ast_findings);
            }

            if let Some(ref pb) = self.pb {
                pb.inc(1);
            }
            if let Some(ref opb) = self.overall_pb {
                opb.inc(1);
            }
            if let Some(kind) = reflected_kind {
                let should_add = if self.args.deep_scan {
                    true
                } else {
                    let mut found = self.found_params.write().await;
                    if !found.reflection.contains(&param.name) {
                        found.reflection.insert(param.name.clone());
                        state.reflection_found_locally = true;
                        true
                    } else {
                        false
                    }
                };

                if should_add {
                    // Build result URL with the reflected payload (via helper).
                    // Use the form action URL when the param came from form
                    // discovery, so the PoC URL points at the actual sink.
                    let base =
                        crate::scanning::url_inject::effective_query_base(&self.target.url, param);
                    // Build the PoC URL from the *as-sent* payload (pre-encoding
                    // applied — base64 / multi-URL / WAF window-pad) so the
                    // reported URL actually reproduces the finding.
                    // `build_injected_url` preserves existing %-encoding, matching
                    // the dedicated reflection-check PoC path. No-op for the common
                    // case (no pre-encoding → payload unchanged).
                    let poc_payload = crate::encoding::pre_encoding::apply_param_encoding(
                        &reflection_payload,
                        param,
                    );
                    let result_url =
                        crate::scanning::url_inject::build_injected_url(&base, param, &poc_payload);

                    let reflection_note = reflection_kind_note(kind);

                    // Static V upgrade: re-use the reflection response body
                    // to look for browser-executable DOM evidence. Saves one
                    // HTTP request relative to running a separate
                    // `check_dom_verification` request. The four evidence
                    // kinds (marker, executable URL in dangerous attribute,
                    // HTML element with sink handler, JS-context sink call)
                    // are the same set DOM verification ultimately uses, so
                    // the static path is consistent with the dedicated path.
                    //
                    // Without this broader check, multi-site reflections where
                    // the reflection-phase payload already contains the
                    // structurally exploitable bytes (e.g. xssmaze
                    // /realworld/level1 reflecting `<svg onload=alert(1)>`
                    // raw into <h2>, and xssmaze /hpp/level1 where the
                    // first-value reflection renders the unfiltered payload)
                    // surfaced as R-only despite being trivially V — the
                    // adaptive DOM payload generator drops HTML-tag payloads
                    // when angles are reported "invalid" at one of the
                    // reflection sites, and the prior `has_js_context_evidence`
                    // check only covered the `<script>`-block case.
                    let dom_evidence_kind = reflection_response_text.as_deref().and_then(|body| {
                        crate::scanning::check_dom_verification::classify_dom_evidence(
                            &reflection_payload,
                            body,
                        )
                    });

                    let (finding_type, severity, summary, poc_msg) =
                        if let Some(kind) = dom_evidence_kind {
                            // Mark dom_found so we skip redundant DOM verification
                            {
                                let mut found = self.found_params.write().await;
                                found.dom.insert(param.name.clone());
                            }
                            state.dom_found_locally = true;
                            let evidence_label = kind.label();
                            (
                                FindingType::Verified,
                                "High".to_string(),
                                format!(
                                    "DOM verification successful for param {} ({})",
                                    param.name, evidence_label
                                ),
                                format!(
                                    "Triggered XSS Payload ({}): {}={}",
                                    evidence_label, param.name, reflection_payload
                                ),
                            )
                        } else {
                            (
                                FindingType::Reflected,
                                "Info".to_string(),
                                format!(
                                    "Reflected XSS detected for param {} ({})",
                                    param.name, reflection_note
                                ),
                                format!(
                                    "[R] Triggered XSS Payload ({}): {}={}",
                                    reflection_note, param.name, reflection_payload
                                ),
                            )
                        };

                    // Record reflected/verified XSS finding (fallback path).
                    // In SXSS mode, prefix inject_type so downstream output
                    // (JSON, markdown, plain) makes the stored route visible.
                    // Template-shaped payloads (`{{…}}`) further refine the
                    // label to `*-CSTI` so users can tell client-side
                    // template injection apart from generic HTML reflection.
                    let mut result = crate::scanning::result::Result::builder(finding_type)
                        .inject_type(inject_type_for_payload_with_sink(
                            self.args.sxss,
                            &reflection_payload,
                            param.framework_sink.as_deref(),
                        ))
                        .method(crate::scanning::url_inject::effective_method(
                            &self.target.method,
                            param,
                        ))
                        .data(result_url)
                        .param(param.name.clone())
                        .payload(reflection_payload.clone())
                        .evidence(summary)
                        .cwe("CWE-79")
                        .severity(severity)
                        .message_id(606)
                        .message_str(poc_msg)
                        .build();
                    result.location = format!("{:?}", param.location);
                    result.request =
                        Some(build_request_text(&self.target, param, &reflection_payload));
                    result.response = reflection_response_text;

                    self.stream_finding(&result);
                    // Defer pushing to shared results (batched)
                    state.local_results.push(result);
                }
            }
        }
        PhaseFlow::Continue
    }

    /// === Stage 6: DOM Verification ===
    ///
    /// Inject each DOM payload and verify actual DOM evidence, recording a V
    /// (Verified) finding on the first hit (one per param). Returns `Abort`
    /// when the global limit was reached mid-loop.
    async fn run_dom_phase(
        &self,
        param: &Param,
        dom_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) -> PhaseFlow {
        for dom_payload in dom_payloads {
            // Check cancellation
            if self.cancelled() {
                break;
            }
            // Early stop if global limit reached
            if self.limit_reached() {
                return PhaseFlow::Abort;
            }
            // Skip DOM verification if already found for this param
            let already_dom_found = if state.dom_found_locally {
                true
            } else {
                let is_found = self.found_params.read().await.dom.contains(&param.name);
                if is_found {
                    state.dom_found_locally = true;
                }
                is_found
            };
            if already_dom_found {
                if let Some(ref pb) = self.pb {
                    pb.inc(1);
                }
                if let Some(ref opb) = self.overall_pb {
                    opb.inc(1);
                }
                continue;
            }
            let (dom_verified, response_text) = check_dom_verification_with_client(
                self.client.as_ref(),
                &self.target,
                param,
                &dom_payload,
                &self.args,
            )
            .await;
            if dom_verified {
                let should_add = if self.args.deep_scan {
                    true
                } else {
                    let mut found = self.found_params.write().await;
                    if !found.dom.contains(&param.name) {
                        found.dom.insert(param.name.clone());
                        state.dom_found_locally = true;
                        true
                    } else {
                        false
                    }
                };

                if should_add {
                    // Create result (via helper). Use the form action URL
                    // when the param came from form discovery.
                    let base =
                        crate::scanning::url_inject::effective_query_base(&self.target.url, param);
                    // PoC URL from the as-sent payload (see reflection path above)
                    // so window-pad / base64 / multi-URL findings reproduce.
                    let poc_payload =
                        crate::encoding::pre_encoding::apply_param_encoding(&dom_payload, param);
                    let result_url =
                        crate::scanning::url_inject::build_injected_url(&base, param, &poc_payload);

                    // Determine which evidence path proved exploitability
                    // so the V finding's message reflects the route.
                    let evidence_label = response_text
                        .as_deref()
                        .and_then(|body| {
                            crate::scanning::check_dom_verification::classify_dom_evidence(
                                &dom_payload,
                                body,
                            )
                        })
                        .map_or("DOM evidence", |k| k.label());

                    // DOM-verified => Vulnerability
                    let mut result =
                        crate::scanning::result::Result::builder(FindingType::Verified)
                            .inject_type(inject_type_for_payload_with_sink(
                                self.args.sxss,
                                &dom_payload,
                                param.framework_sink.as_deref(),
                            ))
                            .method(crate::scanning::url_inject::effective_method(
                                &self.target.method,
                                param,
                            ))
                            .data(result_url)
                            .param(param.name.clone())
                            .payload(dom_payload.clone())
                            .evidence(format!(
                                "DOM verification successful for param {} ({})",
                                param.name, evidence_label
                            ))
                            .cwe("CWE-79")
                            .severity("High")
                            .message_id(606)
                            .message_str(format!(
                                "Triggered XSS Payload ({}): {}={}",
                                evidence_label, param.name, dom_payload
                            ))
                            .build();
                    result.location = format!("{:?}", param.location);
                    result.request = Some(build_request_text(&self.target, param, &dom_payload));
                    result.response = response_text;

                    self.stream_finding(&result);
                    // Defer pushing to shared results (batched)
                    state.local_results.push(result);
                    break;
                }
            }
            if let Some(ref pb) = self.pb {
                pb.inc(1);
            }
            if let Some(ref opb) = self.overall_pb {
                opb.inc(1);
            }
        }
        PhaseFlow::Continue
    }

    /// HPP (HTTP Parameter Pollution) phase: re-test the param with
    /// duplicate-parameter URLs. Only runs for query params under `--hpp`,
    /// uses a small subset of reflection payloads to avoid request
    /// explosion, and records at most one finding per param.
    async fn run_hpp_phase(
        &self,
        param: &Param,
        hpp_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) {
        if !(self.args.hpp && param.location == crate::parameter_analysis::Location::Query) {
            return;
        }
        use crate::scanning::url_inject::{HppPosition, build_hpp_url};

        // `hpp_payloads` is already the small reflection-payload subset capped
        // by the caller (see `scan_param`), which bounds the request fan-out.
        let hpp_positions = [HppPosition::Last, HppPosition::First, HppPosition::Both];

        'hpp_outer: for hpp_payload in &hpp_payloads {
            if self.limit_reached() {
                break;
            }
            for &position in &hpp_positions {
                if let Some(hpp_url) = build_hpp_url(&self.target.url, param, hpp_payload, position)
                {
                    let (kind, response_text) =
                        crate::scanning::check_reflection::check_reflection_with_hpp_url(
                            self.client.as_ref(),
                            &self.target,
                            param,
                            hpp_payload,
                            &hpp_url,
                            &self.args,
                        )
                        .await;

                    if let Some(kind) = kind {
                        let pos_label = match position {
                            HppPosition::Last => "last",
                            HppPosition::First => "first",
                            HppPosition::Both => "both",
                        };
                        let reflection_note = reflection_kind_note(kind);

                        let mut result =
                            crate::scanning::result::Result::builder(FindingType::Reflected)
                                .inject_type("inHTML-HPP")
                                .method(self.target.method.clone())
                                .data(hpp_url.clone())
                                .param(param.name.clone())
                                .payload(hpp_payload.clone())
                                .evidence(format!(
                                    "HPP bypass: reflected XSS for param {} (position={}, {})",
                                    param.name, pos_label, reflection_note
                                ))
                                .cwe("CWE-79")
                                .severity("Medium")
                                .message_id(606)
                                .message_str(format!(
                                    "[R] HPP Bypass ({}): {}={} (position={})",
                                    reflection_note, param.name, hpp_payload, pos_label
                                ))
                                .build();
                        result.location = format!("{:?}", param.location);
                        result.response = response_text;
                        self.stream_finding(&result);
                        state.local_results.push(result);
                        break 'hpp_outer; // One HPP finding per param is enough
                    }
                }
            }
        }
    }
}

/// Outcome of a `run_scanning` call. Currently carries only the number of
/// per-parameter worker tasks that panicked. The CLI ignores it (it returns it
/// as a statement value); the REST server and MCP runners inspect
/// `worker_panics` so a scan that lost workers to a panic can be surfaced as a
/// partial/failed result instead of being silently reported `done` — a worker
/// panic means the param's findings are incomplete, indistinguishable from
/// "scanned, found nothing" otherwise.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanRunReport {
    pub worker_panics: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_scanning(
    target: &Target,
    args: Arc<ScanArgs>,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    multi_pb: Option<Arc<MultiProgress>>,
    overall_pb: Option<Arc<indicatif::ProgressBar>>,
    findings_count: Arc<AtomicUsize>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    finding_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
    // Live "parameters finished" counter for async front-ends (REST server,
    // MCP). Each per-parameter worker bumps it on completion so pollers see
    // `params_tested` climb during the scan instead of staying pinned at 0
    // until the very end. `None` for the CLI, which renders its own
    // indicatif progress bar from `total_tasks` instead.
    params_done: Option<Arc<AtomicU32>>,
) -> ScanRunReport {
    // Short-circuit scanning when skip_xss_scanning is enabled (e.g., in unit tests)
    if args.skip_xss_scanning {
        return ScanRunReport::default();
    }
    let arc_target = Arc::new(target.clone());
    let shared_client = Arc::new(arc_target.build_client_or_default());
    let semaphore = Arc::new(Semaphore::new(if args.sxss { 1 } else { target.workers }));
    let limit_result_type: Arc<str> = Arc::from(args.limit_result_type.to_uppercase());

    // Reset WAF block counters for this scan
    crate::WAF_BLOCK_COUNT.store(0, Ordering::Relaxed);
    crate::WAF_CONSECUTIVE_BLOCKS.store(0, Ordering::Relaxed);

    // Compute WAF bypass strategy + pre-merge the payloads shared across all
    // parameters (CSP bypass + tech-specific).
    let waf_strategy = compute_waf_strategy(target, &args);
    let shared_payloads = build_shared_payloads(target);

    // === Stage 4: Payload Generation — build per-parameter payload sets ===
    let (param_jobs, total_tasks) =
        generate_param_jobs(target, &args, waf_strategy.as_ref(), &shared_payloads);

    let pb = build_scan_progress_bar(&multi_pb, total_tasks, target);

    let found_params = Arc::new(RwLock::new(FoundParams {
        reflection: HashSet::new(),
        dom: HashSet::new(),
    }));

    let ctx = ScanWorkerCtx {
        args: args.clone(),
        target: arc_target.clone(),
        client: shared_client.clone(),
        results: results.clone(),
        found_params: found_params.clone(),
        findings_count: findings_count.clone(),
        pb: pb.clone(),
        overall_pb: overall_pb.clone(),
        limit_result_type: limit_result_type.clone(),
        cancel: cancel.clone(),
        finding_tx: finding_tx.clone(),
        semaphore: semaphore.clone(),
        params_done: params_done.clone(),
    };

    // === Stage 5 & 6: spawn one worker per parameter (Reflection + DOM) ===
    let mut handles = vec![];
    // Capture the per-job task-local scopes (request counter, WAF backoff, rate
    // limiter) bound by the REST/MCP runners. `tokio::spawn` does NOT inherit
    // task-locals, so each worker re-enters them via `with_job_scopes`;
    // otherwise the injection-phase requests (the bulk of the scan) would bump
    // only the process-wide globals — under-counting per-job `requests_sent`
    // and leaking one scan's WAF backoff into unrelated concurrent scans. No-op
    // on the CLI, which binds no per-job scope.
    let job_scopes = crate::JobScopes::capture();
    for (param_clone, reflection_payloads, dom_payloads) in param_jobs {
        // Check cancellation before spawning next param task
        if ctx.cancelled() {
            if let Some(ref pb) = pb {
                finish_scan_bar(
                    pb,
                    console::style("⚠").yellow().to_string(),
                    format!("Cancelled scanning {}", target.url),
                );
            }
            break;
        }
        let already_found = {
            let fp = found_params.read().await;
            fp.reflection.contains(&param_clone.name) || fp.dom.contains(&param_clone.name)
        };
        if already_found && !args.deep_scan {
            // Skip further testing for this param if reflection or DOM XSS
            // already found and not deep scanning. This param *was* exercised
            // (the finding came from its probe/AST pass), so count it toward
            // the live progress counter — otherwise `params_tested` would
            // permanently under-report it on a cancelled scan.
            if let Some(done) = &ctx.params_done {
                done.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }
        // Early stop if global limit reached. Use `break` (not an early
        // `return`) so the join-drain loop below awaits the already-spawned
        // workers instead of detaching them: a dropped JoinHandle does NOT
        // abort its task, so an early return left workers hitting the target
        // past the stop point, skipped `collapse_target_results` and the
        // worker-panic tally, and let late findings race the server's result
        // snapshot. The tail finishes the progress bar with "Completed scanning".
        if ctx.limit_reached() {
            break;
        }

        let ctx = ctx.clone();
        // Re-enter the per-job scopes inside the spawned worker so the requests
        // it sends are tallied and rate-limited against THIS job, not the
        // process-wide globals (see `JobScopes`). Cheap no-op on the CLI.
        let handle = tokio::spawn(crate::with_job_scopes(job_scopes.clone(), async move {
            ctx.scan_param(param_clone, reflection_payloads, dom_payloads)
                .await;
            // Bump the live completion counter after this parameter is fully
            // processed (covers every `scan_param` exit path, including the
            // non-reflective early return), so async front-ends observe
            // `params_tested` advancing as each worker finishes.
            if let Some(done) = &ctx.params_done {
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
        handles.push(handle);
    }

    let mut worker_panics = 0usize;
    for handle in handles {
        if let Err(e) = handle.await {
            // A JoinError from a worker is almost always a panic inside
            // scan_param (a scanning-pipeline bug). Count it so the caller can
            // mark the scan as partial/failed instead of reporting a clean
            // `done`; the param's findings are incomplete either way.
            if e.is_panic() {
                worker_panics += 1;
            }
            eprintln!("[!] scanning task failed: {e}");
        }
    }

    log_waf_block_stats(target);

    // Collapse this target's R findings that are already proven by one of
    // its own V findings on the same (param, inject_type), scoped to the
    // current target so other targets' findings are never affected.
    collapse_target_results(&results, &findings_count, target).await;

    if let Some(pb) = pb {
        finish_scan_bar(
            &pb,
            console::style("✓").green().to_string(),
            format!("Completed scanning {}", target.url),
        );
    }

    ScanRunReport { worker_panics }
}

/// Drop Reflected findings on the *current target* that are already covered
/// by a Verified finding on the same `(param, inject_type)` for that same
/// target. Verified and AST findings are preserved.
///
/// Scope is critical: this runs at the end of each target's scan against
/// the shared cross-target results vector. Without scoping, a V finding on
/// one target would silently drop every later R finding on different
/// targets that share the same reflection shape (param + inject_type) —
/// which on benchmarks like xssmaze is the common case.
fn collapse_redundant_reflected(
    results: Vec<crate::scanning::result::Result>,
    target_url: &str,
) -> Vec<crate::scanning::result::Result> {
    use std::collections::HashSet;
    let belongs = |data: &str| crate::utils::finding_belongs_to_target(target_url, data);
    let verified_keys: HashSet<(String, String)> = results
        .iter()
        .filter(|r| r.result_type == FindingType::Verified && belongs(&r.data))
        .map(|r| (r.param.clone(), r.inject_type.clone()))
        .collect();
    if verified_keys.is_empty() {
        return results;
    }
    results
        .into_iter()
        .filter(|r| {
            !(r.result_type == FindingType::Reflected
                && belongs(&r.data)
                && verified_keys.contains(&(r.param.clone(), r.inject_type.clone())))
        })
        .collect()
}

pub use xss_blind::{
    CallbackSource, blind_scan_forms, blind_scan_forms_with, blind_scanning, blind_scanning_with,
};

#[cfg(test)]
mod tests;
