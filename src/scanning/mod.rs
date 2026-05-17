//! # Scanning (Stages 4–6)
//!
//! Drives payload generation, reflection checking, and DOM verification for
//! each probed parameter.
//!
//! ## Stage 4: Payload Generation (`run_scanning` — first half)
//! Builds per-parameter payload sets based on `injection_context`, CSP bypass,
//! technology-specific payloads, and WAF bypass mutations/encoders.
//! Output: `ParamPayloadJob` tuples fed into the concurrent scan loop.
//!
//! ## Stage 5: Reflection Check (see `check_reflection` module)
//! Each payload is injected and the response is checked for reflection.
//!
//! ## Stage 6: DOM Verification (see `check_dom_verification` module)
//! Reflected payloads are verified for actual DOM evidence to upgrade
//! findings from "R" (Reflected) to "V" (DOM-verified).

pub mod ast_dom_analysis;
pub mod ast_integration;
pub mod check_dom_verification;
pub mod check_reflection;
pub mod js_context_verify;
pub mod light_verify;
pub mod markers;
pub mod result;
pub mod selectors;
pub mod tech_detect;
pub mod url_inject;
pub mod xss_blind;
pub mod xss_common;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification_with_client;
use crate::scanning::check_reflection::check_reflection_with_response_client;
use crate::scanning::result::FindingType;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, Semaphore};

/// Maximum number of WAF mutation variants generated per base payload.
/// Prevents payload explosion when WAF bypass mutations are applied.
const MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD: usize = 3;

/// A per-parameter work unit for the scan loop: the parameter, its reflection
/// payloads (checked in Stage 5), and its DOM payloads (verified in Stage 6).
pub type ParamPayloadJob = (Param, Vec<String>, Vec<String>);

/// Count how many results in `results` match the `--limit-result-type` filter.
/// Returns `results.len()` when filter is `"all"` (default).
/// `filter` must already be uppercased (normalised once at scan start).
fn count_matching_results(results: &[crate::scanning::result::Result], filter: &str) -> usize {
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
    for js_code in js_blocks {
        let findings = crate::scanning::ast_integration::analyze_javascript_for_dom_xss(
            &js_code,
            target.url.as_str(),
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
                crate::scanning::url_inject::build_injected_url(&target.url, param, &payload)
            };
            let mut ast_result = crate::scanning::result::Result::new(
                FindingType::AstDetected,
                "DOM-XSS".to_string(),
                target.method.clone(),
                result_url.clone(),
                param.name.clone(),
                payload.clone(),
                format!(
                    "{}:{}:{} - {} (Source: {}, Sink: {})",
                    target.url.as_str(),
                    vuln.line,
                    vuln.column,
                    description,
                    vuln.source,
                    vuln.sink
                ),
                "CWE-79".to_string(),
                "Medium".to_string(),
                0,
                format!("{} (검증 필요)", description),
            );
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
                ast_result.message_str = format!("{} [경량 확인: 검증됨]", ast_result.message_str);
            } else if self_bootstrap_verified {
                ast_result.result_type = FindingType::Verified;
                ast_result.severity = "High".to_string();
                ast_result.message_str =
                    format!("{} [정적 self-bootstrap 확인]", ast_result.message_str);
            } else {
                ast_result.message_str = format!("{} [경량 확인: 미검증]", ast_result.message_str);
            }
            results.push(ast_result);
        }
    }
    results
}

fn build_request_text(target: &Target, param: &Param, payload: &str) -> String {
    let url = match param.location {
        crate::parameter_analysis::Location::Query => {
            let mut pairs: Vec<(String, String)> = target
                .url
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
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        crate::parameter_analysis::Location::Path => {
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
        _ => target.url.clone(),
    };

    let mut buf = String::with_capacity(512);

    // Request line
    buf.push_str(&target.method);
    buf.push(' ');
    buf.push_str(url.path());
    if let Some(q) = url.query() {
        buf.push('?');
        buf.push_str(q);
    }
    buf.push_str(" HTTP/1.1\r\nHost: ");
    buf.push_str(url.host_str().unwrap_or(""));

    for (k, v) in &target.headers {
        buf.push_str("\r\n");
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(v);
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

    if let Some(data) = &target.data {
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

#[allow(clippy::too_many_arguments)]
pub async fn run_scanning(
    target: &Target,
    args: Arc<ScanArgs>,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    multi_pb: Option<Arc<MultiProgress>>,
    overall_pb: Option<Arc<Mutex<indicatif::ProgressBar>>>,
    findings_count: Arc<AtomicUsize>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    finding_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
) {
    // Short-circuit scanning when skip_xss_scanning is enabled (e.g., in unit tests)
    if args.skip_xss_scanning {
        return;
    }
    let arc_target = Arc::new(target.clone());
    let shared_client = Arc::new(arc_target.build_client_or_default());
    let semaphore = Arc::new(Semaphore::new(if args.sxss { 1 } else { target.workers }));
    let limit = args.limit;
    let limit_result_type: Arc<str> = Arc::from(args.limit_result_type.to_uppercase());

    // Reset WAF block counters for this scan
    crate::WAF_BLOCK_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    crate::WAF_CONSECUTIVE_BLOCKS.store(0, std::sync::atomic::Ordering::Relaxed);

    // Compute WAF bypass strategy if WAF was detected
    let waf_strategy = if args.waf_bypass != "off" {
        target.waf_info.as_ref().and_then(|waf_info| {
            if waf_info.is_empty() {
                None
            } else {
                let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
                Some(crate::waf::bypass::merge_strategies(&waf_types))
            }
        })
    } else {
        None
    };

    // Generate CSP bypass payloads if CSP was analyzed
    let csp_bypass_payloads: Vec<String> = target
        .csp_analysis
        .as_ref()
        .map(crate::payload::xss_csp_bypass::get_csp_bypass_payloads)
        .unwrap_or_default();

    // Generate technology-specific payloads
    let tech_payloads: Vec<String> = target
        .tech_info
        .as_ref()
        .map(crate::scanning::tech_detect::get_tech_specific_payloads)
        .unwrap_or_default();

    // Pre-merge shared payloads (CSP bypass + tech-specific) to avoid repeated cloning
    let shared_payloads: Vec<String> = {
        let mut sp = Vec::with_capacity(csp_bypass_payloads.len() + tech_payloads.len());
        sp.extend(csp_bypass_payloads.iter().cloned());
        sp.extend(tech_payloads.iter().cloned());
        sp
    };

    // === Stage 4: Payload Generation — build per-parameter payload sets ===
    let mut total_tasks = 0u64;
    let mut param_jobs: Vec<ParamPayloadJob> = Vec::with_capacity(target.reflection_params.len());
    for param in &target.reflection_params {
        let mut reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args.as_ref())
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args.as_ref()).unwrap_or_else(|_| vec![])
        };
        let mut dom_payloads = get_dom_payloads(param, args.as_ref()).unwrap_or_else(|_| vec![]);

        // Append shared payloads (CSP bypass + tech-specific)
        reflection_payloads.extend(shared_payloads.iter().cloned());
        dom_payloads.extend(shared_payloads.iter().cloned());

        // Apply WAF bypass mutations and extra encoders if WAF was detected
        if let Some(ref strategy) = waf_strategy {
            // Apply mutations (capped per base payload to prevent explosion).
            // Use the tagged variant so we can attribute each generated
            // variant to its mutation type — record_variant feeds the
            // per-target effectiveness counter that surfaces in
            // target_summary.waf.bypass.mutations_applied[].
            if !strategy.mutations.is_empty() {
                let stats = target.mutation_stats.as_ref();
                let tagged_reflect = crate::waf::bypass::apply_mutations_tagged(
                    &reflection_payloads,
                    &strategy.mutations,
                    MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD,
                );
                reflection_payloads = tagged_reflect
                    .into_iter()
                    .map(|(p, origin)| {
                        if let (Some(stats), Some(m)) = (stats, origin) {
                            stats.record_variant(m);
                        }
                        p
                    })
                    .collect();
                let tagged_dom = crate::waf::bypass::apply_mutations_tagged(
                    &dom_payloads,
                    &strategy.mutations,
                    MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD,
                );
                dom_payloads = tagged_dom
                    .into_iter()
                    .map(|(p, origin)| {
                        if let (Some(stats), Some(m)) = (stats, origin) {
                            stats.record_variant(m);
                        }
                        p
                    })
                    .collect();
            }

            // Apply extra WAF bypass encoders to payloads
            if !strategy.extra_encoders.is_empty() {
                reflection_payloads = crate::encoding::apply_encoders_to_payloads(
                    &reflection_payloads,
                    &strategy.extra_encoders,
                );
                dom_payloads = crate::encoding::apply_encoders_to_payloads(
                    &dom_payloads,
                    &strategy.extra_encoders,
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

        // One pb.inc(1) per reflection payload (line ~770) plus one per DOM
        // payload (lines ~904 / ~988). The previous `len * (1 + len)` formula
        // overcounted by orders of magnitude, which made `{eta}` meaningless
        // (it would project hours for a sub-minute scan).
        total_tasks += reflection_payloads.len() as u64 + dom_payloads.len() as u64;
        param_jobs.push((param.clone(), reflection_payloads, dom_payloads));
    }

    let pb = if let Some(ref mp) = multi_pb {
        let pb = mp.add(ProgressBar::new(total_tasks));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({per_sec}, ETA {eta}) {msg}",
                )
                .expect("valid progress bar template")
                .progress_chars("#>-"),
        );
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_message(format!("Scanning {}", target.url));
        Some(pb)
    } else {
        None
    };

    let found_params = Arc::new(RwLock::new(FoundParams {
        reflection: HashSet::new(),
        dom: HashSet::new(),
    }));

    let mut handles = vec![];

    // === Stage 5 & 6: Reflection Check + DOM Verification (per payload) ===
    for (param_clone, reflection_payloads, dom_payloads) in param_jobs {
        // Check cancellation before spawning next param task
        if let Some(ref c) = cancel
            && c.load(Ordering::Relaxed)
        {
            if let Some(ref pb) = pb {
                pb.finish_with_message(format!("Cancelled scanning {}", target.url));
            }
            break;
        }
        let already_found = {
            let fp = found_params.read().await;
            fp.reflection.contains(&param_clone.name) || fp.dom.contains(&param_clone.name)
        };
        if already_found && !args.deep_scan {
            // Skip further testing for this param if reflection or DOM XSS already found and not deep scanning
            continue;
        }
        // Early stop if global limit reached
        if let Some(lim) = limit
            && findings_count.load(Ordering::Relaxed) >= lim
        {
            if let Some(ref pb) = pb {
                pb.finish_with_message(format!("Completed scanning {}", target.url));
            }
            return;
        }

        let args_clone = args.clone();
        let semaphore_clone = semaphore.clone();
        let target_clone = arc_target.clone();
        let results_clone = results.clone();
        let pb_clone = pb.clone();
        let found_params_clone = found_params.clone();
        let overall_pb_clone = overall_pb.clone();
        let shared_client_clone = shared_client.clone();
        let findings_count_clone = findings_count.clone();
        let limit_result_type_clone = limit_result_type.clone();
        let cancel_clone = cancel.clone();
        let finding_tx_clone = finding_tx.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore_clone
                .acquire()
                .await
                .expect("semaphore closed unexpectedly");
            // Batch local results to reduce mutex contention
            let mut local_results: Vec<crate::scanning::result::Result> = Vec::new();
            // Stream every new finding through the channel (if provided) before it's
            // batched into the shared results — so the CLI can print POC lines while
            // the scan is still running instead of waiting for the end-of-scan flush.
            // The printer only needs metadata (type/url/param/payload), so drop the
            // (potentially large) HTTP response body from the clone we send.
            let stream_finding = |r: &crate::scanning::result::Result| {
                if let Some(tx) = finding_tx_clone.as_ref() {
                    let mut light = r.clone();
                    light.response = None;
                    let _ = tx.send(light);
                }
            };
            let mut local_ast_seen: HashSet<String> = HashSet::new();
            let mut ast_analysis_done = false;
            let mut reflection_found_locally = false;
            let mut dom_found_locally = false;
            let client = shared_client_clone.as_ref();

            // Stage 0: fast probe to avoid large payload blasts on non-reflective params.
            // Sandwich probe (OPEN+INNER+CLOSE) so the response check picks up
            // partial reflections (PrefixOnly / SuffixOnly / InnerOnly) where a
            // server-side filter strips a prefix or suffix off the input before
            // echoing — those cases would slip past a single-token contains().
            let probe_payloads: [&str; 1] = [crate::scanning::markers::bracketed_marker()];
            let mut probe_reflected = false;
            let mut probe_response_text: Option<String> = None;
            for pp in probe_payloads {
                let (kind, response_text) = check_reflection_with_response_client(
                    client,
                    &target_clone,
                    &param_clone,
                    pp,
                    &args_clone,
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
            if !args_clone.skip_ast_analysis
                && let Some(ref response_text) = probe_response_text
            {
                ast_analysis_done = true;
                let ast_findings = run_ast_dom_analysis(
                    client,
                    &target_clone,
                    &param_clone,
                    response_text,
                    &mut local_ast_seen,
                )
                .await;
                for f in &ast_findings {
                    stream_finding(f);
                }
                local_results.extend(ast_findings);
            }

            // If probe found no reflection, try a numeric-only probe to detect
            // letter-stripping filters (e.g., /[a-zA-Z]/ removal).
            if !probe_reflected {
                let numeric_probe = "90197752";
                let (kind, _) = check_reflection_with_response_client(
                    client,
                    &target_clone,
                    &param_clone,
                    numeric_probe,
                    &args_clone,
                )
                .await;
                if kind.is_some() {
                    probe_reflected = true;
                }
            }

            // If probe found no reflection and not in deep_scan, skip heavy payload loops for this param
            if !probe_reflected && !args_clone.deep_scan {
                if !local_results.is_empty() {
                    let added = count_matching_results(&local_results, &limit_result_type_clone);
                    let mut guard = results_clone.lock().await;
                    guard.extend(local_results);
                    findings_count_clone.fetch_add(added, Ordering::Relaxed);
                }
                return;
            }

            // Save a reference copy for HPP phase (only first 5 payloads)
            let reflection_payloads_for_hpp: Vec<String> = if args_clone.hpp {
                reflection_payloads.iter().take(5).cloned().collect()
            } else {
                vec![]
            };

            // Sequential testing for this param
            for reflection_payload in reflection_payloads {
                // Check cancellation
                if let Some(ref c) = cancel_clone
                    && c.load(Ordering::Relaxed)
                {
                    break;
                }
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit
                    && findings_count_clone.load(Ordering::Relaxed) >= lim
                {
                    return;
                }
                // Skip reflection if already found for this param
                let reflection_tuple = if reflection_found_locally {
                    (None, None)
                } else {
                    let already = found_params_clone
                        .read()
                        .await
                        .reflection
                        .contains(&param_clone.name);
                    if already {
                        reflection_found_locally = true;
                        (None, None)
                    } else {
                        check_reflection_with_response_client(
                            client,
                            &target_clone,
                            &param_clone,
                            &reflection_payload,
                            &args_clone,
                        )
                        .await
                    }
                };
                let reflected_kind = reflection_tuple.0;
                let reflection_response_text = reflection_tuple.1;

                // AST-based DOM XSS analysis (enabled by default unless skipped)
                if !args_clone.skip_ast_analysis
                    && !ast_analysis_done
                    && let Some(ref response_text) = reflection_response_text
                {
                    ast_analysis_done = true;
                    let ast_findings = run_ast_dom_analysis(
                        client,
                        &target_clone,
                        &param_clone,
                        response_text,
                        &mut local_ast_seen,
                    )
                    .await;
                    for f in &ast_findings {
                        stream_finding(f);
                    }
                    local_results.extend(ast_findings);
                }

                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                if let Some(ref opb) = overall_pb_clone {
                    opb.lock().await.inc(1);
                }
                if let Some(kind) = reflected_kind {
                    let should_add = if args_clone.deep_scan {
                        true
                    } else {
                        let mut found = found_params_clone.write().await;
                        if !found.reflection.contains(&param_clone.name) {
                            found.reflection.insert(param_clone.name.clone());
                            reflection_found_locally = true;
                            true
                        } else {
                            false
                        }
                    };

                    if should_add {
                        // Build result URL with the reflected payload (via helper)
                        let result_url = crate::scanning::url_inject::build_injected_url(
                            &target_clone.url,
                            &param_clone,
                            &reflection_payload,
                        );

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
                        let dom_evidence_kind =
                            reflection_response_text.as_deref().and_then(|body| {
                                crate::scanning::check_dom_verification::classify_dom_evidence(
                                    &reflection_payload,
                                    body,
                                )
                            });

                        let (finding_type, severity, summary, poc_msg) =
                            if let Some(kind) = dom_evidence_kind {
                                // Mark dom_found so we skip redundant DOM verification
                                {
                                    let mut found = found_params_clone.write().await;
                                    found.dom.insert(param_clone.name.clone());
                                }
                                dom_found_locally = true;
                                let evidence_label = kind.label();
                                (
                                    FindingType::Verified,
                                    "High".to_string(),
                                    format!(
                                        "DOM verification successful for param {} ({})",
                                        param_clone.name, evidence_label
                                    ),
                                    format!(
                                        "Triggered XSS Payload ({}): {}={}",
                                        evidence_label, param_clone.name, reflection_payload
                                    ),
                                )
                            } else {
                                (
                                    FindingType::Reflected,
                                    "Info".to_string(),
                                    format!(
                                        "Reflected XSS detected for param {} ({})",
                                        param_clone.name, reflection_note
                                    ),
                                    format!(
                                        "[R] Triggered XSS Payload ({}): {}={}",
                                        reflection_note, param_clone.name, reflection_payload
                                    ),
                                )
                            };

                        // Record reflected/verified XSS finding (fallback path).
                        // In SXSS mode, prefix inject_type so downstream output
                        // (JSON, markdown, plain) makes the stored route visible.
                        // Template-shaped payloads (`{{…}}`) further refine the
                        // label to `*-CSTI` so users can tell client-side
                        // template injection apart from generic HTML reflection.
                        let mut result = crate::scanning::result::Result::new(
                            finding_type,
                            inject_type_for_payload_with_sink(
                                args_clone.sxss,
                                &reflection_payload,
                                param_clone.framework_sink.as_deref(),
                            ),
                            target_clone.method.clone(),
                            result_url,
                            param_clone.name.clone(),
                            reflection_payload.clone(),
                            summary,
                            "CWE-79".to_string(),
                            severity,
                            606,
                            poc_msg,
                        );
                        result.location = format!("{:?}", param_clone.location);
                        result.request = Some(build_request_text(
                            &target_clone,
                            &param_clone,
                            &reflection_payload,
                        ));
                        result.response = reflection_response_text;

                        stream_finding(&result);
                        // Defer pushing to shared results (batched)
                        local_results.push(result);
                    }
                }
            }

            // DOM verification
            for dom_payload in dom_payloads {
                // Check cancellation
                if let Some(ref c) = cancel_clone
                    && c.load(Ordering::Relaxed)
                {
                    break;
                }
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit
                    && findings_count_clone.load(Ordering::Relaxed) >= lim
                {
                    return;
                }
                // Skip DOM verification if already found for this param
                let already_dom_found = if dom_found_locally {
                    true
                } else {
                    let is_found = found_params_clone
                        .read()
                        .await
                        .dom
                        .contains(&param_clone.name);
                    if is_found {
                        dom_found_locally = true;
                    }
                    is_found
                };
                if already_dom_found {
                    if let Some(ref pb) = pb_clone {
                        pb.inc(1);
                    }
                    if let Some(ref opb) = overall_pb_clone {
                        opb.lock().await.inc(1);
                    }
                    continue;
                }
                let (dom_verified, response_text) = check_dom_verification_with_client(
                    client,
                    &target_clone,
                    &param_clone,
                    &dom_payload,
                    &args_clone,
                )
                .await;
                if dom_verified {
                    let should_add = if args_clone.deep_scan {
                        true
                    } else {
                        let mut found = found_params_clone.write().await;
                        if !found.dom.contains(&param_clone.name) {
                            found.dom.insert(param_clone.name.clone());
                            dom_found_locally = true;
                            true
                        } else {
                            false
                        }
                    };

                    if should_add {
                        // Create result (via helper)
                        let result_url = crate::scanning::url_inject::build_injected_url(
                            &target_clone.url,
                            &param_clone,
                            &dom_payload,
                        );

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
                            .map(|k| k.label())
                            .unwrap_or("DOM evidence");

                        let mut result = crate::scanning::result::Result::new(
                            FindingType::Verified, // DOM-verified => Vulnerability
                            inject_type_for_payload_with_sink(
                                args_clone.sxss,
                                &dom_payload,
                                param_clone.framework_sink.as_deref(),
                            ),
                            target_clone.method.clone(),
                            result_url,
                            param_clone.name.clone(),
                            dom_payload.clone(),
                            format!(
                                "DOM verification successful for param {} ({})",
                                param_clone.name, evidence_label
                            ),
                            "CWE-79".to_string(),
                            "High".to_string(),
                            606,
                            format!(
                                "Triggered XSS Payload ({}): {}={}",
                                evidence_label, param_clone.name, dom_payload
                            ),
                        );
                        result.location = format!("{:?}", param_clone.location);
                        result.request = Some(build_request_text(
                            &target_clone,
                            &param_clone,
                            &dom_payload,
                        ));
                        result.response = response_text;

                        stream_finding(&result);
                        // Defer pushing to shared results (batched)
                        local_results.push(result);
                        break;
                    }
                }
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                if let Some(ref opb) = overall_pb_clone {
                    opb.lock().await.inc(1);
                }
            }
            // HPP (HTTP Parameter Pollution) phase: test duplicate-param URLs
            // Only for query params when --hpp is enabled
            if args_clone.hpp && param_clone.location == crate::parameter_analysis::Location::Query
            {
                use crate::scanning::url_inject::{HppPosition, build_hpp_url};

                // Use a small subset of reflection payloads to avoid request explosion
                let hpp_payloads: Vec<String> = reflection_payloads_for_hpp
                    .iter()
                    .take(5)
                    .cloned()
                    .collect();
                let hpp_positions = [HppPosition::Last, HppPosition::First, HppPosition::Both];

                'hpp_outer: for hpp_payload in &hpp_payloads {
                    if let Some(lim) = args_clone.limit
                        && findings_count_clone.load(Ordering::Relaxed) >= lim
                    {
                        break;
                    }
                    for &position in &hpp_positions {
                        if let Some(hpp_url) =
                            build_hpp_url(&target_clone.url, &param_clone, hpp_payload, position)
                        {
                            let (kind, response_text) =
                                crate::scanning::check_reflection::check_reflection_with_hpp_url(
                                    client,
                                    &target_clone,
                                    &param_clone,
                                    hpp_payload,
                                    &hpp_url,
                                    &args_clone,
                                )
                                .await;

                            if let Some(kind) = kind {
                                let pos_label = match position {
                                    HppPosition::Last => "last",
                                    HppPosition::First => "first",
                                    HppPosition::Both => "both",
                                };
                                let reflection_note = reflection_kind_note(kind);

                                let mut result = crate::scanning::result::Result::new(
                                    FindingType::Reflected,
                                    "inHTML-HPP".to_string(),
                                    target_clone.method.clone(),
                                    hpp_url.clone(),
                                    param_clone.name.clone(),
                                    hpp_payload.clone(),
                                    format!(
                                        "HPP bypass: reflected XSS for param {} (position={}, {})",
                                        param_clone.name, pos_label, reflection_note
                                    ),
                                    "CWE-79".to_string(),
                                    "Medium".to_string(),
                                    606,
                                    format!(
                                        "[R] HPP Bypass ({}): {}={} (position={})",
                                        reflection_note, param_clone.name, hpp_payload, pos_label
                                    ),
                                );
                                result.location = format!("{:?}", param_clone.location);
                                result.response = response_text;
                                stream_finding(&result);
                                local_results.push(result);
                                break 'hpp_outer; // One HPP finding per param is enough
                            }
                        }
                    }
                }
            }

            if !local_results.is_empty() {
                let added = count_matching_results(&local_results, &limit_result_type_clone);
                let mut guard = results_clone.lock().await;
                guard.extend(local_results);
                findings_count_clone.fetch_add(added, Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("[!] scanning task failed: {e}");
        }
    }

    // Log WAF block statistics if any blocks were observed (debug only)
    if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        let total_waf_blocks = crate::WAF_BLOCK_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        if total_waf_blocks > 0 {
            eprintln!(
                "[*] WAF block stats: {} total blocks detected during scan of {}",
                total_waf_blocks, target.url,
            );
        }
    }

    // Collapse this target's R findings that are already proven by one of
    // its own V findings on the same (param, inject_type). Multiple per-
    // param payload variants typically surface the same logical issue
    // twice — keep the strongest evidence and drop weaker R duplicates.
    // AST-detected and per-payload V findings are preserved, and the
    // collapse is scoped to the current target so other targets' findings
    // are never affected.
    {
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

    if let Some(pb) = pb {
        pb.finish_with_message(format!("Completed scanning {}", target.url));
    }
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

pub use xss_blind::{blind_scan_forms, blind_scanning};

#[cfg(test)]
mod tests;
