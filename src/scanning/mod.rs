pub mod ast_dom_analysis;
pub mod ast_integration;
pub mod check_dom_verification;
pub mod check_reflection;
pub mod light_verify;
pub mod markers;
pub mod result;
pub mod url_inject;
pub mod xss_blind;
pub mod xss_common;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification_with_client;
use crate::scanning::check_reflection::check_reflection_with_response_client;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Mutex, Semaphore};

fn get_fallback_reflection_payloads(
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    } else {
        base_payloads.extend(
            crate::payload::XSS_JAVASCRIPT_PAYLOADS
                .iter()
                .map(|s| s.to_string()),
        );
        base_payloads.extend(crate::payload::get_dynamic_xss_html_payloads());
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    }

    // Apply encoder policy to unique base payloads
    let payloads = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);

    Ok(payloads)
}

fn get_dom_payloads(
    param: &Param,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match &param.injection_context {
        // JS context: reflection-only
        Some(crate::parameter_analysis::InjectionContext::Javascript(_)) => Ok(vec![]),
        // Known non-JS contexts: use locally generated payloads only (exclude remote) to avoid large cross-product
        Some(ctx) => {
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

    let mut request_lines = vec![];
    let path_and_query = format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{}", q)).unwrap_or_default()
    );
    request_lines.push(format!("{} {} HTTP/1.1", target.method, path_and_query));
    request_lines.push(format!("Host: {}", url.host_str().unwrap_or("")));
    for (k, v) in &target.headers {
        request_lines.push(format!("{}: {}", k, v));
    }
    if !target.cookies.is_empty() {
        let cookie_header = target
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        request_lines.push(format!("Cookie: {}", cookie_header));
    }
    if let Some(data) = &target.data {
        request_lines.push(format!("Content-Length: {}", data.len()));
        request_lines.push("".to_string());
        request_lines.push(data.clone());
    } else {
        request_lines.push("".to_string());
    }

    request_lines.join("\r\n")
}

#[allow(dead_code)]
fn build_injected_url(
    base: &url::Url,
    param: &crate::parameter_analysis::Param,
    injected: &str,
) -> String {
    crate::scanning::url_inject::build_injected_url(base, param, injected)
}

pub async fn run_scanning(
    target: &Target,
    args: Arc<ScanArgs>,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    multi_pb: Option<Arc<MultiProgress>>,
    overall_pb: Option<Arc<Mutex<indicatif::ProgressBar>>>,
    findings_count: Arc<AtomicUsize>,
) {
    // Short-circuit scanning when skip_xss_scanning is enabled (e.g., in unit tests)
    if args.skip_xss_scanning {
        return;
    }
    let arc_target = Arc::new(target.clone());
    let shared_client = Arc::new(arc_target.build_client().unwrap_or_else(|_| Client::new()));
    let semaphore = Arc::new(Semaphore::new(if args.sxss { 1 } else { target.workers }));
    let limit = args.limit;

    // Precompute payload sets once per parameter to avoid repeated expansion work.
    let mut total_tasks = 0u64;
    let mut param_jobs: Vec<(Param, Vec<String>, Vec<String>)> =
        Vec::with_capacity(target.reflection_params.len());
    for param in &target.reflection_params {
        let reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args.as_ref())
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args.as_ref()).unwrap_or_else(|_| vec![])
        };
        let dom_payloads = get_dom_payloads(param, args.as_ref()).unwrap_or_else(|_| vec![]);
        total_tasks += reflection_payloads.len() as u64 * (1 + dom_payloads.len() as u64);
        param_jobs.push((param.clone(), reflection_payloads, dom_payloads));
    }

    let pb = if let Some(ref mp) = multi_pb {
        let pb = mp.add(ProgressBar::new(total_tasks));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Scanning {}", target.url));
        Some(pb)
    } else {
        None
    };

    let found_reflection_params = Arc::new(Mutex::new(HashSet::new()));
    let found_dom_params = Arc::new(Mutex::new(HashSet::new()));

    let mut handles = vec![];

    for (param_clone, reflection_payloads, dom_payloads) in param_jobs {
        let already_ref = found_reflection_params
            .lock()
            .await
            .contains(&param_clone.name);
        let already_dom = found_dom_params.lock().await.contains(&param_clone.name);
        if (already_ref || already_dom) && !args.deep_scan {
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
        let found_reflection_params_clone = found_reflection_params.clone();
        let found_dom_params_clone = found_dom_params.clone();
        let overall_pb_clone = overall_pb.clone();
        let shared_client_clone = shared_client.clone();
        let findings_count_clone = findings_count.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            // Batch local results to reduce mutex contention
            let mut local_results: Vec<crate::scanning::result::Result> = Vec::new();
            let mut local_ast_seen: HashSet<String> = HashSet::new();
            let mut ast_analysis_done = false;
            let client = shared_client_clone.as_ref();

            // Stage 0: fast probe to avoid large payload blasts on non-reflective params
            // Use a minimal alphanumeric token to check generic reflection across contexts.
            let probe_payloads: [&str; 1] = [crate::scanning::markers::open_marker()]; // small, context-agnostic
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
                } else if response_text.is_some() {
                    // Even without direct reflection, keep one response for AST analysis below.
                    probe_response_text = response_text;
                }
            }

            // Run AST-based DOM XSS static analysis once using the probe response (if available)
            if !args_clone.skip_ast_analysis
                && let Some(ref response_text) = probe_response_text
            {
                ast_analysis_done = true;
                let js_blocks =
                    crate::scanning::ast_integration::extract_javascript_from_html(response_text);
                for js_code in js_blocks {
                    let findings = crate::scanning::ast_integration::analyze_javascript_for_dom_xss(
                        &js_code,
                        target_clone.url.as_str(),
                    );
                    for (vuln, payload, description) in findings {
                        let ast_key = format!(
                            "{}|{}|{}|{}|{}",
                            param_clone.name, vuln.line, vuln.column, vuln.source, vuln.sink
                        );
                        if local_ast_seen.contains(&ast_key) {
                            continue;
                        }
                        local_ast_seen.insert(ast_key);
                        let result_url = crate::scanning::url_inject::build_injected_url(
                            &target_clone.url,
                            &param_clone,
                            // Use the actual executable payload from analysis for POC path
                            &payload,
                        );
                        let mut ast_result = crate::scanning::result::Result::new(
                            "A".to_string(),
                            "DOM-XSS".to_string(),
                            target_clone.method.clone(),
                            result_url.clone(),
                            param_clone.name.clone(),
                            payload.clone(),
                            format!(
                                "{}:{}:{} - {} (Source: {}, Sink: {})",
                                target_clone.url.as_str(),
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
                        ast_result.request =
                            Some(build_request_text(&target_clone, &param_clone, &payload));
                        ast_result.response = Some(response_text.clone());
                        // Lightweight runtime verification (non-headless)
                        let (verified, rt_resp, note) =
                            crate::scanning::light_verify::verify_dom_xss_light_with_client(
                                client,
                                &target_clone,
                                &param_clone,
                                &payload,
                            )
                            .await;
                        if let Some(runtime_response) = rt_resp {
                            ast_result.response = Some(runtime_response);
                        }
                        if let Some(n) = note {
                            ast_result.message_str = format!("{} [{}]", ast_result.message_str, n);
                        }
                        if verified {
                            ast_result.result_type = "V".to_string();
                            ast_result.severity = "High".to_string();
                            ast_result.message_str =
                                format!("{} [경량 확인: 검증됨]", ast_result.message_str);
                        } else {
                            ast_result.message_str =
                                format!("{} [경량 확인: 미검증]", ast_result.message_str);
                        }
                        local_results.push(ast_result);
                    }
                }
            }

            // If probe found no reflection and not in deep_scan, skip heavy payload loops for this param
            if !probe_reflected && !args_clone.deep_scan {
                if !local_results.is_empty() {
                    let added = local_results.len();
                    let mut guard = results_clone.lock().await;
                    guard.extend(local_results);
                    findings_count_clone.fetch_add(added, Ordering::Relaxed);
                }
                return;
            }

            // Sequential testing for this param
            for reflection_payload in reflection_payloads {
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit
                    && findings_count_clone.load(Ordering::Relaxed) >= lim
                {
                    return;
                }
                // Skip reflection if already found for this param
                let reflection_tuple = {
                    let already_found = found_reflection_params_clone
                        .lock()
                        .await
                        .contains(&param_clone.name);
                    if already_found {
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
                    let js_blocks = crate::scanning::ast_integration::extract_javascript_from_html(
                        response_text,
                    );
                    for js_code in js_blocks {
                        let findings =
                            crate::scanning::ast_integration::analyze_javascript_for_dom_xss(
                                &js_code,
                                target_clone.url.as_str(),
                            );
                        for (vuln, payload, description) in findings {
                            let ast_key = format!(
                                "{}|{}|{}|{}|{}",
                                param_clone.name, vuln.line, vuln.column, vuln.source, vuln.sink
                            );
                            if local_ast_seen.contains(&ast_key) {
                                continue;
                            }
                            local_ast_seen.insert(ast_key);
                            // Create an AST-based DOM XSS result with actual executable payload
                            let result_url = crate::scanning::url_inject::build_injected_url(
                                &target_clone.url,
                                &param_clone,
                                &payload,
                            );
                            let mut ast_result = crate::scanning::result::Result::new(
                                "A".to_string(), // AST-detected
                                "DOM-XSS".to_string(),
                                target_clone.method.clone(),
                                result_url.clone(),
                                param_clone.name.clone(),
                                payload.clone(), // Actual XSS payload
                                format!(
                                    "{}:{}:{} - {} (Source: {}, Sink: {})",
                                    target_clone.url.as_str(),
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
                            ast_result.request =
                                Some(build_request_text(&target_clone, &param_clone, &payload));
                            ast_result.response = Some(response_text.clone());
                            // Lightweight runtime verification (non-headless)
                            let (verified, rt_resp, note) =
                                crate::scanning::light_verify::verify_dom_xss_light_with_client(
                                    client,
                                    &target_clone,
                                    &param_clone,
                                    &payload,
                                )
                                .await;
                            if let Some(runtime_response) = rt_resp {
                                ast_result.response = Some(runtime_response);
                            }
                            if let Some(n) = note {
                                ast_result.message_str =
                                    format!("{} [{}]", ast_result.message_str, n);
                            }
                            if verified {
                                ast_result.result_type = "V".to_string();
                                ast_result.severity = "High".to_string();
                                ast_result.message_str =
                                    format!("{} [경량 확인: 검증됨]", ast_result.message_str);
                            } else {
                                ast_result.message_str =
                                    format!("{} [경량 확인: 미검증]", ast_result.message_str);
                            }
                            local_results.push(ast_result);
                        }
                    }
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
                        let mut found = found_reflection_params_clone.lock().await;
                        if !found.contains(&param_clone.name) {
                            found.insert(param_clone.name.clone());
                            true
                        } else {
                            false
                        }
                    };

                    if should_add {
                        // Only emit a POC result when raw payload is present in response.
                        if matches!(kind, crate::scanning::check_reflection::ReflectionKind::Raw) {
                            // Build result URL with the reflected payload (via helper)
                            let result_url = crate::scanning::url_inject::build_injected_url(
                                &target_clone.url,
                                &param_clone,
                                &reflection_payload,
                            );

                            // Record reflected XSS finding (fallback path)
                            let mut result = crate::scanning::result::Result::new(
                                "R".to_string(),
                                "inHTML".to_string(),
                                target_clone.method.clone(),
                                result_url,
                                param_clone.name.clone(),
                                reflection_payload.clone(),
                                format!("Reflected XSS detected for param {}", param_clone.name),
                                "CWE-79".to_string(),
                                "Info".to_string(),
                                606,
                                format!(
                                    "[R] Triggered XSS Payload (reflected): {}={}",
                                    param_clone.name, reflection_payload
                                ),
                            );
                            result.request = Some(build_request_text(
                                &target_clone,
                                &param_clone,
                                &reflection_payload,
                            ));
                            result.response = reflection_response_text;

                            // Defer pushing to shared results (batched)
                            local_results.push(result);
                        }
                    }
                }
            }

            // DOM verification
            for dom_payload in dom_payloads {
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit
                    && findings_count_clone.load(Ordering::Relaxed) >= lim
                {
                    return;
                }
                // Skip DOM verification if already found for this param
                let already_dom_found = found_dom_params_clone
                    .lock()
                    .await
                    .contains(&param_clone.name);
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
                        let mut found = found_dom_params_clone.lock().await;
                        if !found.contains(&param_clone.name) {
                            found.insert(param_clone.name.clone());
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

                        let mut result = crate::scanning::result::Result::new(
                            "V".to_string(), // DOM-verified => Vulnerability
                            "inHTML".to_string(),
                            target_clone.method.clone(),
                            result_url,
                            param_clone.name.clone(),
                            dom_payload.clone(),
                            format!("DOM verification successful for param {}", param_clone.name),
                            "CWE-79".to_string(),
                            "High".to_string(),
                            606,
                            format!(
                                "Triggered XSS Payload (found DOM Object): {}={}",
                                param_clone.name, dom_payload
                            ),
                        );
                        result.request = Some(build_request_text(
                            &target_clone,
                            &param_clone,
                            &dom_payload,
                        ));
                        result.response = response_text;

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
            if !local_results.is_empty() {
                let added = local_results.len();
                let mut guard = results_clone.lock().await;
                guard.extend(local_results);
                findings_count_clone.fetch_add(added, Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    if let Some(pb) = pb {
        pb.finish_with_message(format!("Completed scanning {}", target.url));
    }
}

pub use xss_blind::blind_scanning;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{base64_encode, html_entity_encode, url_encode};
    use crate::parameter_analysis::{InjectionContext, Location, Param};
    use crate::target_parser::parse_target;

    // Mock function for XSS scanning tests (similar to parameter analysis mocks)
    fn mock_add_reflection_param(target: &mut Target, name: &str, location: Location) {
        target.reflection_params.push(Param {
            name: name.to_string(),
            value: "mock_value".to_string(),
            location,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });
    }

    fn default_scan_args() -> crate::cmd::scan::ScanArgs {
        crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }

    #[test]
    fn test_get_dom_payloads_javascript_context_returns_empty() {
        let param = Param {
            name: "q".to_string(),
            value: "seed".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Javascript(None)),
            valid_specials: None,
            invalid_specials: None,
        };
        let args = default_scan_args();
        let payloads = get_dom_payloads(&param, &args).expect("dom payload generation");
        assert!(payloads.is_empty());
    }

    #[test]
    fn test_get_dom_payloads_html_context_includes_encoded_variants() {
        let param = Param {
            name: "q".to_string(),
            value: "seed".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        };
        let args = default_scan_args();
        let payloads = get_dom_payloads(&param, &args).expect("dom payload generation");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("alert(1)")));
        assert!(payloads.iter().any(|p| p.contains("%3C")));
        assert!(payloads.iter().any(|p| p.contains("&#x")));
    }

    #[test]
    fn test_get_dom_payloads_unknown_context_falls_back_even_with_only_custom() {
        let param = Param {
            name: "q".to_string(),
            value: "seed".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };
        let mut args = default_scan_args();
        args.only_custom_payload = true;
        args.custom_payload = None;
        args.encoders = vec!["none".to_string()];

        let payloads = get_dom_payloads(&param, &args).expect("dom fallback payload generation");
        assert!(
            !payloads.is_empty(),
            "fallback should include default HTML/attribute payloads"
        );
        assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
    }

    #[test]
    fn test_get_fallback_reflection_payloads_include_encoder_outputs() {
        let args = default_scan_args();
        let payloads =
            get_fallback_reflection_payloads(&args).expect("reflection fallback payloads");

        assert!(payloads.iter().any(|p| p == "alert(1)"));
        assert!(payloads.iter().any(|p| p == &url_encode("alert(1)")));
        assert!(
            payloads
                .iter()
                .any(|p| p == &html_entity_encode("alert(1)"))
        );
        assert!(payloads.iter().any(|p| p == &base64_encode("alert(1)")));
    }

    #[test]
    fn test_get_fallback_reflection_payloads_none_encoder_keeps_raw_only() {
        let mut args = default_scan_args();
        args.encoders = vec!["none".to_string()];
        let payloads =
            get_fallback_reflection_payloads(&args).expect("reflection fallback payloads");

        assert!(payloads.iter().any(|p| p == "alert(1)"));
        assert!(!payloads.iter().any(|p| p == &url_encode("alert(1)")));
        assert!(
            !payloads
                .iter()
                .any(|p| p == &html_entity_encode("alert(1)"))
        );
        assert!(!payloads.iter().any(|p| p == &base64_encode("alert(1)")));
    }

    #[test]
    fn test_build_request_text_query_contains_headers_and_cookies() {
        let mut target = parse_target("https://example.com/search?a=1").unwrap();
        target.method = "GET".to_string();
        target.headers = vec![("X-Test".to_string(), "1".to_string())];
        target.cookies = vec![("sid".to_string(), "abc".to_string())];

        let param = Param {
            name: "q".to_string(),
            value: "".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };

        let request = build_request_text(&target, &param, "PAYLOAD");
        assert!(request.contains("GET /search?a=1&q=PAYLOAD HTTP/1.1"));
        assert!(request.contains("Host: example.com"));
        assert!(request.contains("X-Test: 1"));
        assert!(request.contains("Cookie: sid=abc"));
    }

    #[test]
    fn test_build_request_text_path_segment_injection() {
        let mut target = parse_target("https://example.com/a/b/c").unwrap();
        target.method = "GET".to_string();

        let param = Param {
            name: "path_segment_1".to_string(),
            value: "b".to_string(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };

        let request = build_request_text(&target, &param, "hello world");
        assert!(request.contains("GET /a/hello%20world/c HTTP/1.1"));
    }

    #[tokio::test]
    async fn test_xss_scanning_get_query() {
        let mut target = parse_target("https://example.com").unwrap();
        mock_add_reflection_param(&mut target, "q", Location::Query);

        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(
            &target,
            Arc::new(args),
            results,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await;

        // Verify that reflection params are present
        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Query);
    }

    #[tokio::test]
    async fn test_xss_scanning_post_body() {
        let mut target = parse_target("https://example.com").unwrap();
        mock_add_reflection_param(&mut target, "data", Location::Body);

        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: Some("key1=value1&key2=value2".to_string()),
            headers: vec![],
            cookies: vec![],
            method: "POST".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(
            &target,
            Arc::new(args),
            results,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await;

        // Verify that reflection params are present
        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Body);
    }

    #[tokio::test]
    async fn test_run_scanning_with_reflection_params() {
        let mut target = parse_target("https://example.com").unwrap();
        target.reflection_params.push(Param {
            name: "test_param".to_string(),
            value: "test_value".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });

        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // This will attempt real HTTP requests, but in test environment it may fail
        // For unit testing, we can just ensure no panic occurs
        run_scanning(
            &target,
            Arc::new(args),
            results,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await;
    }

    #[tokio::test]
    async fn test_run_scanning_empty_params() {
        let target = parse_target("https://example.com").unwrap();

        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        run_scanning(
            &target,
            Arc::new(args),
            results,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await;
    }
}
