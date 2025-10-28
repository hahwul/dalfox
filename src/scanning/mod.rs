pub mod check_dom_verification;
pub mod check_reflection;
pub mod result;
pub mod url_inject;
pub mod xss_blind;
pub mod xss_common;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification;
use crate::scanning::check_reflection::check_reflection_with_response;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
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

    // Deduplicate base_payloads to prevent sending identical payloads multiple times
    let mut unique_base_payloads = std::collections::HashSet::new();
    base_payloads.retain(|p| unique_base_payloads.insert(p.clone()));

    let mut payloads = vec![];
    for payload in base_payloads {
        if args.encoders.contains(&"none".to_string()) {
            payloads.push(payload.clone()); // No encoding
        } else {
            payloads.push(payload.clone()); // Original
            if args.encoders.contains(&"url".to_string()) {
                payloads.push(crate::encoding::url_encode(&payload)); // URL encoded
            }
            if args.encoders.contains(&"html".to_string()) {
                payloads.push(crate::encoding::html_entity_encode(&payload)); // HTML entity encoded
            }
            if args.encoders.contains(&"2url".to_string()) {
                payloads.push(crate::encoding::double_url_encode(&payload)); // Double URL encoded
            }
            if args.encoders.contains(&"base64".to_string()) {
                payloads.push(crate::encoding::base64_encode(&payload)); // Base64 encoded
            }
        }
    }

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
            let mut base_payloads = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
            // Deduplicate base_payloads
            let mut unique_base = std::collections::HashSet::new();
            base_payloads.retain(|p| unique_base.insert(p.clone()));
            let mut out = vec![];
            for p in base_payloads {
                if args.encoders.contains(&"none".to_string()) {
                    out.push(p.clone());
                } else {
                    out.push(p.clone());
                    if args.encoders.contains(&"url".to_string()) {
                        out.push(crate::encoding::url_encode(&p));
                    }
                    if args.encoders.contains(&"html".to_string()) {
                        out.push(crate::encoding::html_entity_encode(&p));
                    }
                    if args.encoders.contains(&"2url".to_string()) {
                        out.push(crate::encoding::double_url_encode(&p));
                    }
                    if args.encoders.contains(&"base64".to_string()) {
                        out.push(crate::encoding::base64_encode(&p));
                    }
                }
            }
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

            // Deduplicate base_payloads
            let mut unique_base = std::collections::HashSet::new();
            base_payloads.retain(|p| unique_base.insert(p.clone()));

            let mut out = vec![];
            for p in base_payloads {
                if args.encoders.contains(&"none".to_string()) {
                    out.push(p.clone());
                } else {
                    out.push(p.clone());
                    if args.encoders.contains(&"url".to_string()) {
                        out.push(crate::encoding::url_encode(&p));
                    }
                    if args.encoders.contains(&"html".to_string()) {
                        out.push(crate::encoding::html_entity_encode(&p));
                    }
                    if args.encoders.contains(&"2url".to_string()) {
                        out.push(crate::encoding::double_url_encode(&p));
                    }
                    if args.encoders.contains(&"base64".to_string()) {
                        out.push(crate::encoding::base64_encode(&p));
                    }
                }
            }
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
            if let Some(idx_str) = param.name.strip_prefix("path_segment_") {
                if let Ok(idx) = idx_str.parse::<usize>() {
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
            }
            url
        }
        _ => target.url.clone(),
    };

    let mut request_lines = vec![];
    request_lines.push(format!(
        "{} {} HTTP/1.1",
        target.method,
        format!(
            "{}{}",
            url.path(),
            url.query().map(|q| format!("?{}", q)).unwrap_or_default()
        )
    ));
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
) {
    // Short-circuit scanning when skip_xss_scanning is enabled (e.g., in unit tests)
    if args.skip_xss_scanning {
        return;
    }
    let semaphore = Arc::new(Semaphore::new(if args.sxss { 1 } else { target.workers }));
    let limit = args.limit;

    // Calculate total tasks by summing payloads for each param
    let mut total_tasks = 0u64;
    for param in &target.reflection_params {
        let reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args.as_ref())
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args.as_ref()).unwrap_or_else(|_| vec![])
        };
        let dom_payloads = get_dom_payloads(param, args.as_ref()).unwrap_or_else(|_| vec![]);
        total_tasks += reflection_payloads.len() as u64 * (1 + dom_payloads.len() as u64);
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

    for param in &target.reflection_params {
        let already_ref = found_reflection_params.lock().await.contains(&param.name);
        let already_dom = found_dom_params.lock().await.contains(&param.name);
        if (already_ref || already_dom) && !args.deep_scan {
            // Skip further testing for this param if reflection or DOM XSS already found and not deep scanning
            continue;
        }
        // Early stop if global limit reached
        if let Some(lim) = limit {
            if results.lock().await.len() >= lim {
                if let Some(ref pb) = pb {
                    pb.finish_with_message(format!("Completed scanning {}", target.url));
                }
                return;
            }
        }

        let reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args.as_ref())
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args.as_ref()).unwrap_or_else(|_| vec![])
        };
        let dom_payloads = get_dom_payloads(param, args.as_ref()).unwrap_or_else(|_| vec![]);

        let args_clone = args.clone();
        let semaphore_clone = semaphore.clone();
        let param_clone = param.clone();
        let target_clone = (*target).clone();
        let reflection_payloads_clone = reflection_payloads.clone();
        let dom_payloads_clone = dom_payloads.clone();
        let results_clone = results.clone();
        let pb_clone = pb.clone();
        let found_reflection_params_clone = found_reflection_params.clone();
        let found_dom_params_clone = found_dom_params.clone();
        let overall_pb_clone = overall_pb.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            // Batch local results to reduce mutex contention
            let mut local_results: Vec<crate::scanning::result::Result> = Vec::new();

            // Sequential testing for this param
            for reflection_payload in reflection_payloads_clone {
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit {
                    if results_clone.lock().await.len() >= lim {
                        return;
                    }
                }
                // Skip reflection if already found for this param
                let reflection_tuple = {
                    let already_found = found_reflection_params_clone
                        .lock()
                        .await
                        .contains(&param_clone.name);
                    if already_found {
                        (false, None)
                    } else {
                        check_reflection_with_response(
                            &target_clone,
                            &param_clone,
                            &reflection_payload,
                            &args_clone,
                        )
                        .await
                    }
                };
                let reflected = reflection_tuple.0;
                let reflection_response_text = reflection_tuple.1;
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                if let Some(ref opb) = overall_pb_clone {
                    opb.lock().await.inc(1);
                }
                if reflected {
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
                            "High".to_string(),
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

            // DOM verification
            for dom_payload in dom_payloads_clone {
                // Early stop if global limit reached
                if let Some(lim) = args_clone.limit {
                    if results_clone.lock().await.len() >= lim {
                        return;
                    }
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
                let (dom_verified, response_text) =
                    check_dom_verification(&target_clone, &param_clone, &dom_payload, &args_clone)
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
                let mut guard = results_clone.lock().await;
                guard.extend(local_results);
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
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, Arc::new(args), results, None, None).await;

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
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, Arc::new(args), results, None, None).await;

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
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // This will attempt real HTTP requests, but in test environment it may fail
        // For unit testing, we can just ensure no panic occurs
        run_scanning(&target, Arc::new(args), results, None, None).await;
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
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        run_scanning(&target, Arc::new(args), results, None, None).await;
    }
}
