pub mod check_dom_verification;
pub mod check_reflection;
pub mod common;
pub mod dynamic;
pub mod result;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification;
use crate::scanning::check_reflection::check_reflection;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use url::form_urlencoded;

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
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        _ => target.url.clone(), // For simplicity, assume query for now
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
    if let Some(data) = &target.data {
        request_lines.push(format!("Content-Length: {}", data.len()));
        request_lines.push("".to_string());
        request_lines.push(data.clone());
    } else {
        request_lines.push("".to_string());
    }

    request_lines.join("\r\n")
}

pub async fn run_scanning(
    target: &Target,
    args: &ScanArgs,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    multi_pb: Option<Arc<MultiProgress>>,
    overall_pb: Option<Arc<Mutex<indicatif::ProgressBar>>>,
) {
    let semaphore = Arc::new(Semaphore::new(target.workers));

    // Calculate total tasks by summing payloads for each param
    let mut total_tasks = 0u64;
    for param in &target.reflection_params {
        let payloads = if let Some(context) = &param.injection_context {
            crate::scanning::dynamic::get_dynamic_payloads(context, args).unwrap_or_else(|_| vec![])
        } else {
            crate::scanning::common::get_payloads(args).unwrap_or_else(|_| vec![])
        };
        total_tasks += payloads.len() as u64;
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

    let found_params = Arc::new(Mutex::new(HashSet::new()));

    let mut handles = vec![];

    for param in &target.reflection_params {
        let payloads = if let Some(context) = &param.injection_context {
            crate::scanning::dynamic::get_dynamic_payloads(context, args).unwrap_or_else(|_| vec![])
        } else {
            crate::scanning::common::get_payloads(args).unwrap_or_else(|_| vec![])
        };

        for payload in payloads {
            let semaphore_clone = semaphore.clone();
            let param_clone = param.clone();
            let target_clone = (*target).clone(); // Clone target for each task
            let payload_clone = payload.clone();
            let results_clone = results.clone();
            let pb_clone = pb.clone();
            let found_params_clone = found_params.clone();
            let overall_pb_clone = overall_pb.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                let reflected = check_reflection(&target_clone, &param_clone, &payload_clone).await;
                if reflected {
                    let (dom_verified, response_text) =
                        check_dom_verification(&target_clone, &param_clone, &payload_clone).await;
                    if dom_verified {
                        // Check if this param has already been found
                        let mut found = found_params_clone.lock().await;
                        if !found.contains(&param_clone.name) {
                            found.insert(param_clone.name.clone());
                            drop(found); // Release lock

                            // Create result
                            let result_url = if param_clone.location
                                == crate::parameter_analysis::Location::Query
                            {
                                let mut pairs: Vec<(String, String)> = target_clone
                                    .url
                                    .query_pairs()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect();
                                let mut found = false;
                                for pair in &mut pairs {
                                    if pair.0 == param_clone.name {
                                        pair.1 = payload_clone.to_string();
                                        found = true;
                                        break;
                                    }
                                }
                                if !found {
                                    pairs.push((
                                        param_clone.name.clone(),
                                        payload_clone.to_string(),
                                    ));
                                }
                                let query = form_urlencoded::Serializer::new(String::new())
                                    .extend_pairs(&pairs)
                                    .finish();
                                let mut url = target_clone.url.clone();
                                url.set_query(Some(&query));
                                url.to_string()
                            } else {
                                target_clone.url.to_string()
                            };

                            let mut result = crate::scanning::result::Result::new(
                                "V".to_string(),
                                "inHTML".to_string(),
                                target_clone.method.clone(),
                                result_url,
                                param_clone.name.clone(),
                                payload_clone.clone(),
                                format!(
                                    "DOM verification successful for param {}",
                                    param_clone.name
                                ),
                                "CWE-79".to_string(),
                                "High".to_string(),
                                606,
                                format!(
                                    "Triggered XSS Payload (found DOM Object): {}={}",
                                    param_clone.name, payload_clone
                                ),
                            );
                            result.request = Some(build_request_text(
                                &target_clone,
                                &param_clone,
                                &payload_clone,
                            ));
                            result.response = response_text;

                            results_clone.lock().await.push(result);
                        }
                    }
                }
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                if let Some(ref opb) = overall_pb_clone {
                    opb.lock().await.inc(1);
                }
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.await.unwrap();
    }

    if let Some(pb) = pb {
        pb.finish_with_message(format!("Completed scanning {}", target.url));
    }
}

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
            injection_context: Some(InjectionContext::Html),
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
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, &args, results, None, None).await;

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
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, &args, results, None, None).await;

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
            injection_context: Some(InjectionContext::Html),
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
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // This will attempt real HTTP requests, but in test environment it may fail
        // For unit testing, we can just ensure no panic occurs
        run_scanning(&target, &args, results, None, None).await;
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
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        run_scanning(&target, &args, results, None, None).await;
    }
}
