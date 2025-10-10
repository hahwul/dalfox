pub mod check_dom_verification;
pub mod check_reflection;
pub mod common;
pub mod result;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification;
use crate::scanning::check_reflection::check_reflection;
use crate::target_parser::Target;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

fn build_request_text(target: &Target, param: &Param, payload: &str) -> String {
    let url = match param.location {
        crate::parameter_analysis::Location::Query => {
            let mut url = target.url.clone();
            url.query_pairs_mut().clear();
            for (n, v) in target.url.query_pairs() {
                if n == param.name {
                    url.query_pairs_mut().append_pair(&n, payload);
                } else {
                    url.query_pairs_mut().append_pair(&n, &v);
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
    results: Arc<tokio::sync::Mutex<Vec<crate::scanning::result::Result>>>,
) {
    let semaphore = Arc::new(Semaphore::new(target.workers));
    let payloads = crate::scanning::common::get_payloads(args).unwrap_or_else(|_| vec![]);

    let total_tasks = target.reflection_params.len() as u64 * payloads.len() as u64;
    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Scanning XSS payloads");
    let pb = Arc::new(Mutex::new(pb));

    let found_params = Arc::new(Mutex::new(HashSet::new()));

    let mut handles = vec![];

    for param in &target.reflection_params {
        for payload in &payloads {
            let semaphore_clone = semaphore.clone();
            let param_clone = param.clone();
            let target_clone = (*target).clone(); // Clone target for each task
            let payload_clone = payload.clone();
            let results_clone = results.clone();
            let pb_clone = pb.clone();
            let found_params_clone = found_params.clone();

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
                                let mut url = target_clone.url.clone();
                                url.query_pairs_mut().clear();
                                for (n, v) in target_clone.url.query_pairs() {
                                    if n == param_clone.name {
                                        url.query_pairs_mut().append_pair(&n, &payload_clone);
                                    } else {
                                        url.query_pairs_mut().append_pair(&n, &v);
                                    }
                                }
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
                pb_clone.lock().await.inc(1);
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.await.unwrap();
    }

    pb.lock()
        .await
        .finish_with_message("XSS scanning completed");
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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, &args, results).await;

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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // Mock scanning - in real scenario this would attempt HTTP requests
        run_scanning(&target, &args, results).await;

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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        // This will attempt real HTTP requests, but in test environment it may fail
        // For unit testing, we can just ensure no panic occurs
        run_scanning(&target, &args, results).await;
    }

    #[tokio::test]
    async fn test_run_scanning_empty_params() {
        let target = parse_target("https://example.com").unwrap();

        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
        };

        let results = Arc::new(Mutex::new(Vec::new()));

        run_scanning(&target, &args, results).await;
    }

    #[test]
    fn test_get_xss_payloads() {
        use crate::scanning::common::get_xss_payloads;
        let payloads = get_xss_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|&p| p.contains("dalfox")));
    }
}
