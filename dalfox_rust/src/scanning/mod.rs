pub mod check_dom_verification;
pub mod check_reflection;
pub mod common;

use crate::cmd::scan::ScanArgs;
use crate::scanning::check_dom_verification::check_dom_verification;
use crate::scanning::check_reflection::check_reflection;
use crate::target_parser::Target;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn run_scanning(target: &Target, args: &ScanArgs) {
    let semaphore = Arc::new(Semaphore::new(target.workers));
    let payloads = crate::scanning::common::get_payloads(args).unwrap_or_else(|_| vec![]);

    let mut handles = vec![];

    for param in &target.reflection_params {
        for payload in &payloads {
            let semaphore_clone = semaphore.clone();
            let param_clone = param.clone();
            let target_clone = (*target).clone(); // Clone target for each task
            let payload_clone = payload.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                let reflected = check_reflection(&target_clone, &param_clone, &payload_clone).await;
                if reflected {
                    check_dom_verification(&target_clone, &param_clone, &payload_clone).await;
                }
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.await.unwrap();
    }

    println!("XSS scanning completed for target: {}", target.url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{InjectionContext, Location, Param};
    use crate::target_parser::parse_target;

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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
        };

        // This will attempt real HTTP requests, but in test environment it may fail
        // For unit testing, we can just ensure no panic occurs
        run_scanning(&target, &args).await;
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
            workers: 10,
            custom_blind_xss_payload: None,
            custom_payload: None,
            only_custom_payload: false,
        };

        run_scanning(&target, &args).await;
    }

    #[test]
    fn test_get_xss_payloads() {
        use crate::scanning::common::get_xss_payloads;
        let payloads = get_xss_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|&p| p.contains("dalfox")));
    }
}
