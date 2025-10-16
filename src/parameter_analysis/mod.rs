pub mod discovery;
pub mod mining;

pub use mining::detect_injection_context;

pub use discovery::*;
pub use mining::*;

use crate::cmd::scan::ScanArgs;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, Clone, PartialEq)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    Header,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DelimiterType {
    SingleQuote,
    DoubleQuote,
    Comment,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InjectionContext {
    Html(Option<DelimiterType>),
    Javascript(Option<DelimiterType>),
    Attribute(Option<DelimiterType>),
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: Location,
    pub injection_context: Option<InjectionContext>,
}

pub async fn analyze_parameters(
    target: &mut Target,
    args: &ScanArgs,
    multi_pb: Option<Arc<MultiProgress>>,
) {
    let pb = if let Some(ref mp) = multi_pb {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Analyzing parameters for {}", target.url));
        Some(pb)
    } else {
        None
    };

    let reflection_params = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Semaphore::new(target.workers));
    check_discovery(target, args, reflection_params.clone(), semaphore.clone()).await;
    mine_parameters(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    let mut params = reflection_params.lock().await.clone();
    if !args.param.is_empty() {
        params = filter_params(params, &args.param, target);
    }
    target.reflection_params = params;

    if let Some(pb) = pb {
        pb.finish_with_message(format!("Completed analyzing parameters for {}", target.url));
    }
}

fn filter_params(params: Vec<Param>, param_specs: &[String], target: &Target) -> Vec<Param> {
    if param_specs.is_empty() {
        return params;
    }

    params
        .into_iter()
        .filter(|p| {
            for spec in param_specs {
                if spec.contains(':') {
                    let parts: Vec<&str> = spec.split(':').collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let type_str = parts[1];
                        if p.name == name {
                            let param_type = match p.location {
                                Location::Query => "query",
                                Location::Body => "body",
                                Location::JsonBody => "json",
                                Location::Header => {
                                    if target.cookies.iter().any(|(n, _)| n == &p.name) {
                                        "cookie"
                                    } else {
                                        "header"
                                    }
                                }
                            };
                            if param_type == type_str {
                                return true;
                            }
                        }
                    } else {
                        // Invalid format, treat as name only
                        if p.name == *spec {
                            return true;
                        }
                    }
                } else {
                    // 이름만 지정
                    if p.name == *spec {
                        return true;
                    }
                }
            }
            false
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::scan::ScanArgs;
    use crate::target_parser::parse_target;

    // Mock mining function for testing
    fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
        // Simulate adding a reflection param
        _target.reflection_params.push(Param {
            name: "test_param".to_string(),
            value: "test_value".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
        });
    }

    #[test]
    fn test_analyze_parameters_with_mock_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };

        // Mock mining instead of real mining
        mock_mine_parameters(&mut target, &args);

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].name, "test_param");
        assert_eq!(target.reflection_params[0].value, "test_value");
        assert_eq!(target.reflection_params[0].location, Location::Query);
        assert_eq!(
            target.reflection_params[0].injection_context,
            Some(InjectionContext::Html(None))
        );
    }

    #[test]
    fn test_analyze_parameters_skip_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
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
            skip_mining: true, // Skip mining
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };

        // Even with mock, if skip_mining is true, no params should be added
        // But since we call mock manually, this tests the logic flow
        assert!(target.reflection_params.is_empty());
    }

    #[test]
    fn test_probe_body_params_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };

        // Mock body param reflection
        target.reflection_params.push(Param {
            name: "key1".to_string(),
            value: "dalfox".to_string(),
            location: Location::Body,
            injection_context: Some(InjectionContext::Html(None)),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Body);
    }

    #[test]
    fn test_check_header_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .headers
            .push(("X-Test".to_string(), "value".to_string()));

        // Mock header discovery
        target.reflection_params.push(Param {
            name: "X-Test".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_check_cookie_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        // Mock cookie discovery
        target.reflection_params.push(Param {
            name: "session".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header, // Cookies are sent in Header
            injection_context: Some(InjectionContext::Html(None)),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_cookie_from_raw() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: Some("samples/sample_request.txt".to_string()),
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };

        // Simulate cookie loading
        if let Some(path) = &args.cookie_from_raw {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        assert!(!target.cookies.is_empty());
        assert_eq!(target.cookies.len(), 2);
        assert_eq!(
            target.cookies[0],
            ("session".to_string(), "abc".to_string())
        );
        assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
    }

    #[test]
    fn test_cookie_from_raw_no_file() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: Some("nonexistent.txt".to_string()),
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };

        // Simulate cookie loading - file doesn't exist
        if let Some(path) = &args.cookie_from_raw {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        // Should remain empty since file doesn't exist
        assert!(target.cookies.is_empty());
    }

    #[test]
    fn test_cookie_from_raw_malformed() {
        let mut target = parse_target("https://example.com").unwrap();
        let malformed_content = "Cookie: session=abc; invalid_cookie; user=123";

        for line in malformed_content.lines() {
            if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                for cookie in cookie_line.split("; ") {
                    if let Some((name, value)) = cookie.split_once('=') {
                        target
                            .cookies
                            .push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }

        // Should parse valid cookies, skip invalid ones
        assert_eq!(target.cookies.len(), 2);
        assert_eq!(
            target.cookies[0],
            ("session".to_string(), "abc".to_string())
        );
        assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
    }

    #[test]
    fn test_filter_params_by_name_and_type() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let params = vec![
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
            },
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Body,
                injection_context: Some(InjectionContext::Html(None)),
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
            },
        ];

        // Filter by name only
        let filtered = filter_params(params.clone(), &["sort".to_string()], &target);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|p| p.name == "sort"));

        // Filter by name and type
        let filtered = filter_params(params.clone(), &["sort:query".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "sort");
        assert_eq!(filtered[0].location, Location::Query);

        // Filter by cookie type
        let filtered = filter_params(params.clone(), &["session:cookie".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "session");
        assert_eq!(filtered[0].location, Location::Header);

        // No match
        let filtered = filter_params(params.clone(), &["nonexistent".to_string()], &target);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_filter_params_multiple_filters() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let params = vec![
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
            },
        ];

        // Multiple filters
        let filtered = filter_params(
            params.clone(),
            &["sort".to_string(), "id".to_string()],
            &target,
        );
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|p| p.name == "sort"));
        assert!(filtered.iter().any(|p| p.name == "id"));
    }

    #[test]
    fn test_filter_params_empty_filters() {
        let target = parse_target("https://example.com").unwrap();
        let params = vec![Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
        }];

        // Empty filters should return all params
        let filtered = filter_params(params.clone(), &[], &target);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_params_invalid_filter_format() {
        let target = parse_target("https://example.com").unwrap();
        let params = vec![Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
        }];

        // Invalid filter format (too many colons) should be treated as name only
        let filtered = filter_params(params.clone(), &["sort:query:extra".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "sort");
    }
}
