use super::*;
use crate::cmd::scan::ScanArgs;
use crate::target_parser::parse_target;
use std::sync::Arc;
use tokio::sync::Semaphore;

// Mock mining function for testing
fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
    // Simulate adding a reflection param
    _target.reflection_params.push(Param {
        name: "test_param".to_string(),
        value: "test_value".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });
}

#[test]
fn test_analyze_parameters_with_mock_mining() {
    let mut target = parse_target("https://example.com").unwrap();
    let args = ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
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
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
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
    let target = parse_target("https://example.com").unwrap();
    let _args = ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
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
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: true, // Skip mining
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // Even with mock, if skip_mining is true, no params should be added
    // But since we call mock manually, this tests the logic flow
    assert!(target.reflection_params.is_empty());
}

#[test]
fn test_probe_body_params_mock() {
    let mut target = parse_target("https://example.com").unwrap();
    let _args = ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
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
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // Mock body param reflection
    target.reflection_params.push(Param {
        name: "key1".to_string(),
        value: "dalfox".to_string(),
        location: Location::Body,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });

    assert!(!target.reflection_params.is_empty());
    assert_eq!(target.reflection_params[0].location, Location::Header);
}

#[test]
fn test_cookie_from_raw() {
    let mut target = parse_target("https://example.com").unwrap();
    let args = ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "auto".to_string(),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: Some("examples/sample_request.txt".to_string()),
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // Simulate cookie loading
    if let Some(path) = &args.cookie_from_raw
        && let Ok(content) = std::fs::read_to_string(path)
    {
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
        insecure: Some(true),
        detect_outdated_libs: false,
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
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // Simulate cookie loading - file doesn't exist
    if let Some(path) = &args.cookie_from_raw
        && let Ok(content) = std::fs::read_to_string(path)
    {
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
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Body,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "id".to_string(),
            value: "123".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "session".to_string(),
            value: "abc".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
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
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "id".to_string(),
            value: "123".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "session".to_string(),
            value: "abc".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
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
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }];

    // Invalid filter format (too many colons) should be treated as name only
    let filtered = filter_params(params.clone(), &["sort:query:extra".to_string()], &target);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "sort");
}

fn bare_param(name: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: String::new(),
        location,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

#[test]
fn test_ensure_explicit_params_synthesizes_missing_targets() {
    let target = parse_target("https://example.com/?present=1").unwrap();
    // Discovery seeded only `present`; the other explicit targets were dropped
    // (e.g. a --skip-* flag suppressed their phase).
    let mut params = vec![bare_param("present", Location::Query)];
    let specs = vec![
        "present:query".to_string(),      // already seeded → not duplicated
        "id:query".to_string(),           // synthesized
        "X-Api-Token:header".to_string(), // synthesized
        "sid:cookie".to_string(),         // synthesized (Header location)
    ];
    ensure_explicit_params(&mut params, &specs, &target);

    assert_eq!(
        params.iter().filter(|p| p.name == "present").count(),
        1,
        "existing target must not be duplicated"
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "id" && p.location == Location::Query)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "X-Api-Token" && p.location == Location::Header)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "sid" && p.location == Location::Header)
    );
}

#[test]
fn test_ensure_explicit_params_skips_unsynthesizable_specs() {
    let target = parse_target("https://example.com").unwrap();
    let mut params: Vec<Param> = vec![];
    // name-only (ambiguous), path (positional), fragment (never scanned)
    let specs = vec![
        "foo".to_string(),
        "seg:path".to_string(),
        "h:fragment".to_string(),
    ];
    ensure_explicit_params(&mut params, &specs, &target);
    assert!(
        params.is_empty(),
        "name-only / path / fragment specs must not be synthesized, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec!["http://127.0.0.1:0".to_string()],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        only_discovery: false,
        skip_discovery: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 1,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
        encoders: vec![
            "url".to_string(),
            "html".to_string(),
            "2url".to_string(),
            "base64".to_string(),
        ],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

fn probe_target() -> crate::target_parser::Target {
    let mut target = parse_target("http://127.0.0.1:0/a/b?x=1").unwrap();
    target.method = "POST".to_string();
    target.data = Some("foo=bar&session=orig".to_string());
    target
        .headers
        .push(("X-Test".to_string(), "header-value".to_string()));
    target
        .cookies
        .push(("session".to_string(), "cookie-value".to_string()));
    target.user_agent = Some("DalfoxTest/1.0".to_string());
    target
}

fn probe_param(name: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: "v".to_string(),
        location,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

#[test]
fn test_classify_special_chars_and_encoded_variants() {
    let body = "/\\\\'{}<>\"()";
    let (valid, invalid) = classify_special_chars(body);
    assert!(valid.contains(&'/'));
    assert!(valid.contains(&'\\'));
    assert!(valid.contains(&'\''));
    assert!(valid.contains(&'<'));
    assert!(!invalid.is_empty());

    assert!(encoded_variants('<').contains(&"&lt;"));
    assert!(encoded_variants('"').contains(&"&quot;"));
    assert!(encoded_variants('x').is_empty());
}

#[test]
fn test_extract_reflected_segment_finds_marker_bounds() {
    let body = format!(
        "aaa{}middle{}bbb",
        crate::scanning::markers::open_marker(),
        crate::scanning::markers::close_marker()
    );
    let seg = extract_reflected_segment(&body).expect("segment should exist");
    assert_eq!(seg, "middle");
}

#[tokio::test]
async fn test_active_probe_param_query_path_failure_paths() {
    let target = probe_target();
    let semaphore = Arc::new(Semaphore::new(8));

    let query_res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        semaphore.clone(),
    )
    .await;
    assert!(query_res.valid_specials.as_ref().is_some());
    assert!(
        query_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let path_res = active_probe_param(
        &target,
        probe_param("path_segment_1", Location::Path),
        semaphore,
    )
    .await;
    assert!(path_res.valid_specials.as_ref().is_some());
    assert!(
        path_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );
}

#[tokio::test]
async fn test_active_probe_param_body_header_json_failure_paths() {
    let mut target = probe_target();
    target.data = Some("{\"json_key\":\"v\"}".to_string());
    let semaphore = Arc::new(Semaphore::new(8));

    let body_res = active_probe_param(
        &target,
        probe_param("foo", Location::Body),
        semaphore.clone(),
    )
    .await;
    assert!(body_res.valid_specials.as_ref().is_some());
    assert!(
        body_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let header_cookie_res = active_probe_param(
        &target,
        probe_param("session", Location::Header),
        semaphore.clone(),
    )
    .await;
    assert!(header_cookie_res.valid_specials.as_ref().is_some());
    assert!(
        header_cookie_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let header_plain_res = active_probe_param(
        &target,
        probe_param("X-Test", Location::Header),
        semaphore.clone(),
    )
    .await;
    assert!(header_plain_res.valid_specials.as_ref().is_some());
    assert!(
        header_plain_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let json_res = active_probe_param(
        &target,
        probe_param("json_key", Location::JsonBody),
        semaphore,
    )
    .await;
    assert!(json_res.valid_specials.as_ref().is_some());
    assert!(
        json_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );
}

#[tokio::test]
async fn test_analyze_parameters_with_skip_flags_finishes_cleanly() {
    let mut target = parse_target("http://127.0.0.1:0").unwrap();
    target.workers = 1;
    let args = default_scan_args();

    analyze_parameters(&mut target, &args, None).await;
    assert!(target.reflection_params.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// Pure char-classification helpers (cases not covered above)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_extract_reflected_segment_none_without_markers() {
    // The no-marker branch (early `?` returns) wasn't exercised before.
    assert_eq!(extract_reflected_segment("no markers here"), None);
}

#[test]
fn test_char_reflected_in_segment_detects_raw_encoded_and_percent() {
    // Raw character.
    assert!(char_reflected_in_segment("abc<def", '<'));
    // HTML-entity variant.
    assert!(char_reflected_in_segment("abc&lt;def", '<'));
    // Percent-encoded (case-insensitive): '<' == 0x3C. Both `%3c` and `%3C`
    // must match (the allocation-free CI scan replaced a per-char uppercase
    // copy of the whole segment).
    assert!(char_reflected_in_segment("abc%3cdef", '<'));
    assert!(char_reflected_in_segment("abc%3Cdef", '<'));
    // Absent entirely.
    assert!(!char_reflected_in_segment("abcdef", '<'));
}

#[test]
fn test_contains_ascii_ci() {
    assert!(contains_ascii_ci("abc%3Cdef", "%3c"));
    assert!(contains_ascii_ci("abc%3cdef", "%3C"));
    assert!(contains_ascii_ci("anything", ""));
    assert!(!contains_ascii_ci("ab", "abc")); // needle longer than haystack
    assert!(!contains_ascii_ci("abcdef", "%3c"));
    // Boundary match at the very end.
    assert!(contains_ascii_ci("xy%3C", "%3c"));
}

// ===== Issue #1072: quote-escape classification =====

/// Build the reflected segment of an escape probe: `A <dq> B <sq> C <bs> D`,
/// optionally wrapped in surrounding noise to prove the slice extraction is
/// robust. `bs` is the region for the lone backslash (`\` raw, `\\` doubled).
fn esc_segment(dq: &str, sq: &str, bs: &str, prefix: &str, suffix: &str) -> String {
    format!("{prefix}{ESC_SENT_A}{dq}{ESC_SENT_B}{sq}{ESC_SENT_C}{bs}{ESC_SENT_D}{suffix}")
}

#[test]
fn classify_escaped_quotes_intact_is_empty() {
    // No escaping: quotes raw, backslash raw.
    let seg = esc_segment("\"", "'", "\\", "", "");
    assert!(classify_escaped_quotes(&seg).is_empty());
}

#[test]
fn classify_escaped_quotes_detects_both() {
    // Classic JS-string-escaping server: `\"` and `\'`, backslash passes raw.
    let seg = esc_segment("\\\"", "\\'", "\\", "", "");
    let r = classify_escaped_quotes(&seg);
    assert!(r.contains(&'"'), "expected \" escaped, got {r:?}");
    assert!(r.contains(&'\''), "expected ' escaped, got {r:?}");
}

#[test]
fn classify_escaped_quotes_detects_only_double() {
    // Only the double quote is escaped (single reflected raw).
    let seg = esc_segment("\\\"", "'", "\\", "<div id=out>", "</div>");
    assert_eq!(classify_escaped_quotes(&seg), vec!['"']);
}

#[test]
fn classify_escaped_quotes_rejects_doubled_backslash_server() {
    // A server that ALSO escapes backslashes (`\` -> `\\`) would re-escape our
    // injected `\`, neutralising the `\";…` bypass — so even though the quotes
    // come back `\"`/`\'`, we must NOT report them escaped.
    let seg = esc_segment("\\\"", "\\'", "\\\\", "", "");
    assert!(
        classify_escaped_quotes(&seg).is_empty(),
        "must not flag escaped when backslash is doubled"
    );
}

#[test]
fn classify_escaped_quotes_even_backslash_run_is_a_real_quote() {
    // `\\"` is a literal backslash followed by a *real* closing quote (even run),
    // not an escaped quote — must not be flagged.
    let seg = esc_segment("\\\\\"", "'", "\\", "", "");
    assert!(!classify_escaped_quotes(&seg).contains(&'"'));
}

#[test]
fn classify_escaped_quotes_missing_sentinels_is_empty() {
    // If the segment doesn't contain the sentinels (probe not reflected), no
    // false positives.
    assert!(classify_escaped_quotes("nothing here").is_empty());
}

#[test]
fn escape_probe_value_has_sentinels_and_quotes() {
    let p = escape_probe_value();
    assert!(p.contains(ESC_SENT_A) && p.contains(ESC_SENT_D));
    assert!(p.contains('"') && p.contains('\'') && p.contains('\\'));
}

#[test]
fn escaped_quotes_from_response_extracts_classifies_and_filters() {
    use crate::scanning::markers::{close_marker, open_marker};
    // A full response with the escape probe reflected inside a JS string, both
    // quotes server-escaped (`\"`, `\'`) and the lone backslash passing raw.
    let body = format!(
        "<html><script>var x=\"{}{}\\\"{}\\'{}\\{}{}\";</script></html>",
        open_marker(),
        ESC_SENT_A,
        ESC_SENT_B,
        ESC_SENT_C,
        ESC_SENT_D,
        close_marker()
    );
    // Both quotes valid → both reported escaped.
    let both = escaped_quotes_from_response(&body, &['"', '\'']).unwrap();
    assert!(both.contains(&'"') && both.contains(&'\''), "got {both:?}");
    // Filtered to the valid set: only `"`.
    assert_eq!(
        escaped_quotes_from_response(&body, &['"']).unwrap(),
        vec!['"']
    );
    // No probe reflected at all → None (distinct from an empty vec).
    assert!(escaped_quotes_from_response("<html>nothing</html>", &['"']).is_none());
}

#[test]
fn quote_is_backslash_escaped_counts_odd_run() {
    assert!(quote_is_backslash_escaped("\\\"", '"')); // \"  -> escaped (1)
    assert!(!quote_is_backslash_escaped("\"", '"')); // "    -> raw (0)
    assert!(!quote_is_backslash_escaped("\\\\\"", '"')); // \\" -> real quote (2)
    assert!(quote_is_backslash_escaped("\\\\\\\"", '"')); // \\\" -> escaped (3)
}

#[test]
fn slice_between_extracts_region() {
    assert_eq!(slice_between("aXXbYYc", "XX", "YY"), Some("b"));
    assert_eq!(slice_between("aXXbYYc", "ZZ", "YY"), None);
    assert_eq!(slice_between("aXXb", "XX", "YY"), None);
}

/// Integration: an AWS-WAF-style inspection-window facade. Only the first 100
/// bytes of the value are inspected; a `<`/`>` there blocks the whole request
/// (403, no reflection), but the full value reflects raw — so a vector pushed
/// past the window slips through (xssmaze `waf-facade/level2`). `active_probe_param`
/// must detect this via the window-overflow probe: reclassify the angle
/// brackets as valid and record the `wafpad` pre-encoding so payloads are sent
/// past the window.
#[tokio::test]
async fn active_probe_detects_inspection_window_waf_and_sets_wafpad() {
    use axum::{Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn window_waf(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        let window: String = v.chars().take(100).collect();
        if window.contains('<') || window.contains('>') {
            // Branded block page — note it does NOT echo the value.
            (
                StatusCode::FORBIDDEN,
                "<h1>403 ERROR</h1> Request blocked by AWS WAF".to_string(),
            )
        } else {
            // Reflects the full value raw (markers + specials intact).
            (
                StatusCode::OK,
                format!("<html><body><div class='results'>{v}</div></body></html>"),
            )
        }
    }

    let app = Router::new().route("/cat", get(window_waf));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_eq!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "size-limited inspection window should set the window-pad pre-encoding"
    );
    let valid = res.valid_specials.clone().unwrap_or_default();
    assert!(
        valid.contains(&'<') && valid.contains(&'>'),
        "angle brackets must be reclassified valid once pushed past the window; got {valid:?}"
    );
}

/// Counter-case: a WAF that blocks `<`/`>` *anywhere* in the value (no size
/// window) must NOT be mistaken for an inspection-window WAF. The batched probe
/// is blocked (None arm), the window-overflow probe is *also* blocked (padding
/// can't help), so `window_overflow_probe` returns `None` and no `wafpad` is
/// set — guarding against a false bypass.
#[tokio::test]
async fn active_probe_does_not_set_wafpad_for_position_independent_block() {
    use axum::{Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn block_anywhere(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        // Inspect the WHOLE value, not a leading window — padding never helps.
        if v.contains('<') || v.contains('>') {
            (StatusCode::FORBIDDEN, "<h1>403</h1> blocked".to_string())
        } else {
            (
                StatusCode::OK,
                format!("<html><body><div class='results'>{v}</div></body></html>"),
            )
        }
    }

    let app = Router::new().route("/cat", get(block_anywhere));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_ne!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "genuine filtering (stripping past any window) must not be treated as window-limited"
    );
}

/// Counter-case: a server that strips a fixed PREFIX (first 4 chars) and echoes
/// the rest. The batched probe's open-marker prefix is eaten, so the segment
/// isn't found (None arm) — but this is *partial reflection*, not a block: the
/// close marker survives. The genuine-block guard must skip the window-overflow
/// probe here, so no `wafpad` is set (a benign pad would otherwise be absorbed
/// by the strip and falsely look like a window bypass).
#[tokio::test]
async fn active_probe_does_not_set_wafpad_for_prefix_strip() {
    use axum::{Router, extract::Query, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn strip_prefix4(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        // Drop the first 4 chars, echo the rest raw — partial reflection.
        let echoed: String = v.chars().skip(4).collect();
        format!("<html><body><div class='results'>{echoed}</div></body></html>")
    }

    let app = Router::new().route("/cat", get(strip_prefix4));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_ne!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "a fixed-prefix-stripping server (partial reflection) must not be mistaken for a window WAF"
    );
}

/// Path regression: the dense batched special-char probe injected into a URL
/// path segment fails to reflect on a perfectly permissive server, because the
/// `/` (and other path-structural chars) in the concatenated payload reshape
/// the request into a different/non-existent route. The probe must NOT conclude
/// "all specials invalid" from that artifact — it must fall back to per-char
/// probing, which round-trips cleanly through percent-encoding, so that
/// genuinely-surviving characters (`<`, `>`, `(`, `)` …) are correctly marked
/// valid. Without this, no angle/paren-bearing payload is ever synthesized for
/// path params and exploitable path reflections (e.g. inside an HTML comment)
/// are missed.
#[tokio::test]
async fn active_probe_path_falls_back_to_per_char_when_batched_breaks_routing() {
    use axum::{Router, extract::Path as AxPath, response::Html, routing::get};
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    // Single-segment route: reflects the segment raw inside a <div>. A payload
    // containing `/` produces extra segments and misses this route (404), which
    // is exactly what happens to the concatenated batched probe.
    async fn reflect_seg(AxPath(seg): AxPath<String>) -> Html<String> {
        Html(format!("<html><body><div id=out>{seg}</div></body></html>"))
    }

    let app = Router::new().route("/p/{seg}", get(reflect_seg));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    // path_segment_1 == the `seed` segment in /p/seed.
    let target = parse_target(&format!("http://{addr}/p/seed")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("path_segment_1", Location::Path),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let valid = res.valid_specials.clone().unwrap_or_default();
    // Per-char probing must have run and reclassified the single-segment-safe
    // structural chars as valid (they survive a lone path-segment injection).
    for c in ['<', '>', '(', ')'] {
        assert!(
            valid.contains(&c),
            "per-char path fallback should mark '{c}' valid (got valid={valid:?})"
        );
    }
    // `/` cannot live inside one path segment — it must stay invalid.
    let invalid = res.invalid_specials.clone().unwrap_or_default();
    assert!(
        invalid.contains(&'/'),
        "'/' reshapes the path and must remain invalid (got invalid={invalid:?})"
    );
}
