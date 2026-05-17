use super::*;
use crate::parameter_analysis::{InjectionContext, Location, Param};
use crate::target_parser::parse_target;

/// ScanArgs preset for run_scanning integration tests below. Keeps
/// `skip_xss_scanning` toggleable per-test so the empty/short-circuit
/// tests can still opt out of real HTTP traffic while the
/// `realworld_level1_shape_v_upgrade` test exercises the full pipeline.
fn integration_scan_args(skip_xss: bool) -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        input_type: "auto".to_string(),
        format: "json".to_string(),
        targets: vec![],
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
        timeout: 5,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: true,
        silence: true,
        dry_run: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 4,
        max_concurrent_targets: 4,
        max_targets_per_host: 8,
        encoders: vec!["url".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: skip_xss,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 1,
        skip_ast_analysis: true,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

fn make_result(ft: FindingType) -> crate::scanning::result::Result {
    crate::scanning::result::Result::new(
        ft,
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        0,
        String::new(),
    )
}

#[test]
fn test_inject_type_label_for_sxss() {
    // Pins the public JSON contract — downstream tooling parses
    // `inject_type` to distinguish stored from reflected findings.
    // Changes to these strings break consumers; bump intentionally.
    assert_eq!(super::inject_type_label_for(false), "inHTML");
    assert_eq!(super::inject_type_label_for(true), "sxss-inHTML");
}

#[test]
fn test_is_template_shaped_payload_detects_double_braces() {
    assert!(super::is_template_shaped_payload(
        "{{constructor.constructor('alert(1)')()}} <span class=x>"
    ));
    assert!(super::is_template_shaped_payload(
        "{{this.constructor.constructor('alert(1)')()}}"
    ));
}

#[test]
fn test_is_template_shaped_payload_ignores_single_brace_or_html() {
    assert!(!super::is_template_shaped_payload("<svg/onload=alert(1)>"));
    assert!(!super::is_template_shaped_payload("{not-a-template}"));
    assert!(!super::is_template_shaped_payload("{{ unclosed"));
    assert!(!super::is_template_shaped_payload("unopened }}"));
}

#[test]
fn test_inject_type_for_payload_adds_csti_suffix() {
    // Template-shaped payloads get the `-CSTI` suffix so downstream
    // reporters distinguish client-side template injection findings
    // from generic HTML reflections.
    assert_eq!(
        super::inject_type_for_payload(false, "{{constructor.constructor('alert(1)')()}}"),
        "inHTML-CSTI"
    );
    assert_eq!(
        super::inject_type_for_payload(true, "{{constructor.constructor('alert(1)')()}}"),
        "sxss-inHTML-CSTI"
    );
    // Non-template payloads keep the legacy label so existing
    // consumers don't have to relearn the format.
    assert_eq!(
        super::inject_type_for_payload(false, "<svg/onload=alert(1)>"),
        "inHTML"
    );
    assert_eq!(
        super::inject_type_for_payload(true, "<svg/onload=alert(1)>"),
        "sxss-inHTML"
    );
}

#[test]
fn test_count_matching_results_all() {
    let results = vec![
        make_result(FindingType::Verified),
        make_result(FindingType::Reflected),
        make_result(FindingType::AstDetected),
    ];
    assert_eq!(count_matching_results(&results, "ALL"), 3);
}

#[test]
fn test_count_matching_results_filtered() {
    let results = vec![
        make_result(FindingType::Verified),
        make_result(FindingType::Reflected),
        make_result(FindingType::Reflected),
        make_result(FindingType::AstDetected),
    ];
    assert_eq!(count_matching_results(&results, "V"), 1);
    assert_eq!(count_matching_results(&results, "R"), 2);
    assert_eq!(count_matching_results(&results, "A"), 1);
}

#[test]
fn test_count_matching_results_empty() {
    let results: Vec<crate::scanning::result::Result> = vec![];
    assert_eq!(count_matching_results(&results, "ALL"), 0);
    assert_eq!(count_matching_results(&results, "V"), 0);
}

fn make_typed_param_result(
    ft: FindingType,
    param: &str,
    inject: &str,
) -> crate::scanning::result::Result {
    make_typed_param_result_for(ft, param, inject, "https://example.com/?x=1")
}

fn make_typed_param_result_for(
    ft: FindingType,
    param: &str,
    inject: &str,
    data: &str,
) -> crate::scanning::result::Result {
    crate::scanning::result::Result::new(
        ft,
        inject.to_string(),
        "GET".to_string(),
        data.to_string(),
        param.to_string(),
        "PAY".to_string(),
        String::new(),
        "CWE-79".to_string(),
        "Info".to_string(),
        606,
        String::new(),
    )
}

#[test]
fn test_collapse_drops_r_when_v_exists_for_same_param_and_inject_type() {
    let results = vec![
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
        make_typed_param_result(FindingType::Verified, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
    ];
    let after = collapse_redundant_reflected(results, "https://example.com/?x=1");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].result_type, FindingType::Verified);
}

#[test]
fn test_collapse_keeps_r_when_no_v_for_that_param() {
    let results = vec![
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
    ];
    let after = collapse_redundant_reflected(results, "https://example.com/?x=1");
    assert_eq!(after.len(), 2, "no V to cover, keep R findings");
}

#[test]
fn test_collapse_keeps_r_for_different_param_or_inject_type() {
    let results = vec![
        make_typed_param_result(FindingType::Verified, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML-HPP"),
        make_typed_param_result(FindingType::Reflected, "other", "inHTML"),
    ];
    let after = collapse_redundant_reflected(results, "https://example.com/?x=1");
    assert_eq!(
        after.len(),
        3,
        "different inject_type or param must be kept"
    );
}

#[test]
fn test_collapse_does_not_drop_r_from_other_targets() {
    // V on target A must not drop R on target B even when (param, inject)
    // shape matches — this was the regression that caused mass false-clean
    // in batch scans of e.g. xssmaze.
    let results = vec![
        make_typed_param_result_for(
            FindingType::Verified,
            "q",
            "inHTML",
            "http://a.example/?q=1",
        ),
        make_typed_param_result_for(
            FindingType::Reflected,
            "q",
            "inHTML",
            "http://b.example/?q=1",
        ),
    ];
    // Run collapse for target A — must keep B's R.
    let after = collapse_redundant_reflected(results, "http://a.example/?q=1");
    assert_eq!(after.len(), 2);
    assert!(
        after
            .iter()
            .any(|r| r.data.starts_with("http://b.example")
                && r.result_type == FindingType::Reflected)
    );
}

#[test]
fn test_collapse_drops_r_within_path_injection_target() {
    // Same path-injection target — different payload encoded into the
    // last segment. R must collapse against V.
    let target = "http://a.example/path/level1/seed";
    let results = vec![
        make_typed_param_result_for(
            FindingType::Verified,
            "p",
            "inHTML",
            "http://a.example/path/level1/%3Cimg%3E",
        ),
        make_typed_param_result_for(
            FindingType::Reflected,
            "p",
            "inHTML",
            "http://a.example/path/level1/%3Csvg%3E",
        ),
    ];
    let after = collapse_redundant_reflected(results, target);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].result_type, FindingType::Verified);
}

#[test]
fn test_collapse_preserves_ast_findings() {
    let results = vec![
        make_typed_param_result(FindingType::Verified, "q", "inHTML"),
        make_typed_param_result(FindingType::AstDetected, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
    ];
    let after = collapse_redundant_reflected(results, "https://example.com/?x=1");
    assert_eq!(after.len(), 2);
    assert!(
        after
            .iter()
            .any(|r| r.result_type == FindingType::AstDetected)
    );
}

// Mock function for XSS scanning tests (similar to parameter analysis mocks)
fn mock_add_reflection_param(target: &mut Target, name: &str, location: Location) {
    target.reflection_params.push(Param {
        name: name.to_string(),
        value: "mock_value".to_string(),
        location,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

#[test]
fn test_get_dom_payloads_javascript_context_returns_breakout_payloads() {
    let param = Param {
        name: "q".to_string(),
        value: "seed".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Javascript(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    };
    let args = default_scan_args();
    let payloads = get_dom_payloads(&param, &args).expect("dom payload generation");
    assert!(
        !payloads.is_empty(),
        "JS context should now produce script breakout payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("</script>")),
        "should contain script breakout"
    );
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
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
    let payloads = get_fallback_reflection_payloads(&args).expect("reflection fallback payloads");

    // Should include HTML payloads (not raw JS like alert(1))
    assert!(payloads.iter().any(|p| p.contains("onerror=")));
    assert!(payloads.iter().any(|p| p.contains("<IMG")));
    // Should have encoded variants
    assert!(
        payloads.len() > 100,
        "should have many payloads with encoder variants"
    );
}

#[test]
fn test_get_fallback_reflection_payloads_none_encoder_keeps_raw_only() {
    let mut args = default_scan_args();
    args.encoders = vec!["none".to_string()];
    let payloads = get_fallback_reflection_payloads(&args).expect("reflection fallback payloads");

    // Should include HTML payloads
    assert!(payloads.iter().any(|p| p.contains("onerror=")));
    // With "none" encoder, should NOT have URL-encoded variants of HTML payloads
    let raw_count = payloads
        .iter()
        .filter(|p| p.contains("<IMG") || p.contains("<sVg"))
        .count();
    assert!(raw_count > 0, "should contain raw HTML payloads");
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
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
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
        None,
        None,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
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
        None,
        None,
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
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
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
        None,
        None,
    )
    .await;
}

/// End-to-end test for the static V upgrade broadened in #960. Runs
/// `run_scanning` against a mock that mimics the xssmaze `/realworld/level1`
/// shape — reflects the query twice, once with angles stripped inside an
/// HTML comment, once raw inside `<h2>`. Before the fix the static V
/// upgrade only checked `has_js_context_evidence`, so this shape produced
/// R findings only (3045 R-only on deep-scan). After the fix the
/// reflection-phase response itself carries `<svg/onload=alert(1)>` and
/// `classify_dom_evidence` returns `HtmlStructural`, so a Verified
/// finding must appear.
#[tokio::test]
async fn test_run_scanning_realworld_level1_shape_promotes_to_verified() {
    use axum::{Router, extract::Query, response::Html, routing::get};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    async fn realworld_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        // Mirror xssmaze /realworld/level1: strip < and > inside the comment,
        // reflect raw inside <h2>. Filters::strip_angles equivalent.
        let q = params.get("query").cloned().unwrap_or_default();
        let safe: String = q.chars().filter(|c| *c != '<' && *c != '>').collect();
        Html(format!(
            "<!-- search: {} --><h2>Results for: {}</h2>",
            safe, q
        ))
    }

    let app = Router::new().route("/", get(realworld_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let url = format!("http://{}/?query=a", addr);
    let mut target = parse_target(&url).expect("parse_target");
    // Skip discovery entirely (it would re-probe and may classify <> as
    // invalid given the comment-side stripping). The test exercises the
    // V-upgrade path with a pre-populated reflection param.
    target.reflection_params.push(Param {
        name: "query".to_string(),
        value: "a".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    });

    let args = Arc::new(integration_scan_args(false));
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        results.clone(),
        None,
        None,
        Arc::new(AtomicUsize::new(0)),
        None,
        None,
    )
    .await;

    let guard = results.lock().await;
    let verified: Vec<_> = guard
        .iter()
        .filter(|r| matches!(r.result_type, FindingType::Verified) && r.param == "query")
        .collect();
    assert!(
        !verified.is_empty(),
        "the realworld/level1 shape must produce at least one Verified finding on `query`; \
         got {} total results: {:?}",
        guard.len(),
        guard
            .iter()
            .map(|r| (&r.result_type, &r.param))
            .collect::<Vec<_>>()
    );
    // The evidence label should reflect the actual DOM evidence kind that
    // fired, not the hard-coded "JS-context AST" string the prior code
    // emitted unconditionally. The comment-breakout shape produces
    // `HtmlStructural` → label "HTML element with sink"; other shapes
    // may surface marker / executable-URL / JS-context.
    let labels: Vec<_> = verified.iter().map(|r| r.evidence.as_str()).collect();
    assert!(
        labels.iter().any(|m| m.contains("HTML element with sink")
            || m.contains("DOM marker")
            || m.contains("javascript: URL in attribute")
            || m.contains("JS-context AST")),
        "V finding must carry a DomEvidenceKind label from classify_dom_evidence; got {:?}",
        labels
    );
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
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
        None,
        None,
    )
    .await;
}
