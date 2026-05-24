use super::*;

#[test]
fn test_generate_dynamic_payloads_comment() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(payloads.iter().any(|p| {
        p.to_lowercase()
            .contains(&format!("<svg onload=alert(1) class={}>", cls))
    }));
}

#[test]
fn test_generate_dynamic_payloads_string_double() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("\"") && p.ends_with("\""))
    );
}

#[test]
fn test_generate_dynamic_payloads_attribute() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(payloads.iter().any(|p| {
        p.to_lowercase()
            .contains(&format!("<img src=x onerror=alert(1) class={}>", cls))
    }));
}

#[test]
fn test_generate_dynamic_payloads_attribute_single_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::SingleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("'")));
}

#[test]
fn test_generate_dynamic_payloads_attribute_double_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
}

#[test]
fn test_generate_dynamic_payloads_url_attribute_prioritizes_protocols() {
    let payloads = generate_dynamic_payloads(&InjectionContext::AttributeUrl(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(
        payloads[0].starts_with("javascript:")
            || payloads[0].starts_with("Javascript:")
            || payloads[0].starts_with("jAvAsCrIpT:")
            || payloads[0].starts_with("data:text/html,"),
        "expected URL-bearing attribute payloads to start with protocol vectors, got {}",
        payloads[0]
    );
}

#[test]
fn test_generate_dynamic_payloads_javascript() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(None));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p == "alert(1)"));
    assert!(
        payloads
            .iter()
            .any(|p| p == "</script><script>alert(1)</script>")
    );
}

#[test]
fn test_generate_dynamic_payloads_javascript_single_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
        DelimiterType::SingleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("'")));
}

#[test]
fn test_generate_dynamic_payloads_javascript_double_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
}

#[test]
fn test_generate_dynamic_payloads_javascript_comment() {
    let payloads =
        generate_dynamic_payloads(&InjectionContext::Javascript(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("*/")));
    assert!(payloads.iter().any(|p| p.starts_with("\n")));
}

#[test]
fn test_generate_dynamic_payloads_comment_single_quote() {
    // With the new representation, comment context is represented via Html(Some(Comment))
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
}

#[test]
fn test_generate_dynamic_payloads_comment_double_quote() {
    // With the new representation, comment context is represented via Html(Some(Comment))
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
}

#[test]
fn test_generate_dynamic_payloads_html() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(None));
    assert!(!payloads.is_empty());
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(
        payloads
            .iter()
            .any(|p| { p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls) })
    );
}

#[test]
fn test_get_dynamic_payloads_basic() {
    let context = InjectionContext::Html(None);
    let args = ScanArgs {
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
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    let payloads = get_dynamic_payloads(&context, &args).unwrap();
    assert!(!payloads.is_empty());
    // Check that original payloads are included
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(
        payloads
            .iter()
            .any(|p| { p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls) })
    );
    // Check encoded versions
    assert!(payloads.iter().any(|p| p.contains("%3C")));
    assert!(payloads.iter().any(|p| p.contains("&#x")));
    // Check that safe-tag breakout payloads are included
    assert!(
        payloads.iter().any(|p| p.contains("</title>")),
        "should contain title breakout payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("</textarea>")),
        "should contain textarea breakout payloads"
    );
}

#[test]
fn test_get_dynamic_payloads_only_custom() {
    let context = InjectionContext::Html(None);
    let args = ScanArgs {
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
        encoders: vec!["none".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: Some("test_payloads.txt".to_string()),
        only_custom_payload: true,
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
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // This will fail if file doesn't exist, but for test structure it's fine
    let result = get_dynamic_payloads(&context, &args);
    // In real test, we'd create a temp file
    assert!(result.is_err()); // Since file doesn't exist
}

#[test]
fn test_get_dynamic_payloads_no_encoders() {
    let context = InjectionContext::Html(None);
    let args = ScanArgs {
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
        encoders: vec!["none".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
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
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    let payloads = get_dynamic_payloads(&context, &args).unwrap();
    assert!(!payloads.is_empty());
    // Should only have original payloads, no encoded ones
    assert!(
        payloads
            .iter()
            .all(|p| !p.contains("%3C") && !p.contains("&#x"))
    );
}
