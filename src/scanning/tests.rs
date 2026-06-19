use super::*;
use crate::parameter_analysis::{InjectionContext, Location, Param};
use crate::target_parser::parse_target;

/// ScanArgs preset for run_scanning integration tests below. Keeps
/// `skip_xss_scanning` toggleable per-test so the empty/short-circuit
/// tests can still opt out of real HTTP traffic while the
/// `realworld_level1_shape_v_upgrade` test exercises the full pipeline.
fn integration_scan_args(skip_xss: bool) -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
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
        scan_timeout: 0,
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
        stream_findings: false,
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
        oob: Default::default(),
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
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
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

fn make_result(ft: FindingType) -> crate::scanning::result::Result {
    crate::scanning::result::Result::builder(ft).build()
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
fn test_inject_type_for_payload_with_sink_prefers_framework_label_over_csti() {
    // Framework innerHTML sinks have a more specific exploitation
    // story than a generic `{{…}}` payload — once the sink is known,
    // the label should reflect it even when the payload itself is
    // template-shaped. Helps users prioritise the higher-signal hit.
    let s = super::inject_type_for_payload_with_sink(
        false,
        "{{constructor.constructor('alert(1)')()}}",
        Some("v-html"),
    );
    assert_eq!(s, "inHTML-VHtml");
}

#[test]
fn test_inject_type_for_payload_with_sink_maps_known_directives() {
    assert_eq!(
        super::inject_type_for_payload_with_sink(false, "<svg/onload=alert(1)>", Some("v-html")),
        "inHTML-VHtml"
    );
    assert_eq!(
        super::inject_type_for_payload_with_sink(false, "<svg/onload=alert(1)>", Some("data-bind")),
        "inHTML-DataBind"
    );
    assert_eq!(
        super::inject_type_for_payload_with_sink(
            false,
            "<svg/onload=alert(1)>",
            Some("ng-bind-html")
        ),
        "inHTML-NgBindHtml"
    );
    assert_eq!(
        super::inject_type_for_payload_with_sink(true, "<svg/onload=alert(1)>", Some("v-html")),
        "sxss-inHTML-VHtml"
    );
    // Unknown directive falls back to the generic `-FrameworkSink`
    // suffix so a future detector entry surfaces clearly even before
    // we wire its short label here.
    assert_eq!(
        super::inject_type_for_payload_with_sink(
            false,
            "<svg/onload=alert(1)>",
            Some("unknown-future-directive")
        ),
        "inHTML-FrameworkSink"
    );
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
    crate::scanning::result::Result::builder(ft)
        .inject_type(inject)
        .method("GET")
        .data(data)
        .param(param)
        .payload("PAY")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(606)
        .build()
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });
}

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
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
        silence: true,
        dry_run: false,
        stream_findings: false,
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
        oob: Default::default(),
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
fn test_interleave_payload_families_round_robins_and_preserves_order() {
    let out = interleave_payload_families(vec![
        vec!["a1".to_string(), "a2".to_string(), "a3".to_string()],
        vec!["b1".to_string()],
        vec!["c1".to_string(), "c2".to_string()],
    ]);
    // Round-robin across families; shorter families simply drop out of later
    // rounds, and within-family order is preserved.
    assert_eq!(out, vec!["a1", "b1", "c1", "a2", "c2", "a3"]);
    // The union is preserved exactly (no dedup at this layer).
    assert_eq!(out.len(), 6);
}

/// Issue #1156 recall guarantee (machine-checked): the unknown-context DOM
/// catalog must place a representative of EVERY DOM-evidence family within the
/// early-exit budget window, so the inert-echo early exit can never cut a whole
/// family — in particular the `javascript:`/`data:` protocol payloads that are
/// the only verifier for URL-attribute sinks (these were appended last before
/// the interleave and sat thousands of payloads past the budget).
#[test]
fn test_get_dom_payloads_unknown_context_samples_every_evidence_family_in_budget_window() {
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let mut args = default_scan_args();
    // `none` keeps the base interleaved order (no encoder expansion) so the
    // assertion is about catalog ordering, independent of encoder fan-out.
    args.encoders = vec!["none".to_string()];
    args.custom_payload = None;
    args.only_custom_payload = false;

    let payloads = get_dom_payloads(&param, &args).expect("dom payloads");

    use std::collections::HashSet;
    let html: HashSet<String> = crate::payload::get_dynamic_xss_html_payloads()
        .into_iter()
        .collect();
    let attr: HashSet<String> = crate::payload::get_dynamic_xss_attribute_payloads()
        .into_iter()
        .collect();
    let mxss: HashSet<String> = crate::payload::get_mxss_payloads().into_iter().collect();
    let clobber: HashSet<String> = crate::payload::get_dom_clobbering_payloads()
        .into_iter()
        .collect();
    let protocol: HashSet<String> = crate::payload::get_protocol_injection_payloads()
        .into_iter()
        .collect();

    // A window far below INERT_ECHO_BUDGET (256): with five interleaved families
    // each appears within the first few rounds.
    let window = 60.min(payloads.len());
    let head = &payloads[..window];
    for (name, fam) in [
        ("html-tag", &html),
        ("attribute/event-handler", &attr),
        ("mXSS", &mxss),
        ("dom-clobbering", &clobber),
        ("protocol/url", &protocol),
    ] {
        assert!(
            head.iter().any(|p| fam.contains(p)),
            "evidence family '{name}' must appear within the first {window} DOM payloads \
             (interleaved) so the early exit cannot cut it; budget is {INERT_ECHO_BUDGET}"
        );
    }
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
fn test_format_req_per_sec_renders_fixed_width_field() {
    // Pins the field shape consumed by the `{req_per_sec}` template key in
    // both the per-target and overall progress bars. The 7-char right-aligned
    // numeric field + ` req/s` suffix keeps the bar's trailing columns from
    // jittering as rate magnitude changes; widen with care.
    let s = format_req_per_sec(120, 2.0);
    assert_eq!(s, "   60.0 req/s");

    // Sub-unit rate still occupies the same column width.
    let slow = format_req_per_sec(1, 10.0);
    assert_eq!(slow, "    0.1 req/s");

    // Large rate doesn't truncate — width is a minimum, not a max.
    let fast = format_req_per_sec(123_456, 1.0);
    assert_eq!(fast, "123456.0 req/s");
}

#[test]
fn test_format_req_per_sec_zero_elapsed_yields_zero_rate() {
    // The tracker is queried on the bar's first tick before any wall time
    // has accumulated; dividing by zero there would render `inf req/s`.
    // Contract: clamp to `0.0 req/s` until elapsed is positive.
    assert_eq!(format_req_per_sec(42, 0.0), "    0.0 req/s");
    assert_eq!(format_req_per_sec(0, 0.0), "    0.0 req/s");
    // Defensive: negative elapsed (shouldn't happen but guards the branch).
    assert_eq!(format_req_per_sec(42, -1.0), "    0.0 req/s");
}

#[test]
fn test_format_req_per_sec_zero_delta_is_zero_rate() {
    // Idle bar (no HTTP traffic yet) still renders cleanly.
    assert_eq!(format_req_per_sec(0, 5.0), "    0.0 req/s");
}

#[test]
fn test_prune_blocked_raw_angles_drops_lt_and_gt_when_blocked() {
    let payloads = vec![
        "<svg onload=alert(1)>".to_string(),
        "\" onfocus=alert(1) \"".to_string(),
        "%3Csvg%20onload%3Dalert(1)%3E".to_string(),
        "&lt;svg&gt;".to_string(),
        "\"><img src=x onerror=alert(1)>".to_string(),
    ];
    let pruned = prune_blocked_raw_angles(payloads, &['<', '>']);
    assert_eq!(pruned.len(), 3, "raw < / > payloads must be dropped");
    assert!(pruned.iter().all(|p| !p.contains('<') && !p.contains('>')));
}

#[test]
fn test_prune_blocked_raw_angles_no_op_without_block() {
    let payloads = vec![
        "<svg onload=alert(1)>".to_string(),
        "\" onfocus=alert(1) \"".to_string(),
    ];
    let original = payloads.clone();
    // Empty invalid set — must be a pass-through.
    let pruned = prune_blocked_raw_angles(payloads, &[]);
    assert_eq!(pruned, original);
}

#[test]
fn test_prune_blocked_raw_angles_partial_block_keeps_other_angle() {
    // Only `>` is blocked: payloads carrying `>` get dropped, but a raw `<`
    // alone is still allowed through. Captures servers that strip one angle
    // but not the other (uncommon, but the helper should respect that).
    let payloads = vec!["<a>".to_string(), "<a".to_string(), "a>".to_string()];
    let pruned = prune_blocked_raw_angles(payloads, &['>']);
    assert_eq!(pruned, vec!["<a".to_string()]);
}

#[test]
fn test_payload_is_angle_free_detects_encoded_forms() {
    assert!(payload_is_angle_free("\" onfocus=alert(1) \""));
    assert!(payload_is_angle_free("javascript:alert(1)"));
    assert!(!payload_is_angle_free("<svg>"));
    assert!(!payload_is_angle_free("%3Csvg%3E"));
    assert!(!payload_is_angle_free("%3csvg%3e"));
    assert!(!payload_is_angle_free("&lt;svg&gt;"));
    assert!(!payload_is_angle_free("&#60;svg&#62;"));
    assert!(!payload_is_angle_free("&#x3c;svg&#x3e;"));
    assert!(!payload_is_angle_free("%253Csvg%253E"));
}

#[test]
fn test_hoist_angle_free_payloads_orders_clean_first() {
    let payloads = vec![
        "%3Csvg%20onload%3Dalert(1)%3E".to_string(), // encoded angles
        "\" onfocus=alert(1) \"".to_string(),        // angle-free
        "&lt;img&gt;".to_string(),                   // encoded angles
        "javascript:alert(1)".to_string(),           // angle-free
    ];
    let hoisted = hoist_angle_free_payloads(payloads, &['<']);
    assert_eq!(hoisted[0], "\" onfocus=alert(1) \"");
    assert_eq!(hoisted[1], "javascript:alert(1)");
    // The encoded-angle ones come after, in original relative order.
    assert!(hoisted[2].contains("%3C"));
    assert!(hoisted[3].contains("&lt;"));
}

#[test]
fn test_hoist_angle_free_payloads_no_op_without_block() {
    let payloads = vec!["<svg>".to_string(), "\" onfocus=alert(1) \"".to_string()];
    let original = payloads.clone();
    let hoisted = hoist_angle_free_payloads(payloads, &['"']);
    assert_eq!(hoisted, original, "non-angle invalids must not reorder");
}

// ── expand_waf_payloads: orthogonal mutation/encoder expansion ───────

#[test]
fn test_expand_waf_payloads_keeps_axes_orthogonal_no_cross_product() {
    use crate::waf::bypass::{BypassStrategy, MutationType};
    let base = vec!["<script>alert(1)</script>".to_string()];
    let strategy = BypassStrategy {
        extra_encoders: vec!["url".to_string()],
        mutations: vec![MutationType::CaseAlternation],
        extra_delay_hint_ms: 0,
    };
    let out = expand_waf_payloads(&base, &strategy, None);

    // The raw mutation is present, un-encoded.
    let mutated = crate::waf::bypass::apply_mutations(&base, &[MutationType::CaseAlternation], 1)
        .into_iter()
        .find(|p| p != &base[0])
        .expect("case-alternation should produce a variant");
    assert!(out.contains(&mutated), "raw mutation must be present");

    // The url-encoded *original* is present.
    let enc = crate::encoding::url_encode(&base[0]);
    assert!(out.contains(&enc), "encoded original must be present");

    // But the cross product encode(mutate(p)) must NOT be generated.
    let cross = crate::encoding::url_encode(&mutated);
    assert!(
        !out.contains(&cross),
        "encode(mutation) cross product must not be emitted"
    );
}

#[test]
fn test_expand_waf_payloads_ordering_originals_then_mutations_then_encoders() {
    use crate::waf::bypass::{BypassStrategy, MutationType};
    let base = vec!["<svg onload=alert(1)>".to_string()];
    let strategy = BypassStrategy {
        extra_encoders: vec!["url".to_string()],
        mutations: vec![MutationType::SlashSeparator],
        extra_delay_hint_ms: 0,
    };
    let out = expand_waf_payloads(&base, &strategy, None);

    assert_eq!(out[0], base[0], "original must come first");
    let slash = "<svg/onload=alert(1)>".to_string();
    let enc = crate::encoding::url_encode(&base[0]);
    let i_slash = out
        .iter()
        .position(|p| p == &slash)
        .expect("raw mutation present");
    let i_enc = out
        .iter()
        .position(|p| p == &enc)
        .expect("encoder variant present");
    assert!(
        i_slash < i_enc,
        "raw mutation must precede encoder variants (got slash@{i_slash}, enc@{i_enc})"
    );
}

#[test]
fn test_expand_waf_payloads_records_mutation_telemetry() {
    use crate::waf::bypass::{BypassStrategy, MutationStats, MutationType};
    let base = vec!["<svg onload=alert(1)>".to_string()];
    let strategy = BypassStrategy {
        extra_encoders: vec![],
        mutations: vec![MutationType::SlashSeparator],
        extra_delay_hint_ms: 0,
    };
    let stats = MutationStats::default();
    let _ = expand_waf_payloads(&base, &strategy, Some(&stats));
    let snap = stats.snapshot();
    assert_eq!(
        snap.variants.get(&MutationType::SlashSeparator).copied(),
        Some(1),
        "the applied mutation must be recorded once"
    );
}

#[test]
fn test_expand_waf_payloads_reduces_request_count_vs_cross_product() {
    use crate::waf::bypass::{BypassStrategy, MutationType};
    // Demonstrates the request-volume win: the orthogonal expansion is
    // strictly smaller than the old multiply-everything cross product.
    let base = vec![
        "<script>alert(1)</script>".to_string(),
        "<svg onload=alert(1)>".to_string(),
    ];
    let strategy = BypassStrategy {
        extra_encoders: vec!["url".to_string(), "2url".to_string(), "unicode".to_string()],
        mutations: vec![
            MutationType::HtmlCommentSplit,
            MutationType::CaseAlternation,
            MutationType::BacktickParens,
        ],
        extra_delay_hint_ms: 0,
    };
    let new = expand_waf_payloads(&base, &strategy, None);

    // Old behavior: mutate first, then encode the *whole* set.
    let mutated = crate::waf::bypass::apply_mutations(
        &base,
        &strategy.mutations,
        MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD,
    );
    let old = crate::encoding::apply_encoders_to_payloads(&mutated, &strategy.extra_encoders);

    assert!(
        new.len() < old.len(),
        "orthogonal expansion ({}) must send fewer payloads than the cross product ({})",
        new.len(),
        old.len()
    );
}

#[test]
fn test_expand_waf_payloads_empty_strategy_dedups_originals() {
    use crate::waf::bypass::BypassStrategy;
    let base = vec!["<x>".to_string(), "<x>".to_string(), "<y>".to_string()];
    let strategy = BypassStrategy::default();
    let out = expand_waf_payloads(&base, &strategy, None);
    assert_eq!(out, vec!["<x>".to_string(), "<y>".to_string()]);
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };

    let request = build_request_text(&target, &param, "hello world");
    assert!(request.contains("GET /a/hello%20world/c HTTP/1.1"));
}

#[test]
fn test_build_request_text_json_body_empty_value_reserializes() {
    // Regression (ORCH-2): an empty `param.value` used to make the JsonBody
    // fallback call `str::replace("", payload)`, splicing the payload between
    // every byte of the (invalid-JSON) body and producing a garbled PoC. It
    // should re-serialize to `{name: payload}` instead, matching what the
    // scanner actually sends for invalid-JSON bodies.
    let mut target = parse_target("https://example.com/api").unwrap();
    target.method = "POST".to_string();
    target.data = Some("not-json-at-all".to_string());

    let param = Param {
        name: "q".to_string(),
        value: String::new(),
        location: Location::JsonBody,
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
    };

    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(
        request.contains(r#"{"q":"PAYLOAD"}"#),
        "expected re-serialized JSON body, got:\n{request}"
    );
    // The old empty-pattern splice produced "PAYLOADn…" (payload interleaved
    // with the original body bytes); ensure that no longer happens.
    assert!(
        !request.contains("PAYLOADn"),
        "payload should not be spliced into the original body:\n{request}"
    );
}

// ── Issue #1156: DOM-phase early-exit decision logic ──────────────────────
// These pin the pure helpers so the threshold semantics are tested without a
// live server; the end-to-end wiring + request reduction is covered by the
// `run_scanning` integration tests further down.

#[test]
fn test_is_blocking_dom_status_is_5xx_only() {
    // Only 5xx server errors are "blocking" for the early exit.
    for s in [500u16, 502, 503, 504, 599] {
        assert!(is_blocking_dom_status(s), "status {s} should be blocking");
    }
    // 4xx WAF blocks are intentionally EXCLUDED — a payload variant can bypass
    // a WAF filter, so they must not drive the early exit (recall preservation).
    // Normal responses and the request-error sentinel are likewise not blocking.
    for s in [0u16, 200, 204, 301, 302, 400, 401, 403, 404, 406, 418, 429] {
        assert!(
            !is_blocking_dom_status(s),
            "status {s} should not be blocking"
        );
    }
}

#[test]
fn test_next_blocked_streak_resets_on_non_block() {
    // Consecutive 5xx accumulate…
    assert_eq!(next_blocked_streak(0, 503), 1);
    assert_eq!(next_blocked_streak(63, 503), 64);
    // …but ANY non-5xx response resets the streak to 0 — this is what makes the
    // streak *consecutive*, so 64 non-consecutive blocks never early-exit.
    assert_eq!(next_blocked_streak(63, 200), 0);
    assert_eq!(next_blocked_streak(63, 403), 0); // 4xx WAF block does not count
    assert_eq!(next_blocked_streak(63, 0), 0); // request error does not count
}

#[test]
fn test_next_inert_echo_count_is_cumulative() {
    // A reflected response increments…
    assert_eq!(next_inert_echo_count(10, true), 11);
    // …and a NON-reflecting response does NOT reset (cumulative, unlike the
    // blocked streak). An endpoint that reflects most-but-not-all payloads must
    // still converge on the budget.
    assert_eq!(next_inert_echo_count(10, false), 10);
    assert_eq!(next_inert_echo_count(0, false), 0);
}

#[test]
fn test_dom_phase_early_exit_disabled_under_deep_scan() {
    // Even way past both budgets, --deep-scan never early-exits (exhaustive).
    assert!(!dom_phase_should_early_exit(
        true,
        INERT_ECHO_BUDGET * 10,
        BLOCKED_STREAK_LIMIT * 10
    ));
}

#[test]
fn test_dom_phase_early_exit_inert_echo_threshold() {
    // One below the budget keeps scanning; reaching it stops.
    assert!(!dom_phase_should_early_exit(
        false,
        INERT_ECHO_BUDGET - 1,
        0
    ));
    assert!(dom_phase_should_early_exit(false, INERT_ECHO_BUDGET, 0));
    assert!(dom_phase_should_early_exit(false, INERT_ECHO_BUDGET + 1, 0));
}

#[test]
fn test_dom_phase_early_exit_blocked_streak_threshold() {
    assert!(!dom_phase_should_early_exit(
        false,
        0,
        BLOCKED_STREAK_LIMIT - 1
    ));
    assert!(dom_phase_should_early_exit(false, 0, BLOCKED_STREAK_LIMIT));
}

#[test]
fn test_dom_phase_no_early_exit_without_signal() {
    // No inert echoes and no block streak → run the full (capped) set.
    assert!(!dom_phase_should_early_exit(false, 0, 0));
    assert!(!dom_phase_should_early_exit(false, 10, 5));
}

#[tokio::test]
async fn test_xss_scanning_get_query() {
    let mut target = parse_target("https://example.com").unwrap();
    mock_add_reflection_param(&mut target, "q", Location::Query);

    let args = crate::cmd::scan::ScanArgs {
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
        skip_xss_scanning: true,
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
        skip_xss_scanning: true,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });

    let args = crate::cmd::scan::ScanArgs {
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
        skip_xss_scanning: true,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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

/// Issue #1156 — a self-/canonical-link-style echo that reflects every payload
/// but in a permanently inert context (`<plaintext>` swallows the rest of the
/// document as raw text, so not even `</title>`/`</textarea>` breakout payloads
/// can form an element) must trigger the DOM-phase inert-echo early exit. The
/// unknown-context (`injection_context: None`) DOM payload set is thousands of
/// payloads; the early exit has to cap the request fan-out well below that
/// without producing a false Verified finding.
#[tokio::test]
async fn test_run_scanning_dom_phase_early_exits_on_inert_echo() {
    use axum::{
        Router,
        extract::{Query, State},
        response::Html,
        routing::get,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{Duration, sleep};

    async fn inert_handler(
        State(counter): State<Arc<AtomicUsize>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Html<String> {
        counter.fetch_add(1, Ordering::Relaxed);
        let q = params.get("query").cloned().unwrap_or_default();
        // Reflect inside an HTML comment with the comment terminator neutralised
        // so no payload can break out. An HTML comment is *not* one of the
        // reflection phase's safe-tag contexts (textarea/noscript/xmp/plaintext/
        // title), so the reflection phase still classifies it as a real R and
        // short-circuits after one request — leaving the DOM phase, where the
        // raw payload reflects (classify_reflection = Some) but is permanently
        // inert (comment content forms no element), to exercise the early exit.
        let sanitized = q.replace("-->", "__");
        Html(format!(
            "<html><body><!-- echo: {} --></body></html>",
            sanitized
        ))
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", get(inert_handler))
        .with_state(counter.clone());
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
    target.reflection_params.clear();
    target.reflection_params.push(Param {
        name: "query".to_string(),
        value: "a".to_string(),
        location: Location::Query,
        // Unknown context → the full HTML+attribute+… DOM payload catalog
        // (thousands of payloads once encoder-expanded).
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
    });

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        results.clone(),
        None,
        None,
        Arc::new(AtomicUsize::new(0)),
        None,
        None,
        None,
    )
    .await;

    let sent = counter.load(Ordering::Relaxed);
    // A full diverse pass (~INERT_ECHO_BUDGET reflections + probe + the
    // short-circuited reflection phase) runs before the exit — proving the cut
    // is signal-driven, not a premature bail.
    assert!(
        sent >= 200,
        "early exit must still take a diverse sample first; only sent {sent}"
    );
    // Without the early exit this echo would run the entire unknown-context DOM
    // set (~6k requests with the url encoder). The inert-echo budget caps it at
    // roughly one diverse pass.
    assert!(
        sent < 600,
        "inert-echo early exit must curb the DOM fan-out; sent {sent} requests"
    );

    let guard = results.lock().await;
    let verified = guard
        .iter()
        .filter(|r| matches!(r.result_type, FindingType::Verified))
        .count();
    let reflected = guard
        .iter()
        .filter(|r| matches!(r.result_type, FindingType::Reflected) && r.param == "query")
        .count();
    assert_eq!(
        verified, 0,
        "a permanently inert <plaintext> echo must not yield a false Verified finding"
    );
    assert!(
        reflected >= 1,
        "the payload is echoed, so the reflection phase must still record an R finding"
    );
}

/// Issue #1156 — recall guard: the early exit must never suppress a real
/// finding. An echo that reflects the payload into live HTML must still surface
/// a Verified finding (the early exit only fires on *non*-verifying responses).
#[tokio::test]
async fn test_run_scanning_dom_phase_preserves_recall_on_executable_echo() {
    use axum::{Router, extract::Query, response::Html, routing::get};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    async fn exec_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("query").cloned().unwrap_or_default();
        // Reflected raw into live body markup — payloads form real elements.
        Html(format!("<html><body><div>{}</div></body></html>", q))
    }

    let app = Router::new().route("/", get(exec_handler));
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
    target.reflection_params.clear();
    target.reflection_params.push(Param {
        name: "query".to_string(),
        value: "a".to_string(),
        location: Location::Query,
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
    });

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        results.clone(),
        None,
        None,
        Arc::new(AtomicUsize::new(0)),
        None,
        None,
        None,
    )
    .await;

    let guard = results.lock().await;
    let verified = guard
        .iter()
        .filter(|r| matches!(r.result_type, FindingType::Verified) && r.param == "query")
        .count();
    assert!(
        verified >= 1,
        "an executable echo must still produce a Verified finding; got {:?}",
        guard
            .iter()
            .map(|r| (&r.result_type, &r.param))
            .collect::<Vec<_>>()
    );
}

/// Issue #1156 — the inert-echo signal must be CUMULATIVE, not consecutive: an
/// endpoint that reflects most-but-not-all payloads (here ~3 of every 4) must
/// still accumulate to the budget and early-exit. A regression making the count
/// reset on a non-reflecting response would never reach the budget on this
/// handler and would run the entire DOM set — so a bounded request count proves
/// the cumulative wiring end-to-end.
#[tokio::test]
async fn test_run_scanning_dom_phase_inert_echo_count_is_cumulative() {
    use axum::{
        Router,
        extract::{Query, State},
        response::Html,
        routing::get,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{Duration, sleep};

    async fn partial_handler(
        State(counter): State<Arc<AtomicUsize>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Html<String> {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let q = params.get("query").cloned().unwrap_or_default();
        // Every 4th request returns a clean page with NO reflection; the other
        // ~75% reflect the payload inertly (inside a comment). The probe and the
        // first reflection payload (n = 0,1,2) always reflect so the scan
        // proceeds into the DOM phase.
        if n >= 3 && n % 4 == 3 {
            return Html("<html><body>clean</body></html>".to_string());
        }
        let sanitized = q.replace("-->", "__");
        Html(format!(
            "<html><body><!-- echo: {} --></body></html>",
            sanitized
        ))
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", get(partial_handler))
        .with_state(counter.clone());
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
    target.reflection_params.clear();
    target.reflection_params.push(Param {
        name: "query".to_string(),
        value: "a".to_string(),
        location: Location::Query,
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
    });

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        results.clone(),
        None,
        None,
        Arc::new(AtomicUsize::new(0)),
        None,
        None,
        None,
    )
    .await;

    let sent = counter.load(Ordering::Relaxed);
    // Cumulative: 256 inert echoes reached after ~256/0.75 ≈ 341 reflecting
    // requests, so the phase early-exits well under the full ~6k set. A
    // consecutive (reset-on-miss) counter would never reach 256 here and would
    // run the entire set.
    assert!(
        sent < 1500,
        "inert_echo_count must be cumulative across non-reflecting gaps; sent {sent} requests"
    );
}

#[tokio::test]
async fn test_run_scanning_increments_params_done_counter() {
    // Each per-parameter worker must bump the live `params_done` counter once
    // on completion — including the non-reflective early-return path — so the
    // REST server and MCP can report `params_tested` climbing during a scan
    // instead of pinning it at 0 until the very end. The target reflects
    // nothing, so every worker takes the "no reflection, skip payloads" path;
    // the counter must still reach the param count.
    use axum::{Router, response::Html, routing::get};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};
    async fn ok_handler() -> Html<String> {
        Html("<html><body>no reflection here</body></html>".to_string())
    }
    let app = Router::new().route("/", get(ok_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let url = format!("http://{}/?a=1&b=2&c=3", addr);
    let mut target = parse_target(&url).expect("parse_target");
    target.reflection_params.clear();
    for name in ["a", "b", "c"] {
        target.reflection_params.push(Param {
            name: name.to_string(),
            value: "1".to_string(),
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

    let params_done = Arc::new(std::sync::atomic::AtomicU32::new(0));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        Arc::new(Mutex::new(Vec::new())),
        None,
        None,
        Arc::new(AtomicUsize::new(0)),
        None,
        None,
        Some(params_done.clone()),
    )
    .await;

    assert_eq!(
        params_done.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "every parameter worker must increment params_done exactly once"
    );
}

#[tokio::test]
async fn test_run_scanning_empty_params() {
    let target = parse_target("https://example.com").unwrap();

    let args = crate::cmd::scan::ScanArgs {
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
        skip_xss_scanning: true,
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
        None,
    )
    .await;
}

// ── fetch_and_analyze_external_js unit tests ─────────────────────────────────

/// Minimal axum server for external-JS unit tests. Serves:
///   GET /app.js  → `js_body`
///   GET /big.js  → body just over MAX_EXTERNAL_JS_BYTES (512 KiB)
async fn start_ext_js_server(js_body: &'static str) -> std::net::SocketAddr {
    use axum::{Router, http::header, routing::get};

    let app_js =
        move || async move { ([(header::CONTENT_TYPE, "application/javascript")], js_body) };
    let big_js = || async {
        // "// x\n" × 110_000 ≈ 550 KiB > 512 KiB cap
        let body = "// x\n".repeat(110_000);
        ([(header::CONTENT_TYPE, "application/javascript")], body)
    };
    let app = Router::new()
        .route("/app.js", get(app_js))
        .route("/big.js", get(big_js));

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ext-js test server");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    addr
}

fn ext_js_scan_args(analyze: bool) -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "url".to_string(),
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
        scan_timeout: 0,
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
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 2,
        max_concurrent_targets: 2,
        max_targets_per_host: 10,
        encoders: vec![],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 1,
        skip_ast_analysis: false,
        analyze_external_js: analyze,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 0,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
        max_payloads_per_param: 0,
    }
}

/// flag=false → always returns empty regardless of page content.
#[tokio::test]
async fn test_fetch_ext_js_flag_off_returns_empty() {
    let addr = start_ext_js_server(
        r#"document.getElementById("r").innerHTML = location.hash.substring(1);"#,
    )
    .await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/app.js"></script></body></html>"#);
    let args = ext_js_scan_args(false);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "flag off must return empty; got {findings:?}"
    );
}

/// flag=true + script has `location.hash → innerHTML` → finding returned and
/// evidence cites the script URL.
#[tokio::test]
async fn test_fetch_ext_js_detects_dom_xss_in_script() {
    let addr = start_ext_js_server(
        r#"document.getElementById("r").innerHTML = location.hash.substring(1);"#,
    )
    .await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/app.js"></script></body></html>"#);
    let args = ext_js_scan_args(true);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        !findings.is_empty(),
        "expected DOM-XSS finding from external script"
    );
    let cites_script = findings.iter().any(|f| f.evidence.contains("/app.js"));
    assert!(
        cites_script,
        "evidence must cite the script URL; got {findings:#?}"
    );
}

/// Body larger than MAX_EXTERNAL_JS_BYTES → skipped gracefully, no panic.
#[tokio::test]
async fn test_fetch_ext_js_skips_oversized_body() {
    let addr = start_ext_js_server("").await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/big.js"></script></body></html>"#);
    let args = ext_js_scan_args(true);
    // big.js has no sink; primary assertion is no panic on oversized body.
    let _ = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
}

/// exclude_url matching the script URL → script skipped, empty result.
#[tokio::test]
async fn test_fetch_ext_js_exclude_url_skips_script() {
    let addr = start_ext_js_server(
        r#"document.getElementById("r").innerHTML = location.hash.substring(1);"#,
    )
    .await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/app.js"></script></body></html>"#);
    let mut args = ext_js_scan_args(true);
    args.exclude_url = vec!["app\\.js".to_string()];
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "excluded script must not produce findings; got {findings:?}"
    );
}

/// Script URL returns a non-2xx status (404) → skipped gracefully, no findings.
#[tokio::test]
async fn test_fetch_ext_js_non_2xx_response_is_skipped() {
    let addr = start_ext_js_server("").await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    // /nonexistent.js has no route → axum returns 404
    let html = format!(
        r#"<html><body><script src="http://{addr}/nonexistent.js"></script></body></html>"#
    );
    let args = ext_js_scan_args(true);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "non-2xx response must be skipped; got {findings:?}"
    );
}

/// Script URL connection is refused (port closed) → error silently skipped, no panic.
#[tokio::test]
async fn test_fetch_ext_js_network_error_is_skipped() {
    // Bind, capture address, then drop so the port is closed before the test connects.
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let closed_addr = listener.local_addr().unwrap();
    drop(listener);

    let target = parse_target(&format!("http://{closed_addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html =
        format!(r#"<html><body><script src="http://{closed_addr}/app.js"></script></body></html>"#);
    let args = ext_js_scan_args(true);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "network error must be skipped gracefully; got {findings:?}"
    );
}

/// include_url set to a pattern that does NOT match the script URL → script skipped, empty result.
#[tokio::test]
async fn test_fetch_ext_js_include_url_skips_non_matching_script() {
    let addr = start_ext_js_server(
        r#"document.getElementById("r").innerHTML = location.hash.substring(1);"#,
    )
    .await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/app.js"></script></body></html>"#);
    let mut args = ext_js_scan_args(true);
    // Pattern that does NOT match /app.js → the include-filter `continue` branch fires.
    args.include_url = vec!["only_this_pattern_matches".to_string()];
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "script not matching include_url must be skipped; got {findings:?}"
    );
}

/// resp.text() failure (connection dropped mid-body) → skipped gracefully, no findings.
#[tokio::test]
async fn test_fetch_ext_js_body_read_error_is_skipped() {
    use tokio::io::AsyncWriteExt;

    // Raw TCP server: advertises Content-Length: 1000 but closes after a few bytes,
    // so reqwest's resp.text() gets a truncated-body error.
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 1000\r\n\r\npartial",
                )
                .await
                .ok();
            // Dropping `stream` closes the connection before 1000 bytes are sent.
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    let html = format!(r#"<html><body><script src="http://{addr}/app.js"></script></body></html>"#);
    let args = ext_js_scan_args(true);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        findings.is_empty(),
        "body read error must be skipped gracefully; got {findings:?}"
    );
}

/// The script_element_ids set must be sourced from the host HTML, not the JS body.
/// When the host page has `<script id="eval-me">` and the external JS writes
/// `document.getElementById('eval-me').innerText = location.hash.substring(1)`,
/// the analyzer must recognise it as a JS-eval sink. With the old (buggy) code the JS
/// body was passed to `extract_script_element_ids`, producing an empty set and silently
/// missing the finding.
#[tokio::test]
async fn test_fetch_ext_js_uses_html_for_script_element_ids() {
    let addr = start_ext_js_server(
        r#"document.getElementById('eval-me').innerText = location.hash.substring(1);"#,
    )
    .await;
    let target = parse_target(&format!("http://{addr}/")).unwrap();
    let client = target.build_client_or_default();
    // Host HTML declares <script id="eval-me"> — the ID that makes the sink recognisable.
    let html = format!(
        r#"<html><body><script id="eval-me"></script><script src="http://{addr}/app.js"></script></body></html>"#
    );
    let args = ext_js_scan_args(true);
    let findings = fetch_and_analyze_external_js(&client, &target, &html, &args).await;
    assert!(
        !findings.is_empty(),
        "expected DOM-XSS finding when host HTML supplies the script element ID; got none"
    );
}

/// accumulate_findings with an empty batch must be a no-op (counter unchanged, vec unchanged).
#[tokio::test]
async fn test_accumulate_findings_empty_batch_is_noop() {
    let results: tokio::sync::Mutex<Vec<crate::scanning::result::Result>> =
        tokio::sync::Mutex::new(Vec::new());
    let counter = std::sync::atomic::AtomicUsize::new(0);
    accumulate_findings(&results, &counter, vec![], "ALL").await;
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "counter must not change for empty batch"
    );
    assert!(
        results.lock().await.is_empty(),
        "results vec must remain empty for empty batch"
    );
}

/// accumulate_findings must bump the limit counter by the number of findings
/// matching --limit-result-type (like flush_results), not the whole batch —
/// otherwise non-matching preflight findings trip --limit early.
#[tokio::test]
async fn test_accumulate_findings_counts_only_matching_result_type() {
    let results: tokio::sync::Mutex<Vec<crate::scanning::result::Result>> =
        tokio::sync::Mutex::new(Vec::new());
    let counter = std::sync::atomic::AtomicUsize::new(0);
    let batch = vec![
        make_result(FindingType::Verified),
        make_result(FindingType::Reflected),
        make_result(FindingType::Reflected),
    ];
    accumulate_findings(&results, &counter, batch, "V").await;
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "only the single V finding should count toward --limit-result-type V"
    );
    assert_eq!(
        results.lock().await.len(),
        3,
        "all findings are still stored regardless of the limit filter"
    );
}

// --- csp_requires_trusted_types (server/MCP TT enforcement gate) ----------

#[test]
fn test_csp_requires_trusted_types_enforcing_header() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "content-security-policy",
        "require-trusted-types-for 'script'".parse().unwrap(),
    );
    assert!(super::csp_requires_trusted_types(&headers));
}

#[test]
fn test_csp_requires_trusted_types_ignores_report_only() {
    // Report-only enforces nothing, so it must NOT signal TT enforcement —
    // otherwise a real DOM-XSS finding would be wrongly suppressed (FN).
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "content-security-policy-report-only",
        "require-trusted-types-for 'script'".parse().unwrap(),
    );
    assert!(!super::csp_requires_trusted_types(&headers));
}

#[test]
fn test_csp_requires_trusted_types_absent() {
    let headers = reqwest::header::HeaderMap::new();
    assert!(!super::csp_requires_trusted_types(&headers));
}

// ---- build_request_text: the displayed PoC HTTP request ------------------

use crate::target_parser::Target;

/// Minimal `Param` for request-text tests (all the discovery-derived metadata
/// fields left at their `None` defaults).
fn req_param(name: &str, value: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: value.to_string(),
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

fn target_for(url: &str) -> Target {
    Target::for_url(url::Url::parse(url).expect("valid url"))
}

#[test]
fn build_request_text_query_replaces_existing_param() {
    let target = target_for("https://example.com/path?a=1&b=2");
    let param = req_param("a", "1", Location::Query);
    let req = super::build_request_text(&target, &param, "PAYLOAD");
    // Request line is the GET method against the path with the injected query.
    assert!(req.starts_with("GET /path?"), "req:\n{req}");
    assert!(req.contains("a=PAYLOAD"), "req:\n{req}");
    assert!(req.contains("b=2"), "req:\n{req}");
    assert!(
        req.contains(" HTTP/1.1\r\nHost: example.com"),
        "req:\n{req}"
    );
    // A bodyless GET ends with the blank-line terminator, no Content-Length.
    assert!(!req.contains("Content-Length:"), "req:\n{req}");
}

#[test]
fn build_request_text_query_appends_missing_param() {
    let target = target_for("https://example.com/path?x=1");
    let param = req_param("q", "", Location::Query);
    let req = super::build_request_text(&target, &param, "INJ");
    assert!(req.contains("x=1"), "req:\n{req}");
    assert!(req.contains("q=INJ"), "req:\n{req}");
}

#[test]
fn build_request_text_path_segment_injection() {
    let target = target_for("https://example.com/a/b/c");
    // path_segment_1 targets the middle segment "b".
    let param = req_param("path_segment_1", "b", Location::Path);
    let req = super::build_request_text(&target, &param, "INJ");
    assert!(req.starts_with("GET /a/INJ/c "), "req:\n{req}");
}

#[test]
fn build_request_text_path_segment_out_of_range_is_unchanged() {
    let target = target_for("https://example.com/a/b");
    // Index 9 is past the end: the path is left intact.
    let param = req_param("path_segment_9", "", Location::Path);
    let req = super::build_request_text(&target, &param, "INJ");
    assert!(req.starts_with("GET /a/b "), "req:\n{req}");
    assert!(!req.contains("INJ"), "req:\n{req}");
}

#[test]
fn build_request_text_body_replaces_in_existing_form_data() {
    let target = Target {
        method: "POST".to_string(),
        data: Some("user=alice&pass=secret".to_string()),
        ..target_for("https://example.com/login")
    };
    let param = req_param("pass", "secret", Location::Body);
    let req = super::build_request_text(&target, &param, "PAY");
    // Body location forces POST and a form content type.
    assert!(req.starts_with("POST /login "), "req:\n{req}");
    assert!(
        req.contains("Content-Type: application/x-www-form-urlencoded"),
        "req:\n{req}"
    );
    assert!(req.contains("user=alice"), "req:\n{req}");
    assert!(req.contains("pass=PAY"), "req:\n{req}");
    assert!(req.contains("Content-Length: "), "req:\n{req}");
}

#[test]
fn build_request_text_body_synthesizes_when_no_data() {
    let target = target_for("https://example.com/login");
    let param = req_param("q", "", Location::Body);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(req.starts_with("POST /login "), "req:\n{req}");
    assert!(req.contains("q=PAY"), "req:\n{req}");
    assert!(
        req.contains("Content-Type: application/x-www-form-urlencoded"),
        "req:\n{req}"
    );
}

#[test]
fn build_request_text_jsonbody_injects_into_object() {
    let target = Target {
        method: "POST".to_string(),
        data: Some(r#"{"name":"bob"}"#.to_string()),
        ..target_for("https://example.com/api")
    };
    let param = req_param("name", "bob", Location::JsonBody);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(
        req.contains("Content-Type: application/json"),
        "req:\n{req}"
    );
    assert!(req.contains(r#""name":"PAY""#), "req:\n{req}");
}

#[test]
fn build_request_text_jsonbody_synthesizes_when_no_data() {
    let target = target_for("https://example.com/api");
    let param = req_param("q", "", Location::JsonBody);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(
        req.contains("Content-Type: application/json"),
        "req:\n{req}"
    );
    assert!(req.contains(r#""q":"PAY""#), "req:\n{req}");
}

#[test]
fn build_request_text_jsonbody_empty_value_reserializes_invalid_json() {
    // Invalid-JSON body + empty param.value: must re-serialize as {name: payload}
    // rather than splicing the payload between every byte of the body.
    let target = Target {
        method: "POST".to_string(),
        data: Some("not-json-at-all".to_string()),
        ..target_for("https://example.com/api")
    };
    let param = req_param("x", "", Location::JsonBody);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(req.contains(r#"{"x":"PAY"}"#), "req:\n{req}");
    assert!(!req.contains("not-json"), "req:\n{req}");
}

#[test]
fn build_request_text_does_not_duplicate_content_type_header() {
    // When the target already carries a Content-Type the synthesizer must not
    // append a second one.
    let target = Target {
        method: "POST".to_string(),
        data: Some(r#"{"a":"1"}"#.to_string()),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        ..target_for("https://example.com/api")
    };
    let param = req_param("a", "1", Location::JsonBody);
    let req = super::build_request_text(&target, &param, "PAY");
    assert_eq!(
        req.matches("Content-Type:").count(),
        1,
        "exactly one Content-Type expected, req:\n{req}"
    );
}

#[test]
fn build_request_text_includes_headers_and_cookies() {
    let target = Target {
        headers: vec![("X-Custom".to_string(), "yes".to_string())],
        cookies: vec![
            ("sid".to_string(), "abc".to_string()),
            ("t".to_string(), "1".to_string()),
        ],
        ..target_for("https://example.com/path?a=1")
    };
    let param = req_param("a", "1", Location::Query);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(req.contains("\r\nX-Custom: yes"), "req:\n{req}");
    // Cookies are joined with "; " on a single Cookie header.
    assert!(req.contains("\r\nCookie: sid=abc; t=1"), "req:\n{req}");
}

#[test]
fn build_request_text_multipart_keeps_body_and_type() {
    let target = Target {
        method: "POST".to_string(),
        data: Some("--boundary\r\n...".to_string()),
        ..target_for("https://example.com/upload")
    };
    let param = req_param("file", "", Location::MultipartBody);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(req.starts_with("POST /upload "), "req:\n{req}");
    assert!(
        req.contains("Content-Type: multipart/form-data"),
        "req:\n{req}"
    );
    assert!(req.contains("--boundary"), "req:\n{req}");
}

// ---- ast_source_uses_browser_url_surface --------------------------------

#[test]
fn ast_source_browser_url_surface_detects_each_source() {
    for src in [
        "var x = location.hash;",
        "location.search.slice(1)",
        "new URLSearchParams.get('q')",
        "el.href = location.href",
        "p = location.pathname",
        "d = document.URL",
        "window.opener.postMessage(1)",
        "if (event.newValue) {}",
        "log(event.oldValue)",
    ] {
        assert!(
            super::ast_source_uses_browser_url_surface(src),
            "should flag attacker-controllable URL surface: {src:?}"
        );
    }
}

#[test]
fn ast_source_browser_url_surface_ignores_safe_sources() {
    for src in [
        "var x = config.value;",
        "el.textContent = data;",
        "const n = items.length;",
        "",
    ] {
        assert!(
            !super::ast_source_uses_browser_url_surface(src),
            "should not flag non-URL source: {src:?}"
        );
    }
}

// ---- compute_waf_strategy -----------------------------------------------

#[test]
fn compute_waf_strategy_off_returns_none() {
    let target = target_for("https://example.com/");
    // integration_scan_args defaults waf_bypass to "off".
    let args = integration_scan_args(true);
    assert_eq!(args.waf_bypass, "off");
    assert!(super::compute_waf_strategy(&target, &args).is_none());
}

#[test]
fn compute_waf_strategy_no_waf_info_returns_none() {
    let target = target_for("https://example.com/");
    let mut args = integration_scan_args(true);
    args.waf_bypass = "auto".to_string();
    // No WAF was fingerprinted, so there's nothing to bypass.
    assert!(super::compute_waf_strategy(&target, &args).is_none());
}

#[test]
fn compute_waf_strategy_empty_waf_info_returns_none() {
    let target = Target {
        waf_info: Some(crate::waf::WafDetectionResult::default()),
        ..target_for("https://example.com/")
    };
    let mut args = integration_scan_args(true);
    args.waf_bypass = "auto".to_string();
    assert!(super::compute_waf_strategy(&target, &args).is_none());
}

#[test]
fn compute_waf_strategy_detected_waf_returns_strategy() {
    let waf = crate::waf::WafDetectionResult {
        detected: vec![crate::waf::WafFingerprint {
            waf_type: crate::waf::WafType::Cloudflare,
            confidence: 0.9,
            evidence: "cf-ray header".to_string(),
        }],
    };
    let target = Target {
        waf_info: Some(waf),
        ..target_for("https://example.com/")
    };
    let mut args = integration_scan_args(true);
    args.waf_bypass = "auto".to_string();
    assert!(super::compute_waf_strategy(&target, &args).is_some());
}

// ---- generate_param_jobs: per-parameter work-unit assembly --------------

fn target_with_params(params: Vec<Param>) -> Target {
    Target {
        reflection_params: params,
        ..target_for("https://example.com/path?a=1")
    }
}

#[test]
fn generate_param_jobs_skips_fragment_params() {
    // URL fragments never reach the server, so they must not produce a job.
    let target = target_with_params(vec![
        req_param("frag", "", Location::Fragment),
        req_param("a", "1", Location::Query),
    ]);
    let args = integration_scan_args(true);
    let (jobs, _total) = super::generate_param_jobs(&target, &args, None, &[]);
    assert_eq!(jobs.len(), 1, "only the query param should yield a job");
    assert_eq!(jobs[0].0.name, "a");
}

#[test]
fn generate_param_jobs_total_tasks_matches_payload_counts() {
    // `total_tasks` must equal the sum of reflection + DOM payloads across all
    // jobs — that count drives the progress bar length and ETA.
    let target = target_with_params(vec![req_param("a", "1", Location::Query)]);
    let args = integration_scan_args(true);
    let (jobs, total) = super::generate_param_jobs(&target, &args, None, &[]);
    let summed: u64 = jobs
        .iter()
        .map(|(_, refl, dom)| (refl.len() + dom.len()) as u64)
        .sum();
    assert_eq!(total, summed);
    // A plain reflected query param yields a non-empty payload set.
    assert!(total > 0, "expected payloads for a reflected param");
}

#[test]
fn generate_param_jobs_respects_max_payloads_per_param() {
    let target = target_with_params(vec![req_param("a", "1", Location::Query)]);
    let mut args = integration_scan_args(true);
    args.max_payloads_per_param = 2;
    let (jobs, _total) = super::generate_param_jobs(&target, &args, None, &[]);
    for (_, refl, dom) in &jobs {
        assert!(refl.len() <= 2, "reflection set over cap: {}", refl.len());
        assert!(dom.len() <= 2, "dom set over cap: {}", dom.len());
    }
}

#[test]
fn generate_param_jobs_appends_shared_payloads() {
    // Shared payloads (CSP-bypass + tech-specific) are appended to every job's
    // reflection and DOM sets.
    let target = target_with_params(vec![req_param("a", "1", Location::Query)]);
    let args = integration_scan_args(true);
    let shared = vec!["<shared-marker>".to_string()];
    let (jobs, _total) = super::generate_param_jobs(&target, &args, None, &shared);
    let (_, refl, dom) = &jobs[0];
    assert!(
        refl.iter().any(|p| p == "<shared-marker>"),
        "refl missing shared"
    );
    assert!(
        dom.iter().any(|p| p == "<shared-marker>"),
        "dom missing shared"
    );
}

#[test]
fn generate_param_jobs_waf_expansion_never_drops_originals() {
    // With a bypass strategy the reflection set is expanded with mutations /
    // encoder variants, but the originals are always kept (at the front), so
    // the expanded count is at least the un-expanded count.
    let target = target_with_params(vec![req_param("a", "1", Location::Query)]);
    let args = integration_scan_args(true);
    let (plain_jobs, _) = super::generate_param_jobs(&target, &args, None, &[]);
    let strategy = crate::waf::bypass::merge_strategies(&[&crate::waf::WafType::Cloudflare]);
    let (waf_jobs, _) = super::generate_param_jobs(&target, &args, Some(&strategy), &[]);
    assert!(
        waf_jobs[0].1.len() >= plain_jobs[0].1.len(),
        "WAF expansion must not shrink the reflection set ({} < {})",
        waf_jobs[0].1.len(),
        plain_jobs[0].1.len()
    );
}

#[test]
fn test_effective_payload_cap_resolution() {
    let safety = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP;
    // Default (0) without deep-scan -> built-in safety cap (issue #1153).
    assert_eq!(effective_payload_cap(0, false), safety);
    // Default (0) with deep-scan -> unlimited.
    assert_eq!(effective_payload_cap(0, true), 0);
    // Explicit cap always wins, even under deep-scan.
    assert_eq!(effective_payload_cap(50, false), 50);
    assert_eq!(effective_payload_cap(50, true), 50);
    // An explicit cap larger than the safety default is honored verbatim.
    assert_eq!(effective_payload_cap(safety + 5000, false), safety + 5000);
}

#[test]
fn test_generate_param_jobs_applies_builtin_safety_cap() {
    // The built-in safety cap must behave exactly like an explicit
    // --max-payloads-per-param of the same size, must bound the *base* payload
    // sets, and must be lifted by --deep-scan. (In real scans a few shared
    // CSP/tech payloads are appended after the cap and can push the final set
    // slightly past it; here we pass no shared payloads — `&[]` below — so the
    // base set is the final set and the cap is a strict bound.) Asserting the
    // default-vs-explicit *equivalence* exercises the cap regardless of how
    // large the base payload set happens to be. Issue #1153.
    let target = target_with_params(vec![req_param("a", "1", Location::Query)]);
    let safety = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP;

    // Default (0, no --deep-scan) -> built-in safety cap.
    let mut args = integration_scan_args(true);
    args.max_payloads_per_param = 0;
    args.deep_scan = false;
    let (default_jobs, _) = super::generate_param_jobs(&target, &args, None, &[]);
    for (_, refl, dom) in &default_jobs {
        assert!(
            refl.len() <= safety && dom.len() <= safety,
            "default scan must cap reflection ({}) and DOM ({}) sets to {safety}",
            refl.len(),
            dom.len(),
        );
    }

    // Default (0) must be equivalent to an explicit cap of the safety value.
    let mut explicit = integration_scan_args(true);
    explicit.max_payloads_per_param = safety;
    explicit.deep_scan = false;
    let (explicit_jobs, _) = super::generate_param_jobs(&target, &explicit, None, &[]);
    assert_eq!(default_jobs.len(), explicit_jobs.len());
    for (d, e) in default_jobs.iter().zip(&explicit_jobs) {
        assert_eq!(
            (d.1.len(), d.2.len()),
            (e.1.len(), e.2.len()),
            "default (built-in cap) must match explicit --max-payloads-per-param {safety}"
        );
    }

    // --deep-scan lifts the bound (never shrinks below the capped run).
    args.deep_scan = true;
    let (deep_jobs, _) = super::generate_param_jobs(&target, &args, None, &[]);
    assert!(
        deep_jobs[0].1.len() >= default_jobs[0].1.len()
            && deep_jobs[0].2.len() >= default_jobs[0].2.len(),
        "--deep-scan must not shrink the payload sets below the capped run"
    );
}

#[test]
fn generate_param_jobs_default_cap_preserves_waf_variants() {
    // Regression for the #1155 review: the safety cap must bound the BASE
    // catalog, NOT the WAF-expanded set. `expand_waf_payloads` keeps originals
    // at the front and appends every mutation/encoder variant at the tail, so
    // capping after expansion truncated 100% of the bypass variants whenever the
    // base exceeded the cap (attribute context ~9k base vs the 3000 default),
    // silently defeating WAF bypass on exactly the params it was selected for.
    let mut param = req_param("a", "1", Location::Query);
    param.injection_context = Some(InjectionContext::Attribute(None));
    let target = target_with_params(vec![param]);
    let mut args = integration_scan_args(true);
    args.max_payloads_per_param = 0; // built-in safety cap (3000)
    args.deep_scan = false;
    let safety = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP;

    // The capped base set (no WAF), used as the "originals" reference.
    let (base_jobs, _) = super::generate_param_jobs(&target, &args, None, &[]);
    let base_set: std::collections::HashSet<&String> = base_jobs[0].1.iter().collect();
    assert!(
        base_jobs[0].1.len() <= safety,
        "no-WAF base reflection set must be bounded to the cap"
    );

    // Same param + same cap, now with a bypass strategy active.
    let strategy = crate::waf::bypass::merge_strategies(&[&crate::waf::WafType::Cloudflare]);
    let (waf_jobs, _) = super::generate_param_jobs(&target, &args, Some(&strategy), &[]);
    let refl = &waf_jobs[0].1;
    let waf_variants = refl.iter().filter(|p| !base_set.contains(*p)).count();
    let base_portion = refl.iter().filter(|p| base_set.contains(*p)).count();
    assert!(
        waf_variants > 0,
        "default cap must NOT evict all WAF-bypass variants (got {waf_variants} variants, \
         {base_portion} base of {} total)",
        refl.len()
    );
    assert!(
        base_portion <= safety,
        "base portion ({base_portion}) must stay bounded to the cap ({safety}); \
         expansion is added on top"
    );
}

#[test]
fn generate_param_jobs_shared_payloads_appended_after_cap() {
    // Covers the shared-after-cap path: shared CSP/tech payloads are appended
    // AFTER the base cap (never trimmed), and angle-bearing shared are pruned
    // when the server strips `<`/`>`.
    let mut param = req_param("a", "1", Location::Query);
    param.injection_context = Some(InjectionContext::Attribute(None));
    param.invalid_specials = Some(vec!['<', '>']);
    let target = target_with_params(vec![param]);
    let mut args = integration_scan_args(true);
    args.max_payloads_per_param = 5; // tiny explicit cap -> base truncated hard
    args.deep_scan = false;

    let shared = vec![
        "zz-angle-free-shared".to_string(),
        "<svg/onload=alert(1)>".to_string(), // angle-bearing -> pruned
    ];
    let (jobs, _) = super::generate_param_jobs(&target, &args, None, &shared);
    let refl = &jobs[0].1;
    assert!(
        refl.iter().any(|p| p == "zz-angle-free-shared"),
        "angle-free shared payload must survive the base cap (appended after)"
    );
    assert!(
        !refl.iter().any(|p| p == "<svg/onload=alert(1)>"),
        "angle-bearing shared payload must be pruned when <>` are stripped"
    );
    // Same on the DOM set.
    let dom = &jobs[0].2;
    assert!(dom.iter().any(|p| p == "zz-angle-free-shared"));
    assert!(!dom.iter().any(|p| p == "<svg/onload=alert(1)>"));
}
