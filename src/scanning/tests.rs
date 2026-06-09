use super::*;
use crate::parameter_analysis::{InjectionContext, Location, Param};
use crate::target_parser::parse_target;

/// ScanArgs preset for run_scanning integration tests below. Keeps
/// `skip_xss_scanning` toggleable per-test so the empty/short-circuit
/// tests can still opt out of real HTTP traffic while the
/// `realworld_level1_shape_v_upgrade` test exercises the full pipeline.
fn integration_scan_args(skip_xss: bool) -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: true,
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
        insecure: true,
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

#[tokio::test]
async fn test_xss_scanning_get_query() {
    let mut target = parse_target("https://example.com").unwrap();
    mock_add_reflection_param(&mut target, "q", Location::Query);

    let args = crate::cmd::scan::ScanArgs {
        insecure: true,
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
        insecure: true,
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
        insecure: true,
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
        insecure: true,
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
        insecure: true,
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
    accumulate_findings(&results, &counter, vec![]).await;
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
