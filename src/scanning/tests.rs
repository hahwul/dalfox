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
        format: "json".to_string(),
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_discovery: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 5,
        no_color: true,
        silence: true,
        workers: 4,
        max_concurrent_targets: 4,
        max_targets_per_host: 8,
        encoders: vec!["url".to_string()],
        skip_xss_scanning: skip_xss,
        sxss_retries: 1,
        skip_ast_analysis: true,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        waf_min_confidence: 0.0,
        ..Default::default()
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

/// A `q` in the query string and a `q` in the request body are different
/// injection points (see `found_param_key`), so proving the body one
/// exploitable must not delete the query one's evidence.
#[test]
fn test_collapse_keeps_r_when_the_v_is_at_a_different_wire_location() {
    let mut verified_body = make_typed_param_result(FindingType::Verified, "q", "inHTML");
    verified_body.location = "Body".to_string();
    let mut reflected_query = make_typed_param_result(FindingType::Reflected, "q", "inHTML");
    reflected_query.location = "Query".to_string();

    let after = collapse_redundant_reflected(
        vec![verified_body, reflected_query],
        "https://example.com/?x=1",
    );
    assert_eq!(
        after.len(),
        2,
        "the query-string reflection is a separate injection point from the \
         verified body parameter and must survive the collapse"
    );

    // Same location: the R really is the weaker evidence for the same finding.
    let mut verified = make_typed_param_result(FindingType::Verified, "q", "inHTML");
    verified.location = "Query".to_string();
    let mut reflected = make_typed_param_result(FindingType::Reflected, "q", "inHTML");
    reflected.location = "Query".to_string();
    let after = collapse_redundant_reflected(vec![verified, reflected], "https://example.com/?x=1");
    assert_eq!(after.len(), 1);
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

#[tokio::test]
async fn test_collapse_target_results_no_underflow_when_filter_excludes_r() {
    // Regression: with `--limit-result-type V`, `findings_count` only ever
    // counted the V findings, but the old collapse subtracted the *raw* drop in
    // length (the dropped R duplicates). On `usize` that wrapped to ~usize::MAX
    // and poisoned `limit_reached()` for the rest of a multi-target run.
    let results = std::sync::Arc::new(tokio::sync::Mutex::new(vec![
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
        make_typed_param_result(FindingType::Verified, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
    ]));
    // Under filter "V" only the single V finding was ever counted.
    let findings_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
    let target = parse_target("https://example.com/?x=1").unwrap();

    collapse_target_results(&results, &findings_count, "V", &target).await;

    // Two R duplicates dropped, but none matched "V" — counter must be untouched.
    assert_eq!(
        findings_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "collapse must not decrement findings_count for non-matching (R) drops"
    );
    assert_eq!(results.lock().await.len(), 1, "collapse keeps only the V");
}

#[tokio::test]
async fn test_collapse_target_results_decrements_matching_r_under_all_filter() {
    // Counterpart: under "ALL" (or "R") the dropped R duplicates *were* counted,
    // so the counter must decrement by exactly the matching drop.
    let results = std::sync::Arc::new(tokio::sync::Mutex::new(vec![
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
        make_typed_param_result(FindingType::Verified, "q", "inHTML"),
        make_typed_param_result(FindingType::Reflected, "q", "inHTML"),
    ]));
    let findings_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(3));
    let target = parse_target("https://example.com/?x=1").unwrap();

    collapse_target_results(&results, &findings_count, "ALL", &target).await;

    // 3 -> 1 finding: decrement by 2.
    assert_eq!(
        findings_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "collapse must decrement by the matching drop under ALL"
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

#[test]
fn test_http_scannable_param_count_excludes_fragment() {
    // Fragment params are client-side only and generate_param_jobs skips them,
    // so async front-ends must not count them in params_total (it would make
    // estimated_completion_pct stall below 100%).
    let mut target = parse_target("https://example.com/?q=x").expect("parse target");
    mock_add_reflection_param(&mut target, "q", Location::Query);
    mock_add_reflection_param(&mut target, "body", Location::Body);
    mock_add_reflection_param(&mut target, "hash", Location::Fragment);

    assert!(super::param_is_http_scannable(&target.reflection_params[0]));
    assert!(!super::param_is_http_scannable(
        &target.reflection_params[2]
    ));
    assert_eq!(
        super::http_scannable_param_count(&target),
        2,
        "fragment param must be excluded from the HTTP-scannable count"
    );
}

// Mock function for XSS scanning tests (similar to parameter analysis mocks)
fn mock_add_reflection_param(target: &mut Target, name: &str, location: Location) {
    target.reflection_params.push(Param {
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new(name.to_string(), "mock_value".to_string(), location)
    });
}

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        silence: true,
        workers: 10,
        max_concurrent_targets: 10,
        encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
    }
}

#[test]
fn test_get_dom_payloads_javascript_context_returns_breakout_payloads() {
    let param = Param {
        injection_context: Some(InjectionContext::Javascript(None)),
        ..Param::new("q".to_string(), "seed".to_string(), Location::Query)
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
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new("q".to_string(), "seed".to_string(), Location::Query)
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
    let param = Param::new("q".to_string(), "seed".to_string(), Location::Query);
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
    let param = Param::new("q".to_string(), "seed".to_string(), Location::Query);
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

#[test]
fn test_prune_keeps_positional_pad_bypass_despite_blocked_angles() {
    // A leading-window ("positional") pad payload carries a raw `<` on purpose —
    // the block may only touch a leading window, so the tag passes once padded
    // past it. The raw-angle prune must exempt it while still dropping ordinary
    // raw-angle payloads.
    let pad = format!("{}<svg onload=alert(1) class=x>", "0".repeat(24));
    let payloads = vec![
        pad.clone(),
        "<svg onload=alert(1)>".to_string(), // ordinary raw-angle: dropped
        "\" onfocus=alert(1) \"".to_string(), // angle-free: kept
    ];
    let pruned = prune_blocked_raw_angles(payloads, &['<', '>']);
    assert!(
        pruned.contains(&pad),
        "positional-pad payload must survive the prune"
    );
    assert!(
        !pruned.iter().any(|p| p == "<svg onload=alert(1)>"),
        "ordinary raw-angle payloads must still be dropped"
    );
}

#[test]
fn test_hoist_puts_positional_pad_bypass_first() {
    // When angles are reported blocked, positional-pad payloads must lead so the
    // DOM phase's inert-echo early exit cannot retire before they are tried.
    let pad = format!("{}<svg onload=alert(1) class=x>", "0".repeat(24));
    let payloads = vec![
        "\" onfocus=alert(1) \"".to_string(), // angle-free
        pad.clone(),                          // positional pad (raw <)
        "%3Csvg%3E".to_string(),              // encoded angle
    ];
    let hoisted = hoist_angle_free_payloads(payloads, &['<']);
    assert_eq!(
        hoisted[0], pad,
        "positional-pad payload must be hoisted to the very front"
    );
    assert_eq!(hoisted[1], "\" onfocus=alert(1) \"");
    assert!(hoisted[2].contains("%3C"));
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

    let param = Param::new("q".to_string(), "".to_string(), Location::Query);

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

    let param = Param::new(
        "path_segment_1".to_string(),
        "b".to_string(),
        Location::Path,
    );

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

    let param = Param::new("q".to_string(), String::new(), Location::JsonBody);

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
    // Consecutive silent 5xx accumulate…
    assert_eq!(next_blocked_streak(0, 503, false), 1);
    assert_eq!(next_blocked_streak(63, 503, false), 64);
    // …but ANY non-5xx response resets the streak to 0 — this is what makes the
    // streak *consecutive*, so 64 non-consecutive blocks never early-exit.
    assert_eq!(next_blocked_streak(63, 200, false), 0);
    assert_eq!(next_blocked_streak(63, 403, false), 0); // 4xx WAF block does not count
    assert_eq!(next_blocked_streak(63, 0, false), 0); // request error does not count
}

/// A 5xx that echoes the payload is a rendered error page, not a dead server.
///
/// Regression guard: framework development error pages (Kemal, Werkzeug, Rails,
/// Symfony) reflect the request path / query string / an exception message built
/// from user input, and they are a 500 by construction — GHSA-2x8p-5jvx-v7jw is
/// exactly this shape. Counting them toward the streak ended the DOM phase after
/// `BLOCKED_STREAK_LIMIT` payloads, so the parameter could only ever be reported
/// `[R]` even though `--deep-scan` verifies it as `[V]`. Fan-out on these
/// endpoints is bounded by `INERT_ECHO_BUDGET` instead, which is the budget
/// meant for "reflects everything, verifies nothing".
#[test]
fn test_next_blocked_streak_spares_reflecting_error_pages() {
    // A reflecting 5xx never accumulates, no matter how long the run.
    assert_eq!(next_blocked_streak(0, 500, true), 0);
    assert_eq!(next_blocked_streak(63, 500, true), 0);
    assert_eq!(next_blocked_streak(63, 503, true), 0);
    // …and it clears a streak built by preceding silent errors, exactly like any
    // other response that proves the endpoint is still rendering.
    assert_eq!(
        next_blocked_streak(next_blocked_streak(0, 500, false), 500, true),
        0
    );
    // The early exit therefore never fires on this endpoint via the streak.
    assert!(!dom_phase_should_early_exit(
        false,
        0,
        next_blocked_streak(63, 500, true)
    ));
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
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        workers: 10,
        max_concurrent_targets: 10,
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    let results = Arc::new(Mutex::new(Vec::new()));

    // Mock scanning - in real scenario this would attempt HTTP requests
    run_scanning(
        &target,
        Arc::new(args),
        ScanRunHandles::new(results, Arc::new(AtomicUsize::new(0))),
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
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        data: Some("key1=value1&key2=value2".to_string()),
        method: "POST".to_string(),
        workers: 10,
        max_concurrent_targets: 10,
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    let results = Arc::new(Mutex::new(Vec::new()));

    // Mock scanning - in real scenario this would attempt HTTP requests
    run_scanning(
        &target,
        Arc::new(args),
        ScanRunHandles::new(results, Arc::new(AtomicUsize::new(0))),
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
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new(
            "test_param".to_string(),
            "test_value".to_string(),
            Location::Query,
        )
    });

    let args = crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        workers: 10,
        max_concurrent_targets: 10,
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    let results = Arc::new(Mutex::new(Vec::new()));

    // This will attempt real HTTP requests, but in test environment it may fail
    // For unit testing, we can just ensure no panic occurs
    run_scanning(
        &target,
        Arc::new(args),
        ScanRunHandles::new(results, Arc::new(AtomicUsize::new(0))),
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
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new("query".to_string(), "a".to_string(), Location::Query)
    });

    let args = Arc::new(integration_scan_args(false));
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
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
/// but in a permanently inert context (reflected inside an HTML comment with the
/// `-->` terminator neutralised, so no payload can break out to form an element)
/// must trigger the DOM-phase inert-echo early exit. An HTML comment is
/// deliberately *not* one of the reflection phase's safe-tag contexts, so that
/// phase still records a real R and short-circuits, leaving the DOM phase — where
/// the raw payload reflects but is permanently inert — to exercise the early
/// exit. The unknown-context (`injection_context: None`) DOM payload set is
/// thousands of payloads; the early exit has to cap the request fan-out well
/// below that without producing a false Verified finding.
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
    // `Param::new` leaves `injection_context` unset: unknown context → the full
    // HTML+attribute+… DOM payload catalog (thousands of payloads once
    // encoder-expanded).
    target
        .reflection_params
        .push(Param::new("query", "a", Location::Query));

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
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
        "a permanently inert HTML-comment echo must not yield a false Verified finding"
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
    target.reflection_params.push(Param::new(
        "query".to_string(),
        "a".to_string(),
        Location::Query,
    ));

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
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
    target.reflection_params.push(Param::new(
        "query".to_string(),
        "a".to_string(),
        Location::Query,
    ));

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
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
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new(name.to_string(), "1".to_string(), Location::Query)
        });
    }

    let params_done = Arc::new(std::sync::atomic::AtomicU32::new(0));
    run_scanning(
        &target,
        Arc::new(integration_scan_args(false)),
        ScanRunHandles::new(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicUsize::new(0)),
        )
        .with_params_done(params_done.clone()),
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
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        workers: 10,
        max_concurrent_targets: 10,
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    let results = Arc::new(Mutex::new(Vec::new()));

    run_scanning(
        &target,
        Arc::new(args),
        ScanRunHandles::new(results, Arc::new(AtomicUsize::new(0))),
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
        input_type: "url".to_string(),
        format: "json".to_string(),
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_discovery: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 5,
        no_color: true,
        silence: true,
        workers: 2,
        max_concurrent_targets: 2,
        max_targets_per_host: 10,
        encoders: vec![],
        skip_xss_scanning: true,
        sxss_retries: 1,
        analyze_external_js: analyze,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        retry_delay: 0,
        waf_min_confidence: 0.0,
        ..Default::default()
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

// ---- build_request_text: the displayed PoC HTTP request ------------------

use crate::target_parser::Target;

/// Minimal `Param` for request-text tests (all the discovery-derived metadata
/// fields left at their `None` defaults).
fn req_param(name: &str, value: &str, location: Location) -> Param {
    Param::new(name.to_string(), value.to_string(), location)
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
    // Body-capable methods are preserved; form content type is set.
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
fn build_request_text_body_preserves_query_method() {
    // RFC 10008 QUERY: body injection must not force POST.
    let target = Target {
        method: "QUERY".to_string(),
        data: Some("filter=foo&q=seed".to_string()),
        ..target_for("https://example.com/search")
    };
    let param = req_param("q", "seed", Location::Body);
    let req = super::build_request_text(&target, &param, "PAY");
    assert!(req.starts_with("QUERY /search "), "req:\n{req}");
    assert!(req.contains("filter=foo"), "req:\n{req}");
    assert!(req.contains("q=PAY"), "req:\n{req}");
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

/// `extract_meta_csp` must prefer an enforcing `Content-Security-Policy` meta
/// over a report-only one even when the report-only tag appears first —
/// otherwise downstream marks the policy report-only (zeroing Trusted Types
/// enforcement) and the real enforcing policy is dropped.
#[test]
fn test_extract_meta_csp_prefers_enforcing_over_report_only() {
    let html = r#"<html><head>
        <meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'none'">
        <meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'">
    </head><body></body></html>"#;
    let (name, content) = extract_meta_csp(html).expect("a meta CSP is present");
    assert_eq!(name, "Content-Security-Policy");
    assert!(content.contains("require-trusted-types-for"));
}

/// With only a report-only meta present, it is still returned (nothing else to
/// fall back to).
#[test]
fn test_extract_meta_csp_returns_report_only_when_no_enforcing() {
    let html = r#"<html><head>
        <meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'">
    </head><body></body></html>"#;
    let (name, content) = extract_meta_csp(html).expect("a report-only meta is present");
    assert_eq!(name, "Content-Security-Policy-Report-Only");
    assert!(content.contains("default-src 'self'"));
}

/// End-to-end coverage for the `--hpp` phase, which had none: `run_hpp_phase`
/// and the `check_reflection_with_hpp_url` it drives were both fully untested,
/// so an `inHTML-HPP` finding was never produced by any test.
///
/// The mock target models the shape HPP exists to defeat: the sanitizer runs on
/// the *first* occurrence of `q`, while the reflection uses the *last* one. A
/// single-parameter request (what the reflection phase sends) is therefore
/// always sanitized and finds nothing — only the duplicated-parameter URL gets
/// the payload through. That makes the assertion specific to the HPP phase
/// rather than something the reflection phase could have produced.
#[tokio::test]
async fn test_run_scanning_hpp_phase_reports_duplicated_param_bypass() {
    use axum::{Router, extract::RawQuery, response::Html, routing::get};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    async fn hpp_handler(RawQuery(raw): RawQuery) -> Html<String> {
        let raw = raw.unwrap_or_default();
        let values: Vec<String> = raw
            .split('&')
            .filter_map(|pair| pair.strip_prefix("q="))
            .map(|v| urlencoding::decode(v).unwrap_or_default().into_owned())
            .collect();
        if values.is_empty() {
            return Html("<div>no q</div>".to_string());
        }
        // Sanitizer inspects the first occurrence...
        let first = &values[0];
        if first.contains('<') || first.contains('>') {
            return Html("<div>blocked</div>".to_string());
        }
        // ...but the page renders the last one, raw.
        Html(format!("<div>{}</div>", values[values.len() - 1]))
    }

    let app = Router::new().route("/", get(hpp_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let url = format!("http://{}/?q=safe", addr);
    let mut target = parse_target(&url).expect("parse_target");
    target.reflection_params.push(Param {
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new("q".to_string(), "safe".to_string(), Location::Query)
    });

    let mut args = integration_scan_args(false);
    args.hpp = true;
    let args = Arc::new(args);
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
    )
    .await;

    let guard = results.lock().await;
    let hpp: Vec<_> = guard
        .iter()
        .filter(|r| r.inject_type == "inHTML-HPP")
        .collect();
    assert!(
        !hpp.is_empty(),
        "the first-occurrence-sanitized / last-occurrence-rendered shape must \
         yield an inHTML-HPP finding; got: {:?}",
        guard
            .iter()
            .map(|r| (&r.result_type, r.inject_type.as_str()))
            .collect::<Vec<_>>()
    );
    let finding = hpp[0];
    // Pin the reporting contract for the HPP finding: these fields are what
    // distinguishes it from a plain reflection in JSON/SARIF output.
    assert_eq!(finding.param, "q");
    assert_eq!(finding.message_id, 606);
    assert_eq!(finding.severity, "Info");
    assert_eq!(finding.location, "Query");
    assert!(
        finding.data.contains("q=") && finding.data.matches("q=").count() >= 2,
        "the reported URL must be the duplicated-parameter one, got: {}",
        finding.data
    );
    assert!(
        finding.evidence.contains("HPP bypass") && finding.evidence.contains("position="),
        "evidence must name the HPP position, got: {}",
        finding.evidence
    );
    // Only one HPP finding per param — the phase breaks out after the first hit.
    assert_eq!(
        hpp.len(),
        1,
        "run_hpp_phase must report at most one finding per param"
    );
}

/// The HPP phase is opt-in. Without `--hpp` the same target must produce no
/// HPP finding, so the flag gate in `run_hpp_phase` (and the payload-cloning
/// gate in `scan_param` that mirrors it) stays honest.
#[tokio::test]
async fn test_run_scanning_without_hpp_flag_reports_no_hpp_finding() {
    use axum::{Router, extract::RawQuery, response::Html, routing::get};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    async fn echo_last_q(RawQuery(raw): RawQuery) -> Html<String> {
        let raw = raw.unwrap_or_default();
        let last = raw
            .split('&')
            .filter_map(|pair| pair.strip_prefix("q="))
            .next_back()
            .unwrap_or("");
        Html(format!(
            "<div>{}</div>",
            urlencoding::decode(last).unwrap_or_default()
        ))
    }

    let app = Router::new().route("/", get(echo_last_q));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let url = format!("http://{}/?q=safe", addr);
    let mut target = parse_target(&url).expect("parse_target");
    target.reflection_params.push(Param {
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new("q".to_string(), "safe".to_string(), Location::Query)
    });

    let args = Arc::new(integration_scan_args(false));
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
    )
    .await;

    let guard = results.lock().await;
    assert!(
        guard.iter().all(|r| r.inject_type != "inHTML-HPP"),
        "HPP findings must require --hpp"
    );
}

// --- evidence-body bounding -------------------------------------------------

#[test]
fn bound_evidence_body_leaves_normal_bodies_untouched() {
    let body = "<html><body>PAYLOAD</body></html>".to_string();
    assert_eq!(
        crate::scanning::result::bound_evidence_body(body.clone(), "PAYLOAD"),
        body
    );
}

#[test]
fn bound_evidence_body_keeps_the_window_around_the_payload() {
    // A reflection far past the cap must survive: `extract_context` searches
    // the retained body for the payload to render the `L1:` line, so a blind
    // prefix cut would silently blank that evidence.
    use crate::scanning::result::{MAX_EVIDENCE_BODY_BYTES, bound_evidence_body};
    let payload = "<svg onload=alert(1)>";
    let body = format!(
        "{}{}{}",
        "A".repeat(4 * 1024 * 1024),
        payload,
        "B".repeat(1024)
    );
    let bounded = bound_evidence_body(body, payload);
    assert!(
        bounded.len() < MAX_EVIDENCE_BODY_BYTES + 64,
        "bounded body is {} bytes",
        bounded.len()
    );
    assert!(
        bounded.contains(payload),
        "the payload must survive the cut"
    );
    assert!(bounded.starts_with('…'), "an elided prefix must be marked");
}

#[test]
fn bound_evidence_body_cuts_on_char_boundaries() {
    use crate::scanning::result::bound_evidence_body;
    // Multi-byte characters straddling both cut points must not panic and must
    // leave valid UTF-8 (the return type guarantees it; the point is no panic).
    let body = format!("{}PAY{}", "한".repeat(1_000_000), "글".repeat(1_000_000));
    let bounded = bound_evidence_body(body, "PAY");
    assert!(bounded.contains("PAY"));
}

#[test]
fn bound_evidence_body_falls_back_to_a_prefix_when_the_payload_is_absent() {
    use crate::scanning::result::{MAX_EVIDENCE_BODY_BYTES, bound_evidence_body};
    let body = "Z".repeat(4 * 1024 * 1024);
    let bounded = bound_evidence_body(body, "not-present");
    assert!(bounded.len() < MAX_EVIDENCE_BODY_BYTES + 64);
    assert!(bounded.ends_with('…'), "an elided suffix must be marked");
}

// --- URL-attribute back-walk budget ----------------------------------------

#[test]
fn url_attr_reflection_in_a_normal_href_is_still_recognised() {
    // The budget must not change the answer for ordinary markup: this is the
    // suppression the back-walk exists to enable.
    let html = r#"<html><body><a href="/path/MARKER1">x</a></body></html>"#;
    assert!(
        crate::scanning::check_reflection::marker_reflects_in_url_attr_only(html, "MARKER1"),
        "a marker echoed only inside href must still read as URL-attr-only"
    );
    let text = r#"<html><body><div>MARKER1</div></body></html>"#;
    assert!(
        !crate::scanning::check_reflection::marker_reflects_in_url_attr_only(text, "MARKER1"),
        "a marker in body text is not URL-attr-only"
    );
}

// ---------------------------------------------------------------------------
// estimate_param_requests — the shared preflight/dry-run request estimator
//
// `run_scanning` fans a parameter out into a reflection payload set AND a DOM
// payload set, truncates each to the effective cap, and sends one request per
// payload in both. The REST `/preflight` endpoint and the MCP `preflight_dalfox`
// tool used to count only the reflection half, so they quoted roughly half the
// real volume — on the one number those surfaces exist to produce. All three
// estimates now call this, so it is worth pinning each branch directly rather
// than only through a live-target preflight (which never reaches the
// no-context and JS-context arms).
// ---------------------------------------------------------------------------

fn param_with_context(ctx: Option<InjectionContext>) -> Param {
    Param {
        injection_context: ctx,
        ..Param::new("q".to_string(), "seed".to_string(), Location::Query)
    }
}

#[test]
fn test_estimate_param_requests_counts_both_scan_phases() {
    let args = default_scan_args();
    let uncapped = |n: usize| n;

    // HTML / Attribute / AttributeUrl / Css and the unknown-context fallback all
    // run both phases, so each must be billed strictly more than its reflection
    // half alone — that difference is exactly what the old estimate dropped.
    for ctx in [
        None,
        Some(InjectionContext::Html(None)),
        Some(InjectionContext::Attribute(None)),
        Some(InjectionContext::AttributeUrl(None)),
        Some(InjectionContext::Css(None)),
    ] {
        let p = param_with_context(ctx.clone());
        let refl_only = match &p.injection_context {
            Some(c) => crate::scanning::xss_common::get_dynamic_payloads(c, &args)
                .expect("reflection payloads")
                .len(),
            None => {
                crate::payload::get_dynamic_xss_html_payloads().len()
                    + crate::payload::XSS_JAVASCRIPT_PAYLOADS.len()
            }
        };
        let total = estimate_param_requests(&p, &args, 1, &uncapped);
        assert!(
            total > refl_only,
            "context {ctx:?} runs a DOM phase too, so the estimate must exceed \
             the reflection-only count ({refl_only}), got {total}"
        );
    }

    // A JS-context param gets no DOM-verification pass, so it is billed for the
    // reflection set alone — the one branch where the two agree.
    let js = param_with_context(Some(InjectionContext::Javascript(None)));
    let js_refl = crate::scanning::xss_common::get_dynamic_payloads(
        js.injection_context.as_ref().expect("js context"),
        &args,
    )
    .expect("reflection payloads")
    .len();
    assert_eq!(estimate_param_requests(&js, &args, 1, &uncapped), js_refl);
}

#[test]
fn test_estimate_param_requests_caps_each_phase_separately() {
    let args = default_scan_args();
    // `run_scanning` truncates the reflection set and the DOM set to `cap`
    // *each*, so a two-phase parameter costs up to `2 * cap` — not `cap`.
    // Clamping the combined figure at `cap` is what halved the quote.
    let cap = 5usize;
    let apply_cap = move |n: usize| n.min(cap);
    let html = param_with_context(Some(InjectionContext::Html(None)));
    assert_eq!(
        estimate_param_requests(&html, &args, 1, &apply_cap),
        2 * cap,
        "both phases generate well over {cap} payloads, so each is capped at \
         {cap} and the parameter costs {}",
        2 * cap
    );

    // A JS-context param has no DOM phase, so it stops at one cap.
    let js = param_with_context(Some(InjectionContext::Javascript(None)));
    assert_eq!(estimate_param_requests(&js, &args, 1, &apply_cap), cap);

    // `cap == 0` is the --deep-scan spelling of "unlimited" and must not zero
    // the estimate.
    let unlimited = |n: usize| n;
    assert!(estimate_param_requests(&html, &args, 1, &unlimited) > 2 * cap);
}

// ---------------------------------------------------------------------------
// Scan-core defect regressions (A1)
// ---------------------------------------------------------------------------

/// Bind an axum app on an ephemeral loopback port and return its base address.
async fn spawn_regression_app(app: axum::Router) -> std::net::SocketAddr {
    use std::net::Ipv4Addr;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

/// `FoundParams` used to be keyed by parameter *name* alone, so the first wire
/// slot to produce a finding suppressed every sibling slot with the same name:
/// the reflection/DOM phases short-circuited and the dispatch loop skipped the
/// sibling's worker outright.
///
/// Here `q` names two genuinely independent injection points on one request —
/// `?q=` in the query string and `q` in the urlencoded POST body — and the mock
/// reflects **both** raw. Both are exploitable, so both must be reported;
/// before the fix whichever worker won the race silenced the other and the scan
/// reported exactly one finding (a false negative on a real vulnerability).
#[tokio::test]
async fn test_run_scanning_reports_same_name_query_and_body_params_separately() {
    use axum::{Router, extract::Query, response::Html, routing::post};
    use std::collections::HashMap;

    async fn handler(Query(q): Query<HashMap<String, String>>, body: String) -> Html<String> {
        let from_query = q.get("q").cloned().unwrap_or_default();
        let from_body = url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == "q")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        Html(format!(
            "<html><body><div id=q>{}</div><div id=b>{}</div></body></html>",
            from_query, from_body
        ))
    }

    let addr = spawn_regression_app(Router::new().route("/", post(handler))).await;

    let url = format!("http://{}/?q=a", addr);
    let mut target = parse_target(&url).expect("parse_target");
    target.method = "POST".to_string();
    target.data = Some("q=b".to_string());
    target.workers = 4;
    target.reflection_params = vec![
        Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new("q".to_string(), "a".to_string(), Location::Query)
        },
        Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new("q".to_string(), "b".to_string(), Location::Body)
        },
    ];

    let args = Arc::new(integration_scan_args(false));
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
    )
    .await;

    let guard = results.lock().await;
    let locations: Vec<&str> = guard
        .iter()
        .filter(|r| r.param == "q")
        .map(|r| r.location.as_str())
        .collect();
    assert!(
        locations.contains(&"Query"),
        "the vulnerable query-string `q` must be reported; got {:?}",
        locations
    );
    assert!(
        locations.contains(&"Body"),
        "the vulnerable body `q` is a different injection point and must be \
         reported too; got {:?}",
        locations
    );
}

/// Cancellation used to be honoured only inside the reflection and DOM payload
/// loops. Every parameter's worker is spawned up front, so on a cancelled scan
/// the workers still queued behind the concurrency semaphore each went on to
/// fire the Stage-0 probe and then the whole `--hpp` phase — thousands of
/// requests at a target the operator had already asked us to stop hitting.
///
/// The mock flips the cancel flag once it has served a handful of requests and
/// counts everything it receives afterwards. `--hpp` is on and duplicate-
/// parameter requests are answered without a reflection, so the HPP phase runs
/// its full `payloads x positions` fan-out when it is not stopped.
#[tokio::test]
async fn test_run_scanning_cancel_stops_probe_and_hpp_requests() {
    use axum::{Router, extract::RawQuery, extract::State, response::Html, routing::get};
    use std::sync::atomic::AtomicBool;

    #[derive(Clone)]
    struct AppState {
        requests: Arc<AtomicUsize>,
        cancel: Arc<AtomicBool>,
    }

    /// Requests served before the scan is cancelled.
    const CANCEL_AFTER: usize = 6;

    async fn handler(State(st): State<AppState>, RawQuery(q): RawQuery) -> Html<String> {
        let n = st.requests.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= CANCEL_AFTER {
            st.cancel.store(true, Ordering::SeqCst);
        }
        let raw = q.unwrap_or_default();
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // HPP probes send the same name twice. Answer those without echoing
        // anything so the HPP phase never short-circuits on a first hit and
        // instead spends its full per-parameter budget.
        let mut names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        let deduped = {
            let mut d = names.clone();
            d.dedup();
            d.len()
        };
        if deduped != names.len() {
            return Html("<html><body>no</body></html>".to_string());
        }
        let echoed: String = pairs.iter().map(|(_, v)| v.as_str()).collect();
        Html(format!("<html><body><div>{}</div></body></html>", echoed))
    }

    let requests = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let state = AppState {
        requests: requests.clone(),
        cancel: cancel.clone(),
    };
    let addr = spawn_regression_app(
        Router::new()
            .route("/", get(handler))
            .with_state(state.clone()),
    )
    .await;

    // 40 parameters, 2 workers: 38 of them are queued behind the semaphore when
    // the cancel flag flips, which is exactly the population the fix protects.
    const PARAMS: usize = 40;
    let query: String = (0..PARAMS)
        .map(|i| format!("p{}=a", i))
        .collect::<Vec<_>>()
        .join("&");
    let url = format!("http://{}/?{}", addr, query);
    let mut target = parse_target(&url).expect("parse_target");
    target.workers = 2;
    target.reflection_params = (0..PARAMS)
        .map(|i| Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new(format!("p{}", i), "a".to_string(), Location::Query)
        })
        .collect();

    let mut raw_args = integration_scan_args(false);
    raw_args.hpp = true;
    // One reflection payload per param keeps the *pre*-cancel traffic tiny; the
    // HPP subset is taken from this same list, so the post-cancel fan-out this
    // test measures stays attributable to the probe + HPP phases.
    raw_args.max_payloads_per_param = 1;
    let args = Arc::new(raw_args);

    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        args,
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))).with_cancel(cancel),
    )
    .await;

    let total = requests.load(Ordering::SeqCst);
    // Before the fix each of the ~38 queued workers still ran a probe and the
    // full HPP fan-out after cancellation, which lands in the hundreds. The
    // small allowance covers the two workers that were already mid-flight.
    assert!(
        total < 60,
        "a cancelled scan must stop issuing requests; the queued workers sent \
         {} requests in total (cancel fired at request {})",
        total,
        CANCEL_AFTER
    );
}

/// The `--sxss` branch of `fetch_injection_response_with_client` used to return
/// candidate bodies without applying any of the response gates the normal
/// reflection branch applies. An `application/json` echo is inert — a browser
/// renders it as data, never as markup — so the plain path suppresses it, while
/// `--sxss` reported it as a stored-XSS reflection.
///
/// The HTML half of the test is the control: it proves the mock is otherwise
/// detectable, so an empty result on the JSON half means "gated", not
/// "nothing reached the scanner".
#[tokio::test]
async fn test_sxss_applies_the_same_response_gates_as_the_normal_path() {
    use axum::http::header;
    use axum::{Router, extract::Query, response::IntoResponse, routing::get};
    use std::collections::HashMap;

    async fn json_echo(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = q.get("q").cloned().unwrap_or_default();
        (
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"q\":\"{}\"}}", v),
        )
    }
    async fn html_echo(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = q.get("q").cloned().unwrap_or_default();
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!("<html><body><div>{}</div></body></html>", v),
        )
    }

    let addr = spawn_regression_app(
        Router::new()
            .route("/json", get(json_echo))
            .route("/html", get(html_echo)),
    )
    .await;

    async fn scan_path(addr: std::net::SocketAddr, path: &str) -> usize {
        let url = format!("http://{}{}?q=a", addr, path);
        let mut target = parse_target(&url).expect("parse_target");
        target.workers = 2;
        target.reflection_params = vec![Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new("q".to_string(), "a".to_string(), Location::Query)
        }];

        let mut raw_args = integration_scan_args(false);
        raw_args.sxss = true;
        raw_args.max_payloads_per_param = 8;
        let results = Arc::new(Mutex::new(Vec::new()));
        run_scanning(
            &target,
            Arc::new(raw_args),
            ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
        )
        .await;
        results.lock().await.len()
    }

    assert!(
        scan_path(addr, "/html").await > 0,
        "control: an HTML echo must still be reported under --sxss"
    );
    assert_eq!(
        scan_path(addr, "/json").await,
        0,
        "an application/json echo is inert markup-wise; --sxss must apply the \
         same inert-content-type gate the plain reflection path applies"
    );
}

/// `PhaseFlow::Abort` (a global `--limit` reached mid-phase) used to `return`
/// out of the per-parameter worker *before* `flush_results`, silently
/// discarding every finding that worker had already confirmed and batched.
///
/// The scan below has two vulnerable parameters and `--limit 1`. `victim`
/// reflects entity-escaped, so it records an `R` on its first reflection
/// payload and then grinds through the (never-verifying) DOM payload set;
/// `trigger` reflects raw and is held back by the mock until `victim` has
/// confirmed its finding, at which point it verifies and flushes, tripping the
/// limit while `victim` is still mid-DOM-phase. `victim`'s already-confirmed
/// finding must survive that: `--limit` is a stop condition, not an instruction
/// to destroy evidence, and the report truncates to the limit on its own
/// (`cmd::scan::output`), so flushing here cannot overshoot the cap.
#[tokio::test]
async fn test_run_scanning_limit_abort_keeps_already_confirmed_findings() {
    use axum::{Router, extract::Query, extract::State, response::Html, routing::get};
    use std::collections::HashMap;

    #[derive(Clone)]
    struct AppState {
        victim_requests: Arc<AtomicUsize>,
    }

    /// `victim` requests to wait for before letting `trigger` verify. High
    /// enough that `victim` has certainly recorded its `R` and moved on to the
    /// (never-verifying) DOM payload set, so the limit trips while its worker
    /// is mid-loop with a batched finding.
    const VICTIM_REQUESTS_BEFORE_TRIGGER: usize = 60;

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    async fn handler(
        State(st): State<AppState>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Html<String> {
        let victim = q.get("victim").cloned().unwrap_or_default();
        let trigger = q.get("trigger").cloned().unwrap_or_default();
        if trigger != "b" {
            // A `trigger` injection: hold it until `victim` has gone past its
            // reflection phase (probe + first payload) and into the DOM phase,
            // so the limit trips while `victim` still has a batched finding.
            while st.victim_requests.load(Ordering::SeqCst) < VICTIM_REQUESTS_BEFORE_TRIGGER {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        } else {
            st.victim_requests.fetch_add(1, Ordering::SeqCst);
        }
        Html(format!(
            "<html><body><div id=v>{}</div><div id=t>{}</div></body></html>",
            escape(&victim),
            trigger
        ))
    }

    let addr = spawn_regression_app(Router::new().route("/", get(handler)).with_state(AppState {
        victim_requests: Arc::new(AtomicUsize::new(0)),
    }))
    .await;

    let url = format!("http://{}/?victim=a&trigger=b", addr);
    let mut target = parse_target(&url).expect("parse_target");
    target.workers = 2;
    target.reflection_params = vec![
        Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new("victim".to_string(), "a".to_string(), Location::Query)
        },
        Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new("trigger".to_string(), "b".to_string(), Location::Query)
        },
    ];

    let mut raw_args = integration_scan_args(false);
    raw_args.limit = Some(1);
    let results = Arc::new(Mutex::new(Vec::new()));
    run_scanning(
        &target,
        Arc::new(raw_args),
        ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
    )
    .await;

    let guard = results.lock().await;
    let params: Vec<(String, String)> = guard
        .iter()
        .map(|r| (r.param.clone(), r.result_type.short().to_string()))
        .collect();
    assert!(
        params.iter().any(|(p, _)| p == "trigger"),
        "sanity: the limit-tripping finding must be present; got {:?}",
        params
    );
    assert!(
        params.iter().any(|(p, _)| p == "victim"),
        "a finding confirmed before the --limit stop must not be discarded by \
         the abort path; got {:?}",
        params
    );
}

/// The other half of the `--sxss` gate parity: the Path-injection drops.
///
/// A path segment echoed back by an error page is only a finding when it lands
/// somewhere a browser parses as markup. Pure URL echo — a canonical `<link>`,
/// `<a href>` breadcrumbs — is noise, and the plain reflection path drops it via
/// `should_suppress_path_reflection_with_body`. The `--sxss` branch never ran
/// that check, so stored runs reported every 404 that prints the requested URI.
#[tokio::test]
async fn test_sxss_path_injection_drops_url_echo_only_reflections() {
    use axum::extract::Path as AxumPath;
    use axum::http::{StatusCode, header};
    use axum::{Router, response::IntoResponse, routing::get};

    /// 404 that echoes the requested path *only* inside a canonical link.
    async fn url_echo(AxumPath(rest): AxumPath<String>) -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "<html><head><link rel=\"canonical\" href=\"/{}\"></head><body>Not found</body></html>",
                rest
            ),
        )
    }

    /// 404 that renders the requested path into the document body — genuine
    /// error-page XSS, and it must survive the gate.
    async fn body_echo(AxumPath(rest): AxumPath<String>) -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!("<html><body><table><td>{}</td></table></body></html>", rest),
        )
    }

    /// An empty body carries no evidence at all.
    async fn empty() -> impl IntoResponse {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            String::new(),
        )
    }

    let addr = spawn_regression_app(
        Router::new()
            .route("/url-echo/{*rest}", get(url_echo))
            .route("/body-echo/{*rest}", get(body_echo))
            .route("/empty/{*rest}", get(empty)),
    )
    .await;

    async fn scan_path(addr: std::net::SocketAddr, prefix: &str) -> usize {
        let url = format!("http://{}/{}/seg", addr, prefix);
        let mut target = parse_target(&url).expect("parse_target");
        target.workers = 2;
        // `Location::Path` params are addressed by segment index (see
        // `url_inject`); index 1 is the `seg` component.
        target.reflection_params = vec![Param {
            injection_context: Some(InjectionContext::Html(None)),
            ..Param::new(
                "path_segment_1".to_string(),
                "seg".to_string(),
                Location::Path,
            )
        }];

        let mut raw_args = integration_scan_args(false);
        raw_args.sxss = true;
        raw_args.max_payloads_per_param = 8;
        let results = Arc::new(Mutex::new(Vec::new()));
        run_scanning(
            &target,
            Arc::new(raw_args),
            ScanRunHandles::new(results.clone(), Arc::new(AtomicUsize::new(0))),
        )
        .await;
        results.lock().await.len()
    }

    assert!(
        scan_path(addr, "body-echo").await > 0,
        "control: a 404 that renders the path segment into the document body is \
         real error-page XSS and must still be reported under --sxss"
    );
    assert_eq!(
        scan_path(addr, "url-echo").await,
        0,
        "a path segment echoed only inside a canonical <link> is URL noise; \
         --sxss must apply the same body-level Path gate the plain path applies"
    );
    assert_eq!(
        scan_path(addr, "empty").await,
        0,
        "an empty response body carries no evidence"
    );
}

#[test]
fn test_build_request_text_host_carries_a_non_default_port() {
    // `Host` is host *and* port. Dropping it replayed every PoC against a
    // non-default port to :80/:443 — a different service, or nothing at all.
    let target = parse_target("http://127.0.0.1:3031/x?q=1").unwrap();
    let param = Param::new("q".to_string(), "1".to_string(), Location::Query);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(
        request.contains("Host: 127.0.0.1:3031"),
        "port missing from Host, got:\n{request}"
    );
}

#[test]
fn test_build_request_text_omits_the_schemes_default_port() {
    // The flip side: :443 on https is implicit and must not be spelled out.
    let target = parse_target("https://example.com/x?q=1").unwrap();
    let param = Param::new("q".to_string(), "1".to_string(), Location::Query);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(request.contains("Host: example.com\r\n"));
    assert!(!request.contains("example.com:443"));
}

#[test]
fn test_build_request_text_injects_a_header_param() {
    // A `Location::Header` param is injected into the request, not the URL.
    // Emitting only the target's original headers left the payload nowhere in
    // the PoC, so it reproduced nothing.
    let mut target = parse_target("http://127.0.0.1:3031/h").unwrap();
    target.method = "GET".to_string();
    target.headers = vec![("X-Keep".to_string(), "1".to_string())];

    let param = Param::new("Referer".to_string(), String::new(), Location::Header);
    let request = build_request_text(&target, &param, "<svg onload=alert(1)>");
    assert!(
        request.contains("Referer: <svg onload=alert(1)>"),
        "injected header missing, got:\n{request}"
    );
    assert!(request.contains("X-Keep: 1"), "original header dropped");
}

#[test]
fn test_build_request_text_header_param_overrides_a_same_named_original() {
    // The wire path applies the injected header via `apply_header_overrides`,
    // which replaces. Emitting both would show a request that was never sent.
    let mut target = parse_target("http://127.0.0.1:3031/h").unwrap();
    target.headers = vec![("Referer".to_string(), "https://original/".to_string())];

    let param = Param::new("Referer".to_string(), String::new(), Location::Header);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(request.contains("Referer: PAYLOAD"));
    assert!(
        !request.contains("https://original/"),
        "the overridden original was emitted too, got:\n{request}"
    );
}

#[test]
fn test_build_request_text_cookie_param_goes_into_the_cookie_header() {
    // Per-cookie discovery files cookies as `Location::Header` named after the
    // cookie. `build_header_request` routes those into `Cookie` — injected
    // first, the target's other cookies preserved after it. Emitting
    // `sid: <payload>` instead would be a header the application never reads.
    let mut target = parse_target("http://127.0.0.1:3031/c").unwrap();
    target.cookies = vec![
        ("sid".to_string(), "abc".to_string()),
        ("theme".to_string(), "dark".to_string()),
    ];

    let param = Param::new("sid".to_string(), "abc".to_string(), Location::Header);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(
        request.contains("Cookie: sid=PAYLOAD"),
        "cookie param not injected into Cookie, got:\n{request}"
    );
    assert!(
        request.contains("theme=dark"),
        "neighbouring cookies dropped — they often carry the session the sink needs, got:\n{request}"
    );
    assert!(
        !request.contains("\r\nsid: PAYLOAD"),
        "cookie emitted as a header of its own name, got:\n{request}"
    );
}

#[test]
fn test_build_request_text_cookie_param_replaces_a_captured_cookie_header() {
    // A cookie param is sent through `build_request_with_cookie`, whose
    // composed value *replaces* any Cookie captured into `target.headers`.
    // Emitting the captured one too showed two Cookie lines that never went out
    // together, and put them in the opposite order to the wire.
    let mut target = parse_target("http://127.0.0.1:3031/c").unwrap();
    target.headers = vec![("Cookie".to_string(), "sid=abc".to_string())];
    target.cookies = vec![("sid".to_string(), "abc".to_string())];

    let param = Param::new("sid".to_string(), "abc".to_string(), Location::Header);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert_eq!(
        request.matches("Cookie: ").count(),
        1,
        "exactly one Cookie line, got:\n{request}"
    );
    assert!(request.contains("Cookie: sid=PAYLOAD"), "got:\n{request}");
}

#[test]
fn test_build_request_text_does_not_emit_a_second_cookie_line() {
    // `apply_headers_ua_cookies` auto-attaches `target.cookies` only when the
    // target has no Cookie header of its own. The PoC must mirror that instead
    // of printing both.
    let mut target = parse_target("http://127.0.0.1:3031/q").unwrap();
    target.headers = vec![("Cookie".to_string(), "sid=abc".to_string())];
    target.cookies = vec![("sid".to_string(), "abc".to_string())];

    let param = Param::new("q".to_string(), String::new(), Location::Query);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert_eq!(
        request.matches("Cookie: ").count(),
        1,
        "the captured Cookie header was duplicated by the auto-attach, got:\n{request}"
    );
}

#[test]
fn test_build_request_text_body_param_shows_the_injectors_content_type() {
    // `build_body_request_base` drops a captured Content-Type so the injector's
    // is the only one on the wire. Showing the captured one instead described a
    // request that frames the body in a format it is not written in.
    let mut target = parse_target("http://127.0.0.1:3031/p").unwrap();
    target.method = "POST".to_string();
    target.headers = vec![(
        "Content-Type".to_string(),
        "multipart/form-data; boundary=----OLD".to_string(),
    )];
    target.data = Some("q=1".to_string());

    let param = Param::new("q".to_string(), "1".to_string(), Location::Body);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(
        request.contains("Content-Type: application/x-www-form-urlencoded"),
        "got:\n{request}"
    );
    assert!(
        !request.contains("boundary=----OLD"),
        "the dropped captured Content-Type was emitted, got:\n{request}"
    );
    assert_eq!(request.matches("Content-Type: ").count(), 1);
}

#[test]
fn test_build_request_text_query_param_keeps_the_captured_content_type() {
    // Query/Path injectors re-send the original body verbatim through
    // `build_request`, which preserves the captured Content-Type.
    let mut target = parse_target("http://127.0.0.1:3031/p").unwrap();
    target.method = "POST".to_string();
    target.headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    target.data = Some("{\"a\":1}".to_string());

    let param = Param::new("q".to_string(), String::new(), Location::Query);
    let request = build_request_text(&target, &param, "PAYLOAD");
    assert!(
        request.contains("Content-Type: application/json"),
        "got:\n{request}"
    );
}
