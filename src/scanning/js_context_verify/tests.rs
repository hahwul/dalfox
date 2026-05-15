use super::*;

#[test]
fn detects_alert_breakout_in_double_quoted_js_string() {
    // Mirrors brutelogic c2 case: var c2 = "<INJECT>"
    let payload = "\"-alert(1)-\"";
    let html = format!(
        "<html><body><script>var c2 = \"{}\";</script></body></html>",
        payload
    );
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_alert_breakout_in_single_quoted_js_string() {
    let payload = "'-alert(1)-'";
    let html = format!(
        "<html><body><script>var c1 = '{}';</script></body></html>",
        payload
    );
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_plus_concat_breakout() {
    let payload = "\"+alert(1)+\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_tagged_template_payload() {
    let payload = "alert`1`";
    let html = format!("<script>var x = {};</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn rejects_html_entity_encoded_reflection_in_script() {
    // Server entity-encoded the reflection, so the JS source contains
    // literal `&#x27;` text — `alert(1)` is never produced as a real call.
    let payload = "'-alert(1)-'";
    let html = "<script>var c5 = '&#x27;-alert(1)-&#x27;';</script>";
    // The literal payload string is not the actual reflected text.
    assert!(!has_js_context_evidence(payload, html));
}

#[test]
fn rejects_when_payload_breaks_syntax() {
    let payload = "</script><h1>";
    let html = "<script>var x = \"</script><h1>\";</script>";
    // After breakout, parser sees `var x = "` which is a syntax error;
    // and there's no sink call anyway. Should not return true here.
    assert!(!has_js_context_evidence(payload, html));
}

#[test]
fn rejects_payload_kept_inside_outer_string_literal() {
    // The payload string `'-alert(1)-'` lands intact inside a double-quoted
    // string literal — single quotes do not close a double-quoted string,
    // so `alert(1)` parses as content of the outer string, not as a call.
    // Without the string-literal containment guard the sink-span check
    // would still fire (the AST sink span happens to overlap the payload
    // range only because the source bytes line up), even though the
    // surrounding string keeps it inert.
    let payload = "'-alert(1)-'";
    let html = format!(
        "<script>var x = decodeURIComponent(\"prefix {} suffix\");</script>",
        payload
    );
    assert!(
        !has_js_context_evidence(payload, &html),
        "payload kept entirely inside a string literal must not be verified"
    );
}

#[test]
fn detects_payload_that_breaks_out_of_outer_string_literal() {
    // Reflection into the middle of a single-argument string slot. The
    // payload's outer quotes merge with the surrounding quotes to form
    // two empty strings on either side of `-alert(1)-`, producing a real
    // `alert(1)` CallExpression *outside* any string literal. Without the
    // payload, the slot would just be `foo("")` — a harmless empty call.
    // The containment guard must allow this case through.
    let payload = "\"-alert(1)-\"";
    let html = format!("<script>foo(\"{}\");</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn ignores_pre_existing_alert_outside_payload_range() {
    let payload = "\"-foo-\"";
    let html = format!("<script>alert(1); var x = \"{}\";</script>", payload);
    // `alert(1)` exists but it's not inside the payload's byte range.
    assert!(!has_js_context_evidence(payload, &html));
}

#[test]
fn detects_set_timeout_string_payload() {
    let payload = "\";setTimeout('alert(1)');\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn no_evidence_when_payload_not_in_script_block() {
    let payload = "\"-alert(1)-\"";
    let html = "<html><body>\"-alert(1)-\"</body></html>";
    // Reflected outside any <script>; this module should not claim V.
    assert!(!has_js_context_evidence(payload, html));
}

#[test]
fn payload_quick_filter_rejects_non_sink_payload() {
    assert!(!payload_carries_js_sink("<svg/onload=foo>"));
    assert!(payload_carries_js_sink("\"-alert(1)-\""));
    assert!(payload_carries_js_sink("prompt`1`"));
}

#[test]
fn cached_parsed_spans_returns_same_result_for_identical_blocks() {
    // Two distinct calls on the same script source must yield the same
    // span set; the second call should hit the cache rather than re-parse.
    let block = "var c2 = \"\"-alert(1)-\"\"; var x = 5; window.foo = 1;";
    let first = cached_parsed_spans(block).expect("parses cleanly");
    let second = cached_parsed_spans(block).expect("parses cleanly (cache hit)");
    assert_eq!(first, second);
    assert!(!first.0.is_empty(), "should record at least one sink span");
}

#[test]
fn detects_comma_operator_bypass() {
    let payload = "\";(0,alert)(1);\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_underscore_comma_bypass() {
    let payload = "\";(_,alert)(1);\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_array_index_bypass() {
    let payload = "\";[alert][0](1);\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_string_keyed_dispatch_bypass() {
    let payload = "\";window[\"alert\"](1);\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_document_write_payload() {
    let payload = "\";document.write(1);\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_inner_html_assignment_payload() {
    let payload = "\";document.body.innerHTML='<img onerror=alert(1)>';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_outer_html_computed_assignment_payload() {
    let payload = "\";el[\"outerHTML\"]='X';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_srcdoc_assignment_payload() {
    let payload = "\";frame.srcdoc='<img onerror=alert(1)>';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_bare_location_assignment_payload() {
    // `location = '…'` is shorthand for window.location and triggers
    // navigation. With a `javascript:` URL it executes inline.
    let payload = "\";location='javascript:alert(1)';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_location_href_assignment_payload() {
    let payload = "\";location.href='javascript:alert(1)';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_window_location_member_assignment_payload() {
    let payload = "\";window.location='javascript:alert(1)';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(has_js_context_evidence(payload, &html));
}

#[test]
fn detects_jsonp_callback_alert_payload() {
    // Pure-JS body (e.g. JSONP response). Payload becomes the callable
    // identifier in `alert(1);foo({…})` — alert executes immediately.
    let payload = "alert(1);foo";
    let body = format!("{payload}({{\"data\":\"x\"}})");
    assert!(
        has_js_context_evidence(payload, &body),
        "JSONP-style body with reflected callee should yield JS evidence"
    );
}

#[test]
fn jsonp_fallback_skipped_when_script_block_present() {
    // A real `<script>` block is present, so the JSONP fallback shouldn't
    // run. Prevents accidental escalation when an HTML page has
    // pre-existing `alert(1)` outside any reflected payload range.
    let payload = "harmless";
    let body = "<html><body><script>alert(1)</script></body></html>";
    assert!(
        !has_js_context_evidence(payload, body),
        "fallback must not run when script blocks exist"
    );
}

#[test]
fn jsonp_fallback_respects_payload_range() {
    let payload = "harmless";
    let body = "alert(1);foo({\"data\":1})";
    // The payload `harmless` is not reflected at all → no evidence.
    assert!(!has_js_context_evidence(payload, body));
}

#[test]
fn does_not_flag_navigation_assignment_with_safe_url() {
    // location.href = '/about' is a normal redirect, not XSS — must not
    // trigger the navigation-sink rule.
    let payload = "\";location.href='/about';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(
        !has_js_context_evidence(payload, &html),
        "navigation to a relative URL should not be flagged"
    );
}

#[test]
fn does_not_flag_assignment_to_innocuous_property() {
    // Assigning to .textContent is safe (no HTML parse, no execution).
    // The payload contains "alert" via quick-filter but the AST should
    // produce no sink spans inside the payload's range.
    let payload = "\";el.textContent='alert(1)';\"";
    let html = format!("<script>var x = \"{}\";</script>", payload);
    assert!(
        !has_js_context_evidence(payload, &html),
        "textContent is not an HTML-parsing sink"
    );
}

#[test]
fn cached_parsed_spans_distinct_for_different_blocks() {
    let a = "var c1 = ''-alert(1)-'';";
    let b = "var c2 = \"-prompt(1)-\";";
    let sa = cached_parsed_spans(a).expect("a parses");
    let sb = cached_parsed_spans(b).expect("b parses");
    assert_ne!(sa, sb);
}

#[test]
fn redirect_location_wrapper_does_not_trigger_js_context() {
    // Regression for xssmaze /redirect/level1: when a 3xx Location header
    // is wrapped as `<html><body>javascript:alert(1)</body></html>` so it
    // reaches the reflection path, the JS-context AST verifier must NOT
    // upgrade to V. Browsers never execute the Location's URL scheme on
    // a 3xx redirect, so any V upgrade here is a false positive.
    let payload = "javascript:alert(1)";
    let body = format!("<html><body>{}</body></html>", payload);
    assert!(
        !has_js_context_evidence(payload, &body),
        "wrapped Location body must not produce JS-context evidence"
    );
}
