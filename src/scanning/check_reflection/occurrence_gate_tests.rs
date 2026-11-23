//! `reflection_inert_at_every_occurrence`: the per-occurrence report gate.

use super::*;

fn marker() -> &'static str {
    crate::scanning::markers::class_marker()
}

/// The attribute-injection payload the scanner sends, quotes and all.
fn attr_payload() -> String {
    format!("' onerror=alert(1) class={} src=x '", marker())
}

fn inert(html: &str, payload: &str) -> bool {
    reflection_inert_at_every_occurrence(html, payload)
}

// ---- the echoes this gate exists to stop reporting -------------------------

#[test]
fn text_attribute_and_js_string_together_are_inert() {
    // The search-page shape: one value printed into an input, a heading and a
    // script string. No earlier gate owns all three contexts.
    let html = r#"<!DOCTYPE html><html><head><title>Search</title></head><body>
<form><input type="text" name="q" value="alert(1)"></form>
<p>Search results for: alert(1)</p>
<div>No results found for "alert(1)"</div>
<script>
  var searchTerm = "alert(1)";
  console.log("Search: " + searchTerm);
</script></body></html>"#;
    assert!(inert(html, "alert(1)"));
    assert!(is_in_safe_context_decoded(html, "alert(1)"));
}

#[test]
fn text_and_js_string_together_are_inert() {
    let html = r#"<div class="error-message">Error: alert(1)</div>
<pre>at handleRequest(alert(1))</pre>
<script>console.log("Error page loaded: alert(1)");</script>"#;
    assert!(inert(html, "alert(1)"));
}

#[test]
fn a_quote_bearing_payload_in_element_text_is_inert() {
    // `raw_reflection_inert_in_text` refuses this payload for its quotes.
    let p = attr_payload();
    let html = format!("<html><body><div class=\"editor\">{p}</div></body></html>");
    assert!(!raw_reflection_inert_in_text(&html, &p));
    assert!(inert(&html, &p));
    assert!(is_in_safe_context_decoded(&html, &p));
}

#[test]
fn text_after_a_tag_whose_attribute_holds_a_gt_is_still_text() {
    let p = attr_payload();
    let html = format!("<p title=\"a > b\">{p}</p>");
    assert!(inert(&html, &p));
}

#[test]
fn display_only_raw_text_elements_are_inert() {
    let p = attr_payload();
    for element in ["textarea", "title", "xmp", "noscript"] {
        let html = format!("<p>{p}</p><{element}>{p}</{element}>");
        assert!(inert(&html, &p), "{element}");
    }
}

#[test]
fn a_quoted_display_attribute_is_inert() {
    let p = format!("x onmouseover=alert(1) class={} ", marker());
    for attr in ["value", "title", "alt", "placeholder", "data-q", "class"] {
        let html = format!("<p>{p}</p><input {attr}=\"{p}\">");
        assert!(inert(&html, &p), "{attr}");
    }
}

#[test]
fn the_middle_of_an_ordinary_url_is_inert() {
    let html = r#"<p>alert(1)</p><a href="/search?q=alert(1)&page=2">next</a>"#;
    assert!(inert(html, "alert(1)"));
    let html = r#"<p>alert(1)</p><meta name="description" content="Results for alert(1)">"#;
    assert!(inert(html, "alert(1)"));
}

#[test]
fn text_inside_an_svg_integration_point_is_text() {
    let html = "<svg><title>alert(1)</title><path d=\"M0 0\"/></svg><p>alert(1)</p>";
    assert!(inert(html, "alert(1)"));
}

// ---- echoes that keep the finding -----------------------------------------

#[test]
fn a_single_quoted_attribute_the_payload_closes_is_live() {
    // What a backward walk reads as text: the `>` is inside the value, and the
    // payload's quote ends that value.
    let p = attr_payload();
    let html = format!("<img title='a > {p}'>");
    assert!(!inert(&html, &p));
    assert!(!is_in_safe_context_decoded(&html, &p));
}

#[test]
fn one_live_occurrence_outweighs_any_number_of_inert_ones() {
    let p = attr_payload();
    let html = format!("<p>{p}</p><p>{p}</p><img alt='{p}'>");
    assert!(!inert(&html, &p));
}

#[test]
fn an_unquoted_attribute_value_the_payload_leaves_is_live() {
    let p = format!("x onmouseover=alert(1) class={} ", marker());
    let html = format!("<p>{p}</p><input value={p}>");
    assert!(!inert(&html, &p));
}

#[test]
fn a_payload_that_opens_a_tag_is_live() {
    let p = format!("<svg onload=alert(1) class={}>", marker());
    let html = format!("<div>{p}</div>");
    assert!(!inert(&html, &p));
    // Inside a display-only element it is text again.
    let html = format!("<textarea>{p}</textarea>");
    assert!(inert(&html, &p));
}

#[test]
fn script_code_is_live() {
    let html = "<p>alert(1)</p><script>var x = alert(1);</script>";
    assert!(!inert(html, "alert(1)"));
    // A string handed to an evaluator is code.
    let html = r#"<p>alert(1)</p><script>setTimeout("alert(1)", 0);</script>"#;
    assert!(!inert(html, "alert(1)"));
    let html = r#"<p>alert(1)</p><script>eval("alert(1)");</script>"#;
    assert!(!inert(html, "alert(1)"));
}

#[test]
fn script_positions_that_are_not_plain_string_literals_keep_the_finding() {
    for script in [
        "// alert(1)",
        "var t = `alert(1)`;",
        "var x = 'alert(1)",             // does not parse
        "var x = {{name: 'alert(1)'}};", // does not parse
    ] {
        let html = format!("<p>alert(1)</p><script>{script}</script>");
        assert!(!inert(&html, "alert(1)"), "{script}");
    }
    // Not JavaScript to the browser: a data block a framework may render.
    let html = r#"<p>alert(1)</p><script type="text/template">var q = "alert(1)";</script>"#;
    assert!(!inert(html, "alert(1)"));
    // Never closed.
    let html = r#"<p>alert(1)</p><script>var q = "alert(1)";"#;
    assert!(!inert(html, "alert(1)"));
}

#[test]
fn a_payload_a_js_string_would_decode_is_live() {
    let p = format!(r"\x3csvg onload=alert(1) class={}\x3e", marker());
    let html = format!("<p>{p}</p><script>var s = \"{p}\"; document.title = s;</script>");
    assert!(!inert(&html, &p));
    // As text alone it is inert.
    let html = format!("<p>{p}</p>");
    assert!(inert(&html, &p));
}

#[test]
fn attributes_a_browser_acts_on_are_live() {
    for (attr, value) in [
        ("onclick", "alert(1)"),
        ("ONMOUSEOVER", "x = 'alert(1)'"),
        ("srcdoc", "alert(1)"),
        ("style", "x:alert(1)"),
        ("ng-click", "alert(1)"),
        ("v-on:click", "alert(1)"),
        ("@click", "alert(1)"),
        (":title", "alert(1)"),
        ("x-data", "alert(1)"),
        ("data-bind", "html: alert(1)"),
    ] {
        let html = format!("<p>alert(1)</p><a {attr}=\"{value}\">x</a>");
        assert!(!inert(&html, "alert(1)"), "{attr}");
    }
}

#[test]
fn an_encoded_echo_in_an_event_handler_is_live() {
    // Raw in text, entity-encoded in the handler: the browser decodes the
    // attribute before running it.
    let p = format!("'-alert(1)-' class={}", marker());
    let encoded = p.replace('\'', "&#39;");
    let html = format!("<p>{p}</p><a onclick=\"go('{encoded}')\">x</a>");
    assert!(!inert(&html, &p));
    // An encoding this gate does not decode is found through the anchor.
    let odd = p.replace('\'', "&apos").replace('(', "&lpar;");
    let html = format!("<p>{p}</p><a onclick=\"go('{odd}')\">x</a>");
    assert!(!inert(&html, &p));
    // The same encoded echo in a display attribute changes nothing.
    let html = format!("<p>{p}</p><input value=\"{encoded}\">");
    assert!(inert(&html, &p));
}

#[test]
fn url_positions_that_execute_or_are_read_back_are_live() {
    for tag in [
        // The echo is the whole URL.
        r#"<a href="alert(1)">x</a>"#,
        r#"<a href="  alert(1)">x</a>"#,
        r#"<form action=alert(1)>"#,
        // The value already runs as script.
        r#"<a href="javascript:void('alert(1)')">x</a>"#,
        r#"<iframe src="data:text/html,alert(1)"></iframe>"#,
        // The page can read these URLs back.
        r#"<script src="/boot.js?msg=alert(1)"></script>"#,
        r#"<iframe src="/frame?msg=alert(1)"></iframe>"#,
        // A refresh target navigates.
        r#"<meta http-equiv="refresh" content="0;url=/next?q=alert(1)">"#,
    ] {
        let html = format!("<p>alert(1)</p>{tag}");
        assert!(!inert(&html, "alert(1)"), "{tag}");
    }
}

#[test]
fn a_percent_encoded_echo_in_a_url_is_judged_by_position() {
    let p = attr_payload();
    let encoded = urlencoding::encode(&p).into_owned();
    let html = format!("<p>{p}</p><a href=\"/search?q={encoded}\">again</a>");
    assert!(inert(&html, &p));
    let html = format!("<p>{p}</p><a href=\"{encoded}\">again</a>");
    assert!(!inert(&html, &p));
    // A form submission spells the space as `+`.
    let form = encoded.replace("%20", "+");
    let html = format!("<p>{p}</p><a href=\"/search?q={form}&amp;page=2\">next</a>");
    assert!(inert(&html, &p));
    let html = format!("<p>{p}</p><a href=\"{form}\">next</a>");
    assert!(!inert(&html, &p));
}

#[test]
fn a_url_echo_in_an_encoding_the_gate_cannot_undo_is_live() {
    // `&lpar;` is not in the decoder's entity set, so the payload never
    // surfaces whole in the value and its position in the URL is unknown.
    let p = format!("'-alert(1)-' class={}", marker());
    let odd = p.replace('(', "&lpar;").replace(')', "&rpar;");
    let html = format!("<p>{p}</p><a href=\"{odd}\">x</a>");
    assert!(!inert(&html, &p));
}

#[test]
fn every_script_occurrence_has_to_be_string_data() {
    let html = r#"<p>alert(1)</p><script>var a = "alert(1)"; // alert(1)
</script>"#;
    assert!(!inert(html, "alert(1)"));
    let html = r#"<p>alert(1)</p><script>var a = "alert(1)"; var b = "alert(1)";</script>"#;
    assert!(inert(html, "alert(1)"));
}

#[test]
fn markup_structure_comments_and_css_are_live() {
    for html in [
        "<p>alert(1)</p><!-- alert(1) -->",
        "<p>alert(1)</p><style>.a{content:'alert(1)'}</style>",
        "<p>alert(1)</p><div alert(1)>x</div>",
        "<p>alert(1)</p><alert(1)>",
        "<p>alert(1)</p><iframe>alert(1)</iframe>",
    ] {
        assert!(!inert(html, "alert(1)"), "{html}");
    }
}

#[test]
fn everything_after_the_segmenter_stops_is_live() {
    let html = "<svg><script>var x = 1;</script></svg><p>alert(1)</p>";
    assert!(!inert(html, "alert(1)"));
    let html = "<p>alert(1)</p><svg><style>a{}</style></svg>";
    assert!(!inert(html, "alert(1)"));
    let html = "<p>alert(1)</p><select><xmp>x</xmp></select>";
    assert!(!inert(html, "alert(1)"));
}

#[test]
fn an_echo_in_a_tag_the_input_ends_inside_is_live() {
    let html = "<p>alert(1)</p><input value=\"alert(1)";
    assert!(!inert(html, "alert(1)"));
}

// ---- scope -----------------------------------------------------------------

#[test]
fn reflection_probes_are_never_suppressed() {
    let probe = crate::scanning::markers::bracketed_marker();
    let html = format!("<p>{probe}</p>");
    assert!(!inert(&html, probe));
    let html = format!("<p>{NUMERIC_PROBE_MARKER}</p>");
    assert!(!inert(&html, NUMERIC_PROBE_MARKER));
    assert!(!inert("<p>hello world</p>", "hello world"));
}

#[test]
fn schemes_templates_and_short_payloads_are_out_of_scope() {
    assert!(!inert("<p>javascript:alert(1)</p>", "javascript:alert(1)"));
    assert!(!inert("<p>{{alert(1)}}</p>", "{{alert(1)}}"));
    assert!(!inert("<p>${alert(1)}</p>", "${alert(1)}"));
    assert!(!inert("<p>alert()</p>", "alert()"));
}

#[test]
fn a_payload_that_is_not_in_the_body_is_not_inert() {
    assert!(!inert("<p>nothing here</p>", "alert(1)"));
    // Present only percent-encoded: `is_escaped_echo` owns that.
    assert!(!inert("<p>alert%281%29</p>", "alert(1)"));
}

#[test]
fn an_xml_document_is_out_of_scope() {
    let html = "<?xml version=\"1.0\"?><root><title>alert(1)</title></root>";
    assert!(!inert(html, "alert(1)"));
}

#[test]
fn a_javascript_body_that_runs_the_payload_is_live() {
    // No `<script>` block: a JSONP-style body is parsed as JavaScript.
    assert!(!inert("alert(1);cb({\"a\":1})", "alert(1)"));
    // A JSON body is data.
    assert!(inert("{\"q\":\"alert(1)\"}", "alert(1)"));
}

#[test]
fn too_many_occurrences_keep_the_finding() {
    let html = "<p>alert(1)</p>".repeat(MAX_PAYLOAD_OCCURRENCES + 1);
    assert!(!inert(&html, "alert(1)"));
    let html = "<p>alert(1)</p>".repeat(MAX_PAYLOAD_OCCURRENCES);
    assert!(inert(&html, "alert(1)"));
}

#[test]
fn decoded_variants_are_vetted_too() {
    // The payload was sent percent-encoded and the server decoded it.
    let p = attr_payload();
    let sent = urlencoding::encode(&p).into_owned();
    let html = format!("<div>{p}</div>");
    assert!(inert(&html, &sent));
    let html = format!("<img alt='{p}'>");
    assert!(!inert(&html, &sent));
}

// ---- helpers ---------------------------------------------------------------

#[test]
fn payload_anchor_prefers_the_scan_marker() {
    let p = attr_payload();
    assert_eq!(payload_anchor(&p), marker());
    assert_eq!(payload_anchor("alert(1)"), "alert");
    assert_eq!(payload_anchor("x=1;confirm`1`"), "confirm");
    assert_eq!(payload_anchor("'\"()"), "");
}

#[test]
fn attr_echo_reports_absence_without_an_echo() {
    let variants = vec!["alert(1)".to_string()];
    for (element, name, value) in [
        ("a", "onclick", "track('click')"),
        ("a", "href", "/home"),
        ("meta", "content", "0;url=/home"),
        ("input", "value", "something"),
    ] {
        assert_eq!(
            attr_echo(element, name, value, &variants, "alert", false),
            AttrEcho::Absent,
            "{name}"
        );
    }
}

#[test]
fn attr_echo_names_are_case_insensitive() {
    let variants = vec!["alert(1)".to_string()];
    assert_eq!(
        attr_echo("A", "HREF", "alert(1)", &variants, "alert", true),
        AttrEcho::Live
    );
    assert_eq!(
        attr_echo(
            "SCRIPT",
            "SRC",
            "/a.js?x=alert(1)",
            &variants,
            "alert",
            true
        ),
        AttrEcho::Live
    );
    assert_eq!(
        attr_echo(
            "META",
            "Content",
            "0; URL=/a?x=alert(1)",
            &variants,
            "alert",
            true
        ),
        AttrEcho::Live
    );
    assert_eq!(
        attr_echo("a", "xlink:href", "/a?x=alert(1)", &variants, "alert", true),
        AttrEcho::Inert
    );
}
