use super::*;

/// Whether some element in `html` carries the scan's class **or** id marker as a
/// real attribute — matching the marker half of
/// `check_dom_verification::is_marker_element` (`class` split on ASCII
/// whitespace, `id` trimmed, both case-insensitive) and parsing with the same
/// `scraper`/html5ever engine the verifier uses.
///
/// This is the *necessary prerequisite* for a `[V]` promotion, not the whole
/// gate: the verifier additionally requires either a surviving on*/script sink
/// on that element (`element_carries_surviving_sink`, issue #1118) or a
/// presence-only structural vector (base-href / object / iframe-`javascript:`).
/// Both of those need the marker to first exist as a real attribute — exactly
/// what the three bugs below break — so this is the property to lock in here.
/// The sink-co-survival half is exercised separately (see the synthesis
/// handler-parse tests); it is deliberately *not* asserted here because a
/// structural vector such as `<iframe src=javascript:… class=…>` carries no
/// on*/script sink yet is a legitimate finding.
fn marker_survives_as_attribute(html: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    let frag = crate::utils::html::parse_fragment_bounded(html);
    let sel = scraper::Selector::parse("*").expect("valid universal selector");
    frag.select(&sel).any(|el| {
        let v = el.value();
        let class_hit = v.attr("class").is_some_and(|c| {
            c.split_ascii_whitespace()
                .any(|t| t.eq_ignore_ascii_case(class_marker))
        });
        let id_hit = v
            .attr("id")
            .is_some_and(|i| i.trim().eq_ignore_ascii_case(id_marker));
        class_hit || id_hit
    })
}

/// Regression guard for three parser-level payload defects that let a
/// marker-carrying payload reflect but never DOM-verify:
///   * a JS primitive whose `>` (e.g. an arrow function's `=>`) closes the
///     unquoted event-handler attribute early, spilling the marker into text;
///   * a fully `/`-separated tag (`<svg/onload=X/class=Y>`) folding the trailing
///     `/class=Y` into the unquoted handler value so no `class` attribute forms;
///   * a non-whitespace "separator" (a vertical tab U+000B) that merges the
///     whole tag into one bogus name with no attributes.
///
/// All three land the marker somewhere other than a real `class`/`id`
/// attribute (as text, or folded into another attribute's value), so it can
/// never match the verifier's marker selector. Every marker-carrying catalog
/// entry must, in at least one of the contexts it is dropped into (HTML text,
/// or a single-/double-quoted attribute value), parse to an element whose
/// marker is a genuine `class`/`id` attribute. (Whether that element also
/// carries an executing sink is a separate gate — see the helper doc.)
#[test]
fn every_dynamic_html_marker_payload_keeps_a_real_marker_attribute() {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    for p in get_dynamic_xss_html_payloads() {
        if !(p.contains(class_marker) || p.contains(id_marker)) {
            continue; // marker-less shapes are [R]-only by design.
        }
        let contexts = [
            format!("<div>{p}</div>"),        // HTML text / body injection
            format!("<input value='{p}'>"),   // single-quoted attribute value
            format!("<input value=\"{p}\">"), // double-quoted attribute value
        ];
        assert!(
            contexts.iter().any(|c| marker_survives_as_attribute(c)),
            "payload carries a marker but it never parses as a real class/id \
             attribute in any injection context (cannot DOM-verify): {p:?}"
        );
    }
}

#[test]
fn test_get_dynamic_xss_html_payloads_non_empty() {
    let payloads = get_dynamic_xss_html_payloads();
    assert!(!payloads.is_empty());
}

#[test]
fn test_get_dynamic_xss_html_payloads_contains_markers_and_js() {
    let payloads = get_dynamic_xss_html_payloads();
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    let idm = crate::scanning::markers::id_marker().to_lowercase();
    let has_class = payloads
        .iter()
        .any(|p| p.to_lowercase().contains(&format!("class={}", cls)));
    let has_id = payloads
        .iter()
        .any(|p| p.to_lowercase().contains(&format!("id={}", idm)));
    assert!(has_class || has_id, "should contain class/id marker");
    let has_alert = payloads
        .iter()
        .any(|p| p.to_lowercase().contains("alert(1)"));
    assert!(has_alert, "should include at least one alert(1) variant");
}

#[test]
fn test_attribute_payloads_from_event_module() {
    let attrs = crate::payload::get_dynamic_xss_attribute_payloads();
    assert!(!attrs.is_empty(), "attribute payloads should not be empty");
    assert!(attrs.iter().any(|p| p.starts_with("onerror=")));
    assert!(attrs.iter().any(|p| p.starts_with("onload=")));
    assert!(
        attrs.iter().any(|p| p.contains("alert(1)")),
        "should include alert(1) primitive"
    );
}

#[test]
fn test_get_mxss_payloads_non_empty() {
    let payloads = get_mxss_payloads();
    assert!(!payloads.is_empty(), "mXSS payloads should not be empty");
}

#[test]
fn test_get_mxss_payloads_contains_svg_foreignobject() {
    let payloads = get_mxss_payloads();
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("foreignobject") || p.contains("foreignObject")),
        "should contain SVG foreignObject payloads"
    );
}

#[test]
fn test_get_mxss_payloads_contains_math_mtext() {
    let payloads = get_mxss_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("mtext")),
        "should contain math/mtext payloads"
    );
}

#[test]
fn test_get_mxss_payloads_contains_markers() {
    let payloads = get_mxss_payloads();
    let cls = crate::scanning::markers::class_marker();
    let idm = crate::scanning::markers::id_marker();
    let has_marker = payloads.iter().any(|p| p.contains(cls) || p.contains(idm));
    assert!(has_marker, "mXSS payloads should contain class/id markers");
}

#[test]
fn test_get_protocol_injection_payloads_non_empty() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        !payloads.is_empty(),
        "protocol injection payloads should not be empty"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_javascript_protocol() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("javascript:")),
        "should contain javascript: protocol payloads"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_case_variations() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("Javascript:")),
        "should contain capitalized javascript: variant"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("jAvAsCrIpT:")),
        "should contain mixed case javascript: variant"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_tab_bypass() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("java\tscript:")),
        "should contain tab-inserted javascript: variant"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_data_protocol() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("data:text/html,")),
        "should contain data: text/html payloads"
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("data:text/html;base64,")),
        "should contain data: base64 payloads"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_alert() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("alert(1)")),
        "should include at least one alert(1) variant"
    );
}

#[test]
fn test_blind_template_placeholder_and_replacement() {
    let tpl = crate::payload::XSS_BLIND_PAYLOADS
        .first()
        .copied()
        .unwrap_or("\"'><script src={}></script>");
    assert!(
        tpl.contains("{}"),
        "blind template should include '{{}}' placeholder"
    );
    let replaced = tpl.replace("{}", "https://callback.example/x");
    assert!(
        replaced.contains("https://callback.example/x"),
        "replaced template should include callback URL"
    );
}
