use super::*;

/// Every point's byte range must exactly cover its reported `value`.
fn assert_ranges_match_values(data: &str, points: &[XmlInjectionPoint]) {
    for p in points {
        assert_eq!(
            &data[p.start..p.end],
            p.value,
            "range [{}, {}) does not cover value {:?} in {:?}",
            p.start,
            p.end,
            p.value,
            data
        );
    }
}

/// Splicing a payload at a point preserves every other byte of the document.
fn splice(data: &str, p: &XmlInjectionPoint, payload: &str) -> String {
    format!("{}{}{}", &data[..p.start], payload, &data[p.end..])
}

#[test]
fn finds_text_node() {
    let xml = "<note><to>Bob</to></note>";
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    let to = pts.iter().find(|p| p.name == "to").expect("to text node");
    assert_eq!(to.value, "Bob");
    assert_eq!(
        splice(xml, to, "<svg onload=alert(1)>"),
        "<note><to><svg onload=alert(1)></to></note>"
    );
}

#[test]
fn finds_attribute_value() {
    let xml = r#"<item id="42">x</item>"#;
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    let id = pts.iter().find(|p| p.name == "item@id").expect("id attr");
    assert_eq!(id.value, "42");
    assert_eq!(
        splice(xml, id, "\"><svg>"),
        r#"<item id=""><svg>">x</item>"#
    );
}

#[test]
fn single_quoted_attribute() {
    let xml = "<a href='http://x'>t</a>";
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    assert!(pts.iter().any(|p| p.name == "a@href" && p.value == "http://x"));
}

#[test]
fn nested_elements_and_multiple_leaves() {
    let xml = "<r><a>1</a><b><c>2</c></b></r>";
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    let names: Vec<&str> = pts.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"c"));
    // The `<r>`/`<b>` wrappers hold only child elements (whitespace-free),
    // so they contribute no text leaves.
    assert!(!names.contains(&"r"));
    assert!(!names.contains(&"b"));
}

#[test]
fn preserves_indentation_whitespace() {
    let xml = "<r>\n  <a>hi</a>\n</r>";
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    // Only "hi" is a text node; the newlines/indentation between elements are
    // whitespace-only runs and are skipped.
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].value, "hi");
    assert_eq!(splice(xml, &pts[0], "P"), "<r>\n  <a>P</a>\n</r>");
}

#[test]
fn self_closing_tag_attribute() {
    let xml = r#"<root><img src="x"/><p>hey</p></root>"#;
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    assert!(pts.iter().any(|p| p.name == "img@src" && p.value == "x"));
    assert!(pts.iter().any(|p| p.name == "p" && p.value == "hey"));
}

#[test]
fn gt_inside_attribute_value_does_not_end_tag() {
    let xml = r#"<a title="x>y">body</a>"#;
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    assert!(pts.iter().any(|p| p.name == "a@title" && p.value == "x>y"));
    assert!(pts.iter().any(|p| p.name == "a" && p.value == "body"));
}

#[test]
fn skips_comment_cdata_pi_doctype() {
    let xml = concat!(
        "<?xml version=\"1.0\"?>\n",
        "<!DOCTYPE note>\n",
        "<note><!-- hi -->",
        "<data><![CDATA[<raw>not injected</raw>]]></data>",
        "<to>Bob</to></note>"
    );
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    // Only the real <to> text node is injectable — comment/CDATA/PI/DOCTYPE
    // content is skipped.
    assert_eq!(pts.len(), 1, "got {pts:?}");
    assert_eq!(pts[0].name, "to");
    assert_eq!(pts[0].value, "Bob");
}

#[test]
fn soap_envelope_leaf() {
    let xml = concat!(
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">",
        "<soap:Body><m:echo><m:text>hello</m:text></m:echo></soap:Body>",
        "</soap:Envelope>"
    );
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts);
    // The xmlns attribute value and the <m:text> leaf are both injectable.
    assert!(pts.iter().any(|p| p.value == "hello"));
}

#[test]
fn duplicate_names_are_disambiguated() {
    let xml = "<r><i>a</i><i>b</i><i>c</i></r>";
    let pts = xml_injection_points(xml);
    let names: Vec<&str> = pts.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["i", "i_2", "i_3"]);
}

// --- FP / fallback safety ---

#[test]
fn non_xml_bodies_yield_nothing() {
    assert!(xml_injection_points("q=1&b=2").is_empty());
    assert!(xml_injection_points(r#"{"a":"b"}"#).is_empty());
    assert!(xml_injection_points("plain text").is_empty());
    assert!(xml_injection_points("").is_empty());
}

#[test]
fn malformed_xml_is_safe() {
    // Unterminated tag / attribute must not panic and must not fabricate a
    // point with a bogus range.
    for bad in [
        "<a href=\"unterminated",
        "<<>>",
        "<a><b>",
        "<a b=",
        "<",
        "< notatag",
    ] {
        let pts = xml_injection_points(bad);
        assert_ranges_match_values(bad, &pts); // any point that IS produced is valid
    }
}

#[test]
fn empty_text_nodes_are_not_points() {
    let xml = "<a></a><b>   </b>";
    let pts = xml_injection_points(xml);
    assert!(pts.is_empty(), "whitespace-only/empty text nodes: {pts:?}");
}

#[test]
fn point_count_is_bounded() {
    // A pathological wide document can't fan out past the cap.
    let mut xml = String::from("<r>");
    for _ in 0..500 {
        xml.push_str("<i>x</i>");
    }
    xml.push_str("</r>");
    let pts = xml_injection_points(&xml);
    assert!(pts.len() <= MAX_POINTS, "exceeded cap: {}", pts.len());
}

#[test]
fn multibyte_utf8_text_and_attribute_ranges_are_char_aligned() {
    // Byte-range indexing must land on char boundaries even with multi-byte
    // content (é = 2 bytes, 世 = 3 bytes, 😀 = 4 bytes) — otherwise slicing panics.
    let xml = "<r><t title=\"héllo\">wörld😀世</t></r>";
    let pts = xml_injection_points(xml);
    assert_ranges_match_values(xml, &pts); // slices here; panics if misaligned
    assert!(pts.iter().any(|p| p.name == "t@title" && p.value == "héllo"));
    assert!(pts.iter().any(|p| p.name == "t" && p.value == "wörld😀世"));
    let t = pts.iter().find(|p| p.name == "t").unwrap();
    assert_eq!(splice(xml, t, "X"), "<r><t title=\"héllo\">X</t></r>");
}
