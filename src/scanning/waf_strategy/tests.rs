use super::*;

#[test]
fn owasp_crs_expansion_keeps_unquoted_handler_marker_parseable() {
    let marker = crate::scanning::markers::class_marker();
    let base = format!("<svg onload=alert(1) class={marker}>");
    let strategy = crate::waf::bypass::merge_strategies(&[&crate::waf::WafType::OwaspCrs]);
    let expanded = expand_waf_payloads(&[base], &strategy, None);

    let malformed = format!("<svg/onload=alert(1)/class={marker}>");
    assert!(
        !expanded.contains(&malformed),
        "the slash after an unquoted handler value must not be emitted"
    );

    let safe = format!("<svg/onload=alert(1) class={marker}>");
    assert!(expanded.contains(&safe));
    let response = format!("<html><body>{safe}</body></html>");
    assert!(
        crate::scanning::check_dom_verification::classify_dom_evidence(&safe, &response).is_some(),
        "the valid slash-separator variant should retain DOM evidence"
    );
}

#[test]
fn cloudflare_expansion_skips_comment_split_inside_js_identifier() {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    let base = "<script>alert(1)</script>".to_string();
    let strategy = crate::waf::bypass::merge_strategies(&[&crate::waf::WafType::Cloudflare]);
    let expanded = expand_waf_payloads(std::slice::from_ref(&base), &strategy, None);
    let invalid = "<script>al/**/ert(1)</script>";

    assert!(expanded.contains(&base));
    assert!(
        !expanded.iter().any(|payload| payload == invalid),
        "a comment inside an identifier must not be emitted as a bypass"
    );

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, "al/**/ert(1)", SourceType::default()).parse();
    assert!(
        !parsed.errors.is_empty(),
        "JavaScript comments separate identifiers instead of joining them"
    );
}
