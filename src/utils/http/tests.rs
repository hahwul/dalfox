use super::*;
use crate::target_parser::parse_target;

#[test]
fn test_compose_cookie_header_empty() {
    let cookies: Vec<(String, String)> = vec![];
    assert!(compose_cookie_header(&cookies).is_none());
}

#[test]
fn test_compose_cookie_header_basic() {
    let cookies = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
    ];
    let s = compose_cookie_header(&cookies).unwrap();
    assert!(s == "a=1; b=2" || s == "b=2; a=1"); // order not guaranteed by this helper
}

#[test]
fn test_compose_cookie_header_excluding() {
    let cookies = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
    ];
    let s = compose_cookie_header_excluding(&cookies, Some("a")).unwrap();
    assert_eq!(s, "b=2");
    assert!(compose_cookie_header_excluding(&cookies, Some("a_non")).is_some());
}

#[test]
fn test_compose_cookie_header_excluding_to_none() {
    let cookies = vec![("only".to_string(), "1".to_string())];
    let s = compose_cookie_header_excluding(&cookies, Some("only"));
    assert!(s.is_none());
}

#[test]
fn test_has_header_case_insensitive() {
    let headers = vec![
        ("X-Test".to_string(), "v".to_string()),
        ("content-type".to_string(), "x".to_string()),
    ];
    assert!(has_header(&headers, "Content-Type"));
    assert!(has_header(&headers, "content-type"));
    assert!(!has_header(&headers, "missing"));
}

#[test]
fn test_parse_header_line_trims_and_splits_once() {
    let parsed = parse_header_line("X-Test: value:with:colons").expect("valid header");
    assert_eq!(parsed.0, "X-Test");
    assert_eq!(parsed.1, "value:with:colons");
}

#[test]
fn test_parse_header_line_invalid_cases() {
    assert!(parse_header_line("NoColon").is_none());
    assert!(parse_header_line(": value").is_none());
    assert!(parse_header_line("   : value").is_none());
}

#[test]
fn test_parse_headers_filters_invalid_entries() {
    let input = vec![
        "X-One: 1".to_string(),
        "BrokenHeader".to_string(),
        ": missing-name".to_string(),
        "X-Two: 2".to_string(),
    ];
    let parsed = parse_headers(&input);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0], ("X-One".to_string(), "1".to_string()));
    assert_eq!(parsed[1], ("X-Two".to_string(), "2".to_string()));
}

#[test]
fn test_content_type_primary_normalization() {
    assert_eq!(
        content_type_primary(" Text/HTML ; charset=UTF-8 "),
        Some("text/html".to_string())
    );
    assert_eq!(
        content_type_primary("application/xhtml+xml;charset=utf-8"),
        Some("application/xhtml+xml".to_string())
    );
}

#[test]
fn test_content_type_primary_invalid_inputs() {
    assert_eq!(content_type_primary(""), None);
    assert_eq!(content_type_primary("text"), None);
    assert_eq!(content_type_primary("/html"), None);
    assert_eq!(content_type_primary("text/"), None);
}

#[test]
fn test_is_htmlish_content_type_allow_list() {
    assert!(is_htmlish_content_type("text/html"));
    assert!(is_htmlish_content_type("application/xhtml+xml"));
    assert!(is_htmlish_content_type("application/xml; charset=utf-8"));
    assert!(is_htmlish_content_type("text/xml"));
    assert!(is_htmlish_content_type("application/rss+xml"));
    assert!(is_htmlish_content_type("application/atom+xml"));
}

#[test]
fn test_is_htmlish_content_type_deny_list() {
    assert!(!is_htmlish_content_type("application/json"));
    assert!(!is_htmlish_content_type("text/plain"));
    assert!(!is_htmlish_content_type("image/svg+xml"));
    assert!(!is_htmlish_content_type("invalid"));
}

#[test]
fn test_is_xss_scannable_content_type_allow_list() {
    assert!(is_xss_scannable_content_type("text/html"));
    assert!(is_xss_scannable_content_type("application/json"));
    assert!(is_xss_scannable_content_type("application/javascript"));
    assert!(is_xss_scannable_content_type(
        "text/javascript; charset=utf-8"
    ));
    assert!(is_xss_scannable_content_type("image/svg+xml"));
}

#[test]
fn test_is_xss_scannable_content_type_deny_list() {
    assert!(!is_xss_scannable_content_type("image/png"));
    assert!(!is_xss_scannable_content_type("application/octet-stream"));
    assert!(!is_xss_scannable_content_type("invalid"));
}

#[test]
fn test_is_xss_scannable_content_type_text_plain_allowed() {
    assert!(is_xss_scannable_content_type("text/plain"));
    assert!(is_xss_scannable_content_type("text/plain; charset=utf-8"));
}

#[test]
fn test_build_preflight_request_get_sets_range_and_headers() {
    let mut target = parse_target("https://example.com/path").unwrap();
    target.headers = vec![("X-Test".to_string(), "1".to_string())];
    target.user_agent = Some("Dalfox-Test-UA".to_string());
    target.cookies = vec![("sid".to_string(), "abc".to_string())];

    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_preflight_request(&client, &target, false, Some(128))
        .build()
        .expect("request should build");

    assert_eq!(req.method(), reqwest::Method::GET);
    assert_eq!(
        req.headers()
            .get("Range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "bytes=0-127"
    );
    assert_eq!(
        req.headers()
            .get("X-Test")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "1"
    );
    assert_eq!(
        req.headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "Dalfox-Test-UA"
    );
    assert!(
        req.headers().get("Cookie").is_some(),
        "cookies should be auto-attached"
    );
}

#[test]
fn test_build_preflight_request_head_ignores_range() {
    let target = parse_target("https://example.com/path").unwrap();
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_preflight_request(&client, &target, true, Some(128))
        .build()
        .expect("request should build");

    assert_eq!(req.method(), reqwest::Method::HEAD);
    assert!(
        req.headers().get("Range").is_none(),
        "HEAD preflight should not set Range header"
    );
}
