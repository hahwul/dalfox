use super::*;

const SAMPLE_HAR: &str = r#"{
      "log": {
        "version": "1.2",
        "creator": { "name": "dalfox-test", "version": "1.0" },
        "entries": [
          {
            "request": {
              "method": "GET",
              "url": "https://example.com/search?q=hello",
              "httpVersion": "HTTP/2",
              "headers": [
                { "name": ":authority", "value": "example.com" },
                { "name": "Host", "value": "example.com" },
                { "name": "User-Agent", "value": "Mozilla/5.0 (HAR)" },
                { "name": "Accept", "value": "text/html" },
                { "name": "Accept-Encoding", "value": "gzip, deflate, br" },
                { "name": "Cookie", "value": "sid=abc; theme=dark" },
                { "name": "Connection", "value": "keep-alive" }
              ],
              "cookies": [
                { "name": "sid", "value": "abc" },
                { "name": "theme", "value": "dark" }
              ],
              "queryString": [ { "name": "q", "value": "hello" } ]
            }
          },
          {
            "request": {
              "method": "POST",
              "url": "https://example.com/comment",
              "headers": [
                { "name": "Content-Type", "value": "application/x-www-form-urlencoded" },
                { "name": "Content-Length", "value": "13" }
              ],
              "cookies": [],
              "postData": {
                "mimeType": "application/x-www-form-urlencoded",
                "text": "body=hi&name=x"
              }
            }
          }
        ]
      }
    }"#;

#[test]
fn detects_har_content() {
    assert!(is_har_content(SAMPLE_HAR));
    assert!(is_har_content("\u{feff}  {\"log\":{\"entries\":[]}}"));
    assert!(!is_har_content("https://example.com/?q=1"));
    assert!(!is_har_content(
        "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ));
    // JSON but not a HAR shape.
    assert!(!is_har_content("{\"hello\":\"world\"}"));
}

#[test]
fn parses_get_entry_url_method_and_query() {
    let targets = parse_har(SAMPLE_HAR).expect("sample HAR should parse");
    assert_eq!(targets.len(), 2);
    let get = &targets[0];
    assert_eq!(get.method, "GET");
    assert_eq!(get.url.as_str(), "https://example.com/search?q=hello");
}

#[test]
fn lifts_user_agent_and_drops_managed_headers() {
    let targets = parse_har(SAMPLE_HAR).unwrap();
    let get = &targets[0];
    assert_eq!(get.user_agent.as_deref(), Some("Mozilla/5.0 (HAR)"));
    // Host, Accept-Encoding, Connection, the :authority pseudo-header, the
    // Cookie header, and User-Agent are all stripped from `headers`.
    for stripped in [
        "host",
        "accept-encoding",
        "connection",
        ":authority",
        "cookie",
        "user-agent",
    ] {
        assert!(
            !get.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(stripped)),
            "header {stripped} should have been stripped, got {:?}",
            get.headers
        );
    }
    // A normal header is preserved verbatim.
    assert!(
        get.headers
            .iter()
            .any(|(k, v)| k == "Accept" && v == "text/html")
    );
}

#[test]
fn splits_cookie_header_into_pairs() {
    let targets = parse_har(SAMPLE_HAR).unwrap();
    let get = &targets[0];
    assert!(get.cookies.iter().any(|(k, v)| k == "sid" && v == "abc"));
    assert!(get.cookies.iter().any(|(k, v)| k == "theme" && v == "dark"));
}

#[test]
fn captures_post_body_and_method() {
    let targets = parse_har(SAMPLE_HAR).unwrap();
    let post = &targets[1];
    assert_eq!(post.method, "POST");
    assert_eq!(post.url.as_str(), "https://example.com/comment");
    assert_eq!(post.data.as_deref(), Some("body=hi&name=x"));
    // Content-Length is recomputed by reqwest, never forwarded.
    assert!(
        !post
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    );
    // Content-Type is preserved so the body is interpreted correctly.
    assert!(
        post.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    );
}

#[test]
fn falls_back_to_cookies_array_without_cookie_header() {
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "cookies":[{"name":"a","value":"1"},{"name":"b","value":"2"}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 2);
    assert!(targets[0].cookies.iter().any(|(k, v)| k == "a" && v == "1"));
}

#[test]
fn falls_back_to_cookies_array_when_cookie_header_is_empty() {
    // A redacting/normalising exporter can emit an empty `Cookie` header
    // alongside a populated structured `cookies[]`. Keying the fallback on
    // the header's mere presence discarded the real cookies and scanned the
    // capture logged-out; the fallback must fire whenever the header path
    // produced no usable cookie.
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "headers":[{"name":"Cookie","value":""}],
            "cookies":[{"name":"session","value":"abc"}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 1);
    assert_eq!(
        targets[0].cookies[0],
        ("session".to_string(), "abc".to_string())
    );
}

#[test]
fn cookie_header_wins_over_structured_array_no_double_count() {
    // When the Cookie header yields cookies, the structured array must not be
    // merged on top (no duplicates).
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "headers":[{"name":"Cookie","value":"sid=fromheader"}],
            "cookies":[{"name":"sid","value":"fromarray"},{"name":"extra","value":"x"}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 1);
    assert_eq!(
        targets[0].cookies[0],
        ("sid".to_string(), "fromheader".to_string())
    );
}

#[test]
fn trims_whitespace_in_cookies_array_values() {
    // Values from the structured `cookies` fallback must be trimmed the same
    // way the Cookie-header path trims them, so a HAR exporter that pads the
    // value doesn't leak whitespace into the request.
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "cookies":[{"name":" session ","value":" abc123 "}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 1);
    assert_eq!(
        targets[0].cookies[0],
        ("session".to_string(), "abc123".to_string())
    );
}

#[test]
fn skips_empty_name_cookies_from_header() {
    // A Cookie header with a `=value` (empty-name) segment must not produce
    // an empty-name cookie pair (which would re-serialize as a malformed
    // `=value` Cookie segment); the well-formed pairs around it survive.
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "headers":[{"name":"Cookie","value":"a=1; =orphan; b=2"}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 2);
    assert!(targets[0].cookies.iter().any(|(k, v)| k == "a" && v == "1"));
    assert!(targets[0].cookies.iter().any(|(k, v)| k == "b" && v == "2"));
    assert!(
        targets[0].cookies.iter().all(|(k, _)| !k.is_empty()),
        "no empty-name cookie should be retained"
    );
}

#[test]
fn skips_empty_name_cookies_from_structured_array() {
    let har = r#"{"log":{"entries":[{"request":{
            "method":"GET","url":"https://example.com/",
            "cookies":[{"name":"","value":"orphan"},{"name":"keep","value":"1"}]
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].cookies.len(), 1);
    assert_eq!(targets[0].cookies[0], ("keep".to_string(), "1".to_string()));
}

#[test]
fn synthesizes_body_from_params_when_text_absent() {
    let har = r#"{"log":{"entries":[{"request":{
            "method":"POST","url":"https://example.com/f",
            "postData":{"mimeType":"application/x-www-form-urlencoded",
              "params":[{"name":"a","value":"1"},{"name":"b","value":"2"}]}
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].data.as_deref(), Some("a=1&b=2"));
}

#[test]
fn params_body_is_form_url_encoded() {
    // Reconstructed params bodies must be properly form-encoded so special
    // characters don't change the request shape, and a valueless param
    // becomes `name=` (not a bare `name`).
    let har = r#"{"log":{"entries":[{"request":{
            "method":"POST","url":"https://example.com/f",
            "postData":{"params":[
                {"name":"q","value":"a b&c=d"},
                {"name":"flag"},
                {"name":"uni","value":"café"}
            ]}
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(
        targets[0].data.as_deref(),
        Some("q=a+b%26c%3Dd&flag=&uni=caf%C3%A9")
    );
}

#[test]
fn skips_non_http_entries_but_keeps_http_ones() {
    let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"data:text/html,<script>1</script>"}},
            {"request":{"method":"GET","url":"wss://example.com/socket"}},
            {"request":{"method":"GET","url":"https://example.com/ok?x=1"}}
        ]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.as_str(), "https://example.com/ok?x=1");
}

#[test]
fn errors_when_no_http_requests() {
    let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"data:text/plain,hi"}}
        ]}}"#;
    let err = parse_har(har).unwrap_err().to_string();
    assert!(err.contains("none used an http/https"), "got: {err}");
}

#[test]
fn errors_on_empty_entries() {
    let err = parse_har(r#"{"log":{"entries":[]}}"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no requests"), "got: {err}");
}

#[test]
fn errors_on_non_har_json() {
    assert!(parse_har(r#"{"not":"har"}"#).is_err());
    assert!(parse_har("not json at all").is_err());
}

#[test]
fn uppercases_method() {
    let har = r#"{"log":{"entries":[{"request":{
            "method":"post","url":"https://example.com/"
        }}]}}"#;
    let targets = parse_har(har).unwrap();
    assert_eq!(targets[0].method, "POST");
}
