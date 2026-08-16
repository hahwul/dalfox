use super::*;

#[test]
fn test_is_raw_http_request_true() {
    let raw = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(is_raw_http_request(raw));
}

#[test]
fn test_is_raw_http_request_false() {
    let not_raw = "https://example.com/path";
    assert!(!is_raw_http_request(not_raw));
}

#[test]
fn test_parse_raw_http_absolute_form() {
    let raw = "GET http://example.com/level1/frame HTTP/1.1\r\nUser-Agent: Dalfox\r\nCookie: sid=abc; a=b\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should parse absolute-form request");
    assert_eq!(t.method, "GET");
    assert_eq!(t.url.as_str(), "http://example.com/level1/frame");
    assert_eq!(t.user_agent.as_deref(), Some("Dalfox"));
    assert!(t.cookies.iter().any(|(k, v)| k == "sid" && v == "abc"));
    assert!(t.cookies.iter().any(|(k, v)| k == "a" && v == "b"));
}

#[test]
fn test_parse_raw_http_skips_empty_name_cookies() {
    // A `=value` (empty-name) segment in a raw-request Cookie header must
    // not produce an empty-name cookie pair; the well-formed pairs survive.
    // Mirrors har.rs::skips_empty_name_cookies_from_header so the twin
    // guards have symmetric coverage.
    let raw = "GET http://example.com/ HTTP/1.1\r\nCookie: a=1; =orphan; b=2\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should parse");
    assert_eq!(t.cookies.len(), 2);
    assert!(t.cookies.iter().any(|(k, v)| k == "a" && v == "1"));
    assert!(t.cookies.iter().any(|(k, v)| k == "b" && v == "2"));
    assert!(
        t.cookies.iter().all(|(k, _)| !k.is_empty()),
        "no empty-name cookie should be retained"
    );
}

#[test]
fn test_parse_raw_http_origin_form() {
    let raw = "GET /level1/frame HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should parse origin-form with Host");
    assert_eq!(t.url.as_str(), "http://vulnerable.com/level1/frame");
    assert_eq!(t.method, "GET");
}

#[test]
fn test_parse_raw_http_https_host_port() {
    let raw = "GET /p HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should infer https from :443");
    let u = &t.url;
    assert_eq!(u.scheme(), "https");
    assert_eq!(u.host_str(), Some("secure.example.com"));
    assert_eq!(u.port_or_known_default(), Some(443));
}

#[test]
fn test_parse_raw_http_missing_host_errors() {
    let raw = "GET /only-path HTTP/1.1\r\nUser-Agent: X\r\n\r\n";
    assert!(parse_raw_http_request(raw).is_err());
}

#[test]
fn test_parse_raw_http_with_body() {
    let raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2";
    let t = parse_raw_http_request(raw).expect("should parse with body");
    assert_eq!(t.method, "POST");
    assert_eq!(t.url.as_str(), "http://example.com/submit");
    assert_eq!(t.data.as_deref(), Some("a=1&b=2"));
}

#[test]
fn raw_http_body_preserves_crlf_line_endings() {
    // A multipart body's CRLFs are load-bearing: RFC 7578 parsers match
    // `\r\n--boundary`. Rebuilding the body from `lines()` joined with `\n`
    // turned every one of them into a bare LF, so a strict server saw zero
    // parts and the whole body-parameter scan silently tested nothing.
    //
    // The body's *final* terminator is a separate question — it is a file
    // artifact and is dropped (see
    // `raw_http_body_drops_exactly_one_trailing_newline`); the close
    // delimiter itself and every internal CRLF survive.
    let body = "--X\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--X--";
    let raw = format!(
        "POST /u HTTP/1.1\r\nHost: e.com\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n{body}\r\n"
    );
    let t = parse_raw_http_request(&raw).expect("should parse");
    assert_eq!(t.data.as_deref(), Some(body));
}

#[test]
fn raw_http_body_preserves_a_leading_blank_line() {
    // The old `lines()` fold started the accumulator empty, so a body that
    // legitimately begins with a blank line lost it.
    let raw = "POST /u HTTP/1.1\r\nHost: e.com\r\n\r\n\r\nreal body";
    let t = parse_raw_http_request(raw).expect("should parse");
    assert_eq!(t.data.as_deref(), Some("\r\nreal body"));
}

#[test]
fn raw_http_lf_only_request_still_finds_its_body() {
    let raw = "POST /u HTTP/1.1\nHost: e.com\n\na=1&b=2";
    let t = parse_raw_http_request(raw).expect("should parse");
    assert_eq!(t.data.as_deref(), Some("a=1&b=2"));
}

#[test]
fn raw_http_without_a_body_has_none() {
    let raw = "GET /u HTTP/1.1\r\nHost: e.com\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should parse");
    assert_eq!(t.data, None);
}

#[test]
fn raw_http_body_drops_exactly_one_trailing_newline() {
    // Every text editor terminates a file with a newline; keeping it made
    // the last body parameter's value `2\n`, which then rode along
    // percent-encoded on every request of the scan.
    let t = parse_raw_http_request("POST /u HTTP/1.1\r\nHost: e\r\n\r\na=1&b=2\r\n")
        .expect("should parse");
    assert_eq!(t.data.as_deref(), Some("a=1&b=2"));
    let lf =
        parse_raw_http_request("POST /u HTTP/1.1\nHost: e\n\na=1&b=2\n").expect("should parse");
    assert_eq!(lf.data.as_deref(), Some("a=1&b=2"));
    // Only ONE terminator goes: a body that really ends in a blank line
    // keeps the rest.
    let two = parse_raw_http_request("POST /u HTTP/1.1\r\nHost: e\r\n\r\na=1\r\n\r\n")
        .expect("should parse");
    assert_eq!(two.data.as_deref(), Some("a=1\r\n"));
}

#[test]
fn raw_http_body_survives_a_whitespace_bearing_separator_line() {
    // The header loop ends on the first line whose `trim_end()` is empty,
    // so a separator carrying a stray space ends the headers there.
    // Scanning for a literal `\r\n\r\n` missed it and reported NO body,
    // silently dropping every body parameter from the scan.
    let t = parse_raw_http_request("POST /u HTTP/1.1\r\nHost: e\r\n \r\na=1&b=2")
        .expect("should parse");
    assert_eq!(t.data.as_deref(), Some("a=1&b=2"));
}

#[test]
fn raw_http_multipart_close_delimiter_is_preserved() {
    // The trailing-newline strip must not eat a multipart body's own CRLF
    // structure; only the final terminator goes.
    let body = "--X\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--X--";
    let raw = format!(
        "POST /u HTTP/1.1\r\nHost: e\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n{body}\r\n"
    );
    let t = parse_raw_http_request(&raw).expect("should parse");
    assert_eq!(t.data.as_deref(), Some(body));
}

#[test]
fn raw_http_strips_stale_framing_and_accept_encoding_headers() {
    // A stale Content-Length / Transfer-Encoding must NOT be forwarded:
    // reqwest recomputes them and a stale value truncates the
    // payload-injected body (body-param XSS silently missed). Accept-Encoding
    // must be dropped so reqwest's transparent decompression stays on.
    let raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2";
    let t = parse_raw_http_request(raw).expect("should parse");
    for stripped in [
        "content-length",
        "transfer-encoding",
        "accept-encoding",
        "connection",
    ] {
        assert!(
            !t.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(stripped)),
            "{stripped} must be stripped, got {:?}",
            t.headers
        );
    }
    // A normal header survives verbatim.
    assert!(
        t.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    );
}

#[test]
fn raw_http_does_not_retain_original_cookie_header() {
    // The Cookie header is split into `cookies` only; keeping it in `headers`
    // too made per-cookie probing emit both the original and the mutated
    // Cookie (reqwest appends), so the payload could fail to land.
    let raw = "GET /p HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc; a=b\r\n\r\n";
    let t = parse_raw_http_request(raw).expect("should parse");
    assert!(
        !t.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cookie")),
        "original Cookie header must not be retained in headers, got {:?}",
        t.headers
    );
    assert!(t.cookies.iter().any(|(k, v)| k == "sid" && v == "abc"));
    assert!(t.cookies.iter().any(|(k, v)| k == "a" && v == "b"));
}
