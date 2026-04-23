/*!
HTTP request builder helpers to centralize consistent header, User-Agent, and Cookie handling.

Rationale:
- Several modules manually construct reqwest RequestBuilder and attach headers, cookies, and body.
  Centralizing this logic avoids subtle inconsistencies (e.g., duplicate Cookie headers, UA precedence).
- These helpers aim to be minimal and non-invasive. Callers that need special handling (like probing a
  single cookie mutation) can use the cookie override or exclusion helpers.

Notes:
- If target.headers already contains a Cookie header (case-insensitive), we do NOT auto-attach cookies.
- If a custom cookie header is provided to build_request_with_cookie, it takes precedence over auto-attach.
- If both a header "User-Agent" is present and target.user_agent is Some, target.user_agent overwrites it.

Usage examples:
  let rb = http::build_request(&client, &target, Method::GET, target.url.clone(), None);

  // With cookie override (e.g., probing a specific cookie param)
  let cookie = http::compose_cookie_header_excluding(&target.cookies, Some("session"))
      .map(|s| format!("{}; session=dalfox", s))
      .or_else(|| Some("session=dalfox".to_string()));
  let rb = http::build_request_with_cookie(&client, &target, Method::GET, url, None, cookie);

*/

use reqwest::{Client, Method, RequestBuilder};
use url::Url;

use crate::target_parser::Target;

/// Compose a single Cookie header string from pairs.
/// Returns None if no cookies are provided.
pub fn compose_cookie_header(cookies: &[(String, String)]) -> Option<String> {
    compose_cookie_header_excluding(cookies, None)
}

/// Compose a Cookie header excluding a specific cookie name (case-sensitive match on name).
/// Returns None if the resulting set is empty.
pub fn compose_cookie_header_excluding(
    cookies: &[(String, String)],
    exclude_name: Option<&str>,
) -> Option<String> {
    if cookies.is_empty() {
        return None;
    }

    // Estimate capacity to avoid reallocations
    let estimated_len = cookies
        .iter()
        .map(|(k, v)| k.len() + v.len() + 2)
        .sum::<usize>();
    let mut s = String::with_capacity(estimated_len);

    let mut first = true;
    for (k, v) in cookies {
        if let Some(name) = exclude_name
            && k == name
        {
            continue;
        }

        if !first {
            s.push_str("; ");
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        first = false;
    }

    if s.is_empty() { None } else { Some(s) }
}

/// Case-insensitive check if a header exists in a (name, value) vector.
#[inline]
pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Apply provided headers (verbatim), then apply User-Agent if present (overrides any existing).
/// If `cookie_header` is Some, attach it. Otherwise, if no Cookie header exists in headers,
/// auto-attach from target.cookies (when non-empty).
pub fn apply_headers_ua_cookies(
    mut rb: RequestBuilder,
    target: &Target,
    cookie_header: Option<String>,
) -> RequestBuilder {
    // Apply user provided headers first
    for (k, v) in &target.headers {
        rb = rb.header(k, v);
    }

    // Apply UA (override any existing UA header)
    if let Some(ua) = &target.user_agent
        && !ua.is_empty()
    {
        rb = rb.header("User-Agent", ua);
    }

    // Cookie precedence:
    // 1) explicit cookie_header (override)
    // 2) if no explicit, but target.headers already had Cookie => honor it (do nothing)
    // 3) otherwise auto-attach the cookie header composed from target.cookies
    if let Some(ch) = cookie_header
        && !ch.is_empty()
    {
        rb = rb.header("Cookie", ch);
        return rb;
    }
    if !has_header(&target.headers, "Cookie")
        && let Some(ch) = compose_cookie_header(&target.cookies)
        && !ch.is_empty()
    {
        rb = rb.header("Cookie", ch);
    }

    rb
}

/// Build a RequestBuilder from the given client, maintaining consistent header/UA/Cookie application.
/// If `body` is Some, attach it as the request body.
/// Auto-attaches cookies (unless a Cookie header is already present in target.headers).
pub fn build_request(
    client: &Client,
    target: &Target,
    method: Method,
    url: Url,
    body: Option<String>,
) -> RequestBuilder {
    let rb = client.request(method, url);
    let rb = apply_headers_ua_cookies(rb, target, None);
    if let Some(b) = body { rb.body(b) } else { rb }
}

/// Build a RequestBuilder with an explicit Cookie header override.
/// If `cookie_header` is Some(string), it will be used regardless of target.headers/target.cookies.
/// If None, behavior is identical to `build_request`.
pub fn build_request_with_cookie(
    client: &Client,
    target: &Target,
    method: Method,
    url: Url,
    body: Option<String>,
    cookie_header: Option<String>,
) -> RequestBuilder {
    let rb = client.request(method, url);
    let rb = apply_headers_ua_cookies(rb, target, cookie_header);
    if let Some(b) = body { rb.body(b) } else { rb }
}

/// Apply arbitrary header overrides on top of an existing RequestBuilder (late binding).
/// Provided `overrides` are appended after target headers and UA, so they take precedence.
pub fn apply_header_overrides(
    mut rb: RequestBuilder,
    overrides: &[(String, String)],
) -> RequestBuilder {
    for (k, v) in overrides {
        rb = rb.header(k, v);
    }
    rb
}

// Header parsing: splitn(2, ':') with both sides trim
pub fn parse_header_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.splitn(2, ':');
    let name = parts.next()?.trim();
    let value = parts.next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

/// Parse a list of raw header lines into (name, value) pairs.
/// Ignores lines without ":" or with empty header names.
pub fn parse_headers(lines: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for l in lines {
        if let Some((k, v)) = parse_header_line(l) {
            out.push((k, v));
        }
    }
    out
}

/// Extract primary type/subtype (lowercased) from a Content-Type header.
/// Returns None for invalid formats.
#[inline]
pub fn content_type_primary(ct: &str) -> Option<String> {
    if ct.trim().is_empty() {
        return None;
    }
    let primary = ct.split(';').next()?.trim().to_ascii_lowercase();
    let mut parts = primary.splitn(2, '/');
    let typ = parts.next().unwrap_or("");
    let sub = parts.next().unwrap_or("");
    if typ.is_empty() || sub.is_empty() {
        return None;
    }
    Some(primary)
}

/// Allow-list check for HTML-ish content types.
/// Accepts:
/// - text/html
/// - application/xhtml+xml
/// - text/xml, application/xml
/// - application/rss+xml, application/atom+xml
#[inline]
pub fn is_htmlish_content_type(ct: &str) -> bool {
    let Some(primary) = content_type_primary(ct) else {
        return false;
    };
    if primary == "text/html" {
        return true;
    }
    matches!(
        primary.as_str(),
        "application/xhtml+xml"
            | "text/xml"
            | "application/xml"
            | "application/rss+xml"
            | "application/atom+xml"
    )
}

/// Allow-list check for content types that are still worth scanning for XSS,
/// even when they are not directly HTML documents.
///
/// This is intentionally broader than `is_htmlish_content_type` because
/// browser-executable or browser-consumed responses such as JSONP, raw JSON
/// fragments, and SVG documents can still surface XSS gadgets or reflective
/// payloads that Dalfox should analyze during preflight.
pub fn is_xss_scannable_content_type(ct: &str) -> bool {
    if is_htmlish_content_type(ct) {
        return true;
    }

    let Some(primary) = content_type_primary(ct) else {
        return false;
    };

    matches!(
        primary.as_str(),
        "application/json"
            | "text/json"
            | "application/javascript"
            | "text/javascript"
            | "application/ecmascript"
            | "text/ecmascript"
            | "application/x-javascript"
            | "image/svg+xml"
            // text/plain may render as HTML when X-Content-Type-Options is absent
            // and the response contains HTML-like content (content-type sniffing).
            | "text/plain"
    )
}

/// Build a preflight request for content-type detection.
/// - If `prefer_head` is true, uses HEAD; otherwise GET.
/// - When using GET and `range_bytes` is Some(n), adds `Range: bytes=0-(n-1)`
///   to minimize transfer size while still allowing meta tag parsing if needed.
pub fn build_preflight_request(
    client: &Client,
    target: &Target,
    prefer_head: bool,
    range_bytes: Option<usize>,
) -> RequestBuilder {
    let method = if prefer_head {
        Method::HEAD
    } else {
        Method::GET
    };
    let mut rb = client.request(method.clone(), target.url.clone());
    // Reuse the same consistent header/UA/Cookie application
    rb = apply_headers_ua_cookies(rb, target, None);

    if method == Method::GET
        && let Some(n) = range_bytes
        && n > 0
    {
        // bytes are inclusive
        let end = n.saturating_sub(1);
        rb = rb.header("Range", format!("bytes=0-{}", end));
    }

    rb
}

/// Send a request with automatic retry on rate-limiting (HTTP 429) responses.
///
/// Respects the `Retry-After` header if present (capped at `max_retry_delay_ms`).
/// Falls back to exponential backoff: 1s, 2s, 4s.
/// Returns the response after successful send or after exhausting retries.
pub async fn send_with_retry(
    request_builder: RequestBuilder,
    max_retries: u32,
    max_retry_delay_ms: u64,
) -> Result<reqwest::Response, reqwest::Error> {
    // reqwest::RequestBuilder is not Clone, so we must try_clone before sending.
    // If cloning fails, just send once without retry capability.
    let mut attempts = 0u32;
    let mut current_rb = request_builder;

    loop {
        let next_rb = current_rb.try_clone();
        let resp = current_rb.send().await?;

        if resp.status().as_u16() != 429 || attempts >= max_retries {
            return Ok(resp);
        }

        // Parse Retry-After header (seconds)
        let wait_ms = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| (secs * 1000).min(max_retry_delay_ms))
            .unwrap_or_else(|| {
                // Exponential backoff: 1s, 2s, 4s
                (1000 * (1u64 << attempts.min(3))).min(max_retry_delay_ms)
            });

        let Some(rb) = next_rb else {
            // Cannot retry (request body was streamed), return the 429
            return Ok(resp);
        };

        if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "[rate-limit] HTTP 429 received, retry {}/{} after {}ms",
                attempts + 1,
                max_retries,
                wait_ms
            );
        }

        tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
        current_rb = rb;
        attempts += 1;
    }
}

#[cfg(test)]
mod tests {
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
}
