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
    if cookies.is_empty() {
        return None;
    }
    let mut s = String::new();
    for (i, (k, v)) in cookies.iter().enumerate() {
        if i > 0 {
            s.push_str("; ");
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    if s.is_empty() { None } else { Some(s) }
}

/// Compose a Cookie header excluding a specific cookie name (case-sensitive match on name).
/// Returns None if the resulting set is empty.
pub fn compose_cookie_header_excluding(
    cookies: &[(String, String)],
    exclude_name: Option<&str>,
) -> Option<String> {
    match exclude_name {
        None => compose_cookie_header(cookies),
        Some(name) => {
            let filtered: Vec<(String, String)> =
                cookies.iter().filter(|(k, _)| k != name).cloned().collect();
            compose_cookie_header(&filtered)
        }
    }
}

/// Case-insensitive check if a header exists in a (name, value) vector.
pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Apply provided headers (verbatim), then apply User-Agent if present (overrides any existing).
/// If `cookie_header` is Some, attach it. Otherwise, if no Cookie header exists in headers,
/// auto-attach from target.cookies (when non-empty).
fn apply_headers_ua_cookies(
    mut rb: RequestBuilder,
    target: &Target,
    cookie_header: Option<String>,
) -> RequestBuilder {
    // Apply user provided headers first
    for (k, v) in &target.headers {
        rb = rb.header(k, v);
    }

    // Apply UA (override any existing UA header)
    if let Some(ua) = &target.user_agent {
        if !ua.is_empty() {
            rb = rb.header("User-Agent", ua);
        }
    }

    // Cookie precedence:
    // 1) explicit cookie_header (override)
    // 2) if no explicit, but target.headers already had Cookie => honor it (do nothing)
    // 3) otherwise auto-attach the cookie header composed from target.cookies
    if let Some(ch) = cookie_header {
        if !ch.is_empty() {
            rb = rb.header("Cookie", ch);
            return rb;
        }
    }
    if !has_header(&target.headers, "Cookie") {
        if let Some(ch) = compose_cookie_header(&target.cookies) {
            if !ch.is_empty() {
                rb = rb.header("Cookie", ch);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
