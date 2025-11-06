use crate::parameter_analysis::Param;
use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    pub method: String,
    pub data: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub user_agent: Option<String>,
    pub reflection_params: Vec<Param>,
    pub timeout: u64,
    pub delay: u64,
    pub proxy: Option<String>,
    pub workers: usize,
    pub follow_redirects: bool,
}

impl Target {
    pub fn build_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(self.timeout))
            .danger_accept_invalid_certs(true); // Insecure mode for scanner

        if let Some(proxy_url) = &self.proxy {
            if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                client_builder = client_builder.proxy(proxy);
            }
        }

        if self.follow_redirects {
            client_builder = client_builder.redirect(Policy::limited(10));
        } else {
            client_builder = client_builder.redirect(Policy::none());
        }

        Ok(client_builder.build()?)
    }
}

pub fn parse_target(s: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let url_str = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{}", s)
    };
    let url = Url::parse(&url_str)?;
    Ok(Target {
        url,
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        reflection_params: vec![],
        timeout: 10,
        delay: 0,
        proxy: None,
        workers: 10,
        follow_redirects: false,
    })
}

/// Parse a target string that may be in "METHOD URL [BODY]" format.
/// Returns (method, url, optional_body).
/// If the string doesn't start with a known HTTP method, it returns ("GET", original_string, None).
pub fn parse_method_url_body(s: &str) -> (String, String, Option<String>) {
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

    let parts: Vec<&str> = s.splitn(3, ' ').collect();

    if parts.len() >= 2 {
        let potential_method = parts[0].to_uppercase();
        if METHODS.iter().any(|m| m.eq(&potential_method)) {
            let url = parts[1].to_string();
            let body = if parts.len() >= 3 && !parts[2].is_empty() {
                Some(parts[2].to_string())
            } else {
                None
            };
            return (potential_method, url, body);
        }
    }

    // Not in METHOD URL [BODY] format, return as-is with GET method
    ("GET".to_string(), s.to_string(), None)
}

/// Parse a target string that may be in "METHOD URL [BODY]" format or a plain URL.
/// This is a wrapper around parse_target that handles the METHOD URL [BODY] format.
pub fn parse_target_with_method(s: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let (method, url_str, body) = parse_method_url_body(s);
    let mut target = parse_target(&url_str)?;
    target.method = method;
    target.data = body;
    Ok(target)
}

/// Detect if the provided text looks like a raw HTTP request (starts with METHOD SP URI SP HTTP/x.y)
pub fn is_raw_http_request(s: &str) -> bool {
    let first = s.lines().next().unwrap_or("").trim_start();
    let mut it = first.split_whitespace();
    if let Some(method) = it.next() {
        const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
        if METHODS.iter().any(|m| m.eq(&method)) && first.contains(" HTTP/") {
            return true;
        }
    }
    false
}

/// Parse a raw HTTP request into a Target.
/// Supports:
/// - Request line with absolute-form URI: GET http://example.com/path HTTP/1.1
/// - Origin-form + Host header:         GET /path HTTP/1.1 + Host: example.com[:port]
/// - Cookies collected from Cookie header
/// - Body captured after the first blank line
pub fn parse_raw_http_request(raw: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let mut lines = raw.lines();

    // 1) Request line
    let request_line = lines.next().ok_or("empty raw http request")?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or("invalid request line: missing method")?
        .to_string();
    let uri = parts
        .next()
        .ok_or("invalid request line: missing request-target")?;
    // HTTP version is optional for our purposes
    let _http_version = parts.next().unwrap_or("");

    // 2) Headers (until blank line)
    let mut headers_vec: Vec<(String, String)> = Vec::new();
    let mut cookies_vec: Vec<(String, String)> = Vec::new();
    let mut host_header: Option<String> = None;
    let mut user_agent: Option<String> = None;

    // Collect raw header lines first (simple unfold; folded headers are uncommon and deprecated)
    let mut header_raw: Vec<String> = Vec::new();
    for line in lines.by_ref() {
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        header_raw.push(l.to_string());
    }

    for h in header_raw {
        if let Some((name, value)) = h.split_once(':') {
            let name_trim = name.trim().to_string();
            let value_trim = value.trim().to_string();

            if name_trim.eq_ignore_ascii_case("host") {
                host_header = Some(value_trim.clone());
                // No need to forward Host to reqwest; it sets Host automatically from URL.
            } else if name_trim.eq_ignore_ascii_case("cookie") {
                // Split cookies into vector
                for kv in value_trim.split(';') {
                    let kv = kv.trim();
                    if let Some((k, v)) = kv.split_once('=') {
                        cookies_vec.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
                // Preserve original Cookie header as well
                headers_vec.push((name_trim, value_trim));
            } else if name_trim.eq_ignore_ascii_case("user-agent") {
                user_agent = Some(value_trim.clone());
                headers_vec.push((name_trim, value_trim));
            } else {
                headers_vec.push((name_trim, value_trim));
            }
        }
    }

    // 3) Body (remaining lines after the first blank line)
    let body = lines.collect::<Vec<&str>>().join("\n");
    let data = if body.is_empty() { None } else { Some(body) };

    // 4) Build URL
    let url = if uri.starts_with("http://") || uri.starts_with("https://") {
        // absolute-form URI in request line
        Url::parse(uri)?
    } else {
        // origin-form; need Host header
        let host = host_header.ok_or("missing Host header for origin-form request")?;
        // Heuristic: default to http, but if :443 present, assume https
        let scheme = if host.ends_with(":443") {
            "https"
        } else {
            "http"
        };
        let base = format!("{}://{}", scheme, host);
        Url::parse(&base)?.join(uri)?
    };

    Ok(Target {
        url,
        method,
        data,
        headers: headers_vec,
        cookies: cookies_vec,
        user_agent,
        reflection_params: vec![],
        timeout: 10,
        delay: 0,
        proxy: None,
        workers: 10,
        follow_redirects: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_with_scheme() {
        let target = parse_target("https://example.com").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/");
        assert_eq!(target.method, "GET");
        assert!(target.data.is_none());
        assert!(target.headers.is_empty());
        assert!(target.cookies.is_empty());
        assert!(target.user_agent.is_none());
        assert!(target.reflection_params.is_empty());
        assert_eq!(target.timeout, 10);
        assert_eq!(target.delay, 0);
        assert!(target.proxy.is_none());
        assert_eq!(target.workers, 10);
        assert_eq!(target.follow_redirects, false);
    }

    #[test]
    fn test_parse_target_without_scheme() {
        let target = parse_target("example.com").unwrap();
        assert_eq!(target.url.as_str(), "http://example.com/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_invalid_url() {
        assert!(parse_target("invalid url").is_err());
    }

    #[test]
    fn test_parse_target_with_path() {
        let target = parse_target("https://example.com/path/to/resource").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/path/to/resource");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_query() {
        let target = parse_target("https://example.com?param=value").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/?param=value");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_fragment() {
        let target = parse_target("https://example.com#section").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/#section");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_port() {
        let target = parse_target("https://example.com:8080").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com:8080/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_ip_address() {
        let target = parse_target("http://192.168.1.1").unwrap();
        assert_eq!(target.url.as_str(), "http://192.168.1.1/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_localhost() {
        let target = parse_target("localhost:3000").unwrap();
        assert_eq!(target.url.as_str(), "http://localhost:3000/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_unicode_domain() {
        // URL parsing converts unicode domains to punycode
        let target = parse_target("https://例え.テスト").unwrap();
        assert!(target.url.as_str().contains("xn--r8jz45g.xn--zckzah"));
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_empty_string() {
        assert!(parse_target("").is_err());
    }

    #[test]
    fn test_parse_target_only_spaces() {
        assert!(parse_target("   ").is_err());
    }

    #[test]
    fn test_parse_target_invalid_scheme() {
        assert!(parse_target("://example.com").is_err());
    }

    #[test]
    fn test_parse_method_url_body_post_with_body() {
        let (method, url, body) = parse_method_url_body("POST https://example.com/test a=b");
        assert_eq!(method, "POST");
        assert_eq!(url, "https://example.com/test");
        assert_eq!(body, Some("a=b".to_string()));
    }

    #[test]
    fn test_parse_method_url_body_get_without_body() {
        let (method, url, body) = parse_method_url_body("GET https://example.com/path");
        assert_eq!(method, "GET");
        assert_eq!(url, "https://example.com/path");
        assert_eq!(body, None);
    }

    #[test]
    fn test_parse_method_url_body_put_with_json() {
        let (method, url, body) =
            parse_method_url_body("PUT https://api.example.com {\"key\":\"value\"}");
        assert_eq!(method, "PUT");
        assert_eq!(url, "https://api.example.com");
        assert_eq!(body, Some("{\"key\":\"value\"}".to_string()));
    }

    #[test]
    fn test_parse_method_url_body_plain_url() {
        let (method, url, body) = parse_method_url_body("https://example.com");
        assert_eq!(method, "GET");
        assert_eq!(url, "https://example.com");
        assert_eq!(body, None);
    }

    #[test]
    fn test_parse_method_url_body_lowercase_method() {
        let (method, url, body) = parse_method_url_body("post https://example.com data=test");
        assert_eq!(method, "POST");
        assert_eq!(url, "https://example.com");
        assert_eq!(body, Some("data=test".to_string()));
    }

    #[test]
    fn test_parse_method_url_body_delete() {
        let (method, url, body) =
            parse_method_url_body("DELETE https://api.example.com/resource/123");
        assert_eq!(method, "DELETE");
        assert_eq!(url, "https://api.example.com/resource/123");
        assert_eq!(body, None);
    }

    #[test]
    fn test_parse_method_url_body_options() {
        let (method, url, body) = parse_method_url_body("OPTIONS https://example.com/api");
        assert_eq!(method, "OPTIONS");
        assert_eq!(url, "https://example.com/api");
        assert_eq!(body, None);
    }

    #[test]
    fn test_parse_target_with_method_post() {
        let target = parse_target_with_method("POST https://www.hahwul.com/post-test a=b").unwrap();
        assert_eq!(target.method, "POST");
        assert_eq!(target.url.as_str(), "https://www.hahwul.com/post-test");
        assert_eq!(target.data, Some("a=b".to_string()));
    }

    #[test]
    fn test_parse_target_with_method_get() {
        let target = parse_target_with_method("GET https://example.com/path").unwrap();
        assert_eq!(target.method, "GET");
        assert_eq!(target.url.as_str(), "https://example.com/path");
        assert_eq!(target.data, None);
    }

    #[test]
    fn test_parse_target_with_method_plain_url() {
        let target = parse_target_with_method("https://example.com").unwrap();
        assert_eq!(target.method, "GET");
        assert_eq!(target.url.as_str(), "https://example.com/");
        assert_eq!(target.data, None);
    }

    #[test]
    fn test_parse_target_with_method_body_with_spaces() {
        let target =
            parse_target_with_method("POST https://example.com/api name=John Doe").unwrap();
        assert_eq!(target.method, "POST");
        assert_eq!(target.url.as_str(), "https://example.com/api");
        assert_eq!(target.data, Some("name=John Doe".to_string()));
    }
}

#[cfg(test)]
mod raw_http_tests {
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
}
