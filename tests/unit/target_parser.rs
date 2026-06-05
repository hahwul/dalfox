//! Unit tests for the target_parser module
//!
//! Tests URL parsing, method detection, raw HTTP request parsing, and HAR input.

use dalfox::target_parser::{
    is_har_content, is_raw_http_request, parse_har, parse_method_url_body, parse_raw_http_request,
    parse_target, parse_target_with_method,
};

mod parse_target {
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
        assert!(!target.follow_redirects);
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
}

mod parse_method_url_body {
    use super::*;

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
    fn test_parse_method_url_body_with_spaces_in_body() {
        let (method, url, body) = parse_method_url_body("POST https://example.com name=John Doe");
        assert_eq!(method, "POST");
        assert_eq!(url, "https://example.com");
        assert_eq!(body, Some("name=John Doe".to_string()));
    }
}

mod parse_target_with_method {
    use super::*;

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

mod raw_http_request {
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
    fn test_is_raw_http_request_post() {
        let raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(is_raw_http_request(raw));
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

/// Fixture-based tests for HAR input (issue #1095). The fixture
/// `tests/fixtures/sample.har` is a realistic HAR with a GET entry (query
/// params, cookies, a User-Agent, HTTP/2 pseudo-headers) and a POST entry
/// (form body + Content-Length). These exercise the public `parse_har` /
/// `is_har_content` API the `scan --input-type har` path relies on.
mod har {
    use super::*;

    const SAMPLE_HAR: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample.har"
    ));

    #[test]
    fn fixture_is_detected_as_har() {
        assert!(is_har_content(SAMPLE_HAR));
        // A URL list and a raw HTTP request must not be mistaken for HAR.
        assert!(!is_har_content(
            "https://example.com/?q=1\nhttps://example.com/?q=2"
        ));
        assert!(!is_har_content(
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
    }

    #[test]
    fn fixture_parses_get_and_post_entries() {
        let targets = parse_har(SAMPLE_HAR).expect("fixture HAR should parse");
        assert_eq!(targets.len(), 2, "fixture has one GET and one POST entry");

        let get = &targets[0];
        assert_eq!(get.method, "GET");
        assert_eq!(
            get.url.as_str(),
            "https://demo.dalfox.test/search?q=hello&lang=en"
        );
        assert_eq!(get.user_agent.as_deref(), Some("Mozilla/5.0 (HAR fixture)"));
        // Cookies are modelled separately, parsed from the Cookie header.
        assert!(
            get.cookies
                .iter()
                .any(|(k, v)| k == "session" && v == "abc123")
        );
        assert!(get.cookies.iter().any(|(k, v)| k == "theme" && v == "dark"));
        // A meaningful header survives; managed/pseudo headers are stripped.
        assert!(
            get.headers
                .iter()
                .any(|(k, v)| k == "Referer" && v == "https://demo.dalfox.test/")
        );
        for stripped in [
            "host",
            "accept-encoding",
            "connection",
            ":authority",
            ":method",
            "cookie",
            "user-agent",
        ] {
            assert!(
                !get.headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case(stripped)),
                "{stripped} should be stripped from GET headers: {:?}",
                get.headers
            );
        }

        let post = &targets[1];
        assert_eq!(post.method, "POST");
        assert_eq!(post.url.as_str(), "https://demo.dalfox.test/comment");
        assert_eq!(post.data.as_deref(), Some("author=guest&body=hi+there"));
        assert!(
            post.cookies
                .iter()
                .any(|(k, v)| k == "session" && v == "abc123")
        );
        // Content-Length is recomputed by the HTTP client, never forwarded.
        assert!(
            !post
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length")),
            "Content-Length must not be forwarded: {:?}",
            post.headers
        );
        // Content-Type is preserved so the body is interpreted correctly.
        assert!(
            post.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        );
    }
}
