use super::*;

// The client cache is process-global and shared with every other test in
// this binary that builds a Client (e.g. the WAF tests). Asserting on the
// cache's *total* length is therefore racy: a concurrent test can insert
// an entry between two measurements, which previously surfaced as a
// `same key must reuse: left 1, right 2` flake. Each test below instead
// scopes its assertions to a timeout value no other test uses, so foreign
// inserts (which carry different timeouts) can't perturb the count. This
// makes the cache tests safe to run concurrently with no shared lock.
//
// Timeouts reserved for these tests' cache keys. The isolation guarantee
// rests on no other test building a Client with one of these values, so
// keep them unique to this module and do not reuse them elsewhere.
const REUSE_TIMEOUT: u64 = 60_001;
const DISTINCT_TIMEOUT_A: u64 = 60_002;
const DISTINCT_TIMEOUT_B: u64 = 60_003;
const INSECURE_TIMEOUT: u64 = 60_004;

/// Count cached Clients whose key carries `timeout`. Scoping by a
/// per-test-unique timeout isolates the measurement from any other test
/// that builds a Client into the same process-global cache.
fn cache_entries_with_timeout(timeout: u64) -> usize {
    client_cache()
        .lock()
        .map(|g| g.keys().filter(|(t, _, _, _)| *t == timeout).count())
        .unwrap_or(0)
}

/// Building twice with the same key reuses the cached Client instead of
/// creating a second entry.
#[test]
fn test_client_cache_reuses_for_same_key() {
    let mut t = parse_target("http://example.com").unwrap();
    t.timeout = REUSE_TIMEOUT;
    t.follow_redirects = false;
    t.proxy = None;
    let _ = t.build_client().unwrap();
    let after_first = cache_entries_with_timeout(t.timeout);
    let _ = t.build_client().unwrap();
    let after_second = cache_entries_with_timeout(t.timeout);
    assert_eq!(after_first, after_second, "same key must reuse");
    assert_eq!(after_first, 1, "exactly one entry for the shared key");
}

/// Two targets differing only in an input that affects Client
/// construction (here, timeout) occupy two distinct cache entries.
#[test]
fn test_client_cache_separates_distinct_keys() {
    let mut a = parse_target("http://example.com").unwrap();
    a.timeout = DISTINCT_TIMEOUT_A;
    let mut b = parse_target("http://example.com").unwrap();
    b.timeout = DISTINCT_TIMEOUT_B; // distinct key
    let _ = a.build_client().unwrap();
    let _ = b.build_client().unwrap();
    let _ = a.build_client().unwrap();
    assert_eq!(cache_entries_with_timeout(a.timeout), 1);
    assert_eq!(cache_entries_with_timeout(b.timeout), 1);
}

/// `insecure` is part of the Client cache key, so toggling TLS
/// verification yields two distinct cached Clients rather than silently
/// reusing one built with the other posture.
#[test]
fn test_client_cache_separates_on_insecure() {
    let mut secure = parse_target("https://example.com").unwrap();
    secure.timeout = INSECURE_TIMEOUT;
    secure.insecure = false;
    let mut insecure = parse_target("https://example.com").unwrap();
    insecure.timeout = INSECURE_TIMEOUT;
    insecure.insecure = true;
    let _ = secure.build_client().unwrap();
    let _ = insecure.build_client().unwrap();
    // Rebuild to confirm reuse (no third entry created).
    let _ = secure.build_client().unwrap();
    assert_eq!(
        cache_entries_with_timeout(INSECURE_TIMEOUT),
        2,
        "secure and insecure clients must not share a cache entry"
    );
}

/// Scanner default: a freshly parsed target trusts invalid certs unless
/// the caller opts into validation.
#[test]
fn test_parse_target_defaults_to_insecure() {
    let target = parse_target("https://example.com").unwrap();
    assert!(
        target.insecure,
        "insecure must default to true (scanner mode)"
    );
}

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

/// Explicit non-http(s) authority-form schemes are rejected with an
/// actionable error instead of being silently mangled into a bogus host
/// (`ftp://127.0.0.1/x` used to become `http://ftp//127.0.0.1/x` and fail
/// DNS as if the user's host were down).
#[test]
fn test_parse_target_rejects_non_http_scheme() {
    for bad in [
        "ftp://127.0.0.1/x?q=1",
        "file:///etc/passwd",
        "gopher://127.0.0.1/x",
        "ws://127.0.0.1/x",
        "FTP://127.0.0.1/x", // case-insensitive
    ] {
        let err = parse_target(bad).expect_err("non-http(s) scheme must be rejected");
        assert!(
            err.to_string().contains("unsupported URL scheme"),
            "expected an unsupported-scheme error for {bad}, got: {err}"
        );
    }
}

/// Scheme-less inputs that merely *contain* a colon (or a `://` inside the
/// query) must keep working — the rejection is anchored on a contiguous
/// leading `scheme://`, so these still get the `http://` prefix.
#[test]
fn test_parse_target_keeps_schemeless_inputs() {
    for ok in [
        "127.0.0.1:8771/ctx/vuln_body?q=1",        // host:port
        "user:pass@127.0.0.1:8771/x",              // userinfo colon
        "example.com/p?next=https://evil.com&q=1", // `://` only in query
        "example.com",
    ] {
        let t = parse_target(ok).unwrap_or_else(|e| panic!("{ok} should parse, got: {e}"));
        assert!(
            t.url.as_str().starts_with("http://"),
            "{ok} should be prefixed with http://, got {}",
            t.url.as_str()
        );
    }
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
    let (method, url, body) = parse_method_url_body("DELETE https://api.example.com/resource/123");
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
fn test_parse_method_url_body_query_with_json_body() {
    // RFC 10008 QUERY — safe/idempotent method with a body.
    let (method, url, body) =
        parse_method_url_body("QUERY https://example.com/search {\"q\":\"test\"}");
    assert_eq!(method, "QUERY");
    assert_eq!(url, "https://example.com/search");
    assert_eq!(body, Some("{\"q\":\"test\"}".to_string()));
}

#[test]
fn test_parse_method_url_body_query_lowercase() {
    let (method, url, body) = parse_method_url_body("query https://example.com/search a=b");
    assert_eq!(method, "QUERY");
    assert_eq!(url, "https://example.com/search");
    assert_eq!(body, Some("a=b".to_string()));
}

#[test]
fn test_is_raw_http_request_query() {
    assert!(is_raw_http_request(
        "QUERY /search HTTP/1.1\r\nHost: example.com\r\n\r\n{\"q\":\"test\"}"
    ));
    assert!(!is_raw_http_request("QUERY https://example.com/search"));
}

#[test]
fn test_parse_target_with_method_query() {
    let target =
        parse_target_with_method("QUERY https://example.com/search {\"q\":\"x\"}").unwrap();
    assert_eq!(target.method, "QUERY");
    assert_eq!(target.url.as_str(), "https://example.com/search");
    assert_eq!(target.data, Some("{\"q\":\"x\"}".to_string()));
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
    let target = parse_target_with_method("POST https://example.com/api name=John Doe").unwrap();
    assert_eq!(target.method, "POST");
    assert_eq!(target.url.as_str(), "https://example.com/api");
    assert_eq!(target.data, Some("name=John Doe".to_string()));
}
