use crate::parameter_analysis::Param;
use reqwest::{Client, redirect::Policy};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use url::Url;

mod har;
pub use har::{is_har_content, parse_har};

/// Cache key capturing the inputs that affect Client construction:
/// timeout, optional proxy URL, follow-redirects policy, and whether TLS
/// certificate verification is skipped (`insecure`). The scheme/host are
/// NOT part of the key because reqwest::Client manages per-host connection
/// pools internally — one Client safely serves any number of hosts.
type ClientCacheKey = (u64, Option<String>, bool, bool);

/// Process-wide cache of reqwest::Clients keyed by ClientCacheKey. Each
/// cached entry is cheap to clone (reqwest::Client is internally Arc'd).
/// This collapses what was previously one fresh Client per call site
/// (10+ sites, called per-target and per-payload) into a small fixed
/// number of pooled clients, which prevents the connection storm that
/// otherwise turned localhost requests into spurious ECONNREFUSED at
/// high worker counts.
fn client_cache() -> &'static Mutex<HashMap<ClientCacheKey, Client>> {
    static CACHE: OnceLock<Mutex<HashMap<ClientCacheKey, Client>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

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
    pub ignore_return: Vec<u16>,
    pub waf_info: Option<crate::waf::WafDetectionResult>,
    pub csp_analysis: Option<crate::payload::xss_csp_bypass::CspAnalysis>,
    pub tech_info: Option<crate::scanning::tech_detect::TechDetectionResult>,
    /// Per-target WAF-bypass telemetry. Populated during preflight when a
    /// WAF is detected and bypass is enabled; left `None` otherwise so
    /// the no-WAF path pays no overhead.
    pub mutation_stats: Option<Arc<crate::waf::bypass::MutationStats>>,
    /// Extra inter-request pause (ms) applied to injection sends once a WAF
    /// is detected, sourced from the matched WAF's `extra_delay_hint_ms`.
    /// 0 when no WAF was detected or `--waf-bypass off`. Set during preflight
    /// analysis; consumed by the reflection / DOM injection paths so the hint
    /// actually paces requests instead of only surfacing in JSON meta.
    pub waf_extra_delay_ms: u64,
    /// Skip TLS/SSL certificate verification when building the HTTP client
    /// (`danger_accept_invalid_certs`). Defaults to `true` so the scanner
    /// trusts self-signed / expired / hostname-mismatched certs out of the
    /// box (`--insecure`); set to `false` (`--insecure=false`) to enforce
    /// certificate validation.
    pub insecure: bool,
}

impl Target {
    /// Construct a `Target` for `url` with empty request fields (method `GET`,
    /// no data/headers/cookies) and scan-context fields at their parse-time
    /// defaults. `resolve_targets` overwrites timeout/delay/proxy/workers/etc.
    /// from the CLI args before scanning, so those values here are just
    /// placeholders that keep unit-level parsing self-contained. Callers fill
    /// the request-specific fields via struct-update syntax, e.g.
    /// `Target { method, data, ..Target::for_url(url) }`.
    pub(crate) fn for_url(url: Url) -> Self {
        Target {
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
            ignore_return: vec![],
            waf_info: None,
            csp_analysis: None,
            tech_info: None,
            mutation_stats: None,
            waf_extra_delay_ms: 0,
            // Scanner default: trust self-signed / staging certs unless the
            // caller explicitly opts into validation (`--insecure=false`).
            insecure: true,
        }
    }

    /// Parse the method string into a `reqwest::Method`, defaulting to GET on failure.
    /// This avoids repeating `.method.parse().unwrap_or(reqwest::Method::GET)` everywhere.
    pub fn parse_method(&self) -> reqwest::Method {
        self.method.parse().unwrap_or(reqwest::Method::GET)
    }

    /// Whether this target's (enforcing) CSP requires Trusted Types
    /// (`require-trusted-types-for 'script'`). Drives the AST DOM analyzer's
    /// strict-default-policy suppression. False when no CSP was analysed or the
    /// captured policy was report-only (neutralised at analysis time).
    pub fn trusted_types_enforced(&self) -> bool {
        self.csp_analysis
            .as_ref()
            .is_some_and(|c| c.require_trusted_types_for)
    }

    /// Build a reqwest Client, falling back to a default Client on error.
    /// Logs a warning in debug mode if the build fails.
    ///
    /// Returns a clone of a cached Client when one already exists for the
    /// (timeout, proxy, follow_redirects) tuple, so call sites that previously
    /// allocated a fresh Client per invocation (parameter mining, reflection
    /// checks, blind callbacks, etc.) now share a pooled connection set.
    pub fn build_client_or_default(&self) -> Client {
        self.build_client().unwrap_or_else(|e| {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[warn] failed to build client: {}, using default", e);
            }
            Client::new()
        })
    }

    pub fn build_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
        // Library consumers may build clients without going through `main()`,
        // so make sure the ring crypto provider is installed first.
        crate::ensure_crypto_provider();
        // Resolve any proxy up front so the cache key reflects what the client
        // will ACTUALLY use, not the raw string. A malformed proxy is silently
        // unusable (matching prior behavior) — but if it still contributed to
        // the key, each distinct malformed (or merely varied) proxy string
        // would mint a permanent, never-evicted entry in the process-wide
        // client cache, growing memory without bound in a long-running
        // server/MCP daemon. Collapsing unusable proxies onto the no-proxy key
        // makes garbage-proxy spam inert while keeping the legitimate (small)
        // proxy keyspace cached.
        let proxy = self
            .proxy
            .as_deref()
            .and_then(|p| reqwest::Proxy::all(p).ok());
        let proxy_key = if proxy.is_some() {
            self.proxy.clone()
        } else {
            None
        };
        let key = (
            self.timeout,
            proxy_key,
            self.follow_redirects,
            self.insecure,
        );
        // Fast path: return a cached Client if one matches the key.
        if let Ok(guard) = client_cache().lock()
            && let Some(c) = guard.get(&key)
        {
            return Ok(c.clone());
        }

        // Slow path: build a fresh Client and insert into cache. We don't hold
        // the lock during build to avoid serializing concurrent first-touches
        // for distinct keys; the small race that may build the same key twice
        // is harmless (the loser's value is dropped on insert).
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(self.timeout))
            // Insecure mode for scanner (default on; `--insecure=false` to
            // enforce TLS certificate validation).
            .danger_accept_invalid_certs(self.insecure);

        if let Some(proxy) = proxy {
            client_builder = client_builder.proxy(proxy);
        }

        if self.follow_redirects {
            client_builder = client_builder.redirect(Policy::limited(10));
        } else {
            client_builder = client_builder.redirect(Policy::none());
        }

        let client = client_builder.build()?;
        if let Ok(mut guard) = client_cache().lock() {
            guard.insert(key, client.clone());
        }
        Ok(client)
    }
}

pub fn parse_target(s: &str) -> Result<Target, Box<dyn std::error::Error>> {
    // RFC 3986 schemes are case-insensitive. Previously `HTTP://x` got
    // double-prefixed because the case-sensitive check missed the
    // uppercase scheme and the fallback rewrote it as
    // `http://HTTP://x`, which then DNS-failed.
    let lower = s.to_ascii_lowercase();
    let url_str = if lower.starts_with("http://") || lower.starts_with("https://") {
        s.to_string()
    } else {
        // Reject an explicit non-http(s) authority-form scheme rather than
        // silently prepending `http://`. Without this, `ftp://127.0.0.1/x`
        // became `http://ftp//127.0.0.1/x` — the scheme token `ftp` was parsed
        // as the host and DNS-resolved, surfacing a misleading
        // DNS_RESOLUTION_FAILED instead of an actionable error. Mirrors the
        // `http|https`-only restriction the HAR import path already enforces.
        // Anchored on a contiguous RFC-3986 `scheme://` so scheme-less inputs
        // (`host:port/path`, `user:pass@host`, or a `://` that appears only
        // inside the query) keep working unchanged.
        if let Some(i) = lower.find("://") {
            let scheme = &lower[..i];
            let valid_scheme = !scheme.is_empty()
                && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.');
            if valid_scheme {
                return Err(format!(
                    "unsupported URL scheme '{scheme}://' (only http and https are supported)"
                )
                .into());
            }
        }
        format!("http://{}", s)
    };
    let url = Url::parse(&url_str)?;
    Ok(Target::for_url(url))
}

/// Parse a target string that may be in "METHOD URL [BODY]" format.
/// Returns (method, url, optional_body).
/// If the string doesn't start with a known HTTP method, it returns ("GET", original_string, None).
pub fn parse_method_url_body(s: &str) -> (String, String, Option<String>) {
    // Use splitn(3, ' ') to preserve spaces in the body portion (e.g., "POST url name=John Doe")
    let parts: Vec<&str> = s.splitn(3, ' ').collect();

    if parts.len() >= 2 {
        let potential_method = parts[0].to_uppercase();
        if is_known_http_method(&potential_method) {
            let url = parts[1].to_string();
            let body = parts
                .get(2)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string);
            return (potential_method, url, body);
        }
    }

    // Not in METHOD URL [BODY] format, return as-is with GET method
    ("GET".to_string(), s.to_string(), None)
}

/// Methods recognized in `METHOD URL [BODY]` shorthand and raw-HTTP request lines.
/// Includes RFC 10008 QUERY (safe/idempotent with a body).
const KNOWN_HTTP_METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "QUERY",
];

#[inline]
fn is_known_http_method(method: &str) -> bool {
    KNOWN_HTTP_METHODS.iter().any(|m| m.eq(&method))
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
    if let Some(method) = it.next()
        && is_known_http_method(method)
        && first.contains(" HTTP/")
    {
        return true;
    }
    false
}

/// Request headers that must not be forwarded verbatim from an imported request
/// (raw HTTP or HAR). `Content-Length`/`Transfer-Encoding` are recomputed by
/// reqwest from the actual (payload-injected) body — a stale value mis-frames
/// the request and truncates the body, so injected params are never seen.
/// `Accept-Encoding` is left to reqwest so its transparent decompression stays
/// on (a manual value yields compressed gibberish the markers never match).
/// `Host` is set from the URL and the rest are hop-by-hop headers tied to the
/// original connection. `Cookie`/`User-Agent` are handled separately by callers
/// and are intentionally not listed here. Shared with the HAR import path.
pub(crate) fn is_skippable_request_header(name: &str) -> bool {
    const SKIP: &[&str] = &[
        "host",
        "content-length",
        "accept-encoding",
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "te",
    ];
    SKIP.iter().any(|s| name.eq_ignore_ascii_case(s))
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
                // Split cookies into vector. Do NOT also keep the original Cookie
                // header: leaving it in `headers_vec` makes per-cookie probing
                // emit both the original and the mutated Cookie (reqwest appends),
                // so the server may take the un-injected value and the payload
                // never lands. `apply_headers_ua_cookies` rebuilds a single,
                // correct Cookie header from `cookies_vec`/overrides — mirror HAR.
                for kv in value_trim.split(';') {
                    let kv = kv.trim();
                    if let Some((k, v)) = kv.split_once('=') {
                        let k = k.trim();
                        // Skip empty-name pairs (e.g. a leading `=val` or `;=v;`
                        // segment): an empty cookie name is invalid and would
                        // re-serialize into a malformed `=val` Cookie segment.
                        if k.is_empty() {
                            continue;
                        }
                        cookies_vec.push((k.to_string(), v.trim().to_string()));
                    }
                }
            } else if name_trim.eq_ignore_ascii_case("user-agent") {
                user_agent = Some(value_trim.clone());
                headers_vec.push((name_trim, value_trim));
            } else if !is_skippable_request_header(&name_trim) {
                // Drop stale `Content-Length`/`Transfer-Encoding` (reqwest
                // recomputes them from the injected body — a stale value
                // truncates it) and hop-by-hop/`Accept-Encoding` headers, the
                // same set the HAR import path strips.
                headers_vec.push((name_trim, value_trim));
            }
        }
    }

    // 3) Body (remaining lines after the first blank line)
    let body = lines.fold(String::new(), |mut acc, l| {
        if !acc.is_empty() {
            acc.push('\n');
        }
        acc.push_str(l);
        acc
    });
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
        method,
        data,
        headers: headers_vec,
        cookies: cookies_vec,
        user_agent,
        ..Target::for_url(url)
    })
}

#[cfg(test)]
mod tests {
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
}
