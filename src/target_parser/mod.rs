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
    /// The `User-Agent` to actually put on the wire, or `None` for "leave it
    /// to the HTTP client".
    ///
    /// `user_agent` carries two spellings of the same thing: `None`, and the
    /// `Some("")` sentinel that every entry point normalizes to when the
    /// operator supplied no override (`job::runner::hydrate_target`,
    /// `cmd::scan::input`). Reading the field directly means remembering to
    /// empty-check, and three of the four call sites that did so forgot —
    /// putting a literal blank `User-Agent:` on probe and blind-XSS requests,
    /// a fingerprint no ordinary client sends. Go through here instead.
    pub(crate) fn effective_user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref().filter(|ua| !ua.is_empty())
    }

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
    pub(crate) fn parse_method(&self) -> reqwest::Method {
        self.method.parse().unwrap_or(reqwest::Method::GET)
    }

    /// Build a reqwest Client, falling back to a default Client on error.
    /// Logs a warning in debug mode if the build fails.
    ///
    /// Returns a clone of a cached Client when one already exists for the
    /// (timeout, proxy, follow_redirects) tuple, so call sites that previously
    /// allocated a fresh Client per invocation (parameter mining, reflection
    /// checks, blind callbacks, etc.) now share a pooled connection set.
    pub(crate) fn build_client_or_default(&self) -> Client {
        self.build_client().unwrap_or_else(|e| {
            // The default client carries no proxy, no `insecure` posture, and
            // no timeout. Dropping the proxy silently is the one fallback that
            // is a scope hazard rather than a mild degradation — the operator
            // asked for their traffic to go through a proxy and it would go
            // DIRECT — so warn unconditionally in that case (not just under
            // --debug), even though `--proxy` is now validated up front and this
            // path is only reachable on a rarer, non-proxy build failure.
            if self.proxy.as_deref().is_some_and(|p| !p.trim().is_empty()) {
                eprintln!(
                    "[warn] HTTP client build failed ({e}); the configured proxy is NOT in effect and requests will go direct"
                );
            } else if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[warn] failed to build client: {}, using default", e);
            }
            Client::new()
        })
    }

    pub(crate) fn build_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
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
/// Drop a leading UTF-8 BOM.
///
/// `str::trim_start` leaves U+FEFF in place — it is not `White_Space` — so
/// every text entry point that inspects the first bytes has to remove it
/// explicitly, or a file saved by Notepad, Excel or PowerShell parses wrong.
fn strip_bom(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

pub fn is_raw_http_request(s: &str) -> bool {
    // Strip a UTF-8 BOM before looking at the method: `str::trim_start` does not
    // remove U+FEFF (it is not `White_Space`), and Notepad / Excel /
    // PowerShell's `Out-File` all write one. Without this the method reads as
    // `\u{feff}GET`, detection fails, and the request file is handed to the
    // URL-list path — which tries to parse `Host: example.com:8080` as a URL
    // and aborts the run. `is_har_content` already strips it.
    let first = strip_bom(s).lines().next().unwrap_or("").trim_start();
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

/// Whether a header imported verbatim from a raw HTTP request or a HAR capture
/// can actually be put on an HTTP/1.1 wire.
///
/// reqwest validates header names/values lazily — a bad one is accepted by
/// `RequestBuilder::header()` and only rejected at `send()`. Since the imported
/// headers are attached to *every* request for the target, a single unsendable
/// header (an empty name, an HTTP/2 pseudo-header like `:authority` that survives
/// a copy-as-curl / HTTP/2 capture, a name containing a space, or a value
/// carrying a control byte such as NUL) fails the reachability probe and every
/// scan request — so a live target is silently reported unreachable and nothing
/// is tested. Such headers can't be sent on HTTP/1.1 anyway, so drop them at
/// import (the caller logs the drop) rather than poisoning the whole scan.
///
/// Shared by [`parse_raw_http_request`] and the HAR import path so both agree.
pub(crate) fn is_forwardable_header(name: &str, value: &str) -> bool {
    use reqwest::header::{HeaderName, HeaderValue};
    HeaderName::try_from(name).is_ok() && HeaderValue::from_str(value).is_ok()
}

/// The body of a raw HTTP request: everything after the blank line that ends
/// the header block, byte-for-byte apart from one optional trailing newline.
/// `None` when there is no separator or nothing follows it.
///
/// Operates on the original text rather than on a `lines()` re-join so that
/// CRLF line endings *inside* the body survive: a `multipart/form-data` body
/// captured from a real request uses CRLF around its boundaries, and RFC 7578
/// parsers that match `\r\n--boundary` see zero parts once those become bare
/// LFs.
///
/// Two details that a naive "find the first \r\n\r\n" gets wrong:
///
/// * **The separator must be found the same way the header loop finds it.**
///   That loop ends on the first line whose `trim_end()` is empty, so a
///   separator line carrying stray whitespace (`\r\n \r\n`) ends the headers
///   there. Scanning for a literal `\r\n\r\n` would miss it and report no
///   body at all, silently dropping every body parameter from the scan.
/// * **A trailing newline is a file artifact, not body content.** Every text
///   editor terminates a file with one, and the old `lines()` fold dropped it.
///   Keeping it verbatim appended a `\n` to the last body parameter's value,
///   which then rode along percent-encoded (`b=2%0A`) on every request of the
///   scan. Exactly one trailing terminator is removed, so a multipart body's
///   internal CRLFs — and its `--boundary--` close delimiter — are untouched.
fn raw_http_body(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    let mut line_start = 0usize;
    let body_start = loop {
        if line_start >= bytes.len() {
            return None;
        }
        let rel_end = raw[line_start..]
            .find('\n')
            .map(|r| line_start + r)
            .unwrap_or(bytes.len());
        let line = &raw[line_start..rel_end];
        let next = (rel_end + 1).min(bytes.len());
        if line.trim_end().is_empty() {
            break next;
        }
        line_start = next;
    };
    let mut body = &raw[body_start..];
    // Drop one trailing terminator (CRLF or LF), never more.
    if let Some(stripped) = body.strip_suffix("\r\n") {
        body = stripped;
    } else if let Some(stripped) = body.strip_suffix('\n') {
        body = stripped;
    }
    (!body.is_empty()).then_some(body)
}

/// Parse a raw HTTP request into a Target.
/// Supports:
/// - Request line with absolute-form URI: GET http://example.com/path HTTP/1.1
/// - Origin-form + Host header:         GET /path HTTP/1.1 + Host: example.com[:port]
/// - Cookies collected from Cookie header
/// - Body captured after the first blank line
pub fn parse_raw_http_request(raw: &str) -> Result<Target, Box<dyn std::error::Error>> {
    // Same BOM strip as `is_raw_http_request`. Forcing `-i raw-http` on a
    // BOM-prefixed file used to parse the method as `\u{feff}GET` — accepted
    // silently here, then rejected by every request built from it.
    let mut lines = strip_bom(raw).lines();

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
                //
                // Also drop any header reqwest can't put on the wire — an empty
                // name (`: value`), an HTTP/2 pseudo-header (`:authority: …`,
                // which the origin-form request line carries instead and which
                // a copy-as-curl / HTTP/2 capture routinely includes), a
                // space-bearing name, or a control byte in the value. Forwarded
                // verbatim, one of these fails the reachability probe and every
                // scan request, so the live target is silently reported
                // unreachable. Mirrors the HAR import path.
                if is_forwardable_header(&name_trim, &value_trim) {
                    headers_vec.push((name_trim, value_trim));
                } else {
                    crate::dbg_log!(
                        "dropping unsendable raw-http header {:?} (name/value rejected by HTTP/1.1)",
                        name_trim
                    );
                }
            }
        }
    }

    // 3) Body — sliced verbatim out of the original text after the blank line
    //    that ends the header block.
    //
    //    Rebuilding it by joining `lines()` with `\n` corrupted every body whose
    //    line endings are load-bearing: a `multipart/form-data` body captured
    //    from a real request uses CRLF around its boundaries, and RFC 7578
    //    parsers that match `\r\n--boundary` see *zero* parts once the CRLFs
    //    become bare LFs. The same fold also swallowed a leading blank line.
    let data = raw_http_body(raw).map(str::to_string);

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
        // An origin-form request-target is an absolute path on `host`, so it is
        // appended to `base` textually rather than joined. `Url::join` treats a
        // `//…`-prefixed target as an RFC 3986 network-path reference and parses
        // its first segment as a *new authority* — so `GET //evil.com/admin`
        // with `Host: internal.local` would silently retarget the scan at
        // `http://evil.com/admin`, dropping the Host header entirely. Such
        // double-slash paths turn up in real proxy captures (buggy client-side
        // URL joins). Concatenating keeps the authority pinned to `host`, and
        // still normalizes dot-segments and percent-encodes exactly as `join`
        // did for the ordinary single-slash case. Non-path forms (`*`,
        // authority-form) don't start with `/`, so they fall back to `join`.
        if uri.starts_with('/') {
            Url::parse(&format!("{}{}", base, uri))?
        } else {
            Url::parse(&base)?.join(uri)?
        }
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
mod tests;

#[cfg(test)]
mod raw_http_tests;
