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
    // Apply user provided headers first. Skip `Accept-Encoding`: setting it
    // manually disables reqwest's transparent decompression, so the body comes
    // back as raw gzip/deflate/br bytes and every reflection/marker check
    // silently fails (scan-wide false negatives). Leaving it unset keeps
    // decompression on, mirroring the HAR import path's `is_skippable_har_header`.
    for (k, v) in &target.headers {
        if k.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
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

/// True when a response Content-Type renders as inert *data* in a browser —
/// navigating to it never parses the body as markup or executes it as a
/// script, so a payload reflected into the body is not exploitable as
/// reflected XSS regardless of the injection context inside it.
///
/// Deliberately a tight deny-list of structured-data / binary types
/// (`application/json`, `text/csv`, `application/octet-stream`, fonts, raw
/// media) rather than the inverse of the HTML allow-list, because the grey
/// zone must stay *scannable* to avoid false negatives:
///   * `application/javascript` / `text/javascript` — a reflected callback
///     name is executable when the response is loaded via `<script src>`
///     (JSONP injection), so these are NOT inert.
///   * `text/plain` — browsers content-sniff it as HTML when
///     `X-Content-Type-Options: nosniff` is absent, so it is NOT inert.
///   * empty / missing Content-Type — also sniffable, NOT inert.
pub fn content_type_is_inert_data(ct: &str) -> bool {
    let Some(primary) = content_type_primary(ct) else {
        return false;
    };
    if matches!(
        primary.as_str(),
        "application/json"
            | "text/json"
            | "application/csv"
            | "text/csv"
            | "application/octet-stream"
            | "application/pdf"
            | "application/zip"
    ) {
        return true;
    }
    // Structured `+json` suffix (e.g. `application/vnd.api+json`,
    // `application/problem+json`) — data, never markup.
    if let Some((typ, sub)) = primary.split_once('/')
        && sub.ends_with("+json")
        && typ != "image"
    {
        return true;
    }
    // Raw binary media — fonts, raster images, audio, video. SVG is excluded
    // on purpose (it executes inline scripts/handlers) and is handled by the
    // existing markup allow-list.
    let primary_type = primary.split('/').next().unwrap_or("");
    if matches!(primary_type, "font" | "audio" | "video") {
        return true;
    }
    if primary_type == "image" && primary != "image/svg+xml" {
        return true;
    }
    false
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

/// Absolute ceiling on any single retry backoff sleep (ms), applied to both
/// the exponential backoff and a server-supplied `Retry-After`.
const BACKOFF_CAP_MS: u64 = 30_000;
/// Cap on the exponential-backoff shift so `base << attempt` can't overflow
/// or explode before [`BACKOFF_CAP_MS`] clamps it (2^5 = 32× the base).
const BACKOFF_SHIFT_CAP: u32 = 5;
/// HTTP 429 is always retried this many times regardless of `--retries`,
/// preserving the long-standing rate-limit resilience. `--retries` governs
/// the *additional*, opt-in retrying of 5xx and transient transport errors.
const MAX_429_RETRIES: u32 = 3;

/// Exponential backoff for retry attempt `attempt` (0-based): `base`,
/// `2·base`, `4·base`, … capped at [`BACKOFF_CAP_MS`].
fn next_backoff_ms(base_ms: u64, attempt: u32) -> u64 {
    let base = base_ms.max(1);
    base.saturating_mul(1u64 << attempt.min(BACKOFF_SHIFT_CAP))
        .min(BACKOFF_CAP_MS)
}

/// Was a failed send caused by a transient transport condition worth
/// retrying (timeout or connection error) rather than a fatal one (TLS,
/// malformed URL, …)?
fn is_transient_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect()
}

/// Parse a `Retry-After` header into ms-from-now. Accepts both RFC 7231 forms:
/// delta-seconds (`Retry-After: 120`) and an HTTP-date (`Retry-After: Wed, 21
/// Oct 2026 07:28:00 GMT`). A date already in the past yields `0`. Returns
/// `None` only when the header is absent or unparseable, in which case the
/// caller falls back to exponential backoff. The returned value is unclamped;
/// [`decide_retry`] clamps it to [`BACKOFF_CAP_MS`].
fn parse_retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get("retry-after").and_then(|v| v.to_str().ok())?;
    let s = raw.trim();
    // Preferred, most common form: delta-seconds.
    if let Ok(secs) = s.parse::<u64>() {
        return Some(secs.saturating_mul(1000));
    }
    // Fallback: HTTP-date. Without this a date-form value fell through to a
    // 1s/2s/4s exponential backoff, burning the 429 retry budget in ~7s and
    // abandoning a request that would have succeeded after the advertised wait.
    parse_http_date_retry_ms(s)
}

/// Milliseconds from now until an HTTP-date `Retry-After`, or `None` if it is
/// not a parseable IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`). A past date
/// yields `0`. The two obsolete date forms (RFC 850, asctime) are rare enough
/// to skip — modern servers send IMF-fixdate.
fn parse_http_date_retry_ms(s: &str) -> Option<u64> {
    // Drop the leading weekday ("Wed, ") and parse the rest without `%a`:
    // chrono rejects an IMF-fixdate whose weekday is inconsistent with the date,
    // but a `Retry-After` hint shouldn't be discarded over a server's weekday
    // typo — the date/time is what matters.
    let date_part = s.split_once(", ").map(|(_, rest)| rest).unwrap_or(s);
    let dt = chrono::NaiveDateTime::parse_from_str(date_part, "%d %b %Y %H:%M:%S GMT").ok()?;
    let delta_ms = (dt.and_utc() - chrono::Utc::now()).num_milliseconds();
    Some(delta_ms.max(0) as u64)
}

/// Network-decoupled outcome of a single send attempt, so the retry policy
/// can be unit-tested without a live server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// A completed response carrying this status code.
    Status(u16),
    /// The send failed with a transient transport error (timeout / connect).
    TransientError,
    /// The send failed with a non-retryable transport error.
    FatalError,
}

/// Retries already spent, tracked separately so the always-on 429 budget and
/// the opt-in transient (5xx / network) budget don't cannibalize each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct RetryState {
    /// HTTP 429 retries consumed.
    pub rl_done: u32,
    /// Transient (5xx / network / timeout) retries consumed.
    pub tr_done: u32,
}

/// What [`decide_retry`] tells the send loop to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryDecision {
    /// Stop and return the result to the caller.
    Stop,
    /// Sleep `ms` then retry; `rate_limited` records whether this consumed a
    /// 429 retry (vs. a transient one) so the loop advances the right budget.
    Sleep { ms: u64, rate_limited: bool },
}

/// Pure retry policy. Given one attempt's `outcome`, the retries already
/// spent (`state`), the user's transient-retry budget
/// (`max_transient_retries` from `--retries`), the backoff `base_delay_ms`
/// (`--retry-delay`), and any parsed `Retry-After`, decide whether and how
/// long to wait before retrying.
///
/// * HTTP 429 is always retried up to [`MAX_429_RETRIES`], honoring
///   `Retry-After` when present — this is the historical behavior and is
///   independent of `--retries`.
/// * HTTP 5xx and transient transport errors are retried only up to
///   `max_transient_retries`, which defaults to 0 (off) so the default scan
///   behaves exactly as before.
pub(crate) fn decide_retry(
    outcome: SendOutcome,
    state: RetryState,
    max_transient_retries: u32,
    base_delay_ms: u64,
    retry_after_ms: Option<u64>,
) -> RetryDecision {
    match outcome {
        SendOutcome::Status(429) if state.rl_done < MAX_429_RETRIES => {
            let ms = retry_after_ms
                .unwrap_or_else(|| next_backoff_ms(base_delay_ms, state.rl_done))
                .min(BACKOFF_CAP_MS);
            RetryDecision::Sleep {
                ms,
                rate_limited: true,
            }
        }
        SendOutcome::Status(code)
            if (500..=599).contains(&code) && state.tr_done < max_transient_retries =>
        {
            RetryDecision::Sleep {
                ms: next_backoff_ms(base_delay_ms, state.tr_done),
                rate_limited: false,
            }
        }
        SendOutcome::TransientError if state.tr_done < max_transient_retries => {
            RetryDecision::Sleep {
                ms: next_backoff_ms(base_delay_ms, state.tr_done),
                rate_limited: false,
            }
        }
        _ => RetryDecision::Stop,
    }
}

/// Send a request, honoring the active rate limiter and retrying retryable
/// failures with exponential backoff.
///
/// Before *each* attempt (including retries) a permit is acquired from the
/// process-wide / per-job rate limiter (`crate::rate_limit_acquire`) so the
/// aggregate request rate stays under `--rate-limit`.
///
/// Retry behavior (see [`decide_retry`]):
/// * HTTP 429 → always retried (up to [`MAX_429_RETRIES`]), honoring
///   `Retry-After`.
/// * HTTP 5xx and transient transport errors (timeouts, connection resets)
///   → retried up to `max_transient_retries` (from `--retries`; 0 disables,
///   the default). `base_delay_ms` (`--retry-delay`) seeds the exponential
///   backoff, which is capped at [`BACKOFF_CAP_MS`].
///
/// Returns the final response or transport error after success or after the
/// applicable retry budget is exhausted. If the request body was streamed
/// (not clonable) the first response/error is returned without retrying.
pub async fn send_with_retry(
    request_builder: RequestBuilder,
    max_transient_retries: u32,
    base_delay_ms: u64,
) -> Result<reqwest::Response, reqwest::Error> {
    // reqwest::RequestBuilder is not Clone, so we try_clone before each send;
    // a streamed body yields None and we fall back to a single attempt.
    let mut state = RetryState::default();
    let mut current_rb = request_builder;

    loop {
        // Throttle every attempt so retries also count against --rate-limit.
        crate::rate_limit_acquire().await;

        let next_rb = current_rb.try_clone();
        let result = current_rb.send().await;

        let (outcome, retry_after) = match &result {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let ra = if code == 429 {
                    parse_retry_after_ms(resp.headers())
                } else {
                    None
                };
                (SendOutcome::Status(code), ra)
            }
            Err(e) => {
                let kind = if is_transient_error(e) {
                    SendOutcome::TransientError
                } else {
                    SendOutcome::FatalError
                };
                (kind, None)
            }
        };

        match decide_retry(
            outcome,
            state,
            max_transient_retries,
            base_delay_ms,
            retry_after,
        ) {
            RetryDecision::Stop => return result,
            RetryDecision::Sleep { ms, rate_limited } => {
                let Some(rb) = next_rb else {
                    // Body was streamed; can't replay the request.
                    return result;
                };
                if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!(
                        "[retry] {:?} -> waiting {}ms before retry (429:{} transient:{})",
                        outcome, ms, state.rl_done, state.tr_done
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                if rate_limited {
                    state.rl_done += 1;
                } else {
                    state.tr_done += 1;
                }
                current_rb = rb;
                // Count the retry attempt we're about to make. Callers tick the
                // first attempt themselves; each additional attempt is a real
                // outbound request that was previously missing from REQUEST_COUNT
                // (and the live req/s rate).
                crate::tick_request_count();
            }
        }
    }
}

/// Hard cap on how many bytes of any single response body we buffer into
/// memory. The reqwest client has a request `timeout` but no body-size limit,
/// so a hostile (or misbehaving) server can stream an arbitrarily large body
/// within the timeout window; with the default worker pool buffering many such
/// bodies concurrently this is an out-of-memory crash vector. 16 MiB is far
/// larger than any realistic HTML/JS page, so benign detection is unaffected.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Read a response body into a `String`, hard-capping at `max_bytes`.
///
/// Streams the body chunk-by-chunk (via [`reqwest::Response::chunk`], which is
/// available without the `stream` feature) and stops — dropping the connection,
/// so the server cannot keep pushing bytes — once `max_bytes` is reached. This
/// bounds memory regardless of the advertised or actual `Content-Length`.
///
/// Invalid UTF-8 (including a multi-byte codepoint split at the cap boundary)
/// is replaced via [`String::from_utf8_lossy`], so this never panics. Use in
/// place of `resp.text().await` on any response from a scanned target.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<String, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max_bytes.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= max_bytes {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Convenience over [`read_body_capped`] using the default
/// [`MAX_RESPONSE_BODY_BYTES`] cap. Drop-in replacement for `resp.text().await`
/// on responses from scanned targets.
pub(crate) async fn read_body(resp: reqwest::Response) -> Result<String, reqwest::Error> {
    read_body_capped(resp, MAX_RESPONSE_BODY_BYTES).await
}

#[cfg(test)]
mod tests;
