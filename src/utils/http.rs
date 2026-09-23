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
- `--user-agent X` is recorded twice on purpose: as a `target.headers` entry (so the
  header-reflection probe enumerates and exercises the UA even on blanket-echo targets, where the
  common header sweep is suppressed) and as `target.user_agent` (which drives the common sweep).
  Both carry the same value, and the wire must still show ONE `User-Agent`. reqwest's
  `RequestBuilder::header()` *appends*, so every "override" in this file goes through
  [`set_header`], which is a real replace.

Usage examples:
  let rb = http::build_request(&client, &target, Method::GET, target.url.clone(), None);

  // With cookie override (e.g., probing a specific cookie param)
  let cookie = http::compose_cookie_header_excluding(&target.cookies, Some("session"))
      .map(|s| format!("{}; session=dalfox", s))
      .or_else(|| Some("session=dalfox".to_string()));
  let rb = http::build_request_with_cookie(&client, &target, Method::GET, url, None, cookie);

*/

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
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

/// Same-origin check: scheme, host and port must all match.
///
/// Compared on the *parsed* URLs, so authority-confusing spellings
/// (`http://a\@b/`, userinfo, IDN) are already resolved by WHATWG parsing
/// before the comparison — a textual prefix check against the target URL would
/// not survive them. `Url::origin` is what does the comparing: it is exactly
/// `(scheme, host, port_or_known_default)` for http(s), and yields a unique
/// opaque origin for schemes with no authority, so two host-less URLs never
/// compare equal to each other the way a hand-rolled `host_str()` check would.
pub(crate) fn is_same_origin(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin()
}

/// Whether sending the operator's credentials from `page` to `dest` keeps them
/// on the origin they were meant for.
///
/// This is [`is_same_origin`] plus one relaxation: a `http://host/` ->
/// `https://host/` upgrade on the default ports. The classic "page served over
/// HTTP, form posts over TLS" shape trips a strict origin check even though the
/// destination is the same host and strictly better protected, and treating it
/// as foreign silently drops every parameter on such a form.
///
/// 80 -> 443 is of course itself a port change; it is allowed because that pair
/// *is* the same logical origin by convention, which is not true of ports in
/// general. So the relaxation is pinned to exactly those two: any other port on
/// either side stays refused, because a different port on the same host is a
/// different service with its own auth realm. The reverse direction
/// (`https` -> `http`) stays refused too, so credentials can never be walked
/// onto plaintext.
///
/// Residual risk, accepted: a host that serves an unrelated application on 443
/// receives credentials that were configured for the :80 service. A browser
/// already sends its (non-`Secure`) cookie jar to both, and the alternative is
/// losing the most common authenticated-form shape on the web.
///
/// One predicate governs both the form-action gates and the `--follow-redirects`
/// policy on purpose: they are the same question (may the operator's
/// credentials go here?) and this codebase's parallel-implementation history is
/// that two copies drift. Widening it therefore widens a security control as
/// well as a recall gate — `target_parser::tests` pins the redirect side
/// independently so that cannot happen unnoticed.
pub(crate) fn same_origin_or_tls_upgrade(page: &Url, dest: &Url) -> bool {
    if is_same_origin(page, dest) {
        return true;
    }
    page.scheme() == "http"
        && dest.scheme() == "https"
        && page.host_str() == dest.host_str()
        && page.port_or_known_default() == Some(80)
        && dest.port_or_known_default() == Some(443)
}

/// Resolve a `<form action>` against the page it was found on, returning the URL
/// to probe -- or `None` when the form must be skipped.
///
/// The action attribute is attacker-controlled content: it comes from the
/// scanned page, not from the operator. Probing a destination the scan may not
/// send credentials to hands over every credential configured for the run --
/// `-H` headers, `--cookies`, and any `Authorization`/`Cookie` inherited from a
/// raw-http or HAR import, all attached unconditionally by
/// [`apply_headers_ua_cookies`] -- to a host the operator never named. A page
/// serving `<form action="https://attacker.example/collect">` is enough to
/// collect the operator's session, and the leak does not stop at the probes: if
/// that endpoint echoes the probe marker back, the fields are recorded as
/// discovered parameters and the whole scanning phase then aims there.
///
/// [`same_origin_or_tls_upgrade`] is what decides, and it compares *parsed*
/// origins, which is what makes this hold against authority-confusing actions
/// such as `http://attacker.example\@target.example/submit`: `join` has already
/// resolved that to host `attacker.example` (correct WHATWG parsing -- a
/// backslash terminates the authority in a special scheme), so it compares as
/// foreign. A textual prefix check against the page URL would not.
///
/// The cost is accepted: parameters on a form that legitimately posts to a
/// different host (a separate API or login host) are not discovered.
///
/// Both form-parsing paths -- `parameter_analysis::discovery::form` and the
/// blind/stored path in `scanning::xss_blind` -- go through here, because they
/// had independently grown the same resolve-then-gate block and this codebase's
/// history is that such pairs drift.
pub(crate) fn resolve_probeable_form_action(page: &Url, action_attr: &str) -> Option<Url> {
    let resolved = if action_attr.is_empty() || action_attr == "#" {
        page.clone()
    } else {
        page.join(action_attr).ok()?
    };
    if !same_origin_or_tls_upgrade(page, &resolved) {
        crate::dbg_log!(
            "skipping form action {} on {} (credentials are not sent off-origin)",
            resolved,
            page
        );
        return None;
    }
    Some(resolved)
}

/// Case-insensitive check if a header exists in a (name, value) vector.
#[inline]
pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Apply provided headers (verbatim), then append `target.user_agent` as a
/// User-Agent header when non-empty. reqwest appends rather than overrides, so a
/// caller that also placed a User-Agent in `target.headers` ends up sending both.
/// If `cookie_header` is Some, attach it. Otherwise, if no Cookie header exists in headers,
/// auto-attach from target.cookies (when non-empty).
pub(crate) fn apply_headers_ua_cookies(
    rb: RequestBuilder,
    target: &Target,
    cookie_header: Option<String>,
) -> RequestBuilder {
    apply_headers_ua_cookies_inner(rb, target, cookie_header, false)
}

/// Same as [`apply_headers_ua_cookies`], but with `suppress_content_type`.
///
/// A body injector generates a *new* body in a chosen wire format and then sets
/// the matching `Content-Type` itself. reqwest's `.header()` / `.multipart()`
/// *append*, so a `Content-Type` copied from an imported (raw-http/HAR) target's
/// `target.headers` would remain the **first** value alongside the injector's —
/// and a server frames the body with the first `Content-Type`, so it parses the
/// injected body under the stale captured type (worst case: a captured
/// multipart boundary makes every multipart injection frame zero parts and test
/// nothing). Suppressing the inherited value here lets the injector's be the
/// only one on the wire.
fn apply_headers_ua_cookies_inner(
    mut rb: RequestBuilder,
    target: &Target,
    cookie_header: Option<String>,
    suppress_content_type: bool,
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
        if suppress_content_type && k.eq_ignore_ascii_case("content-type") {
            continue;
        }
        rb = rb.header(k, v);
    }

    // Apply UA, replacing any `target.headers` entry: `--user-agent` populates
    // both, and an imported (raw-http/HAR) target's captured UA must lose to an
    // explicit override rather than ride along as a duplicate first value.
    if let Some(ua) = target.effective_user_agent() {
        rb = set_header(rb, "User-Agent", ua);
    }

    // Cookie precedence:
    // 1) explicit cookie_header (override)
    // 2) if no explicit, but target.headers already had Cookie => honor it (do nothing)
    // 3) otherwise auto-attach the cookie header composed from target.cookies
    if let Some(ch) = cookie_header
        && !ch.is_empty()
    {
        rb = set_header(rb, "Cookie", &ch);
        return rb;
    }
    if !has_header(&target.headers, "Cookie")
        && let Some(ch) = compose_cookie_header(&target.cookies)
        && !ch.is_empty()
    {
        rb = set_header(rb, "Cookie", &ch);
    }

    rb
}

/// Build a RequestBuilder from the given client, maintaining consistent header/UA/Cookie application.
/// If `body` is Some, attach it as the request body.
/// Auto-attaches cookies (unless a Cookie header is already present in target.headers).
pub(crate) fn build_request(
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

/// Build a RequestBuilder for a body injector, dropping any `Content-Type`
/// inherited from `target.headers`.
///
/// The caller sets the injected body's `Content-Type` itself, and the two ways
/// it does that do not agree: `apply_header_overrides` replaces (see
/// [`set_header`]), but reqwest's `.multipart()` *appends*, so a captured
/// `multipart/...; boundary=OLD` from an imported target would survive as the
/// first value and frame the injected body with a boundary that never appears
/// in it — every multipart injection would then parse as zero parts and test
/// nothing. Dropping the inherited value here makes both callers safe. See
/// [`apply_headers_ua_cookies_inner`]. Query/Path injectors keep using
/// [`build_request`], which preserves the captured `Content-Type` since they
/// re-send the original body verbatim.
pub(crate) fn build_body_request_base(
    client: &Client,
    target: &Target,
    method: Method,
    url: Url,
    body: Option<String>,
) -> RequestBuilder {
    let rb = client.request(method, url);
    let rb = apply_headers_ua_cookies_inner(rb, target, None, true);
    if let Some(b) = body { rb.body(b) } else { rb }
}

/// Build a RequestBuilder with an explicit Cookie header override.
/// If `cookie_header` is Some(string), it will be used regardless of target.headers/target.cookies.
/// If None, behavior is identical to `build_request`.
pub(crate) fn build_request_with_cookie(
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

/// Set `name: value`, *replacing* any value already staged under that name.
///
/// reqwest's `RequestBuilder::header()` appends (`HeaderMap::append`), so every
/// site in this file that means "override" used to leave the earlier value on
/// the wire as the **first** of two. That is not cosmetic for a scanner: a
/// server that reads the first value of a repeated header never sees the
/// injected one, so the payload silently never arrives and the parameter reads
/// as clean. `RequestBuilder::headers()` runs reqwest's `replace_headers`,
/// which is insert-per-name — the real override.
///
/// A name or value reqwest cannot parse falls back to `.header()`, which
/// records the same builder error the caller used to get at `send()` time
/// rather than dropping the header silently.
fn set_header(rb: RequestBuilder, name: &str, value: &str) -> RequestBuilder {
    match (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        (Ok(n), Ok(v)) => {
            let mut map = HeaderMap::with_capacity(1);
            map.insert(n, v);
            rb.headers(map)
        }
        _ => rb.header(name, value),
    }
}

/// Apply arbitrary header overrides on top of an existing RequestBuilder (late binding).
///
/// Each entry *replaces* any same-named value already staged by `target.headers`
/// or the UA/Cookie defaults, so the injected or probed value is the only one on
/// the wire. Repeating a name within `overrides` keeps the last entry, matching
/// override semantics. See [`set_header`] for why replacement rather than
/// reqwest's default append.
pub(crate) fn apply_header_overrides(
    mut rb: RequestBuilder,
    overrides: &[(String, String)],
) -> RequestBuilder {
    for (k, v) in overrides {
        rb = set_header(rb, k, v);
    }
    rb
}

// Header parsing: splitn(2, ':') with both sides trim
pub(crate) fn parse_header_line(line: &str) -> Option<(String, String)> {
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
#[cfg(test)]
pub(crate) fn parse_headers(lines: &[String]) -> Vec<(String, String)> {
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
pub(crate) fn content_type_primary(ct: &str) -> Option<String> {
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

/// Allow-list check for response types that use an HTML document parser.
/// XHTML is included because its namespace-aware XML document has active HTML
/// elements; generic XML, feeds, and SVG use different parsers/types.
#[inline]
pub(crate) fn is_htmlish_content_type(ct: &str) -> bool {
    let Some(primary) = content_type_primary(ct) else {
        return false;
    };
    if primary == "text/html" {
        return true;
    }
    primary == "application/xhtml+xml"
}

/// Whether the supplied MIME type uses an XML parser when navigated.
#[inline]
pub(crate) fn is_xml_content_type(ct: &str) -> bool {
    let Some(primary) = content_type_primary(ct) else {
        return false;
    };
    primary == "application/xml"
        || primary == "text/xml"
        || primary
            .split_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+xml"))
}

const XHTML_NAMESPACE: &str = "http://www.w3.org/1999/xhtml";
const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";

/// Whether the bytes would create an active markup document when opened as a
/// top-level browser navigation. Content-Type alone is insufficient for
/// missing/invalid types, while XML types must be parsed as XML rather than
/// recovered as HTML by scraper.
pub(crate) fn response_has_markup_document(ct: &str, body: &str) -> bool {
    match content_type_primary(ct).as_deref() {
        Some("text/html") => true,
        Some("application/xhtml+xml") => xml_root_is(body, XHTML_NAMESPACE, "html"),
        Some("image/svg+xml") => xml_root_is(body, SVG_NAMESPACE, "svg"),
        Some(primary) if is_xml_content_type(primary) => xml_has_active_markup(body),
        Some("unknown/unknown" | "application/unknown" | "*/*") => body_sniffs_as_html(body),
        Some(_) => false,
        None => body_sniffs_as_html(body),
    }
}

fn xml_root_is(body: &str, namespace: &str, local_name: &str) -> bool {
    let Ok(document) = roxmltree::Document::parse(body) else {
        return false;
    };
    let root = document.root_element().tag_name();
    root.namespace() == Some(namespace) && root.name() == local_name
}

fn xml_has_active_markup(body: &str) -> bool {
    let Ok(document) = roxmltree::Document::parse(body) else {
        return false;
    };
    document.descendants().any(|node| {
        matches!(
            node.tag_name().namespace(),
            Some(XHTML_NAMESPACE | SVG_NAMESPACE)
        )
    })
}

/// Match the HTML signatures used when a browsing context sniffs a response
/// with no valid supplied MIME type. In particular, a JSON object containing
/// `<svg…>` later in a string is not sniffed as HTML, and a bare `<svg>` is not
/// one of the HTML signatures.
fn body_sniffs_as_html(body: &str) -> bool {
    const SIGNATURES: &[&[u8]] = &[
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<script",
        b"<iframe",
        b"<h1",
        b"<div",
        b"<font",
        b"<table",
        b"<a",
        b"<style",
        b"<title",
        b"<b",
        b"<body",
        b"<br",
        b"<p",
        b"<!--",
    ];
    let header = &body.as_bytes()[..body.len().min(1445)];
    let mut start = 0;
    while header
        .get(start)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
    {
        start += 1;
    }
    let header = &header[start..];
    SIGNATURES.iter().any(|signature| {
        header
            .get(..signature.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(signature))
            && header
                .get(signature.len())
                .is_some_and(|byte| matches!(*byte, b' ' | b'>'))
    })
}

/// True when a response Content-Type declares an executable-JavaScript body
/// (`application/javascript`, `text/javascript`, ECMAScript aliases). A browser
/// runs these as script — it never parses the body as an HTML document — so an
/// HTML tag reflected into such a response is inert as markup: `<svg onload=…>`
/// echoed into a JS body is a syntax error, not a rendered element. Only a
/// payload that executes *as JavaScript* (e.g. a JSONP callback name) is
/// exploitable there.
///
/// Deliberately excludes `text/plain` and empty/missing types: the former is
/// never parsed as HTML for a top-level navigation, while the latter can only
/// be classified after checking whether its body matches an HTML sniffing
/// signature.
#[inline]
pub(crate) fn is_javascript_content_type(ct: &str) -> bool {
    let Some(primary) = content_type_primary(ct) else {
        return false;
    };
    matches!(
        primary.as_str(),
        "application/javascript"
            | "text/javascript"
            | "application/ecmascript"
            | "text/ecmascript"
            | "application/x-javascript"
    )
}

/// Allow-list check for content types that are still worth scanning for XSS,
/// even when they are not directly HTML documents.
///
/// This is intentionally broader than `is_htmlish_content_type` because
/// JSONP, raw JSON fragments, SVG, generic XML, and plain-text endpoints are
/// useful scan surfaces. Later finding gates decide whether the response can
/// execute in the relevant browser context.
pub(crate) fn is_xss_scannable_content_type(ct: &str) -> bool {
    if is_htmlish_content_type(ct) || is_xml_content_type(ct) {
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
            // Plain-text endpoints remain useful scan surfaces; body-aware
            // finding gates suppress them as markup documents.
            | "text/plain"
    )
}

/// True when a response Content-Type renders as inert *data* in a browser —
/// navigating to it never parses the body as markup or executes it as a
/// script, so a payload reflected into the body is not exploitable as
/// reflected XSS regardless of the injection context inside it.
///
/// Deliberately a tight deny-list of structured-data / XML / binary types
/// (`application/json`, `text/csv`, `application/octet-stream`, fonts, raw
/// media) rather than the inverse of the HTML allow-list, because the grey
/// zone must stay *scannable* to avoid false negatives:
///   * `application/javascript` / `text/javascript` — a reflected callback
///     name is executable when the response is loaded via `<script src>`
///     (JSONP injection), so these are NOT inert.
///   * `text/plain` is handled after reading the body so browser behavior stays
///     explicit at the caller; a supplied text/plain type is never sniffed into
///     HTML, regardless of `X-Content-Type-Options`.
///   * empty / missing Content-Type is body-dependent: recognized HTML
///     signatures are sniffed as HTML, while JSON and ordinary text are not.
pub(crate) fn content_type_is_inert_data(ct: &str) -> bool {
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

/// Same as [`content_type_is_inert_data`], plus `text/plain`.
///
/// Split from the plain version because that list is also consulted where a
/// `text/plain` response still has to be treated as live (it is the
/// caller-supplied type of an unparsed body, not a rendered document).
///
/// This deliberately takes no `nosniff` argument. It used to, and the header is
/// *not* what makes `text/plain` inert. Per the MIME Sniffing
/// standard, sniffing can only produce `text/html` when the supplied type is
/// absent or one of `unknown/unknown` / `application/unknown` / `*/*`. A
/// supplied `text/plain` either trips the check-for-apache-bug flag — whose
/// "text or binary" rules yield only `text/plain` or
/// `application/octet-stream` — or is returned unchanged. There is no path
/// from a supplied `text/plain` to an HTML parse, with or without the header.
///
/// Confirmed against real Chrome (headless, `--dump-dom`) serving the same
/// `<h1 id=marker>` + `<script>` body five ways: `text/html` parsed it;
/// `text/plain`, `text/plain; charset=utf-8`,
/// `text/plain; charset=windows-1252`, and `text/plain` + `nosniff` all did
/// not. XSSMaze's three `text/plain` endpoints are all `exploitable: false`
/// controls, and `realworld-level6` — which reflects markup raw — says the
/// same thing in its own metadata: "no modern browser sniffs [it] into HTML,
/// so it never parses; reporting no XSS here is the correct result". Before
/// this, dalfox reported `[V] High` on it.
///
/// An absent or empty content-type is deliberately still treated as live: that
/// is exactly the case the standard *does* sniff, so the same reasoning does
/// not carry over.
pub(crate) fn content_type_is_never_markup(ct: &str) -> bool {
    if content_type_is_inert_data(ct) {
        return true;
    }
    matches!(content_type_primary(ct).as_deref(), Some("text/plain"))
}

/// Build a preflight request for content-type detection.
/// - If `prefer_head` is true, uses HEAD; otherwise GET.
/// - When using GET and `range_bytes` is Some(n), adds `Range: bytes=0-(n-1)`
///   to minimize transfer size while still allowing meta tag parsing if needed.
pub(crate) fn build_preflight_request(
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
                // A `Retry-After: 0` or a past HTTP-date parses to `Some(0)`.
                // Honoring it verbatim would sleep 0ms and re-send immediately,
                // turning each 429 into a back-to-back retry burst (up to
                // MAX_429_RETRIES) against an already-overloaded server — the
                // opposite of the backoff this exists to provide. Treat a
                // non-positive hint as "no usable hint" and use exponential
                // backoff instead.
                .filter(|&v| v > 0)
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
/// Send a request, counting a transport failure if it never answers.
///
/// The discovery and mining stages send directly rather than through
/// [`send_with_retry`], and every one of those call sites drops the `Err`
/// (`if let Ok(resp) = …`, `.ok()?`). A parameter whose probe was reset is
/// then indistinguishable from a parameter that does not reflect — so a target
/// that drops requests yields an empty finding list that reads as a verdict.
/// Counting here keeps `failed_requests` aligned with the `total_requests`
/// these stages already tick via `record_outbound_request`.
pub async fn send_counted(
    request_builder: RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let result = request_builder.send().await;
    if result.is_err() {
        crate::tick_request_failure();
    }
    result
}

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
            RetryDecision::Stop => {
                // The retry budget is spent. A request that never produced a
                // response means whatever it carried was never actually tested,
                // and every caller drops the `Err` — so count it here, once,
                // where the give-up decision is made.
                if result.is_err() {
                    crate::tick_request_failure();
                }
                return result;
            }
            RetryDecision::Sleep { ms, rate_limited } => {
                let Some(rb) = next_rb else {
                    // Body was streamed; can't replay the request.
                    if result.is_err() {
                        crate::tick_request_failure();
                    }
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
///
/// NOTE: unlike [`reqwest::Response::text`], this does NOT honor a non-UTF-8
/// `Content-Type` charset label — it always decodes as UTF-8 (lossy). That is
/// intentional (the cap streams raw bytes), and harmless for ASCII markers /
/// payloads, but bytes 0x80–0xFF on a declared Latin-1 / Shift-JIS page become
/// `U+FFFD` here where `text()` would have transcoded them. Modern targets are
/// overwhelmingly UTF-8, so detection impact is negligible.
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
