//! # Stage 5: Reflection Check
//!
//! Determines whether a specific payload string appears in the HTTP response,
//! accounting for server-side transformations (HTML-entity encoding, URL
//! encoding, etc.).
//!
//! **Input:** `(Param, payload: &str)` — a single parameter + candidate payload.
//!
//! **Output:** `(Option<ReflectionKind>, Option<String>)` — the kind of
//! reflection detected (Raw, HtmlEntityDecoded, UrlDecoded, HtmlThenUrlDecoded)
//! and the response body text. `None` kind means no reflection found.
//!
//! **Side effects:** One HTTP request per call (with rate-limit retry).
//! Applies `pre_encoding` from the `Param` before sending. Checks response
//! against the *raw* (unencoded) payload. Suppresses reflection inside safe
//! tags (textarea, noscript, style, xmp, plaintext, title).

use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use regex::Regex;
use reqwest::Client;
use std::sync::OnceLock;
use tokio::time::{Duration, sleep};

/// Re-export for callers outside this module (e.g. DOM verification, active probing).
pub use crate::encoding::pre_encoding::apply_pre_encoding;

/// Maximum number of iterative URL-decode passes when building payload variants.
const MAX_URL_DECODE_ITERATIONS: usize = 4;

/// Check whether *all* occurrences of `payload` in `html` fall inside safe tags
/// (textarea, noscript, style, xmp, plaintext, title).  If the payload appears
/// at least once outside a safe tag, returns `false`.
///
/// Uses a simple tag-stack approach on the raw HTML for reliability, because DOM
/// parsers like `scraper` may normalize text content inside raw-text elements.
/// Find `needle` in `haystack` using ASCII case-insensitive comparison,
/// starting from byte offset `from`. Returns the byte offset of the match.
fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from + needle.len() > haystack.len() {
        return None;
    }
    let end = haystack.len() - needle.len();
    let first = needle[0].to_ascii_lowercase();
    let mut i = from;
    while i <= end {
        if haystack[i].to_ascii_lowercase() == first
            && haystack[i..i + needle.len()]
                .iter()
                .zip(needle)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Pre-computed safe tag patterns: (open_tag_prefix, close_tag)
/// e.g. ("textarea" → (b"<textarea", b"</textarea>"))
const SAFE_TAG_PATTERNS: &[(&[u8], &[u8])] = &[
    (b"<textarea", b"</textarea>"),
    (b"<noscript", b"</noscript>"),
    (b"<xmp", b"</xmp>"),
    (b"<plaintext", b"</plaintext>"),
    (b"<title", b"</title>"),
];

fn is_in_safe_context(html: &str, payload: &str) -> bool {
    // Quick check: payload must be present
    if !html.contains(payload) {
        return true; // nothing reflected, vacuously safe
    }

    let html_bytes = html.as_bytes();

    // Build safe-context ranges by scanning for opening/closing safe tags
    let mut safe_ranges: Vec<(usize, usize)> = Vec::new();
    for &(open_pattern, close_pattern) in SAFE_TAG_PATTERNS {
        let mut search_pos = 0;
        while let Some(open_start) =
            find_ascii_case_insensitive(html_bytes, open_pattern, search_pos)
        {
            // Find the end of the opening tag '>'
            if let Some(tag_end_offset) = html[open_start..].find('>') {
                let content_start = open_start + tag_end_offset + 1;
                // Find closing tag (case-insensitive)
                if let Some(close_start) =
                    find_ascii_case_insensitive(html_bytes, close_pattern, content_start)
                {
                    safe_ranges.push((content_start, close_start));
                    search_pos = close_start + close_pattern.len();
                } else {
                    // No closing tag found, rest of document is in safe context
                    safe_ranges.push((content_start, html.len()));
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Check every occurrence of the payload
    let payload_len = payload.len();
    let mut search_start = 0;
    while let Some(pos) = html[search_start..].find(payload) {
        let abs_pos = search_start + pos;
        let in_safe = safe_ranges
            .iter()
            .any(|&(start, end)| abs_pos >= start && abs_pos + payload_len <= end);
        if !in_safe {
            return false; // at least one occurrence is outside safe context
        }
        search_start = abs_pos + 1;
    }

    true
}

/// Like `is_in_safe_context` but also checks decoded forms of the payload.
/// This catches cases where an encoded payload (URL/HTML-entity) is sent,
/// the server decodes it, and reflects the decoded form inside a safe tag.
fn is_in_safe_context_decoded(html: &str, payload: &str) -> bool {
    // Check the raw payload form (only if it's actually present in the HTML)
    if html.contains(payload) && is_in_safe_context(html, payload) {
        return true;
    }
    // Check URL-decoded form
    if let Ok(url_decoded) = urlencoding::decode(payload)
        && url_decoded != payload
        && html.contains(url_decoded.as_ref())
        && is_in_safe_context(html, &url_decoded)
    {
        return true;
    }
    // Check HTML-entity-decoded form
    let html_decoded = decode_html_entities(payload);
    if html_decoded != payload
        && html.contains(&html_decoded)
        && is_in_safe_context(html, &html_decoded)
    {
        return true;
    }
    // Inert reflection inside <script> blocks: the payload is reflected only
    // inside script source where HTML entities don't decode and the AST shows
    // the reflection produces no sink call — therefore not exploitable.
    if is_payload_inert_in_scripts(html, payload) {
        return true;
    }
    false
}

/// True when a path-segment parameter's "reflection" should be ignored because
/// it came from a non-2xx response. Error pages frequently echo the requested
/// URL/path verbatim, producing reflections that don't represent real
/// injection points.
fn should_suppress_path_reflection(location: &Location, status_code: u16) -> bool {
    matches!(location, Location::Path) && !(200..300).contains(&status_code)
}

/// Find every `<script>...</script>` byte range in `html`. Used by the
/// safe-context heuristic for entity-encoded reflections.
fn script_block_ranges(html: &str) -> Vec<(usize, usize)> {
    let bytes = html.as_bytes();
    let open = b"<script";
    let close = b"</script>";
    let mut ranges = Vec::new();
    let mut search = 0;
    while let Some(start) = find_ascii_case_insensitive(bytes, open, search) {
        // Find the end of the opening tag '>'
        let Some(rel) = html[start..].find('>') else {
            break;
        };
        let content_start = start + rel + 1;
        match find_ascii_case_insensitive(bytes, close, content_start) {
            Some(end) => {
                ranges.push((content_start, end));
                search = end + close.len();
            }
            None => {
                ranges.push((content_start, html.len()));
                break;
            }
        }
    }
    ranges
}

/// Helper: every occurrence of `needle` in `haystack` falls inside one of the
/// supplied byte ranges.
fn all_occurrences_in_ranges(haystack: &str, needle: &str, ranges: &[(usize, usize)]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let needle_len = needle.len();
    let mut search = 0;
    let mut found_any = false;
    while let Some(rel) = haystack[search..].find(needle) {
        let abs = search + rel;
        let in_range = ranges
            .iter()
            .any(|&(s, e)| abs >= s && abs + needle_len <= e);
        if !in_range {
            return false;
        }
        found_any = true;
        search = abs + 1;
    }
    found_any
}

/// True when the payload is reflected only inside `<script>...</script>` blocks
/// (either as raw bytes or via HTML-entity encoding such as `&lt;` for `<`)
/// AND the parsed JS introduces no sink call within the payload's byte range.
/// Such reflections render as inert JavaScript text (e.g. `var x = '&#x27;…'`
/// or `var x = "&lt;img onerror=alert(1)>"`) and are not exploitable, so they
/// should not be reported as Reflected.
fn is_payload_inert_in_scripts(html: &str, payload: &str) -> bool {
    if payload.is_empty() {
        return false;
    }
    let ranges = script_block_ranges(html);
    if ranges.is_empty() {
        return false;
    }

    // Pre-compute decoded views of script-block content vs everything else.
    let mut script_decoded = String::new();
    for &(s, e) in &ranges {
        script_decoded.push_str(&decode_html_entities(&html[s..e]));
        script_decoded.push('\n');
    }
    let mut non_script = String::new();
    let mut prev = 0;
    for &(s, e) in &ranges {
        non_script.push_str(&html[prev..s]);
        prev = e;
    }
    non_script.push_str(&html[prev..]);
    let non_script_decoded = decode_html_entities(&non_script);

    // Build the candidate "what to look for" set: the raw payload and its
    // URL-decoded form. Encoder policy frequently produces URL-encoded
    // payloads (`%27-alert%281%29-%27`) which the server decodes once before
    // reflecting — the literal needle in the response is the decoded form.
    let mut candidates: Vec<String> = vec![payload.to_string()];
    if let Ok(url_dec) = urlencoding::decode(payload) {
        let url_dec_owned: String = url_dec.into_owned();
        if url_dec_owned != payload {
            candidates.push(url_dec_owned);
        }
    }

    let mut matched = false;
    for cand in &candidates {
        // Path A: candidate appears verbatim — all raw occurrences inside scripts.
        let raw_only_in_scripts =
            html.contains(cand.as_str()) && all_occurrences_in_ranges(html, cand, &ranges);
        // Path B: candidate appears only after HTML-entity decoding.
        let decoded_only_in_scripts =
            script_decoded.contains(cand.as_str()) && !non_script_decoded.contains(cand.as_str());
        if raw_only_in_scripts || decoded_only_in_scripts {
            matched = true;
            break;
        }
    }
    if !matched {
        return false;
    }

    // Confirm the AST sees no sink call introduced by any candidate form of
    // the payload — otherwise the reflection IS exploitable and must keep R/V.
    !candidates
        .iter()
        .any(|cand| crate::scanning::js_context_verify::has_js_context_evidence(cand, html))
}

static ENTITY_REGEX: OnceLock<Regex> = OnceLock::new();
static NAMED_ENTITY_REGEX: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectionKind {
    Raw,
    HtmlEntityDecoded,
    UrlDecoded,
    HtmlThenUrlDecoded,
}

/// Decode a subset of HTML entities (numeric dec & hex) for reflection normalization.
/// Examples:
///   "&#x3c;script&#x3e;" -> "<script>"
///   "&#60;alert(1)&#62;"  -> "<alert(1)>"
fn decode_html_entities(input: &str) -> String {
    // Match patterns like &#xHH; or &#xHHHH; or &#DDDD; (hex 'x' is case-insensitive)
    // We purposely limit to reasonable length to avoid catastrophic replacements.
    let re = ENTITY_REGEX.get_or_init(|| {
        Regex::new(r"&#([xX][0-9a-fA-F]{2,6}|[0-9]{2,6});")
            .expect("entity regex pattern must be valid")
    });
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.find_iter(input) {
        out.push_str(&input[last..m.start()]);
        let entity = &input[m.start() + 2..m.end() - 1]; // strip &# and ;
        let decoded = if entity.starts_with('x') || entity.starts_with('X') {
            let hex = &entity[1..];
            u32::from_str_radix(hex, 16)
                .ok()
                .and_then(std::char::from_u32)
                .unwrap_or('\u{FFFD}')
        } else {
            entity
                .parse::<u32>()
                .ok()
                .and_then(std::char::from_u32)
                .unwrap_or('\u{FFFD}')
        };
        out.push(decoded);
        last = m.end();
    }
    out.push_str(&input[last..]);

    // Handle a minimal set of named entities commonly encountered in XSS contexts.
    // Keep decoding narrow but case-insensitive (e.g., &LT; / &Lt;).
    let named_re = NAMED_ENTITY_REGEX.get_or_init(|| {
        Regex::new(r"(?i)&(?:lt|gt|amp|quot|apos);")
            .expect("named entity regex pattern must be valid")
    });
    named_re
        .replace_all(&out, |caps: &regex::Captures| {
            match caps[0].to_ascii_lowercase().as_str() {
                "&lt;" => "<",
                "&gt;" => ">",
                "&amp;" => "&",
                "&quot;" => "\"",
                "&apos;" => "'",
                _ => "",
            }
        })
        .to_string()
}

/// Decode form-style URL-encoded text where spaces may be preserved as '+'.
/// This is intentionally narrow and only used for reflection normalization.
fn decode_form_urlencoded_like(input: &str) -> Option<String> {
    let normalized = input.replace('+', "%20");
    let decoded = urlencoding::decode(&normalized).ok()?.into_owned();
    if decoded == input {
        None
    } else {
        Some(decoded)
    }
}

fn payload_variants(payload: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(10);
    let mut seen = std::collections::HashSet::with_capacity(10);
    let owned_payload = payload.to_string();
    seen.insert(owned_payload.clone());
    variants.push(owned_payload);

    let html_dec = decode_html_entities(payload);
    if !seen.contains(&html_dec) {
        seen.insert(html_dec.clone());
        variants.push(html_dec);
    }

    let seeds_count = variants.len();
    for i in 0..seeds_count {
        let mut current = variants[i].clone();
        for _ in 0..MAX_URL_DECODE_ITERATIONS {
            let Ok(url_dec) = urlencoding::decode(&current) else {
                break;
            };
            let url_dec = url_dec.into_owned();
            if url_dec == current {
                break;
            }
            if !seen.contains(&url_dec) {
                seen.insert(url_dec.clone());
                variants.push(url_dec.clone());
            }
            current = url_dec;
        }
    }

    variants
}

/// Returns true when at least one occurrence of a payload variant (raw or
/// HTML-entity-decoded form) sits inside a context where HTML entity
/// escaping is *not* sufficient to neutralize the injection — namely
/// `<script>` / `<style>` raw-text content or an HTML event-handler
/// attribute (`on*=…`). When this returns `false`, the entity-escaped
/// reflection is safe by construction and can be suppressed.
fn html_entity_reflection_in_unsafe_context(html: &str, variants: &[String]) -> bool {
    static SCRIPT_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_RE: OnceLock<Regex> = OnceLock::new();
    static EVENT_HANDLER_RE: OnceLock<Regex> = OnceLock::new();

    let script_re = SCRIPT_RE
        .get_or_init(|| Regex::new(r"(?is)<script\b[^>]*>(.*?)</script\s*>").expect("script regex"));
    let style_re = STYLE_RE
        .get_or_init(|| Regex::new(r"(?is)<style\b[^>]*>(.*?)</style\s*>").expect("style regex"));
    let event_re = EVENT_HANDLER_RE.get_or_init(|| {
        Regex::new(r#"(?is)\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#)
            .expect("event handler regex")
    });

    let check_body = |body: &str| -> bool {
        let decoded = decode_html_entities(body);
        variants
            .iter()
            .any(|v| body.contains(v) || decoded.contains(v))
    };

    for cap in script_re.captures_iter(html) {
        if let Some(body) = cap.get(1)
            && check_body(body.as_str())
        {
            return true;
        }
    }
    for cap in style_re.captures_iter(html) {
        if let Some(body) = cap.get(1)
            && check_body(body.as_str())
        {
            return true;
        }
    }
    for cap in event_re.captures_iter(html) {
        if let Some(val) = cap.get(1) {
            let raw = val.as_str();
            let inner = match raw.as_bytes() {
                [b'"', .., b'"'] | [b'\'', .., b'\''] => &raw[1..raw.len() - 1],
                _ => raw,
            };
            if check_body(inner) {
                return true;
            }
        }
    }
    false
}

/// Determine if payload is reflected in any normalization variant.
pub(crate) fn classify_reflection(resp_text: &str, payload: &str) -> Option<ReflectionKind> {
    // Direct match first (fast path — avoids payload_variants allocation)
    if resp_text.contains(payload) {
        return Some(ReflectionKind::Raw);
    }

    // Only build variant list when the fast path misses
    let payload_variants = payload_variants(payload);

    // Non-raw payload variant present directly in the raw response — the
    // server applied URL or HTML-entity decoding before reflecting. Without
    // this fast path the entity-decoded check below would wrongly classify
    // a server-side URL-decoded reflection (response holds the raw form)
    // as `HtmlEntityDecoded` and then suppress it as safe escape, hiding a
    // genuine reflection. `skip(1)` skips the original payload (already
    // handled by the raw-match fast path above).
    if payload_variants
        .iter()
        .skip(1)
        .any(|variant| resp_text.contains(variant))
    {
        return Some(ReflectionKind::UrlDecoded);
    }

    let html_dec = decode_html_entities(resp_text);
    // Only treat as an entity-decoded reflection when the response actually
    // changed under entity decoding. The previous predicate (variant present
    // in `html_dec`) is true even when no entities were decoded — in which
    // case `html_dec == resp_text` and the match is really a raw match.
    if html_dec != resp_text
        && payload_variants
            .iter()
            .any(|candidate| html_dec.contains(candidate))
    {
        // The payload only appears after HTML-entity decoding — the server
        // applied entity escaping to the reflection. In ordinary HTML body
        // / attribute-value context, the browser will keep the entities as
        // literal characters and the payload cannot escape into executable
        // code. We demote (return `None`) for those reflections so they no
        // longer surface as R Info findings, mirroring the established rule
        // that a properly escaped reflection is not a vulnerability.
        //
        // We keep the finding when the entity-encoded reflection lands in a
        // context where escaping is *not* sufficient:
        // - inside `<script>` / `<style>` raw-text content (JS/CSS parsers
        //   do not decode HTML entities, but the source still passes
        //   through the parser and the entities can interact with parsing
        //   in surprising ways — keep as a signal for manual review),
        // - inside an HTML event-handler attribute value (`on*=…`) where
        //   the browser decodes the entities while building the value
        //   *before* handing it to the JS parser.
        if html_entity_reflection_in_unsafe_context(resp_text, &payload_variants) {
            return Some(ReflectionKind::HtmlEntityDecoded);
        }
        // Fall through: check URL-decoded variants — an entity-escape on
        // one occurrence does not rule out a different reflection point
        // reached via URL decoding alone.
    }

    // Check URL decoded version of raw
    if let Ok(url_dec) = urlencoding::decode(resp_text)
        && url_dec != resp_text
        && payload_variants
            .iter()
            .any(|candidate| url_dec.contains(candidate))
    {
        return Some(ReflectionKind::UrlDecoded);
    }

    // Check URL decoded version of HTML decoded
    if let Ok(url_dec_html) = urlencoding::decode(&html_dec)
        && url_dec_html != html_dec
        && payload_variants
            .iter()
            .any(|candidate| url_dec_html.contains(candidate))
    {
        return Some(ReflectionKind::HtmlThenUrlDecoded);
    }

    if let Some(form_dec) = decode_form_urlencoded_like(resp_text)
        && payload_variants
            .iter()
            .any(|candidate| form_dec.contains(candidate))
    {
        return Some(ReflectionKind::UrlDecoded);
    }

    if let Some(form_dec_html) = decode_form_urlencoded_like(&html_dec)
        && payload_variants
            .iter()
            .any(|candidate| form_dec_html.contains(candidate))
    {
        return Some(ReflectionKind::HtmlThenUrlDecoded);
    }

    None
}

/// Resolve SXSS check URLs with priority:
/// 1. --sxss-url (explicit) -> single URL
/// 2. param.form_origin_url -> page where form was discovered
/// 3. param.form_action_url -> form action (GET to check stored output)
/// 4. target.url -> fallback
///
/// Deduplicates URLs to avoid redundant checks.
pub(crate) fn resolve_sxss_check_urls(
    target: &Target,
    param: &Param,
    args: &crate::cmd::scan::ScanArgs,
) -> Vec<url::Url> {
    let mut seen = std::collections::HashSet::new();
    let mut urls = Vec::new();

    // 1. Explicit --sxss-url takes highest priority
    if let Some(ref sxss_url_str) = args.sxss_url
        && let Ok(u) = url::Url::parse(sxss_url_str)
    {
        let s = u.to_string();
        if seen.insert(s) {
            urls.push(u);
        }
    }

    // 2. form_origin_url - page where form was discovered
    if let Some(ref origin) = param.form_origin_url
        && let Ok(u) = url::Url::parse(origin)
    {
        let s = u.to_string();
        if seen.insert(s) {
            urls.push(u);
        }
    }

    // 3. form_action_url - form action endpoint (GET to check stored output)
    if let Some(ref action) = param.form_action_url
        && let Ok(u) = url::Url::parse(action)
    {
        let s = u.to_string();
        if seen.insert(s) {
            urls.push(u);
        }
    }

    // 4. target.url as fallback
    {
        let s = target.url.to_string();
        if seen.insert(s) {
            urls.push(target.url.clone());
        }
    }

    urls
}

async fn fetch_injection_response(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> Option<String> {
    if args.skip_xss_scanning {
        return None;
    }
    let client = target.build_client_or_default();
    fetch_injection_response_with_client(&client, target, param, payload, args).await
}

async fn fetch_injection_response_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> Option<String> {
    if args.skip_xss_scanning {
        return None;
    }

    // Apply pre-encoding if the parameter requires it (e.g. base64, 2base64)
    // Use encoded_payload for building the HTTP request, but keep `payload`
    // (the raw/original payload) for response body analysis — the server
    // decodes the encoding and reflects the raw content.
    let encoded_payload = crate::encoding::pre_encoding::apply_param_encoding(payload, param);

    // Build injection request based on parameter location
    let default_method = target.parse_method();
    let inject_request = match param.location {
        Location::Header => {
            // Header injection: use original URL, inject payload as the header value
            let parsed_url = target.url.clone();
            let rb = crate::utils::build_request(
                client,
                target,
                default_method,
                parsed_url,
                target.data.clone(),
            );
            // Override/add the header with the encoded payload value
            crate::utils::apply_header_overrides(
                rb,
                &[(param.name.clone(), encoded_payload.to_string())],
            )
        }
        Location::Body => {
            // Body injection: use form action URL if available, else original URL
            // Force POST for body params even if the original target method was GET
            let method = reqwest::Method::POST;
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let body = if let Some(ref data) = target.data {
                let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(data.as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                let mut found = false;
                for pair in &mut pairs {
                    if pair.0 == param.name {
                        pair.1 = encoded_payload.to_string();
                        found = true;
                        break;
                    }
                }
                if !found {
                    pairs.push((param.name.clone(), encoded_payload.to_string()));
                }
                Some(
                    url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(&pairs)
                        .finish(),
                )
            } else {
                Some(format!(
                    "{}={}",
                    urlencoding::encode(&param.name),
                    urlencoding::encode(&encoded_payload)
                ))
            };
            let rb = crate::utils::build_request(client, target, method, parsed_url, body);
            rb.header("Content-Type", "application/x-www-form-urlencoded")
        }
        Location::JsonBody => {
            // JSON body injection: use form action URL if available, else original URL
            // Force POST for JSON body params
            let method = reqwest::Method::POST;
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let body = if let Some(ref data) = target.data {
                // Attempt to parse as JSON and replace the param value
                if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(obj) = json_val.as_object_mut() {
                        obj.insert(
                            param.name.clone(),
                            serde_json::Value::String(encoded_payload.to_string()),
                        );
                    }
                    Some(serde_json::to_string(&json_val).unwrap_or_else(|_| data.clone()))
                } else {
                    // Fallback: simple string replacement of the param's original value
                    Some(data.replace(&param.value, &encoded_payload))
                }
            } else {
                Some(serde_json::json!({ &param.name: &*encoded_payload }).to_string())
            };
            let rb = crate::utils::build_request(client, target, method, parsed_url, body);
            rb.header("Content-Type", "application/json")
        }
        Location::MultipartBody => {
            let method = reqwest::Method::POST;
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let mut form = reqwest::multipart::Form::new();
            if let Some(ref data) = target.data {
                for pair in data.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let k = urlencoding::decode(k)
                            .unwrap_or(std::borrow::Cow::Borrowed(k))
                            .to_string();
                        let v = urlencoding::decode(v)
                            .unwrap_or(std::borrow::Cow::Borrowed(v))
                            .to_string();
                        if k == param.name {
                            form = form.text(k, encoded_payload.to_string());
                        } else {
                            form = form.text(k, v);
                        }
                    }
                }
            } else {
                form = form.text(param.name.clone(), encoded_payload.to_string());
            }
            crate::utils::build_request(client, target, method, parsed_url, None).multipart(form)
        }
        _ => {
            // Query / Path: inject encoded payload into the URL
            let inject_url = crate::scanning::url_inject::build_injected_url(
                &target.url,
                param,
                &encoded_payload,
            );
            let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| target.url.clone());
            crate::utils::build_request(
                client,
                target,
                default_method,
                parsed_url,
                target.data.clone(),
            )
        }
    };

    // Send the injection request (with rate-limit retry)
    let inject_resp = crate::utils::send_with_retry(inject_request, 3, 5000).await;
    crate::tick_request_count();

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    // For Stored XSS, check reflection on auto-resolved URLs with retry logic
    if args.sxss {
        let check_urls = resolve_sxss_check_urls(target, param, args);
        let retries = args.sxss_retries.max(1) as u64;
        for sxss_url in &check_urls {
            // Retry with delay to handle session / content propagation
            for attempt in 0u64..retries {
                if attempt > 0 {
                    sleep(Duration::from_millis(500 * attempt)).await;
                }
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(client, target, method, sxss_url.clone(), None);

                crate::tick_request_count();
                if let Ok(resp) = check_request.send().await
                    && let Ok(text) = resp.text().await
                    && !text.is_empty()
                {
                    return Some(text);
                }
            }
        }
        None
    } else {
        // Normal reflection check
        if let Ok(resp) = inject_resp {
            let status_code = resp.status().as_u16();

            // Track WAF block status codes for adaptive throttling. The
            // consecutive counter is per-scan when bound (MCP / REST runners)
            // so one scan's WAF blocks don't slow down unrelated concurrent
            // scans; CLI falls back to the process-wide counter.
            let is_waf_block = status_code == 403
                || status_code == 406
                || status_code == 429
                || status_code == 503;
            if is_waf_block {
                let consecutive = crate::tick_waf_block();
                // Apply adaptive backoff when consecutive blocks exceed threshold
                if consecutive >= 3 {
                    let escalation = (consecutive - 3).min(4) as u64;
                    let backoff_ms = 2000u64 * (1u64 << escalation);
                    let backoff_ms = backoff_ms.min(30_000);
                    sleep(Duration::from_millis(backoff_ms)).await;
                }
            } else {
                // Reset consecutive block counter on successful response
                crate::reset_waf_consecutive();
            }
            // Per-target bypass effectiveness telemetry. Only counts when
            // bypass is active for the target (target.mutation_stats is
            // populated during preflight when WAF detected and bypass on).
            if let Some(ref stats) = target.mutation_stats {
                stats.record_request(is_waf_block);
            }

            // Skip processing if the status code is in the ignore_return list
            if !args.ignore_return.is_empty() && args.ignore_return.contains(&status_code) {
                return None;
            }
            // Suppress path-segment "reflections" on non-2xx responses: error
            // pages routinely echo the requested URL back, which produces noisy
            // false-positive R findings rather than real injection points.
            if should_suppress_path_reflection(&param.location, status_code) {
                if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!(
                        "[DBG] suppressing path-injection reflection on non-2xx status (param={}, status={})",
                        param.name, status_code
                    );
                }
                return None;
            }
            // Suppress path-segment "reflections" served as non-HTML content
            // types (application/javascript, application/json, etc.). Browsers
            // render those bodies as data, not HTML, so a literal payload in
            // the response is not exploitable XSS. Only Path location is
            // affected — query/header/etc. may legitimately produce JSONP
            // sinks worth reporting.
            if matches!(param.location, Location::Path) {
                let ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !ct.is_empty() && !crate::utils::is_htmlish_content_type(ct) {
                    if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                        eprintln!(
                            "[DBG] suppressing path-injection reflection on non-HTML content-type (param={}, content-type={})",
                            param.name, ct
                        );
                    }
                    return None;
                }
            }
            // Check for redirect context: if the response is a 3xx redirect,
            // the Location header may contain the reflected payload in either
            // its encoded or decoded form (some servers parse the query and
            // rebuild the redirect URL, which decodes the payload on the way).
            if resp.status().is_redirection()
                && let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
                && (location.contains(&*encoded_payload) || location.contains(payload))
            {
                // Synthesize a response text that includes the Location value
                // so reflection detection can find it
                return Some(location.to_string());
            }
            match resp.text().await {
                Ok(body) => Some(body),
                Err(e) => {
                    if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                        eprintln!(
                            "[DBG] reflection response body read failed (param={}): {}",
                            param.name, e
                        );
                    }
                    None
                }
            }
        } else {
            None
        }
    }
}

pub async fn check_reflection(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> bool {
    if let Some(text) = fetch_injection_response(target, param, payload, args).await {
        match classify_reflection(&text, payload) {
            Some(_) if is_in_safe_context_decoded(&text, payload) => false,
            Some(_) => true,
            None => false,
        }
    } else {
        false
    }
}

pub async fn check_reflection_with_response(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    if let Some(text) = fetch_injection_response(target, param, payload, args).await {
        let kind = classify_reflection(&text, payload);
        let kind = match kind {
            Some(_) if is_in_safe_context_decoded(&text, payload) => None,
            other => other,
        };
        (kind, Some(text))
    } else {
        (None, None)
    }
}

pub async fn check_reflection_with_response_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    if let Some(text) =
        fetch_injection_response_with_client(client, target, param, payload, args).await
    {
        let kind = classify_reflection(&text, payload);
        let kind = match kind {
            Some(_) if is_in_safe_context_decoded(&text, payload) => None,
            other => other,
        };
        (kind, Some(text))
    } else {
        (None, None)
    }
}

/// HPP reflection check: send a request using a pre-built HPP URL (with duplicate params)
/// and check if the payload is reflected in the response.
pub async fn check_reflection_with_hpp_url(
    client: &Client,
    target: &Target,
    _param: &Param,
    payload: &str,
    hpp_url: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    if args.skip_xss_scanning {
        return (None, None);
    }

    // HPP URL already has the encoded payload injected; we only need to
    // check if the server reflects the raw payload in the response.
    let parsed_url = url::Url::parse(hpp_url).unwrap_or_else(|_| target.url.clone());
    let default_method = target.parse_method();
    let inject_request = crate::utils::build_request(
        client,
        target,
        default_method,
        parsed_url,
        target.data.clone(),
    );

    let inject_resp = crate::utils::send_with_retry(inject_request, 3, 5000).await;
    crate::tick_request_count();

    if target.delay > 0 {
        tokio::time::sleep(Duration::from_millis(target.delay)).await;
    }

    if let Ok(resp) = inject_resp {
        // Skip processing if the status code is in the ignore_return list
        if !args.ignore_return.is_empty() && args.ignore_return.contains(&resp.status().as_u16()) {
            return (None, None);
        }
        if resp.status().is_redirection()
            && let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
            && location.contains(payload)
        {
            let kind = classify_reflection(location, payload);
            return (kind, Some(location.to_string()));
        }
        if let Ok(text) = resp.text().await {
            let kind = classify_reflection(&text, payload);
            let kind = match kind {
                Some(_) if is_in_safe_context_decoded(&text, payload) => None,
                other => other,
            };
            (kind, Some(text))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    }
}

#[cfg(test)]
mod tests;
