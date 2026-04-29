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
    let re =
        ENTITY_REGEX.get_or_init(|| Regex::new(r"&#([xX][0-9a-fA-F]{2,6}|[0-9]{2,6});").expect("entity regex pattern must be valid"));
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
    let named_re =
        NAMED_ENTITY_REGEX.get_or_init(|| Regex::new(r"(?i)&(?:lt|gt|amp|quot|apos);").expect("named entity regex pattern must be valid"));
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

/// Determine if payload is reflected in any normalization variant.
pub(crate) fn classify_reflection(resp_text: &str, payload: &str) -> Option<ReflectionKind> {
    // Direct match first (fast path — avoids payload_variants allocation)
    if resp_text.contains(payload) {
        return Some(ReflectionKind::Raw);
    }

    // Only build variant list when the fast path misses
    let payload_variants = payload_variants(payload);

    let html_dec = decode_html_entities(resp_text);
    if payload_variants
        .iter()
        .any(|candidate| html_dec.contains(candidate))
    {
        return Some(ReflectionKind::HtmlEntityDecoded);
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
    let encoded_payload = apply_pre_encoding(payload, &param.pre_encoding);

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
            crate::utils::apply_header_overrides(rb, &[(param.name.clone(), encoded_payload.to_string())])
        }
        Location::Body => {
            // Body injection: use form action URL if available, else original URL
            // Force POST for body params even if the original target method was GET
            let method = reqwest::Method::POST;
            let parsed_url = param.form_action_url
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
            let parsed_url = param.form_action_url
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
            let parsed_url = param.form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let mut form = reqwest::multipart::Form::new();
            if let Some(ref data) = target.data {
                for pair in data.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let k = urlencoding::decode(k).unwrap_or(std::borrow::Cow::Borrowed(k)).to_string();
                        let v = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string();
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
            crate::utils::build_request(client, target, method, parsed_url, None)
                .multipart(form)
        }
        _ => {
            // Query / Path: inject encoded payload into the URL
            let inject_url =
                crate::scanning::url_inject::build_injected_url(&target.url, param, &encoded_payload);
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
            if status_code == 403 || status_code == 406 || status_code == 429 || status_code == 503 {
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

            // Skip processing if the status code is in the ignore_return list
            if !args.ignore_return.is_empty()
                && args.ignore_return.contains(&status_code)
            {
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
        if !args.ignore_return.is_empty()
            && args.ignore_return.contains(&resp.status().as_u16())
        {
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
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::Target;
    use crate::target_parser::parse_target;
    use axum::{
        Router,
        extract::{Query, State},
        http::StatusCode,
        response::{Html, IntoResponse},
        routing::get,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    #[derive(Clone)]
    struct TestState {
        stored_payload: String,
    }

    fn make_param() -> Param {
        Param {
            name: "q".to_string(),
            value: "seed".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        }
    }

    fn default_scan_args() -> crate::cmd::scan::ScanArgs {
        crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: true,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }

    fn make_target(addr: SocketAddr, path: &str) -> Target {
        let target = format!("http://{}:{}{}?q=seed", addr.ip(), addr.port(), path);
        parse_target(&target).expect("valid target")
    }

    fn html_named_encode_all(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                '&' => "&amp;".to_string(),
                '"' => "&quot;".to_string(),
                '\'' => "&apos;".to_string(),
                _ => c.to_string(),
            })
            .collect::<String>()
    }

    async fn raw_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", q))
    }

    async fn html_entity_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", html_named_encode_all(&q)))
    }

    /// Mirrors brutelogic c1: reflects the param into a JS string literal
    /// after HTML-encoding `'` and `<`. Browser does not decode entities
    /// inside `<script>` so the reflection is inert.
    async fn js_string_apos_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!(
            "<html><body><script>var c1 = '{}';</script></body></html>",
            html_named_encode_all(&q)
        ))
    }

    async fn url_encoded_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", urlencoding::encode(&q)))
    }

    async fn form_urlencoded_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        let encoded = urlencoding::encode(&q).to_string().replace("%20", "+");
        Html(format!("<div>{}</div>", encoded))
    }

    async fn none_handler() -> Html<&'static str> {
        Html("<div>not reflected</div>")
    }

    async fn json_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
        let q = params.get("q").cloned().unwrap_or_default();
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            format!("{{\"echo\":\"{}\"}}", q),
        )
    }

    async fn sxss_handler(State(state): State<TestState>) -> Html<String> {
        Html(format!("<div>{}</div>", state.stored_payload))
    }

    /// Returns 302 with Location containing the decoded `q` param. Simulates a
    /// server that parses the query string and rebuilds the redirect URL.
    async fn redirect_decoded_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        let q = params.get("q").cloned().unwrap_or_default();
        (
            StatusCode::FOUND,
            [("location", format!("/final?next={}", q))],
        )
    }

    async fn start_mock_server(stored_payload: &str) -> SocketAddr {
        let app = Router::new()
            .route("/reflect/raw", get(raw_handler))
            .route("/reflect/html-entity", get(html_entity_handler))
            .route("/reflect/js-string-apos", get(js_string_apos_handler))
            .route("/reflect/url-encoded", get(url_encoded_handler))
            .route("/reflect/form-url-encoded", get(form_urlencoded_handler))
            .route("/reflect/none", get(none_handler))
            .route("/reflect/json", get(json_handler))
            .route("/sxss/stored", get(sxss_handler))
            .route("/redirect/decoded", get(redirect_decoded_handler))
            .with_state(TestState {
                stored_payload: stored_payload.to_string(),
            });

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        sleep(Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn test_check_reflection_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = make_param();
        let mut args = default_scan_args();
        args.skip_xss_scanning = true;
        let res = check_reflection(&target, &param, "PAY", &args).await;
        assert!(
            !res,
            "should early-return false when skip_xss_scanning=true"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = make_param();
        let mut args = default_scan_args();
        args.skip_xss_scanning = true;
        let res = check_reflection_with_response(&target, &param, "PAY", &args).await;
        assert_eq!(
            res,
            (None, None),
            "should early-return (None, None) when skip_xss_scanning=true"
        );
    }

    #[test]
    fn test_decode_html_entities_basic() {
        let s = "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;";
        let d = decode_html_entities(s);
        assert!(d.contains("<script>"));
        assert!(d.contains("</script>"));
    }

    #[test]
    fn test_decode_html_entities_uppercase_hex_x() {
        let s = "&#X3C;img src=x onerror=alert(1)&#X3E;";
        let d = decode_html_entities(s);
        assert!(d.contains("<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn test_decode_html_entities_named_common() {
        let s = "&lt;svg onload=alert(1)&gt; &amp; &quot; &apos;";
        let d = decode_html_entities(s);
        assert!(d.contains("<svg onload=alert(1)>"));
        assert!(d.contains("&"));
        assert!(d.contains("\""));
        assert!(d.contains("'"));
    }

    #[test]
    fn test_decode_html_entities_decimal_and_hex_mix() {
        let s = "&#60;img src=x&#62; and &#x3C;svg&#x3E;";
        let d = decode_html_entities(s);
        assert_eq!(d, "<img src=x> and <svg>");
    }

    #[test]
    fn test_decode_html_entities_named_case_insensitive() {
        let s = "&LT;script&GT;1&LT;/script&GT; &QuOt;ok&QuOt;";
        let d = decode_html_entities(s);
        assert!(d.contains("<script>1</script>"));
        assert!(d.contains("\"ok\""));
    }

    #[test]
    fn test_decode_html_entities_ignores_invalid_numeric_sequences() {
        let s = "&#xZZ; &#;";
        let d = decode_html_entities(s);
        assert_eq!(d, s);
    }

    #[test]
    fn test_classify_reflection_prefers_raw_match() {
        let payload = "<script>alert(1)</script>";
        let resp = format!("raw:{} encoded:{}", payload, urlencoding::encode(payload));
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::Raw)
        );
    }

    #[test]
    fn test_is_payload_reflected_html_encoded() {
        let payload = "<script>alert(1)</script>";
        let resp = "prefix &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e; suffix";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::HtmlEntityDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_url_encoded() {
        let payload = "<img src=x onerror=alert(1)>";
        let encoded = urlencoding::encode(payload).to_string();
        let resp = format!("ok {} end", encoded);
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::UrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_form_urlencoded_plus_spaces() {
        let payload = "<img src=x onerror=alert(1) class=dalfox>";
        let resp = "<img+src=x+onerror=alert(1)+class=dalfox>";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::UrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_percent_encoded_with_plus_spaces() {
        let payload = "<img src=x onerror=alert(1) class=dalfox>";
        let resp = "%3Cimg+src%3Dx+onerror%3Dalert%281%29+class%3Ddalfox%3E";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::UrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_quadruple_encoded_payload_variant() {
        let payload =
            crate::encoding::quadruple_url_encode("<img src=x onerror=alert(1) class=dalfox>");
        let resp = "<img+src=x+onerror=alert(1)+class=dalfox>";
        assert_eq!(
            classify_reflection(resp, &payload),
            Some(ReflectionKind::UrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_double_layer_percent_entity_then_url() {
        // Server returns percent sign as HTML-entity, which then precedes URL-encoded payload
        let payload = "<script>alert(1)</script>";
        // Build a string like: &#37;3Cscript%3Ealert(1)%3C%2Fscript%3E
        let url_once = urlencoding::encode(payload).to_string();
        let resp = url_once.replace("%", "&#37;");
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::HtmlThenUrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_negative() {
        let payload = "<svg/onload=alert(1)>";
        let resp = "benign content without the thing";
        assert_eq!(classify_reflection(resp, payload), None);
    }

    #[test]
    fn test_is_payload_reflected_html_named_uppercase() {
        let payload = "<svg onload=alert(1)>";
        let resp = "prefix &LT;svg onload=alert(1)&GT; suffix";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::HtmlEntityDecoded)
        );
    }

    #[tokio::test]
    async fn test_check_reflection_detects_raw_response() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/raw");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "raw reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_detects_html_entity_response() {
        let payload = "<img src=x onerror=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/html-entity");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "entity-encoded reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_suppresses_inert_js_string_apos_reflection() {
        // brutelogic c1 fixture: payload `'-alert(1)-'` reflected as
        // `var c1 = '&apos;-alert(1)-&apos;';` inside <script>. Inside a
        // script block HTML entities never decode, so this is inert text
        // and must not produce an R finding.
        let payload = "'-alert(1)-'";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/js-string-apos");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) =
            check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(
            kind, None,
            "apos-encoded JS-string reflection should be classified inert (no R)"
        );
        assert!(
            body.unwrap_or_default().contains("&apos;"),
            "fixture should reflect the encoded form"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_detects_url_encoded_response() {
        let payload = "<svg onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/url-encoded");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "URL-encoded reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_detects_form_urlencoded_response_runtime() {
        let payload = "<img src=x onerror=alert(1) class=dalfox>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/form-url-encoded");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, Some(ReflectionKind::UrlDecoded));
        assert!(
            body.unwrap_or_default()
                .contains("%3Cimg+src%3Dx+onerror%3Dalert%281%29+class%3Ddalfox%3E"),
            "form-style encoded response should be preserved for inspection"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_returns_false_when_not_reflected() {
        let payload = "<svg/onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(!found, "non-reflective response should not be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_reports_kind_and_body() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/html-entity");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, Some(ReflectionKind::HtmlEntityDecoded));
        assert!(body.unwrap_or_default().contains("&lt;script&gt;"));
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_not_reflected() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, None);
        assert!(
            body.is_some(),
            "request succeeded so response body should be returned"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_sxss_uses_secondary_url() {
        let payload = "STORED_XSS_PAYLOAD";
        let addr = start_mock_server(payload).await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let mut args = default_scan_args();
        args.sxss = true;
        args.sxss_url = Some(format!("http://{}:{}/sxss/stored", addr.ip(), addr.port()));

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "sxss mode should verify reflection via sxss_url");
    }

    #[tokio::test]
    async fn test_check_reflection_sxss_without_url_returns_false() {
        let payload = "STORED_XSS_PAYLOAD";
        let addr = start_mock_server(payload).await;
        let target = make_target(addr, "/reflect/raw");
        let param = make_param();
        let mut args = default_scan_args();
        args.sxss = true;
        args.sxss_url = None;

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(!found, "sxss mode without sxss_url should return false");
    }

    #[tokio::test]
    async fn test_check_reflection_catches_decoded_payload_in_redirect_location() {
        // Server URL-decodes the query and echoes the raw payload back into the
        // Location header. The gate used to only match the encoded form, so
        // this reflection was silently missed. It must now be caught.
        let payload = "<svg/onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/redirect/decoded");
        let param = make_param();
        let args = default_scan_args();
        assert!(
            check_reflection(&target, &param, payload, &args).await,
            "reflection check must catch the raw payload appearing in Location"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_handles_json_raw_reflection() {
        let payload = "<svg/onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/json");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, Some(ReflectionKind::Raw));
        assert!(body.unwrap_or_default().contains("echo"));
    }

    // --- Safe context filtering tests ---

    #[test]
    fn test_safe_context_textarea() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><textarea>{}</textarea></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_noscript() {
        let payload = "<img src=x onerror=alert(1)>";
        let html = format!("<html><noscript>{}</noscript></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_title() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><head><title>{}</title></head></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_style() {
        // Style is intentionally NOT a safe context — CSS injection can break
        // out via </style> and inject executable HTML.
        let payload = "expression(alert(1))";
        let html = format!("<html><style>{}</style></html>", payload);
        assert!(
            !is_in_safe_context(&html, payload),
            "style should NOT be a safe context"
        );
    }

    #[test]
    fn test_safe_context_mixed_safe_and_unsafe() {
        let payload = "<script>alert(1)</script>";
        let html = format!(
            "<html><textarea>{}</textarea><div>{}</div></html>",
            payload, payload
        );
        assert!(
            !is_in_safe_context(&html, payload),
            "mixed context should NOT be considered safe"
        );
    }

    #[test]
    fn test_safe_context_outside_safe_tag() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><div>{}</div></html>", payload);
        assert!(!is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_no_payload() {
        assert!(is_in_safe_context(
            "<html><body>nothing</body></html>",
            "PAYLOAD"
        ));
    }

    #[test]
    fn test_safe_context_title_breakout() {
        let payload = "</title><IMG src=x onerror=alert(1) ClAss=dlxtest>";
        let html = format!("<html><head><title>{}</title></head><body></body></html>", payload);
        // Breakout payload closes the title tag, so the IMG is outside the safe context
        assert!(
            !is_in_safe_context(&html, payload),
            "title breakout payload should NOT be considered safe"
        );
    }

    #[test]
    fn test_safe_context_textarea_breakout() {
        let payload = "</textarea><IMG src=x onerror=alert(1) ClAss=dlxtest>";
        let html = format!("<html><body><textarea>{}</textarea></body></html>", payload);
        assert!(
            !is_in_safe_context(&html, payload),
            "textarea breakout payload should NOT be considered safe"
        );
    }

    // --- Inert-in-script-block heuristic ---

    #[test]
    fn test_inert_in_scripts_entity_encoded_payload_in_js_string() {
        // Mirrors brutelogic c5/c6: server reflects the entity-encoded payload
        // verbatim inside a JS string literal — not exploitable in JS context.
        let payload = "&#x0027;-alert(1)-&#x0027;";
        let html = format!("<script>var c5 = '{}';</script>", payload);
        assert!(
            is_payload_inert_in_scripts(&html, payload),
            "entity-encoded payload reflected only inside a JS string should be inert"
        );
        assert!(
            is_in_safe_context_decoded(&html, payload),
            "should classify as safe so the reflection is not reported"
        );
    }

    #[test]
    fn test_inert_in_scripts_does_not_suppress_real_js_breakout() {
        // c2-style real exploit: payload introduces an `alert(1)` call inside
        // the JS — this MUST NOT be suppressed.
        let payload = "\"-alert(1)-\"";
        let html = format!("<script>var c2 = \"{}\";</script>", payload);
        assert!(
            !is_payload_inert_in_scripts(&html, payload),
            "exploitable JS-context payload must not be classified inert"
        );
    }

    #[test]
    fn test_inert_in_scripts_requires_all_occurrences_inside_script() {
        let payload = "&#x0027;ZZZ&#x0027;";
        let html = format!(
            "<div>{}</div><script>var x = '{}';</script>",
            payload, payload
        );
        assert!(
            !is_payload_inert_in_scripts(&html, payload),
            "if the payload is also reflected outside a script block it is not inert"
        );
    }

    #[test]
    fn test_inert_in_scripts_no_script_block_in_response() {
        let payload = "&#x0027;ZZZ&#x0027;";
        let html = format!("<div>{}</div>", payload);
        assert!(
            !is_payload_inert_in_scripts(&html, payload),
            "without any script block this heuristic should not apply"
        );
    }

    #[test]
    fn test_inert_in_scripts_handles_entity_encoded_html_payload_in_js_string() {
        // Mirrors brutelogic c6 with the marker payload: server HTML-encodes
        // `<` to `&lt;` and reflects inside a JS string. Browser does not
        // decode entities inside <script>, so the payload is just text.
        let payload = "<img src=x onerror=alert(1) class=dlxtest>";
        let html =
            "<script>var c6 = \"&lt;img src=x onerror=alert(1) class=dlxtest>\";</script>";
        assert!(
            is_payload_inert_in_scripts(html, payload),
            "entity-encoded HTML payload reflected only inside JS string should be inert"
        );
    }

    #[test]
    fn test_inert_in_scripts_handles_apos_encoded_quote_in_js_string() {
        // Mirrors brutelogic c1: the server HTML-encodes the `'` chars of
        // `'-alert(1)-'` to `&apos;` before reflecting into a JS string.
        // Inside <script> entities never decode, so the reflection is text.
        let payload = "'-alert(1)-'";
        let html = "<script>var c1 = '&apos;-alert(1)-&apos;';</script>";
        assert!(
            is_payload_inert_in_scripts(html, payload),
            "apos-encoded JS-context payload reflected inside JS string should be inert"
        );
        assert!(
            is_in_safe_context_decoded(html, payload),
            "should classify safe so the R finding is suppressed"
        );
    }

    #[test]
    fn test_inert_in_scripts_handles_url_encoded_payload_variant() {
        // Encoder policy often produces a URL-encoded variant of the original
        // payload; the server then URL-decodes once and reflects the decoded
        // form. The suppression heuristic must inspect that decoded form, not
        // the URL-encoded payload string verbatim.
        let payload = "%27-alert%281%29-%27"; // URL-encoded `'-alert(1)-'`
        let html = "<script>var c1 = '&apos;-alert(1)-&apos;';</script>";
        assert!(!html.contains(payload), "URL-encoded form should not appear");
        assert!(
            is_payload_inert_in_scripts(html, payload),
            "URL-encoded JS-context payload reflected as decoded text inside JS string should be inert"
        );
    }

    #[test]
    fn test_inert_in_scripts_url_encoded_does_not_suppress_real_breakout() {
        // URL-encoded form of `"-alert(1)-"` decodes to a real exploitable
        // breakout. Must NOT be suppressed.
        let payload = "%22-alert%281%29-%22";
        let html = "<script>var c2 = \"\"-alert(1)-\"\";</script>";
        assert!(
            !is_payload_inert_in_scripts(html, payload),
            "exploitable breakout via URL-decoded form must keep its finding"
        );
    }

    #[test]
    fn test_inert_in_scripts_full_brutelogic_response() {
        // Full real-world response capture: c1 reflection inside a multi-block
        // script context with form inputs and HTML comments. Should be inert.
        let payload = "'-alert(1)-'";
        let html = r#"<!DOCTYPE html>
<head>
<!-- XSS in 11 URL parameters (a, b1, b2, b3, b4, b5, b6, c1, c2, c3, c4, c5 and c6) + URL itself -->
<title>XSS Test Page</title>
</head>
<body>
<form>
<input type="text" name="b1" value="">
<input type="text" name="b2" value=''>
</form>
<script>
	var c1 = '&apos;-alert(1)-&apos;';
	var c2 = "1";
	var c3 = '1';
	var c4 = "1";
	var c5 = '1';
	var c6 = "1";
</script>
</body>"#;
        assert!(!html.contains(payload), "payload should not appear raw");
        assert!(
            is_payload_inert_in_scripts(html, payload),
            "full-page response should still classify the apos-encoded reflection as inert"
        );
    }

    // --- Path-injection status-code filter ---

    #[test]
    fn test_suppress_path_reflection_on_404() {
        assert!(should_suppress_path_reflection(&Location::Path, 404));
        assert!(should_suppress_path_reflection(&Location::Path, 500));
        assert!(should_suppress_path_reflection(&Location::Path, 301));
    }

    #[test]
    fn test_keep_path_reflection_on_2xx() {
        assert!(!should_suppress_path_reflection(&Location::Path, 200));
        assert!(!should_suppress_path_reflection(&Location::Path, 204));
    }

    #[test]
    fn test_non_path_locations_are_unaffected() {
        assert!(!should_suppress_path_reflection(&Location::Query, 404));
        assert!(!should_suppress_path_reflection(&Location::Header, 500));
        assert!(!should_suppress_path_reflection(&Location::Body, 404));
    }
}
