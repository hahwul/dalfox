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

/// Upper bounds for the reflection heuristics' scans over a single response.
/// Body analysis runs *after* the response is read, so it is not covered by the
/// request timeout; a hostile page packed with safe tags, `<script>` blocks, or
/// payload echoes could otherwise drive these O(n)/O(n·m) scans into a
/// multi-second CPU hang (the loops vet every occurrence against every range).
/// When a cap is hit we stop early and return the answer that does NOT suppress
/// a finding (fail toward reporting), so the cap can only ever cost extra [R]
/// noise on a pathological page — never a missed vulnerability.
const MAX_SAFE_RANGES: usize = 4096;
const MAX_SCRIPT_RANGES: usize = 4096;
const MAX_PAYLOAD_OCCURRENCES: usize = 4096;

/// Purely numeric reflection probe. Sent for parameters that showed no
/// reflection with the normal alphanumeric markers, to catch injection
/// points behind letter-stripping filters (e.g. `gsub(/[a-zA-Z]/, "")`),
/// which would erase a normal marker but leave digits intact. Shared with
/// `parameter_analysis::discovery` so both probe paths stay in sync.
pub const NUMERIC_PROBE_MARKER: &str = "90197752";

/// Consecutive WAF block responses (HTTP 403/406/429/503) tolerated before
/// adaptive backoff engages. Below this, blocks are assumed transient.
const WAF_BACKOFF_THRESHOLD: u32 = 3;
/// Maximum exponential-backoff escalation step. Caps the doubling so the
/// raw delay plateaus at `WAF_BACKOFF_BASE_MS << WAF_BACKOFF_MAX_ESCALATION`
/// before the absolute `WAF_BACKOFF_CAP_MS` ceiling is applied.
const WAF_BACKOFF_MAX_ESCALATION: u32 = 4;
/// Base backoff delay (milliseconds), doubled once per escalation step.
const WAF_BACKOFF_BASE_MS: u64 = 2000;
/// Absolute ceiling (milliseconds) on a single adaptive-backoff sleep.
const WAF_BACKOFF_CAP_MS: u64 = 30_000;

/// Base adaptive cooldown (milliseconds, before any jitter) for a WAF block
/// response, or `0` for "don't pause". The block *class* decides whether the
/// cooldown applies at all, because the correct reaction differs:
///
/// * **429 / 503** are genuine rate-limit / overload signals — the origin is
///   telling us to slow down, so the escalating cooldown is always honored.
/// * **403 / 406** are per-request *content* blocks: *this payload* was
///   rejected. The right move is to try the next payload immediately, so the
///   cooldown is only paid under explicit `--waf-evasion` (the user opting
///   into cautious, stealthy pacing). Otherwise a facade that 403s most
///   payloads (signature / anomaly-scoring WAFs) would burn the entire
///   `--scan-timeout` in backoff and never reach a bypass that does slip
///   through — the failure mode behind xssmaze `waf-facade` L3/L5.
///
/// Returns `0` below `WAF_BACKOFF_THRESHOLD` consecutive blocks (transient).
fn waf_block_cooldown_ms(status_code: u16, consecutive: u32, waf_evasion: bool) -> u64 {
    let is_rate_limit = matches!(status_code, 429 | 503);
    let is_content_block = matches!(status_code, 403 | 406);
    let apply_cooldown = is_rate_limit || (is_content_block && waf_evasion);
    if !apply_cooldown || consecutive < WAF_BACKOFF_THRESHOLD {
        return 0;
    }
    let escalation = (consecutive - WAF_BACKOFF_THRESHOLD).min(WAF_BACKOFF_MAX_ESCALATION);
    let backoff_ms = WAF_BACKOFF_BASE_MS * (1u64 << escalation);
    backoff_ms.min(WAF_BACKOFF_CAP_MS)
}

/// Adaptive WAF accounting for one injection-response status code, shared by the
/// normal and stored-XSS (`--sxss`) injection paths.
///
/// `streak` is the **per-worker** consecutive-block counter. A single scan fans
/// out to up to ~50 param workers; they previously shared one (per-scan / global)
/// counter, so any worker's 2xx reset another worker's accumulating streak and
/// the `--waf-evasion` escalation almost never fired (and 429/503 storms paced
/// erratically). The escalation now reads this local counter, while the
/// process-wide total ([`crate::tick_waf_block`]) and the per-job task-local
/// stay updated for reporting and cross-scan isolation.
async fn apply_injection_waf_accounting(
    status_code: u16,
    target: &Target,
    args: &crate::cmd::scan::ScanArgs,
    streak: &std::sync::atomic::AtomicU32,
) {
    use std::sync::atomic::Ordering;
    let is_waf_block = matches!(status_code, 403 | 406 | 429 | 503);
    let consecutive = if is_waf_block {
        // Keep the process-wide total + per-job task-local in sync for reporting
        // and cross-scan isolation; the value we act on is the per-worker streak.
        crate::tick_waf_block();
        streak.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        crate::reset_waf_consecutive();
        streak.store(0, Ordering::Relaxed);
        0
    };
    if is_waf_block {
        // `waf_block_cooldown_ms` decides whether (and how long) to pause based
        // on the block class — see its doc comment.
        let mut backoff_ms = waf_block_cooldown_ms(status_code, consecutive, args.waf_evasion);
        if backoff_ms > 0 {
            // Under --waf-evasion, scatter the cooldown by up to +50% so the
            // backoff itself isn't a fixed, fingerprintable interval.
            if args.waf_evasion {
                backoff_ms = backoff_ms
                    .saturating_add(crate::utils::rate_limit::fast_jitter(backoff_ms / 2 + 1));
            }
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }
    // Per-target bypass effectiveness telemetry. Only counts when bypass is
    // active for the target (target.mutation_stats is populated during preflight
    // when a WAF is detected and bypass is on).
    if let Some(ref stats) = target.mutation_stats {
        stats.record_request(is_waf_block);
    }
}

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
    'patterns: for &(open_pattern, close_pattern) in SAFE_TAG_PATTERNS {
        let mut search_pos = 0;
        while let Some(open_start) =
            find_ascii_case_insensitive(html_bytes, open_pattern, search_pos)
        {
            // Cap the range set: a page with this many safe tags is hostile,
            // and more ranges only grow memory and the per-occurrence scan
            // below. Stopping here leaves later occurrences classified as
            // unsafe, which keeps (does not suppress) the finding.
            if safe_ranges.len() >= MAX_SAFE_RANGES {
                break 'patterns;
            }
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
    let mut scanned = 0usize;
    while let Some(pos) = html[search_start..].find(payload) {
        scanned += 1;
        if scanned > MAX_PAYLOAD_OCCURRENCES {
            // Too many echoes to vet individually; treat as not-fully-safe so
            // the reflection is reported rather than silently suppressed.
            return false;
        }
        let abs_pos = search_start + pos;
        let in_safe = safe_ranges
            .iter()
            .any(|&(start, end)| abs_pos >= start && abs_pos + payload_len <= end);
        if !in_safe {
            return false; // at least one occurrence is outside safe context
        }
        search_start = next_char_boundary(html, abs_pos + 1);
    }

    true
}

/// Round `idx` up to the next UTF-8 char boundary in `s` (or to `s.len()`).
/// Prevents `&s[idx..]` from panicking when `idx` lands inside a multi-byte
/// codepoint — e.g. when a payload contains a full-width character such as
/// `＜` (3 bytes) and we advance by a single byte to find overlapping matches.
#[inline]
fn next_char_boundary(s: &str, mut idx: usize) -> usize {
    let len = s.len();
    if idx >= len {
        return len;
    }
    while idx < len && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
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
    // Inert encoded echo: the server escaped its output (percent- or
    // entity-encoded the reflection) and the encoded bytes are not inside a
    // URL-valued attribute. The browser renders such text literally, so the
    // reflection cannot break out. Covers `encoded_url`-style reflections and
    // double-encoded structural/quote break-out payloads.
    if is_inert_encoded_reflection(html, payload) {
        return true;
    }
    false
}

/// True when a path-segment parameter's "reflection" should be ignored because
/// it came from a non-2xx response. Error pages frequently echo the requested
/// URL/path verbatim, producing reflections that don't represent real
/// injection points.
///
/// **Note**: this is the body-less fast path. The full scan-time check uses
/// [`should_suppress_path_reflection_with_body`], which keeps non-2xx
/// findings when the marker reflects outside URL-style attributes — those
/// are genuinely exploitable error-page XSS (e.g. a 404 template that
/// renders the requested URI inside `<td>...</td>`). Retained for legacy
/// tests pinning the conservative status-code-only semantics.
#[cfg(test)]
fn should_suppress_path_reflection(location: &Location, status_code: u16) -> bool {
    matches!(location, Location::Path) && !(200..300).contains(&status_code)
}

/// HTML attributes that carry URL values. Reflections that land *only*
/// inside one of these are noise: browsers parse them as URLs, so an
/// injected `<` doesn't open a tag and the payload can't escape into a
/// script-execution sink. Used by the URL-echo classifier below to keep
/// firing-range-style canonical-link / `<a href>` reflections suppressed
/// while letting `<td>URI</td>` style error-page reflections survive.
const URL_VALUED_ATTRS: &[&[u8]] = &[
    b"href",
    b"src",
    b"action",
    b"formaction",
    b"cite",
    b"data",
    b"manifest",
    b"poster",
    b"srcset",
    b"longdesc",
    b"background",
    b"usemap",
    b"codebase",
    b"profile",
    b"ping",
    b"archive",
    // Namespaced SVG URL sink: `<a xlink:href>` / `<use xlink:href>` navigate,
    // so a `javascript:` scheme there executes. Kept consistent with the AST /
    // DOM-verification sink lists (mining.rs, ast_dom_analysis, check_dom_verification).
    b"xlink:href",
];

/// True when every occurrence of `marker` in `html` sits inside an HTML
/// attribute value whose attribute name is URL-valued (see
/// [`URL_VALUED_ATTRS`]). Used to keep generic error-page URL echo
/// suppressed (canonical link, `<a href>`, breadcrumb anchors) while
/// allowing genuine path-XSS sinks — text content, non-URL attribute
/// values, script blocks — to surface.
///
/// Conservative: a single non-URL-attr occurrence flips the result to
/// `false`, since one exploitable sink is enough to keep the finding.
pub(crate) fn marker_reflects_in_url_attr_only(html: &str, marker: &str) -> bool {
    if marker.is_empty() || !html.contains(marker) {
        return false;
    }
    let bytes = html.as_bytes();
    let mut search_start = 0;
    let mut any = false;
    let mut scanned = 0usize;
    while let Some(pos) = html[search_start..].find(marker) {
        scanned += 1;
        if scanned > MAX_PAYLOAD_OCCURRENCES {
            // Bail toward reporting: `false` means "not exclusively URL-attr",
            // so the URL-echo suppression does not apply and the finding stays.
            return false;
        }
        any = true;
        let abs = search_start + pos;
        if !occurrence_is_in_url_attr(bytes, abs) {
            return false;
        }
        search_start = next_char_boundary(html, abs + 1);
    }
    any
}

/// Walk backwards from byte offset `at` looking for the surrounding HTML
/// attribute context. Returns `true` when the byte sits inside a quoted
/// or unquoted attribute value whose attribute name is in
/// [`URL_VALUED_ATTRS`]. Returns `false` for text content (we hit `>`
/// before finding `=`) and for non-URL attributes.
fn occurrence_is_in_url_attr(bytes: &[u8], at: usize) -> bool {
    if at == 0 || at > bytes.len() {
        return false;
    }
    // Phase 1: walk back to find an `=` without crossing a tag boundary.
    let mut i = at;
    loop {
        if i == 0 {
            return false;
        }
        i -= 1;
        match bytes[i] {
            b'=' => break,
            // Crossing a tag boundary means we're outside any attribute.
            b'<' | b'>' => return false,
            _ => {}
        }
    }
    // Phase 2: skip backwards over whitespace between `=` and attr name.
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    // Phase 3: read the attribute name backwards.
    let name_end = i; // exclusive
    let mut name_start = name_end;
    while name_start > 0 {
        let b = bytes[name_start - 1];
        if b.is_ascii_whitespace() || b == b'<' || b == b'/' || b == b'"' || b == b'\'' {
            break;
        }
        name_start -= 1;
    }
    if name_start == name_end {
        return false;
    }
    let name = &bytes[name_start..name_end];
    URL_VALUED_ATTRS
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

/// Body-aware version of [`should_suppress_path_reflection`]. Lets
/// exploitable error-page reflections (404 templates that render the URI
/// in `<td>`, 500 fallbacks that emit `<h1>You searched for X</h1>`,
/// etc.) reach the V/R reporter so users don't lose those true positives.
///
/// Suppresses when, on a non-2xx response:
///   * the body is empty (nothing to classify — preserve legacy conservatism), OR
///   * the raw payload bytes don't appear in the body (only the
///     percent-encoded form is present — browsers render `%3Csvg…%3E`
///     as literal text, no tag is parsed), OR
///   * every raw occurrence sits inside a URL-valued attribute
///     ([`URL_VALUED_ATTRS`]) — canonical link / `<a href>` URL echo.
pub(crate) fn should_suppress_path_reflection_with_body(
    location: &Location,
    status_code: u16,
    body: &str,
    payload: &str,
) -> bool {
    if !matches!(location, Location::Path) {
        return false;
    }
    if (200..300).contains(&status_code) {
        return false;
    }
    if body.is_empty() {
        return true;
    }
    // Without a raw payload byte sequence in the response body, the
    // upstream reflection detector found us via a URL-decoded match.
    // That's noise for path injection: the browser never decodes the
    // percent-escapes back into `<` / `>` when rendering response text,
    // so there is no tag-parser sink to exploit.
    if !body.contains(payload) {
        return true;
    }
    marker_reflects_in_url_attr_only(body, payload)
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
        // Cap the range set. Unlike the unclosed-tag branch below we do NOT
        // extend to end-of-document here: leaving later regions classified as
        // non-script keeps payload occurrences there reportable (fail toward
        // reporting) instead of marking them inert.
        if ranges.len() >= MAX_SCRIPT_RANGES {
            break;
        }
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
    let mut scanned = 0usize;
    while let Some(rel) = haystack[search..].find(needle) {
        scanned += 1;
        if scanned > MAX_PAYLOAD_OCCURRENCES {
            // Give up vetting; `false` means "not all occurrences are inside the
            // ranges", which keeps the finding rather than treating it as inert.
            return false;
        }
        let abs = search + rel;
        let in_range = ranges
            .iter()
            .any(|&(s, e)| abs >= s && abs + needle_len <= e);
        if !in_range {
            return false;
        }
        found_any = true;
        search = next_char_boundary(haystack, abs + 1);
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
///
/// Shared with DOM verification paths (marker sink survival, structural evidence,
/// inline handler breakout). Unknown entities are passed through unchanged
/// ("never lose bytes").
pub(crate) fn decode_html_entities(input: &str) -> String {
    // Fast path: every HTML entity (numeric `&#…;` and named `&lt;` alike)
    // begins with '&'. When the input has none, there is nothing to decode, so
    // skip both regex scans and the second `replace_all().to_string()`
    // allocation. classify_reflection runs this once per non-reflecting payload
    // on the whole (up to 16 MiB) response body, so the saved scans/allocations
    // add up across a scan.
    if !input.as_bytes().contains(&b'&') {
        return input.to_string();
    }
    // Match patterns like &#xHH; or &#xHHHH; or &#DDDD; (hex 'x' is case-insensitive)
    // Upper bound is 8 hex / 8 decimal digits — covers zero-padded WAF-bypass
    // payloads emitted by `html_entity_zero_padded_encode` (`&#x0000003c;`,
    // 7 hex digits) while still capping the regex so a pathological response
    // can't fan out into catastrophic replacements.
    let re = ENTITY_REGEX.get_or_init(|| {
        Regex::new(r"&#([xX][0-9a-fA-F]{2,8}|[0-9]{2,8});")
            .expect("entity regex pattern must be valid")
    });
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.find_iter(input) {
        out.push_str(&input[last..m.start()]);
        let entity = &input[m.start() + 2..m.end() - 1]; // strip &# and ;
        let ch = if entity.starts_with('x') || entity.starts_with('X') {
            let hex = &entity[1..];
            u32::from_str_radix(hex, 16)
                .ok()
                .and_then(std::char::from_u32)
        } else {
            entity.parse::<u32>().ok().and_then(std::char::from_u32)
        };
        if let Some(c) = ch {
            out.push(c);
        } else {
            // Unknown / unrepresentable numeric entity: preserve the original
            // &#...; text. Mirrors the "never lose bytes" contract used by the
            // DOM verification decoder and prevents dropping information that
            // downstream contains() / sink checks rely on.
            out.push_str(&input[m.start()..m.end()]);
        }
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
    // Form decoding can only change the string when it carries a '+' (space
    // shorthand) or a '%' (percent-escape). Without either, `replace('+',…)`
    // and `urlencoding::decode` are both no-ops, so skip the two full-body
    // allocations entirely — this runs per non-reflecting payload on the whole
    // response body in classify_reflection's slow path.
    if !input.as_bytes().iter().any(|&b| b == b'+' || b == b'%') {
        return None;
    }
    let normalized = input.replace('+', "%20");
    let decoded = urlencoding::decode(&normalized).ok()?.into_owned();
    if decoded == input {
        None
    } else {
        Some(decoded)
    }
}

fn payload_variants(payload: &str) -> Vec<String> {
    // The variant set is tiny (original + entity-decoded + a short URL-decode
    // chain capped at MAX_URL_DECODE_ITERATIONS), so a linear membership scan
    // over the Vec is cheaper than a HashSet — it avoids the per-element hash,
    // the contains()+insert() double lookup, and the extra String clone the set
    // required. Order and membership are identical to the old HashSet-guarded
    // build.
    let mut variants: Vec<String> = Vec::with_capacity(10);
    variants.push(payload.to_string());

    let html_dec = decode_html_entities(payload);
    if !variants.iter().any(|v| v == &html_dec) {
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
            if !variants.iter().any(|v| v == &url_dec) {
                variants.push(url_dec.clone());
            }
            current = url_dec;
        }
    }

    variants
}

/// Returns true when at least one occurrence of a payload variant (raw or
/// HTML-entity-decoded form) sits inside a context where HTML entity
/// escaping is *not* sufficient to neutralize the injection.
///
/// The only such context for an entity-encoded reflection is an HTML
/// event-handler attribute value (`on*=…`): the HTML parser decodes the
/// attribute's character references while building the value, *then* hands
/// the decoded string to the JS engine, so `onclick="&quot;;alert(1)//"`
/// executes. Everywhere else the entities stay literal:
///   * HTML body / non-event attribute text — rendered as characters, never
///     re-parsed as markup.
///   * `<script>` / `<style>` raw-text content — the JS and CSS tokenizers
///     do **not** perform HTML character-reference decoding (HTML5 §13.2.5
///     "script data"/"raw text" states), so `&quot;` inside a `<script>` is
///     the literal six bytes `&quot;`, which cannot terminate a JS string or
///     introduce a statement. A genuine raw-character break-out into a script
///     is caught earlier by the byte-exact fast path in `classify_reflection`
///     (it never reaches this entity-decoded gate).
///
/// When this returns `false`, the entity-escaped reflection is safe by
/// construction and can be suppressed.
fn html_entity_reflection_in_unsafe_context(html: &str, variants: &[String]) -> bool {
    static EVENT_HANDLER_RE: OnceLock<Regex> = OnceLock::new();

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

/// True when every HTML-significant character (`<`, `>`, `"`, `'`) in the
/// payload is already represented as an HTML entity reference. Such payloads
/// reflected verbatim are inert in HTML body / regular-attribute contexts —
/// the browser decodes the entities into text characters rather than
/// re-parsing them as markup, so no element or attribute boundary is
/// crossed. Returns `false` when the payload carries any raw structural
/// character (which would be exploitable on reflection).
fn payload_is_fully_entity_encoded(payload: &str) -> bool {
    if payload.contains(['<', '>', '"', '\'']) {
        return false;
    }
    let decoded = decode_html_entities(payload);
    decoded != payload && decoded.contains(['<', '>', '"', '\''])
}

/// True when the payload carries no raw structural HTML characters
/// (`<`, `>`, `"`, `'`) but does contain at least one ASCII-fullwidth
/// codepoint (U+FF01-U+FF5E). Output of the `unicode` adaptive encoder.
/// Reflected verbatim such payloads are inert in every browser context:
/// fullwidth codepoints are distinct Unicode characters, never normalized
/// to ASCII by the HTML, JS, CSS, or URL parsers, so they cannot start a
/// tag, break an attribute, or form an executable URL scheme.
fn payload_is_fully_fullwidth_encoded(payload: &str) -> bool {
    if payload.contains(['<', '>', '"', '\'']) {
        return false;
    }
    payload
        .chars()
        .any(|c| (0xFF01..=0xFF5E).contains(&(c as u32)))
}

/// True when the payload carries no raw structural HTML characters
/// (`<`, `>`, `"`, `'`) and URL-decoding actually transforms it. Such
/// payloads reflected verbatim are inert in HTML body, non-URL attribute,
/// `<script>`, `<style>`, and event-handler contexts — none of those
/// parsers percent-decode their content. The one remaining execution path
/// (URL-valued attributes navigating to an executable scheme) is handled
/// separately by [`url_encoded_payload_reflects_in_unsafe_url_context`].
fn payload_is_fully_url_encoded(payload: &str) -> bool {
    if payload.contains(['<', '>', '"', '\'']) {
        return false;
    }
    let Ok(decoded) = urlencoding::decode(payload) else {
        return false;
    };
    decoded.as_ref() != payload
}

/// True when a percent-encoded payload that decodes to a JS-executable URL
/// scheme (`javascript:`, `data:text/html`, `data:image/svg`, `vbscript:`)
/// is reflected inside at least one URL-valued attribute. URL attributes
/// are the one context where browsers percent-decode the value (when
/// parsing the URL), so a dangerous decoded scheme there is exploitable
/// on navigation. Other contexts (body, non-URL attr, script, style,
/// event-handler) never decode percent encoding, so they remain safe.
fn url_encoded_payload_reflects_in_unsafe_url_context(html: &str, payload: &str) -> bool {
    let Ok(decoded) = urlencoding::decode(payload) else {
        return false;
    };
    let lower = decoded.trim_start().to_ascii_lowercase();
    let dangerous_scheme = lower.starts_with("javascript:")
        || lower.starts_with("data:text/html")
        || lower.starts_with("data:image/svg")
        || lower.starts_with("vbscript:");
    if !dangerous_scheme {
        return false;
    }
    let bytes = html.as_bytes();
    let mut search_start = 0;
    let mut scanned = 0usize;
    while let Some(pos) = html[search_start..].find(payload) {
        scanned += 1;
        if scanned > MAX_PAYLOAD_OCCURRENCES {
            // Couldn't rule out an unsafe-URL-context occurrence within the
            // scan budget; the caller suppresses only when this is `false`, so
            // returning `true` keeps the finding (fail toward reporting).
            return true;
        }
        let abs = search_start + pos;
        if occurrence_is_in_url_attr(bytes, abs) {
            return true;
        }
        search_start = next_char_boundary(html, abs + 1);
    }
    false
}

/// Count of HTML break-out characters (`<`, `>`, `"`, `'`) in `s`. Used to
/// prove a decode actually *un-escaped* structure (so a `+`→space form-decode,
/// which neutralizes no HTML-active character, is not mistaken for evidence
/// that the server escaped its output).
fn structural_char_count(s: &str) -> usize {
    s.bytes()
        .filter(|b| matches!(b, b'<' | b'>' | b'"' | b'\''))
        .count()
}

/// True when a reflection that `classify_reflection` matched only after
/// decoding the whole response body is an inert *encoded echo* — the server
/// escaped its own output and a browser renders the bytes literally, so the
/// reflection cannot form markup, an attribute break-out, or an executable
/// scheme.
///
/// Scope: this gate only soundly vets payloads that cannot inject an HTML
/// TAG (no raw `<`/`>` in any variant) — quote / attribute-value / scheme
/// break-outs. Deciding whether an escaped `<svg…>` echo co-exists with a
/// *live* `<svg…>` element requires real HTML parsing (a page's own
/// `<body>`/`<svg>` markup defeats byte heuristics), which is the DOM /
/// AST-verification path's job, not the raw-byte report gate's.
///
/// Within that scope it rejects EVERY way the payload could still be live;
/// each of the following keeps the finding (returns false): (a) a payload
/// variant is present RAW (byte-exact) anywhere; (b) any variant carries a raw
/// `<`/`>` (a tag payload — out of scope, keep); (c) the reflection lands in an
/// event-handler (`on*=`) attribute value, where the HTML parser decodes
/// entities before the JS engine runs them; (d) any decoded occurrence sits
/// inside a URL-valued attribute.
///
/// It suppresses ONLY when a variant surfaces via a decode that genuinely
/// un-escaped a structural character (`<`, `>`, `"`, `'`) — never via a bare
/// `+`-to-space form-decode that neutralizes nothing.
fn is_inert_encoded_reflection(html: &str, payload: &str) -> bool {
    let variants = payload_variants(payload);
    // (a) A genuine un-escaped reflection (raw variant present) is never an echo.
    if variants.iter().any(|v| !v.is_empty() && html.contains(v)) {
        return false;
    }
    // (b) Out of scope: any tag-injecting variant (raw `<`/`>`) is left to the
    //     DOM/AST verification path — a byte gate cannot tell a fully-escaped
    //     echo apart from a live element the server reflected with edits.
    if variants.iter().any(|v| v.contains(['<', '>'])) {
        return false;
    }
    // (c) Event-handler (`on*=`) context: the parser decodes entities before the
    //     JS engine, so an entity-escaped break-out there executes. Keep — this
    //     mirrors classify_reflection's own unsafe-context carve-out.
    if html_entity_reflection_in_unsafe_context(html, &variants) {
        return false;
    }
    // Build the decoded views the classifier matches against, keeping only the
    // ones that actually un-escaped a structural character (real server escaping
    // — not a `+`→space whitespace substitution).
    let html_struct = structural_char_count(html);
    let mut decoded_forms: Vec<String> = Vec::new();
    let push_if_unescapes = |forms: &mut Vec<String>, d: String| {
        if structural_char_count(&d) > html_struct {
            forms.push(d);
        }
    };
    if let Ok(d) = urlencoding::decode(html)
        && d.as_ref() != html
    {
        push_if_unescapes(&mut decoded_forms, d.into_owned());
    }
    let html_dec = decode_html_entities(html);
    if html_dec != html {
        if let Ok(d) = urlencoding::decode(&html_dec)
            && d.as_ref() != html_dec.as_str()
        {
            push_if_unescapes(&mut decoded_forms, d.into_owned());
        }
        push_if_unescapes(&mut decoded_forms, html_dec);
    }
    if let Some(f) = decode_form_urlencoded_like(html) {
        push_if_unescapes(&mut decoded_forms, f);
    }
    // The payload must surface in such a decoded view (confirming an encoded
    // echo) and no decoded occurrence may sit in a URL attribute.
    let mut surfaced = false;
    for decoded in &decoded_forms {
        let bytes = decoded.as_bytes();
        for v in &variants {
            if v.is_empty() {
                continue;
            }
            let mut start = 0;
            let mut scanned = 0usize;
            while let Some(pos) = decoded[start..].find(v.as_str()) {
                surfaced = true;
                scanned += 1;
                if scanned > MAX_PAYLOAD_OCCURRENCES {
                    // Couldn't fully vet occurrences — keep the finding.
                    return false;
                }
                let abs = start + pos;
                if occurrence_is_in_url_attr(bytes, abs) {
                    return false;
                }
                start = next_char_boundary(decoded, abs + 1);
            }
        }
    }
    surfaced
}

/// Determine if payload is reflected in any normalization variant.
pub(crate) fn classify_reflection(resp_text: &str, payload: &str) -> Option<ReflectionKind> {
    // Direct match first (fast path — avoids payload_variants allocation)
    if resp_text.contains(payload) {
        // False-positive guard: when the payload is itself HTML-entity
        // encoded (e.g. `&#x003c;br&#x003e;`, `&lt;script&gt;alert(1)&lt;/script&gt;`)
        // and the response reflects that exact encoded form, the reflection
        // is functionally equivalent to the server having entity-escaped its
        // output — both render as literal text in HTML body / non-event
        // attribute context rather than as executable markup. Reuse the same
        // safe-context heuristic the entity-decoded path below applies so
        // these reflections do not surface as [R] noise. Keep the finding
        // when the reflection lands in a context where entity escaping is
        // not sufficient (event-handler attributes, `<script>` / `<style>`
        // raw-text bodies).
        if payload_is_fully_entity_encoded(payload) {
            let variants = [payload.to_string()];
            if !html_entity_reflection_in_unsafe_context(resp_text, &variants) {
                return None;
            }
        }
        // Same FP guard for percent-encoded payloads: `%3C` etc. survive
        // HTML/JS/CSS parsing as literal text — no parser decodes percent
        // encoding inside its tokens. The only execution path is when the
        // payload lands inside a URL-valued attribute and decodes to an
        // executable URL scheme (`javascript:`, `data:text/html`, etc.).
        if payload_is_fully_url_encoded(payload)
            && !url_encoded_payload_reflects_in_unsafe_url_context(resp_text, payload)
        {
            return None;
        }
        // Fullwidth-unicode payloads (`unicode` adaptive encoder, e.g.
        // `＜br＞` made of U+FF1C/U+FF1E) reflected verbatim are inert in
        // every browser context: those codepoints are never normalized to
        // ASCII `<>` by any parser, so they can't start a tag or escape
        // an attribute. Demote unconditionally — there is no analogue to
        // the URL-scheme exception here.
        if payload_is_fully_fullwidth_encoded(payload) {
            return None;
        }
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

    // Only allocate the entity-decoded copy of the body when it actually
    // contains an entity-introducing '&'; otherwise borrow `resp_text`
    // directly so the common no-entity response in this per-payload slow path
    // pays no full-body String copy. `html_dec == resp_text` in the borrowed
    // case, so every `html_dec != resp_text` gate below short-circuits exactly
    // as before.
    let html_dec_owned;
    let html_dec: &str = if resp_text.as_bytes().contains(&b'&') {
        html_dec_owned = decode_html_entities(resp_text);
        html_dec_owned.as_str()
    } else {
        resp_text
    };
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
        // We keep the finding only when the entity-encoded reflection lands
        // in an HTML event-handler attribute value (`on*=…`), the one context
        // where the browser decodes the entities while building the value
        // *before* handing it to the JS parser. `<script>` / `<style>`
        // raw-text content does NOT decode HTML entities (the JS/CSS
        // tokenizers leave `&quot;` as literal bytes), so an entity-escaped
        // reflection there is inert — see
        // `html_entity_reflection_in_unsafe_context`.
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
    if let Ok(url_dec_html) = urlencoding::decode(html_dec)
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

    if let Some(form_dec_html) = decode_form_urlencoded_like(html_dec)
        && payload_variants
            .iter()
            .any(|candidate| form_dec_html.contains(candidate))
    {
        return Some(ReflectionKind::HtmlThenUrlDecoded);
    }

    // Case-folded marker fallback: when none of the byte-exact variants
    // match, but the payload carries a Dalfox marker that survived the
    // round-trip under ASCII case-folding (e.g. a server that uppercases
    // everything before reflecting), treat the response as a reflection.
    //
    // The dynamic markers are `dlx` + 8 random hex digits — case-folded
    // they remain unique to this scan, so finding the marker in the
    // lowercased response is a strong "this came from our payload" signal.
    // Without this fallback, endpoints like xssmaze `obfuscation/level2`
    // (`query.upcase`) and `casemanip/level3` (alpha case swap) escape
    // every reflection check above and produce zero findings.
    if marker_case_fold_reflected(resp_text, payload) {
        return Some(ReflectionKind::Raw);
    }

    None
}

/// True when the payload embeds a Dalfox marker (class/id, dynamic or
/// legacy) and that marker appears in `resp_text` only after ASCII
/// case-folding. Used as a last-chance reflection signal for servers
/// that uppercase / lowercase every reflected byte (xssmaze
/// `obfuscation/level2`, `casemanip/level3`) where every other variant
/// check still produces a byte-exact mismatch.
///
/// The fallback intentionally returns `false` whenever any carried
/// marker is already present in `resp_text` under exact case: the
/// standard reflection-variant paths above will have already fired (or
/// can be reached by callers via `has_marker_evidence`) and we should
/// not double-classify the same response as a case-folded reflection.
fn marker_case_fold_reflected(resp_text: &str, payload: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    let candidates: [&str; 3] = [class_marker, id_marker, "dalfox"];

    // Cheap reject — fast-fail before touching response bytes when the
    // payload carries no marker at all. classify_reflection runs once
    // per payload variant per response, so the hot-path cost of this
    // fallback must stay near a few substring scans on payload itself.
    let mut carried: [&str; 3] = [""; 3];
    let mut carried_len = 0usize;
    for marker in &candidates {
        if payload.contains(*marker) {
            carried[carried_len] = *marker;
            carried_len += 1;
        }
    }
    if carried_len == 0 {
        return false;
    }

    // Same-case marker already in response — let the standard
    // reflection / marker-evidence paths handle it and avoid
    // re-classifying as case-folded.
    for marker in carried[..carried_len].iter() {
        if resp_text.contains(*marker) {
            return false;
        }
    }

    // Case-insensitive substring search over response bytes without
    // allocating a lowercased copy. Markers are short (~11 bytes), so
    // O(n*m) is fine here while avoiding the per-call String alloc
    // that the naive `to_ascii_lowercase().contains(...)` shape costs
    // on every redundant fallback invocation.
    carried[..carried_len]
        .iter()
        .any(|m| ascii_ci_contains(resp_text, m))
}

/// True iff `needle` appears in `haystack` under ASCII case-fold,
/// without allocating a lowercased copy of either string.
fn ascii_ci_contains(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    let first = n[0].to_ascii_lowercase();
    let end = h.len() - n.len();
    let mut i = 0;
    'outer: while i <= end {
        if h[i].to_ascii_lowercase() != first {
            i += 1;
            continue;
        }
        for j in 1..n.len() {
            if !h[i + j].eq_ignore_ascii_case(&n[j]) {
                i += 1;
                continue 'outer;
            }
        }
        return true;
    }
    false
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
    streak: &std::sync::atomic::AtomicU32,
) -> Option<String> {
    if args.skip_xss_scanning {
        return None;
    }
    let client = target.build_client_or_default();
    fetch_injection_response_with_client(&client, target, param, payload, args, streak).await
}

async fn fetch_injection_response_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
    streak: &std::sync::atomic::AtomicU32,
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
            // Query / Path: inject encoded payload into the URL.
            // `effective_query_base` rebases Query params discovered through
            // a `<form action=...>` onto the action endpoint; Path keeps
            // target.url because path-segment injection depends on the
            // original path layout.
            let base_url = crate::scanning::url_inject::effective_query_base(&target.url, param);
            let inject_url =
                crate::scanning::url_inject::build_injected_url(&base_url, param, &encoded_payload);
            let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| base_url.clone());
            crate::utils::build_request(
                client,
                target,
                default_method,
                parsed_url,
                target.data.clone(),
            )
        }
    };

    // Send the injection request. send_with_retry acquires a --rate-limit
    // permit and applies the --retries / --retry-delay policy internally.
    let inject_resp =
        crate::utils::send_with_retry(inject_request, args.retries, args.retry_delay).await;
    crate::tick_request_count();

    // Adaptive inter-request pause: user --delay plus the detected WAF's
    // pacing hint, randomized with jitter under --waf-evasion so the cadence
    // isn't a fixed interval a WAF can lock onto.
    let pause = crate::utils::rate_limit::inter_request_pause(
        target.delay,
        target.waf_extra_delay_ms,
        args.waf_evasion,
    );
    if !pause.is_zero() {
        sleep(pause).await;
    }

    // For Stored XSS, check reflection on auto-resolved URLs with retry logic.
    //
    // We MUST verify the payload actually reflects in each candidate body
    // before returning it — otherwise the first non-empty page (a login
    // form, an empty list, a session-expired page) short-circuits the loop
    // and the real retrieval URL is never tried, producing a false negative.
    //
    // Fallback: if no candidate URL contains the payload but at least one
    // returned a non-empty body, return that body. Callers downstream will
    // run classify_reflection again and conclude "no reflection" — same
    // outcome as before, but only after every URL had a fair chance.
    //
    // Inline-stored sinks: many stored sinks (comment boxes, profile
    // updaters, message composers) render the payload directly into the
    // write-response body — i.e. the same response we already have in hand
    // from the injection request. If retrieval URLs don't surface the
    // payload, classify the inject body before giving up.
    if args.sxss {
        // Eagerly consume the injection response body so we can use it as
        // an inline-rendered fallback. We drop status/headers because the
        // retrieval-URL path doesn't gate on them either, and we want
        // consistent SXSS evidence semantics.
        let inject_body: Option<String> = match inject_resp {
            Ok(resp) => {
                // Mirror the normal path's WAF accounting on the stored-write
                // response before consuming the body: a 403/406/503 stored-write
                // block must drive the same --waf-evasion cooldown + consecutive
                // streak and record bypass telemetry. Without this, SXSS scans
                // hammer a blocking write endpoint (IP-ban risk) and
                // target_summary.waf.bypass is always empty.
                let status_code = resp.status().as_u16();
                apply_injection_waf_accounting(status_code, target, args, streak).await;
                crate::utils::http::read_body(resp)
                    .await
                    .ok()
                    .filter(|t| !t.is_empty())
            }
            Err(_) => None,
        };

        let check_urls = resolve_sxss_check_urls(target, param, args);
        let retries = args.sxss_retries.max(1) as u64;
        let mut fallback_body: Option<String> = None;
        for sxss_url in &check_urls {
            // Retry with delay to handle session / content propagation
            for attempt in 0u64..retries {
                if attempt > 0 {
                    sleep(Duration::from_millis(500 * attempt)).await;
                }
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(client, target, method, sxss_url.clone(), None);

                crate::record_outbound_request().await;
                if let Ok(resp) = check_request.send().await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && !text.is_empty()
                {
                    if classify_reflection(&text, payload).is_some() {
                        return Some(text);
                    }
                    if fallback_body.is_none() {
                        fallback_body = Some(text);
                    }
                }
            }
        }
        // Inline-stored sink fallback: the inject response body itself often
        // renders the stored value (e.g. POST /comments returns the rendered
        // /comments page). Without this check we'd miss the entire class
        // of sinks where the write-response is the rendered view.
        if let Some(body) = inject_body.as_ref()
            && classify_reflection(body, payload).is_some()
        {
            return inject_body;
        }
        fallback_body.or(inject_body)
    } else {
        // Normal reflection check
        if let Ok(resp) = inject_resp {
            let status_code = resp.status().as_u16();

            // Adaptive WAF accounting (per-worker streak + cooldown + telemetry).
            apply_injection_waf_accounting(status_code, target, args, streak).await;

            // Skip processing if the status code is in the ignore_return list
            if !args.ignore_return.is_empty() && args.ignore_return.contains(&status_code) {
                return None;
            }
            // Inert-data content-type suppression for ALL non-Path locations.
            // When the response declares a structured-data / binary type
            // (`application/json`, `text/csv`, raster image, …), a browser
            // navigating to it renders the body as data — never as markup —
            // so a payload reflected into it is not exploitable as reflected
            // XSS even when the body happens to contain HTML-looking text.
            // This removes the false positives where a query/body param is
            // echoed into a JSON API response (e.g. `{"q":"<svg onload=…>"}`).
            // Path has its own stricter markup-only gate just below; JSONP
            // (`application/javascript`) and sniffable `text/plain` are
            // intentionally NOT treated as inert here (see
            // `content_type_is_inert_data`), preserving those detections.
            //
            // Skip redirects: a 3xx carries the reflection in its `Location`
            // header, and the body content-type describes the (usually empty)
            // redirect body, not the redirect target — so it says nothing about
            // whether the Location reflection is exploitable. Let those fall
            // through to the Location-header check below.
            if !matches!(param.location, Location::Path) && !(300..400).contains(&status_code) {
                let ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if crate::utils::content_type_is_inert_data(ct) {
                    crate::dbg_log!(
                        "suppressing reflection on inert-data content-type (param={}, content-type={})",
                        param.name,
                        ct
                    );
                    return None;
                }
            }
            // Hard suppressions for Path that don't need to read the body:
            //   * 3xx redirects: any reflection lives in the Location header,
            //     not a rendered HTML sink. Browsers don't execute Location
            //     bodies, so there's nothing exploitable here regardless of
            //     marker context — keep the old blanket drop.
            //   * non-HTML content-types: response is JSON / JS / image and
            //     browsers render it as data, not markup.
            if matches!(param.location, Location::Path) {
                if (300..400).contains(&status_code) {
                    crate::dbg_log!(
                        "suppressing path reflection on 3xx redirect (param={}, status={})",
                        param.name,
                        status_code
                    );
                    return None;
                }
                let ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                // `image/svg+xml` executes inline <script>/event handlers on
                // top-level navigation, so a dynamically-generated SVG that
                // reflects a path segment is a real sink — allow it alongside
                // the HTML-ish types (don't open up JSON/JS/raster, which render
                // as data).
                let executes_as_markup = crate::utils::is_htmlish_content_type(ct)
                    || crate::utils::content_type_primary(ct).as_deref() == Some("image/svg+xml");
                if !ct.is_empty() && !executes_as_markup {
                    crate::dbg_log!(
                        "suppressing path-injection reflection on non-HTML content-type (param={}, content-type={})",
                        param.name,
                        ct
                    );
                    return None;
                }
            }
            // Check for redirect context: if the response is a 3xx redirect,
            // the Location header may contain the reflected payload in either
            // its encoded or decoded form (some servers parse the query and
            // rebuild the redirect URL, which decodes the payload on the way).
            // (Path was already returned above; this only fires for
            // Query/Header/Cookie/Body/etc.)
            if resp.status().is_redirection()
                && let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
                && (location.contains(&*encoded_payload) || location.contains(payload))
            {
                // Wrap the Location value in a minimal HTML container so the
                // downstream reflection check still finds the payload via
                // substring match, but the JS-context AST verifier cannot
                // parse the synthesized text as JavaScript and wrongly
                // upgrade the finding to V. Without the wrapper, a literal
                // `Location: javascript:alert(1)` becomes a freestanding
                // expression statement that the oxc parser accepts, which
                // triggered V on redirects that no browser ever follows
                // (browsers refuse `javascript:` / `data:` schemes in 3xx
                // `Location:` headers). The wrapper starts with `<html>`,
                // which fails JS parsing cleanly, so reflection-finding
                // R is preserved while the false V upgrade is blocked.
                return Some(format!("<html><body>{}</body></html>", location));
            }
            match crate::utils::http::read_body(resp).await {
                Ok(body) => {
                    // Body-aware Path suppression for 4xx/5xx: keep the
                    // finding when the marker reflects somewhere other than
                    // URL-valued attributes (genuine error-page XSS, e.g. a
                    // 404 template that renders the URI inside
                    // `<td>...</td>`). Pure URL echo (canonical link,
                    // `<a href>` breadcrumbs) is still dropped as noise.
                    if should_suppress_path_reflection_with_body(
                        &param.location,
                        status_code,
                        &body,
                        payload,
                    ) {
                        crate::dbg_log!(
                            "suppressing url-echo-only path reflection (param={}, status={})",
                            param.name,
                            status_code
                        );
                        return None;
                    }
                    Some(body)
                }
                Err(e) => {
                    crate::dbg_log!(
                        "reflection response body read failed (param={}): {}",
                        param.name,
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    }
}

/// Inject `payload`, then classify reflection in the response. Convenience
/// entry for tests / one-shot callers: uses a throwaway per-call WAF streak.
/// Production scan workers call [`check_reflection_with_response_tracked`] with
/// their own per-worker streak so the adaptive backoff escalates correctly.
pub async fn check_reflection_with_response(
    client: Option<&Client>,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    let streak = std::sync::atomic::AtomicU32::new(0);
    check_reflection_with_response_tracked(client, target, param, payload, args, &streak).await
}

/// Inject `payload`, then classify reflection in the response.
///
/// Pass `Some(client)` to reuse a pooled HTTP client (MCP / REST runners);
/// pass `None` on the CLI path to build a default client per request from
/// the target. Returns the reflection kind (suppressed to `None` when the
/// match lands only in a known-safe context) together with the response
/// body, or `(None, None)` when no response was obtained.
///
/// `streak` is the caller's per-worker consecutive-WAF-block counter (see
/// [`apply_injection_waf_accounting`]); one per param worker keeps the
/// `--waf-evasion` backoff escalation from being reset by sibling workers.
pub async fn check_reflection_with_response_tracked(
    client: Option<&Client>,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
    streak: &std::sync::atomic::AtomicU32,
) -> (Option<ReflectionKind>, Option<String>) {
    let text = match client {
        Some(client) => {
            fetch_injection_response_with_client(client, target, param, payload, args, streak).await
        }
        None => fetch_injection_response(target, param, payload, args, streak).await,
    };
    if let Some(text) = text {
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

/// Test-only convenience wrapper over [`check_reflection_with_response`]:
/// discards the body and reports only whether a (non-safe-context) reflection
/// was found, always building a default client. Production code calls
/// [`check_reflection_with_response`] directly with a pooled client.
#[cfg(test)]
async fn check_reflection(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> bool {
    check_reflection_with_response(None, target, param, payload, args)
        .await
        .0
        .is_some()
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

    let inject_resp =
        crate::utils::send_with_retry(inject_request, args.retries, args.retry_delay).await;
    crate::tick_request_count();

    let pause = crate::utils::rate_limit::inter_request_pause(
        target.delay,
        target.waf_extra_delay_ms,
        args.waf_evasion,
    );
    if !pause.is_zero() {
        tokio::time::sleep(pause).await;
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
        // Cap the body read like every other scan-path read: a target serving a
        // huge body must not balloon the scanner's memory. `resp.text()` here was
        // the one site that bypassed `read_body`'s 16 MiB cap, so an attacker-
        // controlled target could drive RSS far past the intended workers × cap
        // bound (verified: a 200 MB body pushed peak RSS to ~1.2 GiB).
        if let Ok(text) = crate::utils::http::read_body(resp).await {
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
