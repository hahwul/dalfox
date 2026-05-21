//! # Stage 6: DOM Verification
//!
//! Confirms that a reflected payload actually creates exploitable DOM structure
//! (not just textual reflection). This upgrades a finding from type "R"
//! (Reflected) to "V" (DOM-verified).
//!
//! **Input:** `(Param, payload: &str)` — a parameter + payload that already
//! passed Stage 5 reflection check.
//!
//! **Output:** `(bool, Option<String>)` — whether DOM evidence was found, and
//! the response HTML body. Evidence requires *both* reflection *and* one of:
//! - Dalfox marker element (class/id `dlx`-hex or legacy `dalfox`) found via
//!   CSS selector in parsed DOM
//! - Executable URL protocol (`javascript:`, `data:text/html`, `vbscript:`)
//!   reflected into a dangerous attribute (href, src, action, etc.)
//!
//! **Side effects:** One HTTP request (with rate-limit retry). For stored XSS
//! (`--sxss`), sends the injection request then checks a secondary URL for
//! the stored payload. Applies `pre_encoding` as `encoded_payload` for the
//! request but checks DOM evidence against the raw `payload`.

use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use reqwest::Client;
use std::sync::OnceLock;
use tokio::time::{Duration, sleep};

use super::selectors;

fn cached_class_marker_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        let marker = crate::scanning::markers::class_marker();
        scraper::Selector::parse(&format!(".{}", marker)).expect("valid class marker selector")
    })
}

fn cached_id_marker_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        let marker = crate::scanning::markers::id_marker();
        scraper::Selector::parse(&format!("#{}", marker)).expect("valid id marker selector")
    })
}

fn cached_legacy_class_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| scraper::Selector::parse(".dalfox").expect("valid selector"))
}

fn cached_legacy_id_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| scraper::Selector::parse("#dalfox").expect("valid selector"))
}

fn payload_uses_legacy_class_marker(payload: &str) -> bool {
    payload.contains("class=dalfox")
        || payload.contains("class=\"dalfox\"")
        || payload.contains("class='dalfox'")
}

fn payload_uses_legacy_id_marker(payload: &str) -> bool {
    payload.contains("id=dalfox")
        || payload.contains("id=\"dalfox\"")
        || payload.contains("id='dalfox'")
}

/// Whether the payload carries at least one Dalfox marker that warrants a
/// DOM-level selector lookup. When false, the caller can skip HTML parsing.
fn payload_has_any_marker(payload: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    payload.contains(class_marker)
        || payload.contains(id_marker)
        || payload_uses_legacy_class_marker(payload)
        || payload_uses_legacy_id_marker(payload)
}

/// Returns `true` when at least one element's whitespace-separated class
/// list contains `marker` under ASCII case-fold comparison. The standard
/// CSS class selector path used elsewhere is case-sensitive (HTML5 class
/// attributes are case-sensitive when matched as CSS selectors), so this
/// scan is the only way to surface marker evidence on servers that
/// case-fold the entire reflected input.
fn any_element_has_class_ascii_ci(document: &scraper::Html, marker: &str) -> bool {
    let selector = super::selectors::universal();
    document.select(selector).any(|node| {
        node.value()
            .attr("class")
            .map(|cls| {
                cls.split_ascii_whitespace()
                    .any(|c| c.eq_ignore_ascii_case(marker))
            })
            .unwrap_or(false)
    })
}

/// Like `any_element_has_class_ascii_ci`, but compares the element's `id`
/// attribute as a whole token. HTML id values are not whitespace-separated
/// lists, so the comparison is over the trimmed attribute value.
fn any_element_has_id_ascii_ci(document: &scraper::Html, marker: &str) -> bool {
    let selector = super::selectors::universal();
    document.select(selector).any(|node| {
        node.value()
            .attr("id")
            .map(|id| id.trim().eq_ignore_ascii_case(marker))
            .unwrap_or(false)
    })
}

fn has_marker_evidence_in_doc(payload: &str, document: &scraper::Html) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let has_class = payload.contains(class_marker);
    let has_legacy_class = payload_uses_legacy_class_marker(payload);
    let has_id = payload.contains(id_marker);
    let has_legacy_id = payload_uses_legacy_id_marker(payload);

    if !has_class && !has_legacy_class && !has_id && !has_legacy_id {
        return false;
    }

    let class_ok = if has_class || has_legacy_class {
        let mut found = false;
        if has_class {
            found = document
                .select(cached_class_marker_selector())
                .next()
                .is_some();
            if !found {
                // Case-folded fallback for servers that uppercase/lowercase
                // reflected input. Markers are 11-char `dlx<hex>` strings
                // with no realistic ASCII case-fold collisions, so a
                // case-insensitive class-list match is still a unique
                // "came from our payload" signal.
                found = any_element_has_class_ascii_ci(document, class_marker);
            }
        }
        if !found && has_legacy_class {
            found = document
                .select(cached_legacy_class_selector())
                .next()
                .is_some();
            if !found {
                found = any_element_has_class_ascii_ci(document, "dalfox");
            }
        }
        found
    } else {
        true
    };

    let id_ok = if has_id || has_legacy_id {
        let mut found = false;
        if has_id {
            found = document
                .select(cached_id_marker_selector())
                .next()
                .is_some();
            if !found {
                found = any_element_has_id_ascii_ci(document, id_marker);
            }
        }
        if !found && has_legacy_id {
            found = document
                .select(cached_legacy_id_selector())
                .next()
                .is_some();
            if !found {
                found = any_element_has_id_ascii_ci(document, "dalfox");
            }
        }
        found
    } else {
        true
    };

    class_ok && id_ok
}

pub(crate) fn has_marker_evidence(payload: &str, text: &str) -> bool {
    if !payload_has_any_marker(payload) {
        return false;
    }
    let document = scraper::Html::parse_document(text);
    has_marker_evidence_in_doc(payload, &document)
}

/// Case-insensitive ASCII prefix check without allocating a lowercased copy.
/// Only ASCII bytes are case-folded; non-ASCII bytes are compared as-is.
/// Callers must ensure `prefix` is ASCII (e.g. protocol schemes like "javascript:").
fn starts_with_ascii_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn payload_is_executable_url_protocol(payload: &str) -> bool {
    let trimmed = payload.trim();
    starts_with_ascii_ci(trimmed, "javascript:")
        || starts_with_ascii_ci(trimmed, "data:text/html")
        || starts_with_ascii_ci(trimmed, "vbscript:")
}

/// Decide whether an `(element, attribute)` pair is a real navigation /
/// embedding sink for an executable URL scheme (`javascript:`, `data:`,
/// `vbscript:`).
///
/// The previous attribute-only check treated every `src=` / `href=` as
/// equally dangerous, which over-counts attributes whose URL value the
/// browser refuses to honour as an executable scheme. The most common
/// regression is `<img src="javascript:…">`: modern browsers ignore the
/// scheme on `img@src` (the request is a fetch for an image resource, not
/// a navigation), so verifying that case produces a High-severity finding
/// that is structurally not exploitable.
///
/// The whitelist below names only attributes a browser will actually
/// dereference as a top-level navigation, frame load, form submit, or
/// resource fetch where `javascript:` runs as code:
///
/// - `a/@href`, `area/@href`, `base/@href`, `link/@href` — navigation
/// - `iframe/@src`, `embed/@src`, `frame/@src` — frame load
/// - `iframe/@srcdoc` — HTML embedded in iframe
/// - `object/@data` — plugin / embed
/// - `form/@action`, `input/@formaction`, `button/@formaction` — submit
/// - `xlink:href` on SVG `<a>` / `<use>` — SVG navigation / external load
///
/// Attributes deliberately omitted: `img/@src`, `audio/@src`, `video/@src`,
/// `source/@src`, `script/@src`, `track/@src` (all of which fetch a
/// resource rather than execute the URL as code).
fn is_executable_url_attribute(element_tag: &str, attr_name: &str) -> bool {
    let attr = attr_name.to_ascii_lowercase();
    let tag = element_tag.to_ascii_lowercase();
    match attr.as_str() {
        "href" => matches!(tag.as_str(), "a" | "area" | "base" | "link"),
        "src" => matches!(tag.as_str(), "iframe" | "embed" | "frame"),
        "srcdoc" => tag == "iframe",
        "data" => tag == "object",
        "action" => tag == "form",
        "formaction" => matches!(tag.as_str(), "input" | "button"),
        "xlink:href" => matches!(tag.as_str(), "a" | "use"),
        _ => false,
    }
}

/// Decide whether a reflected attribute value should count as an executable
/// URL hit for `payload_trimmed`. The previous check required strict equality,
/// which over-rejected real exploits like `<a href="javascript:alert(1)//xyz">`
/// where the server appends or prepends bytes around our reflected scheme.
///
/// Browsers parse the *whole* attribute value as a single URL, so the
/// observable rule is: the trimmed value must start with one of the
/// executable URL schemes (case-insensitive), and the bytes of `payload_trimmed`
/// must appear verbatim somewhere in the value so we know the payload
/// genuinely drives the execution rather than merely sharing a scheme with an
/// unrelated server-emitted `javascript:` URL.
fn attribute_value_executes_payload(value: &str, payload_trimmed: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case(payload_trimmed) {
        return true;
    }
    let starts_executable = starts_with_ascii_ci(trimmed, "javascript:")
        || starts_with_ascii_ci(trimmed, "data:text/html")
        || starts_with_ascii_ci(trimmed, "vbscript:");
    if !starts_executable {
        return false;
    }
    trimmed.contains(payload_trimmed)
}

fn has_executable_url_attribute_evidence_in_doc(payload: &str, document: &scraper::Html) -> bool {
    if !payload_is_executable_url_protocol(payload) {
        return false;
    }

    let payload_trimmed = payload.trim();
    let selector = selectors::universal();

    document.select(selector).any(|node| {
        let tag = node.value().name();
        node.value().attrs().any(|(name, value)| {
            is_executable_url_attribute(tag, name)
                && attribute_value_executes_payload(value, payload_trimmed)
        })
    })
}

/// True when the payload introduced (a) an HTML element with an event-handler
/// attribute whose value contains a JavaScript sink call, OR (b) a `<script>`
/// element whose body is the payload-carried sink call. The "introduced by the
/// payload" check is enforced by requiring the parsed attribute value /
/// script body to appear verbatim inside the original payload string —
/// otherwise the matched element belonged to the original page.
///
/// Catches realistic XSS payloads that don't embed a Dalfox marker, e.g.
/// `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`,
/// `<script>alert(1)</script>` from custom payload lists.
fn has_html_structural_evidence_in_doc(payload: &str, document: &scraper::Html) -> bool {
    if !payload.contains('<') {
        return false;
    }
    if !crate::scanning::js_context_verify::payload_carries_js_sink(payload) {
        return false;
    }

    let selector = selectors::universal();
    for node in document.select(selector) {
        let value = node.value();
        let tag = value.name();

        // (a) Event-handler attribute introduced by the payload.
        for (attr_name, attr_value) in value.attrs() {
            if attr_name.len() < 3 || !attr_name.as_bytes()[..2].eq_ignore_ascii_case(b"on") {
                continue;
            }
            let trimmed = attr_value.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !crate::scanning::js_context_verify::payload_carries_js_sink(trimmed) {
                continue;
            }
            if payload.contains(trimmed) {
                return true;
            }
        }

        // (b) <script> element whose text body came from the payload.
        if tag.eq_ignore_ascii_case("script") {
            let text: String = node.text().collect();
            let trimmed = text.trim();
            if !trimmed.is_empty()
                && crate::scanning::js_context_verify::payload_carries_js_sink(trimmed)
                && payload.contains(trimmed)
            {
                return true;
            }
        }
    }
    false
}

/// Cheap response-body heuristic: returns false for bodies that look like
/// raw JSON/array payloads where browsers do not render the response as HTML.
/// Used to gate the HTML structural-evidence check, which would otherwise
/// false-positive on JSON responses that scraper happily parses as HTML.
fn body_looks_html_renderable(text: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    let first = trimmed.as_bytes()[0];
    // JSON object / array — would be rendered as text by browsers, not HTML.
    if first == b'{' || first == b'[' {
        return false;
    }
    true
}

/// Which evidence path proved the payload exploitable. Returned by
/// `classify_dom_evidence` so callers can surface a human-friendly hint
/// in the V finding (e.g. "JS-context AST" vs "DOM marker").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomEvidenceKind {
    /// Dalfox marker class/id observed in the parsed DOM.
    Marker,
    /// Executable URL protocol (`javascript:` / `data:`) reflected into a
    /// dangerous attribute (href, src, action, etc.).
    ExecutableUrl,
    /// Parsed HTML element introduced by the payload carries an event-handler
    /// attribute (or `<script>` body) containing a JS sink call.
    HtmlStructural,
    /// JS-context: payload reflected inside `<script>` produced a sink
    /// CallExpression / AssignmentExpression covered by the payload's range.
    JsContext,
    /// Payload landed inside an existing `on*` attribute value (server's
    /// own template, not a payload-introduced tag) and broke out of the
    /// surrounding JS string so a sink call is now part of the handler
    /// expression — the xss-game L4 shape, where `<img onload="startTimer(
    /// 'INJECT')">` becomes `startTimer('';alert(1);'')` once HTML entities
    /// decode at attribute-parse time.
    InlineHandlerBreakout,
}

impl DomEvidenceKind {
    /// Short label suitable for inclusion in V finding messages.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            DomEvidenceKind::Marker => "DOM marker",
            DomEvidenceKind::ExecutableUrl => "javascript: URL in attribute",
            DomEvidenceKind::HtmlStructural => "HTML element with sink",
            DomEvidenceKind::JsContext => "JS-context AST",
            DomEvidenceKind::InlineHandlerBreakout => "inline handler JS breakout",
        }
    }
}

/// Returns the evidence kind that confirms the payload is exploitable, or
/// `None` if no evidence was found. Used by `check_dom_verification` to avoid
/// parsing the same response body twice; short-circuits on the marker check
/// when the payload carries one, which is the common case.
///
/// Five evidence paths, probed in this order:
/// - DOM marker (class/id) found via CSS selector — the standard HTML/attr case
/// - Executable URL protocol reflected into a dangerous attribute — `javascript:`/`data:`
/// - HTML structural: parsed element with `on*` handler containing a sink call,
///   OR `<script>` body containing a sink call, where the value/body appears
///   verbatim in the payload (so it was introduced by the injection)
/// - JS-context sink call expression introduced into an existing `<script>` block
///   (e.g. `var x = "<INJECT>"` where the injection produces a real `alert(...)`)
/// - Inline handler breakout: payload lands inside the server's own
///   `on*` attribute and ends the JS string literal so the resulting
///   handler expression contains a sink call (xss-game L4 shape).
pub(crate) fn classify_dom_evidence(payload: &str, text: &str) -> Option<DomEvidenceKind> {
    let needs_markers = payload_has_any_marker(payload);
    let needs_attrs = payload_is_executable_url_protocol(payload);
    let needs_html_struct = payload.contains('<')
        && crate::scanning::js_context_verify::payload_carries_js_sink(payload)
        && body_looks_html_renderable(text);
    let needs_js = crate::scanning::js_context_verify::payload_carries_js_sink(payload);
    if !needs_markers && !needs_attrs && !needs_html_struct && !needs_js {
        return None;
    }
    if needs_markers || needs_attrs || needs_html_struct {
        let document = scraper::Html::parse_document(text);
        if needs_markers && has_marker_evidence_in_doc(payload, &document) {
            return Some(DomEvidenceKind::Marker);
        }
        if needs_attrs && has_executable_url_attribute_evidence_in_doc(payload, &document) {
            return Some(DomEvidenceKind::ExecutableUrl);
        }
        if needs_html_struct && has_html_structural_evidence_in_doc(payload, &document) {
            return Some(DomEvidenceKind::HtmlStructural);
        }
    }
    if needs_js && crate::scanning::js_context_verify::has_js_context_evidence(payload, text) {
        return Some(DomEvidenceKind::JsContext);
    }
    if needs_js && has_inline_handler_breakout_evidence(payload, text) {
        return Some(DomEvidenceKind::InlineHandlerBreakout);
    }
    None
}

/// Minimum payload length required to consider an `on*` substring
/// match as evidence of an injected breakout. Below this length, common
/// page-defined handlers (`onclick="alert('hi')"`) accidentally contain
/// the payload bytes as a substring and we'd up-grade an unrelated R
/// to a fake V. dalfox's real breakout payloads (`'-alert(1)-'`,
/// `"-alert(1)-"`, `'),alert(1),('`, …) are all comfortably longer.
const MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN: usize = 8;

/// Detects xss-game L4-style inline-handler breakouts: payload lands
/// inside an existing `on*` attribute (the server's template emits
/// `<img onload="startTimer('USER_INPUT')">`), the payload terminates
/// the surrounding JS string literal (`'-alert(1)-'` etc.), and the
/// resulting `on*` attribute value — after HTML-entity decoding the
/// browser performs at attribute parse time — contains a real sink
/// call (`alert(`, `prompt(`, `confirm(`, `eval(`, …).
///
/// Strict on three fronts to avoid false-V on pages whose pre-existing
/// `on*` handlers happen to share substrings with the payload list:
///   * `attr_value.contains(payload)` — payload bytes must literally
///     appear in the entity-decoded handler.
///   * payload length ≥ [`MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN`]
///     — short payloads like `'` or `");` are too common as legit
///     substrings of page-defined handlers.
///   * the sink call sits *inside* the same handler as the payload,
///     confirmed via the contains-check above.
fn has_inline_handler_breakout_evidence(payload: &str, text: &str) -> bool {
    if payload.len() < MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN {
        return false;
    }
    // Decode HTML entities once for the whole body — cheap and lets a
    // single substring search cover the dominant on*-attribute escape
    // pattern that servers use (`&#39;` for `'`, `&quot;` for `"`).
    let decoded = decode_html_entities(text);
    let document = scraper::Html::parse_document(&decoded);
    let selector = selectors::universal();
    for node in document.select(selector) {
        let value = node.value();
        for (attr_name, attr_value) in value.attrs() {
            if attr_name.len() < 3 || !attr_name.as_bytes()[..2].eq_ignore_ascii_case(b"on") {
                continue;
            }
            if !attr_value.contains(payload) {
                continue;
            }
            if crate::scanning::js_context_verify::payload_carries_js_sink(attr_value) {
                return true;
            }
        }
    }
    false
}

/// Minimal HTML entity decoder for the named + numeric escapes that
/// real-world templates emit when escaping user input into attribute
/// values. Mirrors browser behaviour for the cases that matter for
/// inline-handler breakout detection: `&#39;` → `'`, `&quot;` → `"`,
/// `&lt;`/`&gt;`/`&amp;`. Anything we don't recognise passes through
/// unchanged so we never lose bytes.
fn decode_html_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let rest = &s[i + 1..];
        let semi = match rest.find(';') {
            Some(pos) if pos <= 8 => pos,
            _ => {
                out.push(c);
                continue;
            }
        };
        let entity = &rest[..semi];
        let decoded = if let Some(stripped) = entity.strip_prefix('#') {
            let (radix, digits) = if let Some(hex) = stripped.strip_prefix('x') {
                (16, hex)
            } else if let Some(hex) = stripped.strip_prefix('X') {
                (16, hex)
            } else {
                (10, stripped)
            };
            u32::from_str_radix(digits, radix)
                .ok()
                .and_then(char::from_u32)
        } else {
            match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => None,
            }
        };
        match decoded {
            Some(ch) => {
                out.push(ch);
                // Skip past the entity body + ';'.
                for _ in 0..(semi + 1) {
                    chars.next();
                }
            }
            None => {
                out.push(c);
            }
        }
    }
    out
}

/// Backward-compat boolean view used by callers that don't need the kind.
pub(crate) fn has_dom_evidence(payload: &str, text: &str) -> bool {
    classify_dom_evidence(payload, text).is_some()
}

pub async fn check_dom_verification(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }
    let client = target.build_client_or_default();
    check_dom_verification_with_client(&client, target, param, payload, args).await
}

/// Build the HTTP request for injecting the payload based on the parameter location.
fn build_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let default_method = target.parse_method();
    match param.location {
        Location::Header => {
            build_header_request(client, target, param, encoded_payload, default_method)
        }
        Location::Body => build_body_request(client, target, param, encoded_payload),
        Location::JsonBody => build_json_body_request(client, target, param, encoded_payload),
        Location::MultipartBody => build_multipart_request(client, target, param, encoded_payload),
        _ => build_url_inject_request(client, target, param, encoded_payload, default_method),
    }
}

fn build_header_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    let parsed_url = target.url.clone();
    if target.cookies.iter().any(|(name, _)| name == &param.name) {
        let others =
            crate::utils::compose_cookie_header_excluding(&target.cookies, Some(&param.name));
        let cookie_header = match others {
            Some(rest) if !rest.is_empty() => {
                format!("{}={}; {}", param.name, encoded_payload, rest)
            }
            _ => format!("{}={}", param.name, encoded_payload),
        };
        crate::utils::build_request_with_cookie(
            client,
            target,
            method,
            parsed_url,
            target.data.clone(),
            Some(cookie_header),
        )
    } else {
        let base =
            crate::utils::build_request(client, target, method, parsed_url, target.data.clone());
        crate::utils::apply_header_overrides(
            base,
            &[(param.name.clone(), encoded_payload.to_string())],
        )
    }
}

fn resolve_form_action_url(param: &Param, target: &Target) -> url::Url {
    param
        .form_action_url
        .as_ref()
        .and_then(|u| url::Url::parse(u).ok())
        .unwrap_or_else(|| target.url.clone())
}

fn build_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
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
            urlencoding::encode(encoded_payload)
        ))
    };
    let base = crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
    )
}

fn build_json_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let body = if let Some(ref data) = target.data {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.insert(
                    param.name.clone(),
                    serde_json::Value::String(encoded_payload.to_string()),
                );
            }
            Some(serde_json::to_string(&json_val).unwrap_or_else(|_| data.clone()))
        } else {
            Some(data.replace(&param.value, encoded_payload))
        }
    } else {
        Some(serde_json::json!({ &param.name: encoded_payload }).to_string())
    };
    let base = crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[("Content-Type".to_string(), "application/json".to_string())],
    )
}

fn build_multipart_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
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
    crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, None)
        .multipart(form)
}

fn build_url_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    let inject_url_str =
        crate::scanning::url_inject::build_injected_url(&target.url, param, encoded_payload);
    let inject_url = url::Url::parse(&inject_url_str).unwrap_or_else(|_| target.url.clone());
    crate::utils::build_request(client, target, method, inject_url, target.data.clone())
}

/// Verify DOM evidence in a stored XSS scenario by checking secondary URLs.
async fn verify_sxss_dom(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    let check_urls =
        crate::scanning::check_reflection::resolve_sxss_check_urls(target, param, args);
    let retries = args.sxss_retries.max(1) as u64;
    for sxss_url in &check_urls {
        for attempt in 0u64..retries {
            if attempt > 0 {
                sleep(Duration::from_millis(500 * attempt)).await;
            }
            let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
            let check_request =
                crate::utils::build_request(client, target, method, sxss_url.clone(), None);

            crate::tick_request_count();
            if let Ok(resp) = check_request.send().await {
                let headers = resp.headers().clone();
                let ct = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if let Ok(text) = resp.text().await
                    && crate::utils::is_htmlish_content_type(ct)
                    && crate::scanning::check_reflection::classify_reflection(&text, payload)
                        .is_some()
                    && has_dom_evidence(payload, &text)
                {
                    return (true, Some(text));
                }
            }
        }
    }
    (false, None)
}

/// Verify DOM evidence from a normal (non-stored) injection response.
///
/// Special-case for 3xx responses: browsers do not render the response body
/// of a redirect — only the `Location:` header drives navigation. So body
/// content can never become an exploitable DOM in a redirect, and any apparent
/// "DOM evidence" inside it is structurally a false positive. We still inspect
/// `Location:` (an executable-URL protocol there is a real sink) but skip
/// body-based DOM verification entirely.
async fn verify_normal_dom(resp: reqwest::Response, payload: &str) -> (bool, Option<String>) {
    let status = resp.status();
    let headers = resp.headers().clone();

    if status.is_redirection() {
        if let Some(location) = headers.get(reqwest::header::LOCATION)
            && let Ok(loc_str) = location.to_str()
            && let Some(result) = check_redirect_location(loc_str, payload)
        {
            return result;
        }
        return (false, None);
    }

    // Both HTML and non-HTML (JSONP, JSON with HTML) content types are accepted
    // as long as there is reflection + marker/executable-URL evidence in the response.
    if let Ok(text) = resp.text().await
        && crate::scanning::check_reflection::classify_reflection(&text, payload).is_some()
        && has_dom_evidence(payload, &text)
    {
        return (true, Some(text));
    }

    (false, None)
}

/// Inspect a redirect's `Location:` header for evidence that the payload
/// itself drives the navigation.
///
/// Returns `None` in every case today: modern browsers (Chrome, Firefox,
/// Safari, all Chromium derivatives) refuse to navigate to `javascript:`,
/// `data:text/html`, and `vbscript:` URLs supplied via a 3xx `Location:`
/// header — the redirect is silently dropped without executing the URL.
/// Treating such a redirect as DOM-verified produced High-severity findings
/// that no real browser actually fires (observed on xssmaze
/// `/redirect/level{1..4}`), so the V upgrade is removed.
///
/// A bare reflection of the payload *inside* a redirect target URL (typically
/// inside a `?next=…`-style query parameter) is also not verified evidence:
/// it merely forwards the attacker-controlled bytes to the next endpoint,
/// which may or may not turn into a sink there. The reflection-finding path
/// still surfaces these as R when the body contains the payload, which is
/// the appropriate severity tier.
fn check_redirect_location(_loc_str: &str, _payload: &str) -> Option<(bool, Option<String>)> {
    None
}

pub async fn check_dom_verification_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }

    // Apply pre-encoding if the parameter requires it.
    // Use encoded_payload for building the HTTP request, but keep `payload`
    // (the raw/original payload) for response body analysis — the server
    // decodes the encoding and reflects the raw content.
    let encoded_payload = crate::encoding::pre_encoding::apply_param_encoding(payload, param);

    let inject_request = build_inject_request(client, target, param, &encoded_payload);

    // Send the injection request (with rate-limit retry)
    crate::tick_request_count();
    let inject_resp = crate::utils::send_with_retry(inject_request, 3, 5000).await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    if args.sxss {
        verify_sxss_dom(client, target, param, payload, args).await
    } else if let Ok(resp) = inject_resp {
        verify_normal_dom(resp, payload).await
    } else {
        (false, None)
    }
}

#[cfg(test)]
mod tests;
