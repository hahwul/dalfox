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

use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::Client;
use std::sync::OnceLock;
use tokio::time::{Duration, sleep};

use super::decode_html_entities;
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

/// Whether an element carries `marker` as one of its whitespace-separated
/// class tokens under ASCII case-fold comparison.
fn element_class_has(node: scraper::ElementRef, marker: &str) -> bool {
    node.value().attr("class").is_some_and(|cls| {
        cls.split_ascii_whitespace()
            .any(|c| c.eq_ignore_ascii_case(marker))
    })
}

/// Returns `true` when at least one element's whitespace-separated class
/// list contains `marker` under ASCII case-fold comparison. The standard
/// CSS class selector path used elsewhere is case-sensitive (HTML5 class
/// attributes are case-sensitive when matched as CSS selectors), so this
/// scan is the only way to surface marker evidence on servers that
/// case-fold the entire reflected input.
fn any_element_has_class_ascii_ci(document: &scraper::Html, marker: &str) -> bool {
    let selector = super::selectors::universal();
    document
        .select(selector)
        .any(|node| element_class_has(node, marker))
}

/// Whether an element's `id` attribute equals `marker` (trimmed, ASCII
/// case-fold).
fn element_id_is(node: scraper::ElementRef, marker: &str) -> bool {
    node.value()
        .attr("id")
        .is_some_and(|id| id.trim().eq_ignore_ascii_case(marker))
}

/// Like `any_element_has_class_ascii_ci`, but compares the element's `id`
/// attribute as a whole token. HTML id values are not whitespace-separated
/// lists, so the comparison is over the trimmed attribute value.
fn any_element_has_id_ascii_ci(document: &scraper::Html, marker: &str) -> bool {
    let selector = super::selectors::universal();
    document
        .select(selector)
        .any(|node| element_id_is(node, marker))
}

/// Which Dalfox marker forms a payload embeds, derived once from the payload.
/// Sharing this keeps the per-node marker test (`is_marker_element`) cheap — it
/// only checks the forms that can actually be present — and gives the marker
/// gates a single source of truth instead of re-deriving the four booleans.
struct MarkerFlags {
    class: bool,
    legacy_class: bool,
    id: bool,
    legacy_id: bool,
}

impl MarkerFlags {
    fn from_payload(payload: &str) -> Self {
        Self {
            class: payload.contains(crate::scanning::markers::class_marker()),
            legacy_class: payload_uses_legacy_class_marker(payload),
            id: payload.contains(crate::scanning::markers::id_marker()),
            legacy_id: payload_uses_legacy_id_marker(payload),
        }
    }

    fn any(&self) -> bool {
        self.class || self.legacy_class || self.id || self.legacy_id
    }
}

/// Whether `node` carries one of the marker forms the payload embeds (per
/// `flags`). All four comparisons are ASCII case-fold (see `element_class_has`
/// / `element_id_is`), so a server that case-folds reflected input still
/// matches.
fn is_marker_element(node: scraper::ElementRef, flags: &MarkerFlags) -> bool {
    (flags.class && element_class_has(node, crate::scanning::markers::class_marker()))
        || (flags.legacy_class && element_class_has(node, "dalfox"))
        || (flags.id && element_id_is(node, crate::scanning::markers::id_marker()))
        || (flags.legacy_id && element_id_is(node, "dalfox"))
}

/// Whether `value` (an `on*` handler value or `<script>` body) carries a
/// JavaScript sink call, tolerating ASCII case-folding (servers that uppercase
/// reflected input) and HTML-entity encoding (WAF-bypass payloads like
/// `alert&#40;1&#41;`), mirroring the decode handling in
/// [`has_html_structural_evidence_in_doc`].
fn value_carries_js_sink(value: &str) -> bool {
    use crate::scanning::js_context_verify::payload_carries_js_sink as sink;
    sink(value)
        || sink(&value.to_ascii_lowercase())
        || sink(&decode_html_entities(value))
        || sink(&decode_html_entities(&value.to_ascii_lowercase()))
}

/// Whether `node`'s own attributes/body carry a surviving JS sink: an `on*`
/// event-handler attribute whose value is a sink call, or a `<script>` element
/// whose text body is a sink call. This is the "active ingredient" a
/// handler/script-body marker template attaches *directly to the marker
/// element*; if it did not survive the server's reflection, the marker class
/// alone is not proof of execution (issue #1118).
fn element_carries_surviving_sink(node: scraper::ElementRef) -> bool {
    let v = node.value();
    for (name, val) in v.attrs() {
        if name.len() >= 3
            && name.as_bytes()[..2].eq_ignore_ascii_case(b"on")
            && value_carries_js_sink(val)
        {
            return true;
        }
    }
    if v.name().eq_ignore_ascii_case("script") {
        let text: String = node.text().collect();
        if value_carries_js_sink(&text) {
            return true;
        }
    }
    false
}

/// Whether `node` is a `<input type="hidden">` element. Such inputs have no
/// rendered box: the browser never lays them out, so they cannot be hovered,
/// focused, or clicked, and they load no resource. Any `on*` event handler
/// injected onto a hidden input therefore never fires — verifying it as DOM
/// evidence is a false positive (issue #1183).
///
/// Scope is deliberately limited to `type="hidden"`. Other input types that
/// look "special" — `submit`, `button`, `image`, `file`, `reset` — are still
/// rendered and interactive, so their handlers *do* fire; lumping them in here
/// would suppress genuine findings. `display:none` / the global `hidden`
/// attribute are intentionally excluded too: detecting them reliably needs CSS
/// (which a stylesheet or script can override), so gating on them risks false
/// negatives.
fn is_hidden_input(node: scraper::ElementRef) -> bool {
    let v = node.value();
    v.name().eq_ignore_ascii_case("input")
        && v.attr("type")
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("hidden"))
}

/// Whether the payload attaches an on*-handler / `<script>`-body JS sink
/// *directly to its marker element*. Parses the payload as an HTML fragment
/// (appending a closing `>` so breakout payloads such as
/// `'"><svg/class=… onload=…//` still yield the element) and also the
/// entity-decoded form, then inspects the element carrying the class/id marker.
///
/// Returns `false` for structural markers — base-href injection, DOM-clobbering
/// containers (`<form id=…>`, `<object data=javascript:…>`) — where the marker
/// element's mere presence is the exploit and there is no on*/script sink on it
/// to verify, so those keep presence-only evidence.
fn payload_marker_element_carries_sink(payload: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    // Inspect the raw payload and, only when it differs, its entity-decoded form
    // (WAF-bypass payloads encode the sink chars). Skipping the no-op decoded
    // pass avoids re-parsing an identical fragment.
    let decoded = decode_html_entities(payload);
    let mut candidates = vec![payload];
    if decoded != payload {
        candidates.push(decoded.as_str());
    }
    for candidate in candidates {
        let normalized = if candidate.trim_end().ends_with('>') {
            candidate.to_string()
        } else {
            format!("{candidate}>")
        };
        // Bounded: html5ever is O(depth^2) and this runs once per payload, so a
        // single pathological entry in a `--custom-payload` file or a fetched
        // `--remote-payloads` list would stall the scan. See
        // `utils::html::parse_fragment_bounded`.
        let frag = crate::utils::html::parse_fragment_bounded(&normalized);
        let sel = super::selectors::universal();
        let hit = frag.select(sel).any(|node| {
            let is_marker = element_class_has(node, class_marker)
                || element_class_has(node, "dalfox")
                || element_id_is(node, id_marker)
                || element_id_is(node, "dalfox");
            is_marker && element_carries_surviving_sink(node)
        });
        if hit {
            return true;
        }
    }
    false
}

/// Whether `payload` can open an HTML tag of its own — a `<` followed by a
/// tag-name start, a closing tag, or a markup declaration — in either its raw
/// or its entity-decoded form.
///
/// Payloads that *cannot* are pure attribute-injection fragments
/// (`" onmouseover=alert(1) class=… x="`): everything they contribute lands on
/// a tag the server already wrote, so whether the handler survives depends
/// entirely on the surrounding markup and can only be answered against the
/// response.
fn payload_opens_tag(payload: &str) -> bool {
    fn opens(text: &str) -> bool {
        text.as_bytes()
            .windows(2)
            .any(|w| w[0] == b'<' && (w[1].is_ascii_alphabetic() || w[1] == b'/' || w[1] == b'!'))
    }
    opens(payload) || opens(&decode_html_entities(payload))
}

/// Whether `payload` contains an `on<event>=` attribute whose value carries a
/// JavaScript sink call.
///
/// Deliberately textual: the shapes this exists for
/// (`'/onmouseover="{JS}"/id="{ID}"/x='`, `" onmouseover={JS} class={CLASS} x="`)
/// form no element on their own, so an HTML fragment parse yields nothing to
/// inspect. Only the attribute *name* is matched structurally (`on` + letters,
/// not preceded by an identifier character, followed by optional whitespace and
/// `=`); the sink test then runs over the remainder of the payload, which is
/// where the handler value lives.
fn payload_has_handler_sink_text(payload: &str) -> bool {
    let bytes = payload.as_bytes();
    for i in 0..bytes.len() {
        if !(bytes[i] | 0x20).eq(&b'o') || i + 2 >= bytes.len() {
            continue;
        }
        if !(bytes[i + 1] | 0x20).eq(&b'n') {
            continue;
        }
        // `on` must start an attribute name, not sit inside a longer word
        // (`button`, `session`, …).
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'-')) {
            continue;
        }
        let mut end = i + 2;
        while end < bytes.len() && bytes[end].is_ascii_alphabetic() {
            end += 1;
        }
        if end == i + 2 {
            continue; // bare `on`, no event name
        }
        let mut eq = end;
        while eq < bytes.len() && bytes[eq].is_ascii_whitespace() {
            eq += 1;
        }
        if eq >= bytes.len() || bytes[eq] != b'=' {
            continue;
        }
        if value_carries_js_sink(&payload[eq + 1..]) {
            return true;
        }
    }
    false
}

/// Whether `payload` is a bare attribute-injection fragment that attaches an
/// `on*` handler sink: it opens no tag of its own, yet carries a handler whose
/// value is a JS sink.
///
/// These payloads slip past [`payload_marker_element_carries_sink`] because
/// parsing them as an HTML fragment yields a text node and no element at all.
/// Their marker and their handler are always emitted onto the *same* injected
/// attribute run (see the `ATTR_*` templates in `payload::synthesis`), so if the
/// response shows the marker on an element that carries no surviving handler,
/// the handler was swallowed by the surrounding markup and nothing executes.
fn payload_is_bare_attribute_handler_injection(payload: &str) -> bool {
    !payload_opens_tag(payload) && payload_has_handler_sink_text(payload)
}

/// Whether at least one element carrying one of the payload's markers also
/// carries a surviving JS sink. Used to gate the marker-evidence path for
/// payloads whose marker element's own attributes/body ARE the exploit.
fn marker_element_carries_surviving_sink(payload: &str, document: &scraper::Html) -> bool {
    let flags = MarkerFlags::from_payload(payload);
    let sel = super::selectors::universal();
    document
        .select(sel)
        .any(|node| is_marker_element(node, &flags) && element_carries_surviving_sink(node))
}

/// Whether the payload's marker rides *only* on `<input type="hidden">`
/// element(s), at least one of which carries an injected `on*` event-handler
/// sink. That handler can never fire — a hidden input has no rendered box — so
/// the reflection is real but inert and must not be upgraded to DOM-verified
/// (issue #1183). The reflection-finding path still surfaces it as `R`.
///
/// Two guards keep this from over-suppressing genuine findings:
/// - It returns `false` the moment *any* marker-bearing element is **not** a
///   hidden input (a rendered sibling — `<svg>`/`<img>` from a tag-breakout, a
///   visible `<input type=text>`, a `<div>` — can execute, so keep the V).
/// - It requires a *surviving handler* on a hidden input. A bare
///   `<input type="hidden" id=… name=…>` with no handler is a structural
///   marker (its only conceivable exploit is DOM clobbering via named-property
///   access), so it is left to the presence-only path like `<base>`/`<form>`
///   structural markers rather than suppressed here.
fn marker_only_on_non_firing_hidden_inputs(payload: &str, document: &scraper::Html) -> bool {
    let flags = MarkerFlags::from_payload(payload);
    let sel = super::selectors::universal();
    let mut saw_marker = false;
    let mut saw_handler_on_hidden = false;
    for node in document.select(sel) {
        if !is_marker_element(node, &flags) {
            continue;
        }
        saw_marker = true;
        if !is_hidden_input(node) {
            // A marker on a rendered/interactive element can execute — keep it.
            return false;
        }
        if element_carries_surviving_sink(node) {
            saw_handler_on_hidden = true;
        }
    }
    saw_marker && saw_handler_on_hidden
}

fn has_marker_evidence_in_doc(payload: &str, document: &scraper::Html) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let flags = MarkerFlags::from_payload(payload);
    if !flags.any() {
        return false;
    }
    let MarkerFlags {
        class: has_class,
        legacy_class: has_legacy_class,
        id: has_id,
        legacy_id: has_legacy_id,
    } = flags;

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

    if !(class_ok && id_ok) {
        return false;
    }

    // Issue #1183: an attribute-injection payload (`" onmouseover=… class=…
    // x="`) lands the marker — plus an `on*` handler — on a pre-existing
    // `<input type="hidden">`. The handler never fires (hidden inputs have no
    // rendered box), so this is reflected-but-inert, not DOM-verified. This
    // shape slips past the #1118 gate below because the bare payload forms no
    // element on its own (`payload_marker_element_carries_sink` is false), so
    // it must be caught here, before the presence-only fall-through. Structural
    // markers (no surviving handler on the hidden input) are preserved.
    if marker_only_on_non_firing_hidden_inputs(payload, document) {
        return false;
    }

    // Issue #1118: when the payload attached its exploit (an `on*` handler or a
    // `<script>` body sink) directly to the marker element, the marker class
    // surviving is not enough — a server that reflects a *truncated* copy of the
    // payload (e.g. ASP.NET `ValidateRequest` error pages) can preserve the
    // marker class while dropping the handler, parsing into a real element that
    // carries our marker but executes nothing. Require the sink to have survived
    // on at least one marker-bearing element before treating this as DOM
    // evidence. Structural markers (base-href, DOM-clobbering containers) carry
    // no such sink on the marker element and keep presence-only evidence.
    if payload_marker_element_carries_sink(payload) {
        return marker_element_carries_surviving_sink(payload, document);
    }

    // Same requirement for the attribute-injection shapes that form no element
    // of their own, so the parse above finds nothing to inspect. When such a
    // payload lands inside a *quoted* attribute value the server already wrote
    // (`style="… url('HERE')"`, `content="Looking for HERE"`), the injected
    // `on*=` is swallowed by that value while a later `id=`/`class=` still
    // tokenizes into a real attribute — leaving the marker on a live element
    // that executes nothing. Require the handler to have survived alongside the
    // marker before calling that DOM-verified.
    if payload_is_bare_attribute_handler_injection(payload) {
        return marker_element_carries_surviving_sink(payload, document);
    }

    true
}

pub(crate) fn has_marker_evidence(payload: &str, text: &str) -> bool {
    if !payload_has_any_marker(payload) {
        return false;
    }
    let document = crate::utils::html::parse_document_bounded(text);
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

    // The raw payload may entity-encode its sink chars for WAF bypass (e.g.
    // `alert&#40;1&#41;`), but scraper decodes the parsed attribute/script text
    // back to `alert(1)`. Compare against the entity-decoded payload too, else a
    // genuine breakout gets downgraded to Reflected in WAF-bypass mode.
    let decoded_payload = decode_html_entities(payload);

    let selector = selectors::universal();
    for node in document.select(selector) {
        // Issue #1183: an `on*` handler injected onto a `<input type="hidden">`
        // never fires (no rendered box), so it is not browser-executable DOM
        // evidence. Skip the element entirely — a hidden input is a void element
        // and is never a `<script>`, so the (b) script-body check never applies
        // to it either.
        if is_hidden_input(node) {
            continue;
        }
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
            if payload.contains(trimmed) || decoded_payload.contains(trimmed) {
                return true;
            }
        }

        // (b) <script> element whose text body came from the payload.
        if tag.eq_ignore_ascii_case("script") {
            let text: String = node.text().collect();
            let trimmed = text.trim();
            if !trimmed.is_empty()
                && crate::scanning::js_context_verify::payload_carries_js_sink(trimmed)
                && (payload.contains(trimmed) || decoded_payload.contains(trimmed))
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

    /// True when this evidence is derived from HTML-parsing the response body
    /// (a DOM marker, a `javascript:` URL in an attribute, an injected element
    /// carrying a sink handler, or a breakout of an existing `on*` handler).
    ///
    /// Such evidence only confirms exploitability when a browser actually parses
    /// the body as markup. A response served as executable JavaScript
    /// (`application/javascript`, JSONP) is run as script and never HTML-parsed,
    /// so an HTML tag reflected into it is inert — only [`Self::JsContext`]
    /// evidence (the payload runs as JavaScript) confirms XSS there.
    pub(crate) fn requires_html_rendering(&self) -> bool {
        match self {
            DomEvidenceKind::Marker
            | DomEvidenceKind::ExecutableUrl
            | DomEvidenceKind::HtmlStructural
            | DomEvidenceKind::InlineHandlerBreakout => true,
            DomEvidenceKind::JsContext => false,
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
        let document = crate::utils::html::parse_document_bounded(text);
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
    let document = crate::utils::html::parse_document_bounded(&decoded);
    let selector = selectors::universal();
    for node in document.select(selector) {
        // Issue #1183: a handler on a `<input type="hidden">` — even one the
        // payload broke into — never fires, so it is not executable evidence.
        if is_hidden_input(node) {
            continue;
        }
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

// The injection request builders live in `url_inject` so the reflection,
// light-verify, and DOM-verify paths cannot drift apart again (they had:
// light-verify was omitting the urlencoded `Content-Type`). Re-exported so
// this module's tests keep addressing them through `super::*`.
pub(crate) use crate::scanning::url_inject::build_inject_request;
#[cfg(test)]
pub(crate) use crate::scanning::url_inject::{build_json_body_request, build_multipart_request};

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
                // Clamped; see the twin loop in check_reflection.rs.
                sleep(Duration::from_millis(
                    (500 * attempt).min(crate::cmd::scan::MAX_SXSS_BACKOFF_MS),
                ))
                .await;
            }
            let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
            let check_request =
                crate::utils::build_request(client, target, method, sxss_url.clone(), None);

            crate::record_outbound_request().await;
            // Direct send (no `send_with_retry`): count the transport failure
            // here so a retrieval URL that never answers is not silently read
            // as "the payload isn't there".
            let sent = check_request.send().await;
            if sent.is_err() {
                crate::tick_request_failure();
            }
            if let Ok(resp) = sent {
                let headers = resp.headers().clone();
                let ct = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if let Ok(text) = crate::utils::http::read_body(resp).await
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

/// Richer result of a single DOM-verification injection (issue #1156).
///
/// The historical `(bool, Option<String>)` tuple returned by
/// [`check_dom_verification_with_client`] is just the `(verified,
/// response_text)` projection of this. The extra `reflected` and `status`
/// fields are threaded out so [`crate::scanning`]'s DOM phase can take a
/// recall-preserving early exit on endpoints that clearly will never verify
/// (a self-/canonical-link echo that reflects every payload inertly, or a
/// server that consistently 5xx/blocks) instead of running the entire DOM
/// payload set.
#[derive(Debug, Default, Clone)]
pub struct DomVerifyOutcome {
    /// Browser-executable DOM evidence was confirmed for this payload.
    pub verified: bool,
    /// Response body — populated only when `verified`, so the full DOM payload
    /// set does not accumulate response bodies in memory.
    pub response_text: Option<String>,
    /// The payload's bytes were detected in the response (reflection present)
    /// but not necessarily in an executable context. Distinguishes a
    /// "reflected-but-inert echo" from a non-reflecting or blocked response.
    /// Always `false` for redirects, request errors, and `--sxss` (where it is
    /// not meaningfully observable).
    pub reflected: bool,
    /// HTTP status of the injection response, or `0` when the request errored
    /// (or for `--sxss`, whose verification fans out across secondary URLs).
    pub status: u16,
}

/// Verify DOM evidence from a normal (non-stored) injection response.
///
/// Special-case for 3xx responses: browsers do not render the response body
/// of a redirect — only the `Location:` header drives navigation. So body
/// content can never become an exploitable DOM in a redirect, and any apparent
/// "DOM evidence" inside it is structurally a false positive. We still inspect
/// `Location:` (an executable-URL protocol there is a real sink) but skip
/// body-based DOM verification entirely.
async fn verify_normal_dom(resp: reqwest::Response, payload: &str) -> DomVerifyOutcome {
    let status = resp.status();
    let status_code = status.as_u16();
    let headers = resp.headers().clone();

    if status.is_redirection() {
        if let Some(location) = headers.get(reqwest::header::LOCATION)
            && let Ok(loc_str) = location.to_str()
            && let Some((verified, response_text)) = check_redirect_location(loc_str, payload)
        {
            return DomVerifyOutcome {
                verified,
                response_text,
                reflected: false,
                status: status_code,
            };
        }
        return DomVerifyOutcome {
            status: status_code,
            ..Default::default()
        };
    }

    // A response served as executable JavaScript (JSONP) is run as script and
    // never HTML-parsed, so HTML-parse-derived evidence (a DOM marker, a
    // `javascript:` attribute, an injected element/handler) found inside it is
    // inert. Only JS-context evidence — the payload runs as JavaScript, the
    // genuine JSONP-callback case — confirms XSS there. `text/plain` and empty
    // content-types stay eligible for HTML-parse evidence (browsers sniff them).
    let js_body_inert_to_markup = crate::utils::is_javascript_content_type(
        headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );

    // Both HTML and non-HTML (JSONP, JSON with HTML) content types are accepted
    // as long as there is reflection + qualifying DOM evidence in the response.
    // `reflected` is computed independently of the evidence check so an inert
    // echo (payload present, but not executable) is still reported as reflected
    // for the DOM-phase early-exit signal.
    if let Ok(text) = crate::utils::http::read_body(resp).await {
        let reflected =
            crate::scanning::check_reflection::classify_reflection(&text, payload).is_some();
        let verified = reflected
            && classify_dom_evidence(payload, &text)
                .is_some_and(|kind| !(js_body_inert_to_markup && kind.requires_html_rendering()));
        if verified {
            return DomVerifyOutcome {
                verified: true,
                response_text: Some(text),
                reflected: true,
                status: status_code,
            };
        }
        return DomVerifyOutcome {
            verified: false,
            response_text: None,
            reflected,
            status: status_code,
        };
    }

    DomVerifyOutcome {
        status: status_code,
        ..Default::default()
    }
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
    let outcome =
        check_dom_verification_with_client_outcome(client, target, param, payload, args).await;
    (outcome.verified, outcome.response_text)
}

/// Same as [`check_dom_verification_with_client`] but returns the full
/// [`DomVerifyOutcome`] (verdict + response body + reflected/status signals)
/// so the DOM phase can drive its recall-preserving early exit (issue #1156).
pub async fn check_dom_verification_with_client_outcome(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> DomVerifyOutcome {
    if args.skip_xss_scanning {
        return DomVerifyOutcome::default();
    }

    // Apply pre-encoding if the parameter requires it.
    // Use encoded_payload for building the HTTP request, but keep `payload`
    // (the raw/original payload) for response body analysis — the server
    // decodes the encoding and reflects the raw content.
    let encoded_payload = crate::encoding::pre_encoding::apply_param_encoding(payload, param);

    let inject_request = build_inject_request(client, target, param, &encoded_payload);

    // Send the injection request. send_with_retry acquires a --rate-limit
    // permit and applies the --retries / --retry-delay policy internally.
    crate::tick_request_count();
    let inject_resp =
        crate::utils::send_with_retry(inject_request, args.retries, args.retry_delay).await;

    let pause = crate::utils::rate_limit::inter_request_pause(
        target.delay,
        target.waf_extra_delay_ms,
        args.waf_evasion,
    );
    if !pause.is_zero() {
        sleep(pause).await;
    }

    if args.sxss {
        // Stored-XSS verification fans out across secondary check URLs; its
        // reflected/status signals are not meaningfully observable from the
        // single injection above, so leave them at their conservative defaults
        // (the DOM-phase early exit therefore never engages under --sxss).
        let (verified, response_text) = verify_sxss_dom(client, target, param, payload, args).await;
        DomVerifyOutcome {
            verified,
            response_text,
            reflected: false,
            status: 0,
        }
    } else if let Ok(resp) = inject_resp {
        verify_normal_dom(resp, payload).await
    } else {
        DomVerifyOutcome::default()
    }
}

#[cfg(test)]
mod tests;
