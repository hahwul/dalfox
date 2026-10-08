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
/// JavaScript sink call, tolerating ASCII case-folding and HTML-entity encoding
/// (`alert&#40;1&#41;`). A loose *classifier* for the #1183 hidden-input
/// suppression; it is not proof that the payload's sink survived the
/// reflection — that is [`sink_survived`].
fn value_carries_js_sink(value: &str) -> bool {
    use crate::scanning::js_context_verify::payload_carries_js_sink as sink;
    sink(value)
        || sink(&value.to_ascii_lowercase())
        || sink(&decode_html_entities(value))
        || sink(&decode_html_entities(&value.to_ascii_lowercase()))
}

fn is_handler_attr(name: &str) -> bool {
    name.len() >= 3 && name.as_bytes()[..2].eq_ignore_ascii_case(b"on")
}

/// Whether `node`'s own attributes/body carry *some* JS sink: an `on*` handler
/// whose value is a sink call, or a `<script>` body that is one. Only the #1183
/// hidden-input suppression uses this; DOM evidence requires the payload's own
/// sink to have survived ([`element_keeps_sent_sink`]).
fn element_carries_surviving_sink(node: scraper::ElementRef) -> bool {
    let v = node.value();
    if v.attrs()
        .any(|(name, val)| is_handler_attr(name) && value_carries_js_sink(val))
    {
        return true;
    }
    v.name().eq_ignore_ascii_case("script")
        && value_carries_js_sink(&node.text().collect::<String>())
}

/// A JS sink the payload writes onto an element: an `on*` handler (`attr` is
/// its lowercased name) or a `<script>` body (`attr` is `None`), holding the
/// value the browser's HTML parser hands to the JS engine (entities decoded).
#[derive(Debug)]
struct SentSink {
    attr: Option<String>,
    value: String,
}

/// Whether `seen` — a handler value or script body parsed out of the response
/// — is the sent sink `sent` surviving the round trip (issue #1522).
///
/// The handler merely being present is not proof: a filter that strips `(`/`)`
/// turns `onload=alert(1)` into `onload=alert1`, an undefined identifier that
/// throws and runs nothing. Both sides come out of an HTML parser, so they are
/// already entity-decoded (a sent `alert&#40;1&#41;` equals an `alert(1)`
/// echo). Only surrounding whitespace is ignored: JS is case-sensitive, so a
/// case-folded `ALERT(1)` is a different, undefined name. A sent value's
/// trailing `//` line comment is no part of the call: it exists to swallow
/// whatever the page appends to an unterminated attribute (`alert(1)//</div`),
/// so the echo may drop it, or keep it followed by anything short of a line
/// terminator.
fn sink_survived(sent: &str, seen: &str) -> bool {
    let (sent, seen) = (sent.trim(), seen.trim());
    // A URL scheme is case-insensitive; the code after it is not.
    if let Some(n) = executable_scheme_len(sent) {
        return seen
            .get(..n)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(&sent[..n]))
            && sink_survived(&sent[n..], &seen[n..]);
    }
    let Some(code) = sent.strip_suffix("//") else {
        return !sent.is_empty() && seen == sent;
    };
    let code = code.trim_end();
    !code.is_empty()
        && seen.strip_prefix(code).is_some_and(|rest| {
            let rest = rest.trim_start();
            rest.is_empty()
                || (rest.starts_with("//") && !rest.contains(['\n', '\r', '\u{2028}', '\u{2029}']))
        })
}

/// Collect the sinks `node` carries (see [`SentSink`]) into `out`. With
/// `urls`, an executable URL in a navigating/embedding attribute
/// (`<iframe src=javascript:alert(1)>`) counts as a sink too: on a marker
/// element it is the exploit, and a filter can mangle it just the same.
fn push_sent_sinks(node: scraper::ElementRef, urls: bool, out: &mut Vec<SentSink>) {
    let v = node.value();
    for (name, val) in v.attrs() {
        let is_url_sink = urls
            && is_executable_url_attribute(v.name(), name)
            && executable_scheme_len(val.trim()).is_some();
        // Any non-empty handler counts, not only ones a sink-name list
        // recognises: an obfuscated call (`top["al"+"ert"](1)`) is just as
        // much the payload's exploit, and just as breakable by a filter.
        if is_url_sink || (is_handler_attr(name) && !val.trim().is_empty()) {
            out.push(SentSink {
                attr: Some(name.to_ascii_lowercase()),
                value: val.to_string(),
            });
        }
    }
    if v.name().eq_ignore_ascii_case("script") {
        let text: String = node.text().collect();
        if !text.trim().is_empty() {
            out.push(SentSink {
                attr: None,
                value: text,
            });
        }
    }
}

/// Whether `node` carries one of the payload's `sinks` with its value intact
/// ([`sink_survived`]). The one survival check every handler/script-body DOM
/// evidence path goes through: marker co-survival, HTML structural, and their
/// XML twin [`xml_node_keeps_sent_sink`].
fn element_keeps_sent_sink(node: scraper::ElementRef, sinks: &[SentSink]) -> bool {
    let v = node.value();
    sinks.iter().any(|s| match &s.attr {
        Some(name) => v
            .attr(name)
            .is_some_and(|seen| sink_survived(&s.value, seen)),
        None => {
            v.name().eq_ignore_ascii_case("script")
                && sink_survived(&s.value, &node.text().collect::<String>())
        }
    })
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

/// The on*-handler / `<script>`-body sinks the payload writes, read the way the
/// browser would: the payload — and, only when it differs, its entity-decoded
/// form — parsed as an HTML fragment (with a closing `>` appended so breakout
/// payloads such as `'"><svg/class=… onload=…//` still yield the element).
/// `marker_only` keeps just the sinks on element(s) carrying a Dalfox marker.
///
/// Empty for structural markers — base-href injection, DOM-clobbering
/// containers (`<form id=…>`, `<object data=javascript:…>`) — where the marker
/// element's mere presence is the exploit and there is no on*/script sink on it
/// to verify, so those keep presence-only evidence.
fn payload_sent_sinks(payload: &str, marker_only: bool) -> Vec<SentSink> {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();
    // Skipping the no-op decoded pass avoids re-parsing an identical fragment.
    let decoded = decode_html_entities(payload);
    let mut candidates = vec![payload];
    if decoded != payload {
        candidates.push(decoded.as_str());
    }
    let mut sinks = Vec::new();
    for candidate in candidates {
        let normalized = if candidate.trim_end().ends_with('>') {
            candidate.to_string()
        } else {
            format!("{candidate}>")
        };
        // Bounded: html5ever is O(depth^2) and this runs once per payload, so a
        // single pathological entry in a `--custom-payload` file or a fetched
        // `--remote-payloads` list would stall the scan. See
        // `utils::html::parse_document_bounded`. A document parse, not a fragment
        // one: it models the response, e.g. `<body onload=… class=…>` nested in
        // `<svg><foreignObject>` merges onto the page `<body>`.
        let frag = crate::utils::html::parse_document_bounded(&normalized);
        for node in frag.select(super::selectors::universal()) {
            let is_marker = element_class_has(node, class_marker)
                || element_class_has(node, "dalfox")
                || element_id_is(node, id_marker)
                || element_id_is(node, "dalfox");
            if is_marker || !marker_only {
                push_sent_sinks(node, marker_only, &mut sinks);
            }
        }
    }
    sinks
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

/// The non-empty `on<event>=` attributes in `payload`, with each value read
/// the way the tag tokenizer would (quoted up to the
/// matching quote, unquoted up to whitespace or `>`) and entity-decoded.
///
/// Deliberately textual: the shapes this exists for
/// (`'/onmouseover="{JS}"/id="{ID}"/x='`, `" onmouseover={JS} class={CLASS} x="`)
/// form no element on their own, so an HTML fragment parse yields nothing to
/// inspect. The attribute name is `on` + letters, not preceded by an identifier
/// character, followed by optional whitespace and `=`. Scanning resumes after
/// each value, so the cost stays linear in the payload however many `on*=` it
/// repeats.
fn payload_handler_sinks_text(payload: &str) -> Vec<SentSink> {
    let bytes = payload.as_bytes();
    let len = bytes.len();
    let mut sinks = Vec::new();
    let mut i = 0;
    while i + 2 < len {
        // `on` must start an attribute name, not sit inside a longer word
        // (`button`, `session`, …).
        if (bytes[i] | 0x20) != b'o'
            || (bytes[i + 1] | 0x20) != b'n'
            || (i > 0
                && (bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'-')))
        {
            i += 1;
            continue;
        }
        let mut end = i + 2;
        while end < len && bytes[end].is_ascii_alphabetic() {
            end += 1;
        }
        let mut eq = end;
        while eq < len && bytes[eq].is_ascii_whitespace() {
            eq += 1;
        }
        if end == i + 2 || eq >= len || bytes[eq] != b'=' {
            i = end.max(i + 1);
            continue;
        }
        let mut start = eq + 1;
        while start < len && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        let (raw, next) = match bytes.get(start) {
            Some(&quote @ (b'"' | b'\'')) => {
                let close = payload[start + 1..]
                    .find(quote as char)
                    .map_or(len, |p| start + 1 + p);
                (&payload[start + 1..close], close + 1)
            }
            _ => {
                let stop = payload[start..]
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .map_or(len, |p| start + p);
                (&payload[start..stop], stop)
            }
        };
        let value = decode_html_entities(raw);
        if !value.trim().is_empty() {
            sinks.push(SentSink {
                attr: Some(payload[i..end].to_ascii_lowercase()),
                value,
            });
        }
        i = next.max(i + 1);
    }
    sinks
}

/// The sinks the payload attaches to its marker element, which must survive on
/// a marker element for the marker to count as DOM evidence (issues #1118,
/// #1522). A tag-forming payload is read through [`payload_sent_sinks`]; a bare
/// attribute-injection fragment (opens no tag of its own, so the fragment parse
/// yields only text) through [`payload_handler_sinks_text`]. Such fragments
/// always emit their marker and handler onto the *same* injected attribute run
/// (see the `ATTR_*` templates in `payload::synthesis`), so a marker on an
/// element without the handler means the handler was swallowed by the
/// surrounding markup and nothing executes.
fn payload_marker_sinks(payload: &str) -> Vec<SentSink> {
    let mut sinks = Vec::new();
    for form in payload_wire_forms(payload) {
        let found = payload_sent_sinks(&form, true);
        if found.is_empty() && !payload_opens_tag(&form) {
            sinks.extend(payload_handler_sinks_text(&form));
        } else {
            sinks.extend(found);
        }
    }
    sinks
}

/// The payload as sent and, when it differs, percent-decoded. A pre-encoded
/// payload (`%3Csvg%20onload%3Dalert%281%29…`) reaches the page decoded, so its
/// sinks only show up in the decoded form; reading just the raw text found no
/// sink and let a bare marker stand in as presence-only evidence.
fn payload_wire_forms(payload: &str) -> Vec<std::borrow::Cow<'_, str>> {
    let mut forms = vec![std::borrow::Cow::Borrowed(payload)];
    if payload.contains('%')
        && let Ok(decoded) = urlencoding::decode(payload)
        && decoded != payload
    {
        forms.push(std::borrow::Cow::Owned(decoded.into_owned()));
    }
    forms
}

/// Whether the payload attaches a sink to its marker and the marker landed on a
/// real, rendered element of `text` — HTML injection confirmed — yet DOM
/// evidence failed, so the sink did not survive (a filter mangled or dropped
/// it, issues #1118/#1522). The DOM phase reports that as `[R]` rather than
/// dropping it. Only meaningful once `classify_dom_evidence` returned `None`.
fn marker_injected_with_broken_sink(payload: &str, text: &str) -> bool {
    let flags = MarkerFlags::from_payload(payload);
    if !flags.any() || payload_marker_sinks(payload).is_empty() {
        return false;
    }
    let document = crate::utils::html::parse_document_bounded(text);
    document
        .select(super::selectors::universal())
        .any(|node| is_marker_element(node, &flags) && !is_hidden_input(node))
}

/// Whether at least one element carrying one of the payload's markers also
/// carries one of `sinks` with its value intact. A hidden input does not count:
/// its handler never fires (#1183), so it cannot be the surviving sink for a
/// marker that also rides on a handler-less rendered element.
fn marker_element_keeps_sent_sink(
    payload: &str,
    document: &scraper::Html,
    sinks: &[SentSink],
) -> bool {
    let flags = MarkerFlags::from_payload(payload);
    let sel = super::selectors::universal();
    document.select(sel).any(|node| {
        is_marker_element(node, &flags)
            && !is_hidden_input(node)
            && element_keeps_sent_sink(node, sinks)
    })
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
    // element on its own (`payload_sent_sinks` finds no marker element), so
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
    // carries our marker but executes nothing. The same goes for bare
    // attribute-injection shapes whose `on*=` is swallowed by a quoted value
    // the server already wrote (`style="… url('HERE')"`) while a later
    // `id=`/`class=` still tokenizes into a real attribute. And the handler
    // being present is not enough either (issue #1522): a filter that strips
    // `(`/`)` leaves `onload=alert1` on the marker element, which throws. So
    // require the payload's own sink value to have survived on at least one
    // marker-bearing element. Structural markers (base-href, DOM-clobbering
    // containers) carry no such sink and keep presence-only evidence.
    let sinks = payload_marker_sinks(payload);
    if !sinks.is_empty() {
        return marker_element_keeps_sent_sink(payload, document, &sinks);
    }

    true
}

#[cfg(test)]
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
    executable_scheme_len(payload.trim()).is_some()
}

/// Byte length of the executable URL scheme `value` starts with
/// (`javascript:`, `data:text/html`, `vbscript:`; ASCII case-insensitive).
fn executable_scheme_len(value: &str) -> Option<usize> {
    ["javascript:", "data:text/html", "vbscript:"]
        .into_iter()
        .find(|scheme| starts_with_ascii_ci(value, scheme))
        .map(str::len)
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

/// Every sink the payload writes, on any element, for the marker-free
/// structural paths. The classifier is case-sensitive here: a payload's own
/// `ALERT(1)` is no sink, and without a marker there is no co-survival gate.
fn payload_structural_sinks(payload: &str) -> Vec<SentSink> {
    let mut sinks: Vec<SentSink> = payload_wire_forms(payload)
        .iter()
        .flat_map(|form| payload_sent_sinks(form, false))
        .collect();
    sinks.retain(|s| crate::scanning::js_context_verify::payload_carries_js_sink(&s.value));
    sinks
}

/// True when the payload introduced (a) an HTML element with an event-handler
/// attribute whose value contains a JavaScript sink call, OR (b) a `<script>`
/// element whose body is the payload-carried sink call. "Introduced by the
/// payload" means the response element carries one of the payload's own sinks
/// — same handler name, value intact ([`element_keeps_sent_sink`]) — so a
/// page's own handler, or the payload's handler mangled by a filter
/// (`onload=alert1`, issue #1522), is not evidence.
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
    let sinks = payload_structural_sinks(payload);
    if sinks.is_empty() {
        return false;
    }
    // Issue #1183: an `on*` handler injected onto a `<input type="hidden">`
    // never fires (no rendered box), so it is not browser-executable DOM
    // evidence. A hidden input is never a `<script>` either.
    document
        .select(selectors::universal())
        .any(|node| !is_hidden_input(node) && element_keeps_sent_sink(node, &sinks))
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
    // One parse shared by the tree checks and the handler-breakout check; the
    // latter used to re-parse the identical body (the common escaped-echo
    // "no V" path paid two full parses per payload response).
    let mut document: Option<scraper::Html> = None;
    if needs_markers || needs_attrs || needs_html_struct {
        let document = document.insert(crate::utils::html::parse_document_bounded(text));
        if needs_markers && has_marker_evidence_in_doc(payload, document) {
            return Some(DomEvidenceKind::Marker);
        }
        if needs_attrs && has_executable_url_attribute_evidence_in_doc(payload, document) {
            return Some(DomEvidenceKind::ExecutableUrl);
        }
        if needs_html_struct && has_html_structural_evidence_in_doc(payload, document) {
            return Some(DomEvidenceKind::HtmlStructural);
        }
    }
    if needs_js
        && crate::scanning::js_context_verify::has_inline_script_context_evidence(payload, text)
    {
        return Some(DomEvidenceKind::JsContext);
    }
    if needs_js && payload.len() >= MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN {
        let document =
            document.get_or_insert_with(|| crate::utils::html::parse_document_bounded(text));
        if has_inline_handler_breakout_evidence_in_doc(payload, document) {
            return Some(DomEvidenceKind::InlineHandlerBreakout);
        }
    }
    None
}

fn classify_dom_evidence_in_recovered_xml(
    payload: &str,
    text: &str,
    document: &scraper::Html,
) -> Option<DomEvidenceKind> {
    let needs_markers = payload_has_any_marker(payload);
    let needs_attrs = payload_is_executable_url_protocol(payload);
    let needs_html_struct = payload.contains('<')
        && crate::scanning::js_context_verify::payload_carries_js_sink(payload)
        && body_looks_html_renderable(text);
    let needs_js = crate::scanning::js_context_verify::payload_carries_js_sink(payload);
    if !needs_markers && !needs_attrs && !needs_html_struct && !needs_js {
        return None;
    }
    if needs_markers && has_marker_evidence_in_doc(payload, document) {
        return Some(DomEvidenceKind::Marker);
    }
    if needs_attrs && has_executable_url_attribute_evidence_in_doc(payload, document) {
        return Some(DomEvidenceKind::ExecutableUrl);
    }
    if needs_html_struct && has_html_structural_evidence_in_doc(payload, document) {
        return Some(DomEvidenceKind::HtmlStructural);
    }
    if needs_js
        && crate::scanning::js_context_verify::has_inline_script_context_evidence(payload, text)
    {
        return Some(DomEvidenceKind::JsContext);
    }
    if needs_js && has_inline_handler_breakout_evidence(payload, text) {
        return Some(DomEvidenceKind::InlineHandlerBreakout);
    }
    None
}

/// Classify evidence using the browser's response parser for the supplied
/// Content-Type. JavaScript responses are parsed as JavaScript (preserving
/// callable JSONP sinks); HTML, sniffable unknown-type responses, XHTML, and
/// SVG are parsed as markup only when their browser document is active.
pub(crate) fn classify_dom_evidence_for_response(
    payload: &str,
    text: &str,
    content_type: &str,
) -> Option<DomEvidenceKind> {
    if crate::utils::is_javascript_content_type(content_type) {
        return crate::scanning::js_context_verify::has_javascript_body_evidence(payload, text)
            .then_some(DomEvidenceKind::JsContext);
    }
    match crate::utils::content_type_primary(content_type).as_deref() {
        Some("application/xhtml+xml") => {
            classify_xml_response(payload, text, "http://www.w3.org/1999/xhtml", "html")
        }
        Some("image/svg+xml") => {
            classify_xml_response(payload, text, "http://www.w3.org/2000/svg", "svg")
        }
        Some(primary) if crate::utils::is_xml_content_type(primary) => {
            classify_xml_response_with_active_namespaces(payload, text)
        }
        _ if crate::utils::response_has_markup_document(content_type, text) => {
            classify_dom_evidence(payload, text)
        }
        _ => None,
    }
}

/// Classify a body that has already passed the response-type gate in the
/// reflection fetcher. `ReflectionBody` retains the executable-JavaScript bit
/// because its public shape cannot carry the entire response header map.
pub(crate) fn classify_dom_evidence_for_reflection_body(
    payload: &str,
    text: &str,
    javascript_body: bool,
    xml_body: bool,
) -> Option<DomEvidenceKind> {
    if javascript_body {
        return crate::scanning::js_context_verify::has_javascript_body_evidence(payload, text)
            .then_some(DomEvidenceKind::JsContext);
    }
    if xml_body {
        return classify_xml_response_with_active_namespaces(payload, text);
    }
    classify_dom_evidence(payload, text)
}

fn classify_xml_response(
    payload: &str,
    text: &str,
    namespace: &str,
    root_name: &str,
) -> Option<DomEvidenceKind> {
    match crate::utils::xml::parse_xml_document(text) {
        crate::utils::xml::XmlDocument::Parsed(document) => {
            let root = document.root_element().tag_name();
            (root.namespace() == Some(namespace) && root.name() == root_name)
                .then(|| classify_dom_evidence_in_xml(payload, &document))
                .flatten()
        }
        crate::utils::xml::XmlDocument::Recovered(document)
            if crate::utils::xml::recovered_xml_root_is(text, &document, namespace, root_name)
                && crate::utils::xml::recovered_xml_has_executable_markup_before_error(
                    &document,
                ) =>
        {
            classify_dom_evidence_in_recovered_xml(
                payload,
                document.source_prefix(),
                &document.document,
            )
        }
        crate::utils::xml::XmlDocument::Recovered(_) => None,
    }
}

fn classify_xml_response_with_active_namespaces(
    payload: &str,
    text: &str,
) -> Option<DomEvidenceKind> {
    match crate::utils::xml::parse_xml_document(text) {
        crate::utils::xml::XmlDocument::Parsed(document) => document_has_active_markup(&document)
            .then(|| classify_dom_evidence_in_xml(payload, &document))
            .flatten(),
        crate::utils::xml::XmlDocument::Recovered(document)
            if crate::utils::xml::recovered_xml_has_executable_markup_before_error(&document) =>
        {
            classify_dom_evidence_in_recovered_xml(
                payload,
                document.source_prefix(),
                &document.document,
            )
        }
        crate::utils::xml::XmlDocument::Recovered(_) => None,
    }
}

fn document_has_active_markup(document: &roxmltree::Document<'_>) -> bool {
    document.descendants().any(|node| xml_node_is_active(node))
}

fn xml_node_is_active(node: roxmltree::Node<'_, '_>) -> bool {
    matches!(
        node.tag_name().namespace(),
        Some("http://www.w3.org/1999/xhtml" | "http://www.w3.org/2000/svg")
    )
}

fn xml_node_is_hidden_input(node: roxmltree::Node<'_, '_>) -> bool {
    node.tag_name().namespace() == Some("http://www.w3.org/1999/xhtml")
        && node.tag_name().name() == "input"
        && node
            .attribute("type")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("hidden"))
}

fn xml_node_is_marker(node: roxmltree::Node<'_, '_>, flags: &MarkerFlags) -> bool {
    let class_has = |marker: &str| {
        node.attribute("class")
            .is_some_and(|classes| classes.split_ascii_whitespace().any(|c| c == marker))
    };
    let id_is = |marker: &str| node.attribute("id").is_some_and(|id| id.trim() == marker);
    (flags.class && class_has(crate::scanning::markers::class_marker()))
        || (flags.legacy_class && class_has("dalfox"))
        || (flags.id && id_is(crate::scanning::markers::id_marker()))
        || (flags.legacy_id && id_is("dalfox"))
}

fn xml_node_text(node: roxmltree::Node<'_, '_>) -> String {
    node.descendants()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect()
}

fn xml_script_type_is_javascript(node: roxmltree::Node<'_, '_>) -> bool {
    let Some(script_type) = node.attribute("type") else {
        return true;
    };
    let script_type = script_type.trim().to_ascii_lowercase();
    script_type.is_empty() || crate::scanning::ast_integration::is_js_mime_essence(&script_type)
}

fn xml_node_carries_sink(node: roxmltree::Node<'_, '_>) -> bool {
    if node
        .attributes()
        .any(|attr| attr.name().starts_with("on") && value_carries_js_sink(attr.value()))
    {
        return true;
    }
    node.tag_name().name() == "script"
        && xml_script_type_is_javascript(node)
        && value_carries_js_sink(&xml_node_text(node))
}

/// [`element_keeps_sent_sink`] for an XML (XHTML/SVG) node. XML attribute and
/// element names are case-sensitive, so the names compare exactly.
fn xml_node_keeps_sent_sink(node: roxmltree::Node<'_, '_>, sinks: &[SentSink]) -> bool {
    sinks.iter().any(|s| match &s.attr {
        Some(name) => node
            .attribute(name.as_str())
            .is_some_and(|seen| sink_survived(&s.value, seen)),
        None => {
            node.tag_name().name() == "script"
                && xml_script_type_is_javascript(node)
                && sink_survived(&s.value, &xml_node_text(node))
        }
    })
}

fn xml_node_has_payload_structural_sink(node: roxmltree::Node<'_, '_>, sinks: &[SentSink]) -> bool {
    !xml_node_is_hidden_input(node)
        && xml_node_keeps_sent_sink(node, sinks)
        && (node.tag_name().name() != "script" || {
            let script = xml_node_text(node);
            crate::scanning::js_context_verify::has_javascript_body_evidence(
                script.trim(),
                script.trim(),
            )
        })
}

fn classify_dom_evidence_in_xml(
    payload: &str,
    document: &roxmltree::Document<'_>,
) -> Option<DomEvidenceKind> {
    let mut elements = document
        .descendants()
        .filter(|node| node.is_element() && xml_node_is_active(*node));
    let flags = MarkerFlags::from_payload(payload);
    if flags.any() {
        let nodes: Vec<_> = elements
            .clone()
            .filter(|node| xml_node_is_marker(*node, &flags))
            .collect();
        let class_ok = (!flags.class && !flags.legacy_class)
            || nodes.iter().any(|node| {
                let class = node.attribute("class").unwrap_or("");
                class.split_ascii_whitespace().any(|c| {
                    (flags.class && c == crate::scanning::markers::class_marker())
                        || (flags.legacy_class && c == "dalfox")
                })
            });
        let id_ok = (!flags.id && !flags.legacy_id)
            || nodes.iter().any(|node| {
                let id = node.attribute("id").unwrap_or("").trim();
                (flags.id && id == crate::scanning::markers::id_marker())
                    || (flags.legacy_id && id == "dalfox")
            });
        let sinks = payload_marker_sinks(payload);
        let marker_keeps_sink = nodes.iter().any(|node| {
            !xml_node_is_hidden_input(*node) && xml_node_keeps_sent_sink(*node, &sinks)
        });
        let hidden_only_with_sink = !nodes.is_empty()
            && nodes.iter().all(|node| xml_node_is_hidden_input(*node))
            && nodes.iter().any(|node| xml_node_carries_sink(*node));
        if class_ok && id_ok && !hidden_only_with_sink && (sinks.is_empty() || marker_keeps_sink) {
            return Some(DomEvidenceKind::Marker);
        }
    }

    if payload_is_executable_url_protocol(payload) {
        let payload_trimmed = payload.trim();
        if elements.clone().any(|node| {
            let tag = node.tag_name().name();
            node.attributes().any(|attr| {
                tag == tag.to_ascii_lowercase()
                    && attr.name() == attr.name().to_ascii_lowercase()
                    && is_executable_url_attribute(tag, attr.name())
                    && attribute_value_executes_payload(attr.value(), payload_trimmed)
            })
        }) {
            return Some(DomEvidenceKind::ExecutableUrl);
        }
    }

    if payload.contains('<') && crate::scanning::js_context_verify::payload_carries_js_sink(payload)
    {
        let sinks = payload_structural_sinks(payload);
        if elements
            .clone()
            .any(|node| xml_node_has_payload_structural_sink(node, &sinks))
        {
            return Some(DomEvidenceKind::HtmlStructural);
        }
    }

    if crate::scanning::js_context_verify::payload_carries_js_sink(payload)
        && elements.clone().any(|node| {
            node.tag_name().name() == "script"
                && xml_script_type_is_javascript(node)
                && crate::scanning::js_context_verify::has_javascript_body_evidence(
                    payload,
                    &xml_node_text(node),
                )
        })
    {
        return Some(DomEvidenceKind::JsContext);
    }

    if crate::scanning::js_context_verify::payload_carries_js_sink(payload)
        && elements.any(|node| {
            node.attributes().any(|attr| {
                attr.name().starts_with("on")
                    && crate::scanning::js_context_verify::handler_payload_hits_sink(
                        attr.value(),
                        payload,
                    )
            })
        })
    {
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
    // Parse the raw body: the HTML parser decodes attribute entities exactly
    // once, as the browser does (`&#39;` → `'`). Pre-decoding the whole body
    // first decoded twice, turning a server's `&amp;#39;` (a literal `&#39;`
    // in the handler's JS) into a quote that never reaches the JS engine.
    let document = crate::utils::html::parse_document_bounded(text);
    has_inline_handler_breakout_evidence_in_doc(payload, &document)
}

/// [`has_inline_handler_breakout_evidence`] over an already-parsed raw body.
fn has_inline_handler_breakout_evidence_in_doc(payload: &str, document: &scraper::Html) -> bool {
    if payload.len() < MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN {
        return false;
    }
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
            // The sink must be the payload's own call, outside every string
            // literal: a payload reflected *inside* the template's quoted
            // argument (`startTimer('<svg onload=alert(1)>')`, or a `"`
            // payload inside a `'…'` string) carries `alert(` as inert text.
            if crate::scanning::js_context_verify::handler_payload_hits_sink(attr_value, payload) {
                return true;
            }
        }
    }
    false
}

/// Test-only boolean view for evidence fixtures that don't need the kind.
#[cfg(test)]
pub(crate) fn has_dom_evidence(payload: &str, text: &str) -> bool {
    classify_dom_evidence(payload, text).is_some()
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
) -> (bool, Option<String>, Option<DomEvidenceKind>) {
    let check_urls =
        crate::scanning::check_reflection::resolve_sxss_check_urls(target, param, args);
    let retries = args.sxss_retries.max(1) as u64;
    let skip_payload_retries = crate::scanning::check_reflection::sxss_payload_retries_skipped();
    // Attempt-major, mirroring the reflection retrieval loop, so the retry-skip
    // can weigh the whole first pass over the check URLs.
    'retry: for attempt in 0u64..retries {
        if attempt > 0 {
            // Clamped; see the twin loop in check_reflection.rs.
            sleep(Duration::from_millis(
                (500 * attempt).min(crate::cmd::scan::MAX_SXSS_BACKOFF_MS),
            ))
            .await;
        }
        let mut saw_any_body = false;
        for sxss_url in &check_urls {
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
                if let Ok(text) = crate::utils::http::read_body(resp).await {
                    saw_any_body = true;
                    if crate::scanning::check_reflection::classify_reflection(&text, payload)
                        .is_some()
                        // Credit the stored payload to this parameter only when its
                        // injection increased the payload's occurrence over the
                        // pre-injection baseline — a copy another parameter stored
                        // earlier is already in the retrieval page (see
                        // `check_reflection::SXSS_BASELINE`).
                        && crate::scanning::check_reflection::sxss_injection_credited(
                            &text, payload,
                        )
                        && let Some(evidence_kind) =
                            classify_dom_evidence_for_response(payload, &text, ct)
                    {
                        return (true, Some(text), Some(evidence_kind));
                    }
                }
            }
        }
        // See the reflection retrieval loop: once a pass has read the pages and
        // none shows this payload's DOM evidence above the baseline, the backoff
        // retries cannot change that; propagation delay was absorbed once by the
        // store-probe at parameter entry.
        if skip_payload_retries && saw_any_body {
            break 'retry;
        }
    }
    (false, None, None)
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
    /// The payload came back in the response — byte-exact, or as a pure
    /// *escaped* echo of the same bytes — but not necessarily in an executable
    /// context. Distinguishes a "reflected-but-inert echo" from a
    /// non-reflecting, sanitized, or blocked response. Always `false` for
    /// redirects, request errors, and `--sxss` (where it is not meaningfully
    /// observable).
    pub reflected: bool,
    /// The payload came back **byte-exact** (`classify_reflection`), i.e. the
    /// server echoed it live rather than escaping it away.
    ///
    /// Narrower than [`Self::reflected`] on purpose. `reflected` was widened to
    /// include pure escaped echoes so the cumulative inert-echo budget can see a
    /// uniformly-escaping endpoint — but it has a second consumer,
    /// `next_blocked_streak`, whose contract is "spare a 5xx that reflected the
    /// payload, because a later variant may still get through". An *escaped*
    /// echo is exactly the case that cannot get through, and letting it reset
    /// the streak meant a 5xx error page that HTML-escapes the query never
    /// tripped `BLOCKED_STREAK_LIMIT` (64) and instead ran to
    /// `INERT_ECHO_BUDGET` (256) — four times the requests against a server
    /// that is already erroring.
    pub live_reflection: bool,
    /// HTTP status of the injection response, or `0` when the request errored
    /// (or for `--sxss`, whose verification fans out across secondary URLs).
    pub status: u16,
}

/// Internal typed companion used by the scan worker to preserve the parser
/// evidence that actually verified a response without changing the public
/// `DomVerifyOutcome` shape.
#[derive(Debug, Default, Clone)]
pub(crate) struct DomVerifyEvidenceOutcome {
    pub(crate) outcome: DomVerifyOutcome,
    pub(crate) evidence_kind: Option<DomEvidenceKind>,
    /// Not verified, but the payload's marker landed on a real element whose
    /// sink a filter broke (issue #1522): HTML injection worth reporting as R.
    pub(crate) markup_injected: bool,
}

/// Verify DOM evidence from a normal (non-stored) injection response.
///
/// Special-case for 3xx responses: browsers do not render the response body
/// of a redirect — only the `Location:` header drives navigation. So body
/// content can never become an exploitable DOM in a redirect, and any apparent
/// "DOM evidence" inside it is structurally a false positive. `Location:` is
/// not evidence either: modern browsers refuse to navigate to `javascript:`,
/// `data:text/html` and `vbscript:` URLs from a 3xx header (treating them as
/// verified produced High findings no browser fires — xssmaze
/// `/redirect/level{1..4}`), and a payload reflected inside a `?next=…` target
/// merely forwards the bytes; the reflection path still reports it as R. So a
/// redirect never verifies.
async fn verify_normal_dom(resp: reqwest::Response, payload: &str) -> DomVerifyEvidenceOutcome {
    let status = resp.status();
    let status_code = status.as_u16();
    let headers = resp.headers().clone();

    if status.is_redirection() {
        return DomVerifyEvidenceOutcome {
            outcome: DomVerifyOutcome {
                status: status_code,
                ..Default::default()
            },
            evidence_kind: None,
            ..Default::default()
        };
    }

    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // `reflected` is computed independently of the browser-parser check so an
    // inert echo (payload present, but not executable) can still feed the
    // DOM-phase early-exit signal.
    if let Ok(text) = crate::utils::http::read_body(resp).await {
        // The signal the DOM-phase inert-echo early exit budgets against.
        //
        // Byte-exact reflection is one half. The other half is the *escaped
        // echo*: the server handed our exact payload back, escaped
        // (`&lt;svg …&gt;`, `%3Csvg%20…`), which `classify_reflection`
        // deliberately reports as no reflection because it is not a finding.
        // Budgeting only on the byte-exact form meant a uniformly escaping
        // endpoint — the most common shape on the web — advanced the counter
        // zero times and the phase ran its entire catalog against a body that
        // can never verify (measured: 5394 requests, 0 findings, on the
        // `inert` perf-budget scenario).
        //
        // The recall constraint this used to protect is preserved by
        // `is_escaped_echo` itself, not by abstaining: a *sanitizing* endpoint
        // must never advance the counter, or the early exit can retire before a
        // genuine late verifier (e.g. sanitizer-level3's whitelisted
        // `<a href=javascript:>`) is reached. A whitelisting sanitizer *removes*
        // markup rather than escaping it, so the payload never surfaces whole in
        // any decoded view and `is_escaped_echo` returns false — as it also does
        // for truncated echoes, `+`→space form decoding, event-handler and
        // URL-attribute contexts, and unrelated bodies.
        //
        // 4xx is excluded for the reason `BLOCKED_STREAK_LIMIT` is scoped to
        // 5xx: a WAF block page that echoes the payload is a *block*, and a
        // later payload variant may still bypass it, so it must not consume the
        // budget that keeps the bypass surface alive.
        let live_reflection =
            crate::scanning::check_reflection::classify_reflection(&text, payload).is_some();
        let reflected = live_reflection
            || (!(400..500).contains(&status_code)
                && crate::scanning::check_reflection::is_escaped_echo(&text, payload));
        // Verification uses a *broader* reflection pre-gate: the byte-exact check
        // misses a payload the server *transforms* — a one-shot angle filter
        // collapsing a doubled-angle bypass (`<<svg class=dlx… onload=…>>`) to a
        // single-angle tag being the motivating case. The payload's unique
        // per-scan marker surviving into the response is an equally valid "this
        // came from us" signal there. It is confined to the `verified` gate (not
        // the inert-echo `reflected` signal above) precisely to preserve that
        // budget's invariant, and `classify_dom_evidence` still independently
        // proves the marker landed on a real sink-carrying element (issue #1118),
        // so an inert marker echo yields no finding.
        let reflected_for_evidence =
            reflected || crate::scanning::check_reflection::payload_marker_present(&text, payload);
        let evidence_kind = reflected_for_evidence
            .then(|| classify_dom_evidence_for_response(payload, &text, content_type))
            .flatten();
        if let Some(evidence_kind) = evidence_kind {
            return DomVerifyEvidenceOutcome {
                outcome: DomVerifyOutcome {
                    verified: true,
                    response_text: Some(text),
                    reflected: true,
                    live_reflection,
                    status: status_code,
                },
                evidence_kind: Some(evidence_kind),
                ..Default::default()
            };
        }
        let markup_injected = reflected_for_evidence
            && crate::utils::response_has_markup_document(content_type, &text)
            && marker_injected_with_broken_sink(payload, &text);
        return DomVerifyEvidenceOutcome {
            outcome: DomVerifyOutcome {
                verified: false,
                response_text: None,
                reflected,
                live_reflection,
                status: status_code,
            },
            evidence_kind: None,
            markup_injected,
        };
    }

    DomVerifyEvidenceOutcome {
        outcome: DomVerifyOutcome {
            status: status_code,
            ..Default::default()
        },
        evidence_kind: None,
        ..Default::default()
    }
}

/// DOM-verify one injected `payload`: the verdict, response body,
/// reflected/status signals (which drive the DOM phase's recall-preserving early
/// exit, issue #1156) and the typed parser evidence for the finding label.
pub(crate) async fn check_dom_verification_with_evidence(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> DomVerifyEvidenceOutcome {
    if args.skip_xss_scanning {
        return DomVerifyEvidenceOutcome::default();
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
        let (verified, response_text, evidence_kind) =
            verify_sxss_dom(client, target, param, payload, args).await;
        DomVerifyEvidenceOutcome {
            outcome: DomVerifyOutcome {
                verified,
                response_text,
                reflected: false,
                live_reflection: false,
                status: 0,
            },
            evidence_kind,
            ..Default::default()
        }
    } else if let Ok(resp) = inject_resp {
        verify_normal_dom(resp, payload).await
    } else {
        DomVerifyEvidenceOutcome::default()
    }
}

#[cfg(test)]
mod tests;
