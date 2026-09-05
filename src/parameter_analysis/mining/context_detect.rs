//! Mining: context detect. See module docs in `mod.rs`.

use super::*;

pub(crate) fn detect_injection_context(text: &str) -> InjectionContext {
    // Inner marker survives every reflection form classified by
    // `classify_probe_reflection` (Full / PrefixOnly / SuffixOnly /
    // InnerOnly), so it's the most reliable anchor for context inference
    // on bracketed probes. Fall back to the open marker for callers that
    // still inject it directly (older tests, legacy probe sites).
    let inner = crate::scanning::markers::inner_marker();
    if text.contains(inner) {
        return detect_injection_context_with_marker(text, inner);
    }
    let open = crate::scanning::markers::open_marker();
    detect_injection_context_with_marker(text, open)
}

/// Compute the exact JS breakout closer (issue #1073 follow-up) from the
/// *observed* response when a probe marker reflects inside an inline `<script>`
/// body. Returns the minimal closer sequence — produced by
/// [`crate::payload::js_breakout::compute_js_breakout`] over the real script
/// source from the enclosing `<script>` content start up to the reflection
/// point — that escapes the open string and every unbalanced `([{` so a
/// following `;<payload>//` reaches executable statement position.
///
/// This is the per-parameter carrier the synthesis layer consumes to emit a
/// breakout matched to the *site's actual nesting* rather than only the fixed
/// depth-0–3 catalog. Returns `None` when the marker is not inside an inline
/// `<script>` body (the script-tag requirement scopes this to script contexts,
/// not event-handler/attribute JS), when no marker is present, or when the
/// observed prefix already sits at statement position (empty closer) — every
/// such case falls back to the fixed catalog, so the result is strictly
/// additive and never removes coverage.
///
/// Mirrors `detect_injection_context`'s marker selection (inner marker
/// preferred, open marker fallback) so the closer is computed for the same
/// reflection the context classifier anchored on. Uses raw response slicing
/// (inline `<script>` content is CDATA-like, not HTML-entity-decoded by the
/// browser), so the prefix matches the JS source the browser actually parses.
pub(crate) fn detect_js_breakout(text: &str) -> Option<String> {
    let inner = crate::scanning::markers::inner_marker();
    let marker = if text.contains(inner) {
        inner
    } else {
        crate::scanning::markers::open_marker()
    };
    detect_js_breakout_with_marker(text, marker)
}

/// `detect_js_breakout` with a caller-supplied marker string (mirrors
/// `detect_injection_context_with_marker`). Used by probes that inject a
/// non-standard marker, e.g. the numeric-only discovery probe.
/// Offset of the last ASCII-case-insensitive occurrence of `needle` in
/// `bytes[..before]`.
///
/// Allocation-free on purpose. The obvious spelling — `text[..mp]
/// .to_ascii_lowercase().rfind(..)` — copies the whole prefix, and that prefix
/// can be the full `read_body_capped` 16 MiB, once per probed parameter.
/// Bounding the search window instead would have cost recall: framework apps
/// routinely inline a serialized state blob or a whole bundle in one
/// `<script>`, and a reflection several hundred KiB into it is ordinary, so any
/// window short enough to be a useful cost bound also silently dropped those
/// reflections back to the fixed catalog. Not allocating removes the need to
/// choose. (`MAX_OPEN_DEPTH` in `js_breakout` remains the guard that stops a
/// hostile prefix from producing a giant closer.)
fn rfind_ascii_case_insensitive(bytes: &[u8], before: usize, needle: &[u8]) -> Option<usize> {
    let before = before.min(bytes.len());
    if needle.is_empty() || needle.len() > before {
        return None;
    }
    (0..=before - needle.len())
        .rev()
        .find(|&start| bytes[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

pub(crate) fn detect_js_breakout_with_marker(text: &str, marker: &str) -> Option<String> {
    let mp = text.find(marker)?;
    // Find the enclosing inline `<script …>` opening tag before the reflection.
    // `<script` (case-insensitive) never matches a closing `</script>` tag (the
    // char after `<` is `/`, not `s`), so the last match is a real opener.
    let open_tag = rfind_ascii_case_insensitive(text.as_bytes(), mp, b"<script")?;
    // Script content begins just after the `>` that ends the opening tag.
    let gt = text[open_tag..mp].find('>')?;
    let content_start = open_tag + gt + 1;
    let prefix = &text[content_start..mp];
    // Guard the multi-`<script>` edge: if a `</script>` closes between this
    // opener and the marker, the marker isn't inside this script body — bail to
    // the fixed catalog rather than computing a bogus closer.
    if prefix.to_ascii_lowercase().contains("</script") {
        return None;
    }
    let closer = crate::payload::js_breakout::compute_js_breakout(prefix);
    // An empty closer means the prefix already sits at statement position; the
    // raw-JS catalog templates handle that, so carry nothing.
    if closer.is_empty() {
        None
    } else {
        Some(closer)
    }
}

/// Like `detect_injection_context` but uses a caller-supplied marker string.
/// Useful for probes that don't use the standard alphanumeric marker (e.g. numeric-only probes).
pub(crate) fn detect_injection_context_with_marker(text: &str, marker: &str) -> InjectionContext {
    if !text.contains(marker) {
        return InjectionContext::Html(None);
    }

    // Fast comment check using raw HTML when available
    if let (Some(cs), Some(ce)) = (text.find("<!--"), text.find("-->"))
        && let Some(mp) = text.find(marker)
        && cs < mp
        && mp < ce
    {
        return InjectionContext::Html(Some(DelimiterType::Comment));
    }

    // Parse HTML and locate marker via element text/attributes/script
    let document = crate::utils::html::parse_document_bounded(text);

    // Heuristic to infer surrounding quote delimiter around the first marker.
    // Picks the *closest* opening quote before the marker (the one that
    // actually contains it). Includes backtick template literals so a marker
    // reflected inside `` `…` `` is reported as Backtick rather than falling
    // back to None — the breakout payload (`${…}`) is different from `'/`"`.
    fn infer_quote_delimiter(text: &str, marker: &str) -> Option<DelimiterType> {
        let pos = text.find(marker)?;
        let before = &text[..pos];
        let after = &text[pos + marker.len()..];

        let candidates: [(char, DelimiterType); 3] = [
            ('"', DelimiterType::DoubleQuote),
            ('\'', DelimiterType::SingleQuote),
            ('`', DelimiterType::Backtick),
        ];

        let (qch, delim) = candidates
            .iter()
            .filter_map(|(c, d)| before.rfind(*c).map(|p| (*c, d.clone(), p)))
            .max_by_key(|(_, _, p)| *p)
            .map(|(c, d, _)| (c, d))?;

        if after.find(qch).is_some() {
            return Some(delim);
        }
        None
    }

    fn is_url_like_attribute(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "src" | "href" | "xlink:href" | "data" | "action" | "formaction" | "poster"
        )
    }

    // 1) JavaScript context: marker appears in any <script> text
    {
        let sel = selectors::script();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Javascript(delim);
            }
        }
    }

    // 1b) CSS context: marker appears in any <style> text
    {
        let sel = selectors::style();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Css(delim);
            }
        }
    }

    // 2) Attribute context: marker in any attribute value.
    //
    // Event-handler attributes (`onload`, `onerror`, `onclick`, …) hold
    // JavaScript source that the browser feeds into an event handler
    // function — escaping out of the surrounding string literal yields
    // a JS-context XSS, not an HTML one. Classifying these as plain
    // `Attribute(delim)` makes the payload generator emit HTML tag
    // breakouts (`'><svg…>`) that get serialised as inert HTML inside
    // the handler's string. JS-breakout payloads (`',alert(1),'`) are
    // the right strategy, so route on*-attributes through the
    // `Javascript(delim)` branch.
    fn is_event_handler_attribute(name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n.starts_with("on") && n.len() > 2
    }
    {
        let any = selectors::universal();
        for el in document.select(any) {
            for (name, v) in el.value().attrs() {
                if v.contains(marker) {
                    let delim = infer_quote_delimiter(text, marker);
                    if is_event_handler_attribute(name) {
                        return InjectionContext::Javascript(delim);
                    }
                    return if is_url_like_attribute(name) {
                        InjectionContext::AttributeUrl(delim)
                    } else {
                        InjectionContext::Attribute(delim)
                    };
                }
            }
            // Marker landed *as* an attribute name (not a value). Example:
            //   <div id='x' MARKER>
            // Scraper parses MARKER as a boolean attribute with empty value,
            // so the value-side scan above misses it. This is the "free
            // attribute slot inside an existing tag" position — HTML-tag
            // breakouts (`<svg…>`) just become more attribute names, but
            // bare event handlers (`onmouseover=alert(1)`) execute as-is.
            // Classify as Attribute(None) so the payload generator emits
            // the unquoted-attribute branch (event handlers + protocols).
            for (name, _v) in el.value().attrs() {
                if name.contains(marker) {
                    return InjectionContext::Attribute(None);
                }
            }
        }
    }

    // 3) HTML text context — deliberately not scanned.
    //
    // There used to be a loop here that walked every element and materialized
    // `el.text()` (that element's *entire subtree* text) looking for the
    // marker, returning `InjectionContext::Html(None)` on a hit. It could not
    // change the answer: the fallback below is the same value, so the loop's
    // only observable effect was its cost — and that cost is quadratic, since
    // each of N elements re-collects the text of everything beneath it. A body
    // of `<div>` × 500 000 with the marker in a *comment* node (which matches
    // no element, so the loop never short-circuits) ran it to completion.
    //
    // Fallback to HTML.
    InjectionContext::Html(None)
}

/// Identify a framework innerHTML-style sink the marker landed inside,
/// if any. Returns the directive/attribute name (`"v-html"`,
/// `"data-bind"`, `"ng-bind-html"`, …) so scanning can:
///   1. Upgrade the finding's `inject_type` to surface the sink class.
///   2. Treat HTML-entity-encoded reflections as exploitable — the
///      framework hands the entity-decoded value to `innerHTML` at
///      runtime, so `&lt;img onerror=…&gt;` still executes.
///
/// Conservative: only returns `Some(_)` when *every* marker occurrence
/// sits inside one of the recognised attributes. A single occurrence in
/// plain text content is enough to fall back to generic HTML payloads —
/// the regular `detect_injection_context` already covers that path.
///
/// Returns `None` when:
///   * the marker isn't present at all,
///   * any occurrence lives outside an HTML attribute (text node,
///     `<script>`, `<style>`), or
///   * the attribute name isn't in the recognised innerHTML-sink set.
pub(crate) fn detect_framework_html_sink(text: &str, marker: &str) -> Option<&'static str> {
    if marker.is_empty() || !text.contains(marker) {
        return None;
    }
    let document = crate::utils::html::parse_document_bounded(text);
    let any = selectors::universal();
    let mut found: Option<&'static str> = None;
    for el in document.select(any) {
        for (name, value) in el.value().attrs() {
            if !value.contains(marker) {
                continue;
            }
            let sink = match name.to_ascii_lowercase().as_str() {
                "v-html" => Some("v-html"),
                "ng-bind-html" | "[innerhtml]" | "innerhtml" => Some("ng-bind-html"),
                // Knockout `data-bind` carries multiple clauses
                // (e.g. `data-bind="text: foo, html: bar"`). Only the
                // `html:` clause is an innerHTML sink, so require the
                // clause to live at a real binding boundary — start of
                // the attribute or after `,` / `;` / whitespace. A bare
                // `value.contains("html:")` false-positives on
                // `data-bind="text: 'html: link'"` and on any string
                // literal that happens to contain `html:`.
                "data-bind" if has_knockout_html_clause(value) => Some("data-bind"),
                _ => None,
            };
            let s = sink?;
            match found {
                Some(prev) if prev != s => return None,
                _ => found = Some(s),
            }
        }
    }
    found
}

/// True when `value` (a Knockout `data-bind` attribute) has an `html:`
/// clause at a real binding boundary — start of the value, or after
/// `,` / `;` / whitespace that separates clauses. Skipping inside
/// quoted strings prevents the dominant false-positive shape:
/// `data-bind="text: 'html: link'"` where `html:` is just data.
pub(crate) fn has_knockout_html_clause(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut at_clause_start = true;
    while i < bytes.len() {
        let b = bytes[i];
        // Track string literal context so an `html:` substring inside a
        // quoted clause value doesn't trigger.
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = Some(b);
            at_clause_start = false;
            i += 1;
            continue;
        }
        if b == b',' || b == b';' {
            at_clause_start = true;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if at_clause_start {
            // Check for `html` followed by whitespace + `:`. ASCII-only
            // attribute name, so direct byte comparison is fine.
            let remaining = &bytes[i..];
            if remaining.len() >= 4 && remaining[..4].eq_ignore_ascii_case(b"html") {
                let mut j = i + 4;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    return true;
                }
            }
            at_clause_start = false;
        }
        i += 1;
    }
    false
}
