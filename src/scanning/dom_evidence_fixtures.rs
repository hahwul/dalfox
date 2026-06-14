//! Shared test fixtures that model how a real server transforms a reflected
//! payload before it appears in the response body.
//!
//! The DOM-evidence checks (`check_dom_verification`, `js_context_verify`,
//! `light_verify`) gate the highest-confidence **[V]** finding. Their unit
//! tests used to hand-write the "response body" by sprinkling the payload into
//! a minimal wrapper — which silently divorced the fixture from any concrete
//! server behaviour and let false-positive/false-negative gaps hide (see
//! issue #1118 / #1124).
//!
//! This module makes "what the server did" explicit and reviewable: a fixture
//! states a [`Transform`] (full reflect, handler stripped, entity/percent
//! encoded, case-folded, truncated, …) and a sink template, and [`reflect`]
//! produces the body. The transform — not ad-hoc HTML — is the source of truth
//! for whether the body should still constitute DOM evidence.

use regex::Regex;
use std::sync::OnceLock;

/// A documented server-side transformation applied to a reflected payload.
///
/// Each variant corresponds to a behaviour observed on real targets, so a
/// fixture that names one is asserting "a server that does *this* produces
/// *this* body" — and the expected verdict can be reviewed against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transform<'a> {
    /// Reflect the payload verbatim, byte-for-byte (no sanitisation).
    Full,
    /// Drop every `on*` event-handler attribute (name and value). Models a
    /// sanitiser that keeps the tag but strips handlers, or the ASP.NET-style
    /// truncation that severs the `onload=`/`onerror=` after the marker.
    HandlerStripped,
    /// Keep `on*` attribute names but blank their values (`onload=""`).
    HandlerBlanked,
    /// HTML-entity-encode the metacharacters `& < > " '` — the canonical
    /// "echoed safely into HTML text/attribute" behaviour.
    EntityEncoded,
    /// Percent-encode the payload (server reflected the still-URL-encoded form
    /// without decoding it). Percent escapes are *not* decoded by the HTML
    /// parser, so this neutralises markup and JS-string breakouts alike.
    PercentEncoded,
    /// ASCII-uppercase every byte (case-folding reverse proxy / template).
    /// JavaScript identifiers are case-sensitive, so a folded `ALERT(1)` is a
    /// different (undefined) name and never executes.
    CaseFolded,
    /// Truncate the payload at the first occurrence of `needle` (exclusive),
    /// modelling a length cap or a sink that cuts at a delimiter.
    TruncatedAt(&'a str),
    /// Entity-encode only the angle brackets so the payload renders as inert
    /// text rather than parsed markup.
    TextOnly,
}

/// Matches an `on*` event-handler attribute with its value (quoted or bare).
fn handler_attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\s+on[a-z0-9_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#)
            .expect("valid handler-attr regex")
    })
}

/// Like [`handler_attr_re`] but captures the attribute name so the value can be
/// blanked while the handler attribute itself stays present.
fn handler_attr_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(\s+on[a-z0-9_-]+)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#)
            .expect("valid handler-attr-name regex")
    })
}

fn entity_encode(s: &str) -> String {
    // `&` first so we don't double-encode the escapes we introduce.
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Apply `transform` to `payload`, returning the bytes a server would emit for
/// the reflected value. This is the only place transformation semantics live.
pub(crate) fn apply_transform(payload: &str, transform: Transform) -> String {
    match transform {
        Transform::Full => payload.to_string(),
        Transform::HandlerStripped => handler_attr_re().replace_all(payload, "").into_owned(),
        Transform::HandlerBlanked => handler_attr_name_re()
            .replace_all(payload, r#"${1}="""#)
            .into_owned(),
        Transform::EntityEncoded => entity_encode(payload),
        Transform::PercentEncoded => urlencoding::encode(payload).into_owned(),
        Transform::CaseFolded => payload.to_ascii_uppercase(),
        Transform::TruncatedAt(needle) => payload
            .split_once(needle)
            .map(|(head, _)| head.to_string())
            .unwrap_or_else(|| payload.to_string()),
        Transform::TextOnly => payload.replace('<', "&lt;").replace('>', "&gt;"),
    }
}

/// Produce a response body by applying `transform` to `payload` and
/// substituting the result into `sink_template` at the `{PAYLOAD}` placeholder.
///
/// `sink_template` names the reflection context (an `<a href>`, a `<script>`
/// string slot, an inline `on*` handler, …), so a single transform can be
/// exercised across every DOM-evidence kind from one helper.
pub(crate) fn reflect(payload: &str, transform: Transform, sink_template: &str) -> String {
    debug_assert!(
        sink_template.contains("{PAYLOAD}"),
        "sink template must contain a {{PAYLOAD}} placeholder"
    );
    sink_template.replace("{PAYLOAD}", &apply_transform(payload, transform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_reflects_verbatim() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::Full),
            "<svg onload=alert(1)>"
        );
    }

    #[test]
    fn handler_stripped_drops_event_handlers() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::HandlerStripped),
            "<svg>"
        );
        assert_eq!(
            apply_transform("<img src=x onerror=alert(1)>", Transform::HandlerStripped),
            "<img src=x>"
        );
        assert_eq!(
            apply_transform(
                r#"<img src=x onerror="alert(1)">"#,
                Transform::HandlerStripped
            ),
            "<img src=x>"
        );
    }

    #[test]
    fn handler_blanked_keeps_name_drops_value() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::HandlerBlanked),
            r#"<svg onload="">"#
        );
    }

    #[test]
    fn entity_encoded_escapes_markup_metacharacters() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::EntityEncoded),
            "&lt;svg onload=alert(1)&gt;"
        );
        assert_eq!(
            apply_transform("'-alert(1)-'", Transform::EntityEncoded),
            "&#39;-alert(1)-&#39;"
        );
        // `&` is encoded first, so existing ampersands survive faithfully.
        assert_eq!(apply_transform("a&b", Transform::EntityEncoded), "a&amp;b");
    }

    #[test]
    fn percent_encoded_neutralises_quotes_and_angles() {
        assert_eq!(
            apply_transform("'-alert(1)-'", Transform::PercentEncoded),
            "%27-alert%281%29-%27"
        );
        // A `javascript:` scheme loses its `:` so it no longer parses as a URL scheme.
        let encoded = apply_transform("javascript:alert(1)", Transform::PercentEncoded);
        assert!(!encoded.starts_with("javascript:"), "{encoded}");
        assert!(encoded.starts_with("javascript%3A"), "{encoded}");
    }

    #[test]
    fn case_folded_uppercases_ascii() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::CaseFolded),
            "<SVG ONLOAD=ALERT(1)>"
        );
    }

    #[test]
    fn truncated_keeps_prefix_before_needle() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::TruncatedAt("onload")),
            "<svg "
        );
        // Needle absent → payload passes through unchanged.
        assert_eq!(apply_transform("abc", Transform::TruncatedAt("z")), "abc");
    }

    #[test]
    fn text_only_encodes_angle_brackets_only() {
        assert_eq!(
            apply_transform("<svg onload=alert(1)>", Transform::TextOnly),
            "&lt;svg onload=alert(1)&gt;"
        );
    }

    #[test]
    fn reflect_substitutes_into_sink_template() {
        let body = reflect(
            "javascript:alert(1)",
            Transform::Full,
            r#"<a href="{PAYLOAD}">x</a>"#,
        );
        assert_eq!(body, r#"<a href="javascript:alert(1)">x</a>"#);
    }
}
