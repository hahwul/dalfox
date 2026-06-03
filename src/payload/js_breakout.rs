//! Exact JavaScript breakout-sequence computation (issue #1073).
//!
//! When a reflection lands inside an inline `<script>`, escaping to an
//! executable position requires closing whatever syntactic structure the
//! injection point sits in — an open string, and any unbalanced `(`, `[`, `{`
//! (including a template-literal `${…}` expression) that precede it. A fixed
//! breakout such as `';alert(1)//` only closes the string; for
//! `foo({ bar: [ "INJECT" ] })` it leaves the `]`, `}` and `)` open and the
//! injected statement never parses.
//!
//! [`compute_js_breakout`] scans the script prefix up to the injection point —
//! string-, comment- and template-aware — and returns the minimal closer
//! sequence (e.g. `"]})`) that reaches statement position. [`breakout_templates`]
//! uses it to derive a small, high-coverage set of payload templates for the
//! common nesting shapes, which the synthesis engine emits for JS string
//! contexts.
//!
//! [`compute_js_breakout`] is run two ways: by [`breakout_templates`] on the
//! known-clean [`NESTING_SHELLS`] to derive the fixed depth-0–3 catalog, and —
//! the issue #1073 follow-up — on the *real* observed inline-`<script>` source
//! at scan time via [`crate::parameter_analysis::detect_js_breakout`], whose
//! closer is carried per-parameter and emitted first by synthesis.
//!
//! Limitation — regex literals: `/` is only ever read as division or a comment
//! start, never as a regex-literal delimiter. A prefix containing a regex
//! (`x.test(/)/)`, `s.replace(/}{/, …)`) *before* the injection point can
//! therefore mis-balance the stack and yield a *wrong* closer — not merely a
//! missing one. Disambiguating regex-vs-division needs token-level context and
//! is out of scope here. This is non-regressing by construction: a wrong closer
//! only produces an inert payload (it reflects but does not parse to an
//! executable position), promotion to [V] is execution/marker-verified so an
//! inert payload can never become a false positive, and synthesis always *also*
//! emits the fixed catalog as a fallback — so the observed-prefix closer is
//! strictly additive over the prior fixed-only behavior.

/// A structural opener tracked on the scan stack.
#[derive(Clone, Copy, PartialEq)]
enum Open {
    Paren,   // (
    Bracket, // [
    Brace,   // {
    /// A `${` template-literal expression brace: closing it (`}`) returns to the
    /// surrounding template string, which then also needs a `` ` ``.
    TplExpr,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Code,
    Single,   // '…'
    Double,   // "…"
    Template, // `…`
    Line,     // // …
    Block,    // /* … */
}

/// Compute the minimal closer sequence that, injected at the end of `prefix`,
/// escapes any open string/comment and unbalanced `()[]{}`/`${}` so a following
/// `;<payload>//` reaches executable statement position.
///
/// Returns an empty string when `prefix` already ends at statement/expression
/// position (nothing to close).
pub fn compute_js_breakout(prefix: &str) -> String {
    let chars: Vec<char> = prefix.chars().collect();
    let mut state = State::Code;
    let mut stack: Vec<Open> = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match state {
            State::Code => match c {
                '\'' => state = State::Single,
                '"' => state = State::Double,
                '`' => state = State::Template,
                '(' => stack.push(Open::Paren),
                '[' => stack.push(Open::Bracket),
                '{' => stack.push(Open::Brace),
                ')' => {
                    if stack.last() == Some(&Open::Paren) {
                        stack.pop();
                    }
                }
                ']' => {
                    if stack.last() == Some(&Open::Bracket) {
                        stack.pop();
                    }
                }
                '}' => match stack.last() {
                    Some(Open::Brace) => {
                        stack.pop();
                    }
                    Some(Open::TplExpr) => {
                        stack.pop();
                        // Closing a `${…}` expression returns us to the template.
                        state = State::Template;
                    }
                    _ => {}
                },
                '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                    state = State::Line;
                    i += 1;
                }
                '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                    state = State::Block;
                    i += 1;
                }
                _ => {}
            },
            State::Single => {
                if c == '\\' {
                    i += 2; // skip the escaped char
                    continue;
                } else if c == '\'' {
                    state = State::Code;
                }
            }
            State::Double => {
                if c == '\\' {
                    i += 2;
                    continue;
                } else if c == '"' {
                    state = State::Code;
                }
            }
            State::Template => {
                if c == '\\' {
                    i += 2;
                    continue;
                } else if c == '`' {
                    state = State::Code;
                } else if c == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
                    stack.push(Open::TplExpr);
                    state = State::Code;
                    i += 2;
                    continue;
                }
            }
            State::Line => {
                if c == '\n' {
                    state = State::Code;
                }
            }
            State::Block => {
                if c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    state = State::Code;
                    i += 1;
                }
            }
        }
        i += 1;
    }

    let mut out = String::new();
    // 1) Close an open string / comment so the rest is parsed as code.
    match state {
        State::Single => out.push('\''),
        State::Double => out.push('"'),
        State::Template => out.push('`'),
        State::Block => out.push_str("*/"),
        State::Line => out.push('\n'),
        State::Code => {}
    }
    // 2) Close unbalanced structural openers, innermost first.
    for opener in stack.iter().rev() {
        match opener {
            Open::Paren => out.push(')'),
            Open::Bracket => out.push(']'),
            Open::Brace => out.push('}'),
            // Close the `${…}` expression brace, then the template literal that
            // contains it.
            Open::TplExpr => {
                out.push('}');
                out.push('`');
            }
        }
    }
    out
}

/// Representative structural shells (openers preceding the reflected string),
/// covering the common reflection sinks: bare string, inside a call, inside an
/// array, and one/two levels of array/object nesting inside a call.
const NESTING_SHELLS: &[&str] = &[
    "",      // var x = "…"
    "(",     // foo("…"
    "[",     // arr = ["…"
    "([",    // foo(["…"
    "({k:",  // foo({k:"…"
    "([{k:", // foo([{k:"…"
    "({k:[", // foo({k:["…"
];

/// Derive payload *templates* (carrying the `{JS}` placeholder) that break out
/// of a JS string delimited by `quote` for each common nesting shape. Each is
/// produced by running [`compute_js_breakout`] on `shell + quote`, so the
/// closer sequences are exactly what the scanner would compute for a real
/// prefix — deduplicated and ordered shallowest-first (highest confidence).
pub fn breakout_templates(quote: char) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for shell in NESTING_SHELLS {
        let prefix = format!("{}{}", shell, quote);
        let breaker = compute_js_breakout(&prefix);
        // `breaker` already includes the closing quote; append a statement
        // separator, the payload, and a line comment to neutralise the
        // original trailing source.
        let template = format!("{};{{JS}}//", breaker);
        if seen.insert(template.clone()) {
            out.push(template);
        }
    }
    out
}

/// Like [`breakout_templates`] but for a JS string whose delimiter the server
/// backslash-escapes (`"` → `\"`, issue #1072). Each template is the normal
/// breakout with a leading `\`: injecting `\"]});…` means the server escapes our
/// `"` to `\"`, so the source becomes `\\"]});…` — a literal backslash followed
/// by a *real* closing quote that reaches statement position. The leading `\` is
/// gated by `allows_str` in the synthesis layer like any other character.
///
/// Only meaningful for `'` / `"` delimiters — the quote-escape probe never flags
/// a backtick (a template literal isn't closed by `\``), so synthesis never
/// calls this with one.
pub fn escaped_breakout_templates(quote: char) -> Vec<String> {
    breakout_templates(quote)
        .into_iter()
        .map(|t| format!("\\{t}"))
        .collect()
}

#[cfg(test)]
mod tests;
