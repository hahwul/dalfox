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
//! Limitation — regex literals: `/` is only ever read as division or a comment
//! start, never as a regex-literal delimiter. A prefix containing a regex
//! (`x.test(/)/)`, `s.replace(/}{/, …)`) can therefore mis-balance the stack and
//! yield a *wrong* closer — not merely a missing one. This is currently dormant:
//! [`compute_js_breakout`] is only ever run on the known-clean [`NESTING_SHELLS`]
//! by [`breakout_templates`]; it is NOT yet fed real observed script prefixes
//! (that wiring is a follow-up that also needs a per-parameter carrier).
//! Disambiguating regex-vs-division needs token-level context and is out of
//! scope here. Either way the synthesis path always falls back to the catalog.

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

#[cfg(test)]
mod tests;
