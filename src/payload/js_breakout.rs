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

/// Deepest run of unbalanced `(`/`[`/`{`/`${` we will build a closer for.
/// See the `push_open!` comment in [`compute_js_breakout`] — this bounds both
/// the returned string and every payload it is interpolated into.
const MAX_OPEN_DEPTH: usize = 256;

/// Compute the minimal closer sequence that, injected at the end of `prefix`,
/// escapes any open string/comment and unbalanced `()[]{}`/`${}` so a following
/// `;<payload>//` reaches executable statement position.
///
/// Returns an empty string when `prefix` already ends at statement/expression
/// position (nothing to close), or when the prefix nests deeper than
/// [`MAX_OPEN_DEPTH`].
pub(crate) fn compute_js_breakout(prefix: &str) -> String {
    let chars: Vec<char> = prefix.chars().collect();
    let mut state = State::Code;
    let mut stack: Vec<Open> = Vec::new();
    let mut i = 0;

    macro_rules! push_open {
        ($opener:expr) => {{
            stack.push($opener);
            // The closer is one byte per unbalanced opener and is carried into
            // every payload synthesized for the parameter, so an input like
            // `foo(` × 1 000 000 turns one reflection into megabyte payloads.
            // Nothing real nests this deep; past the bound we return "no
            // breakout" and the caller falls back to the fixed catalog, which
            // is the same path an already-balanced prefix takes.
            if stack.len() > MAX_OPEN_DEPTH {
                return String::new();
            }
        }};
    }

    while i < chars.len() {
        let c = chars[i];
        match state {
            State::Code => match c {
                '\'' => state = State::Single,
                '"' => state = State::Double,
                '`' => state = State::Template,
                '(' => push_open!(Open::Paren),
                '[' => push_open!(Open::Bracket),
                '{' => push_open!(Open::Brace),
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
                    push_open!(Open::TplExpr);
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

/// The quote character (`'`, `"` or `` ` ``) of the JS string or template
/// literal that is still open at the end of `prefix`, or `None` when `prefix`
/// ends in code or a comment.
///
/// This is the *innermost enclosing* delimiter: in `` foo(`a 'x `` the `'` is
/// literal text inside the template, so the answer is `` ` ``, where a
/// "closest quote before the marker" guess says `'`. Unlike
/// [`compute_js_breakout`] it recognises regex literals (by the preceding
/// token, the usual heuristic), because quote-escaping idioms such as
/// `s.replace(/"/g, '&quot;')` are common in the code before a reflection and
/// would otherwise leave the scan inside a phantom string.
pub(crate) fn enclosing_js_quote(prefix: &str) -> Option<char> {
    const KEYWORDS_BEFORE_REGEX: &[&str] = &[
        "return",
        "typeof",
        "case",
        "do",
        "else",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "instanceof",
        "yield",
        "await",
    ];
    let chars: Vec<char> = prefix.chars().collect();
    // Is a `/` at `i` (in code) the start of a regex literal? Decided by the
    // previous significant character or keyword.
    let regex_starts_at = |i: usize| -> bool {
        let mut j = i;
        while j > 0 && chars[j - 1].is_whitespace() {
            j -= 1;
        }
        if j == 0 {
            return true;
        }
        let prev = chars[j - 1];
        if prev.is_alphanumeric() || prev == '_' || prev == '$' {
            let end = j;
            while j > 0
                && (chars[j - 1].is_alphanumeric() || chars[j - 1] == '_' || chars[j - 1] == '$')
            {
                j -= 1;
            }
            let word: String = chars[j..end].iter().collect();
            return KEYWORDS_BEFORE_REGEX.contains(&word.as_str());
        }
        !matches!(prev, ')' | ']' | '\'' | '"' | '`' | '.')
    };
    let mut state = State::Code;
    // `true` for a `${` expression brace, `false` for an ordinary `{`.
    let mut braces: Vec<bool> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match state {
            State::Code => match c {
                '\'' => state = State::Single,
                '"' => state = State::Double,
                '`' => state = State::Template,
                '{' => braces.push(false),
                '}' => {
                    if braces.pop() == Some(true) {
                        state = State::Template;
                    }
                }
                '/' if chars.get(i + 1) == Some(&'/') => {
                    state = State::Line;
                    i += 1;
                }
                '/' if chars.get(i + 1) == Some(&'*') => {
                    state = State::Block;
                    i += 1;
                }
                '/' if regex_starts_at(i) => {
                    // Skip to the closing `/`, honouring escapes and `[…]`
                    // classes. A line break (or the end of the prefix) means
                    // it was not a regex after all; resume after the `/`.
                    let mut j = i + 1;
                    let mut in_class = false;
                    while j < chars.len() && chars[j] != '\n' {
                        match chars[j] {
                            '\\' => j += 1,
                            '[' => in_class = true,
                            ']' => in_class = false,
                            '/' if !in_class => break,
                            _ => {}
                        }
                        j += 1;
                    }
                    if j < chars.len() && chars[j] == '/' {
                        i = j;
                    }
                }
                _ => {}
            },
            State::Single | State::Double => {
                let close = if state == State::Single { '\'' } else { '"' };
                if c == '\\' {
                    i += 1;
                } else if c == close || c == '\n' {
                    state = State::Code;
                }
            }
            State::Template => {
                if c == '\\' {
                    i += 1;
                } else if c == '`' {
                    state = State::Code;
                } else if c == '$' && chars.get(i + 1) == Some(&'{') {
                    braces.push(true);
                    state = State::Code;
                    i += 1;
                }
            }
            State::Line => {
                if c == '\n' {
                    state = State::Code;
                }
            }
            State::Block => {
                if c == '*' && chars.get(i + 1) == Some(&'/') {
                    state = State::Code;
                    i += 1;
                }
            }
        }
        i += 1;
    }
    match state {
        State::Single => Some('\''),
        State::Double => Some('"'),
        State::Template => Some('`'),
        _ => None,
    }
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
pub(crate) fn breakout_templates(quote: char) -> Vec<String> {
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
pub(crate) fn escaped_breakout_templates(quote: char) -> Vec<String> {
    breakout_templates(quote)
        .into_iter()
        .map(|t| format!("\\{t}"))
        .collect()
}

#[cfg(test)]
mod tests;
