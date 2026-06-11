//! JS-context exploit verification via static AST analysis.
//!
//! HTML-DOM-marker verification (in `check_dom_verification`) cannot flag
//! payloads that exploit JavaScript string contexts (e.g. `var x = "<INJECT>"`)
//! because no DOM element is created. This module fills that gap: it locates
//! the reflected payload inside `<script>` blocks, parses the script with oxc,
//! and reports a positive verification when a known XSS sink call expression
//! (`alert`, `prompt`, `confirm`, `print`, `eval`, `setTimeout`, `setInterval`,
//! `Function`) appears within the byte range covered by the payload — meaning
//! the injection introduced an executable sink call.
//!
//! Strict overlap on the call's `Span` keeps this from firing on script blocks
//! whose original (un-injected) source already calls `alert(...)`.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use regex::Regex;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

/// Identifier or member-property names whose call we treat as an XSS sink.
/// Includes the obvious dialog/eval/timer family plus the DOM mutation sinks
/// most commonly reached through reflected JavaScript injection
/// (`document.write`, `el.insertAdjacentHTML`).
const JS_SINK_NAMES: &[&str] = &[
    "alert",
    "prompt",
    "confirm",
    "print",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "write",
    "writeln",
    "insertAdjacentHTML",
    // Modern Sanitizer-API opt-out: explicitly parses its argument as
    // HTML with no sanitization, so a payload that names it is almost
    // certainly attempting code execution through that path.
    "setHTMLUnsafe",
];

/// Properties whose assignment from injected content is itself an XSS sink
/// regardless of the right-hand value: the browser always parses the value
/// as HTML and runs any embedded event handlers.
const ASSIGNMENT_SINK_PROPERTIES_HTML: &[&str] = &["innerHTML", "outerHTML", "srcdoc"];

/// Navigation properties whose assignment is only a sink when the right-hand
/// value is a `javascript:` URL literal. Without this guard the heuristic
/// would falsely flag harmless redirects like `el.href = '/about'`.
const ASSIGNMENT_SINK_PROPERTIES_NAV: &[&str] = &["location", "href"];

/// Bare identifiers whose assignment behaves as `window.<id> = …` in the
/// browser. Same `javascript:` guard applies as for navigation properties.
const ASSIGNMENT_SINK_IDENTIFIERS_NAV: &[&str] = &["location"];

/// Quick filter: does the payload look like it carries a JavaScript sink that
/// could fire when reflected into a script context?
pub(crate) fn payload_carries_js_sink(payload: &str) -> bool {
    JS_SINK_NAMES.iter().any(|s| payload.contains(s))
        || ASSIGNMENT_SINK_PROPERTIES_HTML
            .iter()
            .any(|s| payload.contains(s))
        || (payload.contains("javascript:")
            && (ASSIGNMENT_SINK_PROPERTIES_NAV
                .iter()
                .any(|s| payload.contains(s))
                || ASSIGNMENT_SINK_IDENTIFIERS_NAV
                    .iter()
                    .any(|s| payload.contains(s))))
}

fn script_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)<script\b[^>]*>(.*?)</script\s*>").expect("valid script block regex")
    })
}

/// Iterate `<script>` block contents in the HTML response.
fn script_blocks(html: &str) -> impl Iterator<Item = &str> {
    script_block_re()
        .captures_iter(html)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str()))
}

/// Soft cap on cached entries. Beyond this we drop a quarter of the cache
/// (cheap FIFO-ish eviction) to keep memory bounded for long-running scans
/// hitting many distinct `<script>` blocks.
const SINK_CACHE_CAPACITY: usize = 1024;

/// Parsed-spans bundle for a `<script>` body, or `None` when the body
/// failed to parse (and is therefore treated as inert). The first vector
/// holds sink-call spans, the second holds string-literal spans (used to
/// gate sink hits that sit *inside* a string).
type ParsedSpans = Option<(Vec<(u32, u32)>, Vec<(u32, u32)>)>;
type SinkCache = Mutex<HashMap<u64, ParsedSpans>>;

fn sink_cache() -> &'static SinkCache {
    static CACHE: OnceLock<SinkCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hash_block(script_src: &str) -> u64 {
    let mut h = DefaultHasher::new();
    script_src.hash(&mut h);
    h.finish()
}

/// Parse `script_src` once and collect every sink-call span and every
/// string-literal span. Returns `None` when the source has parser errors
/// (treated as inert — injected JS that breaks parsing won't execute).
fn collect_parsed_spans(script_src: &str) -> ParsedSpans {
    // Guard the oxc parse exactly like `ast_dom_analysis::analyze`: a single
    // malicious/compromised target can serve a `<script>` body with thousands
    // of nested brackets or a multi-byte right-leaning chain that overflows
    // oxc's recursive-descent parser *inside* `.parse()` — a stack overflow
    // SIGABRTs the whole process (all in-flight scans, server/MCP jobs). Skip
    // pathological bodies (treated as inert) and run larger-but-approved ones
    // on a dedicated big-stack thread.
    if crate::scanning::ast_dom_analysis::source_exceeds_parse_guards(script_src) {
        return None;
    }
    if script_src.len() <= crate::scanning::ast_dom_analysis::SAFE_INLINE_PARSE_BYTES {
        return collect_spans_on_stack(script_src);
    }
    // A spawn failure (`None`) is also treated as inert — we must NOT fall back
    // to an inline parse, which could overflow the caller's worker stack.
    crate::scanning::ast_dom_analysis::run_parse_on_large_stack(|| {
        collect_spans_on_stack(script_src)
    })
    .flatten()
}

/// Parse `script_src` and collect every sink-call span and every string-literal
/// span. Factored out of [`collect_parsed_spans`] so it can run on a dedicated
/// large-stack thread for inputs above [`SAFE_INLINE_PARSE_BYTES`].
fn collect_spans_on_stack(script_src: &str) -> ParsedSpans {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, script_src, SourceType::default()).parse();
    if !ret.errors.is_empty() {
        return None;
    }
    let mut sinks: Vec<(u32, u32)> = Vec::new();
    let mut strings: Vec<(u32, u32)> = Vec::new();
    for stmt in &ret.program.body {
        gather_sink_spans_in_statement(stmt, &mut sinks, &mut strings);
    }
    Some((sinks, strings))
}

/// Cached `collect_parsed_spans`. The same `<script>` body often appears
/// across many per-payload responses (page boilerplate, inline framework
/// setup); each distinct block is parsed at most once across the whole
/// process.
fn cached_parsed_spans(script_src: &str) -> ParsedSpans {
    let key = hash_block(script_src);
    {
        let cache = sink_cache().lock().expect("sink cache poisoned");
        if let Some(v) = cache.get(&key) {
            return v.clone();
        }
    }
    let result = collect_parsed_spans(script_src);
    let mut cache = sink_cache().lock().expect("sink cache poisoned");
    if cache.len() >= SINK_CACHE_CAPACITY {
        let drop_n = cache.len() / 4;
        let to_drop: Vec<u64> = cache.keys().take(drop_n).copied().collect();
        for k in to_drop {
            cache.remove(&k);
        }
    }
    cache.insert(key, result.clone());
    result
}

/// Returns true when the payload range introduced a real sink call into
/// the parsed script. Two guards:
///
/// - String-literal containment: if the payload range sits *strictly*
///   inside any string literal (i.e. the payload did not consume the
///   opening or closing quote), the reflection never broke out of the
///   string. Any sink-call token inside is just string content the JS
///   engine will not evaluate. Without this guard, a reflection like
///   `decodeURIComponent("…'-alert(1)-'…")` — where the payload is a
///   literal `'-alert(1)-'` inside a *double-quoted* string — would be
///   verified, because the payload bytes happen to overlap a sink span
///   that lives inside the surrounding string literal.
/// - Sink containment: a sink-call span lies fully within the payload's
///   byte range, meaning the payload itself produced the call.
fn script_block_has_sink_call_in_range(
    script_src: &str,
    payload_start: u32,
    payload_end: u32,
) -> bool {
    let Some((sinks, strings)) = cached_parsed_spans(script_src) else {
        return false;
    };
    // Strict containment: payload range must sit *between* the quotes,
    // not touch them — otherwise the payload broke the string and the
    // surrounding literal is no longer a literal.
    if strings
        .iter()
        .any(|&(s, e)| payload_start > s && payload_end < e)
    {
        return false;
    }
    sinks
        .iter()
        .any(|&(s, e)| s >= payload_start && e <= payload_end)
}

fn callee_is_js_sink(call: &CallExpression<'_>) -> bool {
    callee_identifier_is_sink(&call.callee)
}

/// True when an AssignmentExpression's right-hand side is a string literal
/// that begins with `javascript:` (case-insensitive). Used to gate the
/// navigation-sink rule so harmless redirects like `el.href = '/about'` are
/// not flagged.
fn rhs_is_javascript_url(right: &Expression<'_>) -> bool {
    match right {
        Expression::StringLiteral(lit) => {
            let trimmed = lit.value.trim_start();
            trimmed.len() >= "javascript:".len()
                && trimmed.as_bytes()[..11].eq_ignore_ascii_case(b"javascript:")
        }
        Expression::ParenthesizedExpression(p) => rhs_is_javascript_url(&p.expression),
        Expression::BinaryExpression(b) => {
            // Loose check: any concatenation chain producing a string starting
            // with `javascript:` like `'jav' + 'ascript:' + …`.
            // Conservative — only check left operand's literal prefix.
            rhs_is_javascript_url(&b.left)
        }
        _ => false,
    }
}

/// Whether an `AssignmentExpression` is itself an XSS sink. Combines the
/// HTML-parsing properties (always sink) with the navigation properties
/// (sink only when the right-hand value is a `javascript:` URL).
fn assignment_is_sink(assign: &AssignmentExpression<'_>) -> bool {
    match &assign.left {
        AssignmentTarget::AssignmentTargetIdentifier(id) => {
            ASSIGNMENT_SINK_IDENTIFIERS_NAV.contains(&id.name.as_str())
                && rhs_is_javascript_url(&assign.right)
        }
        AssignmentTarget::StaticMemberExpression(m) => {
            let name = m.property.name.as_str();
            if ASSIGNMENT_SINK_PROPERTIES_HTML.contains(&name) {
                return true;
            }
            if ASSIGNMENT_SINK_PROPERTIES_NAV.contains(&name) {
                return rhs_is_javascript_url(&assign.right);
            }
            false
        }
        AssignmentTarget::ComputedMemberExpression(m) => {
            if let Expression::StringLiteral(lit) = &m.expression {
                let name = lit.value.as_str();
                if ASSIGNMENT_SINK_PROPERTIES_HTML.contains(&name) {
                    return true;
                }
                if ASSIGNMENT_SINK_PROPERTIES_NAV.contains(&name) {
                    return rhs_is_javascript_url(&assign.right);
                }
            }
            false
        }
        _ => false,
    }
}

fn callee_identifier_is_sink(callee: &Expression<'_>) -> bool {
    match callee {
        Expression::Identifier(id) => JS_SINK_NAMES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(member) => {
            JS_SINK_NAMES.contains(&member.property.name.as_str())
        }
        Expression::ComputedMemberExpression(member) => {
            // foo["alert"](1) — string-keyed dynamic dispatch
            if let Expression::StringLiteral(lit) = &member.expression
                && JS_SINK_NAMES.contains(&lit.value.as_str())
            {
                return true;
            }
            // [alert][0](1) — array-then-index bypass: object is an
            // ArrayExpression whose first element is a sink identifier and
            // the indexer is the literal numeric 0.
            if let Expression::ArrayExpression(arr) = &member.object
                && let Expression::NumericLiteral(num) = &member.expression
                && num.value == 0.0
                && let Some(first) = arr.elements.first()
                && let Some(first_expr) = first.as_expression()
                && callee_identifier_is_sink(first_expr)
            {
                return true;
            }
            false
        }
        Expression::ParenthesizedExpression(p) => callee_identifier_is_sink(&p.expression),
        // (0,alert)(1) / (_,alert)(1) — comma-operator bypass: only the last
        // expression in the sequence determines the call target.
        Expression::SequenceExpression(seq) => seq
            .expressions
            .last()
            .is_some_and(callee_identifier_is_sink),
        _ => false,
    }
}

/// Walk the AST once and accumulate every sink CallExpression / NewExpression
/// / TaggedTemplateExpression span and every StringLiteral span. Range filtering
/// happens at lookup time against the cached span list, so the heavy parse runs
/// at most once per distinct script body.
fn gather_sink_spans_in_statement(
    stmt: &Statement<'_>,
    out: &mut Vec<(u32, u32)>,
    strings: &mut Vec<(u32, u32)>,
) {
    match stmt {
        Statement::ExpressionStatement(es) => {
            gather_sink_spans_in_expression(&es.expression, out, strings)
        }
        Statement::VariableDeclaration(decl) => {
            for d in &decl.declarations {
                if let Some(init) = &d.init {
                    gather_sink_spans_in_expression(init, out, strings);
                }
            }
        }
        Statement::BlockStatement(b) => {
            for s in &b.body {
                gather_sink_spans_in_statement(s, out, strings);
            }
        }
        Statement::IfStatement(s) => {
            gather_sink_spans_in_expression(&s.test, out, strings);
            gather_sink_spans_in_statement(&s.consequent, out, strings);
            if let Some(alt) = &s.alternate {
                gather_sink_spans_in_statement(alt, out, strings);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                match init {
                    ForStatementInit::VariableDeclaration(decl) => {
                        for d in &decl.declarations {
                            if let Some(e) = &d.init {
                                gather_sink_spans_in_expression(e, out, strings);
                            }
                        }
                    }
                    expr => {
                        if let Some(e) = expr.as_expression() {
                            gather_sink_spans_in_expression(e, out, strings);
                        }
                    }
                }
            }
            if let Some(t) = &s.test {
                gather_sink_spans_in_expression(t, out, strings);
            }
            if let Some(u) = &s.update {
                gather_sink_spans_in_expression(u, out, strings);
            }
            gather_sink_spans_in_statement(&s.body, out, strings);
        }
        Statement::WhileStatement(s) => {
            gather_sink_spans_in_expression(&s.test, out, strings);
            gather_sink_spans_in_statement(&s.body, out, strings);
        }
        Statement::DoWhileStatement(s) => {
            gather_sink_spans_in_statement(&s.body, out, strings);
            gather_sink_spans_in_expression(&s.test, out, strings);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = &s.argument {
                gather_sink_spans_in_expression(arg, out, strings);
            }
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    gather_sink_spans_in_statement(s, out, strings);
                }
            }
        }
        Statement::TryStatement(t) => {
            for s in &t.block.body {
                gather_sink_spans_in_statement(s, out, strings);
            }
            if let Some(handler) = &t.handler {
                for s in &handler.body.body {
                    gather_sink_spans_in_statement(s, out, strings);
                }
            }
            if let Some(finalizer) = &t.finalizer {
                for s in &finalizer.body {
                    gather_sink_spans_in_statement(s, out, strings);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            gather_sink_spans_in_expression(&s.discriminant, out, strings);
            for case in &s.cases {
                if let Some(t) = &case.test {
                    gather_sink_spans_in_expression(t, out, strings);
                }
                for s in &case.consequent {
                    gather_sink_spans_in_statement(s, out, strings);
                }
            }
        }
        Statement::LabeledStatement(s) => gather_sink_spans_in_statement(&s.body, out, strings),
        Statement::ThrowStatement(s) => gather_sink_spans_in_expression(&s.argument, out, strings),
        _ => {}
    }
}

fn push_span(out: &mut Vec<(u32, u32)>, span: oxc_span::Span) {
    out.push((span.start, span.end));
}

fn gather_sink_spans_in_expression(
    expr: &Expression<'_>,
    out: &mut Vec<(u32, u32)>,
    strings: &mut Vec<(u32, u32)>,
) {
    // String literals are leaves — record their full source span (quotes
    // included, as produced by the oxc parser) so the lookup stage can
    // tell when a payload landed strictly inside a string and never
    // escaped its delimiters.
    if let Expression::StringLiteral(lit) = expr {
        push_span(strings, lit.span);
        return;
    }
    match expr {
        Expression::CallExpression(call) => {
            if callee_is_js_sink(call) {
                push_span(out, call.span());
            }
            gather_sink_spans_in_expression(&call.callee, out, strings);
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    gather_sink_spans_in_expression(e, out, strings);
                }
            }
        }
        Expression::TaggedTemplateExpression(t) => {
            if callee_identifier_is_sink(&t.tag) {
                push_span(out, t.span());
            }
            gather_sink_spans_in_expression(&t.tag, out, strings);
            for e in &t.quasi.expressions {
                gather_sink_spans_in_expression(e, out, strings);
            }
        }
        Expression::NewExpression(ne) => {
            if callee_identifier_is_sink(&ne.callee) {
                push_span(out, ne.span());
            }
            gather_sink_spans_in_expression(&ne.callee, out, strings);
            for arg in &ne.arguments {
                if let Some(e) = arg.as_expression() {
                    gather_sink_spans_in_expression(e, out, strings);
                }
            }
        }
        Expression::AssignmentExpression(a) => {
            if assignment_is_sink(a) {
                push_span(out, a.span());
            }
            gather_sink_spans_in_expression(&a.right, out, strings);
        }
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                gather_sink_spans_in_expression(e, out, strings);
            }
        }
        Expression::BinaryExpression(b) => {
            gather_sink_spans_in_expression(&b.left, out, strings);
            gather_sink_spans_in_expression(&b.right, out, strings);
        }
        Expression::LogicalExpression(l) => {
            gather_sink_spans_in_expression(&l.left, out, strings);
            gather_sink_spans_in_expression(&l.right, out, strings);
        }
        Expression::ConditionalExpression(c) => {
            gather_sink_spans_in_expression(&c.test, out, strings);
            gather_sink_spans_in_expression(&c.consequent, out, strings);
            gather_sink_spans_in_expression(&c.alternate, out, strings);
        }
        Expression::UnaryExpression(u) => {
            gather_sink_spans_in_expression(&u.argument, out, strings)
        }
        Expression::UpdateExpression(_) => {}
        Expression::ParenthesizedExpression(p) => {
            gather_sink_spans_in_expression(&p.expression, out, strings)
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(e) = el.as_expression() {
                    gather_sink_spans_in_expression(e, out, strings);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    gather_sink_spans_in_expression(&p.value, out, strings);
                }
            }
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                gather_sink_spans_in_expression(e, out, strings);
            }
        }
        Expression::ArrowFunctionExpression(f) => {
            for s in &f.body.statements {
                gather_sink_spans_in_statement(s, out, strings);
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    gather_sink_spans_in_statement(s, out, strings);
                }
            }
        }
        Expression::StaticMemberExpression(m) => {
            gather_sink_spans_in_expression(&m.object, out, strings)
        }
        Expression::ComputedMemberExpression(m) => {
            gather_sink_spans_in_expression(&m.object, out, strings);
            gather_sink_spans_in_expression(&m.expression, out, strings);
        }
        Expression::ChainExpression(c) => {
            if let ChainElement::CallExpression(call) = &c.expression {
                if callee_is_js_sink(call) {
                    push_span(out, call.span());
                }
                gather_sink_spans_in_expression(&call.callee, out, strings);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        gather_sink_spans_in_expression(e, out, strings);
                    }
                }
            }
        }
        _ => {}
    }
}

/// True when *any* occurrence of `payload` within `src` introduces a JS sink
/// call. A benign in-string reflection (e.g. `var s = "…alert(1)…"`) can precede
/// the genuinely executable breakout occurrence in the same `<script>` block, so
/// every occurrence is checked — not just `find()`'s first, which downgraded a
/// real finding to Reflected.
fn any_payload_occurrence_hits_sink(src: &str, payload: &str) -> bool {
    if payload.is_empty() {
        return false;
    }
    src.match_indices(payload).any(|(start, _)| {
        let end = start + payload.len();
        script_block_has_sink_call_in_range(src, start as u32, end as u32)
    })
}

/// Maximum body size (bytes) for which we attempt full-body JS parsing as a
/// JSONP-context fallback. Large transpiled bundles are skipped to keep
/// per-payload overhead bounded.
const JSONP_PARSE_MAX_BYTES: usize = 64 * 1024;

/// Public entry point: returns true when the payload, reflected inside any
/// `<script>` block of `html`, parses cleanly and produces a JS sink call
/// whose span sits inside the payload range.
///
/// Falls back to parsing the entire body as JavaScript when the response
/// contains no `<script>` blocks — this handles JSONP / pure-JS responses
/// where the payload is reflected as the callable identifier (e.g.
/// `callback=alert(1);foo` reflected as `alert(1);foo({…})`).
pub(crate) fn has_js_context_evidence(payload: &str, html: &str) -> bool {
    if !payload_carries_js_sink(payload) {
        return false;
    }
    let mut saw_block = false;
    for block in script_blocks(html) {
        saw_block = true;
        if any_payload_occurrence_hits_sink(block, payload) {
            return true;
        }
    }
    if !saw_block
        && html.len() <= JSONP_PARSE_MAX_BYTES
        && any_payload_occurrence_hits_sink(html, payload)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests;
