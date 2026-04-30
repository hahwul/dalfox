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
];

/// Quick filter: does the payload look like it carries a JavaScript sink that
/// could fire when reflected into a script context?
pub(crate) fn payload_carries_js_sink(payload: &str) -> bool {
    JS_SINK_NAMES.iter().any(|s| payload.contains(s))
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

fn sink_cache() -> &'static Mutex<HashMap<u64, Option<Vec<(u32, u32)>>>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Option<Vec<(u32, u32)>>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hash_block(script_src: &str) -> u64 {
    let mut h = DefaultHasher::new();
    script_src.hash(&mut h);
    h.finish()
}

/// Parse `script_src` once and collect every sink-call span. Returns `None`
/// when the source has parser errors (treated as inert — injected JS that
/// breaks parsing won't execute).
fn collect_sink_spans(script_src: &str) -> Option<Vec<(u32, u32)>> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, script_src, SourceType::default()).parse();
    if !ret.errors.is_empty() {
        return None;
    }
    let mut spans: Vec<(u32, u32)> = Vec::new();
    for stmt in &ret.program.body {
        gather_sink_spans_in_statement(stmt, &mut spans);
    }
    Some(spans)
}

/// Cached `collect_sink_spans`. The same `<script>` body often appears across
/// many per-payload responses (page boilerplate, inline framework setup); each
/// distinct block is parsed at most once across the whole process.
fn cached_sink_spans(script_src: &str) -> Option<Vec<(u32, u32)>> {
    let key = hash_block(script_src);
    {
        let cache = sink_cache().lock().expect("sink cache poisoned");
        if let Some(v) = cache.get(&key) {
            return v.clone();
        }
    }
    let result = collect_sink_spans(script_src);
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

/// Returns true when a cached sink-call span lies fully within the
/// `[payload_start, payload_end)` byte range inside `script_src`.
fn script_block_has_sink_call_in_range(
    script_src: &str,
    payload_start: u32,
    payload_end: u32,
) -> bool {
    let Some(spans) = cached_sink_spans(script_src) else {
        return false;
    };
    spans
        .iter()
        .any(|&(s, e)| s >= payload_start && e <= payload_end)
}

fn callee_is_js_sink(call: &CallExpression<'_>) -> bool {
    callee_identifier_is_sink(&call.callee)
}

fn callee_identifier_is_sink(callee: &Expression<'_>) -> bool {
    match callee {
        Expression::Identifier(id) => JS_SINK_NAMES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(member) => {
            JS_SINK_NAMES.contains(&member.property.name.as_str())
        }
        Expression::ComputedMemberExpression(member) => {
            // foo["alert"](1) — string-keyed dynamic dispatch
            if let Expression::StringLiteral(lit) = &member.expression {
                if JS_SINK_NAMES.contains(&lit.value.as_str()) {
                    return true;
                }
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
            .map(callee_identifier_is_sink)
            .unwrap_or(false),
        _ => false,
    }
}

/// Walk the AST once and accumulate every sink CallExpression / NewExpression
/// / TaggedTemplateExpression span. Range filtering happens at lookup time
/// against the cached span list, so the heavy parse runs at most once per
/// distinct script body.
fn gather_sink_spans_in_statement(stmt: &Statement<'_>, out: &mut Vec<(u32, u32)>) {
    match stmt {
        Statement::ExpressionStatement(es) => gather_sink_spans_in_expression(&es.expression, out),
        Statement::VariableDeclaration(decl) => {
            for d in &decl.declarations {
                if let Some(init) = &d.init {
                    gather_sink_spans_in_expression(init, out);
                }
            }
        }
        Statement::BlockStatement(b) => {
            for s in &b.body {
                gather_sink_spans_in_statement(s, out);
            }
        }
        Statement::IfStatement(s) => {
            gather_sink_spans_in_expression(&s.test, out);
            gather_sink_spans_in_statement(&s.consequent, out);
            if let Some(alt) = &s.alternate {
                gather_sink_spans_in_statement(alt, out);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                match init {
                    ForStatementInit::VariableDeclaration(decl) => {
                        for d in &decl.declarations {
                            if let Some(e) = &d.init {
                                gather_sink_spans_in_expression(e, out);
                            }
                        }
                    }
                    expr => {
                        if let Some(e) = expr.as_expression() {
                            gather_sink_spans_in_expression(e, out);
                        }
                    }
                }
            }
            if let Some(t) = &s.test {
                gather_sink_spans_in_expression(t, out);
            }
            if let Some(u) = &s.update {
                gather_sink_spans_in_expression(u, out);
            }
            gather_sink_spans_in_statement(&s.body, out);
        }
        Statement::WhileStatement(s) => {
            gather_sink_spans_in_expression(&s.test, out);
            gather_sink_spans_in_statement(&s.body, out);
        }
        Statement::DoWhileStatement(s) => {
            gather_sink_spans_in_statement(&s.body, out);
            gather_sink_spans_in_expression(&s.test, out);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = &s.argument {
                gather_sink_spans_in_expression(arg, out);
            }
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    gather_sink_spans_in_statement(s, out);
                }
            }
        }
        Statement::TryStatement(t) => {
            for s in &t.block.body {
                gather_sink_spans_in_statement(s, out);
            }
            if let Some(handler) = &t.handler {
                for s in &handler.body.body {
                    gather_sink_spans_in_statement(s, out);
                }
            }
            if let Some(finalizer) = &t.finalizer {
                for s in &finalizer.body {
                    gather_sink_spans_in_statement(s, out);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            gather_sink_spans_in_expression(&s.discriminant, out);
            for case in &s.cases {
                if let Some(t) = &case.test {
                    gather_sink_spans_in_expression(t, out);
                }
                for s in &case.consequent {
                    gather_sink_spans_in_statement(s, out);
                }
            }
        }
        Statement::LabeledStatement(s) => gather_sink_spans_in_statement(&s.body, out),
        Statement::ThrowStatement(s) => gather_sink_spans_in_expression(&s.argument, out),
        _ => {}
    }
}

fn push_span(out: &mut Vec<(u32, u32)>, span: oxc_span::Span) {
    out.push((span.start, span.end));
}

fn gather_sink_spans_in_expression(expr: &Expression<'_>, out: &mut Vec<(u32, u32)>) {
    match expr {
        Expression::CallExpression(call) => {
            if callee_is_js_sink(call) {
                push_span(out, call.span());
            }
            gather_sink_spans_in_expression(&call.callee, out);
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    gather_sink_spans_in_expression(e, out);
                }
            }
        }
        Expression::TaggedTemplateExpression(t) => {
            if callee_identifier_is_sink(&t.tag) {
                push_span(out, t.span());
            }
            gather_sink_spans_in_expression(&t.tag, out);
            for e in &t.quasi.expressions {
                gather_sink_spans_in_expression(e, out);
            }
        }
        Expression::NewExpression(ne) => {
            if callee_identifier_is_sink(&ne.callee) {
                push_span(out, ne.span());
            }
            gather_sink_spans_in_expression(&ne.callee, out);
            for arg in &ne.arguments {
                if let Some(e) = arg.as_expression() {
                    gather_sink_spans_in_expression(e, out);
                }
            }
        }
        Expression::AssignmentExpression(a) => gather_sink_spans_in_expression(&a.right, out),
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                gather_sink_spans_in_expression(e, out);
            }
        }
        Expression::BinaryExpression(b) => {
            gather_sink_spans_in_expression(&b.left, out);
            gather_sink_spans_in_expression(&b.right, out);
        }
        Expression::LogicalExpression(l) => {
            gather_sink_spans_in_expression(&l.left, out);
            gather_sink_spans_in_expression(&l.right, out);
        }
        Expression::ConditionalExpression(c) => {
            gather_sink_spans_in_expression(&c.test, out);
            gather_sink_spans_in_expression(&c.consequent, out);
            gather_sink_spans_in_expression(&c.alternate, out);
        }
        Expression::UnaryExpression(u) => gather_sink_spans_in_expression(&u.argument, out),
        Expression::UpdateExpression(_) => {}
        Expression::ParenthesizedExpression(p) => {
            gather_sink_spans_in_expression(&p.expression, out)
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(e) = el.as_expression() {
                    gather_sink_spans_in_expression(e, out);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    gather_sink_spans_in_expression(&p.value, out);
                }
            }
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                gather_sink_spans_in_expression(e, out);
            }
        }
        Expression::ArrowFunctionExpression(f) => {
            for s in &f.body.statements {
                gather_sink_spans_in_statement(s, out);
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    gather_sink_spans_in_statement(s, out);
                }
            }
        }
        Expression::StaticMemberExpression(m) => gather_sink_spans_in_expression(&m.object, out),
        Expression::ComputedMemberExpression(m) => {
            gather_sink_spans_in_expression(&m.object, out);
            gather_sink_spans_in_expression(&m.expression, out);
        }
        Expression::ChainExpression(c) => {
            if let ChainElement::CallExpression(call) = &c.expression {
                if callee_is_js_sink(call) {
                    push_span(out, call.span());
                }
                gather_sink_spans_in_expression(&call.callee, out);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        gather_sink_spans_in_expression(e, out);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Locate the payload in the script block as raw substring. Returns the byte
/// range `[start, end)` if found.
fn locate_payload(script_src: &str, payload: &str) -> Option<(u32, u32)> {
    let start = script_src.find(payload)?;
    let end = start + payload.len();
    Some((start as u32, end as u32))
}

/// Public entry point: returns true when the payload, reflected inside any
/// `<script>` block of `html`, parses cleanly and produces a JS sink call
/// whose span sits inside the payload range.
pub(crate) fn has_js_context_evidence(payload: &str, html: &str) -> bool {
    if !payload_carries_js_sink(payload) {
        return false;
    }
    for block in script_blocks(html) {
        if let Some((ps, pe)) = locate_payload(block, payload)
            && script_block_has_sink_call_in_range(block, ps, pe)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_alert_breakout_in_double_quoted_js_string() {
        // Mirrors brutelogic c2 case: var c2 = "<INJECT>"
        let payload = "\"-alert(1)-\"";
        let html = format!(
            "<html><body><script>var c2 = \"{}\";</script></body></html>",
            payload
        );
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_alert_breakout_in_single_quoted_js_string() {
        let payload = "'-alert(1)-'";
        let html = format!(
            "<html><body><script>var c1 = '{}';</script></body></html>",
            payload
        );
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_plus_concat_breakout() {
        let payload = "\"+alert(1)+\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_tagged_template_payload() {
        let payload = "alert`1`";
        let html = format!("<script>var x = {};</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn rejects_html_entity_encoded_reflection_in_script() {
        // Server entity-encoded the reflection, so the JS source contains
        // literal `&#x27;` text — `alert(1)` is never produced as a real call.
        let payload = "'-alert(1)-'";
        let html = "<script>var c5 = '&#x27;-alert(1)-&#x27;';</script>";
        // The literal payload string is not the actual reflected text.
        assert!(!has_js_context_evidence(payload, html));
    }

    #[test]
    fn rejects_when_payload_breaks_syntax() {
        let payload = "</script><h1>";
        let html = "<script>var x = \"</script><h1>\";</script>";
        // After breakout, parser sees `var x = "` which is a syntax error;
        // and there's no sink call anyway. Should not return true here.
        assert!(!has_js_context_evidence(payload, html));
    }

    #[test]
    fn ignores_pre_existing_alert_outside_payload_range() {
        let payload = "\"-foo-\"";
        let html = format!(
            "<script>alert(1); var x = \"{}\";</script>",
            payload
        );
        // `alert(1)` exists but it's not inside the payload's byte range.
        assert!(!has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_set_timeout_string_payload() {
        let payload = "\";setTimeout('alert(1)');\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn no_evidence_when_payload_not_in_script_block() {
        let payload = "\"-alert(1)-\"";
        let html = "<html><body>\"-alert(1)-\"</body></html>";
        // Reflected outside any <script>; this module should not claim V.
        assert!(!has_js_context_evidence(payload, html));
    }

    #[test]
    fn payload_quick_filter_rejects_non_sink_payload() {
        assert!(!payload_carries_js_sink("<svg/onload=foo>"));
        assert!(payload_carries_js_sink("\"-alert(1)-\""));
        assert!(payload_carries_js_sink("prompt`1`"));
    }

    #[test]
    fn cached_sink_spans_returns_same_result_for_identical_blocks() {
        // Two distinct calls on the same script source must yield the same
        // span set; the second call should hit the cache rather than re-parse.
        let block = "var c2 = \"\"-alert(1)-\"\"; var x = 5; window.foo = 1;";
        let first = cached_sink_spans(block).expect("parses cleanly");
        let second = cached_sink_spans(block).expect("parses cleanly (cache hit)");
        assert_eq!(first, second);
        assert!(!first.is_empty(), "should record at least one sink span");
    }

    #[test]
    fn detects_comma_operator_bypass() {
        let payload = "\";(0,alert)(1);\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_underscore_comma_bypass() {
        let payload = "\";(_,alert)(1);\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_array_index_bypass() {
        let payload = "\";[alert][0](1);\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_string_keyed_dispatch_bypass() {
        let payload = "\";window[\"alert\"](1);\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn detects_document_write_payload() {
        let payload = "\";document.write(1);\"";
        let html = format!("<script>var x = \"{}\";</script>", payload);
        assert!(has_js_context_evidence(payload, &html));
    }

    #[test]
    fn cached_sink_spans_distinct_for_different_blocks() {
        let a = "var c1 = ''-alert(1)-'';";
        let b = "var c2 = \"-prompt(1)-\";";
        let sa = cached_sink_spans(a).expect("a parses");
        let sb = cached_sink_spans(b).expect("b parses");
        assert_ne!(sa, sb);
    }
}
