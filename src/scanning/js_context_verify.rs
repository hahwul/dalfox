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
use std::sync::OnceLock;

const JS_SINK_NAMES: &[&str] = &[
    "alert",
    "prompt",
    "confirm",
    "print",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
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

/// Returns true when a sink CallExpression's span lies fully within the
/// `[payload_start, payload_end)` byte range inside `script_src`. A strict
/// containment check ensures the injection — not the original page script —
/// produced the sink call.
fn script_block_has_sink_call_in_range(
    script_src: &str,
    payload_start: u32,
    payload_end: u32,
) -> bool {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, script_src, SourceType::default()).parse();
    if !ret.errors.is_empty() {
        // Syntax errors after injection ⇒ not exploitable as parsed JS.
        return false;
    }

    let mut found = false;
    for stmt in &ret.program.body {
        walk_statement(stmt, payload_start, payload_end, &mut found);
        if found {
            break;
        }
    }
    found
}

fn span_within(s: oxc_span::Span, start: u32, end: u32) -> bool {
    s.start >= start && s.end <= end
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
            if let Expression::StringLiteral(lit) = &member.expression {
                JS_SINK_NAMES.contains(&lit.value.as_str())
            } else {
                false
            }
        }
        Expression::ParenthesizedExpression(p) => callee_identifier_is_sink(&p.expression),
        _ => false,
    }
}

/// Recursive walker focused on locating sink CallExpression nodes whose span
/// lies inside the payload's reflected byte range.
fn walk_statement(stmt: &Statement<'_>, ps: u32, pe: u32, found: &mut bool) {
    if *found {
        return;
    }
    match stmt {
        Statement::ExpressionStatement(es) => walk_expr(&es.expression, ps, pe, found),
        Statement::VariableDeclaration(decl) => {
            for d in &decl.declarations {
                if let Some(init) = &d.init {
                    walk_expr(init, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Statement::BlockStatement(b) => {
            for s in &b.body {
                walk_statement(s, ps, pe, found);
                if *found {
                    return;
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expr(&s.test, ps, pe, found);
            if *found {
                return;
            }
            walk_statement(&s.consequent, ps, pe, found);
            if let Some(alt) = &s.alternate {
                walk_statement(alt, ps, pe, found);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                match init {
                    ForStatementInit::VariableDeclaration(decl) => {
                        for d in &decl.declarations {
                            if let Some(e) = &d.init {
                                walk_expr(e, ps, pe, found);
                            }
                        }
                    }
                    expr => {
                        if let Some(e) = expr.as_expression() {
                            walk_expr(e, ps, pe, found);
                        }
                    }
                }
            }
            if let Some(t) = &s.test {
                walk_expr(t, ps, pe, found);
            }
            if let Some(u) = &s.update {
                walk_expr(u, ps, pe, found);
            }
            walk_statement(&s.body, ps, pe, found);
        }
        Statement::WhileStatement(s) => {
            walk_expr(&s.test, ps, pe, found);
            if !*found {
                walk_statement(&s.body, ps, pe, found);
            }
        }
        Statement::DoWhileStatement(s) => {
            walk_statement(&s.body, ps, pe, found);
            if !*found {
                walk_expr(&s.test, ps, pe, found);
            }
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = &s.argument {
                walk_expr(arg, ps, pe, found);
            }
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    walk_statement(s, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Statement::TryStatement(t) => {
            for s in &t.block.body {
                walk_statement(s, ps, pe, found);
                if *found {
                    return;
                }
            }
            if let Some(handler) = &t.handler {
                for s in &handler.body.body {
                    walk_statement(s, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
            if let Some(finalizer) = &t.finalizer {
                for s in &finalizer.body {
                    walk_statement(s, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Statement::SwitchStatement(s) => {
            walk_expr(&s.discriminant, ps, pe, found);
            for case in &s.cases {
                if let Some(t) = &case.test {
                    walk_expr(t, ps, pe, found);
                }
                for s in &case.consequent {
                    walk_statement(s, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Statement::LabeledStatement(s) => walk_statement(&s.body, ps, pe, found),
        Statement::ThrowStatement(s) => walk_expr(&s.argument, ps, pe, found),
        _ => {}
    }
}

fn walk_expr(expr: &Expression<'_>, ps: u32, pe: u32, found: &mut bool) {
    if *found {
        return;
    }
    match expr {
        Expression::CallExpression(call) => {
            if callee_is_js_sink(call) && span_within(call.span(), ps, pe) {
                *found = true;
                return;
            }
            walk_expr(&call.callee, ps, pe, found);
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    walk_expr(e, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Expression::TaggedTemplateExpression(t) => {
            // alert`1`, prompt`1`, confirm`1`
            if callee_identifier_is_sink(&t.tag) && span_within(t.span(), ps, pe) {
                *found = true;
                return;
            }
            walk_expr(&t.tag, ps, pe, found);
            for e in &t.quasi.expressions {
                walk_expr(e, ps, pe, found);
                if *found {
                    return;
                }
            }
        }
        Expression::NewExpression(ne) => {
            if callee_identifier_is_sink(&ne.callee) && span_within(ne.span(), ps, pe) {
                *found = true;
                return;
            }
            walk_expr(&ne.callee, ps, pe, found);
            for arg in &ne.arguments {
                if let Some(e) = arg.as_expression() {
                    walk_expr(e, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expr(&a.right, ps, pe, found),
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                walk_expr(e, ps, pe, found);
                if *found {
                    return;
                }
            }
        }
        Expression::BinaryExpression(b) => {
            walk_expr(&b.left, ps, pe, found);
            walk_expr(&b.right, ps, pe, found);
        }
        Expression::LogicalExpression(l) => {
            walk_expr(&l.left, ps, pe, found);
            walk_expr(&l.right, ps, pe, found);
        }
        Expression::ConditionalExpression(c) => {
            walk_expr(&c.test, ps, pe, found);
            walk_expr(&c.consequent, ps, pe, found);
            walk_expr(&c.alternate, ps, pe, found);
        }
        Expression::UnaryExpression(u) => walk_expr(&u.argument, ps, pe, found),
        Expression::UpdateExpression(_) => {}
        Expression::ParenthesizedExpression(p) => walk_expr(&p.expression, ps, pe, found),
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(e) = el.as_expression() {
                    walk_expr(e, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expr(&p.value, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                walk_expr(e, ps, pe, found);
                if *found {
                    return;
                }
            }
        }
        Expression::ArrowFunctionExpression(f) => {
            for s in &f.body.statements {
                walk_statement(s, ps, pe, found);
                if *found {
                    return;
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    walk_statement(s, ps, pe, found);
                    if *found {
                        return;
                    }
                }
            }
        }
        Expression::StaticMemberExpression(m) => walk_expr(&m.object, ps, pe, found),
        Expression::ComputedMemberExpression(m) => {
            walk_expr(&m.object, ps, pe, found);
            if !*found {
                walk_expr(&m.expression, ps, pe, found);
            }
        }
        Expression::ChainExpression(c) => match &c.expression {
            ChainElement::CallExpression(call) => {
                if callee_is_js_sink(call) && span_within(call.span(), ps, pe) {
                    *found = true;
                    return;
                }
                walk_expr(&call.callee, ps, pe, found);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        walk_expr(e, ps, pe, found);
                        if *found {
                            return;
                        }
                    }
                }
            }
            _ => {}
        },
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
}
