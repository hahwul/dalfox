use super::*;

// ===== Algorithm: exact closer sequences =====

#[test]
fn closes_plain_string() {
    assert_eq!(compute_js_breakout("var x = \""), "\"");
    assert_eq!(compute_js_breakout("var x = '"), "'");
    assert_eq!(compute_js_breakout("var x = `"), "`");
}

#[test]
fn closes_nested_call_array_object() {
    assert_eq!(compute_js_breakout("foo(\""), "\")");
    assert_eq!(compute_js_breakout("arr = [\""), "\"]");
    assert_eq!(compute_js_breakout("foo([\""), "\"])");
    assert_eq!(compute_js_breakout("foo({k:\""), "\"})");
    // The issue's worked example: foo({ bar: [ "INJECT" ] })
    assert_eq!(compute_js_breakout("foo({ bar: [ \""), "\"]})");
}

#[test]
fn ignores_delimiters_inside_strings_and_comments() {
    // Brackets inside a (closed) string must not affect the stack.
    assert_eq!(compute_js_breakout("foo(\"a)]}b\", \""), "\")");
    // Escaped quote does not close the string.
    assert_eq!(compute_js_breakout("\"a\\\"b"), "\"");
    // Line comment swallows everything to EOL.
    assert_eq!(compute_js_breakout("foo( // )]}\n  \""), "\")");
    // Block comment.
    assert_eq!(compute_js_breakout("/* unterminated ("), "*/");
}

#[test]
fn balanced_prefix_needs_no_closer() {
    assert_eq!(compute_js_breakout("var x = 1; "), "");
    assert_eq!(compute_js_breakout("foo(\"a\", bar()); "), "");
}

#[test]
fn template_literal_expression() {
    // Inside `${ foo(" }` we must close the string, the call, the ${} brace,
    // and the surrounding template literal.
    assert_eq!(compute_js_breakout("`a${foo(\""), "\")}`");
    // Plain template string (no ${}) just closes the backtick.
    assert_eq!(compute_js_breakout("`hello "), "`");
}

#[test]
fn covers_scanner_state_edges() {
    // Standalone / mismatched closers in code position are no-ops (never pop the
    // wrong opener), leaving nothing to close.
    assert_eq!(compute_js_breakout("}}])"), "");
    // `)` must not pop a `[`; both stay open.
    assert_eq!(compute_js_breakout("(["), "])");
    assert_eq!(compute_js_breakout("([)"), "])");

    // Single-quoted string: escaped quote keeps it open; a real quote closes it.
    assert_eq!(compute_js_breakout("'a\\'b'"), ""); // opened and closed
    assert_eq!(compute_js_breakout("x='a\\'"), "'"); // escaped quote -> still open

    // Template literal: escaped backtick keeps it open; a real backtick closes.
    assert_eq!(compute_js_breakout("`a\\`b`"), ""); // opened and closed

    // Block comment that terminates, then an open call after it.
    assert_eq!(compute_js_breakout("/* x */ foo("), ")");

    // Ending inside a line comment must emit a newline to escape it.
    assert_eq!(compute_js_breakout("x // foo"), "\n");
}

// ===== oxc-validated correctness =====
//
// The decisive proof, browser-free: reconstruct `prefix + breakout +
// ;alert(1)` and parse it with the same oxc parser the scanner uses. The
// breakout is correct iff the result parses cleanly AND `alert(1)` lands as a
// top-level statement (i.e. it escaped every string/structure rather than
// staying inert inside one).

/// True iff `code` parses without errors and contains a top-level `alert(...)`
/// call statement.
fn alert_reaches_top_level(code: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_ast::ast::{Expression, Statement};
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, code, SourceType::default()).parse();
    if !ret.errors.is_empty() {
        return false;
    }
    ret.program.body.iter().any(|stmt| {
        if let Statement::ExpressionStatement(es) = stmt
            && let Expression::CallExpression(call) = &es.expression
            && let Expression::Identifier(id) = &call.callee
        {
            return id.name.as_str() == "alert";
        }
        false
    })
}

/// Realistic inline-script prefixes (everything before the reflected value) and
/// the original trailing source after it. The reflected value sits inside a
/// string literal that the prefix opens.
const SCENARIOS: &[(&str, &str)] = &[
    ("var q = \"", "\";"),
    ("search(\"", "\");"),
    ("var a = [\"", "\"];"),
    ("track([\"", "\"]);"),
    ("render({title:\"", "\"});"),
    ("foo({ bar: [ \"", "\" ] });"),
    ("init([{name:\"", "\"}]);"),
    ("var s = '", "';"),
    ("g('", "');"),
];

#[test]
fn computed_breakout_reaches_executable_position() {
    for (prefix, suffix) in SCENARIOS {
        let breaker = compute_js_breakout(prefix);
        // Injected value = breaker + ";alert(1)//"; the `//` neutralises the
        // original suffix (single line), exactly as the real payload would.
        let code = format!("{}{};alert(1)//{}", prefix, breaker, suffix);
        assert!(
            alert_reaches_top_level(&code),
            "breakout {:?} failed to reach executable position for prefix {:?} -> {:?}",
            breaker,
            prefix,
            code
        );
    }
}

#[test]
fn regex_literals_are_a_known_limitation() {
    // DOCUMENTED GAP (see module header): `/` is never treated as a regex-literal
    // delimiter, so a `)` inside a regex wrongly pops a real open paren and the
    // breaker under-closes. We pin the current (wrong) output so the limitation
    // is tracked rather than silently assumed correct. This is dormant today —
    // `compute_js_breakout` is only run on the clean NESTING_SHELLS, never on
    // real prefixes. If this assertion ever fails because the behaviour was
    // fixed, delete it and add genuine regex coverage to SCENARIOS.
    let breaker = compute_js_breakout("f(/)/, \"");
    assert_eq!(
        breaker, "\"",
        "regex `)` no longer pops the real paren — limitation may be fixed; \
         the correct breaker for this prefix is \"\\\")\""
    );
}

#[test]
fn naive_breakout_fails_on_nested_scenarios() {
    // Contrast: closing only the string (no structural closers) leaves the
    // surrounding brackets unbalanced, so the reconstructed code is a JS syntax
    // error and `alert` never reaches top level. This proves the structural
    // closers are load-bearing (the result fails to parse, errs != 0).
    let nested = [
        ("foo({ bar: [ \"", "\" ] });"),
        ("track([\"", "\"]);"),
        ("render({title:\"", "\"});"),
    ];
    for (prefix, suffix) in nested {
        // Naive: just the delimiter quote, no `]`, `}`, `)`.
        let quote = prefix
            .chars()
            .rev()
            .find(|c| *c == '"' || *c == '\'')
            .unwrap();
        let code = format!("{}{};alert(1)//{}", prefix, quote, suffix);
        assert!(
            !alert_reaches_top_level(&code),
            "naive breakout unexpectedly worked for {:?} — scenario is not actually nested",
            prefix
        );
    }
}

// ===== Template generation =====

#[test]
fn breakout_templates_cover_common_nestings_and_carry_placeholder() {
    let templates = breakout_templates('"');
    assert!(templates.iter().all(|t| t.contains("{JS}")));
    // Deduped.
    let mut sorted = templates.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), templates.len());
    // Covers the bare close and the deep array-in-object-in-call close.
    assert!(templates.iter().any(|t| t == "\";{JS}//"));
    assert!(templates.iter().any(|t| t == "\"]});{JS}//"));
    // Single-quote variant uses the right delimiter.
    assert!(breakout_templates('\'').iter().all(|t| t.starts_with('\'')));
}

#[test]
fn generated_templates_execute_for_their_nesting() {
    // Each generated template, substituted with alert(1) and placed in a
    // matching nested prefix, must reach executable position.
    let cases = [
        ("\");{JS}//", "foo(\"", "\");"),
        ("\"];{JS}//", "arr=[\"", "\"];"),
        ("\"});{JS}//", "foo({k:\"", "\"});"),
        ("\"]});{JS}//", "foo({k:[\"", "\"]});"),
    ];
    let templates = breakout_templates('"');
    for (tmpl, prefix, suffix) in cases {
        assert!(
            templates.iter().any(|t| t == tmpl),
            "expected template {:?} in generated set {:?}",
            tmpl,
            templates
        );
        let payload = tmpl.replace("{JS}", "alert(1)");
        let code = format!("{}{}{}", prefix, payload, suffix);
        assert!(
            alert_reaches_top_level(&code),
            "template {:?} did not execute in {:?}",
            tmpl,
            code
        );
    }
}

// ===== Issue #1072: escaped-quote breakouts (server escapes `"` -> `\"`) =====

/// Model the mock server's `escape_quotes` filter: backslash-escape JS quotes.
fn escape_quotes(s: &str) -> String {
    s.replace('"', "\\\"").replace('\'', "\\'")
}

#[test]
fn escaped_breakout_templates_are_backslash_prefixed() {
    for q in ['"', '\''] {
        let normal = breakout_templates(q);
        let escaped = escaped_breakout_templates(q);
        assert_eq!(normal.len(), escaped.len());
        for (n, e) in normal.iter().zip(escaped.iter()) {
            assert_eq!(
                *e,
                format!("\\{n}"),
                "escaped template must be backslash-prefixed"
            );
            assert!(e.contains("{JS}"));
        }
    }
}

#[test]
fn escaped_breakout_executes_under_escaping_where_naive_fails() {
    // Reflection inside a double-quoted JS string at several nesting depths.
    // The server escapes our `"` -> `\"`. The naive quote-close is neutralised;
    // the backslash-prefixed escaped breakout converts the server's own escaping
    // into a real string break. Proven via oxc, no browser.
    let cases = [
        ("var x = \"", "\";"),
        ("search(\"", "\");"),
        ("var a = [\"", "\"];"),
        ("foo({ bar: [ \"", "\" ] });"),
        // single-quote string contexts
        ("var y = '", "';"),
        ("g('", "');"),
    ];
    for (prefix, suffix) in cases {
        let closer = compute_js_breakout(prefix);
        let naive = format!("{closer};alert(1)//");
        let escaped = format!("\\{closer};alert(1)//");

        // Naive payload, after the server escapes its quote, stays inside the
        // string -> alert does NOT reach top level.
        let naive_code = format!("{prefix}{}{suffix}", escape_quotes(&naive));
        assert!(
            !alert_reaches_top_level(&naive_code),
            "naive breakout unexpectedly executed under escaping: {naive_code:?}"
        );

        // Escaped payload, after the server escapes its quote, yields `\\\"`
        // (literal backslash + real closing quote) -> alert reaches top level.
        let esc_code = format!("{prefix}{}{suffix}", escape_quotes(&escaped));
        assert!(
            alert_reaches_top_level(&esc_code),
            "escaped breakout failed to execute under escaping: {esc_code:?}"
        );
    }
}
