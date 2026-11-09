use super::*;

#[test]
fn optional_chains_preserve_sources_and_sinks() {
    for js in [
        "document.write?.(location.hash);",
        "document?.write(location.hash);",
        "document.write(window?.location.hash);",
        "document.write(location?.['hash']);",
        "document.write(location.hash?.slice(1));",
        "const x = location?.hash; document.write(x);",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(
            findings.iter().any(|v| v.source.contains("location.hash")),
            "{js}: {findings:?}"
        );
    }
    for js in [
        "document.write?.('safe');",
        "document.write(DOMPurify.sanitize?.(location.hash));",
    ] {
        assert!(
            AstDomAnalyzer::new().analyze(js).unwrap().is_empty(),
            "{js}"
        );
    }
}

#[test]
fn computed_sources_preserve_parameter_and_storage_keys() {
    for (js, source) in [
        (
            "document.write(window['location'].hash);",
            "window.location.hash",
        ),
        (
            "document.write(new URLSearchParams(location.search)['get']('query'));",
            "URLSearchParams.get(query)",
        ),
        (
            "document.write(localStorage['getItem']('preview'));",
            "localStorage.getItem(preview)",
        ),
        (
            "const state = {}; state.html = location.hash; document.write(state['html']);",
            "location.hash",
        ),
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(
            findings.iter().any(|v| v.source == source),
            "{js}: {findings:?}"
        );
    }
}

#[test]
fn nested_sink_expressions_are_visited() {
    for js in [
        "void document.write(location.hash);",
        "!function () { document.write(location.hash); }();",
        "const a = [document.write(location.hash)];",
        "const a = {value: document.write(location.hash)};",
        "const a = {[document.write(location.hash)]: 1};",
        "new Object(document.write(location.hash));",
        "new Object(...[document.write(location.hash)]);",
        "const a = [...[document.write(location.hash)]];",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(
            findings.iter().any(|v| v.source == "location.hash"),
            "{js}: {findings:?}"
        );
    }
}

#[test]
fn function_literals_in_containers_are_analyzed() {
    // A function literal is analyzed wherever it is written. Reaching one
    // through an array, an object literal, an options-object property, a
    // constructor argument, or a unary operand does not make the source it
    // reads any less real — and these container shapes are how every
    // jQuery/axios-style API takes its callbacks.
    for js in [
        "const f = [() => document.write(location.hash)];",
        "const f = {run() { document.write(location.hash); }};",
        "void (() => document.write(location.hash));",
        "new Object(function () { document.write(location.hash); });",
        "$.ajax({success: function (d) { document.write(location.hash); }});",
        "new Promise(function (resolve) { document.write(location.hash); });",
        "grid.render({rows: [], onDraw: () => document.write(location.hash)});",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert_eq!(findings.len(), 1, "{js}: {findings:?}");
        assert_eq!(findings[0].source, "location.hash", "{js}");
    }
}

#[test]
fn function_parameters_shadow_the_enclosing_scope() {
    // The body can only ever see the argument it was called with, so an outer
    // binding of the same name is not a flow. The parameter's own flow is
    // reported at the call site from the function's summary instead, which is
    // also why walking the body here cannot double-report it.
    for js in [
        "const x = location.hash; const f = function (x) { document.write(x); }; f('safe');",
        "const x = location.hash; const f = {run(x) { document.write(x); }}; f.run('safe');",
        "const x = location.hash; const f = function ({x}) { document.write(x); }; f({});",
        "const x = location.hash; const f = function (...x) { document.write(x); }; f('safe');",
        "const x = location.hash; function f(x) { document.write(x); } f('safe');",
        "const d = location.hash; setTimeout(function (d) { document.write(d); }, 0);",
        "const d = location.hash; $.ajax({success: function (d) { document.write(d); }});",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(findings.is_empty(), "{js}: {findings:?}");
    }
}

#[test]
fn free_variables_in_parameterized_functions_still_flow() {
    // The summary registered for a declaration only carries parameter flows,
    // so a source the body reads on its own has to come from the body walk.
    // Both may fire for the same function without duplicating each other.
    let findings = AstDomAnalyzer::new()
        .analyze("function render(el) { el.innerHTML = location.hash; } render(document.body);")
        .unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].source, "location.hash");

    let findings = AstDomAnalyzer::new()
        .analyze("function show(v) { document.write(v); } show(location.hash);")
        .unwrap();
    assert_eq!(
        findings.len(),
        1,
        "parameter flow must not double-report: {findings:?}"
    );
}

#[test]
fn function_bodies_leak_outer_writes_but_not_their_own_locals() {
    // A write to a binding the body does not own outlives the call.
    for js in [
        "const f = function () { g = location.hash; }; f(); document.write(g);",
        "function f() { g = location.hash; } f(); document.write(g);",
        "setTimeout(function () { g = location.hash; }, 0); document.write(g);",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert_eq!(findings.len(), 1, "{js}: {findings:?}");
        assert_eq!(findings[0].source, "location.hash", "{js}");
    }
    // A local of the same name is a different variable, in every statement
    // form that can hold a declaration. Each entry exercises one arm of the
    // declared-name scan; an arm that stops matching lets that local escape
    // as a global and taints an unrelated outer `q`.
    for js in [
        "const f = function () { var q = location.hash; }; f(); document.write(q);",
        "const f = function () { { var q = location.hash; } }; f(); document.write(q);",
        "const f = function () { if (0) 1; else { var q = location.hash; } }; document.write(q);",
        "const f = function () { for (var q = location.hash;;) break; }; f(); document.write(q);",
        "const f = function () { for (var q in o) { q = location.hash; } }; document.write(q);",
        "const f = function () { for (var q of o) { q = location.hash; } }; document.write(q);",
        "const f = function () { while (0) { var q = location.hash; } }; document.write(q);",
        "const f = function () { do { var q = location.hash; } while (0); }; document.write(q);",
        "const f = function () { loop: { var q = location.hash; } }; document.write(q);",
        "const f = function () { switch (1) { case 1: var q = location.hash; } }; document.write(q);",
        "const f = function () { try { let q = location.hash; } catch (q) {} }; document.write(q);",
        "const f = function () { try { 1; } finally { var q = location.hash; } }; document.write(q);",
        "const f = function () { function q() {} q = location.hash; }; document.write(q);",
        "const f = function () { class q {} q = location.hash; }; document.write(q);",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(findings.is_empty(), "{js}: {findings:?}");
    }
    // Shadowing a parameter must not erase the outer binding's own taint —
    // including a name the enclosing scope tainted by destructuring, which is
    // tracked as a global rather than a plain local.
    for js in [
        "const x = location.hash; const f = function (x) { return x; }; document.write(x);",
        "const {x} = location; const f = function (x) { return x; }; document.write(x + location.hash);",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert_eq!(findings.len(), 1, "{js}: {findings:?}");
    }
}

#[test]
fn parameter_shadowing_covers_every_binding_form() {
    // Destructuring defaults, nested patterns, and rest elements all bind
    // names the body sees instead of the enclosing scope's.
    for js in [
        "const x = location.hash; const f = function (x = 1) { document.write(x); }; f();",
        "const x = location.hash; const f = function ({x = 1}) { document.write(x); }; f({});",
        "const x = location.hash; const f = function ({a: {x}}) { document.write(x); }; f({a: {}});",
        "const x = location.hash; const f = function ({...x}) { document.write(x); }; f({});",
        "const x = location.hash; const f = function ([, x]) { document.write(x); }; f([]);",
        "const x = location.hash; const f = function ([...x]) { document.write(x); }; f([]);",
        // A name the enclosing scope tainted by destructuring is tracked as a
        // global, which the parameter has to shadow the same way.
        "const {x} = location.hash; const f = function (x) { document.write(x); }; f('safe');",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(findings.is_empty(), "{js}: {findings:?}");
    }
    // …and the outer binding keeps its taint once the function is behind us.
    let findings = AstDomAnalyzer::new()
        .analyze("const {x} = location.hash; const f = function (x) {}; document.write(x);")
        .unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn callbacks_and_chains_are_reached_through_wrappers() {
    // A parenthesized callback argument and a spread-in options object are
    // still callbacks; an optional computed member is still a member walk.
    for js in [
        "setTimeout((function () { document.write(location.hash); }), 0);",
        "render({...base, draw: function () { document.write(location.hash); }});",
        "const o = {...{run: () => document.write(location.hash)}};",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert_eq!(findings.len(), 1, "{js}: {findings:?}");
    }
    // The chain's own operands are walked, so a sink evaluated to build the
    // key or the receiver is not lost.
    for js in [
        "cache?.[document.write(location.hash)];",
        "document.write(location.hash)?.trim();",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(
            findings.iter().any(|v| v.source == "location.hash"),
            "{js}: {findings:?}"
        );
    }
}

#[test]
fn numeric_and_boolean_binary_results_do_not_carry_executable_input() {
    for value in [
        "location.hash === '#yes'",
        "location.hash != ''",
        "location.hash < 'z'",
        "location.hash - 1",
        "location.hash * 2",
        "location.hash | 0",
    ] {
        let js = format!("document.write({value});");
        assert!(
            AstDomAnalyzer::new().analyze(&js).unwrap().is_empty(),
            "{js}"
        );
    }
    for value in [
        "'prefix' + location.hash",
        "location.hash || ''",
        "location.hash ?? ''",
    ] {
        let js = format!("document.write({value});");
        assert!(
            !AstDomAnalyzer::new().analyze(&js).unwrap().is_empty(),
            "{js}"
        );
    }
    // Coercing the result never makes a sink evaluated inside the operand safe.
    assert!(
        !AstDomAnalyzer::new()
            .analyze("document.write(location.hash) === 0;")
            .unwrap()
            .is_empty()
    );
}

/// #1663: built-ins that return a number or a boolean cannot carry markup,
/// and a lookup whose only tainted part is the key returns the container's
/// value, not the key.
#[test]
fn number_and_boolean_builtins_do_not_propagate_taint() {
    for js in [
        "el.innerHTML = location.search.indexOf('x');",
        "el.innerHTML = location.search.includes('a');",
        "el.innerHTML = location.pathname.startsWith('/a');",
        "el.innerHTML = /admin/.test(location.hash);",
        "el.innerHTML = new RegExp('a').test(location.hash);",
        "const re = new RegExp('a'); el.innerHTML = re.test(location.hash);",
        "var tabs = ['a', 'b']; el.innerHTML = tabs.indexOf(location.hash.slice(1));",
        "el.innerHTML = new Set(['a']).has(location.hash);",
        "el.innerHTML = new Map([['a', '<b>A</b>']]).get(location.hash.slice(1));",
        "const m = new Map([['a', '<b>A</b>']]); el.innerHTML = m.get(location.hash.slice(1));",
        "el.innerHTML = location.hash.localeCompare('a') + location.hash.search('x');",
        "el.innerHTML = location.hash.split(',').some(function (x) { return x; });",
        "var re = /admin/; el.innerHTML = re.test(location.hash);",
        "var re; re = /admin/; el.innerHTML = re.test(location.hash);",
        "el.innerHTML = new URLSearchParams(location.search).has('a');",
        // ordinary code that only looks like a definition
        "const search = new URLSearchParams(location.search); el.innerHTML = location.hash.search('x');",
        "fetch(u, { method: 'get' }); const m = new Map(); el.innerHTML = m.get(location.hash);",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(findings.is_empty(), "{js}: {findings:?}");
    }
}

#[test]
fn number_and_boolean_builtins_keep_real_flows() {
    for js in [
        "el.innerHTML = location.hash.slice(1);",
        // the map's *values* are tainted
        "const m = new Map(); m.set('k', location.hash); el.innerHTML = m.get('k');",
        "const m = new Map([['k', location.hash]]); el.innerHTML = m.get('k');",
        // a page-local method of the same name is followed, not assumed built-in
        "var o = { has: function (x) { return x; } }; el.innerHTML = o.has(location.hash);",
        // …even when the receiver's class is unknown at the call
        "class W { has(x) { return x; } } var w = make(); el.innerHTML = w.has(location.hash);",
        // `test` on something that is not a regex
        "el.innerHTML = lib.test(location.hash);",
        // `get` on an unknown object (could fetch an attacker URL)
        "el.innerHTML = cache.get(location.hash);",
        // methods attached by assignment, or defined after the use
        "function W() {} W.prototype.search = function (q) { return '<b>' + q + '</b>'; }; var w = new W(); el.innerHTML = w.search(location.hash);",
        "var o; o = { has: function (x) { return x; } }; el.innerHTML = o.has(location.hash);",
        "function render() { el.innerHTML = widget.has(location.hash); } var widget = { has: function (x) { return x; } }; render();",
        "o['includes'] = function (x) { return x; }; el.innerHTML = o.includes(location.hash);",
        "class T { includes = (x) => x; } var t = make(); el.innerHTML = t.includes(location.hash);",
        "class T { includes(x) { return x; } } var t = make(); el.innerHTML = t.includes(location.hash);",
        // `search` / `has` on a receiver not known to be the built-in
        "el.innerHTML = searchLib.search(location.hash);",
        "el.innerHTML = lib.has(location.hash);",
        // a parameter shadows the outer Map
        "const m = new Map(); function f(m) { el.innerHTML = m.get(location.hash); } f(remoteCache);",
        // a hoisted reader walked before the write that taints the map
        "const m = new Map(); function show() { el.innerHTML = m.get(location.hash.slice(1)); } m.set('a', location.search); show();",
        // char codes rebuilt into a string
        "var h = location.hash, s = ''; for (var i = 1; i < h.length; i++) { s += String.fromCharCode(h.charCodeAt(i)); } el.innerHTML = s;",
        "el.innerHTML = String.fromCharCode(location.hash.charCodeAt(1));",
    ] {
        let findings = AstDomAnalyzer::new().analyze(js).unwrap();
        assert!(!findings.is_empty(), "{js}");
    }
}

/// An inert call contributes no source, so the label names the operand that
/// actually carries the taint.
#[test]
fn inert_builtin_does_not_label_the_source() {
    let js = "el.innerHTML = location.hash.includes('x') + location.search;";
    let findings = AstDomAnalyzer::new().analyze(js).unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].source, "location.search", "{findings:?}");
}
