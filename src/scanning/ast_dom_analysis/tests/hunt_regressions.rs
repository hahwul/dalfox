use super::*;

fn found(js: &str) -> Vec<DomXssVulnerability> {
    AstDomAnalyzer::new().analyze(js).expect("parses")
}

/// The page-wide id set / markup are shared, not deep-cloned, per analyzer —
/// a page with N `<script id>` blocks otherwise did O(N²) string clones.
#[test]
fn analyzer_shares_page_context_instead_of_cloning() {
    let ids: Arc<HashSet<String>> = Arc::new(["a".to_string()].into_iter().collect());
    let markup = Arc::new(PageMarkup::default());
    let analyzer = AstDomAnalyzer::new()
        .with_script_element_ids(Arc::clone(&ids))
        .with_reflected_markup(Arc::clone(&markup));
    assert!(Arc::ptr_eq(&analyzer.script_element_ids, &ids));
    assert!(Arc::ptr_eq(&analyzer.reflected_markup, &markup));
}

#[test]
fn function_local_redeclaration_clears_inherited_taint() {
    for js in [
        r#"var q = location.hash.slice(1); function f(){ var q = "static"; document.getElementById("a").innerHTML = q; } f();"#,
        r#"var q = location.hash.slice(1); function f(){ let q = "static"; document.getElementById("a").innerHTML = q; } f();"#,
        r#"var q = location.hash.slice(1); var g = function(){ var q = "static"; document.getElementById("a").innerHTML = q; }; g();"#,
        // Hoisted: the local `q` is already undefined at the earlier read.
        r#"var q = location.hash.slice(1); function f(){ document.getElementById("a").innerHTML = q; var q = "static"; } f();"#,
    ] {
        assert!(found(js).is_empty(), "{js}");
    }
}

#[test]
fn function_redeclaration_keeps_real_flows() {
    for js in [
        // No local `q`: the outer taint is what the body reads.
        r#"var q = location.hash.slice(1); function f(){ document.getElementById("a").innerHTML = q; } f();"#,
        // The local is itself tainted.
        r#"function f(){ var q = location.hash.slice(1); document.getElementById("a").innerHTML = q; } f();"#,
        // A `let` in a nested block does not hide the outer binding outside it.
        r#"var q = location.hash.slice(1); function f(c){ if (c) { let q = "x"; } document.getElementById("a").innerHTML = q; } f(1);"#,
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
}

#[test]
fn bare_identifier_named_like_a_sink_property_is_not_a_sink() {
    for name in ["href", "src", "innerHTML", "srcdoc"] {
        let js = format!("var {name}; {name} = location.hash.slice(1); console.log({name});");
        assert!(found(&js).is_empty(), "{js}");
    }
    // The taint is still recorded, so a real sink fed by it reports.
    let real = found("var href; href = location.hash.slice(1); a.href = href;");
    assert!(real.iter().any(|v| v.sink == "href"), "{real:?}");
}

#[test]
fn sloppy_mode_scripts_are_still_analyzed() {
    for js in [
        "<!-- hide\ndocument.getElementById('a').innerHTML = location.hash.slice(1);\n//-->",
        "var await = location.hash.slice(1); document.getElementById('a').innerHTML = await;",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
    // Module-only syntax keeps working.
    let module = found(
        "import x from './x.js'; document.getElementById('a').innerHTML = location.hash.slice(1); export {x};",
    );
    assert!(!module.is_empty(), "{module:?}");
    // Genuinely broken source is still an error.
    assert!(AstDomAnalyzer::new().analyze("var = ;").is_err());
}

#[test]
fn inverse_of_a_sanitizer_does_not_clear_taint() {
    for name in [
        "unescapeHtml",
        "unescapeHTML",
        "unsanitizeHtml",
        "unencodeHtml",
        "deescapeHtml",
    ] {
        let js = format!(
            "function {name}(s){{return s.replace(/&amp;/g,'&')}} document.getElementById('a').innerHTML = {name}(location.hash.slice(1));"
        );
        assert!(!found(&js).is_empty(), "{name} must not sanitize");
    }
    for name in [
        "sanitizeHtml",
        "escapeHtml",
        "htmlEscape",
        "encodeHtml",
        "xssSanitize",
    ] {
        // Not defined on the page (a library function): the name is all
        // there is to go on.
        let js =
            format!("document.getElementById('a').innerHTML = {name}(location.hash.slice(1));");
        assert!(found(&js).is_empty(), "{name} is a sanitizer");
    }
}

/// A function the page defines under a sanitizer's name and that hands its
/// parameter straight back is a stub: the name is not evidence.
#[test]
fn a_sanitizer_name_on_a_body_that_returns_its_parameter_is_not_believed() {
    let sink = "document.getElementById('a').innerHTML";
    let src = "location.hash.slice(1)";
    for name in ["escapeHtml", "sanitizeHtml", "encodeHtml", "xssSanitize"] {
        for body in [
            "return s",
            "return (s)",
            "return s.trim()",
            "return String(s).trim()",
            "return s + ''",
            "return s || ''",
            "return s ? s.toString() : ''",
            "console.log(s); return s",
            // Words and characters that say nothing about what it does.
            "return /* encode */ s",
            "var encoded = 0; return s",
            "if (s.length < 5) return s; return s",
        ] {
            for definition in [
                format!("function {name}(s){{{body}}}"),
                format!("var {name} = function(s){{{body}}};"),
                format!("const {name} = (s) => {{{body}}};"),
            ] {
                let js = format!("{definition} {sink} = {name}({src});");
                assert!(!found(&js).is_empty(), "{js}");
            }
        }
    }
    // A concise arrow body.
    let js = format!("const escapeHtml = s => s; {sink} = escapeHtml({src});");
    assert!(!found(&js).is_empty(), "{js}");
    // Reached through `window.`.
    let js = format!("function escapeHtml(s){{return s}} {sink} = window.escapeHtml({src});");
    assert!(!found(&js).is_empty(), "{js}");
    // As a tagged template and inside a Trusted Types policy.
    let js = format!("function escapeHtml(s, v){{return v}} {sink} = escapeHtml`${{{src}}}`;");
    assert!(!found(&js).is_empty(), "{js}");
    let js = format!(
        "function escapeHtml(s){{return s}} \
         var p = trustedTypes.createPolicy('p', {{ createHTML: s => escapeHtml(s) }}); \
         {sink} = p.createHTML({src});"
    );
    assert!(!found(&js).is_empty(), "{js}");
    // Declared after the function that calls it.
    let js = format!(
        "function show(s){{ {sink} = escapeHtml(s) }} function escapeHtml(s){{return s}} show({src});"
    );
    assert!(!found(&js).is_empty(), "{js}");
}

/// Anything short of "returns its parameter unchanged" keeps the name's
/// benefit of the doubt. Each of these was a new false report when the test
/// was "the body shows no sign of escaping".
#[test]
fn a_page_defined_sanitizer_is_believed_unless_it_is_plainly_a_stub() {
    let sink = "document.getElementById('a').innerHTML";
    let src = "location.hash.slice(1)";
    for body in [
        r#"return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')"#,
        r#"return String(s).replace(/[&<>"']/g, function(c){ return MAP[c]; })"#,
        r#"var d = document.createElement('div'); d.textContent = s; return d.innerHTML"#,
        r#"var d = document.createElement('div'); d.appendChild(document.createTextNode(s)); return d.innerHTML"#,
        "return DOMPurify.sanitize(s)",
        "return _.escape(s)",
        // No textual sign of escaping, and still not a stub.
        "return 'safe'",
        "return Number(s)",
        "return parseInt(s, 10)",
        "return +s",
        "return new Option(s).innerHTML",
        "var d = document.createElement('textarea'); d.value = s; return d.innerHTML",
        "return clean(s)",
        "return s.replaceAll(new RegExp(pat, 'g'), c => map[c])",
        r#"return s.replace(/"/g, String.fromCharCode(38,113,117,111,116,59))"#,
        // The parameter is rewritten before it is returned.
        "s = s.replace(/</g, '&lt;'); return s",
        "s = clean(s); return s",
        // Not every path returns it.
        "if (!s) return; return s",
    ] {
        let js = format!("function escapeHtml(s){{{body}}} {sink} = escapeHtml({src});");
        assert!(found(&js).is_empty(), "{js}");
    }
}

/// Every kind of statement a `return` can sit in is followed, and every way
/// of rewriting the parameter is seen.
#[test]
fn stub_detection_follows_control_flow_and_assignments() {
    let sink = "document.getElementById('a').innerHTML";
    let src = "location.hash.slice(1)";
    // Still a stub: each path returns the parameter as it came in.
    for body in [
        "try { return s } catch (e) { return s } finally { log() }",
        "switch (mode) { case 1: return s; default: return s.trim() }",
        "for (;;) { return s }",
        "for (var k in o) { return s } return s",
        "for (var v of o) { return s } return s",
        "while (true) { return s }",
        "do { return s } while (false)",
        "out: { return s }",
        "{ return `${1}` ? s : '' }",
    ] {
        let js = format!("function escapeHtml(s){{{body}}} {sink} = escapeHtml({src});");
        assert!(!found(&js).is_empty(), "{js}");
    }
    // Not a stub: the parameter is rewritten somewhere, or a path returns
    // something else.
    for body in [
        "s += ''; return s",
        "s++; return s",
        "++s; return s",
        "--s; return s",
        "s ||= ''; return s",
        "s ??= ''; return s",
        "s <<= 1; return s",
        "try { return s } catch (e) { return clean(s) }",
        "switch (mode) { case 1: return s; default: return clean(s) }",
        "while (true) { return clean(s) }",
        "return s.concat(other)",
        "return other",
        "return s && clean(s)",
        "return mode ? clean(s) : s",
        "log(s)",
    ] {
        let js = format!("function escapeHtml(s){{{body}}} {sink} = escapeHtml({src});");
        assert!(found(&js).is_empty(), "{js}");
    }
    // A parameter the check cannot name is not evidence either.
    for params in ["{s}", "[s]", "...s", "s = ''"] {
        let js = format!("function escapeHtml({params}){{return s}} {sink} = escapeHtml({src});");
        assert!(found(&js).is_empty(), "{js}");
    }
    // A comparison or an arrow is not an assignment.
    for body in [
        "if (s == null) return s; return s",
        "var f = s => 1; return s",
    ] {
        let js = format!("function escapeHtml(s){{{body}}} {sink} = escapeHtml({src});");
        assert!(!found(&js).is_empty(), "{js}");
    }
}

/// Past the cap no further definition is remembered, so its name is believed.
#[test]
fn sanitizer_definitions_are_remembered_up_to_a_cap() {
    let sink = "document.getElementById('a').innerHTML";
    let mut js = String::new();
    for i in 0..1100 {
        js.push_str(&format!("function escapeHtml{i}(s){{return s}}\n"));
    }
    let early = format!("{js}{sink} = escapeHtml0(location.hash.slice(1));");
    assert!(!found(&early).is_empty());
    let late = format!("{js}{sink} = escapeHtml1099(location.hash.slice(1));");
    assert!(found(&late).is_empty());
}

/// The analyzer does not tell same-named functions in different scopes apart,
/// so a stub only discredits the name when every definition is one.
#[test]
fn a_stub_does_not_discredit_an_escaping_function_of_the_same_name() {
    let sink = "document.getElementById('a').innerHTML";
    let escaping = "function escapeHtml(s){return s.replace(/</g,'&lt;')}";
    let call = format!("{sink} = escapeHtml(location.hash.slice(1));");
    let js = format!(
        "{escaping} function unused(){{ function escapeHtml(s){{return s.trim()}} return escapeHtml('ok') }} {call}"
    );
    assert!(found(&js).is_empty(), "{js}");
    let js = format!(
        "function escapeHtml(s){{return s}} function escapeHtml(s){{return s.trim()}} {call}"
    );
    assert!(!found(&js).is_empty(), "{js}");
}

#[test]
fn a_method_named_like_a_sanitizer_is_judged_by_its_body_too() {
    let sink = "document.getElementById('a').innerHTML";
    let src = "location.hash.slice(1)";
    for (definition, callee) in [
        (
            "var Utils = { escapeHtml: function(s){ return s } };",
            "Utils.escapeHtml",
        ),
        (
            "var Utils = { escapeHtml(s){ return s } };",
            "Utils.escapeHtml",
        ),
        (
            "class Utils { static escapeHtml(s){ return s } }",
            "Utils.escapeHtml",
        ),
        // An instance's method is summarised under its class.
        (
            "class Utils { escapeHtml(s){ return s } } var u = new Utils();",
            "u.escapeHtml",
        ),
    ] {
        let js = format!("{definition} {sink} = {callee}({src});");
        assert!(!found(&js).is_empty(), "{js}");
    }
    let js = format!(
        "var Utils = {{ escapeHtml(s){{ return s.replace(/</g, '&lt;') }} }}; \
         {sink} = Utils.escapeHtml({src});"
    );
    assert!(found(&js).is_empty(), "{js}");
    // Known limits: a method assigned after the object was created and a
    // webpack export alias get no summary under the sanitizer's name, so
    // there is no body to judge and the name is still believed.
    let js = format!(
        "var Utils = {{}}; Utils.escapeHtml = function(s){{ return s }}; \
         {sink} = Utils.escapeHtml({src});"
    );
    assert!(found(&js).is_empty(), "{js}");
}

#[test]
fn set_attribute_src_and_formaction_are_sinks() {
    for js in [
        "var f=document.createElement('iframe'); f.setAttribute('src', location.hash.slice(1));",
        "var b=document.createElement('button'); b.setAttribute('formAction', location.hash.slice(1));",
        "var f=document.createElement('iframe'); f.setAttributeNS(null, 'src', location.hash.slice(1));",
        "var f=document.createElement('iframe'); Reflect.apply(f.setAttribute, f, ['src', location.hash.slice(1)]);",
        "var f=document.createElement('form'); f.setAttribute('action', location.hash.slice(1));",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
    for js in [
        "var f=document.createElement('div'); f.setAttribute('class', location.hash.slice(1));",
        "var f=document.createElement('div'); f.setAttribute('data-id', location.hash.slice(1));",
        // `action` by name alone is not a sink (redux-style objects).
        "store.setAttribute('action', location.hash.slice(1));",
        "var o=document.createElement('object'); o.setAttribute('data', location.hash.slice(1));",
    ] {
        assert!(found(js).is_empty(), "{js}");
    }
}

#[test]
fn length_of_a_location_string_is_not_tainted() {
    for js in [
        "document.getElementById('a').innerHTML = 'n=' + location.hash.length;",
        "document.getElementById('a').innerHTML = 'n=' + window.location.search.length;",
        "document.getElementById('a').innerHTML = 'n=' + document.referrer.length;",
    ] {
        assert!(found(js).is_empty(), "{js}");
    }
    for js in [
        "document.getElementById('a').innerHTML = 'n=' + location.hash;",
        // Object-typed taint: `length` is an attacker field here.
        "var o = JSON.parse(location.hash.slice(1)); document.getElementById('a').innerHTML = o.length;",
        "document.getElementById('a').innerHTML = location.hash.slice(1).length + location.hash;",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
}

fn sinks(js: &str) -> Vec<String> {
    found(js).into_iter().map(|v| v.sink).collect()
}

/// `export` wraps an ordinary declaration; module scripts were never walked.
#[test]
fn exported_declarations_are_walked() {
    for js in [
        "export function render(){ out.innerHTML = location.hash.slice(1); }",
        "export default function(){ out.innerHTML = location.hash.slice(1); }",
        "export const r = () => { out.innerHTML = location.hash.slice(1); };",
        "export class A { r(){ out.innerHTML = location.hash.slice(1); } }",
        "export const q = location.hash.slice(1); out.innerHTML = q;",
        // The summary pre-pass sees exported helpers too.
        "export function getP(n){ return new URLSearchParams(location.search).get(n); } out.innerHTML = getP('q');",
        "export function show(h){ out.innerHTML = h; } show(location.hash.slice(1));",
    ] {
        assert_eq!(sinks(js), ["innerHTML"], "{js}");
    }
    assert!(
        found("export function show(h){ out.textContent = h; } show(location.hash);").is_empty()
    );
}

#[test]
fn jquery_only_methods_are_sinks_on_a_jquery_chain() {
    for (js, sink) in [
        (
            "$('#a').replaceWith(location.hash.slice(1));",
            "replaceWith",
        ),
        ("$('#a').wrap(location.hash.slice(1));", "wrap"),
        (
            "$('#a').find('b').wrapInner(location.hash.slice(1));",
            "wrapInner",
        ),
        ("$('a').attr('href', location.hash.slice(1));", "attr:href"),
        ("$('a').prop('href', location.hash.slice(1));", "prop:href"),
        (
            "$('b').attr('onclick', location.hash.slice(1));",
            "attr:onclick",
        ),
        ("$.globalEval(location.hash.slice(1));", "$.globalEval"),
        (
            "jQuery.getScript(new URLSearchParams(location.search).get('cb'));",
            "jQuery.getScript",
        ),
    ] {
        assert_eq!(sinks(js), [sink], "{js}");
    }
    for js in [
        // Native `replaceWith` inserts text.
        "document.getElementById('o').replaceWith(location.hash.slice(1));",
        "$('#a').attr('title', location.hash.slice(1));",
        "$('#a').attr('href', '/search?q=' + location.hash.slice(1));",
        "$('#a').prop('checked', location.hash.slice(1));",
    ] {
        assert!(found(js).is_empty(), "{js}");
    }
}

#[test]
fn popup_and_frame_documents_write_html() {
    for js in [
        "var w = window.open('', '_blank'); w.document.write(location.hash.slice(1));",
        "document.getElementById('f').contentDocument.writeln(location.hash.slice(1));",
    ] {
        assert!(sinks(js)[0].starts_with("document.write"), "{js}");
    }
    assert!(found("w.document.write('<p>hi</p>');").is_empty());
    assert!(found("logger.write(location.hash);").is_empty());
}

#[test]
fn react_dangerously_set_inner_html_is_a_sink() {
    for js in [
        "React.createElement('div', { dangerouslySetInnerHTML: { __html: new URLSearchParams(location.search).get('m') } });",
        "function App(){ const m = location.hash.slice(1); return _jsx('div', { dangerouslySetInnerHTML: { __html: m } }); }",
        // A props object built before the call.
        "const props = { dangerouslySetInnerHTML: { __html: location.hash } };",
    ] {
        assert_eq!(sinks(js), ["dangerouslySetInnerHTML"], "{js}");
    }
    assert!(
        found("_jsx('div', { dangerouslySetInnerHTML: { __html: '<b>static</b>' } });").is_empty()
    );
    assert!(found("_jsx('div', { title: location.hash, children: location.hash });").is_empty());
}

#[test]
fn clean_var_redeclaration_clears_taint() {
    assert!(found("var q = location.hash; var q = 'static'; out.innerHTML = q;").is_empty());
    for js in [
        // Self-referencing redeclaration keeps the taint.
        "var q = location.hash; var q = q + '!'; out.innerHTML = q;",
        // A conditional redeclaration does not clear the other path.
        "var q = location.hash; if (x) { var q = 'static'; } out.innerHTML = q;",
        // A block-scoped `let` only shadows inside its block.
        "var q = location.hash; { let q = 'static'; } out.innerHTML = q;",
    ] {
        assert_eq!(sinks(js), ["innerHTML"], "{js}");
    }
}

/// A same-origin or CDN prefix does not make a script URL safe: the tail can
/// still reach a JSONP callback, `../` an upload, or pick a CDN package.
#[test]
fn script_url_sinks_are_not_host_pinned() {
    let load = |url: &str| {
        format!(
            "var s = document.createElement('script'); s.src = {url}; document.head.appendChild(s);"
        )
    };
    for url in [
        "'/api/jsonp?callback=' + location.hash.slice(1)",
        "'/js/' + location.hash.slice(1) + '.js'",
        "'https://cdn.jsdelivr.net/npm/' + location.hash.slice(1)",
        "'https:' + location.hash.slice(1)",
    ] {
        assert_eq!(sinks(&load(url)), ["src"], "{url}");
    }
    assert_eq!(
        sinks("$.getScript('/js/' + location.hash.slice(1));"),
        ["$.getScript"]
    );
    assert_eq!(
        sinks("$('#b').attr('onclick', 'go(' + location.hash.slice(1) + ')');"),
        ["attr:onclick"]
    );
    assert!(found("$('#avatar').attr('src', location.hash.slice(1));").is_empty());
}

#[test]
fn jquery_prop_follows_property_semantics() {
    assert_eq!(
        sinks("$('#o').prop('innerHTML', location.hash.slice(1));"),
        ["prop:innerHTML"]
    );
    // An `on*` property ignores a string; attribute casing does not apply.
    for js in [
        "$('#b').prop('onclick', location.hash.slice(1));",
        "$('#o').prop('INNERHTML', location.hash.slice(1));",
    ] {
        assert!(found(js).is_empty(), "{js}");
    }
}
