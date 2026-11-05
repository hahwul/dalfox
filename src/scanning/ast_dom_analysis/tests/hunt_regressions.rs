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
        let js = format!(
            "function {name}(s){{return s}} document.getElementById('a').innerHTML = {name}(location.hash.slice(1));"
        );
        assert!(found(&js).is_empty(), "{name} is a sanitizer");
    }
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
