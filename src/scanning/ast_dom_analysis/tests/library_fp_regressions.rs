//! False positives on ordinary library code (jQuery, DataTables, Vue,
//! underscore, …). Each fixture is a minimal hand-written reduction of the
//! shape that fired, not vendored library source.

use super::*;

fn found(js: &str) -> Vec<DomXssVulnerability> {
    AstDomAnalyzer::new().analyze(js).expect("parses")
}

/// A function summary walks the body once per parameter *assuming* it is
/// tainted. What that hypothetical walk writes to a field or a global must not
/// survive into the real walk — jQuery's `jQuery.ready` (written by a helper
/// that takes it as a parameter) then read as `setTimeout(jQuery.ready)`.
#[test]
fn summary_walk_does_not_leak_hypothetical_taint() {
    for js in [
        // field write from a parameter
        "var x = {}; function init(e) { x.ready = e; } setTimeout(x.ready);",
        // global write from a closure over a parameter
        "var g; function wrap(e) { return function () { g = e; }; } document.body.innerHTML = g;",
        // destructuring a parameter
        "function opts(o) { const { label } = o; return 1; } document.body.innerHTML = label;",
    ] {
        assert!(found(js).is_empty(), "{js}: {:?}", found(js));
    }
}

/// The same shapes with a real source still report.
#[test]
fn summary_walk_keeps_real_field_and_global_flows() {
    for js in [
        "var x = {}; function init(e) { x.ready = e; } init(location.hash); setTimeout(x.ready);",
        "var x = {}; function init() { x.ready = location.hash; } init(); setTimeout(x.ready);",
        "var g; function wrap() { return function () { g = location.hash; }; } document.body.innerHTML = g;",
        "function opts() { const { label } = JSON.parse(location.hash.slice(1)); document.body.innerHTML = label; }",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
}

/// A destructured binding is local to its function. Minified bundles (Vue)
/// reuse one-letter names in every function, so a destructured `l` escaping
/// into the global set tainted every unrelated `l` after it.
#[test]
fn destructured_local_does_not_escape_its_function() {
    for js in [
        "function outer() { let l = function () {}; function a() { const { l } = JSON.parse(location.hash.slice(1)); return 1; } setTimeout(l, 0); }",
        "function outer() { let l = function () {}; function a() { const [l] = location.hash.slice(1).split(','); return 1; } setTimeout(l, 0); }",
    ] {
        assert!(found(js).is_empty(), "{js}: {:?}", found(js));
    }
}

#[test]
fn destructured_binding_keeps_real_flows() {
    for js in [
        "const { l } = JSON.parse(location.hash.slice(1)); setTimeout(l, 0);",
        "function a() { const [l] = location.hash.slice(1).split(','); setTimeout(l, 0); }",
        "function a() { const { l } = JSON.parse(location.hash.slice(1)); [1].forEach(function () { document.body.innerHTML = l; }); }",
        "const { l } = JSON.parse(location.hash.slice(1)); function b() { document.body.innerHTML = l; }",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
}

/// A navigation sink only runs script when the tainted text supplies the
/// scheme. Reloads, path rewrites and share links lead with the page's own
/// URL or a literal that already fixes the scheme.
#[test]
fn navigation_with_pinned_scheme_is_not_a_finding() {
    for js in [
        "window.location.href = window.location.href;",
        "window.location.href = window.location.origin + window.location.pathname;",
        "location.href = location.pathname + '?page=2';",
        "location.replace(location.href.split('#')[0]);",
        "document.getElementById('a').href = location.pathname + '#top';",
        "var a = document.createElement('a'); a.href = location.protocol + '//' + location.host + location.pathname;",
        "document.getElementById('x').setAttribute('href', '/search' + location.search);",
        "window.open('https://www.facebook.com/sharer.php?u=' + location.href, '_blank');",
        "location.assign(`/login?next=${location.pathname}`);",
        "location.href = ' \\t/x?' + location.hash;",
    ] {
        assert!(found(js).is_empty(), "{js}: {:?}", found(js));
    }
}

#[test]
fn navigation_with_tainted_scheme_still_reports() {
    for js in [
        "location.href = location.hash.slice(1);",
        "location.href = decodeURIComponent(location.hash.substring(1));",
        "location.href = new URLSearchParams(location.search).get('next');",
        "location.href = location.pathname.substring(1);",
        "location.href = 'java' + location.hash.slice(1);",
        "location.href = 'javascript:' + location.hash.slice(1);",
        "location.href = 'JavaScript:' + location.hash;",
        "location.href = 'java\\tscript:' + location.hash;",
        "location.href = 'data:text/html,' + location.hash;",
        "location.href = '' + location.hash.slice(1);",
        "location.href = `${location.hash.slice(1)}/x`;",
        "document.getElementById('x').setAttribute('href', location.hash.slice(1));",
        "window.open(location.hash.slice(1));",
        // `src` is not pinned by a scheme: the host still matters.
        "var s = document.createElement('script'); s.src = '/' + location.hash.slice(1);",
    ] {
        assert!(!found(js).is_empty(), "{js}");
    }
}

/// When several tainted arguments of one call reach different sinks (htmx's
/// `swap(elt, content, spec)`), the finding named whichever parameter a
/// `HashMap` yielded first, so rescans of the same page disagreed on the sink
/// and source — and `--baseline` read it as a new finding.
#[test]
fn summary_call_reports_the_same_flow_every_run() {
    let js = "function swap(a, b, c) { document.body.innerHTML = a; setTimeout(b); eval(c); }\n\
              function pick(a, b) { return a || b; }\n\
              var h = location.hash; swap(h, h, h);\n\
              document.write(pick(location.search, document.cookie));";
    let first: Vec<(String, String)> = found(js).into_iter().map(|v| (v.source, v.sink)).collect();
    assert_eq!(
        first,
        [
            ("location.hash".to_string(), "innerHTML".to_string()),
            ("location.search".to_string(), "document.write".to_string()),
        ]
    );
    for _ in 0..32 {
        let again: Vec<(String, String)> =
            found(js).into_iter().map(|v| (v.source, v.sink)).collect();
        assert_eq!(again, first);
    }
}
