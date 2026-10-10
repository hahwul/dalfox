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
