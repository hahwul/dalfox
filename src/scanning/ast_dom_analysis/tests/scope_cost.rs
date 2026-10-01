//! Cost regressions for the visitor's per-scope state handling.
//!
//! Every function body (literal, callback, event handler, summary) used to
//! clone the whole live taint/alias/field state on entry and restore it on
//! exit, so `N` tainted bindings followed by `N` function bodies cost
//! O(N²). These tests grow both halves together and require the analysis to
//! scale roughly linearly: quadrupling `N` must not cost anything close to
//! the 16× a quadratic walk pays.

use super::*;
use std::time::{Duration, Instant};

/// Base size per shape. Large enough that the quadratic term dominates the
/// fixed parse/thread cost in a debug build, small enough to keep the test
/// cheap once the walk is linear.
const BASE_N: usize = 1500;

/// Ratio ceiling for `t(4N) / t(N)`. Linear is ~4; the quadratic walk measured
/// 16–22. The headroom absorbs debug-build noise and a loaded test host.
const MAX_SCALING_RATIO: f64 = 10.0;

fn shape(prelude: &str, body: &str, n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&prelude.replace('I', &i.to_string()));
    }
    for i in 0..n {
        s.push_str(&body.replace('I', &i.to_string()));
    }
    s
}

/// Best of three, so one scheduling hiccup on a busy host can't fail the test.
fn best_time(src: &str) -> Duration {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            let _ = AstDomAnalyzer::new()
                .analyze(src)
                .expect("shape must parse");
            start.elapsed()
        })
        .min()
        .unwrap_or_default()
}

fn assert_linear(name: &str, prelude: &str, body: &str) {
    let small = shape(prelude, body, BASE_N);
    let large = shape(prelude, body, BASE_N * 4);
    assert!(
        large.len() <= MAX_ANALYZE_SOURCE_BYTES,
        "{name}: shape too big"
    );
    let t_small = best_time(&small);
    let t_large = best_time(&large);
    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(1e-6);
    eprintln!("{name}: N={BASE_N} {t_small:?}, 4N {t_large:?}, ratio {ratio:.1}");
    assert!(
        ratio < MAX_SCALING_RATIO,
        "{name}: 4N/N = {ratio:.1} ({t_small:?} -> {t_large:?}); per-scope state handling went quadratic"
    );
}

#[test]
fn function_literal_bodies_scale_linearly_with_tainted_state() {
    assert_linear(
        "callback",
        "var vI=location.hash;",
        "setTimeout(function(){x()},0);",
    );
    assert_linear("arrow", "var vI=location.hash;", "var fI=()=>{x()};");
}

#[test]
fn hoisted_declaration_summaries_scale_linearly_with_live_state() {
    assert_linear(
        "summary/taint",
        "var vI=location.hash;",
        "if(1){function gI(a){}}",
    );
    assert_linear(
        "summary/instances",
        "var vI=new C();",
        "if(1){function gI(a){}}",
    );
}

#[test]
fn event_handlers_and_callbacks_scale_linearly_with_field_state() {
    assert_linear(
        "event handler",
        "var vI=location.hash;",
        "window.addEventListener('message',function(e){x()});",
    );
    assert_linear(
        "isolated callback",
        "o.fI=location.hash;",
        "setTimeout(function(){x()},0);",
    );
}

fn walk_with_budget(src: &str, budget: u64) -> (Vec<DomXssVulnerability>, u64) {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, src, SourceType::default()).parse();
    assert!(ret.errors.is_empty(), "{src}");
    let mut visitor = DomXssVisitor::new(src);
    visitor.work_budget = budget;
    visitor.walk_statements(&ret.program.body);
    (visitor.vulnerabilities, visitor.work_steps.get())
}

#[test]
fn work_budget_stops_the_walk_and_keeps_earlier_findings() {
    let head = "document.write(location.hash);";
    let (_, head_steps) = walk_with_budget(head, u64::MAX);
    let src = format!("{head}{}eval(location.search);", "var a=1;".repeat(200));

    let (all, _) = walk_with_budget(&src, u64::MAX);
    assert!(all.iter().any(|v| v.sink.contains("eval")), "{all:?}");

    let (cut, steps) = walk_with_budget(&src, head_steps);
    assert_eq!(steps, head_steps, "the walk must stop at its budget");
    assert!(
        cut.iter().any(|v| v.source.contains("location.hash")),
        "findings before the budget ran out are kept: {cut:?}"
    );
    assert!(
        !cut.iter().any(|v| v.sink.contains("eval")),
        "nothing past the budget is walked: {cut:?}"
    );
}

#[test]
fn work_budget_is_far_above_a_large_ordinary_script() {
    // A bundle-shaped script near the length cap: many small functions,
    // callbacks and property writes. It must finish well inside the budget.
    let unit = "function hI(a,b){var c=a+b;if(c){o.pI=c;}return c;}\
                setTimeout(function(){hI(1,2);},0);";
    let mut src = String::new();
    let mut i = 0;
    while src.len() + unit.len() + 16 < MAX_ANALYZE_SOURCE_BYTES {
        src.push_str(&unit.replace('I', &i.to_string()));
        i += 1;
    }
    let (_, steps) = walk_with_budget(&src, u64::MAX);
    assert!(
        steps * 5 < MAX_AST_WORK_STEPS,
        "{steps} steps for a {}-byte ordinary script leaves too little headroom",
        src.len()
    );
}
