//! End-to-end recall guard for #1520: client-side template injection on a
//! server-template framework (AngularJS 1.x / Vue) whose reflection the server
//! HTML-escapes.
//!
//! The 2026-06 FN hunt found that AngularJS (c40) and Vue (c41) pages execute a
//! reflected `{{…}}` interpolation even when the server entity-escapes the
//! markup — entity escaping is transparent to the framework compiler, which
//! reads the decoded text node. The byte-level reflection path correctly
//! demotes that escaped echo as inert (it is, for a non-framework page), so the
//! CSTI went unreported. `scanning::csti` adds a fallback probe that fires only
//! for those frameworks; these tests pin both the recall (AngularJS/Vue report)
//! and the gate (React does not).

use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue};
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, run_scan};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

/// `run_scan` resets and reads process-global request/failure counters, so
/// concurrent scans in this binary corrupt each other's tallies. Serialize.
static RUN_SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn html_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers
}

/// Entity-escape every structural character — the uniformly-escaping server the
/// reflection checks treat as safe. Braces and alnum pass through untouched, so
/// a `{{marker}}` probe still survives verbatim.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Serve one page that fingerprints as `framework_marker` (an attribute on the
/// root element) and reflects `q` into the compiled body. When `raw`, the
/// reflection is unescaped (an ordinary reflected-XSS sink).
async fn spawn_app(
    framework_marker: &'static str,
    raw: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(move |q: Query<HashMap<String, String>>| async move {
            let v = q.get("q").cloned().unwrap_or_default();
            let v = if raw { v } else { escape(&v) };
            (
                html_headers(),
                format!(
                    "<!doctype html><html {framework_marker}><body>\
                     <h1>Results for: {v}</h1></body></html>"
                ),
            )
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}/?q=hello", addr), handle)
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    path.push(format!(
        "dalfox-{}-{}-{}-{}",
        prefix,
        std::process::id(),
        nanos,
        seq
    ));
    path
}

fn scan_args(target: &str, output: &Path) -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: Some(output.to_string_lossy().to_string()),
        silence: true,
        targets: vec![target.to_string()],
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        skip_waf_probe: true,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_ast_analysis: true,
        insecure: Some(true),
        ..ScanArgs::default()
    }
}

fn read_findings(path: &Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).expect("output exists");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    parsed["findings"].as_array().cloned().unwrap_or_default()
}

fn csti_findings(findings: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    findings
        .iter()
        .filter(|f| f["inject_type"].as_str().unwrap_or("").contains("CSTI"))
        .collect()
}

#[tokio::test]
async fn angularjs_escaped_reflection_reports_csti() {
    let _serial = RUN_SCAN_LOCK.lock().await;
    let (target, server) = spawn_app("ng-app", false).await;
    let output = unique_temp_path("csti-angular.json");
    let _ = run_scan(&scan_args(&target, &output)).await;
    server.abort();

    let findings = read_findings(&output);
    let csti = csti_findings(&findings);
    assert!(
        !csti.is_empty(),
        "AngularJS escaped-reflection page must report CSTI; findings: {findings:#?}"
    );
    let f = csti[0];
    assert_eq!(f["param"].as_str(), Some("q"));
    // Static evidence ceiling — graded Low.
    assert_eq!(f["confidence"].as_str(), Some("low"), "finding: {f:#?}");
    // The PoC carries the AngularJS sandbox-escape, not the bare probe.
    assert!(
        f["message_str"]
            .as_str()
            .unwrap_or("")
            .contains("constructor.constructor"),
        "message should carry the sandbox-escape PoC: {f:#?}"
    );
}

#[tokio::test]
async fn vue_escaped_reflection_reports_csti() {
    let _serial = RUN_SCAN_LOCK.lock().await;
    let (target, server) = spawn_app("v-app", false).await;
    let output = unique_temp_path("csti-vue.json");
    let _ = run_scan(&scan_args(&target, &output)).await;
    server.abort();

    let findings = read_findings(&output);
    let csti = csti_findings(&findings);
    assert!(
        !csti.is_empty(),
        "Vue escaped-reflection page must report CSTI; findings: {findings:#?}"
    );
    assert!(
        csti[0]["message_str"]
            .as_str()
            .unwrap_or("")
            .contains("$emit.constructor"),
        "message should carry the Vue sandbox-escape PoC: {:#?}",
        csti[0]
    );
}

#[tokio::test]
async fn react_escaped_reflection_reports_no_csti() {
    let _serial = RUN_SCAN_LOCK.lock().await;
    // React does not compile server-rendered `{{…}}`, so a surviving brace probe
    // is inert — the gate must not fire.
    let (target, server) = spawn_app("data-reactroot", false).await;
    let output = unique_temp_path("csti-react.json");
    let _ = run_scan(&scan_args(&target, &output)).await;
    server.abort();

    let findings = read_findings(&output);
    assert!(
        csti_findings(&findings).is_empty(),
        "React page must not report CSTI; findings: {findings:#?}"
    );
}

#[tokio::test]
async fn reflection_outside_the_ng_app_root_is_not_csti() {
    let _serial = RUN_SCAN_LOCK.lock().await;
    // `ng-app` is scoped to one widget; `q` reflects (escaped) into a footer
    // that is a sibling of that widget, so AngularJS never compiles it.
    let app = Router::new().route(
        "/",
        get(|q: Query<HashMap<String, String>>| async move {
            let v = escape(&q.get("q").cloned().unwrap_or_default());
            (
                html_headers(),
                format!(
                    "<!doctype html><html><body><div ng-app=\"w\">widget</div>\
                     <footer>Results for: {v}</footer></body></html>"
                ),
            )
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let target = format!("http://{}/?q=hello", addr);
    let output = unique_temp_path("csti-outside-root.json");
    let _ = run_scan(&scan_args(&target, &output)).await;
    server.abort();

    let findings = read_findings(&output);
    assert!(
        csti_findings(&findings).is_empty(),
        "reflection outside the ng-app subtree must not report CSTI: {findings:#?}"
    );
}

#[tokio::test]
async fn angularjs_raw_reflection_does_not_add_a_separate_csti_finding() {
    let _serial = RUN_SCAN_LOCK.lock().await;
    // An unescaped reflection on an AngularJS page is an ordinary reflected XSS
    // that the normal phase finds with higher signal. The CSTI probe is a
    // fallback only, so it must not pile a second finding onto the same param.
    let (target, server) = spawn_app("ng-app", true).await;
    let output = unique_temp_path("csti-angular-raw.json");
    let _ = run_scan(&scan_args(&target, &output)).await;
    server.abort();

    let findings = read_findings(&output);
    assert!(!findings.is_empty(), "raw reflection must still be found");
    assert!(
        csti_findings(&findings).is_empty(),
        "no separate CSTI finding when the reflection already fired: {findings:#?}"
    );
}
