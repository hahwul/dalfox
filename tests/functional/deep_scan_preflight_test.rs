//! Regression tests for the `--deep-scan` preflight gate.
//!
//! `--deep-scan` is documented as "keep testing after the first finding" and
//! "lift the built-in payload cap" — it is meant to be *more* thorough. A bug
//! wrapped the entire preflight probe in `if !deep_scan`, so under `--deep-scan`
//! the landing-page body was never captured and the initial-response AST DOM-XSS
//! analysis (plus WAF/CSP/tech detection) silently never ran — making the mode
//! strictly weaker. These tests pin the fixed behavior: the initial AST pass
//! fires for a `deep_scan` scan, and still fires for a normal scan.

use axum::{Router, http::header, response::IntoResponse, routing::get};
use dalfox::cmd::scan::{self, ScanArgs};
use std::net::SocketAddr;
use std::time::Duration;

// A landing page whose *inline* script carries a `location.hash → innerHTML`
// DOM-XSS flow. There is no server-side reflection and no external script, so
// the finding can only come from the initial-response AST DOM analysis that
// runs on the preflight body — the exact path the bug disabled under deep-scan.
async fn inline_dom_xss_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        r#"<!DOCTYPE html><html><body>
            <div id="result"></div>
            <script>
              document.getElementById("result").innerHTML = location.hash.substring(1);
            </script>
        </body></html>"#,
    )
}

async fn start_server() -> SocketAddr {
    let app = Router::new().route("/", get(inline_dom_xss_page));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Give the listener a beat to come up before the scan dials it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Build ScanArgs isolated to the AST path (no payload probing, no mining/
/// discovery) so the only possible finding is the initial-response DOM-XSS one.
fn make_args(addr: SocketAddr, deep_scan: bool, out: &std::path::Path) -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![format!("http://{}:{}/", addr.ip(), addr.port())],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        only_discovery: false,
        skip_discovery: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 5,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: Some(out.to_string_lossy().to_string()),
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: true,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 4,
        max_concurrent_targets: 4,
        max_targets_per_host: 100,
        encoders: vec![],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true, // isolate the AST pass from the payload loop
        deep_scan,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 1,
        skip_ast_analysis: false, // the AST pass must be allowed to run
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 0,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
        max_payloads_per_param: 0,
    }
}

fn read_findings(out: &std::path::Path) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(out) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };
    v["findings"].as_array().cloned().unwrap_or_default()
}

/// The regression: under `--deep-scan`, the preflight body is still captured and
/// the initial AST DOM analysis still finds the inline `location.hash → innerHTML`
/// sink. Before the fix this returned zero findings because the whole preflight
/// was skipped for deep scans.
#[tokio::test]
async fn deep_scan_still_runs_initial_ast_dom_analysis() {
    let addr = start_server().await;
    let out = std::env::temp_dir().join(format!(
        "dalfox_deepscan_ast_{}_{}.json",
        addr.ip(),
        addr.port()
    ));
    let _ = std::fs::remove_file(&out);
    let args = make_args(addr, /* deep_scan = */ true, &out);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        !findings.is_empty(),
        "deep-scan must still capture the preflight body and run the initial AST \
         DOM analysis (inline location.hash → innerHTML sink); got no findings"
    );
    let _ = std::fs::remove_file(&out);
}

/// A normal (non-deep) scan of the same page must still find the sink — this is
/// the baseline the deep-scan behavior is expected to match.
#[tokio::test]
async fn normal_scan_runs_initial_ast_dom_analysis() {
    let addr = start_server().await;
    let out = std::env::temp_dir().join(format!(
        "dalfox_normalscan_ast_{}_{}.json",
        addr.ip(),
        addr.port()
    ));
    let _ = std::fs::remove_file(&out);
    let args = make_args(addr, /* deep_scan = */ false, &out);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        !findings.is_empty(),
        "a normal scan should find the inline DOM-XSS sink via the initial AST pass"
    );
    let _ = std::fs::remove_file(&out);
}
