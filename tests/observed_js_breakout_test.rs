//! End-to-end coverage for the issue #1073 follow-up: the *observed-prefix* JS
//! breakout. A reflection nested inside a JS object literal in an inline
//! `<script>` (`var config = {apiKey: '…'}`), served by a filter that blocks
//! the breakouts the fixed catalog relies on. Stripping `<`/`>` makes the
//! `</script>` HTML breakout inert; stripping `-`/`+` strips the
//! arithmetic-expression breakouts (`'-alert(1)-'`, `'+alert(1)+'`) that would
//! otherwise evaluate `alert(1)` inside the object *value* without closing the
//! brace. That leaves exactly one route to execution: close the open string
//! AND the enclosing object brace to reach a statement — `'};alert(1)//`.
//!
//! The `'}` closer is NOT one of the fixed depth-0–3 catalog shells (whose
//! object closers are all paired with a call paren, e.g. `'})`), so it is
//! reachable only by computing the breakout from the real observed script
//! prefix — exactly what this change wires in. On `main` (catalog-only) this
//! case is a false negative; with the observed-prefix breakout it is detected.
//!
//! This is a NON-ignored integration test, so the full discovery → mining →
//! synthesis → reflection pipeline is exercised against a live local server.

use axum::Router;
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, run_scan};
use std::collections::HashMap;
use tokio::net::TcpListener;

/// Reflect `q` into a single-quoted JS string that is the value of a key in an
/// object literal — `var config = {apiKey: '<q>', debug: false};` — after
/// stripping `<`, `>`, `-` and `+`. Stripping angles makes every HTML-tag /
/// `</script>` breakout inert; stripping `-`/`+` kills the arithmetic-expression
/// breakouts that would otherwise evaluate `alert(1)` inside the object value.
/// The only remaining route to execution is the JS-native `'};` statement close.
async fn nested_object_handler(Query(p): Query<HashMap<String, String>>) -> Html<String> {
    let q = p.get("q").cloned().unwrap_or_default();
    let stripped: String = q
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '-' | '+'))
        .collect();
    Html(format!(
        "<html><body><script>var config = {{apiKey: '{stripped}', debug: false}};\
         init(config);</script></body></html>"
    ))
}

fn base_args(url: String, out: String) -> ScanArgs {
    ScanArgs {
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url],
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
        skip_discovery: false,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 5,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: Some(out),
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
        // Production default encoders.
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
        max_payloads_per_param: 0,
    }
}

#[tokio::test]
async fn observed_breakout_detects_nested_object_script_context() {
    dalfox::ensure_crypto_provider();

    let app = Router::new().route("/", get(nested_object_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_obs_breakout_{}.json", addr.port()));
    let args = base_args(url, out.to_string_lossy().to_string());

    run_scan(&args).await;

    let content = std::fs::read_to_string(&out).expect("scan should write JSON output");
    let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    let findings = v["findings"].as_array().cloned().unwrap_or_default();
    let _ = std::fs::remove_file(&out);

    // The nested object brace must be closed to reach a statement, and `<`/`>`
    // are stripped — so detection here is only possible via a breakout that
    // closes the object (`'}…`), i.e. the observed-prefix path.
    assert!(
        !findings.is_empty(),
        "expected a finding for the nested object-literal script context"
    );
    // The winning payload must carry the object-brace close (`'}`), which only
    // the observed-prefix breakout supplies — distinguishing it from the
    // (here filtered-out) arithmetic-expression breakouts.
    let closes_object = findings.iter().any(|f| {
        f.get("payload")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p.contains("'}"))
    });
    assert!(
        closes_object,
        "expected a winning payload that closes the object brace (`'}}…`); \
         findings: {:#?}",
        findings
            .iter()
            .map(|f| f.get("payload").cloned())
            .collect::<Vec<_>>()
    );
}
