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
use dalfox::parameter_analysis::analyze_parameters;
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
        analyze_external_js: false,        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
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

/// Reflect every non-sentinel query value AND the raw request body (where each
/// probe's marker lands, whether form-encoded `b=MARKER` or JSON `{"k":"MARKER"}`)
/// into the response, and serve a POST form. Skipping the `dlfx_` sentinel names
/// keeps the reflect-everything collapse from firing, so each per-route
/// discovery/mining `Param` constructor actually runs on its own marker probe.
/// Used to exercise the `js_breakout` carrier on the body / JSON / form /
/// response-id routes (mirrors `escaped_quote_probe_test`'s constructor coverage).
async fn reflect_non_sentinel_handler(
    uri: axum::extract::OriginalUri,
    body: String,
) -> Html<String> {
    let mut parts: Vec<String> = Vec::new();
    for pair in uri.0.query().unwrap_or("").split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if !v.is_empty() && !k.contains("dlfx_") {
            parts.push(v.to_string());
        }
    }
    if !body.is_empty() {
        // Reflect the raw body verbatim — the marker is in it for both the
        // form-encoded and JSON probes.
        parts.push(body);
    }
    let joined = parts.join(" ");
    // Strip the chars that would break the surrounding div/script so the marker
    // reflects cleanly (detection only needs the marker present).
    let safe: String = joined
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '\'' | '"'))
        .collect();
    Html(format!(
        "<html><body><div id=out>{safe}</div>\
         <script>var o = {{id: 'static'}};</script>\
         <form method=\"post\" action=\"/x\"><input name=\"fld\" value=\"\"></form>\
         </body></html>"
    ))
}

/// Drive a full scan with mining enabled over the body, response-id and form
/// routes so the `js_breakout` per-parameter carrier is populated on each — the
/// HTTP-driven `Param` constructors the pure unit tests can't reach. No
/// assertion on findings; exercising the constructors without panic (and
/// covering the carrier wiring) is the goal.
#[tokio::test]
async fn observed_breakout_carrier_covers_mining_and_form_routes() {
    dalfox::ensure_crypto_provider();

    let app = Router::new()
        .route(
            "/",
            get(reflect_non_sentinel_handler).post(reflect_non_sentinel_handler),
        )
        .route(
            "/x",
            get(reflect_non_sentinel_handler).post(reflect_non_sentinel_handler),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed&id=seed", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_obs_cov_{}.json", addr.port()));
    let mut args = base_args(url, out.to_string_lossy().to_string());
    // Enable mining (dict + dom). The reflect-everything mock drives the dict
    // probe to the sustained-reflection EWMA collapse, exercising the collapse
    // post-processing that carries `js_breakout` on the synthetic 'any' param.
    args.skip_mining = false;
    args.skip_mining_dict = false;
    args.skip_mining_dom = false;
    args.skip_reflection_header = false;
    args.skip_reflection_cookie = false;
    args.skip_reflection_path = false;
    // 16+ reflecting body params trip the body-probe EWMA collapse too.
    let body: String = (0..18)
        .map(|i| format!("p{i}=seed"))
        .collect::<Vec<_>>()
        .join("&");
    args.data = Some(body);
    args.skip_xss_scanning = true;

    run_scan(&args).await;
    let _ = std::fs::remove_file(&out);
}

/// Drive form discovery so the POST-form `Param` constructor (and its
/// `js_breakout` carrier) runs: a page with a `<form method=post action=/x>`
/// whose action endpoint reflects the POST body.
#[tokio::test]
async fn observed_breakout_carrier_covers_form_route() {
    dalfox::ensure_crypto_provider();

    let app = Router::new()
        .route(
            "/",
            get(reflect_non_sentinel_handler).post(reflect_non_sentinel_handler),
        )
        .route(
            "/x",
            get(reflect_non_sentinel_handler).post(reflect_non_sentinel_handler),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let mut target = dalfox::target_parser::parse_target(&url).expect("parse target");
    let mut args = base_args(url.clone(), String::new());
    args.output = None;
    args.skip_mining = true;
    args.skip_xss_scanning = true;

    analyze_parameters(&mut target, &args, None).await;

    // The form's `fld` input reflects via POST to its action URL, so form
    // discovery must surface a Body param carrying the form action URL.
    assert!(
        target
            .reflection_params
            .iter()
            .any(|p| p.form_action_url.is_some()),
        "form discovery should surface a form-action Body param; got {:?}",
        target
            .reflection_params
            .iter()
            .map(|p| (&p.name, &p.location))
            .collect::<Vec<_>>()
    );
}

/// Same intent as above for the JSON-body route: a JSON `-d` payload makes the
/// JSON-body probe construct its `Param` (and its `js_breakout` carrier).
#[tokio::test]
async fn observed_breakout_carrier_covers_json_body_route() {
    dalfox::ensure_crypto_provider();

    let app = Router::new().route(
        "/",
        get(reflect_non_sentinel_handler).post(reflect_non_sentinel_handler),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_obs_json_{}.json", addr.port()));
    let mut args = base_args(url, out.to_string_lossy().to_string());
    args.skip_mining = false;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.method = "POST".to_string();
    // 16+ reflecting JSON fields trip the JSON-body-probe EWMA collapse, which
    // carries `js_breakout` on the synthetic 'any' JSON param.
    let json: String = format!(
        "{{{}}}",
        (0..18)
            .map(|i| format!("\"p{i}\":\"seed\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    args.data = Some(json);
    args.headers = vec!["Content-Type: application/json".to_string()];
    args.skip_xss_scanning = true;

    run_scan(&args).await;
    let _ = std::fs::remove_file(&out);
}
