//! Integration coverage for the issue #1072 quote-escape probe: run the real
//! `active_probe_param` against a local server that backslash-escapes quotes
//! inside a JS string, and confirm it populates `escaped_specials`. This is a
//! NON-ignored test (unlike the mock-server functional suite) so the async probe
//! path + the active-probe glue are exercised by the coverage job.

use axum::Router;
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use dalfox::parameter_analysis::{
    DelimiterType, InjectionContext, Location, Param, active_probe_param,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Reflect `q` into a double-quoted JS string after JavaScript-style
/// backslash-escaping of quotes (`"` -> `\"`, `'` -> `\'`). Backslashes pass
/// through raw, so the `\";…` bypass precondition holds.
async fn escaping_handler(Query(p): Query<HashMap<String, String>>) -> Html<String> {
    let q = p.get("q").cloned().unwrap_or_default();
    let escaped = q.replace('"', "\\\"").replace('\'', "\\'");
    Html(format!(
        "<html><body><script>var x=\"{escaped}\";</script></body></html>"
    ))
}

fn js_dq_param() -> Param {
    Param {
        name: "q".to_string(),
        value: "seed".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Javascript(Some(
            DelimiterType::DoubleQuote,
        ))),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

#[tokio::test]
async fn active_probe_detects_escaped_quotes_against_escaping_server() {
    dalfox::ensure_crypto_provider();

    let app = Router::new().route("/", get(escaping_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let target = dalfox::target_parser::parse_target(&url).expect("parse target");

    let probed = active_probe_param(&target, js_dq_param(), Arc::new(Semaphore::new(4))).await;

    let escaped = probed.escaped_specials.unwrap_or_default();
    assert!(
        escaped.contains(&'"'),
        "quote-escape probe should flag `\"` as escaped on a JS-string-escaping server, got {escaped:?}"
    );
}

#[tokio::test]
async fn active_probe_no_escaped_flag_on_plain_reflection() {
    dalfox::ensure_crypto_provider();

    // Reflects the value verbatim into a JS string — no escaping, so no flag.
    async fn plain_handler(Query(p): Query<HashMap<String, String>>) -> Html<String> {
        let q = p.get("q").cloned().unwrap_or_default();
        Html(format!("<html><script>var x=\"{q}\";</script></html>"))
    }

    let app = Router::new().route("/", get(plain_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let target = dalfox::target_parser::parse_target(&url).expect("parse target");

    let probed = active_probe_param(&target, js_dq_param(), Arc::new(Semaphore::new(4))).await;

    assert!(
        probed.escaped_specials.unwrap_or_default().is_empty(),
        "a verbatim-reflecting server must not flag any escaped quotes"
    );
}

/// Drive the real `analyze_parameters` (discovery + active probing) against a
/// server that reflects a query param and a header, so the discovery-path Param
/// constructors and the `[param-analysis]` debug line (which now carries
/// `escaped_specials`) are exercised by the coverage job — these live on
/// HTTP-driven paths the pure unit tests can't reach.
#[tokio::test]
async fn analyze_parameters_covers_discovery_constructors_and_debug_line() {
    use axum::http::HeaderMap;
    use dalfox::cmd::scan::ScanArgs;
    use dalfox::parameter_analysis::analyze_parameters;

    // Reflect the query param, a header, a cookie, the request path, and a form
    // input — so discovery exercises the query / header / cookie / path / form
    // Param constructors (each on an HTTP-driven path the pure unit tests miss).
    async fn reflect_handler(
        uri: axum::extract::OriginalUri,
        headers: HeaderMap,
        Query(p): Query<HashMap<String, String>>,
    ) -> Html<String> {
        let q = p.get("q").cloned().unwrap_or_default();
        let h = headers
            .get("x-test")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let c = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let path = uri.0.path().to_string();
        Html(format!(
            "<html><body><div>q={q} h={h} c={c} path={path}</div>\
             <form action=\"/submit\" method=\"post\"><input name=\"fld\" value=\"{q}\"></form>\
             </body></html>"
        ))
    }

    dalfox::ensure_crypto_provider();
    let app = Router::new()
        .route("/", get(reflect_handler))
        .route("/{*rest}", get(reflect_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/app/seed?q=seed", addr.port());
    let mut target = dalfox::target_parser::parse_target(&url).expect("parse target");
    target.headers = vec![("X-Test".to_string(), "seed".to_string())];
    target.cookies = vec![("sid".to_string(), "seed".to_string())];

    let args = ScanArgs {
        insecure: true,
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url.clone()],
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
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 5,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: true,
        // silence=false so the `[param-analysis]` debug line (with escaped_specials) runs.
        silence: false,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: true,
        analyze_external_js: false,
        hpp: false,
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
    };

    analyze_parameters(&mut target, &args, None).await;

    // The query param reflects, so discovery must find at least one param
    // (exercising the discovery constructors + the debug summary line).
    assert!(
        !target.reflection_params.is_empty(),
        "discovery should find the reflected query param"
    );
}

/// Cover the `--inject-marker` discovery path (analysis.rs marker_params
/// constructors), which builds Params from the marker's position in the
/// query / body / header / cookie of the *request* — an HTTP-driven path the
/// pure unit tests don't reach. No reflection is needed; preflight just has to
/// succeed, so the server returns a minimal 200.
#[tokio::test]
async fn run_scan_inject_marker_covers_marker_param_constructors() {
    use dalfox::cmd::scan::{ScanArgs, run_scan};

    async fn ok_handler() -> Html<String> {
        Html("<html><body>ok</body></html>".to_string())
    }

    dalfox::ensure_crypto_provider();
    let app = Router::new()
        .route("/", get(ok_handler))
        .route("/{*rest}", get(ok_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let marker = "DLFXMARKERZ9";
    let url = format!("http://127.0.0.1:{}/?q={marker}", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_marker_{}.json", addr.port()));

    let args = ScanArgs {
        insecure: true,
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url],
        param: vec![],
        // Marker present in body, a header, and a cookie too → query + body +
        // header + cookie marker_params constructors all run.
        data: Some(format!("b={marker}")),
        headers: vec![format!("X-Mark: {marker}")],
        cookies: vec![format!("c={marker}")],
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
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: Some(marker.to_string()),
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: true,
        analyze_external_js: false,
        hpp: false,
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
    };

    // Just exercises the marker-discovery path; no assertion on findings (scanning
    // is skipped). Completing without panic is the coverage goal.
    let _ = run_scan(&args).await;
    let _ = std::fs::remove_file(&out);
}
