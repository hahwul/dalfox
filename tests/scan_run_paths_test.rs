use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;
use dalfox::cmd::scan::{
    DEFAULT_DELAY_MS, DEFAULT_ENCODERS, DEFAULT_MAX_CONCURRENT_TARGETS,
    DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD, DEFAULT_TIMEOUT_SECS, DEFAULT_WORKERS, ScanArgs,
    run_scan,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

fn base_scan_args() -> ScanArgs {
    ScanArgs {
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: DEFAULT_METHOD.to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        mining_dict_word: None,
        remote_wordlists: vec![],
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        timeout: DEFAULT_TIMEOUT_SECS,
        scan_timeout: 0,
        delay: DEFAULT_DELAY_MS,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        workers: DEFAULT_WORKERS,
        max_concurrent_targets: DEFAULT_MAX_CONCURRENT_TARGETS,
        max_targets_per_host: DEFAULT_MAX_TARGETS_PER_HOST,
        encoders: DEFAULT_ENCODERS.iter().map(|s| s.to_string()).collect(),
        remote_payloads: vec![],
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
        targets: vec![],
        max_payloads_per_param: 0,
    }
}

fn non_network_url_args(url: &str) -> ScanArgs {
    let mut args = base_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![url.to_string()];
    args.deep_scan = true;
    args.skip_discovery = true;
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_reflection_header = true;
    args.skip_reflection_cookie = true;
    args.skip_reflection_path = true;
    args.skip_xss_scanning = true;
    args.skip_ast_analysis = true;
    args
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    path.push(format!(
        "dalfox-{}-{}-{}",
        prefix,
        std::process::id(),
        nanos
    ));
    path
}

#[tokio::test]
async fn test_run_scan_rejects_invalid_input_type() {
    let mut args = base_scan_args();
    args.input_type = "not-valid".to_string();
    args.targets = vec!["http://example.com".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_file_input_requires_path() {
    let mut args = base_scan_args();
    args.input_type = "file".to_string();
    args.targets.clear();
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_file_input_handles_missing_file() {
    let mut args = base_scan_args();
    args.input_type = "file".to_string();
    args.targets = vec!["/tmp/dalfox-missing-input-file.txt".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_raw_http_parse_error_path() {
    let mut args = base_scan_args();
    args.input_type = "raw-http".to_string();
    args.targets = vec!["INVALID RAW REQUEST".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_writes_json_output_for_empty_results() {
    let output_path = unique_temp_path("scan-output.json");
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.output = Some(output_path.to_string_lossy().to_string());
    args.silence = false;

    run_scan(&args).await;

    let content = std::fs::read_to_string(&output_path).expect("output should exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("output should be valid JSON");
    assert_eq!(parsed["findings"], serde_json::json!([]));
    assert_eq!(parsed["meta"]["findings_count"], 0);
    let _ = std::fs::remove_file(&output_path);
}

#[tokio::test]
async fn test_run_scan_handles_output_write_error() {
    let output_dir = unique_temp_path("scan-output-dir");
    std::fs::create_dir_all(&output_dir).expect("create temp directory");
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.output = Some(output_dir.to_string_lossy().to_string());
    args.silence = false;

    run_scan(&args).await;
    let _ = std::fs::remove_dir_all(&output_dir);
}

/// Spin up a local server that returns a fixed Cloudflare-like header set
/// so the WAF fingerprinter triggers without us needing real CF
/// infrastructure. Returns the base URL and the JoinHandle (caller aborts).
async fn spawn_cloudflare_lookalike() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(
                HeaderName::from_static("server"),
                HeaderValue::from_static("cloudflare"),
            );
            headers.insert(
                HeaderName::from_static("cf-ray"),
                HeaderValue::from_static("1234abc-NRT"),
            );
            (
                headers,
                "<html><body><p>welcome</p></body></html>".to_string(),
            )
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}/", addr), handle)
}

#[tokio::test]
async fn test_run_scan_emits_waf_block_in_target_summary() {
    let (url, handle) = spawn_cloudflare_lookalike().await;
    let output_path = unique_temp_path("scan-waf-output.json");
    let mut args = base_scan_args();
    args.targets = vec![format!("{}?q=1", url)];
    args.output = Some(output_path.to_string_lossy().to_string());
    args.format = "json".to_string();
    // Auto-detect on, but skip the active probe — we only want the
    // header-based detection to trigger, not extra requests.
    args.waf_bypass = "auto".to_string();
    args.skip_waf_probe = true;
    // Keep the run lean; we're only verifying preflight metadata, not
    // payload behavior.
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_xss_scanning = true;
    args.silence = true;

    run_scan(&args).await;
    handle.abort();

    let content = std::fs::read_to_string(&output_path).expect("output should exist");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    let summary = &parsed["meta"]["target_summary"][0];
    let waf = &summary["waf"];
    assert!(
        waf.is_object(),
        "expected target_summary[0].waf to be an object, got: {}",
        summary
    );
    let detected = waf["detected"].as_array().expect("detected is array");
    assert!(!detected.is_empty(), "at least one WAF should be detected");
    assert_eq!(
        detected[0]["type"], "Cloudflare",
        "header-based fingerprint should pick Cloudflare"
    );
    let bypass = &waf["bypass"];
    assert!(
        bypass.is_object(),
        "bypass strategy should be present when waf_bypass=auto"
    );
    assert!(bypass["encoders"].is_array());
    assert!(bypass["mutation_count"].is_number());
    // Effectiveness telemetry shows up alongside the strategy. With
    // skip_xss_scanning=true no requests fire so counts are zero, but
    // the keys must be present so consumers can rely on the shape.
    assert!(
        bypass["mutations_applied"].is_array(),
        "mutations_applied[] should always be present when bypass ran"
    );
    assert!(bypass["requests_sent"].is_number());
    assert!(bypass["requests_blocked"].is_number());
    let _ = std::fs::remove_file(&output_path);
}

/// `via: varnish` is a low-confidence (0.5) Fastly fingerprint —
/// useful for testing the --waf-min-confidence cutoff because it sits
/// right in the middle of the 0..1 range. Higher thresholds (e.g.
/// 0.7) should drop it; lower or unset should keep it.
async fn spawn_low_confidence_via_varnish_server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(
                HeaderName::from_static("via"),
                HeaderValue::from_static("1.1 varnish"),
            );
            (headers, "<html><body>ok</body></html>".to_string())
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}/", addr), handle)
}

#[tokio::test]
async fn test_run_scan_filters_waf_below_min_confidence() {
    // Scenario A: threshold 0.0 (default) → low-confidence "via: varnish"
    // (0.5) survives.
    let (url_a, handle_a) = spawn_low_confidence_via_varnish_server().await;
    let output_a = unique_temp_path("scan-waf-conf-a.json");
    let mut args_a = base_scan_args();
    args_a.targets = vec![format!("{}?q=1", url_a)];
    args_a.output = Some(output_a.to_string_lossy().to_string());
    args_a.format = "json".to_string();
    args_a.waf_bypass = "auto".to_string();
    args_a.skip_waf_probe = true;
    args_a.skip_mining = true;
    args_a.skip_mining_dict = true;
    args_a.skip_mining_dom = true;
    args_a.skip_xss_scanning = true;
    args_a.silence = true;
    args_a.waf_min_confidence = 0.0;
    run_scan(&args_a).await;
    handle_a.abort();
    let parsed_a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_a).expect("file")).expect("json");
    assert!(
        parsed_a["meta"]["target_summary"][0]["waf"]["detected"]
            .as_array()
            .map(|d| !d.is_empty())
            .unwrap_or(false),
        "with default threshold 0.0, the 0.5-confidence Fastly hint should remain"
    );
    let _ = std::fs::remove_file(&output_a);

    // Scenario B: threshold 0.7 → 0.5-confidence detection drops; the
    // entry has no "waf" field at all (lean output convention when
    // nothing remained after filtering).
    let (url_b, handle_b) = spawn_low_confidence_via_varnish_server().await;
    let output_b = unique_temp_path("scan-waf-conf-b.json");
    let mut args_b = base_scan_args();
    args_b.targets = vec![format!("{}?q=1", url_b)];
    args_b.output = Some(output_b.to_string_lossy().to_string());
    args_b.format = "json".to_string();
    args_b.waf_bypass = "auto".to_string();
    args_b.skip_waf_probe = true;
    args_b.skip_mining = true;
    args_b.skip_mining_dict = true;
    args_b.skip_mining_dom = true;
    args_b.skip_xss_scanning = true;
    args_b.silence = true;
    args_b.waf_min_confidence = 0.7;
    run_scan(&args_b).await;
    handle_b.abort();
    let parsed_b: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_b).expect("file")).expect("json");
    assert!(
        parsed_b["meta"]["target_summary"][0]["waf"].is_null(),
        "with threshold 0.7, the only weak fingerprint should drop and waf should be omitted"
    );
    let _ = std::fs::remove_file(&output_b);
}

#[tokio::test]
async fn test_run_scan_omits_waf_block_when_no_waf_detected() {
    // Plain server with no WAF-like headers: target_summary entry must
    // NOT contain a `waf` field, keeping the common-case output lean.
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            (headers, "<html><body>ok</body></html>".to_string())
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let output_path = unique_temp_path("scan-nowaf-output.json");
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{}/?q=1", addr)];
    args.output = Some(output_path.to_string_lossy().to_string());
    args.format = "json".to_string();
    args.waf_bypass = "auto".to_string();
    args.skip_waf_probe = true;
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_xss_scanning = true;
    args.silence = true;

    run_scan(&args).await;
    handle.abort();

    let content = std::fs::read_to_string(&output_path).expect("output should exist");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    let summary = &parsed["meta"]["target_summary"][0];
    assert!(
        summary["waf"].is_null(),
        "no WAF detected → waf field should be absent, got: {}",
        summary
    );
    let _ = std::fs::remove_file(&output_path);
}

#[tokio::test]
async fn test_run_scan_unknown_format_fallback_path() {
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.format = "custom-format".to_string();
    args.silence = true;

    run_scan(&args).await;
}

/// `--input-type har` with no file argument and no stdin pipe must fail fast
/// with a clear error rather than hanging or scanning nothing.
#[tokio::test]
async fn test_run_scan_har_requires_a_source() {
    let mut args = base_scan_args();
    args.input_type = "har".to_string();
    args.targets.clear();
    args.silence = false;

    let outcome = run_scan(&args).await;
    assert_eq!(outcome, dalfox::cmd::scan::ScanOutcome::Error);
}

/// A `--input-type har` argument that is neither a readable file nor valid HAR
/// JSON surfaces a parse error instead of being silently treated as a URL.
#[tokio::test]
async fn test_run_scan_har_invalid_content_errors() {
    let mut args = base_scan_args();
    args.input_type = "har".to_string();
    args.targets = vec!["this is definitely not har".to_string()];
    args.silence = false;

    let outcome = run_scan(&args).await;
    assert_eq!(outcome, dalfox::cmd::scan::ScanOutcome::Error);
}

/// End-to-end proof that a HAR file drives the scan: both entries — a GET with
/// query params and a POST carrying a body — must reach the target host with
/// their original method and path preserved. A local recorder captures every
/// request the scan sends so we can assert the HAR shaped them.
#[tokio::test]
async fn test_run_scan_har_input_drives_get_and_post_targets() {
    use axum::extract::State;
    use axum::response::Html;
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    type Hits = Arc<Mutex<Vec<(String, String)>>>;

    async fn record(
        State(hits): State<Hits>,
        method: axum::http::Method,
        uri: axum::http::Uri,
    ) -> Html<String> {
        hits.lock()
            .expect("hits mutex")
            .push((method.to_string(), uri.path().to_string()));
        Html("<html><body>ok</body></html>".to_string())
    }

    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/search", get(record))
        .route("/comment", post(record))
        .with_state(hits.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{}/", addr);

    // GET entry with a query param + POST entry with a urlencoded body.
    let har = format!(
        r#"{{"log":{{"version":"1.2","entries":[
            {{"request":{{"method":"GET","url":"{base}search?q=test","headers":[],"cookies":[]}}}},
            {{"request":{{"method":"POST","url":"{base}comment",
              "headers":[{{"name":"Content-Type","value":"application/x-www-form-urlencoded"}}],
              "cookies":[],
              "postData":{{"mimeType":"application/x-www-form-urlencoded","text":"comment=hello"}}}}}}
        ]}}}}"#
    );
    let har_path = unique_temp_path("har-input.har");
    std::fs::write(&har_path, har).expect("write HAR");

    let mut args = base_scan_args();
    args.input_type = "har".to_string();
    args.targets = vec![har_path.to_string_lossy().to_string()];
    // Keep it lean: mining/AST add noise and latency without changing what we
    // assert (that both HAR entries are reached with the right method).
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_ast_analysis = true;
    args.silence = true;

    run_scan(&args).await;
    handle.abort();
    let _ = std::fs::remove_file(&har_path);

    let recorded = hits.lock().expect("hits mutex").clone();
    assert!(
        recorded.iter().any(|(m, p)| m == "GET" && p == "/search"),
        "HAR GET entry should have been scanned, recorded: {:?}",
        recorded
    );
    assert!(
        recorded.iter().any(|(m, p)| m == "POST" && p == "/comment"),
        "HAR POST entry (with body) should have been scanned, recorded: {:?}",
        recorded
    );
}
