//! Integration tests for `--analyze-external-js`.
//!
//! Spins up a minimal axum server, runs a full dalfox scan, and asserts
//! whether external script bundles are fetched and analyzed for DOM XSS.
//!
//! All tests use `deep_scan: false` so the preflight fires and captures the
//! page body — the path that feeds `fetch_and_analyze_external_js`.

use axum::{Router, extract::Path as AxumPath, http::header, response::IntoResponse, routing::get};
use dalfox::cmd::scan::{self, ScanArgs};
use std::net::SocketAddr;
use std::time::Duration;

// A JS body with a `location.hash → innerHTML` DOM-XSS flow that the AST
// analyzer reliably detects.
const DOM_XSS_JS: &str =
    r#"document.getElementById("result").innerHTML = location.hash.substring(1);"#;

// ── server handlers ──────────────────────────────────────────────────────────

/// SPA page: no query params, no server-side reflection, one external script.
async fn spa_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        r#"<!DOCTYPE html><html><body>
            <div id="result"></div>
            <script src="/app.js"></script>
        </body></html>"#,
    )
}

/// The external script with a DOM-XSS sink.
async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        DOM_XSS_JS,
    )
}

/// A JS body just over MAX_EXTERNAL_JS_BYTES (512 KiB). No sink.
async fn big_js() -> impl IntoResponse {
    // "// x\n" = 5 bytes; 110_000 × 5 = 550_000 bytes > 524_288
    let body = "// x\n".repeat(110_000);
    ([(header::CONTENT_TYPE, "application/javascript")], body)
}

/// Page that references only the over-sized script.
async fn big_js_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        r#"<!DOCTYPE html><html><body>
            <div id="result"></div>
            <script src="/big.js"></script>
        </body></html>"#,
    )
}

/// Page with 18 distinct `<script src>` tags.
/// Scripts /js/0 … /js/15  →  harmless (no sink).
/// Scripts /js/16 … /js/17 →  contain a DOM-XSS sink.
/// With MAX_EXTERNAL_JS_FILES = 16 only the first 16 are attempted; the
/// sinky ones at index 16-17 are never fetched.
async fn many_page() -> impl IntoResponse {
    let mut scripts = String::new();
    for i in 0..18_u32 {
        scripts.push_str(&format!("<script src=\"/js/{i}\"></script>\n"));
    }
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!("<!DOCTYPE html><html><body><div id=\"result\"></div>{scripts}</body></html>"),
    )
}

/// /js/:n — harmless for n < 16, DOM-XSS sink for n >= 16.
async fn numbered_js(AxumPath(n): AxumPath<u32>) -> impl IntoResponse {
    let body = if n >= 16 {
        DOM_XSS_JS.to_string()
    } else {
        format!("var x{n} = {n};")
    };
    ([(header::CONTENT_TYPE, "application/javascript")], body)
}

// ── server bootstrap ─────────────────────────────────────────────────────────

async fn start_server() -> SocketAddr {
    let app = Router::new()
        .route("/", get(spa_page))
        .route("/app.js", get(app_js))
        .route("/big.js", get(big_js))
        .route("/big", get(big_js_page))
        .route("/many", get(many_page))
        .route("/js/{n}", get(numbered_js));

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test server");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Give the server a moment to accept connections.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

// ── scan helper ──────────────────────────────────────────────────────────────

fn make_scan_args(
    addr: SocketAddr,
    path: &str,
    analyze_external_js: bool,
    exclude_url: Vec<String>,
) -> (ScanArgs, std::path::PathBuf) {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), path);
    // Unique output path per test: port + path avoids cross-test collisions.
    let out = std::env::temp_dir().join(format!(
        "dalfox_extjs_{}_{}.json",
        addr.port(),
        path.replace(['/', '.'], "_"),
    ));
    let args = ScanArgs {
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
        exclude_url,
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
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true, // skip payload probing — we only care about AST findings
        deep_scan: false,        // must be false so the preflight captures the page body
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 1,
        skip_ast_analysis: false, // must be false for AST/external-JS path to run
        analyze_external_js,
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
    };
    (args, out)
}

fn read_findings(out: &std::path::Path) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(out) else {
        // Scan produced no output file → no findings.
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };
    v["findings"].as_array().cloned().unwrap_or_default()
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Flag on: SPA page with no server-side reflection still yields a DOM-XSS
/// finding from the external script. Verifies the pre-scan path, not the
/// per-param probe loop (which never runs when reflection_params is empty).
#[tokio::test]
async fn test_ext_js_spa_finds_dom_xss() {
    let addr = start_server().await;
    let (args, out) = make_scan_args(addr, "/", true, vec![]);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        !findings.is_empty(),
        "expected DOM-XSS finding from external app.js on SPA with no server-side reflection"
    );
    let cites_script = findings.iter().any(|f| {
        f["evidence"]
            .as_str()
            .is_some_and(|e| e.contains("/app.js"))
    });
    assert!(
        cites_script,
        "finding evidence should cite the external script URL; got: {findings:?}"
    );
}

/// Flag off (default): external scripts are never fetched → no findings.
#[tokio::test]
async fn test_ext_js_default_off_no_findings() {
    let addr = start_server().await;
    let (args, out) = make_scan_args(addr, "/", false, vec![]);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        findings.is_empty(),
        "no external JS findings expected when --analyze-external-js is off; got: {findings:?}"
    );
}

/// Body over MAX_EXTERNAL_JS_BYTES (512 KiB): script is skipped, no panic.
#[tokio::test]
async fn test_ext_js_size_cap_skips_oversized_script() {
    let addr = start_server().await;
    let (args, out) = make_scan_args(addr, "/big", true, vec![]);
    // Primarily a no-panic smoke test; big.js has no sink so findings == 0.
    scan::run_scan(&args).await;
    let _ = read_findings(&out); // must not panic
}

/// Count cap: page has 18 scripts; /js/16 and /js/17 contain sinks but
/// MAX_EXTERNAL_JS_FILES = 16 means they are never fetched → no findings.
#[tokio::test]
async fn test_ext_js_count_cap_stops_at_max() {
    let addr = start_server().await;
    let (args, out) = make_scan_args(addr, "/many", true, vec![]);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        findings.is_empty(),
        "scripts beyond MAX_EXTERNAL_JS_FILES should not be analyzed; got: {findings:?}"
    );
}

/// --exclude-url filter: when the script URL matches the denylist, it is
/// skipped even with --analyze-external-js on.
#[tokio::test]
async fn test_ext_js_exclude_url_skips_matched_script() {
    let addr = start_server().await;
    let (args, out) = make_scan_args(addr, "/", true, vec!["app\\.js".to_string()]);
    scan::run_scan(&args).await;
    let findings = read_findings(&out);
    assert!(
        findings.is_empty(),
        "excluded script should not be analyzed; got: {findings:?}"
    );
}
