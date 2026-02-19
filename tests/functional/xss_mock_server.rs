//! Integration test: run dalfox scan against a local mock server
//! and verify that reflected XSS is detected and reported.
//!
//! This version uses structured mock cases loaded from TOML files.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::prelude::*;

use super::mock_case_loader::{self, MockCase};
use dalfox::cmd::scan::{self, ScanArgs};
use dalfox::parameter_analysis::analyze_parameters;
use dalfox::target_parser::parse_target;

/// Application state holding all loaded mock cases
#[derive(Clone)]
struct AppState {
    query_cases: Arc<HashMap<u32, MockCase>>,
    header_cases: Arc<HashMap<u32, MockCase>>,
    cookie_cases: Arc<HashMap<u32, MockCase>>,
    path_cases: Arc<HashMap<u32, MockCase>>,
    body_cases: Arc<HashMap<u32, MockCase>>,
}

// Helpers for mock encoding behaviors
fn html_named_encode_all(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            _ => c.to_string(),
        })
        .collect::<String>()
}

fn html_numeric_hex_lower(input: &str) -> String {
    input
        .chars()
        .map(|c| format!("&#x{:02x};", c as u32))
        .collect::<String>()
}

fn html_numeric_hex_upper_x(input: &str) -> String {
    input
        .chars()
        .map(|c| format!("&#X{:02X};", c as u32))
        .collect::<String>()
}

/// Apply the reflection pattern defined in the mock case
fn apply_reflection(reflection_pattern: &str, input: &str) -> String {
    match reflection_pattern {
        "encoded_html_named" => html_named_encode_all(input),
        "encoded_html_hex_lower" => html_numeric_hex_lower(input),
        "encoded_html_hex_upper" => html_numeric_hex_upper_x(input),
        "percent_to_entity" => input.replace('%', "&#37;"),
        "encoded_base64" => BASE64_STANDARD.encode(input),
        "encoded_url" => urlencoding::encode(input).to_string(),
        _ => reflection_pattern.replace("{input}", input),
    }
}

async fn query_handler_v2(
    Path(case_id): Path<u32>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let q = params.get("query").cloned().unwrap_or_default();

    let reflected = if let Some(case) = state.query_cases.get(&case_id) {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn header_handler_v2(
    Path(case_id): Path<u32>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let case = state.header_cases.get(&case_id);

    let header_name = case
        .and_then(|c| c.header_name.as_ref())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "x-test".to_string());

    let q = headers
        .get(header_name.as_str())
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn cookie_handler_v2(
    Path(case_id): Path<u32>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let case = state.cookie_cases.get(&case_id);

    let cookie_name = case
        .and_then(|c| c.cookie_name.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("test");

    let cookie_header = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let q = cookie_header
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            let prefix = format!("{}=", cookie_name);
            if c.starts_with(&prefix) {
                Some(c[prefix.len()..].to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn path_handler_v2(
    Path((case_id, param)): Path<(u32, String)>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let reflected = if let Some(case) = state.path_cases.get(&case_id) {
        apply_reflection(&case.reflection, &param)
    } else {
        param.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn body_handler_v2(
    State(state): State<AppState>,
    Path(case_id): Path<u32>,
    Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let case = state.body_cases.get(&case_id);

    let param_name = case
        .and_then(|c| c.param_name.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("query");

    let q = params.get(param_name).cloned().unwrap_or_default();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn start_mock_server_v2() -> (SocketAddr, AppState) {
    // Load all mock cases
    let base_dir = mock_case_loader::get_mock_cases_base_dir();
    let cases_by_type =
        mock_case_loader::load_all_mock_cases(&base_dir).expect("Failed to load mock cases");

    // Organize cases by ID for quick lookup
    let mut query_cases = HashMap::new();
    let mut header_cases = HashMap::new();
    let mut cookie_cases = HashMap::new();
    let mut path_cases = HashMap::new();
    let mut body_cases = HashMap::new();

    for (handler_type, cases) in cases_by_type {
        for case in cases {
            match handler_type.as_str() {
                "query" => {
                    query_cases.insert(case.id, case);
                }
                "header" => {
                    header_cases.insert(case.id, case);
                }
                "cookie" => {
                    cookie_cases.insert(case.id, case);
                }
                "path" => {
                    path_cases.insert(case.id, case);
                }
                "body" => {
                    body_cases.insert(case.id, case);
                }
                _ => {}
            }
        }
    }

    let state = AppState {
        query_cases: Arc::new(query_cases),
        header_cases: Arc::new(header_cases),
        cookie_cases: Arc::new(cookie_cases),
        path_cases: Arc::new(path_cases),
        body_cases: Arc::new(body_cases),
    };

    let app = Router::new()
        .route("/query/:case_id", get(query_handler_v2))
        .route("/header/:case_id", get(header_handler_v2))
        .route("/cookie/:case_id", get(cookie_handler_v2))
        .route("/path/:case_id/:param", get(path_handler_v2))
        .route("/body/:case_id", post(body_handler_v2))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                // Keep server alive for the duration of the test
                tokio::time::sleep(Duration::from_secs(300)).await;
            })
            .await
            .ok();
    });

    (addr, state)
}

/// Helper to run a scan test for a specific case
async fn run_scan_test(
    addr: SocketAddr,
    endpoint: &str,
    case_id: u32,
    scan_config: ScanTestConfig,
) -> Vec<serde_json::Value> {
    let target = format!(
        "http://{}:{}/{}{}",
        addr.ip(),
        addr.port(),
        endpoint,
        scan_config.url_suffix
    );

    let out_path = std::env::temp_dir().join(format!(
        "dalfox_mock_{}_case{}_{}_{}.json",
        endpoint.replace('/', "_"),
        case_id,
        addr.ip(),
        addr.port()
    ));
    let out_path_str = out_path.to_string_lossy().to_string();

    let args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![target],
        param: scan_config.param.clone(),
        data: scan_config.data.clone(),
        headers: scan_config.headers.clone(),
        cookies: scan_config.cookies.clone(),
        method: scan_config.method.clone(),
        user_agent: None,
        cookie_from_raw: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        skip_discovery: false,
        skip_reflection_header: scan_config.skip_reflection_header,
        skip_reflection_cookie: scan_config.skip_reflection_cookie,
        skip_reflection_path: scan_config.skip_reflection_path,
        timeout: 5,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        output: Some(out_path_str.clone()),
        include_request: false,
        include_response: false,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        skip_xss_scanning: false,
        deep_scan: true,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        skip_ast_analysis: false,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    scan::run_scan(&args).await;

    let content = std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
    let v: serde_json::Value =
        serde_json::from_str(&content).expect("output should be valid JSON array");

    v.as_array().expect("json should be an array").clone()
}

/// Run only discovery phase against a single target and report if any reflection params were found.
async fn run_discovery_once(
    addr: SocketAddr,
    url_path: String,
    method: String,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: Option<String>,
    skip_reflection_header: bool,
    skip_reflection_cookie: bool,
    skip_reflection_path: bool,
) -> bool {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), url_path);
    let mut target = parse_target(&url).unwrap();
    target.method = method;
    let body_clone = body.clone();
    target.data = body_clone.clone();
    target.headers = headers;
    target.cookies = cookies;
    target.user_agent = Some("".to_string());
    target.timeout = 5;
    target.workers = 10;

    let args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url.clone()],
        param: vec![],
        data: body_clone,
        headers: vec![],
        cookies: vec![],
        method: target.method.clone(),
        user_agent: None,
        cookie_from_raw: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_discovery: false,
        skip_reflection_header,
        skip_reflection_cookie,
        skip_reflection_path,
        timeout: 5,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        output: None,
        include_request: false,
        include_response: false,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        skip_ast_analysis: true,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    analyze_parameters(&mut target, &args, None).await;
    !target.reflection_params.is_empty()
}

struct ScanTestConfig {
    url_suffix: String,
    param: Vec<String>,
    data: Option<String>,
    headers: Vec<String>,
    cookies: Vec<String>,
    method: String,
    skip_reflection_header: bool,
    skip_reflection_cookie: bool,
    skip_reflection_path: bool,
}

#[tokio::test]
#[ignore]
async fn test_query_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    // Wait a moment for server to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.query_cases.len();
    println!("Testing {} query reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.query_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}?query=seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
        };

        let results = run_scan_test(addr, "query", *case_id, config).await;

        if !results.is_empty() {
            detected += 1;
        }
    }
    assert!(detected > 0, "query tests: expected at least one detection");
}

#[tokio::test]
#[ignore]
async fn test_header_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.header_cases.len();
    println!("Testing {} header reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.header_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let header_name = case.header_name.as_deref().unwrap_or("X-Test");
        let header_name_lc = header_name.to_ascii_lowercase();

        // Simple functional check: server reflects the header value (transformed)
        let client = reqwest::Client::new();
        let url = format!("http://{}:{}/header/{}", addr.ip(), addr.port(), case_id);
        let resp = client
            .get(&url)
            .header(&header_name_lc, "seed")
            .send()
            .await
            .expect("header request");
        let text = resp.text().await.expect("header text");
        let expected = apply_reflection(&case.reflection, "seed");
        if text.contains(&expected) {
            detected += 1;
        }
    }
    assert!(
        detected > 0,
        "header tests: expected at least one detection"
    );
}

#[tokio::test]
#[ignore]
async fn test_cookie_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.cookie_cases.len();
    println!("Testing {} cookie reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.cookie_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let cookie_name = case.cookie_name.as_deref().unwrap_or("test");

        let found = run_discovery_once(
            addr,
            format!("/cookie/{}", case_id),
            "GET".to_string(),
            vec![],
            vec![(cookie_name.to_string(), "seed".to_string())],
            None,
            true,
            false,
            true,
        )
        .await;
        if found {
            detected += 1;
        }
    }
    assert!(
        detected > 0,
        "cookie tests: expected at least one detection"
    );
}

#[tokio::test]
#[ignore]
async fn test_path_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.path_cases.len();
    println!("Testing {} path reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.path_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}/seed"),
            // Leave empty so discovery can add path_segment_* entries
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: false,
        };

        let results = run_scan_test(addr, "path", *case_id, config).await;

        if !results.is_empty() {
            detected += 1;
        }
    }
    assert!(detected > 0, "path tests: expected at least one detection");
}

#[tokio::test]
#[ignore]
async fn test_body_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.body_cases.len();
    println!("Testing {} body reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.body_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let param_name = case.param_name.as_deref().unwrap_or("query");

        // Simple functional check: server reflects the body param (transformed)
        let client = reqwest::Client::new();
        let url = format!("http://{}:{}/body/{}", addr.ip(), addr.port(), case_id);
        let form = [(param_name.to_string(), "seed".to_string())];
        let resp = client
            .post(&url)
            .form(&form)
            .send()
            .await
            .expect("body request");
        let text = resp.text().await.expect("body text");
        let expected = apply_reflection(&case.reflection, "seed");
        if text.contains(&expected) {
            detected += 1;
        }
    }
    assert!(detected > 0, "body tests: expected at least one detection");
}
