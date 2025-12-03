//! Integration test: run dalfox scan against a local mock server
//! and verify that reflected XSS is detected and reported.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};

use dalfox::cmd::scan::{self, ScanArgs};

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

async fn generic_handler(
    Path(case_id): Path<u32>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("query").cloned().unwrap_or_default();
    let reflected = match case_id {
        1 => q.clone(),
        2 => html_named_encode_all(&q),
        3 => html_numeric_hex_lower(&q),
        4 => html_numeric_hex_upper_x(&q),
        5 => q.replace('%', "&#37;"),
        6 => format!("<img src=x alt=\"{}\">", q), // attribute context
        7 => format!("<script>var s=\"{}\";</script>", q), // JS context
        8 => format!("<!-- {} -->", q), // comment context
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn start_mock_server() -> SocketAddr {
    let app = Router::new().route("/:case_id", get(generic_handler));

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                // Keep server alive for the duration of the test; no external shutdown
                tokio::time::sleep(Duration::from_millis(1)).await;
            })
            .await
            .ok();
    });
    addr
}

#[tokio::test]
#[ignore]
async fn test_dalfox_scan_detects_multiple_reflection_cases() {
    let addr = start_mock_server().await;

    // Run across several cases (1..=8) with fixed param name 'query'
    for case_id in 1u32..=8u32 {
        let target = format!(
            "http://{}:{}/{}?query=seed",
            addr.ip(),
            addr.port(),
            case_id
        );

        let out_path = std::env::temp_dir()
            .join(format!("dalfox_mock_out_case{}_{}_{}.json", case_id, addr.ip(), addr.port()));
        let out_path_str = out_path.to_string_lossy().to_string();

        let args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: true,
            skip_mining_dict: true,
            skip_mining_dom: true,
            skip_discovery: false,
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
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

        scan::run_scan(&args).await;

        let content = std::fs::read_to_string(&out_path)
            .expect("scan should write JSON output file");
        let v: serde_json::Value = serde_json::from_str(&content)
            .expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_query = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("query"));
        assert!(has_query, "case {case_id}: at least one result should target param 'query'");
    }
}
