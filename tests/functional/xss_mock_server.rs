//! Integration test: run dalfox scan against a local mock server
//! and verify that reflected XSS is detected and reported.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    Router,
    extract::{Form, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
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

async fn query_handler(
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
        6 => format!("<img src=x alt=\"{}\">", q), // attribute context double quote
        7 => format!("<script>var s=\"{}\";</script>", q), // JS context double quote
        8 => format!("<!-- {} -->", q),            // comment context
        9 => format!("<div>{}</div>", q),          // HTML element
        10 => format!("<script>{}</script>", q),   // JS block
        11 => format!("<img src=\"{}\">", q),      // attribute src
        12 => format!("<a href=\"{}\">", q),       // attribute href
        13 => format!("{{\"data\": \"{}\"}}", q),  // JSON
        14 => format!("<meta http-equiv=\"refresh\" content=\"0; url={}\">", q), // meta refresh
        15 => format!("<form action=\"{}\">", q),  // form action
        16 => format!("<input value=\"{}\">", q),  // input value
        17 => format!("<script>alert({})</script>", q), // JS no quotes
        18 => format!("<img alt='{}'>", q),        // attribute single quote
        19 => format!("<script>var s='{}';</script>", q), // JS single quote
        20 => format!("<p title=\"{}\">", q),      // attribute title
        21 => format!("<iframe src=\"{}\">", q),   // iframe src
        22 => format!("<object data=\"{}\">", q),  // object data
        23 => format!("<embed src=\"{}\">", q),    // embed src
        24 => format!("<link href=\"{}\">", q),    // link href
        25 => format!("<area href=\"{}\">", q),    // area href
        26 => format!("<base href=\"{}\">", q),    // base href
        27 => format!("<script src=\"{}\"></script>", q), // script src
        28 => format!("<style>@import url({});</style>", q), // CSS import
        29 => format!("javascript:{}", q),         // javascript: URL
        30 => format!("data:text/html,{}", q),     // data URL
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn header_handler(Path(case_id): Path<u32>, headers: HeaderMap) -> impl IntoResponse {
    let q = headers
        .get("x-test")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let reflected = match case_id {
        1 => q.clone(),
        2 => html_named_encode_all(&q),
        3 => html_numeric_hex_lower(&q),
        4 => html_numeric_hex_upper_x(&q),
        5 => q.replace('%', "&#37;"),
        6 => base64::encode(&q),
        7 => urlencoding::encode(&q).to_string(),
        8 => format!("<div>{}</div>", q),
        9 => format!("<script>{}</script>", q),
        10 => format!("<!-- {} -->", q),
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn cookie_handler(Path(case_id): Path<u32>, headers: HeaderMap) -> impl IntoResponse {
    let cookie_header = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let q = cookie_header
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            if c.starts_with("test=") {
                Some(c[5..].to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let reflected = match case_id {
        1 => q.clone(),
        2 => html_named_encode_all(&q),
        3 => html_numeric_hex_lower(&q),
        4 => html_numeric_hex_upper_x(&q),
        5 => q.replace('%', "&#37;"),
        6 => base64::encode(&q),
        7 => urlencoding::encode(&q).to_string(),
        8 => format!("<div>{}</div>", q),
        9 => format!("<script>{}</script>", q),
        10 => format!("<!-- {} -->", q),
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn path_handler(Path((case_id, param)): Path<(u32, String)>) -> impl IntoResponse {
    let q = param;
    let reflected = match case_id {
        1 => q.clone(),
        2 => html_named_encode_all(&q),
        3 => html_numeric_hex_lower(&q),
        4 => html_numeric_hex_upper_x(&q),
        5 => q.replace('%', "&#37;"),
        6 => base64::encode(&q),
        7 => urlencoding::encode(&q).to_string(),
        8 => format!("<div>{}</div>", q),
        9 => format!("<script>{}</script>", q),
        10 => format!("<!-- {} -->", q),
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn body_handler(
    Path(case_id): Path<u32>,
    Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("query").cloned().unwrap_or_default();
    let reflected = match case_id {
        1 => q.clone(),
        2 => html_named_encode_all(&q),
        3 => html_numeric_hex_lower(&q),
        4 => html_numeric_hex_upper_x(&q),
        5 => q.replace('%', "&#37;"),
        6 => base64::encode(&q),
        7 => urlencoding::encode(&q).to_string(),
        8 => format!("<div>{}</div>", q),
        9 => format!("<script>{}</script>", q),
        10 => format!("<!-- {} -->", q),
        _ => q.clone(),
    };
    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn start_mock_server() -> SocketAddr {
    let app = Router::new()
        .route("/query/:case_id", get(query_handler))
        .route("/header/:case_id", get(header_handler))
        .route("/cookie/:case_id", get(cookie_handler))
        .route("/path/:case_id/:param", get(path_handler))
        .route("/body/:case_id", post(body_handler));

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
async fn test_query_reflection() {
    let addr = start_mock_server().await;

    // Run across several cases (1..=30) with fixed param name 'query'
    for case_id in 1u32..=30u32 {
        let target = format!(
            "http://{}:{}/query/{}?query=seed",
            addr.ip(),
            addr.port(),
            case_id
        );

        let out_path = std::env::temp_dir().join(format!(
            "dalfox_mock_query_out_case{}_{}_{}.json",
            case_id,
            addr.ip(),
            addr.port()
        ));
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
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
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

        let content =
            std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
        let v: serde_json::Value =
            serde_json::from_str(&content).expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_query = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("query"));
        assert!(
            has_query,
            "case {case_id}: at least one result should target param 'query'"
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_header_reflection() {
    let addr = start_mock_server().await;

    for case_id in 1u32..=10u32 {
        let target = format!("http://{}:{}/header/{}", addr.ip(), addr.port(), case_id);

        let out_path = std::env::temp_dir().join(format!(
            "dalfox_mock_header_out_case{}_{}_{}.json",
            case_id,
            addr.ip(),
            addr.port()
        ));
        let out_path_str = out_path.to_string_lossy().to_string();

        let args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target],
            param: vec!["X-Test:header".to_string()],
            data: None,
            headers: vec!["X-Test: seed".to_string()],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: true,
            skip_mining_dict: true,
            skip_mining_dom: true,
            skip_discovery: false,
            skip_reflection_header: false,
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
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
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

        let content =
            std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
        let v: serde_json::Value =
            serde_json::from_str(&content).expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_header = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("X-Test"));
        assert!(
            has_header,
            "case {case_id}: at least one result should target param 'X-Test'"
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_cookie_reflection() {
    let addr = start_mock_server().await;

    for case_id in 1u32..=10u32 {
        let target = format!("http://{}:{}/cookie/{}", addr.ip(), addr.port(), case_id);

        let out_path = std::env::temp_dir().join(format!(
            "dalfox_mock_cookie_out_case{}_{}_{}.json",
            case_id,
            addr.ip(),
            addr.port()
        ));
        let out_path_str = out_path.to_string_lossy().to_string();

        let args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target],
            param: vec!["test:cookie".to_string()],
            data: None,
            headers: vec![],
            cookies: vec!["test=seed".to_string()],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: true,
            skip_mining_dict: true,
            skip_mining_dom: true,
            skip_discovery: false,
            skip_reflection_header: true,
            skip_reflection_cookie: false,
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
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
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

        let content =
            std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
        let v: serde_json::Value =
            serde_json::from_str(&content).expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_cookie = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("test"));
        assert!(
            has_cookie,
            "case {case_id}: at least one result should target param 'test'"
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_path_reflection() {
    let addr = start_mock_server().await;

    for case_id in 1u32..=10u32 {
        let target = format!("http://{}:{}/path/{}/seed", addr.ip(), addr.port(), case_id);

        let out_path = std::env::temp_dir().join(format!(
            "dalfox_mock_path_out_case{}_{}_{}.json",
            case_id,
            addr.ip(),
            addr.port()
        ));
        let out_path_str = out_path.to_string_lossy().to_string();

        let args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target],
            param: vec!["seed:path".to_string()],
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
            skip_reflection_path: false,
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
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: true,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        scan::run_scan(&args).await;

        let content =
            std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
        let v: serde_json::Value =
            serde_json::from_str(&content).expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_path = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("seed"));
        assert!(
            has_path,
            "case {case_id}: at least one result should target param 'seed'"
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_body_reflection() {
    let addr = start_mock_server().await;

    for case_id in 1u32..=10u32 {
        let target = format!("http://{}:{}/body/{}", addr.ip(), addr.port(), case_id);

        let out_path = std::env::temp_dir().join(format!(
            "dalfox_mock_body_out_case{}_{}_{}.json",
            case_id,
            addr.ip(),
            addr.port()
        ));
        let out_path_str = out_path.to_string_lossy().to_string();

        let args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target],
            param: vec!["query:body".to_string()],
            data: Some("query=seed".to_string()),
            headers: vec![],
            cookies: vec![],
            method: "POST".to_string(),
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
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
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

        let content =
            std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
        let v: serde_json::Value =
            serde_json::from_str(&content).expect("output should be valid JSON array");
        let arr = v.as_array().expect("json should be an array");
        assert!(
            !arr.is_empty(),
            "case {case_id}: should detect at least one XSS on the mock server"
        );
        let has_body = arr
            .iter()
            .any(|item| item.get("param").and_then(|p| p.as_str()) == Some("query"));
        assert!(
            has_body,
            "case {case_id}: at least one result should target param 'query'"
        );
    }
}
