use super::*;
use axum::{
    Router, body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::any,
};
use std::collections::HashMap as Map;
use std::net::Ipv4Addr;
use std::path::PathBuf;

fn make_state(
    api_key: Option<&str>,
    origins: Option<Vec<&str>>,
    allow_all: bool,
    jsonp: bool,
    cb_name: &str,
) -> AppState {
    AppState {
        api_key: api_key.map(|s| s.to_string()),
        jobs: Arc::new(Mutex::new(std::collections::HashMap::new())),
        log_file: None,
        allowed_origins: origins.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
        allowed_origin_regexes: vec![],
        allow_all_origins: allow_all,
        allow_methods: "GET,POST,OPTIONS,PUT,PATCH,DELETE".to_string(),
        allow_headers: "Content-Type,X-API-KEY,Authorization".to_string(),
        jsonp_enabled: jsonp,
        callback_param_name: cb_name.to_string(),
    }
}

/// Build a synthetic Job for tests. Non-terminal jobs get no finished_at;
/// terminal jobs get `now_ms()` so retention tests can bracket around them.
fn test_job(status: JobStatus, results: Option<Vec<SanitizedResult>>, target_url: &str) -> Job {
    let mut job = Job::new_queued(target_url.to_string());
    job.status = status.clone();
    job.results = results.map(Arc::new);
    if matches!(
        status,
        JobStatus::Done | JobStatus::Error | JobStatus::Cancelled
    ) {
        job.finished_at_ms = Some(now_ms());
    }
    job
}

fn temp_log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "dalfox-server-{}-{}.log",
        name,
        crate::utils::make_scan_id(name)
    ))
}

async fn response_body_string(resp: axum::response::Response) -> String {
    let bytes = body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    String::from_utf8(bytes.to_vec()).expect("utf8 response")
}

async fn target_ok_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "<html><body>ok</body></html>",
    )
}

async fn start_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(target_ok_handler))
        .route("/{*rest}", any(target_ok_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind target listener");
    let addr = listener.local_addr().expect("target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

async fn target_slow_handler() -> impl IntoResponse {
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "<html><body><a href=\"?slow=1\">link</a></body></html>",
    )
}

/// Target server that adds a fixed delay per request, so callers can
/// reliably observe `progress.requests_sent` ticking up *before* the scan
/// finishes — guards against a regression that defers the counter update.
async fn start_slow_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(target_slow_handler))
        .route("/{*rest}", any(target_slow_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind slow target listener");
    let addr = listener.local_addr().expect("slow target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

#[test]
fn test_check_api_key_variants() {
    let state_no_key = make_state(None, None, false, false, "callback");
    let headers = HeaderMap::new();
    assert!(check_api_key(&state_no_key, &headers));

    let state_with_key = make_state(Some("secret"), None, false, false, "callback");
    assert!(!check_api_key(&state_with_key, &headers));

    let mut ok_headers = HeaderMap::new();
    ok_headers.insert("X-API-KEY", HeaderValue::from_static("secret"));
    assert!(check_api_key(&state_with_key, &ok_headers));

    let mut bad_headers = HeaderMap::new();
    bad_headers.insert("X-API-KEY", HeaderValue::from_static("wrong"));
    assert!(!check_api_key(&state_with_key, &bad_headers));
}

#[test]
fn test_make_and_short_scan_id_shape() {
    let id = make_scan_id("https://example.com");
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(crate::utils::short_scan_id(&id).len(), 7);
    assert_eq!(crate::utils::short_scan_id("abc"), "abc");
}

#[test]
fn test_validate_jsonp_callback_accepts_and_rejects() {
    assert_eq!(
        validate_jsonp_callback(" cb.func_1 "),
        Some("cb.func_1".to_string())
    );
    assert_eq!(validate_jsonp_callback("$name"), Some("$name".to_string()));
    assert!(validate_jsonp_callback("").is_none());
    assert!(validate_jsonp_callback("1abc").is_none());
    assert!(validate_jsonp_callback("a-b").is_none());
    assert!(validate_jsonp_callback(&"a".repeat(65)).is_none());
}

#[test]
fn test_build_cors_headers_none_all_exact_regex_and_fallbacks() {
    let req_headers = HeaderMap::new();
    let state_none = make_state(None, None, false, false, "callback");
    let none_headers = build_cors_headers(&state_none, &req_headers);
    assert!(none_headers.is_empty());

    let state_all = make_state(None, Some(vec!["*"]), true, false, "callback");
    let all_headers = build_cors_headers(&state_all, &req_headers);
    assert_eq!(
        all_headers
            .get("Access-Control-Allow-Origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );

    let state_exact = make_state(
        None,
        Some(vec!["http://localhost:3000"]),
        false,
        false,
        "callback",
    );
    let mut exact_req_headers = HeaderMap::new();
    exact_req_headers.insert("Origin", HeaderValue::from_static("http://localhost:3000"));
    let exact_headers = build_cors_headers(&state_exact, &exact_req_headers);
    assert_eq!(
        exact_headers
            .get("Access-Control-Allow-Origin")
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:3000")
    );
    assert_eq!(
        exact_headers.get("Vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );

    let mut state_regex = make_state(None, Some(vec!["http://dummy"]), false, false, "callback");
    state_regex.allowed_origin_regexes =
        vec![regex::Regex::new(r"^https://.*\.example\.com$").expect("valid regex")];
    let mut regex_req_headers = HeaderMap::new();
    regex_req_headers.insert(
        "Origin",
        HeaderValue::from_static("https://api.example.com"),
    );
    let regex_headers = build_cors_headers(&state_regex, &regex_req_headers);
    assert_eq!(
        regex_headers
            .get("Access-Control-Allow-Origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://api.example.com")
    );

    let mut state_fallback = make_state(None, Some(vec!["http://x"]), false, false, "callback");
    state_fallback.allow_methods = "\n".to_string();
    state_fallback.allow_headers = "\n".to_string();
    let fallback_headers = build_cors_headers(&state_fallback, &HeaderMap::new());
    assert!(
        fallback_headers
            .get("Access-Control-Allow-Methods")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("GET"))
            .unwrap_or(false)
    );
    assert!(
        fallback_headers
            .get("Access-Control-Allow-Headers")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("Content-Type"))
            .unwrap_or(false)
    );
}

#[test]
fn test_log_writes_to_file_and_supports_unknown_level() {
    let mut state = make_state(None, None, false, false, "callback");
    let path = temp_log_path("log-test");
    let _ = std::fs::remove_file(&path);
    state.log_file = Some(path.to_string_lossy().to_string());

    log(&state, "CUSTOM", "hello-log");
    let content = std::fs::read_to_string(&path).expect("log file should be readable");
    assert!(content.contains("[CUSTOM] hello-log"));
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_run_scan_job_invalid_target_sets_error() {
    let state = make_state(None, None, false, false, "callback");
    let id = "scan-job-error".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    run_scan_job(
        state.clone(),
        id.clone(),
        "not a valid target".to_string(),
        ScanOptions::default(),
        false,
        false,
    )
    .await;

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should exist");
    assert_eq!(job.status, JobStatus::Error);
}

#[tokio::test]
async fn test_get_scan_handler_unauthorized_and_bad_request_jsonp() {
    let state_auth = make_state(Some("secret"), None, false, true, "cb");
    let mut params_auth = Map::new();
    params_auth.insert("cb".to_string(), "myFn".to_string());
    params_auth.insert("url".to_string(), "http://example.com".to_string());
    let headers_missing_key = HeaderMap::new();

    let unauthorized_resp =
        get_scan_handler(State(state_auth), headers_missing_key, Query(params_auth))
            .await
            .into_response();
    assert_eq!(unauthorized_resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        unauthorized_resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/javascript")
    );

    let state_no_key = make_state(None, None, false, true, "cb");
    let mut params_bad_req = Map::new();
    params_bad_req.insert("cb".to_string(), "myFn".to_string());
    let bad_req_resp =
        get_scan_handler(State(state_no_key), HeaderMap::new(), Query(params_bad_req))
            .await
            .into_response();
    assert_eq!(bad_req_resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        bad_req_resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/javascript")
    );
}

#[tokio::test]
async fn test_get_result_handler_not_found_jsonp() {
    let state = make_state(None, None, false, true, "cb");
    let mut q = Map::new();
    q.insert("cb".to_string(), "resultCb".to_string());
    let resp = get_result_handler(
        State(state),
        HeaderMap::new(),
        Path("missing-id".to_string()),
        Query(q),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/javascript")
    );
}

#[tokio::test]
async fn test_options_scan_handler_returns_no_content() {
    let state = make_state(None, Some(vec!["*"]), true, false, "callback");
    let mut headers = HeaderMap::new();
    headers.insert("Origin", HeaderValue::from_static("http://any.origin"));

    let resp = options_scan_handler(State(state), headers)
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
}

#[tokio::test]
async fn test_cors_headers_on_result_exact_origin() {
    let state = make_state(
        Some("secret"),
        Some(vec!["http://localhost:3000"]),
        false,
        false,
        "callback",
    );

    // Insert a dummy job
    let id = "job1".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Done, None, ""));
    }

    // Build headers with API key and Origin
    let mut headers = HeaderMap::new();
    headers.insert("X-API-KEY", HeaderValue::from_static("secret"));
    headers.insert("Origin", HeaderValue::from_static("http://localhost:3000"));

    let resp = super::get_result_handler(
        State(state.clone()),
        headers,
        Path(id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::OK);
    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "http://localhost:3000");

    let allow_methods = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(allow_methods.contains("GET"));
    assert!(allow_methods.contains("POST"));
    assert!(allow_methods.contains("OPTIONS"));
}

#[tokio::test]
async fn test_jsonp_unauthorized_with_callback() {
    let state = make_state(Some("secret"), None, false, true, "cb");

    // No API key header provided to trigger 401
    let mut headers = HeaderMap::new();
    headers.insert("Origin", HeaderValue::from_static("http://evil.test"));

    // Provide ?cb=myFunc in query to request JSONP
    let mut q = Map::new();
    q.insert("cb".to_string(), "myFunc".to_string());

    let resp = super::get_result_handler(
        State(state.clone()),
        headers,
        Path("nojob".to_string()),
        Query(q),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.starts_with("application/javascript"));
}

#[tokio::test]
async fn test_auth_success_and_failure() {
    let state = make_state(Some("secret"), None, false, false, "callback");

    // Insert a dummy job for success case
    let ok_id = "ok".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(ok_id.clone(), test_job(JobStatus::Done, None, ""));
    }

    // Failure (no key)
    let headers_fail = HeaderMap::new();
    let resp_fail = super::get_result_handler(
        State(state.clone()),
        headers_fail,
        Path(ok_id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp_fail.status(), StatusCode::UNAUTHORIZED);

    // Success
    let mut headers_ok = HeaderMap::new();
    headers_ok.insert("X-API-KEY", HeaderValue::from_static("secret"));
    let resp_ok = super::get_result_handler(
        State(state.clone()),
        headers_ok,
        Path(ok_id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp_ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_options_preflight_headers() {
    let state = make_state(None, Some(vec!["*"]), true, false, "callback");

    let mut headers = HeaderMap::new();
    headers.insert("Origin", HeaderValue::from_static("http://any.example"));

    let resp =
        super::options_result_handler(State(state.clone()), headers, Path("any".to_string()))
            .await
            .into_response();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "*");

    let allow_methods = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(allow_methods.contains("OPTIONS"));
}

#[tokio::test]
async fn test_scan_alternate_path_uses_same_handler_semantics() {
    // This test validates that the result handler semantics (used by /result/{id})
    // are suitable for /scan/{id} as well (same handler wired).
    let state = make_state(Some("secret"), None, false, false, "callback");

    // Insert job
    let id = "alt".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Running, None, ""));
    }

    let mut headers = HeaderMap::new();
    headers.insert("X-API-KEY", HeaderValue::from_static("secret"));

    // Directly call the same handler that is wired to both /result/{id} and /scan/{id}
    let resp = super::get_result_handler(
        State(state.clone()),
        headers,
        Path(id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_start_scan_handler_unauthorized_and_bad_request_jsonp() {
    let state_auth = make_state(Some("secret"), None, false, true, "cb");
    let mut params_auth = Map::new();
    params_auth.insert("cb".to_string(), "startCb".to_string());
    let unauthorized_resp = start_scan_handler(
        State(state_auth),
        HeaderMap::new(),
        Query(params_auth),
        Ok(Json(ScanRequest {
            url: "http://example.com".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(unauthorized_resp.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_body = response_body_string(unauthorized_resp).await;
    assert!(unauthorized_body.starts_with("startCb("));

    let state_no_key = make_state(None, None, false, true, "cb");
    let mut params_bad_req = Map::new();
    params_bad_req.insert("cb".to_string(), "startCb".to_string());
    let bad_req_resp = start_scan_handler(
        State(state_no_key),
        HeaderMap::new(),
        Query(params_bad_req),
        Ok(Json(ScanRequest {
            url: "   ".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(bad_req_resp.status(), StatusCode::BAD_REQUEST);
    let bad_req_body = response_body_string(bad_req_resp).await;
    assert!(bad_req_body.starts_with("startCb("));
}

#[tokio::test]
async fn test_start_scan_handler_success_creates_queued_job() {
    let state = make_state(None, None, false, false, "cb");
    let resp = start_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            url: "not-a-valid-target".to_string(),
            options: Some(ScanOptions {
                include_request: Some(true),
                include_response: Some(true),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json response");
    let id = parsed["data"]["scan_id"]
        .as_str()
        .expect("scan id should be present")
        .to_string();
    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should be inserted");
    // The spawned task may move from Queued to Running/Done/Error very quickly
    assert!(
        matches!(
            job.status,
            JobStatus::Queued | JobStatus::Running | JobStatus::Done | JobStatus::Error
        ),
        "job should have been created with a valid status, got: {:?}",
        job.status
    );
    assert!(
        job.queued_at_ms > 0,
        "queued_at_ms must be set on submission"
    );
}

#[tokio::test]
async fn test_start_scan_handler_success_jsonp_response() {
    let state = make_state(None, None, false, true, "cb");
    let mut q = Map::new();
    q.insert("cb".to_string(), "scanCb".to_string());
    let resp = start_scan_handler(
        State(state),
        HeaderMap::new(),
        Query(q),
        Ok(Json(ScanRequest {
            url: "still-not-valid-target".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(body.starts_with("scanCb("));
}

#[tokio::test]
async fn test_get_result_handler_plain_json_branches() {
    let state_auth = make_state(Some("secret"), None, false, false, "callback");
    let unauthorized = get_result_handler(
        State(state_auth),
        HeaderMap::new(),
        Path("id".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let body = response_body_string(unauthorized).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(parsed["code"], 401);

    let state_no_key = make_state(None, None, false, false, "callback");
    let not_found = get_result_handler(
        State(state_no_key),
        HeaderMap::new(),
        Path("missing".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
    let nf_body = response_body_string(not_found).await;
    let nf_parsed: serde_json::Value = serde_json::from_str(&nf_body).expect("json body");
    assert_eq!(nf_parsed["code"], 404);
}

#[tokio::test]
async fn test_get_result_handler_running_message_branch() {
    let state = make_state(None, None, false, false, "callback");
    let id = "running-job".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Running, None, ""));
    }

    let resp = get_result_handler(State(state), HeaderMap::new(), Path(id), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(parsed["msg"], "ok");
    assert_eq!(parsed["data"]["status"], "running");
}

#[tokio::test]
async fn test_get_scan_handler_success_parses_query_options_and_jsonp() {
    let state = make_state(None, None, false, true, "cb");
    let mut params = Map::new();
    params.insert("cb".to_string(), "getCb".to_string());
    params.insert("url".to_string(), "bad-target-for-fast-fail".to_string());
    params.insert("header".to_string(), "X-A:1,Invalid,X-B:2".to_string());
    params.insert("encoders".to_string(), "url,html,base64".to_string());
    params.insert("worker".to_string(), "3".to_string());
    params.insert("delay".to_string(), "1".to_string());
    params.insert("blind".to_string(), "http://callback.local".to_string());
    params.insert("method".to_string(), "POST".to_string());
    params.insert("data".to_string(), "k=v".to_string());
    params.insert("user_agent".to_string(), "Dalfox-Test-UA".to_string());
    params.insert("include_request".to_string(), "true".to_string());
    params.insert("include_response".to_string(), "true".to_string());
    params.insert(
        "remote_payloads".to_string(),
        "unknown-provider".to_string(),
    );
    params.insert(
        "remote_wordlists".to_string(),
        "unknown-provider".to_string(),
    );
    params.insert("detect_outdated_libs".to_string(), "true".to_string());

    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(body.starts_with("getCb("));
    let inner = body.trim_start_matches("getCb(").trim_end_matches(");");
    let parsed: serde_json::Value = serde_json::from_str(inner).expect("jsonp payload");
    let id = parsed["data"]["scan_id"]
        .as_str()
        .expect("scan id")
        .to_string();

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job inserted");
    assert!(matches!(
        job.status,
        JobStatus::Queued | JobStatus::Running | JobStatus::Done | JobStatus::Error
    ));
    assert!(
        job.queued_at_ms > 0,
        "queued_at_ms must be set on submission"
    );
}

#[test]
fn test_split_cookie_pairs_handles_http_style_header() {
    // Regression: previously the server's singular `cookie` option was
    // fed through a single `split_once('=')`, so `"a=b; c=d"` collapsed to
    // one pair `("a", "b; c=d")` and `c=d` was silently dropped. The
    // preflight handler already split by `;`, so the two server endpoints
    // disagreed on semantics. `split_cookie_pairs` is now the single source.
    let pairs = split_cookie_pairs("a=b; c=d");
    assert_eq!(
        pairs,
        vec![
            ("a".to_string(), "b".to_string()),
            ("c".to_string(), "d".to_string()),
        ]
    );

    // Values containing `=` (e.g. session tokens) survive the per-pair
    // `split_once` because each `;`-delimited piece is parsed independently.
    let with_equals = split_cookie_pairs(" sid=abc=def; theme=dark ");
    assert_eq!(
        with_equals,
        vec![
            ("sid".to_string(), "abc=def".to_string()),
            ("theme".to_string(), "dark".to_string()),
        ]
    );

    // Pieces without `=` are dropped rather than producing empty pairs.
    let with_junk = split_cookie_pairs("a=b; ; not-a-pair; c=d");
    assert_eq!(
        with_junk,
        vec![
            ("a".to_string(), "b".to_string()),
            ("c".to_string(), "d".to_string()),
        ]
    );

    // Empty input must not panic and must not produce any spurious pairs.
    assert!(split_cookie_pairs("").is_empty());
    // Single piece without an `=` is dropped (no empty name/value pair).
    assert!(split_cookie_pairs("nosemi").is_empty());
    // Empty key (e.g. `=v`) is preserved as a pair with an empty name —
    // matches the upstream `split_once('=')` contract. Callers that need
    // to reject empty names must do so themselves, but record the current
    // behavior so a future refactor doesn't silently change it.
    let leading_eq = split_cookie_pairs("=v; k=w");
    assert_eq!(
        leading_eq,
        vec![
            ("".to_string(), "v".to_string()),
            ("k".to_string(), "w".to_string()),
        ]
    );
    // Empty value (`k=`) is preserved as an empty string, mirroring how
    // real browsers send `Set-Cookie: k=` to clear the cookie.
    let empty_val = split_cookie_pairs("k=; j=1");
    assert_eq!(
        empty_val,
        vec![
            ("k".to_string(), "".to_string()),
            ("j".to_string(), "1".to_string()),
        ]
    );
}

#[tokio::test]
async fn test_run_scan_job_exposes_requests_sent_before_completion() {
    // Regression: this asserts the *live* contract — `progress.requests_sent`
    // must be observably > 0 while `run_scan_job` is still in flight, not
    // only after it returns. The old code copied a private atomic into
    // `progress.requests_sent` only at the very end, so a passing test of
    // the post-scan value alone would not catch a regression to that
    // behavior. A slow target (40 ms per request) keeps the scan running
    // long enough for the polling loop to peek.
    let addr = start_slow_target_server().await;
    let state = make_state(None, None, false, false, "callback");
    let id = "live-mid-flight".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let opts = ScanOptions {
        encoders: Some(vec!["none".to_string()]),
        worker: Some(2),
        ..ScanOptions::default()
    };
    let progress = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).expect("job").progress.clone()
    };

    let scan_fut = run_scan_job(
        state.clone(),
        id.clone(),
        format!("http://{}/", addr),
        opts,
        false,
        false,
    );
    tokio::pin!(scan_fut);

    let mut observed_mid_flight: u64 = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::select! {
            _ = &mut scan_fut => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {
                let r = progress
                    .requests_sent
                    .load(std::sync::atomic::Ordering::Relaxed);
                if r > observed_mid_flight {
                    observed_mid_flight = r;
                }
                if tokio::time::Instant::now() > deadline {
                    panic!("scan did not complete within 30s");
                }
            }
        }
    }

    assert!(
        observed_mid_flight > 0,
        "progress.requests_sent must tick during the scan, not only at end"
    );
}

#[tokio::test]
async fn test_run_scan_job_populates_live_request_counter() {
    // Regression: previously a private `job_requests` atomic was scoped into
    // `REQUEST_COUNT_JOB` and only copied into `progress.requests_sent`
    // after `run_scanning` returned, so GET /scan/{id} reported 0 requests
    // for the entire scan and then jumped to the final value. Now
    // `progress.requests_sent` itself is the scoped counter, and `analyze_
    // parameters` alone issues at least one request via `tick_request_count`.
    let addr = start_target_server().await;
    let state = make_state(None, None, false, false, "callback");
    let id = "live-progress".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let opts = ScanOptions {
        encoders: Some(vec!["none".to_string()]),
        worker: Some(2),
        ..ScanOptions::default()
    };
    let progress = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).expect("job").progress.clone()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/", addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "run_scan_job should complete in time");

    let final_requests = progress
        .requests_sent
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        final_requests > 0,
        "progress.requests_sent must reflect issued requests, got {}",
        final_requests
    );

    // `params_tested` is now stamped to `params_total` on completion so the
    // post-run payload is internally consistent (each discovered param has
    // been pushed through `run_scanning`).
    let params_total = progress
        .params_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let params_tested = progress
        .params_tested
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        params_tested, params_total,
        "params_tested should equal params_total after completion"
    );
}

#[tokio::test]
async fn test_run_scan_job_success_marks_done() {
    let addr = start_target_server().await;
    let state = make_state(None, None, false, false, "callback");
    let id = "scan-job-success".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let opts = ScanOptions {
        cookie: Some("session=abc".to_string()),
        worker: Some(4),
        delay: Some(0),
        timeout: None,
        blind: None,
        header: Some(vec![
            "X-Test: 1".to_string(),
            "InvalidHeaderLine".to_string(),
            ":empty-name".to_string(),
        ]),
        method: Some("GET".to_string()),
        data: None,
        user_agent: Some("Dalfox-Server-Test".to_string()),
        encoders: Some(vec!["none".to_string()]),
        remote_payloads: Some(vec!["unknown-provider".to_string()]),
        remote_wordlists: Some(vec!["unknown-provider".to_string()]),
        include_request: Some(false),
        include_response: Some(false),
        callback_url: None,
        param: None,
        proxy: None,
        follow_redirects: None,
        skip_mining: None,
        skip_discovery: None,
        deep_scan: None,
        skip_ast_analysis: None,
        // Exercise the ON path: opts -> job_runner -> ScanArgs -> analysis gate.
        detect_outdated_libs: Some(true),
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/", addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "run_scan_job should complete in time");

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should remain");
    assert_eq!(job.status, JobStatus::Done);
    assert!(job.results.is_some());
}

#[tokio::test]
async fn test_run_scan_job_webhook_reports_cancelled_status() {
    // Regression for the webhook payload's `status` field: prior to
    // #977 the callback always emitted `"status":"done"` even when the
    // scan was cancelled mid-flight, leaving downstream consumers unable
    // to distinguish a fully-completed scan from a partial one. The
    // contract under test: when `cancel_flag` is flipped while the scan
    // is in flight, the webhook payload reports `"cancelled"`.
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    let target_addr = start_slow_target_server().await;

    // Webhook capture server: records the most recent POST body and signals
    // a oneshot when it fires so the test doesn't need to poll.
    let captured: StdArc<Mutex<Option<serde_json::Value>>> = StdArc::new(Mutex::new(None));
    let fired = StdArc::new(AtomicBool::new(false));
    let (tx, rx) = oneshot::channel::<()>();
    let tx_shared = StdArc::new(Mutex::new(Some(tx)));

    let captured_clone = captured.clone();
    let fired_clone = fired.clone();
    let tx_clone = tx_shared.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move |body: axum::body::Bytes| {
            let captured = captured_clone.clone();
            let fired = fired_clone.clone();
            let tx_shared = tx_clone.clone();
            async move {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                *captured.lock().await = Some(parsed);
                if !fired.swap(true, Ordering::SeqCst)
                    && let Some(tx) = tx_shared.lock().await.take()
                {
                    let _ = tx.send(());
                }
                StatusCode::OK
            }
        }),
    );
    let webhook_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind webhook listener");
    let webhook_addr = webhook_listener.local_addr().expect("webhook local addr");
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "callback");
    let id = "cancel-webhook-test".to_string();
    let mut job = test_job(JobStatus::Queued, None, "");
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    let cancel_flag = job.cancelled.clone();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    let opts = ScanOptions {
        encoders: Some(vec!["none".to_string()]),
        worker: Some(2),
        callback_url: Some(format!("http://{}/hook", webhook_addr)),
        ..ScanOptions::default()
    };

    // Flip the cancel flag a short time after the scan starts. The slow
    // target server (40ms / request) keeps the scan busy long enough.
    let cancel_flag_for_task = cancel_flag.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        cancel_flag_for_task.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/", target_addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "run_scan_job should complete in time");

    // Wait for the webhook POST to actually arrive (run_scan_job awaits
    // the POST so once the future resolves this should be immediate, but
    // be defensive against flakes on slower CI).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), rx).await;

    let payload = captured
        .lock()
        .await
        .clone()
        .expect("webhook should have been invoked");
    assert_eq!(
        payload["status"], "cancelled",
        "cancelled scan must emit status=cancelled (got payload: {})",
        payload
    );
    assert_eq!(payload["scan_id"], serde_json::Value::String(id.clone()));

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job still present");
    assert_eq!(job.status, JobStatus::Cancelled);
}

#[tokio::test]
async fn test_run_scan_job_webhook_reports_done_status() {
    // Companion to the cancelled-status test: the same code path emits
    // `"done"` when the scan completes without cancellation. Asserting
    // both branches keeps the conditional honest if someone later flips
    // the polarity.
    let target_addr = start_target_server().await;

    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move |body: axum::body::Bytes| {
            let captured = captured_clone.clone();
            async move {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                *captured.lock().await = Some(parsed);
                StatusCode::OK
            }
        }),
    );
    let webhook_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind webhook listener");
    let webhook_addr = webhook_listener.local_addr().expect("webhook local addr");
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "callback");
    let id = "done-webhook-test".to_string();
    let mut job = test_job(JobStatus::Queued, None, "");
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    let opts = ScanOptions {
        encoders: Some(vec!["none".to_string()]),
        worker: Some(2),
        callback_url: Some(format!("http://{}/hook", webhook_addr)),
        ..ScanOptions::default()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/", target_addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "run_scan_job should complete in time");

    let payload = captured
        .lock()
        .await
        .clone()
        .expect("webhook should have been invoked");
    assert_eq!(
        payload["status"], "done",
        "successful scan must emit status=done (got payload: {})",
        payload
    );
}

#[tokio::test]
async fn test_get_result_handler_jsonp_done_branch() {
    let state = make_state(None, None, false, true, "cb");
    let id = "done-jsonp".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Done, Some(Vec::new()), ""));
    }

    let mut q = Map::new();
    q.insert("cb".to_string(), "doneCb".to_string());
    let resp = get_result_handler(State(state), HeaderMap::new(), Path(id), Query(q))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/javascript")
    );
    let body = response_body_string(resp).await;
    assert!(body.starts_with("doneCb("));
}

#[tokio::test]
async fn test_get_scan_handler_success_plain_json_defaults() {
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "still-invalid-for-fast-fail".to_string());

    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let id = parsed["data"]["scan_id"]
        .as_str()
        .expect("scan id")
        .to_string();

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job inserted");
    assert!(matches!(
        job.status,
        JobStatus::Queued | JobStatus::Running | JobStatus::Done | JobStatus::Error
    ));
    assert!(
        job.queued_at_ms > 0,
        "queued_at_ms must be set on submission"
    );
}

#[tokio::test]
async fn test_run_server_returns_on_invalid_bind_address() {
    run_server(ServerArgs {
        port: 6664,
        host: "not a valid host".to_string(),
        api_key: None,
        log_file: None,
        allowed_origins: None,
        jsonp: false,
        callback_param_name: "callback".to_string(),
        cors_allow_methods: None,
        cors_allow_headers: None,
    })
    .await;
}

#[tokio::test]
async fn test_run_server_returns_on_bind_failure_after_state_build() {
    let guard_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind guard listener");
    let guard_addr = guard_listener.local_addr().expect("guard addr");

    run_server(ServerArgs {
        port: guard_addr.port(),
        host: Ipv4Addr::LOCALHOST.to_string(),
        api_key: Some("server-key".to_string()),
        log_file: None,
        allowed_origins: Some(
            "*,regex:^https://.*\\.example\\.com$,https://*.corp.local".to_string(),
        ),
        jsonp: true,
        callback_param_name: "cb".to_string(),
        cors_allow_methods: Some("GET,POST,OPTIONS".to_string()),
        cors_allow_headers: Some("Content-Type,X-API-KEY".to_string()),
    })
    .await;

    drop(guard_listener);
}

// ---- Tests for new endpoints: cancel, list, preflight ----

#[tokio::test]
async fn test_cancel_scan_handler_cancels_queued_job() {
    let state = make_state(None, None, false, false, "cb");
    let scan_id = "cancel-test-id".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(scan_id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let resp = cancel_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Path(scan_id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["cancelled"], true);
    assert_eq!(parsed["data"]["previous_status"], "queued");

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&scan_id).expect("job still exists");
    assert_eq!(job.status, JobStatus::Cancelled);
    assert!(job.cancelled.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn test_cancel_scan_handler_returns_404_for_unknown_id() {
    let state = make_state(None, None, false, false, "cb");
    let resp = cancel_scan_handler(
        State(state),
        HeaderMap::new(),
        Path("nonexistent".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_cancel_scan_handler_requires_auth() {
    let state = make_state(Some("secret"), None, false, false, "cb");
    let resp = cancel_scan_handler(
        State(state),
        HeaderMap::new(),
        Path("any".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_scans_handler_returns_all_jobs() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        for (id, status) in [("a", JobStatus::Done), ("b", JobStatus::Running)] {
            jobs.insert(id.to_string(), test_job(status, None, ""));
        }
    }

    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["total"], 2);
    assert_eq!(parsed["data"]["scans"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_scans_handler_filters_by_status() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        for (id, status) in [("a", JobStatus::Done), ("b", JobStatus::Running)] {
            jobs.insert(id.to_string(), test_job(status, None, ""));
        }
    }

    let mut params = Map::new();
    params.insert("status".to_string(), "done".to_string());
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["total"], 1);
    assert_eq!(parsed["data"]["scans"][0]["status"], "done");
}

#[tokio::test]
async fn test_list_scans_handler_requires_auth() {
    let state = make_state(Some("secret"), None, false, false, "cb");
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_preflight_handler_rejects_invalid_url() {
    let state = make_state(None, None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            url: "not-http".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_preflight_handler_requires_auth() {
    let state = make_state(Some("secret"), None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            url: "http://example.com".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_preflight_handler_unreachable_target() {
    let state = make_state(None, None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            url: "http://127.0.0.1:1/unreachable".to_string(),
            options: Some(ScanOptions {
                timeout: Some(1),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["reachable"], false);
    assert_eq!(parsed["data"]["error_code"], "CONNECTION_FAILED");
}

#[test]
fn test_validate_scan_options_accepts_defaults() {
    assert!(validate_scan_options(&ScanOptions::default()).is_ok());
}

#[test]
fn test_validate_scan_options_rejects_out_of_range() {
    let bad_timeout = ScanOptions {
        timeout: Some(0),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&bad_timeout).is_err());

    let bad_timeout_hi = ScanOptions {
        timeout: Some(9999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&bad_timeout_hi).is_err());

    let bad_delay = ScanOptions {
        delay: Some(999_999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&bad_delay).is_err());

    let bad_worker = ScanOptions {
        worker: Some(0),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&bad_worker).is_err());

    let bad_worker_hi = ScanOptions {
        worker: Some(999_999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&bad_worker_hi).is_err());
}

#[tokio::test]
async fn test_start_scan_handler_rejects_out_of_range_timeout() {
    let state = make_state(None, None, false, false, "cb");
    let resp = start_scan_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            url: "http://example.com".to_string(),
            options: Some(ScanOptions {
                timeout: Some(9999),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body_string(resp).await;
    assert!(body.contains("timeout must be between"));
}

#[tokio::test]
async fn test_get_scan_handler_rejects_out_of_range_delay() {
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "http://example.com".to_string());
    params.insert("delay".to_string(), "999999".to_string());
    let resp = get_scan_handler(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_result_handler_emits_timestamps() {
    let state = make_state(None, None, false, false, "cb");
    let id = "ts-done".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        let mut job = test_job(JobStatus::Done, Some(vec![]), "http://example.com");
        job.started_at_ms = Some(job.queued_at_ms + 10);
        job.finished_at_ms = Some(job.queued_at_ms + 100);
        jobs.insert(id.clone(), job);
    }
    let resp = get_result_handler(
        State(state),
        HeaderMap::new(),
        Path(id.clone()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let data = &parsed["data"];
    assert!(data["queued_at_ms"].as_i64().is_some());
    assert!(data["started_at_ms"].as_i64().is_some());
    assert!(data["finished_at_ms"].as_i64().is_some());
    assert_eq!(data["duration_ms"], 90);
}

#[tokio::test]
async fn test_list_scans_handler_emits_timestamps() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            "a".to_string(),
            test_job(JobStatus::Done, None, "http://example.com"),
        );
    }
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let entry = &parsed["data"]["scans"][0];
    assert!(entry["queued_at_ms"].as_i64().is_some());
    assert!(entry["finished_at_ms"].as_i64().is_some());
}

#[tokio::test]
async fn test_purge_expired_jobs_removes_old_terminal_jobs() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        let mut old = test_job(JobStatus::Done, None, "");
        old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
        jobs.insert("old".to_string(), old);
        jobs.insert("fresh".to_string(), test_job(JobStatus::Done, None, ""));
        jobs.insert("active".to_string(), test_job(JobStatus::Running, None, ""));
    }

    purge_expired_jobs(&state).await;

    let jobs = state.jobs.lock().await;
    assert!(
        !jobs.contains_key("old"),
        "old terminal job should be purged"
    );
    assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
    assert!(
        jobs.contains_key("active"),
        "active job must never be purged"
    );
}

#[tokio::test]
async fn test_cancel_scan_handler_purge_requires_terminal() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            "running-purge".to_string(),
            test_job(JobStatus::Running, None, ""),
        );
    }
    let mut params = Map::new();
    params.insert("purge".to_string(), "1".to_string());
    let resp = cancel_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Path("running-purge".to_string()),
        Query(params),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let jobs = state.jobs.lock().await;
    assert!(
        jobs.contains_key("running-purge"),
        "non-terminal job must not be purged"
    );
}

#[tokio::test]
async fn test_list_scans_handler_rejects_invalid_status_filter() {
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("status".to_string(), "bogus".to_string());
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body_string(resp).await;
    assert!(body.contains("invalid status filter"));
}

#[tokio::test]
async fn test_list_scans_handler_pagination_slices_and_reports_has_more() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        // Insert 5 jobs with increasing queued_at_ms so sort order is
        // deterministic for this test.
        for i in 0..5 {
            let mut job = test_job(JobStatus::Done, None, &format!("http://t{}", i));
            job.queued_at_ms = 1_000_000 + i as i64;
            jobs.insert(format!("job-{}", i), job);
        }
    }

    let mut params = Map::new();
    params.insert("offset".to_string(), "1".to_string());
    params.insert("limit".to_string(), "2".to_string());
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["total"], 5);
    assert_eq!(parsed["data"]["scans"].as_array().unwrap().len(), 2);
    let pag = &parsed["data"]["pagination"];
    assert_eq!(pag["offset"], 1);
    assert_eq!(pag["limit"], 2);
    assert_eq!(pag["returned"], 2);
    assert_eq!(pag["has_more"], true);
}

#[tokio::test]
async fn test_list_scans_handler_zero_limit_returns_all() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        for i in 0..3 {
            jobs.insert(
                format!("job-{}", i),
                test_job(JobStatus::Done, None, "http://example.com"),
            );
        }
    }
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["scans"].as_array().unwrap().len(), 3);
    assert_eq!(parsed["data"]["pagination"]["has_more"], false);
}

#[tokio::test]
async fn test_run_scan_job_webhook_fires_on_pre_start_cancellation() {
    // Regression: previously run_scan_job returned silently when it
    // observed the job was already cancelled / cancel_flag set before
    // entering the Running state, so subscribers wired to the webhook
    // never got a terminal callback for "cancel immediately after submit"
    // scans. The mid-flight cancel path already fired the webhook with
    // status=cancelled — this asserts the pre-start path matches that
    // contract.
    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move |body: axum::body::Bytes| {
            let captured = captured_clone.clone();
            async move {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                *captured.lock().await = Some(parsed);
                StatusCode::OK
            }
        }),
    );
    let webhook_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind webhook listener");
    let webhook_addr = webhook_listener.local_addr().expect("webhook local addr");
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "callback");
    let id = "pre-cancel-webhook".to_string();
    let target_url = "http://example.com/will-not-be-scanned";
    let mut job = test_job(JobStatus::Queued, None, target_url);
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    // Trip the cancel flag *before* run_scan_job starts. The new code
    // path must observe this, fire the webhook, and return — without
    // ever issuing a request to the target.
    job.cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    let opts = ScanOptions {
        callback_url: Some(format!("http://{}/hook", webhook_addr)),
        ..ScanOptions::default()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run_scan_job(
            state.clone(),
            id.clone(),
            target_url.to_string(),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "pre-cancelled run_scan_job should return fast");

    // The webhook is awaited in run_scan_job, so by the time it returns
    // the body should already be captured.
    let payload = captured
        .lock()
        .await
        .clone()
        .expect("webhook must fire for pre-start cancellation");
    assert_eq!(payload["status"], "cancelled");
    assert_eq!(payload["scan_id"], serde_json::Value::String(id));
    assert_eq!(payload["url"], target_url);
    // No scan ran, so results must be an empty array (not missing).
    assert!(
        payload["results"].is_array() && payload["results"].as_array().unwrap().is_empty(),
        "results should be [] for pre-start cancellation, got {:?}",
        payload["results"]
    );
}

#[tokio::test]
async fn test_run_scan_job_pre_cancel_webhook_falls_back_when_url_unparseable() {
    // Companion to the pre-start cancellation webhook test: even when the
    // submitted URL is garbage (so `parse_target` would fail when we try to
    // honor opts.proxy/TLS), the webhook must still fire with status=
    // cancelled. The pre-cancel path falls back to a default reqwest
    // client in that case rather than dropping the callback.
    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move |body: axum::body::Bytes| {
            let captured = captured_clone.clone();
            async move {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                *captured.lock().await = Some(parsed);
                StatusCode::OK
            }
        }),
    );
    let webhook_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind webhook listener");
    let webhook_addr = webhook_listener.local_addr().expect("webhook local addr");
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "callback");
    let id = "pre-cancel-bad-url".to_string();
    let target_url = "definitely-not-a-valid-url";
    let mut job = test_job(JobStatus::Queued, None, target_url);
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    job.cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    let opts = ScanOptions {
        callback_url: Some(format!("http://{}/hook", webhook_addr)),
        ..ScanOptions::default()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run_scan_job(
            state.clone(),
            id.clone(),
            target_url.to_string(),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "pre-cancelled run_scan_job should return fast");

    let payload = captured
        .lock()
        .await
        .clone()
        .expect("webhook must fire even when target url is unparseable");
    assert_eq!(payload["status"], "cancelled");
    assert_eq!(payload["scan_id"], serde_json::Value::String(id));
}

#[tokio::test]
async fn test_send_terminal_webhook_skips_non_http_url() {
    // The webhook helper must refuse non-http(s) URLs so a malicious
    // callback_url can't trick the server into dialing odd schemes
    // (file://, ftp://, javascript://, etc.). The contract is "silently
    // drop"; verify two observable things:
    //
    //   1. Each scheme returns under a tight deadline — proves we never
    //      reached reqwest's transport layer, which for unsupported
    //      schemes would emit a callback-failed log line. The default
    //      reqwest request timeout for these helpers is 10s, so a sub-
    //      second deadline reliably catches a regression that lets a
    //      non-http URL through to the client.
    //   2. The `None` callback_url path is also a no-op (no scheme to
    //      check at all).
    let state = make_state(None, None, false, false, "cb");
    for url in [
        "file:///etc/passwd",
        "ftp://example.com/payload",
        "javascript:alert(1)",
        "ws://example.com/hook",
    ] {
        let started = std::time::Instant::now();
        send_terminal_webhook(
            &state,
            Some(url.to_string()),
            "id",
            "http://example.com",
            "cancelled",
            &[],
            None,
        )
        .await;
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "send_terminal_webhook took too long for {} ({:?}) — scheme filter may have leaked",
            url,
            started.elapsed()
        );
    }

    // None-callback path: should be a fast no-op as well.
    let started = std::time::Instant::now();
    send_terminal_webhook(&state, None, "id", "http://example.com", "done", &[], None).await;
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
}

#[tokio::test]
async fn test_mark_job_error_transitions_non_terminal() {
    // Recovery primitive used by spawn_scan_task when the inner scan
    // panics or the scan runtime fails to build. Verify the basic
    // contract: a non-terminal job is moved to Error with the message
    // and a finished_at_ms timestamp.
    let state = make_state(None, None, false, false, "cb");
    let id = "panic-recover".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Running, None, "http://x"));
    }

    mark_job_error(&state, &id, "http://x", "synthetic panic".to_string()).await;

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job present");
    assert_eq!(job.status, JobStatus::Error);
    assert_eq!(job.error_message.as_deref(), Some("synthetic panic"));
    assert!(job.finished_at_ms.is_some());
}

#[tokio::test]
async fn test_mark_job_error_does_not_clobber_terminal_state() {
    // If the scan task panics *after* it has already written a terminal
    // outcome (e.g. cancelled mid-flight, then the cleanup path panics),
    // the recovery must not rewrite Done/Cancelled/Error to Error. The
    // gate is `!is_terminal()`; assert it holds for each terminal state.
    let state = make_state(None, None, false, false, "cb");

    for (id, status) in [
        ("done-stays-done", JobStatus::Done),
        ("cancelled-stays-cancelled", JobStatus::Cancelled),
        ("error-stays-error", JobStatus::Error),
    ] {
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(id.to_string(), test_job(status.clone(), None, "http://x"));
        }
        mark_job_error(&state, id, "http://x", "should-not-overwrite".to_string()).await;
        let jobs = state.jobs.lock().await;
        let job = jobs.get(id).expect("job present");
        assert_eq!(
            job.status, status,
            "terminal status must not be rewritten by recovery"
        );
        assert!(job.error_message.is_none());
    }
}

#[tokio::test]
async fn test_mark_job_error_fires_webhook_with_error_status() {
    // Regression: parse_target / panic recovery paths used to mark the
    // job Error but never fire the webhook, so subscribers waiting on a
    // terminal callback hung indefinitely for malformed-URL scans. The
    // contract now matches mid-flight cancel and natural completion —
    // every terminal transition fires the webhook exactly once.
    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move |body: axum::body::Bytes| {
            let captured = captured_clone.clone();
            async move {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                *captured.lock().await = Some(parsed);
                StatusCode::OK
            }
        }),
    );
    let webhook_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind webhook listener");
    let webhook_addr = webhook_listener.local_addr().expect("webhook local addr");
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "cb");
    let id = "error-webhook".to_string();
    let target_url = "http://example.com/bad";
    let mut job = test_job(JobStatus::Running, None, target_url);
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    mark_job_error(
        &state,
        &id,
        target_url,
        "parse_target failed: bad url".to_string(),
    )
    .await;

    let payload = captured
        .lock()
        .await
        .clone()
        .expect("webhook must fire on Error transition");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["scan_id"], serde_json::Value::String(id));
    assert_eq!(payload["url"], target_url);
    assert!(payload["results"].is_array() && payload["results"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_mark_job_error_does_not_double_fire_webhook_on_terminal_job() {
    // The transition guard (!is_terminal) must also gate the webhook —
    // otherwise a panic-recovery path racing with natural completion
    // would emit two terminal callbacks for the same scan_id and
    // confuse subscribers tracking lifecycle events.
    let webhook_hits: Arc<std::sync::atomic::AtomicUsize> =
        Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let webhook_hits_clone = webhook_hits.clone();
    let webhook_app = Router::new().route(
        "/hook",
        any(move || {
            let hits = webhook_hits_clone.clone();
            async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, webhook_app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "cb");
    let id = "already-done".to_string();
    let mut job = test_job(JobStatus::Done, None, "http://x");
    job.callback_url = Some(format!("http://{}/hook", addr));
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    mark_job_error(&state, &id, "http://x", "late panic".to_string()).await;
    // Give the webhook a beat in case it was sent anyway (it shouldn't be).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        webhook_hits.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "webhook must not fire when the job is already terminal"
    );
}

#[test]
fn test_constant_time_eq_matches_and_differs() {
    // Sanity: the timing-safe comparator must agree with `==` on equality
    // outcomes. Length mismatches return false without examining contents
    // (we don't try to assert constant-time timing here — that needs
    // statistical measurement — but verify behavioral correctness).
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"secret-key-123", b"secret-key-123"));
    assert!(!constant_time_eq(b"secret-key-123", b"secret-key-124"));
    assert!(!constant_time_eq(b"short", b"longer"));
    assert!(!constant_time_eq(b"a", b""));
    assert!(!constant_time_eq(b"", b"a"));
}

#[tokio::test]
async fn test_cancel_scan_handler_purge_deletes_terminal_job() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            "done-purge".to_string(),
            test_job(JobStatus::Done, None, ""),
        );
    }
    let mut params = Map::new();
    params.insert("purge".to_string(), "1".to_string());
    let resp = cancel_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Path("done-purge".to_string()),
        Query(params),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["deleted"], true);
    assert_eq!(parsed["data"]["previous_status"], "done");

    let jobs = state.jobs.lock().await;
    assert!(!jobs.contains_key("done-purge"));
}
