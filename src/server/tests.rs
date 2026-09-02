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
        rate_limit: None,
        scan_timeout: None,
        // 0 = unlimited so existing tests aren't rejected by the concurrency cap.
        max_concurrent_scans: 0,
        allowed_hosts: vec![],
        // 0 = unlimited, so a test that stages jobs by hand keeps all of them.
        max_retained_scans: 0,
        last_purge_ms: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        preflight_sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PREFLIGHT)),
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

/// Echoes every query-param value back into the HTML body so
/// `analyze_parameters` classifies each as a reflection param — giving a
/// scan with `params_total > 0` to exercise the live `params_tested` counter.
async fn target_reflect_handler(Query(q): Query<Map<String, String>>) -> impl IntoResponse {
    let mut body = String::from("<html><body>");
    for (k, v) in &q {
        body.push_str(&format!("<div>{k}={v}</div>"));
    }
    body.push_str("</body></html>");
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
}

async fn start_reflecting_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(target_reflect_handler))
        .route("/{*rest}", any(target_reflect_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind reflecting target listener");
    let addr = listener.local_addr().expect("reflecting target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

/// Reflects each query value back into the HTML body — but with the
/// XSS-significant characters (`< > " '`) stripped — after a fixed per-request
/// delay. The alphanumeric reflection probe still appears, so `analyze_parameters`
/// classifies the param as reflective and `run_scanning` sweeps the *whole*
/// payload set; yet no payload can ever verify (the breakout chars are gone),
/// so the scan never short-circuits on a finding. Combined with the delay this
/// guarantees the scan runs long enough for a small `scan_timeout` to trip.
async fn target_slow_reflect_handler(Query(q): Query<Map<String, String>>) -> impl IntoResponse {
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let mut body = String::from("<html><body>");
    for (k, v) in &q {
        let safe: String = v
            .chars()
            .filter(|c| !matches!(c, '<' | '>' | '"' | '\''))
            .collect();
        body.push_str(&format!("<div>{k}={safe}</div>"));
    }
    body.push_str("</body></html>");
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
}

async fn start_slow_reflecting_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(target_slow_reflect_handler))
        .route("/{*rest}", any(target_slow_reflect_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind slow reflecting target listener");
    let addr = listener
        .local_addr()
        .expect("slow reflecting target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

/// Reflects each query value with the XSS-significant characters stripped, and
/// without the artificial delay of [`target_slow_reflect_handler`]. The
/// alphanumeric probe still shows up, so the param is classified as reflective
/// and the whole payload set gets swept — but nothing ever verifies, so the
/// scan never short-circuits on a finding. That makes the total request count a
/// direct read on how far the payload fan-out went.
async fn target_inert_reflect_handler(Query(q): Query<Map<String, String>>) -> impl IntoResponse {
    let mut body = String::from("<html><body>");
    for (k, v) in &q {
        let safe: String = v
            .chars()
            .filter(|c| !matches!(c, '<' | '>' | '"' | '\''))
            .collect();
        body.push_str(&format!("<div>{k}={safe}</div>"));
    }
    body.push_str("</body></html>");
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
}

async fn start_inert_reflecting_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(target_inert_reflect_handler))
        .route("/{*rest}", any(target_inert_reflect_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind inert reflecting target listener");
    let addr = listener
        .local_addr()
        .expect("inert reflecting target local addr");
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
    let id = crate::utils::make_scan_id("https://example.com");
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
fn test_jsonp_body_escapes_line_and_paragraph_separators() {
    // F4: U+2028 (LINE SEPARATOR) / U+2029 (PARAGRAPH SEPARATOR) in an
    // attacker-influenced finding field must be escaped in the JSONP body, or
    // the wrapped `callback(...)` becomes a syntax error / split string literal
    // on engines that treat them as string-literal line terminators.
    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "evidence": "a\u{2028}b\u{2029}c" })),
    };
    let (ct, body) = build_response_body(&resp, Some("cb"));
    assert_eq!(ct, Some("application/javascript; charset=utf-8"));
    assert!(body.starts_with("cb(") && body.ends_with(");"));
    assert!(
        !body.contains('\u{2028}') && !body.contains('\u{2029}'),
        "raw separators must not survive into the JS body: {body}"
    );
    assert!(body.contains("\\u2028") && body.contains("\\u2029"));

    // The non-JSONP path is unchanged: plain JSON is a superset and modern
    // parsers accept the raw separators, so they pass through untouched.
    let (ct2, body2) = build_response_body(&resp, None);
    assert_eq!(ct2, None);
    assert!(body2.contains('\u{2028}') && body2.contains('\u{2029}'));
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
async fn test_responses_set_json_content_type_and_nosniff() {
    // Non-JSONP responses must carry an explicit application/json Content-Type
    // (not axum's String default of text/plain) plus X-Content-Type-Options:
    // nosniff, so an attacker-influenced body can't be MIME-sniffed into HTML.
    let state = make_state(None, None, false, false, "callback");
    let resp = health_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/json"),
        "non-JSONP responses must be application/json"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "every API response must forbid MIME sniffing"
    );
}

#[tokio::test]
async fn test_jsonp_response_keeps_javascript_content_type_with_nosniff() {
    // The JSONP path keeps application/javascript but must still send nosniff.
    let state = make_state(None, None, false, true, "cb");
    let mut q = Map::new();
    q.insert("cb".to_string(), "myFn".to_string());
    let resp = health_handler(State(state), HeaderMap::new(), Query(q))
        .await
        .into_response();
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/javascript"),
        "JSONP responses stay application/javascript"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
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
            target: "http://example.com".to_string(),
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
            target: "   ".to_string(),
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
            target: "http://127.0.0.1:1/".to_string(),
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
            target: "http://127.0.0.1:1/".to_string(),
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
    params.insert("url".to_string(), "http://127.0.0.1:1/".to_string());
    params.insert("header".to_string(), "X-A:1,X-B:2".to_string());
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
fn test_split_header_query_param_keeps_commas_inside_values() {
    // `GET /scan?header=...` packs several headers into one comma-separated
    // value, but a comma is legal inside a header value. A blind split chopped
    // `Accept: text/html,application/xhtml+xml` into a truncated Accept plus a
    // nameless fragment — silently dropped before header validation existed,
    // and a 400 for an otherwise valid request afterwards.
    assert_eq!(
        split_header_query_param("Accept: text/html,application/xhtml+xml"),
        vec!["Accept: text/html,application/xhtml+xml".to_string()]
    );
    // The multi-header form still works.
    assert_eq!(
        split_header_query_param("X-A: 1,X-B: 2"),
        vec!["X-A: 1".to_string(), "X-B: 2".to_string()]
    );
    // Mixed: a value with commas followed by a genuine second header.
    assert_eq!(
        split_header_query_param("Accept: a/b,c/d,X-Trace: 9"),
        vec!["Accept: a/b,c/d".to_string(), "X-Trace: 9".to_string()]
    );
    assert!(split_header_query_param("").is_empty());
    assert!(split_header_query_param("   ").is_empty());
}

#[tokio::test]
async fn test_get_scan_handler_rejects_a_malformed_header_entry() {
    // A header entry with no `Name: value` shape used to be dropped on the
    // floor and the scan queued anyway, so a caller whose header never went out
    // got a `200 OK` and a "clean" result. reqwest rejects it on every request
    // in the job, which surfaced as the *target* being reported unreachable.
    // Refuse at the boundary and name the offender instead.
    let state = make_state(None, None, false, true, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "http://127.0.0.1:1/".to_string());
    // A leading entry with no `Name: value` shape is unambiguously malformed.
    // (A bare fragment *after* a valid header is not: the comma-packed query
    // form cannot tell it apart from a comma inside that header's value, so
    // `split_header_query_param` keeps it as part of the value — see
    // `test_split_header_query_param_keeps_commas_inside_values`.)
    params.insert("header".to_string(), "Invalid,X-B:2".to_string());
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(state.jobs.lock().await.is_empty(), "no job may be queued");
}

#[tokio::test]
async fn test_get_scan_handler_accepts_a_comma_bearing_header_value() {
    // Regression for the interaction between the comma-packed `header=` query
    // form and strict header validation: `Accept: text/html,application/xhtml+xml`
    // must not be chopped into a nameless fragment and 400 the request.
    let state = make_state(None, None, false, true, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "http://127.0.0.1:1/".to_string());
    params.insert(
        "header".to_string(),
        "Accept: text/html,application/xhtml+xml".to_string(),
    );
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
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
    // A nameless pair (`=v`) is dropped. It used to be preserved to match the
    // raw `split_once('=')` contract, but no caller could do anything useful
    // with it: `compose_cookie_header` re-serializes it as a leading `=v` that
    // no server parses as a cookie, and the discovery stage spent a probe per
    // scan injecting into a cookie that cannot exist. The raw-HTTP and HAR
    // parsers already dropped nameless cookies, so this also makes the four
    // cookie sources agree.
    let leading_eq = split_cookie_pairs("=v; k=w");
    assert_eq!(leading_eq, vec![("k".to_string(), "w".to_string())]);
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

/// Reflects while "authenticated", then answers `401` to everything once
/// `healthy_hits` requests have been served — an app whose session expires
/// partway through a scan. The post-scan session probe is the last request the
/// job makes, so it always lands after the flip.
async fn start_expiring_target_server(healthy_hits: usize) -> SocketAddr {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let handler = {
        let hits = hits.clone();
        move |Query(q): Query<Map<String, String>>| {
            let hits = hits.clone();
            async move {
                if hits.fetch_add(1, AtomicOrdering::SeqCst) < healthy_hits {
                    let mut body = String::from("<html><body>");
                    for (k, v) in &q {
                        body.push_str(&format!("<div>{k}={v}</div>"));
                    }
                    body.push_str("</body></html>");
                    (
                        StatusCode::OK,
                        [("content-type", "text/html; charset=utf-8")],
                        body,
                    )
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        [("content-type", "text/html; charset=utf-8")],
                        "<html><body>session expired</body></html>".to_string(),
                    )
                }
            }
        }
    };
    let app = Router::new()
        .route("/", any(handler.clone()))
        .route("/{*rest}", any(handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind expiring target listener");
    let addr = listener.local_addr().expect("expiring target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

/// Run a scan job against `url` with `cookie` and return (status, error_message).
async fn run_job_and_settle(
    id: &str,
    url: String,
    cookie: Option<&str>,
) -> (JobStatus, Option<String>) {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.to_string(), test_job(JobStatus::Queued, None, ""));
    }
    let opts = ScanOptions {
        skip_mining: Some(true),
        worker: Some(4),
        encoders: Some(vec!["none".to_string()]),
        cookie: cookie.map(|c| c.to_string()),
        ..ScanOptions::default()
    };
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        run_scan_job(state.clone(), id.to_string(), url, opts, false, false),
    )
    .await;
    assert!(run.is_ok(), "scan should finish in time");
    let jobs = state.jobs.lock().await;
    let job = jobs.get(id).expect("job");
    (job.status.clone(), job.error_message.clone())
}

// Issue #1273 on the server surface. A job whose session dies mid-scan used to
// settle `done` with zero findings — indistinguishable from a clean target, and
// the exact silent false negative the CLI already guards against. It must now
// settle `error` and name the signal.
#[tokio::test]
async fn test_run_scan_job_reports_a_session_that_died_mid_scan() {
    // Healthy long enough to capture the baseline and start scanning, then 401
    // for the rest — including the post-scan probe.
    let addr = start_expiring_target_server(3).await;
    let (status, error) = run_job_and_settle(
        "session-lost",
        format!("http://{}/?a=1&b=2", addr),
        Some("sid=deadbeef"),
    )
    .await;

    assert_eq!(
        status,
        JobStatus::Error,
        "a job that lost its session must not settle as a clean done"
    );
    let error = error.expect("error_message must name the signal");
    assert!(
        error.starts_with(crate::cmd::error_codes::SESSION_LOST),
        "error_message must be machine-matchable: {error}"
    );
    assert!(
        error.contains("401"),
        "the triggering signal is carried verbatim: {error}"
    );
}

// The other baseline path. With `skip_ast_analysis` there is no preflight
// response to derive a fingerprint from, so the job pays for one dedicated
// capture request instead — a branch nothing else exercises, and
// `skip_ast_analysis` is an ordinary scan option.
#[tokio::test]
async fn test_run_scan_job_detects_session_loss_without_the_ast_preflight() {
    let addr = start_expiring_target_server(3).await;
    let state = make_state(None, None, false, false, "cb");
    let id = "session-lost-no-ast".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }
    let opts = ScanOptions {
        skip_mining: Some(true),
        skip_ast_analysis: Some(true),
        worker: Some(4),
        encoders: Some(vec!["none".to_string()]),
        cookie: Some("sid=deadbeef".to_string()),
        ..ScanOptions::default()
    };
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/?a=1", addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(run.is_ok(), "scan should finish in time");

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job");
    assert_eq!(
        job.status,
        JobStatus::Error,
        "the dedicated-capture path must detect loss too: {:?}",
        job.error_message
    );
    assert!(
        job.error_message
            .as_deref()
            .is_some_and(|m| m.starts_with(crate::cmd::error_codes::SESSION_LOST)),
        "{:?}",
        job.error_message
    );
}

// The control: same credentials, a target that never expires. Monitoring must
// not turn a healthy authenticated scan into an error.
#[tokio::test]
async fn test_run_scan_job_with_a_live_session_still_settles_done() {
    let addr = start_reflecting_target_server().await;
    let (status, error) = run_job_and_settle(
        "session-alive",
        format!("http://{}/?a=1", addr),
        Some("sid=deadbeef"),
    )
    .await;
    assert_eq!(status, JobStatus::Done, "error_message={error:?}");
    assert!(error.is_none(), "{error:?}");
}

// Monitoring is opt-in-by-context: with no credentials there is no session to
// lose, and the job must not pay for a probe or change its verdict. Guards the
// "off, and free" promise for the overwhelmingly common unauthenticated job.
#[tokio::test]
async fn test_run_scan_job_without_credentials_is_untouched_by_session_monitoring() {
    let addr = start_expiring_target_server(3).await;
    let (status, error) =
        run_job_and_settle("session-none", format!("http://{}/?a=1", addr), None).await;
    assert_eq!(
        status,
        JobStatus::Done,
        "an unauthenticated job has no session to lose: {error:?}"
    );
    assert!(error.is_none(), "{error:?}");
}

#[tokio::test]
async fn test_run_scan_job_wires_live_params_tested_counter() {
    // End-to-end at the server layer: run_scan_job must thread the live
    // `params_done` counter into run_scanning so `progress.params_tested`
    // reflects the discovered parameters. Against a reflecting target with
    // three query params, the scan should discover >= 2 and end with
    // params_tested == params_total (the live increments + the natural-
    // completion store agree). The per-worker live mechanism itself is
    // covered by scanning::tests::test_run_scanning_increments_params_done_counter.
    let addr = start_reflecting_target_server().await;
    let state = make_state(None, None, false, false, "cb");
    let id = "params-tested-wiring".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }
    let opts = ScanOptions {
        skip_mining: Some(true),
        worker: Some(4),
        encoders: Some(vec!["none".to_string()]),
        ..ScanOptions::default()
    };
    let progress = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).expect("job").progress.clone()
    };
    let url = format!("http://{}/?a=1&b=2&c=3", addr);
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_scan_job(state.clone(), id.clone(), url, opts, false, false),
    )
    .await;
    assert!(run.is_ok(), "scan should finish in time");

    use std::sync::atomic::Ordering::Relaxed;
    let total = progress.params_total.load(Relaxed);
    let tested = progress.params_tested.load(Relaxed);
    assert!(
        total >= 2,
        "reflecting target with 3 query params should discover >= 2, got {}",
        total
    );
    assert_eq!(
        tested, total,
        "server must feed the live params_done counter so params_tested reaches params_total"
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
        insecure: None,
        follow_redirects: None,
        skip_mining: None,
        skip_discovery: None,
        deep_scan: None,
        skip_ast_analysis: None,
        analyze_external_js: None,
        // Exercise the ON path: opts -> job_runner -> ScanArgs -> analysis gate.
        detect_outdated_libs: Some(true),
        rate_limit: None,
        scan_timeout: None,
        ..ScanOptions::default()
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
async fn test_run_scan_job_scan_timeout_marks_cancelled_with_partial_results() {
    // End-to-end: a per-request `scan_timeout` must bound the whole scan. The
    // target reflects (neutralized) values after a 120ms delay, and with a
    // single worker the payload sweep serializes well past the 1s budget — so
    // the budget trips mid-scan. The job must settle as `cancelled` (not Done
    // at a bogus 100%), expose whatever partial results it has, and record an
    // error_message that distinguishes a timeout from a user-initiated cancel.
    let addr = start_slow_reflecting_target_server().await;
    let state = make_state(None, None, false, false, "callback");
    let id = "scan-timeout-job".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let opts = ScanOptions {
        encoders: Some(vec!["none".to_string()]),
        worker: Some(1),
        // Skip mining so the (slow) traffic is the reflective-param payload
        // sweep rather than dictionary guessing — keeps the test focused.
        skip_mining: Some(true),
        scan_timeout: Some(1),
        ..ScanOptions::default()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/?q=test", addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(
        run.is_ok(),
        "run_scan_job should return once the budget trips"
    );

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should remain");
    assert_eq!(
        job.status,
        JobStatus::Cancelled,
        "a budget-tripped scan must settle as cancelled, not done"
    );
    let msg = job
        .error_message
        .as_deref()
        .expect("a timeout must record an error_message");
    assert!(
        msg.contains("scan_timeout"),
        "error_message should mention scan_timeout, got: {msg}"
    );
    assert!(
        job.results.is_some(),
        "partial results vector should be attached even on timeout"
    );
    assert!(job.finished_at_ms.is_some());
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
async fn test_run_scan_job_unreachable_target_fires_error_webhook() {
    // Regression for F1: an unreachable (but parseable) target must still fire a
    // terminal webhook, and that webhook is now dispatched through the scan
    // target's own proxy/TLS/redirect-aware client (previously a bare default
    // client, which silently failed to deliver whenever the callback host was
    // only reachable via the scan's configured proxy). We can't wire a proxy in
    // a unit test, but we lock in the observable contract subscribers depend on:
    // unreachable → a webhook with status="error", and the job settles Error.
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    // Webhook capture server (bound first so it can't collide with the port we
    // free below).
    let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let fired = Arc::new(AtomicBool::new(false));
    let (tx, rx) = oneshot::channel::<()>();
    let tx_shared = Arc::new(Mutex::new(Some(tx)));
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

    // Reserve then immediately drop a port so a connection there is refused —
    // a reliably unreachable but well-formed http target.
    let dead_addr = {
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind throwaway listener");
        l.local_addr().expect("throwaway local addr")
    };

    let state = make_state(None, None, false, false, "callback");
    let id = "unreachable-webhook-test".to_string();
    let mut job = test_job(JobStatus::Queued, None, "");
    job.callback_url = Some(format!("http://{}/hook", webhook_addr));
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), job);
    }

    let opts = ScanOptions {
        // Short request timeout; connection-refused returns well within it.
        timeout: Some(5),
        callback_url: Some(format!("http://{}/hook", webhook_addr)),
        ..ScanOptions::default()
    };

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        run_scan_job(
            state.clone(),
            id.clone(),
            format!("http://{}/", dead_addr),
            opts,
            false,
            false,
        ),
    )
    .await;
    assert!(
        run.is_ok(),
        "run_scan_job should return promptly for an unreachable target"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), rx).await;
    let payload = captured
        .lock()
        .await
        .clone()
        .expect("unreachable scan must still fire a terminal webhook");
    assert_eq!(
        payload["status"], "error",
        "unreachable target must emit status=error (got payload: {})",
        payload
    );
    assert_eq!(payload["scan_id"], serde_json::Value::String(id.clone()));

    let jobs = state.jobs.lock().await;
    assert_eq!(
        jobs.get(&id).expect("job still present").status,
        JobStatus::Error
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
    params.insert("url".to_string(), "http://127.0.0.1:1/".to_string());

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
        rate_limit: None,
        scan_timeout: None,
        max_concurrent_scans: 100,
        allowed_hosts: None,
        max_retained_scans: 1000,
        max_body_bytes: 1_048_576,
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
        rate_limit: None,
        scan_timeout: None,
        max_concurrent_scans: 100,
        allowed_hosts: None,
        max_retained_scans: 1000,
        max_body_bytes: 1_048_576,
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
async fn test_cancel_scan_handler_on_terminal_job_is_a_noop() {
    // Cancelling a scan that already finished must not claim `cancelled: true`
    // — nothing was actually stopped, and the stored status must not change.
    let state = make_state(None, None, false, false, "cb");
    let scan_id = "done-cancel-test-id".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(scan_id.clone(), test_job(JobStatus::Done, None, ""));
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
    assert_eq!(parsed["data"]["cancelled"], false);
    assert_eq!(parsed["data"]["previous_status"], "done");

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&scan_id).expect("job still exists");
    assert_eq!(job.status, JobStatus::Done);
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

/// Jobs sharing a `queued_at_ms` millisecond must list in a deterministic
/// order (scan_id ascending as the tiebreak), not the nondeterministic HashMap
/// iteration order — otherwise offset/limit pagination over the unstable order
/// could skip or duplicate an entry across pages.
#[tokio::test]
async fn test_list_scans_handler_deterministic_tiebreak_on_equal_queued_at() {
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        // Insert in a deliberately non-sorted id order, all with the SAME
        // queued_at_ms so only the tiebreak decides ordering.
        for id in ["m", "a", "z", "c", "b"] {
            let mut job = test_job(JobStatus::Done, None, "");
            job.queued_at_ms = 1_700_000_000_000;
            jobs.insert(id.to_string(), job);
        }
    }

    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let ids: Vec<&str> = parsed["data"]["scans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["scan_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["a", "b", "c", "m", "z"],
        "equal-timestamp jobs must be ordered by scan_id ascending"
    );
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
            target: "not-http".to_string(),
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
            target: "http://example.com".to_string(),
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
            target: "http://127.0.0.1:1/unreachable".to_string(),
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
    assert!(validate_scan_options(&mut ScanOptions::default()).is_ok());
}

#[test]
fn test_validate_scan_options_rejects_malformed_headers() {
    // Both REST (`POST /scan`, `GET /scan`) and MCP funnel through here, so
    // this is the one place that has to know a header is unusable. reqwest
    // errors on the builder for these, which made *every* request in the job
    // fail — surfacing as the target being reported unreachable rather than as
    // the caller's malformed input.
    for bad in [
        "no-colon-at-all",
        "X Custom: v",             // space in the name
        "X-Bad: a\r\nInjected: 1", // CRLF in the value
        "X-Null: a\0b",            // NUL in the value
    ] {
        let mut opts = ScanOptions {
            header: Some(vec![bad.to_string()]),
            ..ScanOptions::default()
        };
        assert!(
            validate_scan_options(&mut opts).is_err(),
            "header {bad:?} must be rejected"
        );
    }

    // Legal headers still pass, including obs-text in a value (`café`), which
    // `HeaderValue` accepts and an over-strict check would have broken.
    let mut ok = ScanOptions {
        header: Some(vec![
            "X-Api-Key: abc123".to_string(),
            "Accept: text/html,application/xhtml+xml".to_string(),
            "X-Note: caf\u{e9}".to_string(),
        ]),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut ok).is_ok());
}

#[test]
fn test_validate_scan_options_rejects_malformed_user_agent_and_cookie() {
    // `user_agent` and `cookie` also become header values on the wire, so a
    // control byte in either fails reqwest's builder for every request — the
    // same "live target reported unreachable" failure the header check exists
    // to prevent. They were previously unvalidated.
    let mut bad_ua = ScanOptions {
        user_agent: Some("Mozilla/5.0\r\nX-Injected: 1".to_string()),
        ..ScanOptions::default()
    };
    assert!(
        validate_scan_options(&mut bad_ua).is_err(),
        "a CRLF in user_agent must be rejected"
    );

    let mut bad_cookie = ScanOptions {
        cookie: Some("sid=abc\ndef".to_string()),
        ..ScanOptions::default()
    };
    assert!(
        validate_scan_options(&mut bad_cookie).is_err(),
        "a newline in a cookie value must be rejected"
    );

    // A UTF-8 User-Agent and an ordinary cookie still pass; an empty
    // user_agent (the "no override" sentinel) must not be rejected.
    let mut ok = ScanOptions {
        user_agent: Some("Mozilla/5.0 (caf\u{e9})".to_string()),
        cookie: Some("sid=abc; theme=dark".to_string()),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut ok).is_ok());

    let mut empty_ua = ScanOptions {
        user_agent: Some(String::new()),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut empty_ua).is_ok());
}

#[test]
fn test_validate_scan_options_rejects_out_of_range() {
    let mut bad_timeout = ScanOptions {
        timeout: Some(0),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_timeout).is_err());

    let mut bad_timeout_hi = ScanOptions {
        timeout: Some(9999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_timeout_hi).is_err());

    let mut bad_delay = ScanOptions {
        delay: Some(999_999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_delay).is_err());

    let mut bad_worker = ScanOptions {
        worker: Some(0),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_worker).is_err());

    let mut bad_worker_hi = ScanOptions {
        worker: Some(999_999),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_worker_hi).is_err());

    // scan_timeout: 0 is allowed (disabled); anything over the ceiling is not.
    let mut ok_disabled = ScanOptions {
        scan_timeout: Some(0),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut ok_disabled).is_ok());
    let mut bad_scan_timeout = ScanOptions {
        scan_timeout: Some(MAX_SCAN_TIMEOUT_SECS + 1),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut bad_scan_timeout).is_err());
}

#[test]
fn test_validate_scan_options_proxy() {
    // A routable proxy is accepted, matching the CLI startup gate.
    assert!(
        validate_scan_options(&mut ScanOptions {
            proxy: Some("http://127.0.0.1:8080".to_string()),
            ..ScanOptions::default()
        })
        .is_ok()
    );
    // An unroutable scheme parses fine but reqwest drops it (job would scan
    // DIRECT while reporting `done`), so server/MCP refuse it like the CLI.
    assert!(
        validate_scan_options(&mut ScanOptions {
            proxy: Some("ftp://127.0.0.1:8080".to_string()),
            ..ScanOptions::default()
        })
        .is_err()
    );
    // Garbage is refused too.
    assert!(
        validate_scan_options(&mut ScanOptions {
            proxy: Some("::not a url::".to_string()),
            ..ScanOptions::default()
        })
        .is_err()
    );
}

#[test]
fn test_validate_scan_options_waf_fields() {
    // waf_bypass must be one of the CLI's three modes.
    assert!(
        validate_scan_options(&mut ScanOptions {
            waf_bypass: Some("force".to_string()),
            ..ScanOptions::default()
        })
        .is_ok()
    );
    assert!(
        validate_scan_options(&mut ScanOptions {
            waf_bypass: Some("nonsense".to_string()),
            ..ScanOptions::default()
        })
        .is_err()
    );

    // force_waf is normalized/validated against the shared CLI WAF-name set.
    assert!(
        validate_scan_options(&mut ScanOptions {
            force_waf: Some("CloudFlare".to_string()),
            ..ScanOptions::default()
        })
        .is_ok()
    );
    assert!(
        validate_scan_options(&mut ScanOptions {
            force_waf: Some("notawaf".to_string()),
            ..ScanOptions::default()
        })
        .is_err()
    );

    // waf_min_confidence is a probability in [0.0, 1.0].
    assert!(
        validate_scan_options(&mut ScanOptions {
            waf_min_confidence: Some(0.5),
            ..ScanOptions::default()
        })
        .is_ok()
    );
    assert!(
        validate_scan_options(&mut ScanOptions {
            waf_min_confidence: Some(1.5),
            ..ScanOptions::default()
        })
        .is_err()
    );
}

#[tokio::test]
async fn test_start_scan_handler_rejects_out_of_range_timeout() {
    let state = make_state(None, None, false, false, "cb");
    let resp = start_scan_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: "http://example.com".to_string(),
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
async fn test_start_scan_handler_rejects_non_http_url() {
    // POST /scan must reject a non-http(s) target with a 400, matching
    // /preflight and the MCP scan tool — instead of queueing it and
    // silently finishing `done` with 0 findings.
    let state = make_state(None, None, false, false, "cb");
    for bad in [
        "ftp://x",
        "file:///etc/passwd",
        "example.com",
        "javascript:alert(1)",
    ] {
        let resp = start_scan_handler(
            State(state.clone()),
            HeaderMap::new(),
            Query(Map::new()),
            Ok(Json(ScanRequest {
                target: bad.to_string(),
                options: None,
            })),
        )
        .await
        .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "POST /scan should reject non-http(s) url {:?}",
            bad
        );
        let body = response_body_string(resp).await;
        assert!(
            body.contains("must start with http"),
            "expected scheme error for {:?}, got {}",
            bad,
            body
        );
    }
    // No jobs should have been queued for any of the rejected targets.
    assert!(state.jobs.lock().await.is_empty());
}

#[tokio::test]
async fn test_get_scan_handler_rejects_non_http_url() {
    // GET /scan must enforce the same http(s) scheme check as POST /scan.
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "ftp://x".to_string());
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body_string(resp).await;
    assert!(body.contains("must start with http"));
    assert!(state.jobs.lock().await.is_empty());
}

#[tokio::test]
async fn test_get_scan_handler_rejects_unparseable_numeric_query() {
    // A present-but-unparseable numeric query param is a 400, not a silent
    // fallback to the default. (`?timeout=0` is already rejected by range
    // validation; this covers the non-numeric / negative class.)
    for (key, val) in [
        ("timeout", "abc"),
        ("worker", "-5"),
        ("delay", "1.5"),
        ("scan_timeout", "soon"),
    ] {
        let state = make_state(None, None, false, false, "cb");
        let mut params = Map::new();
        params.insert("url".to_string(), "http://example.com".to_string());
        params.insert(key.to_string(), val.to_string());
        let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "GET /scan should reject {}={}",
            key,
            val
        );
        let body = response_body_string(resp).await;
        assert!(
            body.contains(key),
            "error should name the offending field {}, got {}",
            key,
            body
        );
        assert!(state.jobs.lock().await.is_empty());
    }
}

#[tokio::test]
async fn test_run_scan_job_unreachable_target_sets_error() {
    // A parseable but unreachable target (connection refused) must end as
    // Error with a connection-failed message — not `done` with 0 findings,
    // which a client cannot distinguish from "scanned, no XSS". Mirrors
    // /preflight's reachable:false / CONNECTION_FAILED behavior.
    let state = make_state(None, None, false, false, "cb");
    let id = "unreachable-scan".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }
    run_scan_job(
        state.clone(),
        id.clone(),
        "http://127.0.0.1:1/".to_string(),
        ScanOptions {
            timeout: Some(2),
            ..ScanOptions::default()
        },
        false,
        false,
    )
    .await;

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should exist");
    assert_eq!(job.status, JobStatus::Error);
    assert!(
        job.error_message
            .as_deref()
            .is_some_and(|m| m.contains("unreachable") && m.contains("CONNECTION_FAILED")),
        "expected connection-failed error message, got {:?}",
        job.error_message
    );
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
async fn test_purge_expired_jobs_is_throttled() {
    // SRV-3: the retention sweep is throttled to once per interval so it doesn't
    // run an O(n) scan (and lock the jobs map) on every request.
    let state = make_state(None, None, false, false, "cb");

    // First sweep runs (last_purge_ms starts at 0) and removes the expired job.
    {
        let mut jobs = state.jobs.lock().await;
        let mut old = test_job(JobStatus::Done, None, "");
        old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
        jobs.insert("old1".to_string(), old);
    }
    purge_expired_jobs(&state).await;
    assert!(
        !state.jobs.lock().await.contains_key("old1"),
        "first purge should run and remove the expired job"
    );

    // A second, immediate sweep is throttled: a freshly-inserted expired job
    // survives because the minimum interval hasn't elapsed yet.
    {
        let mut jobs = state.jobs.lock().await;
        let mut old = test_job(JobStatus::Done, None, "");
        old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
        jobs.insert("old2".to_string(), old);
    }
    purge_expired_jobs(&state).await;
    assert!(
        state.jobs.lock().await.contains_key("old2"),
        "second purge within the interval should be throttled (no-op)"
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

    mark_job_error(&state, &id, "http://x", "synthetic panic".to_string(), None).await;

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
        mark_job_error(
            &state,
            id,
            "http://x",
            "should-not-overwrite".to_string(),
            None,
        )
        .await;
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
        None,
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

    mark_job_error(&state, &id, "http://x", "late panic".to_string(), None).await;
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

#[tokio::test]
async fn test_start_scan_handler_503_when_at_capacity() {
    // F3: with max_concurrent_scans=1 and one active (Running) job, a new
    // submission is rejected with 503 and no job is queued.
    let mut state = make_state(None, None, false, false, "callback");
    state.max_concurrent_scans = 1;
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            "active-1".to_string(),
            test_job(JobStatus::Running, None, "http://busy/"),
        );
    }
    let resp = start_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: "http://example.com".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_body_string(resp).await;
    assert!(body.contains("at capacity"), "got {body}");
    // No new job queued — still just the one we seeded.
    assert_eq!(state.jobs.lock().await.len(), 1);
}

#[test]
fn test_sanitize_log_message_escapes_crlf() {
    use crate::utils::log::sanitize_log_message;
    // F11: clean strings are passed through unchanged (borrowed)...
    assert_eq!(sanitize_log_message("clean line").as_ref(), "clean line");
    // ...but CR/LF that could forge a log line are escaped, tab preserved.
    let forged = sanitize_log_message("http://x/\n[2026] [ERR] forged\r");
    assert!(
        !forged.contains('\n') && !forged.contains('\r'),
        "got {forged}"
    );
    assert!(forged.contains("\\n") && forged.contains("\\r"));
    assert!(sanitize_log_message("a\tb").contains('\t'));
}

#[tokio::test]
async fn test_list_scans_rejects_unparseable_limit() {
    // F12: a present-but-unparseable pagination value is a 400, matching GET
    // /scan rather than the old silent "return everything" fallback.
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("limit".to_string(), "abc".to_string());
    let resp = list_scans_handler(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_result_exposes_progress_for_error_jobs() {
    // F10: an Error job still surfaces its progress block (params discovered
    // before the failure) plus error_message, with a terminal poll interval of
    // 0 — not an opaque error with no progress.
    let state = make_state(None, None, false, false, "cb");
    {
        let mut jobs = state.jobs.lock().await;
        let mut job = test_job(JobStatus::Error, None, "http://x/");
        job.error_message = Some("boom".to_string());
        job.progress
            .params_total
            .store(4, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .params_tested
            .store(1, std::sync::atomic::Ordering::Relaxed);
        jobs.insert("errored".to_string(), job);
    }
    let resp = get_result_handler(
        State(state.clone()),
        HeaderMap::new(),
        Path("errored".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["data"]["status"], "error");
    assert_eq!(parsed["data"]["error_message"], "boom");
    assert_eq!(parsed["data"]["progress"]["params_total"], 4);
    assert_eq!(parsed["data"]["progress"]["params_tested"], 1);
    assert_eq!(parsed["data"]["progress"]["suggested_poll_interval_ms"], 0);
}

#[test]
fn test_parse_bool_query_accepts_common_truthy_forms() {
    // F13: 1/true/yes/on (any case, trimmed) are truthy; everything else false.
    for v in ["1", "true", "TRUE", "yes", "on", "  True  "] {
        let mut p = Map::new();
        p.insert("flag".to_string(), v.to_string());
        assert!(parse_bool_query(&p, "flag"), "should accept {v:?}");
    }
    for v in ["0", "false", "no", "off", "", "2"] {
        let mut p = Map::new();
        p.insert("flag".to_string(), v.to_string());
        assert!(!parse_bool_query(&p, "flag"), "should reject {v:?}");
    }
    assert!(!parse_bool_query(&Map::new(), "absent"));
}

#[test]
fn test_parse_opt_bool_query_preserves_absent() {
    // Absent -> None (so callers can apply a non-false default like insecure).
    assert_eq!(parse_opt_bool_query(&Map::new(), "insecure"), None);
    // Present truthy / falsy values map to Some(bool).
    for v in ["1", "true", "yes", "on", " TRUE "] {
        let mut p = Map::new();
        p.insert("insecure".to_string(), v.to_string());
        assert_eq!(parse_opt_bool_query(&p, "insecure"), Some(true), "{v:?}");
    }
    for v in ["0", "false", "no", "off", ""] {
        let mut p = Map::new();
        p.insert("insecure".to_string(), v.to_string());
        assert_eq!(parse_opt_bool_query(&p, "insecure"), Some(false), "{v:?}");
    }
}

#[test]
fn test_hydrate_preflight_target_insecure_default_and_override() {
    // Absent insecure -> scanner default (true). Explicit false -> validate.
    let mut opts = ScanOptions::default();
    let t = hydrate_preflight_target("https://example.com", &opts, 10).expect("hydrate default");
    assert!(
        t.insecure,
        "preflight target should default to insecure=true"
    );

    opts.insecure = Some(false);
    let t =
        hydrate_preflight_target("https://example.com", &opts, 10).expect("hydrate insecure=false");
    assert!(!t.insecure, "insecure=false must propagate to the target");
}

/// `/preflight` sends real discovery/mining traffic, and `analyze_parameters`
/// reads its pacing off the **target** (`target.delay` between probes,
/// `target.workers` for the semaphore) — not off `ScanArgs`. Both used to be
/// left at `parse_target`'s defaults, so the very options `/preflight`
/// validates (`delay`, `worker`) were accepted and then discarded.
#[test]
fn test_hydrate_preflight_target_carries_delay_and_workers() {
    let mut opts = ScanOptions::default();
    let t = hydrate_preflight_target("https://example.com", &opts, 10).expect("hydrate default");
    assert_eq!(
        t.delay,
        crate::cmd::scan::DEFAULT_DELAY_MS,
        "no delay requested -> the scanner default"
    );
    assert_eq!(
        t.workers, PREFLIGHT_DEFAULT_WORKERS,
        "no worker count requested -> preflight's long-standing default"
    );

    opts.delay = Some(250);
    opts.worker = Some(3);
    let t = hydrate_preflight_target("https://example.com", &opts, 10).expect("hydrate paced");
    assert_eq!(t.delay, 250, "delay must reach the discovery stage");
    assert_eq!(t.workers, 3, "worker must reach the discovery stage");
}

// ─────────────────────────────────────────────────────────────────────────
// job_runner.rs — analyze_external_js: Some(true) exercises the new
// fetch_and_analyze_external_js call added in run_scan_job.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_run_scan_job_analyze_external_js_produces_external_js_findings() {
    // Serve HTML that references a same-origin script with a DOM-XSS sink.
    // The inline HTML carries no sink so any finding must originate from
    // the external script fetched by fetch_and_analyze_external_js.
    let app = Router::new()
        .route(
            "/",
            any(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "text/html; charset=utf-8")],
                    r#"<html><head><script src="/sink.js"></script></head><body>ok</body></html>"#,
                )
            }),
        )
        .route(
            "/sink.js",
            any(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/javascript")],
                    "document.write(location.hash.substring(1));",
                )
            }),
        );

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ext-js test server");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "callback");
    let id = "ext-js-job".to_string();
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id.clone(), test_job(JobStatus::Queued, None, ""));
    }

    let opts = ScanOptions {
        analyze_external_js: Some(true),
        encoders: Some(vec!["none".to_string()]),
        worker: Some(1),
        skip_mining: Some(true),
        ..ScanOptions::default()
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
    assert!(run.is_ok(), "run_scan_job must complete in time");

    let jobs = state.jobs.lock().await;
    let job = jobs.get(&id).expect("job should remain");
    assert_eq!(job.status, JobStatus::Done);
    let results = job.results.as_ref().expect("results must be set");
    assert!(
        results.iter().any(|f| f.evidence.contains("sink.js")),
        "findings must reference sink.js from external JS analysis; findings: {:?}",
        results
    );
}

// ─────────────────────────────────────────────────────────────────────────
// handlers.rs — ?analyze_external_js=true is parsed and forwarded to
// ScanOptions, not rejected with a 400.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_scan_handler_analyze_external_js_param_is_accepted() {
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("url".to_string(), "http://127.0.0.1:1/".to_string());
    params.insert("analyze_external_js".to_string(), "true".to_string());

    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "?analyze_external_js=true must queue the scan, not return 400"
    );

    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let scan_id = parsed["data"]["scan_id"]
        .as_str()
        .expect("scan_id in response")
        .to_string();

    let jobs = state.jobs.lock().await;
    assert!(
        jobs.contains_key(&scan_id),
        "job must be present in the queue after handler returns"
    );
}

// Target/URL param unification: `target` is canonical (matches MCP + response),
// `url` stays as a backwards-compatible alias on the REST surface.
#[test]
fn test_scan_request_accepts_target_canonical_and_url_alias() {
    let from_target: ScanRequest =
        serde_json::from_str(r#"{"target":"http://a.test/?q=1"}"#).expect("target key parses");
    assert_eq!(from_target.target, "http://a.test/?q=1");

    let from_url: ScanRequest =
        serde_json::from_str(r#"{"url":"http://b.test/?q=1"}"#).expect("url alias parses");
    assert_eq!(from_url.target, "http://b.test/?q=1");

    // Neither key present is a hard error (target is required).
    assert!(serde_json::from_str::<ScanRequest>(r#"{"options":{}}"#).is_err());
}

#[tokio::test]
async fn test_get_scan_handler_accepts_target_query_param() {
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("target".to_string(), "http://127.0.0.1:1/?q=1".to_string());
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert!(
        parsed["data"]["scan_id"].as_str().is_some(),
        "a scan submitted via the `target` query param must return a scan_id"
    );
}

#[tokio::test]
async fn test_get_scan_handler_empty_target_falls_through_to_url_alias() {
    // A present-but-empty `target` must not shadow a real `url`, so a templated
    // `?target=&url=...` still scans the url (preserves the pre-rename behavior).
    let state = make_state(None, None, false, false, "cb");
    let mut params = Map::new();
    params.insert("target".to_string(), String::new());
    params.insert("url".to_string(), "http://127.0.0.1:1/?q=1".to_string());
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        parsed["data"]["target"], "http://127.0.0.1:1/?q=1",
        "empty target must fall through to the url alias"
    );
}

// ---------------------------------------------------------------------------
// Method / encoder normalization at the REST boundary.
//
// A JSON request body bypasses clap's value parsers exactly like a config file
// does (see `ScanConfig::normalize_and_validate`). `method` is put on the wire
// verbatim and compared case-sensitively downstream, so an un-normalized
// `"post"` was sent as the literal extension verb `post` — which real servers
// answer with 405/501 — and `"GET junk"` failed `Method::from_str` and silently
// degraded to GET. Either way the job settled `done` with zero findings and no
// error, indistinguishable from a genuinely clean target.
// ---------------------------------------------------------------------------

#[test]
fn test_validate_scan_options_normalizes_method() {
    let mut lower = ScanOptions {
        method: Some("post".to_string()),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut lower).is_ok());
    assert_eq!(lower.method.as_deref(), Some("POST"));

    for bad in ["TRACE", "GET junk", "   "] {
        let mut opts = ScanOptions {
            method: Some(bad.to_string()),
            ..ScanOptions::default()
        };
        assert!(
            validate_scan_options(&mut opts).is_err(),
            "method {bad:?} must be rejected"
        );
    }
}

#[test]
fn test_validate_scan_options_rejects_unknown_encoder() {
    let mut ok = ScanOptions {
        encoders: Some(vec!["url".to_string(), "html".to_string()]),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut ok).is_ok());

    let mut bad = ScanOptions {
        encoders: Some(vec!["url".to_string(), "urlencode".to_string()]),
        ..ScanOptions::default()
    };
    let err = validate_scan_options(&mut bad).expect_err("unknown encoder must be rejected");
    assert!(err.contains("unknown encoder 'urlencode'"), "got: {err}");
}

#[tokio::test]
async fn test_get_scan_handler_rejects_bad_method_and_encoder() {
    let state = make_state(None, None, false, false, "cb");

    let mut q = Map::new();
    q.insert("target".to_string(), "http://example.com/".to_string());
    q.insert("method".to_string(), "TRACE".to_string());
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(q))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let mut q = Map::new();
    q.insert("target".to_string(), "http://example.com/".to_string());
    q.insert("encoders".to_string(), "url,urlencode".to_string());
    let resp = get_scan_handler(State(state), HeaderMap::new(), Query(q))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body_string(resp).await;
    assert!(body.contains("unknown encoder"), "got: {body}");
}

#[tokio::test]
async fn test_run_scan_job_sends_uppercased_method_on_the_wire() {
    // Target that records the verb of every request it receives.
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_app = seen.clone();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind method-recorder listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route(
            "/{*rest}",
            any(move |req: axum::extract::Request| {
                let seen = seen_for_app.clone();
                async move {
                    seen.lock().await.push(req.method().as_str().to_string());
                    target_ok_handler().await
                }
            }),
        );
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "cb");
    let url = format!("http://{addr}/page?q=a");
    // Drive the public handler so the request goes through validation exactly
    // as a real client's would.
    let resp = start_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: url.clone(),
            options: Some(ScanOptions {
                method: Some("post".to_string()),
                timeout: Some(5),
                worker: Some(2),
                encoders: Some(vec!["none".to_string()]),
                skip_mining: Some(true),
                skip_ast_analysis: Some(true),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a lowercase method must be normalized, not rejected"
    );

    // Wait for the job to settle.
    for _ in 0..300 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let done = {
            let jobs = state.jobs.lock().await;
            jobs.values().all(|j| j.is_terminal())
        };
        if done && !seen.lock().await.is_empty() {
            break;
        }
    }

    let methods = seen.lock().await.clone();
    assert!(
        !methods.is_empty(),
        "the scan must have reached the target at least once"
    );
    assert!(
        !methods.iter().any(|m| m == "post"),
        "no request may go out with the un-normalized lowercase verb; saw {methods:?}"
    );
    assert!(
        methods.iter().all(|m| *m == m.to_ascii_uppercase()),
        "every wire method must be uppercase; saw {methods:?}"
    );
}

#[tokio::test]
async fn test_preflight_handler_rejects_bad_method() {
    let state = make_state(None, None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: "http://example.com/".to_string(),
            options: Some(ScanOptions {
                method: Some("TRACE".to_string()),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_cors_sets_vary_origin_even_when_origin_is_not_allowed() {
    // With an allow-list configured, the response depends on the request's
    // Origin whether or not it matched. Emitting `Vary: Origin` only on a match
    // let a shared cache store the no-ACAO response built for a disallowed
    // origin and replay it to an allowed one.
    let state = make_state(
        None,
        Some(vec!["http://localhost:3000"]),
        false,
        false,
        "callback",
    );

    let mut denied = HeaderMap::new();
    denied.insert("Origin", HeaderValue::from_static("http://evil.example"));
    let headers = build_cors_headers(&state, &denied);
    assert!(
        headers.get("Access-Control-Allow-Origin").is_none(),
        "a disallowed origin must not be reflected"
    );
    assert_eq!(
        headers.get("Vary").and_then(|v| v.to_str().ok()),
        Some("Origin"),
        "Vary: Origin must be present on the deny path too"
    );

    // Also present when the request carries no Origin at all.
    let headers = build_cors_headers(&state, &HeaderMap::new());
    assert_eq!(
        headers.get("Vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
}

#[tokio::test]
async fn test_scan_options_max_payloads_per_param_is_honored_and_bounded() {
    // The REST API accepted no per-parameter payload cap at all: the field was
    // pinned to 0 in ScanArgs regardless of the request, so the MCP tool's
    // `max_payloads_per_param` had no REST equivalent.
    let mut ok = ScanOptions {
        max_payloads_per_param: Some(25),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut ok).is_ok());

    let mut too_big = ScanOptions {
        max_payloads_per_param: Some(crate::job::MAX_PAYLOADS_PER_PARAM + 1),
        ..ScanOptions::default()
    };
    let err = validate_scan_options(&mut too_big).expect_err("absurd cap must be rejected");
    assert!(err.contains("max_payloads_per_param"), "got: {err}");

    // GET /scan parses it off the query string like the other numeric options.
    let state = make_state(None, None, false, false, "cb");
    let mut q = Map::new();
    q.insert("target".to_string(), "http://example.com/".to_string());
    q.insert("max_payloads_per_param".to_string(), "abc".to_string());
    let resp = get_scan_handler(State(state), HeaderMap::new(), Query(q))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body_string(resp).await;
    assert!(
        body.contains("max_payloads_per_param must be a valid number"),
        "got: {body}"
    );
}

#[tokio::test]
async fn test_run_scan_job_omits_user_agent_header_when_explicitly_empty() {
    // `apply_headers_ua_cookies` copies target.headers verbatim, so pushing an
    // empty entry put a literal `User-Agent:` on every outbound request while
    // the (empty-checked) `target.user_agent` sent none. MCP already filters
    // this; the REST path did not.
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_app = seen.clone();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ua-recorder listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route(
            "/{*rest}",
            any(move |req: axum::extract::Request| {
                let seen = seen_for_app.clone();
                async move {
                    seen.lock().await.push(
                        req.headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                    );
                    target_ok_handler().await
                }
            }),
        );
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let state = make_state(None, None, false, false, "cb");
    let job_id = "ua-empty".to_string();
    let url = format!("http://{addr}/page?q=a");
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(job_id.clone(), test_job(JobStatus::Queued, None, &url));
    }
    run_scan_job(
        state,
        job_id,
        url,
        ScanOptions {
            user_agent: Some(String::new()),
            timeout: Some(5),
            worker: Some(2),
            encoders: Some(vec!["none".to_string()]),
            skip_mining: Some(true),
            skip_ast_analysis: Some(true),
            max_payloads_per_param: Some(1),
            ..ScanOptions::default()
        },
        false,
        false,
    )
    .await;

    let uas = seen.lock().await.clone();
    assert!(!uas.is_empty(), "the scan must have reached the target");
    assert!(
        !uas.iter().any(|ua| ua.as_deref() == Some("")),
        "an explicitly-empty user_agent must not put a blank User-Agent header on the wire; saw {uas:?}"
    );
}

#[tokio::test]
async fn test_run_scan_job_honors_max_payloads_per_param() {
    // Proves the option reaches ScanArgs, not just that it validates: the REST
    // path hard-coded `max_payloads_per_param: 0`, so a request asking for a
    // small cap fanned out exactly as far as one asking for none.
    async fn requests_for(cap: Option<usize>, addr: SocketAddr, job_id: &str) -> u64 {
        let state = make_state(None, None, false, false, "cb");
        let url = format!("http://{addr}/page?q=a");
        let progress = {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(job_id.to_string(), test_job(JobStatus::Queued, None, &url));
            jobs.get(job_id).expect("job").progress.clone()
        };
        run_scan_job(
            state,
            job_id.to_string(),
            url,
            ScanOptions {
                max_payloads_per_param: cap,
                timeout: Some(5),
                worker: Some(4),
                encoders: Some(vec!["none".to_string()]),
                skip_mining: Some(true),
                skip_ast_analysis: Some(true),
                ..ScanOptions::default()
            },
            false,
            false,
        )
        .await;
        progress
            .requests_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    let addr = start_inert_reflecting_target_server().await;
    let capped = requests_for(Some(1), addr, "cap-1").await;
    let uncapped = requests_for(None, addr, "cap-none").await;
    assert!(
        capped < uncapped,
        "max_payloads_per_param must bound the scan's fan-out: capped={capped} uncapped={uncapped}"
    );
}

#[tokio::test]
async fn test_suggested_poll_interval_is_monotonic_in_progress() {
    // Drives the real handler: the advised delay must never *grow* as a running
    // scan progresses. It used to (2000ms below 10%, 3000ms between 10% and
    // 80%), telling a client that had just seen progress to slow down.
    use std::sync::atomic::Ordering::Relaxed;

    let state = make_state(None, None, false, false, "cb");
    let id = "poll-ladder".to_string();
    let progress = {
        let mut jobs = state.jobs.lock().await;
        let job = test_job(JobStatus::Running, None, "http://example.com/");
        job.progress.params_total.store(100, Relaxed);
        let progress = job.progress.clone();
        jobs.insert(id.clone(), job);
        progress
    };

    let mut prev = u64::MAX;
    for tested in 0..=100u32 {
        progress.params_tested.store(tested, Relaxed);
        let resp = get_result_handler(
            State(state.clone()),
            HeaderMap::new(),
            Path(id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();
        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
        let now = parsed["data"]["progress"]["suggested_poll_interval_ms"]
            .as_u64()
            .expect("suggested_poll_interval_ms");
        assert!(
            now <= prev,
            "poll interval must not increase with progress: {tested}/100 advises {now}ms after {prev}ms"
        );
        prev = now;
    }
    assert_eq!(
        prev, 1000,
        "a nearly-finished scan should be polled fastest"
    );
}

// ---- /preflight success path ----
//
// Only the rejection paths (bad URL, bad method, missing auth, unreachable
// target) were covered. Everything after the reachability probe — building the
// preflight ScanArgs, running discovery, and turning the discovered params into
// the estimate the REST contract publishes — had no test, so the shape of a
// successful response and the arithmetic behind `estimated_total_requests`
// could drift silently.

/// A reachable, reflecting target must come back `reachable: true` with one
/// entry per discovered param and a total that is exactly the sum of the
/// per-param estimates. Clients budget scan time off these numbers.
#[tokio::test]
async fn test_preflight_handler_success_reports_params_and_consistent_estimate() {
    let addr = start_reflecting_target_server().await;
    let state = make_state(None, None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: format!("http://{addr}/?q=1"),
            options: Some(ScanOptions {
                timeout: Some(5),
                skip_mining: Some(true),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let parsed: serde_json::Value =
        serde_json::from_str(&response_body_string(resp).await).expect("json");
    let data = &parsed["data"];
    assert_eq!(data["reachable"], true);
    assert_eq!(data["method"], "GET");

    let params = data["params"].as_array().expect("params array");
    assert_eq!(
        data["params_discovered"].as_u64().expect("count") as usize,
        params.len(),
        "params_discovered must match the params array length"
    );
    assert!(
        !params.is_empty(),
        "a reflecting target must yield at least one discovered param, got {data}"
    );
    for p in params {
        assert!(p["name"].is_string(), "each param must carry a name: {p}");
        assert!(
            p["location"].is_string(),
            "each param must carry a location: {p}"
        );
    }

    let summed: u64 = params
        .iter()
        .map(|p| p["estimated_requests"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(
        data["estimated_total_requests"].as_u64().expect("total"),
        summed,
        "the total must be the sum of the per-param estimates"
    );
    assert!(summed > 0, "a scannable param must bill a nonzero estimate");
}

// ---- /preflight pacing: rate_limit, delay and worker are not cosmetic ----
//
// Preflight is a *network* operation — discovery and mining probe the target
// dozens of times — but it used to run flat out: no limiter was bound around
// `analyze_parameters`, and `hydrate_preflight_target` left `delay`/`workers`
// at `parse_target`'s defaults. So the operator's `--rate-limit` (documented as
// applying to every submitted scan) and the caller's own pacing options were
// both silently void on this route.

/// A reflecting target that counts every request it serves.
async fn start_counting_reflecting_target_server()
-> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    let hits = Arc::new(AtomicUsize::new(0));
    let handler = {
        let hits = hits.clone();
        move |Query(q): Query<Map<String, String>>| {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, AtomicOrdering::SeqCst);
                let mut body = String::from("<html><body>");
                for (k, v) in &q {
                    body.push_str(&format!("<div>{k}={v}</div>"));
                }
                body.push_str("</body></html>");
                (
                    StatusCode::OK,
                    [("content-type", "text/html; charset=utf-8")],
                    body,
                )
            }
        }
    };
    let app = Router::new()
        .route("/", any(handler.clone()))
        .route("/{*rest}", any(handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind counting target listener");
    let addr = listener.local_addr().expect("counting target local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // These two tests assert on *timing*, so a target that is not accepting yet
    // would both zero the request count and shorten the measured window. Wait
    // for a real connection instead of a fixed sleep. Connecting sends no
    // request, so `hits` is untouched.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return (addr, hits);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("counting target server never accepted a connection");
}

/// The server-wide `--rate-limit` must bound `/preflight` traffic the way it
/// bounds `/scan` traffic. Before the fix this exact call sent ~20 requests in
/// under 100 ms with `state.rate_limit = Some(20)` set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_preflight_honors_server_wide_rate_limit() {
    const RATE: u64 = 20; // requests/second -> 50 ms apart
    let (addr, hits) = start_counting_reflecting_target_server().await;
    let mut state = make_state(None, None, false, false, "cb");
    state.rate_limit = Some(RATE as u32);

    let started = std::time::Instant::now();
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: format!("http://{addr}/?q=1&z=2"),
            options: Some(ScanOptions {
                timeout: Some(5),
                skip_mining: Some(true),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);

    let sent = hits.load(std::sync::atomic::Ordering::SeqCst) as u64;
    assert!(
        sent >= 8,
        "preflight must actually probe the target for the pacing bound to mean \
         anything (sent {sent})"
    );
    // GCRA with a burst of one admits the first request immediately and spaces
    // the rest by 1/RATE. Allow generous slack (60% of the theoretical floor)
    // so this asserts "throttled" rather than an exact schedule.
    let floor_ms = (sent - 1) * 1000 / RATE * 6 / 10;
    assert!(
        elapsed.as_millis() as u64 >= floor_ms,
        "server-wide rate_limit={RATE} must throttle /preflight: {sent} requests \
         in {}ms, expected at least {floor_ms}ms",
        elapsed.as_millis()
    );
}

/// `delay` and `worker` reach `analyze_parameters` through the target, so a
/// single worker with a per-probe delay must serialize preflight's discovery
/// traffic. Both options were previously dropped on the floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_preflight_honors_delay_and_worker_options() {
    const DELAY_MS: u64 = 60;
    let (addr, hits) = start_counting_reflecting_target_server().await;
    let state = make_state(None, None, false, false, "cb");

    let started = std::time::Instant::now();
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: format!("http://{addr}/?q=1&z=2"),
            options: Some(ScanOptions {
                timeout: Some(5),
                skip_mining: Some(true),
                delay: Some(DELAY_MS),
                worker: Some(1),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);

    let sent = hits.load(std::sync::atomic::Ordering::SeqCst) as u64;
    assert!(sent >= 8, "preflight must probe the target (sent {sent})");
    // One worker sleeping DELAY_MS after each probe: not every send is inside a
    // delayed loop, so hold the bound to half the sends.
    let floor_ms = sent / 2 * DELAY_MS;
    assert!(
        elapsed.as_millis() as u64 >= floor_ms,
        "delay={DELAY_MS}ms with worker=1 must pace /preflight: {sent} requests \
         in {}ms, expected at least {floor_ms}ms",
        elapsed.as_millis()
    );
}

/// `encoders: ["none"]` collapses the encoder fan-out factor to 1, so the
/// estimate must come out strictly lower than the multi-encoder default. This
/// is the one knob in the request that changes the arithmetic rather than the
/// param set, and it is what callers reach for to preview a cheap scan.
#[tokio::test]
async fn test_preflight_handler_encoder_none_lowers_the_estimate() {
    let addr = start_reflecting_target_server().await;

    async fn estimate_for(addr: SocketAddr, encoders: Option<Vec<String>>) -> u64 {
        let state = make_state(None, None, false, false, "cb");
        let resp = preflight_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
            Ok(Json(ScanRequest {
                target: format!("http://{addr}/?q=1"),
                options: Some(ScanOptions {
                    timeout: Some(5),
                    skip_mining: Some(true),
                    encoders,
                    ..ScanOptions::default()
                }),
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let parsed: serde_json::Value =
            serde_json::from_str(&response_body_string(resp).await).expect("json");
        parsed["data"]["estimated_total_requests"]
            .as_u64()
            .expect("total")
    }

    let default_estimate = estimate_for(addr, None).await;
    let none_estimate = estimate_for(addr, Some(vec!["none".to_string()])).await;
    assert!(
        default_estimate > 0 && none_estimate > 0,
        "both runs must discover the reflecting param (default={default_estimate}, none={none_estimate})"
    );
    assert!(
        none_estimate < default_estimate,
        "`encoders: [none]` must shrink the estimate; got none={none_estimate} default={default_estimate}"
    );
}

// ---------------------------------------------------------------------------
// ScanOptions deserialization: unknown fields are refused, MCP spellings map.
//
// Before `deny_unknown_fields`, serde dropped anything it did not recognise,
// so a misspelled or MCP-spelled option was accepted with 200 and silently
// discarded — including `cookies` / `headers` / `blind_callback_url`, which
// meant a scan ran unauthenticated and reported a clean result.
// ---------------------------------------------------------------------------

#[test]
fn test_scan_options_rejects_unknown_field() {
    let err = serde_json::from_str::<ScanOptions>(r#"{"totally_bogus": 123}"#)
        .expect_err("an unknown option must not deserialize");
    // The message names the offending key, which is what makes the 400 useful.
    assert!(
        err.to_string().contains("totally_bogus"),
        "error should name the unknown field, got: {err}"
    );
}

#[test]
fn test_scan_options_accepts_mcp_spellings() {
    // The four options MCP spells differently. Each must land on the REST
    // field rather than being dropped.
    let opts: ScanOptions = serde_json::from_str(
        r#"{
            "cookies": ["sess=abc", "lang=ko"],
            "headers": ["X-A: 1"],
            "workers": 7,
            "blind_callback_url": "https://oob.example/cb"
        }"#,
    )
    .expect("MCP spellings must deserialize");

    // A cookie list collapses to the single header value the scanner takes.
    assert_eq!(opts.cookie.as_deref(), Some("sess=abc; lang=ko"));
    assert_eq!(opts.header.as_deref(), Some(&["X-A: 1".to_string()][..]));
    assert_eq!(opts.worker, Some(7));
    assert_eq!(opts.blind.as_deref(), Some("https://oob.example/cb"));
}

#[test]
fn test_scan_options_keeps_rest_spellings() {
    let opts: ScanOptions = serde_json::from_str(
        r#"{
            "cookie": "sess=abc",
            "header": ["X-A: 1"],
            "worker": 7,
            "blind": "https://oob.example/cb"
        }"#,
    )
    .expect("the original REST spellings must keep working");

    assert_eq!(opts.cookie.as_deref(), Some("sess=abc"));
    assert_eq!(opts.worker, Some(7));
    assert_eq!(opts.blind.as_deref(), Some("https://oob.example/cb"));
}

#[test]
fn test_scan_options_cookie_list_drops_empty_entries() {
    // `["a=b", ""]` must not produce a trailing `; ` in the header value.
    let opts: ScanOptions =
        serde_json::from_str(r#"{"cookies": ["a=b", "", "  ", "c=d"]}"#).unwrap();
    assert_eq!(opts.cookie.as_deref(), Some("a=b; c=d"));

    // An all-empty list is the same as not sending one at all.
    let opts: ScanOptions = serde_json::from_str(r#"{"cookies": ["", " "]}"#).unwrap();
    assert_eq!(opts.cookie, None);
}

// ---- Request-source gate: browser cross-site + Host (DNS rebinding) ----

/// Query params that make `get_scan_handler` submit a real scan, so a gate
/// test can assert on the "would have started a scan" path.
fn scan_query() -> Map<String, String> {
    let mut params = Map::new();
    params.insert("target".to_string(), "http://127.0.0.1:1/".to_string());
    params
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            axum::http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    headers
}

#[tokio::test]
async fn test_cross_site_browser_request_is_refused_and_starts_no_scan() {
    // The core regression: a page the operator merely visits could fire
    // `<img src="http://127.0.0.1:6664/scan?target=…&callback_url=http://attacker/">`,
    // and the results were POSTed to the attacker without them ever reading a
    // response. No API key is set here — that is the default configuration.
    let state = make_state(None, None, false, false, "callback");

    let resp = get_scan_handler(
        State(state.clone()),
        header_map(&[
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Dest", "image"),
        ]),
        Query(scan_query()),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        state.jobs.lock().await.is_empty(),
        "a refused request must not queue a scan"
    );
}

#[tokio::test]
async fn test_cross_site_gate_applies_to_every_authenticated_route() {
    let state = make_state(None, None, false, false, "callback");
    let cross_site = header_map(&[("Sec-Fetch-Site", "cross-site")]);

    let scan = start_scan_handler(
        State(state.clone()),
        cross_site.clone(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: "http://127.0.0.1:1/".to_string(),
            options: None,
        })),
    )
    .await
    .into_response();
    assert_eq!(scan.status(), StatusCode::FORBIDDEN);

    let list = list_scans_handler(State(state.clone()), cross_site.clone(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(list.status(), StatusCode::FORBIDDEN);

    let result = get_result_handler(
        State(state.clone()),
        cross_site.clone(),
        Path("whatever".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(result.status(), StatusCode::FORBIDDEN);

    let cancel = cancel_scan_handler(
        State(state.clone()),
        cross_site.clone(),
        Path("whatever".to_string()),
        Query(Map::new()),
    )
    .await
    .into_response();
    assert_eq!(cancel.status(), StatusCode::FORBIDDEN);

    // /health takes no API key but must still not answer a malicious page
    // probing whether a dalfox server is listening on this machine.
    let health = health_handler(State(state.clone()), cross_site, Query(Map::new()))
        .await
        .into_response();
    assert_eq!(health.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_health_stays_open_without_an_api_key() {
    // The gate must not turn /health into an authenticated endpoint.
    let state = make_state(Some("secret"), None, false, false, "callback");
    let resp = health_handler(State(state), HeaderMap::new(), Query(Map::new()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_non_browser_client_is_unaffected_by_the_gate() {
    // curl / CLI / agent clients send neither Origin nor Sec-Fetch-*; they must
    // keep working exactly as before.
    let state = make_state(None, None, false, false, "callback");
    let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(scan_query()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(state.jobs.lock().await.len(), 1);
}

#[tokio::test]
async fn test_same_origin_and_direct_navigation_pass_the_gate() {
    let state = make_state(None, None, false, false, "callback");

    for site in ["same-origin", "none"] {
        let resp = get_scan_handler(
            State(state.clone()),
            header_map(&[("Sec-Fetch-Site", site)]),
            Query(scan_query()),
        )
        .await
        .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Sec-Fetch-Site: {} must be allowed",
            site
        );
    }
}

#[tokio::test]
async fn test_configured_origin_is_allowed_and_others_are_not() {
    // The legitimate cross-site case: an operator wiring up a web UI. It is
    // cross-site by definition, so the Origin allow-list has to win over the
    // fetch-metadata check.
    let state = make_state(
        None,
        Some(vec!["http://localhost:3000", "regex:^https://ui\\.corp$"]),
        false,
        false,
        "callback",
    );
    let mut state = state;
    state.allowed_origin_regexes = vec![regex::Regex::new("^https://ui\\.corp$").unwrap()];

    for origin in ["http://localhost:3000", "https://ui.corp"] {
        let resp = get_scan_handler(
            State(state.clone()),
            header_map(&[("Origin", origin), ("Sec-Fetch-Site", "cross-site")]),
            Query(scan_query()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "{} must be allowed", origin);
    }

    let resp = get_scan_handler(
        State(state.clone()),
        header_map(&[("Origin", "https://evil.example")]),
        Query(scan_query()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_jsonp_mode_opts_out_of_the_cross_site_gate() {
    // JSONP is served to `<script src>`, which carries no Origin to validate,
    // so enabling it is an explicit decision to allow cross-origin reads.
    // Pinning it here so the exception can't be removed by accident — or added
    // to the non-JSONP path by accident.
    let state = make_state(None, None, false, true, "cb");
    let resp = get_scan_handler(
        State(state.clone()),
        header_map(&[("Sec-Fetch-Site", "cross-site")]),
        Query(scan_query()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_wildcard_origin_opts_out_of_the_cross_site_gate() {
    let state = make_state(None, Some(vec!["*"]), true, false, "callback");
    let resp = get_scan_handler(
        State(state),
        header_map(&[("Origin", "https://evil.example")]),
        Query(scan_query()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_untrusted_host_is_refused_but_ip_literals_and_localhost_pass() {
    // DNS rebinding: the attacker's own hostname re-resolves to this machine,
    // after which the browser calls the request same-origin and sends no
    // Origin at all — so only the Host header still names the attacker.
    let mut state = make_state(None, None, false, false, "callback");
    state.allowed_hosts = vec!["dalfox.internal".to_string()];

    let resp = get_scan_handler(
        State(state.clone()),
        header_map(&[
            ("Host", "evil.example:6664"),
            ("Sec-Fetch-Site", "same-origin"),
        ]),
        Query(scan_query()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        state.jobs.lock().await.is_empty(),
        "a rebound request must not queue a scan"
    );

    // An IP literal can't be rebound, `localhost` is us, and an operator-listed
    // name is explicitly trusted.
    for host in [
        "127.0.0.1:6664",
        "127.0.0.1",
        "[::1]:6664",
        "localhost:6664",
        "LOCALHOST",
        "dalfox.internal:6664",
    ] {
        let resp = get_scan_handler(
            State(state.clone()),
            header_map(&[("Host", host)]),
            Query(scan_query()),
        )
        .await
        .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Host {} must be allowed",
            host
        );
    }
}

/// End-to-end: a scan cancelled while it is still draining must survive the
/// retention cap, and the worker must still find its entry to write results
/// into.
///
/// `cancel_scan_handler` stamps `status = Cancelled` and `finished_at_ms`
/// immediately, so `is_terminal()` is true while the worker keeps running.
/// Retention used to evict on that alone: a few new submissions in that window
/// removed the entry, and the worker's `jobs.get_mut(&id)` then came back
/// `None` — partial results dropped, terminal webhook never fired, and a GET on
/// the scan_id the client is holding 404s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_but_draining_scan_survives_the_retention_cap() {
    let addr = start_slow_reflecting_target_server().await;
    let mut state = make_state(None, None, false, false, "cb");
    // Aggressive cap: any further admission wants to evict something.
    state.max_retained_scans = 1;

    let resp = start_scan_handler(
        State(state.clone()),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: format!("http://{addr}/?q=1"),
            options: Some(ScanOptions {
                timeout: Some(5),
                skip_mining: Some(true),
                ..ScanOptions::default()
            }),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let parsed: serde_json::Value =
        serde_json::from_str(&response_body_string(resp).await).expect("json");
    let scan_id = parsed["data"]["scan_id"]
        .as_str()
        .expect("scan_id")
        .to_string();

    // Wait for the worker to claim the job.
    for _ in 0..200 {
        {
            let jobs = state.jobs.lock().await;
            if jobs.get(&scan_id).map(|j| j.status.clone()) == Some(JobStatus::Running) {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    {
        let jobs = state.jobs.lock().await;
        assert_eq!(
            jobs.get(&scan_id).map(|j| j.status.clone()),
            Some(JobStatus::Running),
            "the scan must be running before we cancel it"
        );
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

    // The window this test is about: terminal on paper, worker still running.
    {
        let jobs = state.jobs.lock().await;
        let job = jobs.get(&scan_id).expect("job still present after cancel");
        assert!(job.is_terminal(), "cancel stamps the terminal state at once");
        assert!(
            job.worker_alive(),
            "the slow target guarantees the worker is still draining here"
        );
    }

    // Three more admissions, each of which runs enforce_retention_cap against a
    // cap of 1. Leases are held so these stay active and are never themselves
    // candidates — the cancelled job is the only one the old code could take.
    let mut _leases = Vec::new();
    for i in 0..3 {
        let (_id, lease) =
            try_admit_and_queue(&state, &format!("http://example.com/filler{i}"), None)
                .await
                .expect("admission succeeds");
        _leases.push(lease);
    }

    {
        let jobs = state.jobs.lock().await;
        assert!(
            jobs.contains_key(&scan_id),
            "a cancelled scan whose worker is still draining must not be evicted"
        );
    }

    // And the worker still has somewhere to put what it collected.
    for _ in 0..400 {
        {
            let jobs = state.jobs.lock().await;
            let job = jobs.get(&scan_id).expect("job must remain until it settles");
            if !job.worker_alive() {
                assert!(
                    job.results.is_some(),
                    "the draining worker must have written its results back"
                );
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("cancelled scan never settled");
}

#[tokio::test]
async fn test_retention_cap_evicts_oldest_finished_scans_only() {
    let mut state = make_state(None, None, false, false, "callback");
    state.max_retained_scans = 3;

    {
        let mut jobs = state.jobs.lock().await;
        for (i, id) in ["old", "mid", "new"].iter().enumerate() {
            let mut job = test_job(JobStatus::Done, None, "http://example.com");
            job.finished_at_ms = Some(1_000 + i as i64);
            jobs.insert((*id).to_string(), job);
        }
        // Still running: must survive eviction even though it is the oldest.
        let mut running = test_job(JobStatus::Running, None, "http://example.com");
        running.queued_at_ms = 1;
        jobs.insert("running".to_string(), running);
    }

    let (id, _lease) = try_admit_and_queue(&state, "http://example.com/new", None)
        .await
        .expect("admission succeeds");

    let jobs = state.jobs.lock().await;
    assert!(jobs.contains_key(&id), "the new scan is retained");
    assert!(
        jobs.contains_key("running"),
        "an active scan must never be evicted"
    );
    assert!(
        !jobs.contains_key("old"),
        "the oldest finished scan is evicted"
    );
    assert!(!jobs.contains_key("mid"), "eviction continues until at cap");
    assert!(
        jobs.contains_key("new"),
        "the newest finished scan survives"
    );
}

// ---------------------------------------------------------------------------
// /preflight estimate: the per-parameter payload cap the scan actually enforces
//
// `run_scanning` truncates each parameter's payload set to
// `effective_payload_cap(max_payloads_per_param, deep_scan)` — 3000 by default.
// The REST estimate did not, so /preflight quoted a request budget the scan
// would never spend: on a reflecting target it reported 7008 requests for a run
// capped at 6000, and 14016 with five encoders selected. Sizing a scan is the
// entire purpose of the endpoint, so an estimate that ignores the cap is wrong
// in the one number callers act on. The CLI's `--dry-run` estimate has always
// applied the cap; this brings REST (and MCP) in line.
// ---------------------------------------------------------------------------

async fn preflight_estimate(addr: SocketAddr, options: ScanOptions) -> serde_json::Value {
    let state = make_state(None, None, false, false, "cb");
    let resp = preflight_handler(
        State(state),
        HeaderMap::new(),
        Query(Map::new()),
        Ok(Json(ScanRequest {
            target: format!("http://{addr}/?q=1"),
            options: Some(options),
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    serde_json::from_str::<serde_json::Value>(&response_body_string(resp).await).expect("json")
        ["data"]
        .clone()
}

#[tokio::test]
async fn test_preflight_estimate_respects_the_scan_time_payload_cap() {
    let addr = start_reflecting_target_server().await;
    let base = ScanOptions {
        timeout: Some(5),
        skip_mining: Some(true),
        ..ScanOptions::default()
    };

    let cap = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP as u64;
    let capped = preflight_estimate(addr, base.clone()).await;
    let params = capped["params"].as_array().expect("params array");
    assert!(!params.is_empty(), "reflecting target must discover params");
    for p in params {
        let est = p["estimated_requests"]
            .as_u64()
            .expect("per-param estimate");
        // `run_scanning` truncates the reflection set and the DOM set to `cap`
        // each, then sends one request per payload in both — so a parameter
        // costs at most `2 * cap`, and the estimate must not exceed that.
        assert!(
            est <= 2 * cap,
            "no parameter may be quoted more requests than the scan will send it \
             (reflection + DOM, {cap} each), got {est} for {p}"
        );
        // ...and must not fall below one capped half either. Clamping the whole
        // per-param figure at `cap` — i.e. counting only the reflection phase —
        // halved the quote for exactly the sprawling parameters callers reach
        // for preflight to size.
        assert!(
            est > cap,
            "the estimate must count the DOM phase too, not just reflection: \
             got {est} for {p} with a per-half cap of {cap}"
        );
    }

    // The cap is the *scan's* cap, not a hardcoded ceiling on the estimate:
    // raising `max_payloads_per_param` must raise the quote with it, otherwise
    // this test would also pass against an estimate that simply clamps.
    let raised = preflight_estimate(
        addr,
        ScanOptions {
            max_payloads_per_param: Some(100_000),
            ..base
        },
    )
    .await;
    assert!(
        raised["estimated_total_requests"].as_u64().expect("total")
            > capped["estimated_total_requests"].as_u64().expect("total"),
        "lifting the per-param cap must raise the estimate: capped={} raised={}",
        capped["estimated_total_requests"],
        raised["estimated_total_requests"]
    );
}

// ---------------------------------------------------------------------------
// validate_scan_options: options that were accepted and then silently dropped
// ---------------------------------------------------------------------------

/// `Target::build_client` resolves the proxy with `Proxy::all(..).ok()` and
/// falls back to **no proxy** when that fails. A scan submitted with a typo'd
/// `proxy` therefore connected straight to the target — bypassing the intercept
/// proxy / tunnel the caller asked for — and still settled `done`. Refuse it at
/// the boundary instead.
#[test]
fn test_validate_scan_options_rejects_unusable_proxy() {
    for bad in [
        "not a url",
        "http://",
        // Parses and passes `Proxy::all`, then hyper-util drops it and the
        // scan would go DIRECT — the same hole the CLI startup gate closes.
        "ftp://127.0.0.1:8080",
        "socks6://127.0.0.1:1080",
    ] {
        let mut opts = ScanOptions {
            proxy: Some(bad.to_string()),
            ..ScanOptions::default()
        };
        let err = validate_scan_options(&mut opts)
            .expect_err("an unusable proxy must be refused, not silently dropped");
        assert!(
            err.contains("proxy"),
            "the 400 must name the offending option, got: {err}"
        );
    }
    // Forms the CLI also accepts stay accepted, and the *normalized* value is
    // what gets stored, because that is the string `build_client` later feeds
    // to `Proxy::all`. `str::trim` strips all Unicode whitespace while
    // `url::Url` strips only ASCII, so validating the trimmed form while
    // storing the raw one would let a NBSP-prefixed copy-paste pass the check
    // and still resolve away to no proxy — the very hole this write-back
    // exists to close.
    for (given, stored) in [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"),
        ("  http://127.0.0.1:8080  ", "http://127.0.0.1:8080"),
        ("\u{a0}http://127.0.0.1:8080", "http://127.0.0.1:8080"),
    ] {
        let mut opts = ScanOptions {
            proxy: Some(given.to_string()),
            ..ScanOptions::default()
        };
        validate_scan_options(&mut opts)
            .unwrap_or_else(|e| panic!("'{given}' is a usable proxy and must be accepted: {e}"));
        assert_eq!(
            opts.proxy.as_deref(),
            Some(stored),
            "the stored proxy must be the normalized form the client builder resolves"
        );
        assert!(
            reqwest::Proxy::all(opts.proxy.as_deref().expect("proxy")).is_ok(),
            "whatever validation stored must survive `Proxy::all`, or the scan \
             silently goes direct anyway"
        );
    }

    // Empty already meant "no proxy" and still does: refusing it would break the
    // routine `?proxy=` templated-query shape without closing any hole.
    for empty in ["", "   "] {
        let mut opts = ScanOptions {
            proxy: Some(empty.to_string()),
            ..ScanOptions::default()
        };
        assert!(validate_scan_options(&mut opts).is_ok());
        assert_eq!(
            opts.proxy, None,
            "an empty proxy must normalize to absent, not stay an empty string"
        );
    }
}

/// `send_terminal_webhook` dials http(s) only and returns silently otherwise,
/// so a `callback_url` with any other scheme was accepted with `200 OK` and
/// then discarded — the subscriber waited forever for a callback that had
/// already been thrown away at submission time.
#[test]
fn test_validate_scan_options_rejects_non_http_callback_url() {
    for bad in ["file:///etc/passwd", "ftp://x/cb", "example.com/cb"] {
        let mut opts = ScanOptions {
            callback_url: Some(bad.to_string()),
            ..ScanOptions::default()
        };
        let err = validate_scan_options(&mut opts)
            .expect_err("a callback_url the webhook can never dial must be refused");
        assert!(
            err.contains("callback_url"),
            "the 400 must name the offending option, got: {err}"
        );
    }
    let mut opts = ScanOptions {
        callback_url: Some("https://hooks.example/cb".to_string()),
        ..ScanOptions::default()
    };
    assert!(validate_scan_options(&mut opts).is_ok());

    // Empty already meant "no webhook" and still does — same templated-query
    // reasoning as `proxy` above.
    for empty in ["", "   "] {
        let mut opts = ScanOptions {
            callback_url: Some(empty.to_string()),
            ..ScanOptions::default()
        };
        assert!(validate_scan_options(&mut opts).is_ok());
        assert_eq!(opts.callback_url, None);
    }
}

/// The boundary check and the dispatcher must agree on what counts as an
/// http(s) callback, or validation just moves the silent drop one step later.
/// URI schemes are case-insensitive and `validate_scan_options` compares them
/// that way; the dispatcher's test has to as well, and the value it dials has
/// to be the normalized one validation approved.
#[test]
fn test_callback_url_validation_and_dispatch_agree_on_the_scheme() {
    for accepted in [
        "https://hooks.example/cb",
        "HTTPS://hooks.example/cb",
        "  http://hooks.example/cb  ",
    ] {
        let mut opts = ScanOptions {
            callback_url: Some(accepted.to_string()),
            ..ScanOptions::default()
        };
        validate_scan_options(&mut opts)
            .unwrap_or_else(|e| panic!("'{accepted}' must be accepted, got: {e}"));
        let stored = opts.callback_url.expect("callback_url survives validation");
        assert_eq!(
            stored,
            accepted.trim(),
            "the stored callback_url must be the normalized (trimmed) form the \
             dispatcher will dial"
        );
        assert!(
            has_http_scheme(&stored),
            "'{stored}' passed validation, so the dispatcher's scheme test must \
             accept it too — otherwise the webhook is silently dropped"
        );
    }
}
