use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    response::{Html, IntoResponse},
    routing::{any, get},
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body: String,
}

type CaptureState = Arc<Mutex<Vec<CapturedRequest>>>;

async fn capture_handler(
    State(state): State<CaptureState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let mut headers = HashMap::new();
    for (name, value) in &parts.headers {
        headers.insert(
            name.as_str().to_ascii_lowercase(),
            value.to_str().unwrap_or_default().to_string(),
        );
    }

    state.lock().await.push(CapturedRequest {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    });
    StatusCode::OK
}

async fn start_capture_server() -> (SocketAddr, CaptureState) {
    let state: CaptureState = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", any(capture_handler))
        .route("/submit", any(capture_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(30)).await;
    (addr, state)
}

fn make_target(addr: SocketAddr, path: &str) -> Target {
    let target = format!("http://{}:{}{}", addr.ip(), addr.port(), path);
    crate::target_parser::parse_target(&target).expect("valid target")
}

#[tokio::test]
async fn test_send_blind_request_query_injects_payload_and_keeps_existing_state() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/?q=seed&keep=1");
    target.headers = vec![("X-Test".to_string(), "header".to_string())];
    target.cookies = vec![("sid".to_string(), "abc".to_string())];
    target.user_agent = Some("dalfox-test".to_string());
    target.delay = 1;

    send_blind_request(&target, "q", "PAYLOAD", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert_eq!(req.method, "GET");
    assert!(req.uri.contains("q=PAYLOAD"));
    assert!(req.uri.contains("keep=1"));
    assert_eq!(
        req.headers.get("x-test").map(String::as_str),
        Some("header")
    );
    assert_eq!(
        req.headers.get("user-agent").map(String::as_str),
        Some("dalfox-test")
    );
    assert!(
        req.headers
            .get("cookie")
            .map(|v| v.contains("sid=abc"))
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn test_send_blind_request_query_appends_when_param_missing() {
    let (addr, state) = start_capture_server().await;
    let target = make_target(addr, "/?keep=1");

    send_blind_request(&target, "q", "PAYLOAD", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert!(req.uri.contains("keep=1"));
    assert!(req.uri.contains("q=PAYLOAD"));
}

#[tokio::test]
async fn test_send_blind_request_mutates_body_header_and_cookie_targets() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some("a=1&b=2".to_string());
    target.headers = vec![("X-Trace".to_string(), "old".to_string())];
    target.cookies = vec![("session".to_string(), "old".to_string())];

    send_blind_request(&target, "a", "BODYPAY", "body").await;
    send_blind_request(&target, "X-Trace", "HDRPAY", "header").await;
    send_blind_request(&target, "session", "CKPAY", "cookie").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].method, "POST");
    assert!(records[0].body.contains("a=BODYPAY"));
    assert_eq!(
        records[1].headers.get("x-trace").map(String::as_str),
        Some("HDRPAY")
    );
    assert!(
        records[2]
            .headers
            .get("cookie")
            .map(|v| v.contains("session=CKPAY"))
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn test_send_blind_request_unknown_param_type_falls_back_to_default_path() {
    let (addr, state) = start_capture_server().await;
    let target = make_target(addr, "/");

    send_blind_request(&target, "unused", "PAYLOAD", "unknown-type").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].uri, "/");
}

async fn start_form_server(html: &'static str) -> (SocketAddr, CaptureState) {
    let state: CaptureState = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", get(move || async move { Html(html) }))
        .route("/submit", any(capture_handler))
        .route("/other", any(capture_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(30)).await;
    (addr, state)
}

#[tokio::test]
async fn test_blind_scan_forms_posts_payload_for_same_origin_post_form() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
            <input name="msg" value="hi">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Two text fields -> two POSTs, one with payload in `user`, one in `msg`.
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.method == "POST"));
    assert!(records.iter().all(|r| r.uri == "/submit"));
    assert!(records.iter().all(|r| {
        r.headers
            .get("content-type")
            .map(|v| v.contains("application/x-www-form-urlencoded"))
            .unwrap_or(false)
    }));
    // Each request carries the callback URL somewhere in the body.
    // form_urlencoded::byte_serialize leaves '.' alone, so the literal host
    // string is what we expect to see on the wire.
    assert!(records.iter().all(|r| r.body.contains("cb.example")));
    // Payload should land in each field exactly once across the two requests.
    let user_hits = records
        .iter()
        .filter(|r| {
            let user_part = r.body.split('&').find(|p| p.starts_with("user="));
            user_part.map(|p| p.contains("cb.example")).unwrap_or(false)
        })
        .count();
    let msg_hits = records
        .iter()
        .filter(|r| {
            let msg_part = r.body.split('&').find(|p| p.starts_with("msg="));
            msg_part.map(|p| p.contains("cb.example")).unwrap_or(false)
        })
        .count();
    assert_eq!(user_hits, 1);
    assert_eq!(msg_hits, 1);
}

#[tokio::test]
async fn test_blind_scan_forms_skips_get_forms() {
    static HTML: &str = r#"<html><body>
        <form method="GET" action="/submit">
            <input name="q" value="seed">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // The form-bearing GET / is handled by a static Html route (not captured).
    // No requests should ever reach the capture handler for a GET form.
    assert!(records.is_empty(), "unexpected requests: {:?}", records);
}

#[tokio::test]
async fn test_blind_scan_forms_skips_cross_origin_action() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="https://evil.example/x">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Cross-origin action should be skipped; nothing posted to /submit.
    assert!(records.iter().all(|r| r.method != "POST"));
}

#[tokio::test]
async fn test_blind_scan_forms_preserves_hidden_csrf_and_skips_hidden_rotation() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input type="hidden" name="_csrf" value="tok123">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Exactly one POST: the `user` field rotates in, the hidden _csrf is not
    // rotated (so it never receives the payload), but its original value is
    // preserved in every emitted body.
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert_eq!(req.method, "POST");
    // CSRF token survives intact.
    assert!(
        req.body.contains("_csrf=tok123"),
        "csrf token missing: {}",
        req.body
    );
    // Payload landed in `user` and not in `_csrf`.
    let csrf_part = req.body.split('&').find(|p| p.starts_with("_csrf="));
    let user_part = req.body.split('&').find(|p| p.starts_with("user="));
    assert!(
        csrf_part
            .map(|p| !p.contains("cb.example"))
            .unwrap_or(false)
    );
    assert!(user_part.map(|p| p.contains("cb.example")).unwrap_or(false));
}

#[tokio::test]
async fn test_blind_scan_forms_uses_get_to_fetch_even_when_target_is_post() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    // Configure the target as POST with body data; the fetch step must still
    // GET the form-bearing page rather than echoing the target's method.
    let mut target = make_target(addr, "/");
    target.method = "POST".to_string();
    target.data = Some("seed=1".to_string());

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // The only request we capture is the form POST to /submit.
    // (The HTML GET to "/" is served by the static Html handler.)
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, "POST");
    assert_eq!(records[0].uri, "/submit");
}

#[tokio::test]
async fn test_blind_scan_forms_overrides_caller_content_type() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let mut target = make_target(addr, "/");
    // Caller-supplied Content-Type would otherwise be appended alongside our
    // urlencoded type. Verify it does NOT make it onto the form POST.
    target.headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let ct = records[0]
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.contains("application/x-www-form-urlencoded"),
        "content-type missing urlencoded: {}",
        ct
    );
    assert!(
        !ct.contains("application/json"),
        "caller content-type leaked: {}",
        ct
    );
}

#[tokio::test]
async fn test_blind_scan_forms_skips_multipart() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit" enctype="multipart/form-data">
            <input name="file" value="">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert!(records.iter().all(|r| r.method != "POST"));
}

#[tokio::test]
async fn test_blind_scanning_sends_requests_for_query_body_header_and_cookie() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/?q=1");
    target.method = "POST".to_string();
    target.data = Some("bodyp=2".to_string());
    target.headers = vec![("x-h".to_string(), "v".to_string())];
    target.cookies = vec![("c".to_string(), "3".to_string())];

    blind_scanning(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 4);
    assert!(records.iter().all(|r| r.method == "POST"));
    assert!(records.iter().any(|r| {
        r.uri.contains("cb.example")
            || r.body.contains("cb.example")
            || r.headers.values().any(|v| v.contains("cb.example"))
    }));
}
