use super::*;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::{Target, parse_target};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use reqwest::Client;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::{Duration, sleep};

#[derive(Clone)]
struct TestState {
    class_marker: String,
}

fn make_param(loc: Location, name: &str) -> Param {
    Param {
        name: name.to_string(),
        value: "seed".to_string(),
        location: loc,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
    }
}

fn make_target(addr: SocketAddr, path: &str, method: Option<&str>, data: Option<&str>) -> Target {
    let target = format!("http://{}:{}{}?q=seed", addr.ip(), addr.port(), path);
    let mut t = parse_target(&target).expect("valid target");
    if let Some(m) = method {
        t.method = m.to_string();
    }
    if let Some(d) = data {
        t.data = Some(d.to_string());
    }
    t
}

async fn reflect_html(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<html><body>{}</body></html>", q))
}

async fn marker_only_html(State(state): State<TestState>) -> Html<String> {
    Html(format!(
        "<html><body><div class=\"{}\">ok</div></body></html>",
        state.class_marker
    ))
}

async fn csp_html() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "text/html"),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self'",
            ),
        ],
        "<html><body>safe</body></html>",
    )
}

async fn redirect_route() -> impl IntoResponse {
    (
        StatusCode::FOUND,
        [("Location", "/reflect")],
        "Redirecting...",
    )
}

async fn reflect_header(headers: HeaderMap) -> Html<String> {
    let val = headers
        .get("x-xss")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    Html(format!("<html><body>{}</body></html>", val))
}

async fn reflect_body(body: String) -> Html<String> {
    let decoded = urlencoding::decode(&body)
        .unwrap_or(std::borrow::Cow::Borrowed(&body))
        .into_owned();
    let decoded = decoded.replace('+', " ");
    Html(format!("<html><body>{}</body></html>", decoded))
}

async fn reflect_json(Json(payload): Json<HashMap<String, String>>) -> Html<String> {
    let val = payload.get("q").cloned().unwrap_or_default();
    Html(format!("<html><body>{}</body></html>", val))
}

async fn reflect_multipart(body: String) -> Html<String> {
    Html(format!("<html><body>{}</body></html>", body))
}

async fn start_mock_server(class_marker: &str) -> SocketAddr {
    let app = Router::new()
        .route("/reflect", get(reflect_html))
        .route("/marker-only", get(marker_only_html))
        .route("/csp", get(csp_html))
        .route("/redirect", get(redirect_route))
        .route("/header", get(reflect_header))
        .route("/body", post(reflect_body))
        .route("/json", post(reflect_json))
        .route("/multipart", post(reflect_multipart))
        .with_state(TestState {
            class_marker: class_marker.to_string(),
        });

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(30)).await;
    addr
}

#[tokio::test]
async fn test_verify_dom_xss_light_marker_reflected() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/reflect", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);

    let (verified, response, note) = verify_dom_xss_light(&target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
    assert_eq!(note, Some("marker-reflected".to_string()));
}

#[tokio::test]
async fn test_verify_dom_xss_light_raw_reflection_without_marker_evidence() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/reflect", None, None);
    let param = make_param(Location::Query, "q");
    let payload = "<script>alert(1)</script>";
    let client = Client::new();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, payload).await;

    assert!(!verified);
    assert!(response.expect("response").contains(payload));
    assert_eq!(
        note,
        Some("payload reflection without marker evidence".to_string())
    );
}

#[tokio::test]
async fn test_verify_dom_xss_light_marker_element_present_without_payload() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/marker-only", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("<div class=\"{}\">injected</div>", marker);
    let client = Client::new();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&marker));
    assert_eq!(note, Some("marker element present".to_string()));
}

#[tokio::test]
async fn test_verify_dom_xss_light_sets_csp_hint_when_inline_handlers_blocked() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/csp", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("payload-{}", marker);
    let client = Client::new();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(!verified);
    assert!(response.is_some());
    assert_eq!(note, Some("CSP may block inline handlers".to_string()));
}

#[tokio::test]
async fn test_verify_dom_xss_light_returns_none_response_on_request_failure() {
    let listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve local port");
    let port = listener.local_addr().expect("listener addr").port();
    drop(listener);

    let target_url = format!("http://127.0.0.1:{}/?q=seed", port);
    let mut target = parse_target(&target_url).expect("valid target");
    target.timeout = 1;
    let param = make_param(Location::Query, "q");
    let payload = "x";
    let client = Client::new();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, payload).await;

    assert!(!verified);
    assert!(response.is_none());
    assert!(note.is_none());
}

#[tokio::test]
async fn test_verify_dom_xss_light_redirection() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/redirect", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(!verified);
    assert!(response.is_none());
    assert_eq!(note, Some("3xx response — DOM verify skipped".to_string()));
}

#[tokio::test]
async fn test_verify_dom_xss_light_location_header() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/header", None, None);
    let param = make_param(Location::Header, "X-XSS");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);
    let client = Client::new();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
    assert_eq!(note, Some("marker-reflected".to_string()));
}

#[tokio::test]
async fn test_verify_dom_xss_light_location_body() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/body", Some("POST"), Some("q=seed"));
    let param = make_param(Location::Body, "q");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);
    let client = Client::new();

    let (verified, response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
}

#[tokio::test]
async fn test_verify_dom_xss_light_location_json_body() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/json", Some("POST"), Some("{\"q\":\"seed\"}"));
    let param = make_param(Location::JsonBody, "q");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);
    let client = Client::new();

    let (verified, response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
}

#[tokio::test]
async fn test_verify_dom_xss_light_location_multipart_body() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/multipart", Some("POST"), Some("q=seed"));
    let param = make_param(Location::MultipartBody, "q");
    let payload = format!("<img class=\"{}\" src=x onerror=1>", marker);
    let client = Client::new();

    let (verified, response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
}
