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

/// reqwest is built with `rustls-no-provider`, so the ring crypto provider
/// must be installed before the first `Client::build()` or it panics.
/// Production installs it in `main()` / the pooled builders; these unit tests
/// construct bare clients, so route them through this helper.
fn test_client() -> Client {
    crate::ensure_crypto_provider();
    Client::new()
}

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
        escaped_specials: None,
        js_breakout: None,
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

/// Models an ASP.NET `ValidateRequest`-style error page (issue #1118): the raw
/// submitted value is echoed unencoded but cut off right before the event
/// handler, so the parsed element keeps the marker class while the `onload=` /
/// `onerror=` handler never survives.
async fn truncate_before_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    let cut = q
        .find("onload")
        .or_else(|| q.find("onerror"))
        .map(|i| &q[..i])
        .unwrap_or(q.as_str());
    Html(format!(
        "<html><body><header>blocked: {cut}</header></body></html>"
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
        .route("/truncate", get(truncate_before_handler))
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
    let client = test_client();

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
    let client = test_client();

    let (verified, response, note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&marker));
    assert_eq!(note, Some("marker element present".to_string()));
}

/// Issue #1118: path #2 ("marker element present") has no reflection gate, so
/// it was the one surface where a marker-only reflection became a false [V].
/// `/marker-only` echoes `<div class="MARKER">ok</div>` regardless of input —
/// the marker class survives but the payload's `onload` handler never does.
/// With the handler-survival gate, a sink-bearing payload must no longer verify
/// here (contrast the test above, whose payload carries no sink and stays
/// presence-only).
#[tokio::test]
async fn test_verify_dom_xss_light_marker_without_surviving_handler_demoted() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/marker-only", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("'\"><svg/class={} onload=alert()//", marker);
    let client = test_client();

    let (verified, _response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(
        !verified,
        "marker class without the payload's surviving handler must not verify"
    );
}

/// Issue #1118 end-to-end at the HTTP layer: the `/truncate` route faithfully
/// reproduces the reported scenario (raw value echoed, cut before the handler).
/// This is the test that would have caught the original bug — the marker class
/// reaches the DOM but the handler does not, so it must not verify.
#[tokio::test]
async fn test_verify_dom_xss_light_truncated_handler_reflection_demoted() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/truncate", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("'\"><svg/class={} onload=alert()//", marker);
    let client = test_client();

    let (verified, _response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(
        !verified,
        "truncated-handler reflection must not verify (issue #1118)"
    );
}

/// Counter-case to the truncation test: when the same handler payload is
/// reflected in full, the handler survives on the marker element and the
/// candidate genuinely verifies.
#[tokio::test]
async fn test_verify_dom_xss_light_full_handler_reflection_verifies() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/reflect", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("<svg onload=alert(1) class={}>", marker);
    let client = test_client();

    let (verified, _response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(
        verified,
        "fully-reflected handler on the marker element must verify"
    );
}

#[tokio::test]
async fn test_verify_dom_xss_light_sets_csp_hint_when_inline_handlers_blocked() {
    let marker = crate::scanning::markers::class_marker().to_string();
    let addr = start_mock_server(&marker).await;
    let target = make_target(addr, "/csp", None, None);
    let param = make_param(Location::Query, "q");
    let payload = format!("payload-{}", marker);
    let client = test_client();

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
    let client = test_client();

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
    crate::ensure_crypto_provider();
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
    let client = test_client();

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
    let client = test_client();

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
    let client = test_client();

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
    let client = test_client();

    let (verified, response, _note) =
        verify_dom_xss_light_with_client(&client, &target, &param, &payload).await;

    assert!(verified);
    assert!(response.expect("response").contains(&payload));
}
