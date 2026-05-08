use super::*;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use crate::target_parser::parse_target;
use axum::{
    Router,
    extract::{Form, Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::{Duration, sleep};

#[derive(Clone)]
struct TestState {
    stored_payload: String,
}

fn make_param() -> Param {
    Param {
        name: "q".to_string(),
        value: "seed".to_string(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    }
}

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        input_type: "auto".to_string(),
        format: "json".to_string(),
        targets: vec![],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 10,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
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
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

fn make_target(addr: SocketAddr, path: &str) -> Target {
    let target = format!("http://{}:{}{}?q=seed", addr.ip(), addr.port(), path);
    parse_target(&target).expect("valid target")
}

async fn html_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", q))
}

async fn xhtml_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "application/xhtml+xml")],
        format!("<html><body>{}</body></html>", q),
    )
}

async fn json_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        format!("{{\"echo\":\"{}\"}}", q),
    )
}

async fn html_without_payload_handler() -> Html<&'static str> {
    Html("<div>no payload</div>")
}

async fn decoded_payload_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    let decoded = urlencoding::decode(&q)
        .map(|value| value.into_owned())
        .unwrap_or(q);
    Html(format!("<div>{}</div>", decoded))
}

async fn header_reflection_handler(headers: HeaderMap) -> Html<String> {
    let value = headers
        .get("x-test")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    Html(format!("<div>{}</div>", value))
}

async fn cookie_reflection_handler(headers: HeaderMap) -> Html<String> {
    let value = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    Html(format!("<div>{}</div>", value))
}

async fn form_reflection_handler(Form(params): Form<HashMap<String, String>>) -> Html<String> {
    let value = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", value))
}

async fn json_reflection_handler(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let value = body
        .get("q")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    (
        StatusCode::OK,
        [("content-type", "text/html")],
        format!("<div>{}</div>", value),
    )
}

async fn url_attribute_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<iframe src=\"{}\"></iframe>", q))
}

async fn sxss_html_handler(State(state): State<TestState>) -> Html<String> {
    Html(format!("<div>{}</div>", state.stored_payload))
}

async fn sxss_json_handler(State(state): State<TestState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        format!("{{\"stored\":\"{}\"}}", state.stored_payload),
    )
}

async fn start_mock_server(stored_payload: &str) -> SocketAddr {
    let app = Router::new()
        .route("/dom/html", get(html_handler))
        .route("/dom/decoded", get(decoded_payload_handler))
        .route("/dom/url-attribute", get(url_attribute_handler))
        .route("/dom/xhtml", get(xhtml_handler))
        .route("/dom/json", get(json_handler))
        .route("/dom/no-payload", get(html_without_payload_handler))
        .route("/dom/header", get(header_reflection_handler))
        .route("/dom/cookie", get(cookie_reflection_handler))
        .route("/dom/form", axum::routing::post(form_reflection_handler))
        .route(
            "/dom/json-body",
            axum::routing::post(json_reflection_handler),
        )
        .route("/sxss/html", get(sxss_html_handler))
        .route("/sxss/json", get(sxss_json_handler))
        .with_state(TestState {
            stored_payload: stored_payload.to_string(),
        });

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_check_dom_verification_early_return_when_skip() {
    let target = parse_target("https://example.com/?q=1").unwrap();
    let param = make_param();
    let mut args = default_scan_args();
    args.skip_xss_scanning = true;
    let res = check_dom_verification(&target, &param, "PAY", &args).await;
    assert_eq!(res, (false, None));
}

#[tokio::test]
async fn test_check_dom_verification_detects_html_reflection() {
    let payload = format!(
        "<svg onload=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/html");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found, "text/html responses with payload should be detected");
    assert!(body.unwrap_or_default().contains(&payload));
}

#[tokio::test]
async fn test_check_dom_verification_accepts_xhtml_content_type() {
    let payload = format!(
        "<img src=x onerror=alert(1) id={}>",
        crate::scanning::markers::id_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/xhtml");
    let param = make_param();
    let args = default_scan_args();

    let (found, _) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(
        found,
        "application/xhtml+xml should be treated as HTML-like"
    );
}

#[tokio::test]
async fn test_check_dom_verification_rejects_non_html_without_marker() {
    // Non-HTML responses without marker evidence should still be rejected
    let payload = "<script>alert(1)</script>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/json");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, payload, &args).await;
    assert!(
        !found,
        "application/json without marker should not pass DOM verification"
    );
    assert!(
        body.is_none(),
        "non-html responses without marker should not be returned"
    );
}

#[tokio::test]
async fn test_check_dom_verification_accepts_non_html_with_marker() {
    // Non-HTML responses WITH marker evidence should pass (JSONP/JSON XSS cases)
    let payload = format!(
        "<script class={}>alert(1)</script>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/json");
    let param = make_param();
    let args = default_scan_args();

    let (found, _body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(
        found,
        "non-HTML responses with marker evidence should pass DOM verification for JSONP/JSON XSS"
    );
}

#[tokio::test]
async fn test_check_dom_verification_returns_false_when_payload_missing() {
    let payload = format!(
        "<script class={}>alert(1)</script>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/no-payload");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(!found);
    assert!(body.is_none());
}

#[tokio::test]
async fn test_check_dom_verification_injects_header_params() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = parse_target(&format!("http://{}:{}/dom/header", addr.ip(), addr.port()))
        .expect("valid target");
    let param = Param {
        name: "X-Test".to_string(),
        value: "seed".to_string(),
        location: Location::Header,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    };
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found);
    assert!(body.unwrap_or_default().contains(&payload));
}

#[tokio::test]
async fn test_check_dom_verification_injects_cookie_params() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let mut target = parse_target(&format!("http://{}:{}/dom/cookie", addr.ip(), addr.port()))
        .expect("valid target");
    target
        .cookies
        .push(("session".to_string(), "seed".to_string()));
    let param = Param {
        name: "session".to_string(),
        value: "seed".to_string(),
        location: Location::Header,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    };
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found);
    assert!(
        body.unwrap_or_default()
            .contains(&format!("session={}", payload))
    );
}

#[tokio::test]
async fn test_check_dom_verification_injects_form_body_params() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let mut target = parse_target(&format!("http://{}:{}/dom/form", addr.ip(), addr.port()))
        .expect("valid target");
    target.method = "POST".to_string();
    target.data = Some("q=seed".to_string());
    let param = Param {
        name: "q".to_string(),
        value: "seed".to_string(),
        location: Location::Body,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    };
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found);
    assert!(body.unwrap_or_default().contains(&payload));
}

#[tokio::test]
async fn test_check_dom_verification_injects_json_body_params() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let mut target = parse_target(&format!(
        "http://{}:{}/dom/json-body",
        addr.ip(),
        addr.port()
    ))
    .expect("valid target");
    target.method = "POST".to_string();
    target.data = Some("{\"q\":\"seed\"}".to_string());
    let param = Param {
        name: "q".to_string(),
        value: "seed".to_string(),
        location: Location::JsonBody,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
    };
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found);
    assert!(body.unwrap_or_default().contains(&payload));
}

#[tokio::test]
async fn test_check_dom_verification_sxss_uses_secondary_url() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server(&payload).await;
    let target = make_target(addr, "/dom/no-payload");
    let param = make_param();
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = Some(format!("http://{}:{}/sxss/html", addr.ip(), addr.port()));

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(found, "sxss should verify stored payload at secondary URL");
    assert!(body.unwrap_or_default().contains(&payload));
}

#[tokio::test]
async fn test_check_dom_verification_sxss_rejects_non_html_secondary_content() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server(&payload).await;
    let target = make_target(addr, "/dom/no-payload");
    let param = make_param();
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = Some(format!("http://{}:{}/sxss/json", addr.ip(), addr.port()));

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(!found);
    assert!(body.is_none());
}

#[tokio::test]
async fn test_check_dom_verification_sxss_without_url_returns_false() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server(&payload).await;
    let target = make_target(addr, "/dom/html");
    let param = make_param();
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = None;

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(!found);
    assert!(body.is_none());
}

#[test]
fn test_has_marker_evidence_requires_payload_marker() {
    let body = format!(
        "<html><body><div class=\"{}\">x</div></body></html>",
        crate::scanning::markers::class_marker()
    );
    assert!(!has_marker_evidence("<img src=x onerror=alert(1)>", &body));
}

#[test]
fn test_has_marker_evidence_detects_class_marker_element() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("<img src=x onerror=alert(1) class={}>", marker);
    let body = format!("<html><body><img class=\"{}\"></body></html>", marker);
    assert!(has_marker_evidence(&payload, &body));
}

#[test]
fn test_has_marker_evidence_detects_legacy_dalfox_class_marker_element() {
    let payload = "<img class=\"dalfox\" src=x onerror=alert(1)>";
    let body = "<html><body><img class=\"dalfox\"></body></html>";
    assert!(has_marker_evidence(payload, body));
}

#[test]
fn test_has_executable_url_attribute_evidence_detects_iframe_src_protocol() {
    let payload = "javascript:alert(1)";
    let body = "<html><body><iframe src=\"javascript:alert(1)\"></iframe></body></html>";
    assert!(has_dom_evidence(payload, body));
}

#[test]
fn test_has_dom_evidence_skips_parse_for_irrelevant_payload() {
    // Payload has neither Dalfox markers nor an executable URL protocol,
    // so has_dom_evidence should short-circuit to false without parsing.
    let payload = "plain alphanumeric";
    let body = "<html><body>irrelevant</body></html>";
    assert!(!has_dom_evidence(payload, body));
}

#[test]
fn test_has_dom_evidence_combines_marker_and_protocol_checks() {
    // Marker-bearing payload passes via the marker branch even when the
    // payload is not an executable URL protocol.
    let class_marker = crate::scanning::markers::class_marker();
    let payload = format!("<img class=\"{}\">", class_marker);
    let body = format!("<html><body><img class=\"{}\"></body></html>", class_marker);
    assert!(has_dom_evidence(&payload, &body));
}

#[test]
fn test_has_dom_evidence_via_js_context_breakout() {
    // Mirrors brutelogic c3 / c4: payload introduces a real alert call
    // inside a JS string-context reflection. No marker, no executable URL,
    // but the JS-context AST verifier should accept it.
    let payload = "\"-alert(1)-\"";
    let body = format!(
        "<html><body><script>var c2 = \"{}\";</script></body></html>",
        payload
    );
    assert!(has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_rejects_inert_js_string_payload() {
    // A payload that just becomes plain string text inside a JS literal
    // has no exploit potential — must not be treated as evidence.
    let payload = "\"hello\"";
    let body = format!(
        "<html><body><script>var x = \"{}\";</script></body></html>",
        payload
    );
    assert!(!has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_html_struct_svg_onload() {
    // No Dalfox marker in the payload but the parsed DOM contains a real
    // svg element with onload="alert(1)" introduced by the injection.
    let payload = "<svg/onload=alert(1)>";
    let body = format!("<html><body>hello {}</body></html>", payload);
    assert!(has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_html_struct_img_onerror() {
    let payload = "<img src=x onerror=prompt(1)>";
    let body = format!("<html><body>{}</body></html>", payload);
    assert!(has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_html_struct_script_body() {
    let payload = "<script>alert(1)</script>";
    let body = format!("<html><body>{}</body></html>", payload);
    assert!(has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_html_struct_ignores_pre_existing_handler() {
    // The page already had <body onload="alert(1)">. The payload doesn't
    // contain that attribute string, so the structural check must NOT
    // claim evidence.
    let payload = "harmless";
    let body = "<html><body onload=\"alert(1)\">harmless</body></html>";
    assert!(!has_dom_evidence(payload, body));
}

#[test]
fn test_has_dom_evidence_html_struct_requires_sink_call() {
    // Payload reflects as a real element with an event handler, but the
    // handler value doesn't reference any sink — not actionable XSS.
    let payload = "<div onmouseover=foo()>";
    let body = format!("<html><body>{}</body></html>", payload);
    assert!(!has_dom_evidence(payload, &body));
}

#[test]
fn test_has_dom_evidence_html_struct_ignores_text_only_reflection() {
    // Server entity-encoded `<` so the payload renders as text, not as
    // a parsed element. scraper produces no svg element — no evidence.
    let payload = "<svg/onload=alert(1)>";
    let body = "<html><body>hello &lt;svg/onload=alert(1)&gt;</body></html>";
    assert!(!has_dom_evidence(payload, body));
}

#[test]
fn test_classify_dom_evidence_returns_marker() {
    let class_marker = crate::scanning::markers::class_marker();
    let payload = format!("<img class=\"{}\">", class_marker);
    let body = format!("<html><body><img class=\"{}\"></body></html>", class_marker);
    assert_eq!(
        classify_dom_evidence(&payload, &body),
        Some(DomEvidenceKind::Marker)
    );
}

#[test]
fn test_classify_dom_evidence_returns_html_structural() {
    let payload = "<svg/onload=alert(1)>";
    let body = format!("<html><body>{}</body></html>", payload);
    assert_eq!(
        classify_dom_evidence(payload, &body),
        Some(DomEvidenceKind::HtmlStructural)
    );
}

#[test]
fn test_classify_dom_evidence_returns_js_context() {
    let payload = "\"-alert(1)-\"";
    let body = format!(
        "<html><body><script>var c2 = \"{}\";</script></body></html>",
        payload
    );
    assert_eq!(
        classify_dom_evidence(payload, &body),
        Some(DomEvidenceKind::JsContext)
    );
}

#[test]
fn test_classify_dom_evidence_returns_executable_url() {
    let payload = "javascript:alert(1)";
    let body = format!("<html><body><a href=\"{}\">x</a></body></html>", payload);
    assert_eq!(
        classify_dom_evidence(payload, &body),
        Some(DomEvidenceKind::ExecutableUrl)
    );
}

#[test]
fn test_classify_dom_evidence_returns_none_for_inert() {
    let payload = "harmless";
    let body = "<html><body>harmless</body></html>";
    assert_eq!(classify_dom_evidence(payload, body), None);
}

#[test]
fn test_has_dom_evidence_html_struct_skipped_for_json_body() {
    // Browsers don't render application/json as HTML, so even though
    // scraper happily parses `{"echo":"<script>alert(1)</script>"}` and
    // finds a script element, this is not exploitable in real conditions.
    let payload = "<script>alert(1)</script>";
    let body = "{\"echo\":\"<script>alert(1)</script>\"}";
    assert!(
        !has_dom_evidence(payload, body),
        "JSON-shaped body should not yield structural HTML evidence"
    );
}

#[tokio::test]
async fn test_check_dom_verification_accepts_executable_url_attribute_protocol() {
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/url-attribute");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, "javascript:alert(1)", &args).await;

    assert!(
        found,
        "javascript: payloads reflected into iframe src should verify"
    );
    assert!(
        body.unwrap_or_default()
            .contains("iframe src=\"javascript:alert(1)\"")
    );
}

#[tokio::test]
async fn test_check_dom_verification_accepts_decoded_payload_variant_with_marker() {
    let payload = crate::encoding::url_encode(&format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    ));
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/decoded");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(
        found,
        "decoded payload variants with DOM markers should verify"
    );
    assert!(
        body.unwrap_or_default()
            .contains(crate::scanning::markers::class_marker())
    );
}
