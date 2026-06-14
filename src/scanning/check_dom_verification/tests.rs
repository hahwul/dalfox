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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
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
        scan_timeout: 0,
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
        stream_findings: false,
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
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
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

async fn html_uppercase_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", q.to_uppercase()))
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

/// Reflects the payload into `<img src=…>`. Modern browsers do not execute
/// a `javascript:` URL in `img@src` (it's a resource fetch, not a
/// navigation), so DOM verification must not promote this to Verified
/// purely on the basis that the scheme reached the attribute value.
async fn url_attribute_img_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<img src=\"{}\">", q))
}

/// Returns a 307 whose body echoes the payload verbatim. Browsers never render
/// the body of a 3xx response, so this is the canonical "DOM evidence inside a
/// redirect body" false-positive case — verification must not fire here.
async fn redirect_body_echo_handler(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default();
    (
        StatusCode::TEMPORARY_REDIRECT,
        [
            ("content-type", "text/html"),
            ("location", "/dom/no-payload"),
        ],
        format!("<html><body><div>{}</div></body></html>", q),
    )
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
        .route("/dom/html-upper", get(html_uppercase_handler))
        .route("/dom/decoded", get(decoded_payload_handler))
        .route("/dom/url-attribute", get(url_attribute_handler))
        .route("/dom/url-attribute-img", get(url_attribute_img_handler))
        .route("/dom/redirect-body", get(redirect_body_echo_handler))
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

// Server uppercases every reflected byte; the marker survives as a
// case-folded class value. The standard CSS class selector is case-
// sensitive so it misses the match, but the case-insensitive
// attribute walk added to `has_marker_evidence_in_doc` recovers V.
#[tokio::test]
async fn test_check_dom_verification_marker_survives_case_fold() {
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/html-upper");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(
        found,
        "uppercased marker class should still satisfy DOM evidence via case-insensitive scan"
    );
    let body = body.unwrap_or_default();
    let marker = crate::scanning::markers::class_marker();
    assert!(
        body.to_ascii_lowercase().contains(marker),
        "marker should appear in the body under ASCII case fold"
    );
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
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
    // The payload attaches its sink (onerror) to the marker element, so the
    // marker class is evidence only when the handler also survives (issue #1118).
    let body = format!(
        "<html><body><img src=x onerror=alert(1) class=\"{}\"></body></html>",
        marker
    );
    assert!(has_marker_evidence(&payload, &body));
}

#[test]
fn test_has_marker_evidence_detects_legacy_dalfox_class_marker_element() {
    let payload = "<img class=\"dalfox\" src=x onerror=alert(1)>";
    let body = "<html><body><img class=\"dalfox\" src=x onerror=alert(1)></body></html>";
    assert!(has_marker_evidence(payload, body));
}

/// Issue #1118: a server that reflects a *truncated* copy of the payload can
/// preserve the marker class while dropping the `on*` handler. The marker
/// element parses, but the handler never survives, so this is NOT exploitable
/// and must not count as marker evidence.
#[test]
fn test_has_marker_evidence_demoted_when_handler_truncated() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("'\"><svg/class={} onload=alert()//", marker);
    // ASP.NET ValidateRequest-style error page: the raw reflection is cut off
    // right before `onload`, so the parsed svg carries the marker class but no
    // handler.
    let body = format!(
        "<html><body><header>A potentially dangerous Request.Form value was \
         detected (q=\"...&gt;&lt;svg/class={} onlo...\").</header>\
         <svg class=\"{}\"></svg></body></html>",
        marker, marker
    );
    assert!(
        !has_marker_evidence(&payload, &body),
        "marker class without the payload's surviving handler must not be evidence"
    );
}

/// Issue #1118 (counter-case): when the same payload's handler DOES survive on
/// the marker element, the finding is genuinely exploitable and stays evidence.
#[test]
fn test_has_marker_evidence_kept_when_handler_survives() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("'\"><svg/class={} onload=alert()//", marker);
    let body = format!(
        "<html><body><svg class=\"{}\" onload=\"alert()\"></svg></body></html>",
        marker
    );
    assert!(has_marker_evidence(&payload, &body));
}

/// Issue #1118 (no regression): structural markers whose exploit is the
/// element's mere presence — base-href injection, DOM-clobbering containers —
/// carry no on*/script sink on the marker element, so presence-only evidence is
/// preserved.
#[test]
fn test_has_marker_evidence_kept_for_structural_markers() {
    let id = crate::scanning::markers::id_marker();
    let class = crate::scanning::markers::class_marker();

    // base-href injection — no sink on the marker element.
    let base_payload = format!("<base href=//evil.example/ id={}>", id);
    let base_body = format!(
        "<html><head><base href=\"//evil.example/\" id=\"{}\"></head></html>",
        id
    );
    assert!(
        has_marker_evidence(&base_payload, &base_body),
        "base-href marker presence is the exploit; must stay evidence"
    );

    // DOM-clobbering form container — the sink lives in a child input, not on
    // the marker element itself.
    let form_payload = format!(
        "<form id={} class={}><input name=\"action\" value=\"javascript:alert(1)\"></form>",
        id, class
    );
    let form_body = format!(
        "<html><body><form id=\"{}\" class=\"{}\"><input name=\"action\" \
         value=\"javascript:alert(1)\"></form></body></html>",
        id, class
    );
    assert!(
        has_marker_evidence(&form_payload, &form_body),
        "clobbering container marker presence is the exploit; must stay evidence"
    );
}

/// Issue #1118 (script-body family): a `<script class=marker>sink</script>`
/// payload whose body is truncated away leaves the marker class on an empty
/// script — no sink survives, so it is not evidence.
#[test]
fn test_has_marker_evidence_demoted_when_script_body_truncated() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("<script class={}>alert(1)</script>", marker);
    let body = format!(
        "<html><body><script class=\"{}\"></script></body></html>",
        marker
    );
    assert!(
        !has_marker_evidence(&payload, &body),
        "marker class on an empty script (sink body dropped) must not be evidence"
    );
}

/// Issue #1118 (script-body counter-case): when the `<script>` body sink
/// survives on the marker element, the finding stays evidence.
#[test]
fn test_has_marker_evidence_kept_when_script_body_survives() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("<script class={}>alert(1)</script>", marker);
    let body = format!(
        "<html><body><script class=\"{}\">alert(1)</script></body></html>",
        marker
    );
    assert!(has_marker_evidence(&payload, &body));
}

/// Issue #1118 (id-marker symmetry): the handler-survival gate applies to id
/// markers too, not only class markers.
#[test]
fn test_has_marker_evidence_demoted_when_id_handler_truncated() {
    let id = crate::scanning::markers::id_marker();
    let payload = format!("<svg onload=alert() id={}>", id);
    let truncated = format!("<html><body><svg id=\"{}\"></svg></body></html>", id);
    assert!(
        !has_marker_evidence(&payload, &truncated),
        "id-marker element without the surviving handler must not be evidence"
    );
    let survived = format!(
        "<html><body><svg id=\"{}\" onload=\"alert()\"></svg></body></html>",
        id
    );
    assert!(has_marker_evidence(&payload, &survived));
}

/// Issue #1118 (WAF-bypass): payloads entity-encode the sink chars
/// (`alert&#40;1&#41;`); scraper decodes the parsed handler back to `alert(1)`.
/// The co-survival check must compare against the decoded value too — a genuine
/// breakout stays evidence, while a truncated one is still demoted.
#[test]
fn test_has_marker_evidence_entity_encoded_sink() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("<svg onload=alert&#40;1&#41; class={}>", marker);
    let survived = format!(
        "<html><body><svg onload=\"alert(1)\" class=\"{}\"></svg></body></html>",
        marker
    );
    assert!(
        has_marker_evidence(&payload, &survived),
        "decoded handler sink on the marker element should still be evidence"
    );
    let truncated = format!("<html><body><svg class=\"{}\"></svg></body></html>", marker);
    assert!(
        !has_marker_evidence(&payload, &truncated),
        "entity-encoded payload with the handler dropped must be demoted"
    );
}

/// Issue #1118: the public entry point used by the scan worker
/// (`classify_dom_evidence`) must return `None` for a truncated-handler
/// reflection — no fallback evidence path (HTML-structural, JS-context, inline
/// breakout) should rescue it into a false [V].
#[test]
fn test_classify_dom_evidence_none_when_handler_truncated() {
    let marker = crate::scanning::markers::class_marker();
    let payload = format!("'\"><svg/class={} onload=alert()//", marker);
    let body = format!("<html><body><svg class=\"{}\"></svg></body></html>", marker);
    assert_eq!(classify_dom_evidence(&payload, &body), None);
}

/// Issue #1118 coverage matrix for `has_marker_evidence`.
///
/// The bug slipped past the original suite because the fixtures sprinkled the
/// marker into a hand-written body (`<img class="MARKER">`) instead of faithfully
/// modelling what the server did to the *whole* payload. This table pins the
/// verdict for each payload family against an explicit server transformation —
/// full reflection, handler stripped/blanked/neutralised, marker as text only,
/// multiple classes, multiple elements, ASCII case-fold, and entity-encoded
/// sinks — so a regression in either direction (false [V] or lost recall) fails
/// a named row.
#[test]
fn test_has_marker_evidence_matrix() {
    let cm = crate::scanning::markers::class_marker();
    let im = crate::scanning::markers::id_marker();
    let up = cm.to_uppercase();

    // (name, payload, reflected body, expected evidence)
    let cases: Vec<(&str, String, String, bool)> = vec![
        // ── handler templates: sink lives on the marker element ──
        (
            "svg_onload_full",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg onload=alert() class=\"{cm}\"></svg>"),
            true,
        ),
        (
            "svg_onload_handler_stripped",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg class=\"{cm}\"></svg>"),
            false,
        ),
        (
            "svg_onload_handler_blanked",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg onload=\"\" class=\"{cm}\"></svg>"),
            false,
        ),
        (
            "svg_onload_handler_neutralised",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg onload=\"void(0)\" class=\"{cm}\"></svg>"),
            false,
        ),
        (
            "breakout_class_first_full",
            format!("'\"><svg/class={cm} onload=alert()//"),
            format!("<svg class=\"{cm}\" onload=\"alert()//\"></svg>"),
            true,
        ),
        (
            "breakout_class_first_truncated",
            format!("'\"><svg/class={cm} onload=alert()//"),
            format!("<svg class=\"{cm}\"></svg>"),
            false,
        ),
        (
            "img_onerror_full",
            format!("<img src=x onerror=alert(1) class={cm}>"),
            format!("<img src=x onerror=alert(1) class=\"{cm}\">"),
            true,
        ),
        (
            "img_onerror_stripped",
            format!("<img src=x onerror=alert(1) class={cm}>"),
            format!("<img src=x class=\"{cm}\">"),
            false,
        ),
        // ── script-body template: sink lives in the <script> body ──
        (
            "script_body_full",
            format!("<script class={cm}>alert(1)</script>"),
            format!("<script class=\"{cm}\">alert(1)</script>"),
            true,
        ),
        (
            "script_body_emptied",
            format!("<script class={cm}>alert(1)</script>"),
            format!("<script class=\"{cm}\"></script>"),
            false,
        ),
        // ── marker placement / parsing edge cases ──
        (
            "marker_among_multiple_classes",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg onload=alert() class=\"a {cm} b\"></svg>"),
            true,
        ),
        (
            "marker_as_text_only_no_element",
            format!("<svg onload=alert() class={cm}>"),
            format!("<p>blocked input: class={cm} onlo...</p>"),
            false,
        ),
        (
            "multiple_markers_one_carries_handler",
            format!("<svg onload=alert() class={cm}>"),
            format!("<svg class=\"{cm}\"></svg><svg onload=alert() class=\"{cm}\"></svg>"),
            true,
        ),
        // ── structural markers: presence is the exploit, no sink to verify ──
        (
            "structural_base_id",
            format!("<base href=//evil/ id={im}>"),
            format!("<base href=\"//evil/\" id=\"{im}\">"),
            true,
        ),
        (
            "structural_clobber_form",
            format!(
                "<form id={im} class={cm}><input name=action value=\"javascript:alert(1)\"></form>"
            ),
            format!(
                "<form id=\"{im}\" class=\"{cm}\"><input name=action value=\"javascript:alert(1)\"></form>"
            ),
            true,
        ),
        // ── legacy `dalfox` marker ──
        (
            "legacy_dalfox_full",
            "<img class=dalfox src=x onerror=alert(1)>".to_string(),
            "<img class=\"dalfox\" src=x onerror=alert(1)>".to_string(),
            true,
        ),
        (
            "legacy_dalfox_stripped",
            "<img class=dalfox src=x onerror=alert(1)>".to_string(),
            "<img class=\"dalfox\">".to_string(),
            false,
        ),
        // ── server uppercases every reflected byte (ASCII case-fold) ──
        (
            "casefold_handler_survives",
            format!("<img src=x onerror=alert(1) class={cm}>"),
            format!("<IMG SRC=X ONERROR=ALERT(1) CLASS=\"{up}\">"),
            true,
        ),
        (
            "casefold_handler_stripped",
            format!("<img src=x onerror=alert(1) class={cm}>"),
            format!("<IMG CLASS=\"{up}\">"),
            false,
        ),
        // ── WAF-bypass: entity-encoded sink decodes to a live handler ──
        (
            "entity_encoded_sink_survives",
            format!("<svg onload=alert&#40;1&#41; class={cm}>"),
            format!("<svg onload=\"alert(1)\" class=\"{cm}\"></svg>"),
            true,
        ),
        // numeric hex entity form in the sink value (tests shared decoder recovery)
        (
            "entity_encoded_sink_numeric_hex",
            format!("<svg onload=alert&#x28;1&#x29; class={cm}>"),
            format!("<svg onload=\"alert(1)\" class=\"{cm}\"></svg>"),
            true,
        ),
        // server emitted uppercase named entity in handler value; DOM decoder + value_carries must recover
        (
            "entity_encoded_sink_upper_named_in_value",
            format!("<img src=x onerror=alert(1) class={cm}>"),
            format!("<img src=x onerror=\"ALERT&#40;1&#41;\" class=\"{cm}\">"),
            true,
        ),
    ];

    for (name, payload, body, expected) in cases {
        assert_eq!(
            has_marker_evidence(&payload, &body),
            expected,
            "case `{name}`: payload={payload:?} body={body:?}"
        );
    }
}

/// Exercise the shared fixtures reflect() helper + both decoders (reflection
/// classify + DOM classify_dom_evidence / has_html_structural) on a
/// structural payload whose handler value uses entity encoding (WAF bypass
/// style). The DOM decoder must turn the payload's &#40; into ( so the
/// "sink value verbatim in payload or its decode" check passes against the
/// parsed attr. Cross-checks decoder unification + fixture usage.
#[test]
fn test_fixtures_reflect_entity_structural_roundtrip_with_decoders() {
    use crate::scanning::dom_evidence_fixtures::{Transform, reflect};
    // Structural tag payload with entity-encoded parens inside the handler
    // (common WAF-bypass shape). Full reflect: server echoes the syntax raw.
    let payload = "<svg onload=alert&#40;1&#41;>".to_string();
    let body = reflect(&payload, Transform::Full, "<div>reflected: {PAYLOAD}</div>");
    // has_html_structural will parse the body (creating <svg> with onload="alert(1)"),
    // then require that "alert(1)" appears in payload or (more relevant here)
    // in decode_html_entities(payload). The shared decoder must succeed.
    assert!(
        crate::scanning::check_dom_verification::has_dom_evidence(&payload, &body),
        "structural with entity-encoded sink value in payload must yield DOM evidence via decoder"
    );
    let kind = crate::scanning::check_reflection::classify_reflection(&body, &payload);
    assert!(kind.is_some(), "must still classify as a reflection");
}

#[test]
fn test_has_executable_url_attribute_evidence_detects_iframe_src_protocol() {
    let payload = "javascript:alert(1)";
    let body = "<html><body><iframe src=\"javascript:alert(1)\"></iframe></body></html>";
    assert!(has_dom_evidence(payload, body));
}

/// The server-side template often appends bytes around the reflected
/// payload (a trailing comment, a serialized `&next=…`, an HTML entity).
/// Browsers parse the entire attribute value as one URL, so when the value
/// still *starts* with an executable scheme and the payload bytes appear
/// verbatim inside it, the navigation still fires. The previous strict
/// equality check rejected these, costing real findings.
#[test]
fn test_has_executable_url_attribute_evidence_with_trailing_bytes() {
    let payload = "javascript:alert(1)";
    let body = "<html><body><a href=\"javascript:alert(1)//&next=/home\">go</a></body></html>";
    assert!(
        has_dom_evidence(payload, body),
        "trailing bytes after the reflected javascript: URL must still verify"
    );
}

#[test]
fn test_has_executable_url_attribute_evidence_not_a_substring_match() {
    // Page already had its own javascript: URL; our payload appears nowhere
    // inside the attribute value. Must NOT count as evidence.
    let payload = "javascript:alert(1)";
    let body = "<html><body><a href=\"javascript:console.log('hi')\">x</a></body></html>";
    assert!(
        !has_dom_evidence(payload, body),
        "an unrelated javascript: URL must not verify our payload"
    );
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
fn test_classify_dom_evidence_returns_inline_handler_breakout() {
    // xss-game L4 shape: server emits `<img onload="startTimer('USER')">`,
    // the browser decodes the `&#39;` HTML entity at attribute-parse
    // time, so the handler becomes `startTimer('';-alert(1)-'')` and
    // the alert fires.
    let payload = "'-alert(1)-'";
    let body = "<img onload=\"startTimer('&#39;-alert(1)-&#39;');\">".to_string();
    assert_eq!(
        classify_dom_evidence(payload, &body),
        Some(DomEvidenceKind::InlineHandlerBreakout)
    );
}

#[test]
fn test_inline_handler_breakout_ignores_short_payload_substring_match() {
    // A short payload like `'` or `");` will accidentally match the
    // bytes of any page-defined `onclick="alert('hi')"` — the strict
    // `contains(payload)` check alone isn't enough. The length floor
    // (MIN_INLINE_HANDLER_BREAKOUT_PAYLOAD_LEN) keeps short payloads
    // from auto-upgrading R to V.
    let payload = "');";
    let body = "<button onclick=\"alert('hi');\">Click</button>".to_string();
    assert_eq!(classify_dom_evidence(payload, &body), None);
}

#[test]
fn test_inline_handler_breakout_ignores_unrelated_alert_in_handler() {
    // Page-defined `onclick="alert('hi')"` shares the `alert(`
    // substring with the payload list. Without the
    // `attr_value.contains(payload)` strictness check we'd false-V
    // every reflection. Confirm the strict check holds.
    let payload = "'-alert(1)-'";
    let body = "<button onclick=\"alert('hi')\">Click</button>".to_string();
    assert_eq!(classify_dom_evidence(payload, &body), None);
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
fn test_classify_dom_evidence_realworld_marker_in_comment_and_body() {
    // xssmaze /realworld/level1 reflects the query twice: once with angles
    // stripped inside an HTML comment, and once raw inside `<h2>`. With
    // the standard marker-bearing payload, the marker should be found in
    // the parsed DOM. Pinning this regression: dalfox previously reported
    // only R against this shape (3045 R-only on deep-scan).
    let class_marker = crate::scanning::markers::class_marker();
    let payload = format!("<svg/onload=alert(1) class={}>", class_marker);
    let body = format!(
        "<!-- search: svg/onload=alert(1) class={} --><h2>Results for: {}</h2>",
        class_marker, payload
    );
    assert!(
        has_dom_evidence(&payload, &body),
        "marker carried on a <svg> inside <h2> must be detected as DOM evidence; \
         current behavior on /realworld/level1 was 'R only'"
    );
}

#[test]
fn test_classify_dom_evidence_comment_breakout() {
    // xssmaze /realworld/level1 shape: payload reflects raw inside a
    // following <h2>, and via a comment-breakout sequence
    // (--><payload><!--) the comment is closed mid-page. After parsing,
    // the introduced <svg onload=…> element should fire structural
    // evidence. Pinning this here flagged the gap where dalfox surfaced
    // only R despite the payload trivially producing a sink element.
    let payload = "--><svg/onload=alert(1)><!--";
    let body = format!(
        "<!-- search: {} --><h2>Results for: {}</h2>",
        payload, payload
    );
    assert_eq!(
        classify_dom_evidence(payload, &body),
        Some(DomEvidenceKind::HtmlStructural),
        "comment-breakout payload that introduces <svg onload=alert(1)> \
         must classify as structural HTML evidence"
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

#[tokio::test]
async fn test_check_dom_verification_rejects_javascript_url_in_img_src() {
    // `<img src="javascript:alert(1)">` is structurally not exploitable —
    // browsers refuse the scheme on img@src. Verification must not fire.
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/url-attribute-img");
    let param = make_param();
    let args = default_scan_args();

    let (found, _body) =
        check_dom_verification(&target, &param, "javascript:alert(1)", &args).await;
    assert!(
        !found,
        "javascript: scheme reflected into img@src must not be a verified finding"
    );
}

#[tokio::test]
async fn test_check_dom_verification_skips_body_on_redirect_response() {
    // A 307 whose body echoes the payload — body has marker, looks like
    // text/html, would satisfy DOM evidence if naively parsed. Browsers
    // never render a 3xx body, so verification must short-circuit on the
    // redirect status without consulting the body.
    let payload = format!(
        "<img src=x onerror=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/dom/redirect-body");
    let param = make_param();
    let args = default_scan_args();

    let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
    assert!(
        !found,
        "DOM evidence in a 3xx response body must not be treated as verified"
    );
    assert!(body.is_none(), "no body should be returned for redirects");
}

#[test]
fn test_is_executable_url_attribute_pin_whitelist() {
    // Pin the (element, attribute) pairs that browsers actually dereference
    // as code. xssmaze /mediacontext exercises src reflections on every media
    // element; verification must NOT promote those to V, while the genuine
    // navigation/frame-load/submit pairs must keep doing so. Any change to
    // the whitelist surfaces here instead of silently flipping behavior.

    // Should be exec URL contexts (V allowed):
    for (tag, attr) in [
        ("a", "href"),
        ("area", "href"),
        ("base", "href"),
        ("link", "href"),
        ("iframe", "src"),
        ("embed", "src"),
        ("frame", "src"),
        ("iframe", "srcdoc"),
        ("object", "data"),
        ("form", "action"),
        ("input", "formaction"),
        ("button", "formaction"),
        ("a", "xlink:href"),
        ("use", "xlink:href"),
        // Case insensitivity guarantee
        ("A", "HREF"),
        ("IFRAME", "Src"),
    ] {
        assert!(
            is_executable_url_attribute(tag, attr),
            "{tag}@{attr} must be a verified-V exec URL context"
        );
    }

    // Resource-fetch / inert pairs (V forbidden — only R should fire):
    for (tag, attr) in [
        ("img", "src"),
        ("audio", "src"),
        ("video", "src"),
        ("source", "src"),
        ("script", "src"),
        ("track", "src"),
        // Other innocuous combinations
        ("img", "alt"),
        ("a", "target"),
        ("div", "data-href"),
        ("link", "rel"),
        ("meta", "content"),
        ("iframe", "name"),
    ] {
        assert!(
            !is_executable_url_attribute(tag, attr),
            "{tag}@{attr} must NOT be treated as exec URL context"
        );
    }
}

// ---------------------------------------------------------------------------
// Payload × transform matrices (issue #1124)
//
// The marker-evidence matrix lives with the #1118/#1123 handler-survival fix.
// These tables extend the same pattern to the *other* DOM-evidence kinds —
// executable-URL attribute, HTML-structural, and inline-handler breakout — so
// each kind is exercised against bodies produced by an explicit, reviewable
// server transform (`reflect(payload, Transform, sink)`) rather than ad-hoc
// hand-written HTML. Every row documents "what the server did", and the
// expected verdict is checked against that transform.
// ---------------------------------------------------------------------------
use crate::scanning::dom_evidence_fixtures::{Transform, reflect};

#[test]
fn test_executable_url_evidence_matrix() {
    // Payload is a bare `javascript:` URL; the sink template decides the
    // reflection context (navigational vs resource-fetch attribute).
    let payload = "javascript:alert(1)";
    let nav = r#"<html><body><a href="{PAYLOAD}">go</a></body></html>"#;
    let img = r#"<html><body><img src="{PAYLOAD}"></body></html>"#;

    // (label, transform, sink, expected_kind) — pin the exact evidence path so
    // a regression that confirms via the wrong kind is caught, not just masked.
    let hit = Some(DomEvidenceKind::ExecutableUrl);
    let cases: &[(&str, Transform, &str, Option<DomEvidenceKind>)] = &[
        ("full reflect into a@href", Transform::Full, nav, hit),
        // HTML-entity encoding does NOT defang a scheme with no markup
        // metacharacters — the href still navigates. URL/percent encoding is
        // the real defence here.
        (
            "entity-encoded into a@href",
            Transform::EntityEncoded,
            nav,
            hit,
        ),
        // Percent-encoding breaks the `:` so it is no longer a URL scheme.
        (
            "percent-encoded into a@href",
            Transform::PercentEncoded,
            nav,
            None,
        ),
        // Schemes are matched case-insensitively, mirroring the browser.
        ("case-folded into a@href", Transform::CaseFolded, nav, hit),
        // Truncated before `(` — the full payload no longer appears in the value.
        (
            "truncated at '(' into a@href",
            Transform::TruncatedAt("("),
            nav,
            None,
        ),
        // Same scheme, reflected into a resource-fetch attribute the browser
        // never executes as code: the "sink" is not actually a sink.
        ("full reflect into img@src", Transform::Full, img, None),
    ];

    for (label, transform, sink, expected) in cases {
        let body = reflect(payload, *transform, sink);
        assert_eq!(
            classify_dom_evidence(payload, &body),
            *expected,
            "executable-URL matrix row `{label}` mismatched on body: {body}"
        );
    }
}

#[test]
fn test_html_structural_evidence_matrix() {
    // Payload introduces a real element carrying an event-handler sink.
    let payload = "<svg onload=alert(1)>";
    let text_sink = "<html><body>results: {PAYLOAD}</body></html>";

    let hit = Some(DomEvidenceKind::HtmlStructural);
    let cases: &[(&str, Transform, Option<DomEvidenceKind>)] = &[
        ("full reflect", Transform::Full, hit),
        // Element survives but the handler that carried the sink is gone.
        ("handler stripped", Transform::HandlerStripped, None),
        // Handler attribute present but emptied — no sink call.
        ("handler blanked", Transform::HandlerBlanked, None),
        // Angle brackets escaped → inert text, scraper builds no <svg> element.
        ("entity encoded", Transform::EntityEncoded, None),
        // Percent escapes are not decoded by the HTML parser → inert text.
        ("percent encoded", Transform::PercentEncoded, None),
        // `ALERT` is a distinct (undefined) identifier; JS is case-sensitive.
        ("case folded", Transform::CaseFolded, None),
        // Truncated before the handler — element with no usable handler.
        (
            "truncated before handler",
            Transform::TruncatedAt("onload"),
            None,
        ),
    ];

    for (label, transform, expected) in cases {
        let body = reflect(payload, *transform, text_sink);
        assert_eq!(
            classify_dom_evidence(payload, &body),
            *expected,
            "html-structural matrix row `{label}` mismatched on body: {body}"
        );
    }
}

#[test]
fn test_inline_handler_breakout_evidence_matrix() {
    // xss-game L4 shape: the server's own template wraps the reflected payload
    // inside an existing `on*` handler's JS string argument.
    let payload = "'-alert(1)-'";
    let handler_sink = r#"<img onload="startTimer('{PAYLOAD}')">"#;
    // A non-handler reflection context (server emits no `on*` attribute).
    let text_sink = "<div>startTimer('{PAYLOAD}')</div>";

    let hit = Some(DomEvidenceKind::InlineHandlerBreakout);
    let cases: &[(&str, Transform, &str, Option<DomEvidenceKind>)] = &[
        // Raw reflection: the single quotes break the JS string immediately.
        (
            "full reflect into on-handler",
            Transform::Full,
            handler_sink,
            hit,
        ),
        // Server entity-encodes the quote, but the browser decodes `&#39;` at
        // attribute-parse time, so the breakout still fires (the L4 lesson).
        (
            "entity-encoded quote in on-handler",
            Transform::EntityEncoded,
            handler_sink,
            hit,
        ),
        // Percent escapes stay literal in an HTML attribute → no breakout.
        (
            "percent-encoded quote in on-handler",
            Transform::PercentEncoded,
            handler_sink,
            None,
        ),
        // `ALERT` is not the real sink under case-sensitive JS.
        (
            "case-folded in on-handler",
            Transform::CaseFolded,
            handler_sink,
            None,
        ),
        // No `on*` attribute at all → nothing to break out of.
        (
            "reflected outside any handler",
            Transform::Full,
            text_sink,
            None,
        ),
    ];

    for (label, transform, sink, expected) in cases {
        let body = reflect(payload, *transform, sink);
        assert_eq!(
            classify_dom_evidence(payload, &body),
            *expected,
            "inline-handler matrix row `{label}` mismatched on body: {body}"
        );
    }
}

#[test]
fn html_structural_evidence_matches_entity_encoded_payload() {
    // WAF-bypass payloads entity-encode the sink chars (`alert&#40;1&#41;`), but
    // scraper decodes the parsed attribute back to `alert(1)`. The containment
    // check must compare against the entity-decoded payload too, otherwise a
    // genuine breakout is downgraded from Verified to Reflected.
    let payload = "<svg onload=alert&#40;1&#41; class=dalfox>";
    let doc = scraper::Html::parse_document(r#"<svg onload="alert(1)" class="dalfox"></svg>"#);
    assert!(
        has_html_structural_evidence_in_doc(payload, &doc),
        "entity-encoded payload should still match the decoded attribute value"
    );
}
