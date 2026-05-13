use super::*;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use crate::target_parser::parse_target;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
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

async fn raw_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", q))
}

async fn html_entity_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", html_named_encode_all(&q)))
}

/// Mirrors brutelogic c1: reflects the param into a JS string literal
/// after HTML-encoding `'` and `<`. Browser does not decode entities
/// inside `<script>` so the reflection is inert.
async fn js_string_apos_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!(
        "<html><body><script>var c1 = '{}';</script></body></html>",
        html_named_encode_all(&q)
    ))
}

async fn url_encoded_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    Html(format!("<div>{}</div>", urlencoding::encode(&q)))
}

async fn form_urlencoded_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let q = params.get("q").cloned().unwrap_or_default();
    let encoded = urlencoding::encode(&q).to_string().replace("%20", "+");
    Html(format!("<div>{}</div>", encoded))
}

async fn none_handler() -> Html<&'static str> {
    Html("<div>not reflected</div>")
}

async fn json_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        format!("{{\"echo\":\"{}\"}}", q),
    )
}

async fn sxss_handler(State(state): State<TestState>) -> Html<String> {
    Html(format!("<div>{}</div>", state.stored_payload))
}

/// Returns 302 with Location containing the decoded `q` param. Simulates a
/// server that parses the query string and rebuilds the redirect URL.
async fn redirect_decoded_handler(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default();
    (
        StatusCode::FOUND,
        [("location", format!("/final?next={}", q))],
    )
}

async fn start_mock_server(stored_payload: &str) -> SocketAddr {
    let app = Router::new()
        .route("/reflect/raw", get(raw_handler))
        .route("/reflect/html-entity", get(html_entity_handler))
        .route("/reflect/js-string-apos", get(js_string_apos_handler))
        .route("/reflect/url-encoded", get(url_encoded_handler))
        .route("/reflect/form-url-encoded", get(form_urlencoded_handler))
        .route("/reflect/none", get(none_handler))
        .route("/reflect/json", get(json_handler))
        .route("/sxss/stored", get(sxss_handler))
        .route("/redirect/decoded", get(redirect_decoded_handler))
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
async fn test_check_reflection_early_return_when_skip() {
    let target = parse_target("https://example.com/?q=1").unwrap();
    let param = make_param();
    let mut args = default_scan_args();
    args.skip_xss_scanning = true;
    let res = check_reflection(&target, &param, "PAY", &args).await;
    assert!(
        !res,
        "should early-return false when skip_xss_scanning=true"
    );
}

#[tokio::test]
async fn test_check_reflection_with_response_early_return_when_skip() {
    let target = parse_target("https://example.com/?q=1").unwrap();
    let param = make_param();
    let mut args = default_scan_args();
    args.skip_xss_scanning = true;
    let res = check_reflection_with_response(&target, &param, "PAY", &args).await;
    assert_eq!(
        res,
        (None, None),
        "should early-return (None, None) when skip_xss_scanning=true"
    );
}

#[test]
fn test_decode_html_entities_basic() {
    let s = "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;";
    let d = decode_html_entities(s);
    assert!(d.contains("<script>"));
    assert!(d.contains("</script>"));
}

#[test]
fn test_decode_html_entities_uppercase_hex_x() {
    let s = "&#X3C;img src=x onerror=alert(1)&#X3E;";
    let d = decode_html_entities(s);
    assert!(d.contains("<img src=x onerror=alert(1)>"));
}

#[test]
fn test_decode_html_entities_named_common() {
    let s = "&lt;svg onload=alert(1)&gt; &amp; &quot; &apos;";
    let d = decode_html_entities(s);
    assert!(d.contains("<svg onload=alert(1)>"));
    assert!(d.contains("&"));
    assert!(d.contains("\""));
    assert!(d.contains("'"));
}

#[test]
fn test_decode_html_entities_decimal_and_hex_mix() {
    let s = "&#60;img src=x&#62; and &#x3C;svg&#x3E;";
    let d = decode_html_entities(s);
    assert_eq!(d, "<img src=x> and <svg>");
}

#[test]
fn test_decode_html_entities_named_case_insensitive() {
    let s = "&LT;script&GT;1&LT;/script&GT; &QuOt;ok&QuOt;";
    let d = decode_html_entities(s);
    assert!(d.contains("<script>1</script>"));
    assert!(d.contains("\"ok\""));
}

#[test]
fn test_decode_html_entities_ignores_invalid_numeric_sequences() {
    let s = "&#xZZ; &#;";
    let d = decode_html_entities(s);
    assert_eq!(d, s);
}

#[test]
fn test_classify_reflection_prefers_raw_match() {
    let payload = "<script>alert(1)</script>";
    let resp = format!("raw:{} encoded:{}", payload, urlencoding::encode(payload));
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_is_payload_reflected_html_encoded_in_unsafe_context() {
    // Entity-encoded reflection nested inside <script> — entities are not
    // decoded by the JS parser but the source still passes through it, so
    // the reflection is kept as an HtmlEntityDecoded finding for review.
    let payload = "<script>alert(1)</script>";
    let resp =
        "<script>var x = '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;';</script>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::HtmlEntityDecoded)
    );
}

#[test]
fn test_is_payload_reflected_html_encoded_in_safe_context_demoted() {
    // Same payload, but reflected into HTML body — the browser keeps the
    // entities as literal characters, the reflection is not exploitable,
    // and classification must demote to `None` (no R Info noise).
    let payload = "<script>alert(1)</script>";
    let resp = "<div>prefix &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e; suffix</div>";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_is_payload_reflected_html_encoded_in_attribute_value_demoted() {
    // Realistic shape of an Open Graph meta-tag reflecting the query string
    // back with HTML-entity escaping. Both `&quot;` and `&lt;`/`&gt;` are
    // present — the attribute value cannot be broken out of, so the
    // reflection must demote.
    let payload = "\">'><IMG src=x onerror=alert(1)>\"";
    let resp = concat!(
        "<meta property=\"og:url\" ",
        "content=\"https://example.com/?s=&quot;&gt;&#39;&gt;&lt;IMG src=x onerror=alert(1)&gt;&quot;\">"
    );
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_is_payload_reflected_html_encoded_in_event_handler_kept() {
    // The browser decodes entities inside an `on*=…` attribute value before
    // handing the result to the JS parser, so entity escaping is not
    // sufficient there — the reflection must remain visible.
    let payload = "alert(1)";
    let resp = "<button onclick=\"&#x61;lert&#40;1&#41;\">x</button>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::HtmlEntityDecoded)
    );
}

#[test]
fn test_is_payload_reflected_url_encoded() {
    let payload = "<img src=x onerror=alert(1)>";
    let encoded = urlencoding::encode(payload).to_string();
    let resp = format!("ok {} end", encoded);
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::UrlDecoded)
    );
}

#[test]
fn test_is_payload_reflected_form_urlencoded_plus_spaces() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let resp = "<img+src=x+onerror=alert(1)+class=dalfox>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::UrlDecoded)
    );
}

#[test]
fn test_is_payload_reflected_percent_encoded_with_plus_spaces() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let resp = "%3Cimg+src%3Dx+onerror%3Dalert%281%29+class%3Ddalfox%3E";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::UrlDecoded)
    );
}

#[test]
fn test_is_payload_reflected_quadruple_encoded_payload_variant() {
    let payload =
        crate::encoding::quadruple_url_encode("<img src=x onerror=alert(1) class=dalfox>");
    let resp = "<img+src=x+onerror=alert(1)+class=dalfox>";
    assert_eq!(
        classify_reflection(resp, &payload),
        Some(ReflectionKind::UrlDecoded)
    );
}

#[test]
fn test_is_payload_reflected_double_layer_percent_entity_then_url() {
    // Server returns percent sign as HTML-entity, which then precedes URL-encoded payload
    let payload = "<script>alert(1)</script>";
    // Build a string like: &#37;3Cscript%3Ealert(1)%3C%2Fscript%3E
    let url_once = urlencoding::encode(payload).to_string();
    let resp = url_once.replace("%", "&#37;");
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::HtmlThenUrlDecoded)
    );
}

#[test]
fn test_is_payload_reflected_negative() {
    let payload = "<svg/onload=alert(1)>";
    let resp = "benign content without the thing";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_is_payload_reflected_html_named_uppercase() {
    // Uppercase named entities must still decode for classification. Placed
    // inside `<style>` so the unsafe-context gate keeps the reflection
    // visible — body-context placement would be demoted (covered by the
    // safe-context test above).
    let payload = "<svg onload=alert(1)>";
    let resp = "<style>body::before{content:'&LT;svg onload=alert(1)&GT;'}</style>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::HtmlEntityDecoded)
    );
}

#[tokio::test]
async fn test_check_reflection_detects_raw_response() {
    let payload = "<script>alert(1)</script>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/raw");
    let param = make_param();
    let args = default_scan_args();

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(found, "raw reflection should be detected");
}

#[tokio::test]
async fn test_check_reflection_demotes_html_entity_response_in_safe_context() {
    // The mock handler entity-encodes the payload and reflects it into a
    // plain `<div>` — a safe HTML body context. Entity escaping makes the
    // reflection inert, so classification must demote to `None` and
    // `check_reflection` must report no reflection found.
    let payload = "<img src=x onerror=alert(1)>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/html-entity");
    let param = make_param();
    let args = default_scan_args();

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(
        !found,
        "entity-encoded reflection inside a safe body context should be demoted"
    );
}

#[tokio::test]
async fn test_check_reflection_suppresses_inert_js_string_apos_reflection() {
    // brutelogic c1 fixture: payload `'-alert(1)-'` reflected as
    // `var c1 = '&apos;-alert(1)-&apos;';` inside <script>. Inside a
    // script block HTML entities never decode, so this is inert text
    // and must not produce an R finding.
    let payload = "'-alert(1)-'";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/js-string-apos");
    let param = make_param();
    let args = default_scan_args();

    let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
    assert_eq!(
        kind, None,
        "apos-encoded JS-string reflection should be classified inert (no R)"
    );
    assert!(
        body.unwrap_or_default().contains("&apos;"),
        "fixture should reflect the encoded form"
    );
}

#[tokio::test]
async fn test_check_reflection_detects_url_encoded_response() {
    let payload = "<svg onload=alert(1)>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/url-encoded");
    let param = make_param();
    let args = default_scan_args();

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(found, "URL-encoded reflection should be detected");
}

#[tokio::test]
async fn test_check_reflection_detects_form_urlencoded_response_runtime() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/form-url-encoded");
    let param = make_param();
    let args = default_scan_args();

    let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
    assert_eq!(kind, Some(ReflectionKind::UrlDecoded));
    assert!(
        body.unwrap_or_default()
            .contains("%3Cimg+src%3Dx+onerror%3Dalert%281%29+class%3Ddalfox%3E"),
        "form-style encoded response should be preserved for inspection"
    );
}

#[tokio::test]
async fn test_check_reflection_returns_false_when_not_reflected() {
    let payload = "<svg/onload=alert(1)>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/none");
    let param = make_param();
    let args = default_scan_args();

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(!found, "non-reflective response should not be detected");
}

#[tokio::test]
async fn test_check_reflection_with_response_demotes_safe_html_entity_reflection() {
    // The handler entity-encodes the payload into HTML body — a safe
    // context. Classification must return `None` while the actual response
    // body is still returned (callers may need it for AST analysis even
    // when the reflection itself is not exploitable).
    let payload = "<script>alert(1)</script>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/html-entity");
    let param = make_param();
    let args = default_scan_args();

    let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
    assert_eq!(
        kind, None,
        "safe-context entity reflection must not produce a reflection kind"
    );
    assert!(
        body.unwrap_or_default().contains("&lt;script&gt;"),
        "response body should still be propagated to callers"
    );
}

#[tokio::test]
async fn test_check_reflection_with_response_not_reflected() {
    let payload = "<script>alert(1)</script>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/none");
    let param = make_param();
    let args = default_scan_args();

    let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
    assert_eq!(kind, None);
    assert!(
        body.is_some(),
        "request succeeded so response body should be returned"
    );
}

#[tokio::test]
async fn test_check_reflection_sxss_uses_secondary_url() {
    let payload = "STORED_XSS_PAYLOAD";
    let addr = start_mock_server(payload).await;
    let target = make_target(addr, "/reflect/none");
    let param = make_param();
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = Some(format!("http://{}:{}/sxss/stored", addr.ip(), addr.port()));

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(found, "sxss mode should verify reflection via sxss_url");
}

#[tokio::test]
async fn test_check_reflection_sxss_without_url_returns_false() {
    let payload = "STORED_XSS_PAYLOAD";
    let addr = start_mock_server(payload).await;
    let target = make_target(addr, "/reflect/raw");
    let param = make_param();
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = None;

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(!found, "sxss mode without sxss_url should return false");
}

#[tokio::test]
async fn test_check_reflection_catches_decoded_payload_in_redirect_location() {
    // Server URL-decodes the query and echoes the raw payload back into the
    // Location header. The gate used to only match the encoded form, so
    // this reflection was silently missed. It must now be caught.
    let payload = "<svg/onload=alert(1)>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/redirect/decoded");
    let param = make_param();
    let args = default_scan_args();
    assert!(
        check_reflection(&target, &param, payload, &args).await,
        "reflection check must catch the raw payload appearing in Location"
    );
}

#[tokio::test]
async fn test_check_reflection_with_response_handles_json_raw_reflection() {
    let payload = "<svg/onload=alert(1)>";
    let addr = start_mock_server("stored").await;
    let target = make_target(addr, "/reflect/json");
    let param = make_param();
    let args = default_scan_args();

    let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
    assert_eq!(kind, Some(ReflectionKind::Raw));
    assert!(body.unwrap_or_default().contains("echo"));
}

// --- Safe context filtering tests ---

#[test]
fn test_safe_context_textarea() {
    let payload = "<script>alert(1)</script>";
    let html = format!("<html><textarea>{}</textarea></html>", payload);
    assert!(is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_noscript() {
    let payload = "<img src=x onerror=alert(1)>";
    let html = format!("<html><noscript>{}</noscript></html>", payload);
    assert!(is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_title() {
    let payload = "<script>alert(1)</script>";
    let html = format!("<html><head><title>{}</title></head></html>", payload);
    assert!(is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_style() {
    // Style is intentionally NOT a safe context — CSS injection can break
    // out via </style> and inject executable HTML.
    let payload = "expression(alert(1))";
    let html = format!("<html><style>{}</style></html>", payload);
    assert!(
        !is_in_safe_context(&html, payload),
        "style should NOT be a safe context"
    );
}

#[test]
fn test_safe_context_mixed_safe_and_unsafe() {
    let payload = "<script>alert(1)</script>";
    let html = format!(
        "<html><textarea>{}</textarea><div>{}</div></html>",
        payload, payload
    );
    assert!(
        !is_in_safe_context(&html, payload),
        "mixed context should NOT be considered safe"
    );
}

#[test]
fn test_safe_context_outside_safe_tag() {
    let payload = "<script>alert(1)</script>";
    let html = format!("<html><div>{}</div></html>", payload);
    assert!(!is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_no_payload() {
    assert!(is_in_safe_context(
        "<html><body>nothing</body></html>",
        "PAYLOAD"
    ));
}

#[test]
fn test_safe_context_title_breakout() {
    let payload = "</title><IMG src=x onerror=alert(1) ClAss=dlxtest>";
    let html = format!(
        "<html><head><title>{}</title></head><body></body></html>",
        payload
    );
    // Breakout payload closes the title tag, so the IMG is outside the safe context
    assert!(
        !is_in_safe_context(&html, payload),
        "title breakout payload should NOT be considered safe"
    );
}

#[test]
fn test_safe_context_textarea_breakout() {
    let payload = "</textarea><IMG src=x onerror=alert(1) ClAss=dlxtest>";
    let html = format!("<html><body><textarea>{}</textarea></body></html>", payload);
    assert!(
        !is_in_safe_context(&html, payload),
        "textarea breakout payload should NOT be considered safe"
    );
}

// --- Inert-in-script-block heuristic ---

#[test]
fn test_inert_in_scripts_entity_encoded_payload_in_js_string() {
    // Mirrors brutelogic c5/c6: server reflects the entity-encoded payload
    // verbatim inside a JS string literal — not exploitable in JS context.
    let payload = "&#x0027;-alert(1)-&#x0027;";
    let html = format!("<script>var c5 = '{}';</script>", payload);
    assert!(
        is_payload_inert_in_scripts(&html, payload),
        "entity-encoded payload reflected only inside a JS string should be inert"
    );
    assert!(
        is_in_safe_context_decoded(&html, payload),
        "should classify as safe so the reflection is not reported"
    );
}

#[test]
fn test_inert_in_scripts_does_not_suppress_real_js_breakout() {
    // c2-style real exploit: payload introduces an `alert(1)` call inside
    // the JS — this MUST NOT be suppressed.
    let payload = "\"-alert(1)-\"";
    let html = format!("<script>var c2 = \"{}\";</script>", payload);
    assert!(
        !is_payload_inert_in_scripts(&html, payload),
        "exploitable JS-context payload must not be classified inert"
    );
}

#[test]
fn test_inert_in_scripts_requires_all_occurrences_inside_script() {
    let payload = "&#x0027;ZZZ&#x0027;";
    let html = format!(
        "<div>{}</div><script>var x = '{}';</script>",
        payload, payload
    );
    assert!(
        !is_payload_inert_in_scripts(&html, payload),
        "if the payload is also reflected outside a script block it is not inert"
    );
}

#[test]
fn test_inert_in_scripts_no_script_block_in_response() {
    let payload = "&#x0027;ZZZ&#x0027;";
    let html = format!("<div>{}</div>", payload);
    assert!(
        !is_payload_inert_in_scripts(&html, payload),
        "without any script block this heuristic should not apply"
    );
}

#[test]
fn test_inert_in_scripts_handles_entity_encoded_html_payload_in_js_string() {
    // Mirrors brutelogic c6 with the marker payload: server HTML-encodes
    // `<` to `&lt;` and reflects inside a JS string. Browser does not
    // decode entities inside <script>, so the payload is just text.
    let payload = "<img src=x onerror=alert(1) class=dlxtest>";
    let html = "<script>var c6 = \"&lt;img src=x onerror=alert(1) class=dlxtest>\";</script>";
    assert!(
        is_payload_inert_in_scripts(html, payload),
        "entity-encoded HTML payload reflected only inside JS string should be inert"
    );
}

#[test]
fn test_inert_in_scripts_handles_apos_encoded_quote_in_js_string() {
    // Mirrors brutelogic c1: the server HTML-encodes the `'` chars of
    // `'-alert(1)-'` to `&apos;` before reflecting into a JS string.
    // Inside <script> entities never decode, so the reflection is text.
    let payload = "'-alert(1)-'";
    let html = "<script>var c1 = '&apos;-alert(1)-&apos;';</script>";
    assert!(
        is_payload_inert_in_scripts(html, payload),
        "apos-encoded JS-context payload reflected inside JS string should be inert"
    );
    assert!(
        is_in_safe_context_decoded(html, payload),
        "should classify safe so the R finding is suppressed"
    );
}

#[test]
fn test_inert_in_scripts_handles_url_encoded_payload_variant() {
    // Encoder policy often produces a URL-encoded variant of the original
    // payload; the server then URL-decodes once and reflects the decoded
    // form. The suppression heuristic must inspect that decoded form, not
    // the URL-encoded payload string verbatim.
    let payload = "%27-alert%281%29-%27"; // URL-encoded `'-alert(1)-'`
    let html = "<script>var c1 = '&apos;-alert(1)-&apos;';</script>";
    assert!(
        !html.contains(payload),
        "URL-encoded form should not appear"
    );
    assert!(
        is_payload_inert_in_scripts(html, payload),
        "URL-encoded JS-context payload reflected as decoded text inside JS string should be inert"
    );
}

#[test]
fn test_inert_in_scripts_url_encoded_does_not_suppress_real_breakout() {
    // URL-encoded form of `"-alert(1)-"` decodes to a real exploitable
    // breakout. Must NOT be suppressed.
    let payload = "%22-alert%281%29-%22";
    let html = "<script>var c2 = \"\"-alert(1)-\"\";</script>";
    assert!(
        !is_payload_inert_in_scripts(html, payload),
        "exploitable breakout via URL-decoded form must keep its finding"
    );
}

#[test]
fn test_inert_in_scripts_full_brutelogic_response() {
    // Full real-world response capture: c1 reflection inside a multi-block
    // script context with form inputs and HTML comments. Should be inert.
    let payload = "'-alert(1)-'";
    let html = r#"<!DOCTYPE html>
<head>
<!-- XSS in 11 URL parameters (a, b1, b2, b3, b4, b5, b6, c1, c2, c3, c4, c5 and c6) + URL itself -->
<title>XSS Test Page</title>
</head>
<body>
<form>
<input type="text" name="b1" value="">
<input type="text" name="b2" value=''>
</form>
<script>
	var c1 = '&apos;-alert(1)-&apos;';
	var c2 = "1";
	var c3 = '1';
	var c4 = "1";
	var c5 = '1';
	var c6 = "1";
</script>
</body>"#;
    assert!(!html.contains(payload), "payload should not appear raw");
    assert!(
        is_payload_inert_in_scripts(html, payload),
        "full-page response should still classify the apos-encoded reflection as inert"
    );
}

// --- Path-injection status-code filter ---

#[test]
fn test_suppress_path_reflection_on_404() {
    assert!(should_suppress_path_reflection(&Location::Path, 404));
    assert!(should_suppress_path_reflection(&Location::Path, 500));
    assert!(should_suppress_path_reflection(&Location::Path, 301));
}

#[test]
fn test_keep_path_reflection_on_2xx() {
    assert!(!should_suppress_path_reflection(&Location::Path, 200));
    assert!(!should_suppress_path_reflection(&Location::Path, 204));
}

#[test]
fn test_non_path_locations_are_unaffected() {
    assert!(!should_suppress_path_reflection(&Location::Query, 404));
    assert!(!should_suppress_path_reflection(&Location::Header, 500));
    assert!(!should_suppress_path_reflection(&Location::Body, 404));
}

#[tokio::test]
async fn test_path_reflection_suppressed_on_non_html_content_type() {
    // Mirrors brutelogic: path-injected URL returns 200 application/javascript
    // with the payload echoed in the JS body. Not exploitable as XSS — should
    // be filtered.
    async fn js_handler() -> impl IntoResponse {
        (
            StatusCode::OK,
            [("content-type", "application/javascript")],
            "// echo: <script>alert(1)</script>\nvar x = 1;",
        )
    }
    let app = Router::new().route("/path/echo", get(js_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{}/path/echo", addr)).expect("target");
    let mut param = make_param();
    param.name = "path_segment_0".to_string();
    param.location = Location::Path;
    let args = default_scan_args();

    let (kind, _body) =
        check_reflection_with_response(&target, &param, "<script>alert(1)</script>", &args).await;
    assert_eq!(
        kind, None,
        "path-injection reflection on application/javascript should be suppressed"
    );
}
