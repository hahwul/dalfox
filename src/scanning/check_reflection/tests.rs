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
        framework_sink: None,
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
        max_payloads_per_param: 0,
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
fn test_decode_html_entities_zero_padded_hex() {
    // Output shape of `html_entity_zero_padded_encode` — 7 hex digits per char.
    // The regex must accept this length so the resulting payload classifies
    // as entity-encoded by the same safe-context guard the 4-digit form uses.
    let s = "&#x0000003c;script&#x0000003e;alert(1)&#x0000003c;/script&#x0000003e;";
    let d = decode_html_entities(s);
    assert_eq!(d, "<script>alert(1)</script>");
}

#[test]
fn test_decode_html_entities_eight_digit_hex_boundary() {
    // 8 hex digits is the new upper bound. Verify it still decodes and that
    // 9-digit sequences fall through as literal text (regex must not match).
    assert_eq!(decode_html_entities("&#x0000003e;"), ">");
    let nine = "&#x000000003e;";
    assert_eq!(decode_html_entities(nine), nine);
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
    let resp = "<script>var x = '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;';</script>";
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
fn test_classify_reflection_demotes_entity_encoded_payload_in_html_body() {
    // The payload itself is HTML-entity encoded (e.g. encoder produced
    // `&#x003c;br&#x003e;`). The server reflects it verbatim into HTML body
    // context. Browsers decode the entities into literal text characters
    // and do NOT re-parse them as markup, so no `<br>` element is created.
    // Classification must demote — surfacing this as [R] is the false
    // positive we are trying to eliminate.
    let payload = "&#x003c;br&#x003e;";
    let resp = "<div>Hello &#x003c;br&#x003e; world</div>";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_entity_encoded_named_payload_in_html_body() {
    // Same idea using named entities. `&lt;img src=x onerror=alert(1)&gt;`
    // reflected verbatim into body context renders as visible text, not as
    // an `<img>` element.
    let payload = "&lt;img src=x onerror=alert(1)&gt;";
    let resp = format!("<p>echo: {} done</p>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_keeps_entity_encoded_payload_in_event_handler() {
    // Inside an `on*=` attribute the browser decodes HTML entities before
    // handing the value to the JS parser, so an entity-encoded payload
    // landing there IS exploitable. The reflection must survive.
    let payload = "&#x27;-alert(1)-&#x27;";
    let resp = "<button onclick=\"x=&#x27;-alert(1)-&#x27;\">x</button>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_classify_reflection_demotes_url_encoded_payload_in_html_body() {
    // The `url` adaptive encoder produces `%3Cbr%3E`. Reflected verbatim
    // in HTML body context, no HTML / JS / CSS parser decodes percent
    // sequences, so the reflection is inert. Without this guard the fast
    // path returned `Raw` and surfaced as [R] Info noise.
    let payload = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    let resp = format!("<div>echo {} done</div>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_double_url_encoded_payload_in_html_body() {
    // `2url` encoder doubles the percent layer (`%253C…`). Iterative URL
    // decode via `payload_variants` collapses both layers and ultimately
    // produces `<>` — the guard must demote.
    let payload = "%253Cscript%253Ealert(1)%253C%252Fscript%253E";
    let resp = format!("<p>{}</p>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_url_encoded_payload_in_event_handler() {
    // `%XX` is NOT decoded by the HTML parser inside attribute values, so
    // it is also inert in event-handler contexts. Unlike entity-encoded
    // payloads, URL-encoded payloads can be safely demoted here too.
    let payload = "%3Cscript%3E";
    let resp = "<button onclick=\"x='%3Cscript%3E'\">x</button>";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_url_encoded_payload_in_script_block() {
    // Inside `<script>` the JS parser sees `%XX` as literal characters
    // (likely a syntax error), never as `<` or `>`. Safe.
    let payload = "%3Cscript%3E";
    let resp = "<script>var x = '%3Cscript%3E';</script>";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_classify_reflection_keeps_url_encoded_javascript_scheme_in_href() {
    // URL-valued attributes are the one context where the browser DOES
    // percent-decode the value (when parsing the URL on navigation). A
    // payload decoding to `javascript:alert(1)` reflected in `href` IS
    // exploitable — the finding must survive.
    let payload = "javascript%3Aalert%281%29";
    let resp = format!("<a href=\"{}\">click</a>", payload);
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_classify_reflection_keeps_url_encoded_data_html_in_href() {
    // `data:text/html` URLs execute inline content on navigation.
    let payload = "data%3Atext%2Fhtml%2C%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    let resp = format!("<iframe src=\"{}\"></iframe>", payload);
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_classify_reflection_demotes_url_encoded_javascript_scheme_outside_url_attr() {
    // Same `javascript:`-scheme payload but reflected only in body text.
    // Without a URL attribute boundary the browser never navigates to
    // it — pure text rendering, safe.
    let payload = "javascript%3Aalert%281%29";
    let resp = format!("<div>visit {} please</div>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_url_encoded_javascript_scheme_in_non_url_attr() {
    // `title` is not a URL-valued attribute, so the browser never
    // percent-decodes its content for URL parsing. URL-encoded
    // `javascript:` here just renders as a tooltip string — safe.
    let payload = "javascript%3Aalert%281%29";
    let resp = format!("<span title=\"{}\">x</span>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_fullwidth_payload_in_html_body() {
    // `unicode` adaptive encoder maps ASCII to fullwidth (U+FF01-U+FF5E).
    // `<br>` becomes `＜br＞`. Browsers never normalize fullwidth to ASCII,
    // so the reflection cannot start a tag — must demote.
    let payload = "\u{ff1c}br\u{ff1e}";
    let resp = format!("<div>echo {} done</div>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_fullwidth_payload_in_event_handler() {
    // Fullwidth bytes are inert in every parser, including the JS parser
    // reached via event-handler entity decoding.
    let payload = "\u{ff1c}script\u{ff1e}alert(1)\u{ff1c}/script\u{ff1e}";
    let resp = format!("<button onclick=\"x='{}'\">x</button>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_fullwidth_payload_in_script_block() {
    let payload = "\u{ff1c}svg onload=alert(1)\u{ff1e}";
    let resp = format!("<script>var x = '{}';</script>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_demotes_fullwidth_payload_in_href() {
    // Even URL-valued attributes are safe — fullwidth `:` (U+FF1A) isn't
    // recognized as a scheme delimiter by URL parsers.
    let payload = "javascript\u{ff1a}alert(1)";
    let resp = format!("<a href=\"{}\">x</a>", payload);
    assert_eq!(classify_reflection(&resp, payload), None);
}

#[test]
fn test_classify_reflection_keeps_mixed_fullwidth_and_raw_specials() {
    // A payload mixing fullwidth and raw `<` still has the raw structural
    // char, so reflection IS exploitable. Guard must not demote.
    let payload = "\u{ff1c}br\u{ff1e}<script>alert(1)</script>";
    let resp = format!("<div>{}</div>", payload);
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_payload_is_fully_fullwidth_encoded_detection() {
    assert!(payload_is_fully_fullwidth_encoded("\u{ff1c}br\u{ff1e}"));
    assert!(payload_is_fully_fullwidth_encoded(
        "\u{ff1c}script\u{ff1e}alert(1)\u{ff1c}/script\u{ff1e}"
    ));
    // Fullwidth `:` enough to gate — covers fullwidth `javascript:` URLs
    // which the URL parser also refuses to recognize as a scheme.
    assert!(payload_is_fully_fullwidth_encoded(
        "javascript\u{ff1a}alert(1)"
    ));
    // Raw `<` present — not fully encoded
    assert!(!payload_is_fully_fullwidth_encoded("<br>"));
    // No fullwidth chars at all
    assert!(!payload_is_fully_fullwidth_encoded("plain text"));
    // A non-fullwidth non-ASCII char (CJK) by itself doesn't qualify —
    // the guard is specifically for the U+FF01-U+FF5E ASCII-fullwidth
    // block produced by `unicode_fullwidth_encode`.
    assert!(!payload_is_fully_fullwidth_encoded("\u{4e2d}"));
}

#[test]
fn test_payload_is_fully_url_encoded_detection() {
    assert!(payload_is_fully_url_encoded("%3Cscript%3E"));
    // `javascript:`-scheme payload: decoded form differs even though it
    // contains no raw `<>"'`. The URL-attr-scheme check downstream is
    // responsible for keeping these when reflected in href/src/etc.
    assert!(payload_is_fully_url_encoded("javascript%3Aalert%281%29"));
    // Double-URL form decodes to another encoded layer — still differs.
    assert!(payload_is_fully_url_encoded("%253Cscript%253E"));
    // Raw `<` present — not fully encoded
    assert!(!payload_is_fully_url_encoded("<script>%3C"));
    // No percent encoding — URL decode is a no-op.
    assert!(!payload_is_fully_url_encoded("plain text"));
}

#[test]
fn test_classify_reflection_keeps_mixed_payload_with_raw_specials() {
    // The payload mixes entity-encoded fragments with raw `<` / `>`, so the
    // raw portion creates real markup when reflected. The full-entity guard
    // must NOT demote here.
    let payload = "&#x003c;br&#x003e;<script>alert(1)</script>";
    let resp = format!("<div>{}</div>", payload);
    assert_eq!(
        classify_reflection(&resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_classify_reflection_demotes_zero_padded_entity_payload_in_html_body() {
    // `html_entity_zero_padded_encode` is a common WAF-bypass encoder. With
    // the entity regex bumped to {2,8}, these payloads decode the same way
    // 4-digit hex entities do, so the entity-encoded safe-context guard
    // automatically demotes verbatim reflections in HTML body context.
    let payload = "&#x0000003c;br&#x0000003e;";
    let resp = "<div>echo &#x0000003c;br&#x0000003e; done</div>";
    assert_eq!(classify_reflection(resp, payload), None);
}

#[test]
fn test_classify_reflection_keeps_zero_padded_entity_payload_in_event_handler() {
    // Same context rule as the 4-digit case: zero-padded entities decoded
    // inside an `on*=` attribute can still produce JS-significant chars,
    // so the reflection must survive.
    let payload = "&#x00000027;-alert(1)-&#x00000027;";
    let resp = "<button onclick=\"x=&#x00000027;-alert(1)-&#x00000027;\">x</button>";
    assert_eq!(
        classify_reflection(resp, payload),
        Some(ReflectionKind::Raw)
    );
}

#[test]
fn test_payload_is_fully_entity_encoded_detection() {
    assert!(payload_is_fully_entity_encoded("&#x003c;br&#x003e;"));
    assert!(payload_is_fully_entity_encoded(
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    ));
    // Has raw `<` — not fully encoded
    assert!(!payload_is_fully_entity_encoded("<br>"));
    // Has no entities at all
    assert!(!payload_is_fully_entity_encoded("plain text"));
    // Entity decodes to something with no HTML-significant chars — not the
    // shape this guard cares about (won't change reflection semantics).
    assert!(!payload_is_fully_entity_encoded("&#x41;"));
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

/// Regression: in SXSS mode the retrieval loop used to return the first
/// non-empty body without verifying the payload was in it. When the highest-
/// priority candidate (form_origin_url) returns an unrelated page (login
/// redirect, empty list, etc.) the loop exited before trying form_action_url
/// or target.url — even when those URLs contained the stored payload. Each
/// candidate body must now be classified before we give up.
#[tokio::test]
async fn test_check_reflection_sxss_skips_junk_url_and_finds_later_candidate() {
    let payload = "STORED_XSS_PAYLOAD";
    let addr = start_mock_server(payload).await;
    // Injection target points at /reflect/none, but the stored payload only
    // surfaces at /sxss/stored. form_origin_url points at a junk URL
    // (/reflect/none returns "<div>not reflected</div>") and form_action_url
    // is the real retrieval URL. The fix must continue past the junk URL.
    let target = make_target(addr, "/reflect/none");
    let mut param = make_param();
    param.form_origin_url = Some(format!("http://{}:{}/reflect/none", addr.ip(), addr.port()));
    param.form_action_url = Some(format!("http://{}:{}/sxss/stored", addr.ip(), addr.port()));
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = None;
    // Single retry per candidate keeps the test fast.
    args.sxss_retries = 1;

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(
        found,
        "sxss retrieval must continue past a candidate URL whose body lacks the payload"
    );
}

/// Inline-stored sink: the write-response body itself renders the stored
/// value (think POST /comments returning the rendered /comments page).
/// None of the retrieval URLs surface the payload, but the inject response
/// does — the SXSS path must catch this via the inject-body fallback.
#[tokio::test]
async fn test_check_reflection_sxss_falls_back_to_inject_response_body() {
    let payload = "STORED_XSS_PAYLOAD";
    let addr = start_mock_server("ignored").await;
    // target.url is /reflect/raw, which echoes the q param back in its
    // body. The inject GET to /reflect/raw?q=PAYLOAD therefore returns a
    // body containing the payload. The SXSS retrieval candidates all fail
    // to surface it (the original target.url uses q=seed, form_origin_url
    // points at /reflect/none).
    let target = make_target(addr, "/reflect/raw");
    let mut param = make_param();
    param.form_origin_url = Some(format!("http://{}:{}/reflect/none", addr.ip(), addr.port()));
    let mut args = default_scan_args();
    args.sxss = true;
    args.sxss_url = None;
    args.sxss_retries = 1;

    let found = check_reflection(&target, &param, payload, &args).await;
    assert!(
        found,
        "sxss must fall back to the inject-response body when retrieval URLs miss the payload"
    );
}

#[tokio::test]
async fn test_check_reflection_sxss_without_url_returns_false() {
    let payload = "STORED_XSS_PAYLOAD";
    let addr = start_mock_server(payload).await;
    // Point target at a handler that does NOT echo the query param, so
    // neither the retrieval fallback (GET target.url) nor the inject-body
    // fallback surface the payload. This isolates the "no SXSS signal
    // anywhere" case — distinct from the inline-stored-sink fallback test
    // above, which deliberately uses /reflect/raw to exercise the fallback.
    let target = make_target(addr, "/reflect/none");
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

// Regression: full-width unicode payloads (e.g. `＜svg…＞` produced by the
// `unicode` bypass encoder) must not panic the slice loop when reflected.
// Each full-width char is 3 bytes in UTF-8, so an `abs_pos + 1` advance would
// previously land inside a multi-byte codepoint and panic `html[idx..]`.
#[test]
fn test_safe_context_fullwidth_payload_no_panic() {
    let payload = "＜ｓｖｇ／ｏｎｌｏａｄ＝ａｌｅｒｔ（１）＞";
    let html = format!("<html><body><textarea>{}</textarea></body></html>", payload);
    // Inside <textarea>, so it is in a safe context — and must not panic.
    assert!(is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_fullwidth_payload_outside_textarea() {
    let payload = "＜ｓｖｇ／ｏｎｌｏａｄ＝ａｌｅｒｔ（１）＞";
    let html = format!("<html><body><div>{}</div></body></html>", payload);
    // Outside any safe tag — must report unsafe without panicking.
    assert!(!is_in_safe_context(&html, payload));
}

#[test]
fn test_safe_context_fullwidth_payload_in_title() {
    // Matches the firing range `/reflected/parameter/title` case that triggered
    // the original panic at byte 23 ("inside ＜ bytes 22..25").
    let payload = "＜ｓｖｇ／ｏｎｌｏａｄ＝ａｌｅｒｔ（１）＞";
    let html = format!(
        "<html>\n  <head><title>{}</title>\n  </head>\n  <body></body>\n</html>",
        payload
    );
    assert!(is_in_safe_context(&html, payload));
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

// --- Body-aware path reflection (4xx/5xx exploitable XSS preservation) ---

#[test]
fn test_url_attr_only_classifier_recognizes_anchor_href() {
    // `<a href="/foo/MARKER/bar">` — pure URL echo, no exploit surface.
    let html = "<html><a href=\"/users/MARKER/posts\">profile</a></html>";
    assert!(marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_url_attr_only_classifier_recognizes_canonical_link() {
    let html = "<head><link rel=\"canonical\" href=\"/p/MARKER\"></head>";
    assert!(marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_url_attr_only_classifier_rejects_text_content() {
    // Firing-range 404 pattern: URI rendered inside `<td>` — exploitable.
    let html = "<html><body><tr><td>/no/MARKER/route</td></tr></body></html>";
    assert!(
        !marker_reflects_in_url_attr_only(html, "MARKER"),
        "text-content reflection must NOT be classified as url-echo"
    );
}

#[test]
fn test_url_attr_only_classifier_rejects_non_url_attr() {
    // `value="MARKER"` is exploitable (attribute-value injection).
    let html = "<input type=\"text\" value=\"MARKER\">";
    assert!(
        !marker_reflects_in_url_attr_only(html, "MARKER"),
        "non-URL attribute reflection must NOT be classified as url-echo"
    );
}

#[test]
fn test_url_attr_only_classifier_mixed_occurrences_keep_finding() {
    // Marker appears in both a href AND in `<td>`. Single text-content
    // occurrence is enough to keep the finding — be conservative.
    let html = "<a href=\"/x/MARKER\">hi</a><td>/x/MARKER</td>";
    assert!(!marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_url_attr_only_classifier_handles_single_quoted_attr() {
    let html = "<a href='/foo/MARKER'>x</a>";
    assert!(marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_url_attr_only_classifier_handles_unquoted_attr() {
    let html = "<a href=/foo/MARKER>x</a>";
    assert!(marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_url_attr_only_returns_false_when_no_match() {
    let html = "<html>no marker here</html>";
    assert!(!marker_reflects_in_url_attr_only(html, "MARKER"));
}

#[test]
fn test_should_suppress_with_body_keeps_exploitable_404() {
    // 404 page echoing URI inside `<td>` — should NOT be suppressed even
    // on 4xx. Regression for the firing-range / App Engine error template
    // pattern.
    let body = "<html><body><tr><td>/no/PAY/route</td></tr></body></html>";
    assert!(!should_suppress_path_reflection_with_body(
        &Location::Path,
        404,
        body,
        "PAY",
    ));
}

#[test]
fn test_should_suppress_with_body_drops_url_echo_404() {
    // Generic 404 page that just echoes the path inside `<a href>` —
    // unexploitable URL echo, drop it.
    let body =
        "<html><body><p>Not found. Did you mean <a href=\"/old/PAY\">this</a>?</p></body></html>";
    assert!(should_suppress_path_reflection_with_body(
        &Location::Path,
        404,
        body,
        "PAY",
    ));
}

#[test]
fn test_should_suppress_with_body_2xx_never_suppresses() {
    // 2xx always survives regardless of where the reflection lands; the
    // V/R upgrade pipeline decides correctness from there.
    let body = "<a href=\"/foo/PAY\">link</a>";
    assert!(!should_suppress_path_reflection_with_body(
        &Location::Path,
        200,
        body,
        "PAY",
    ));
}

#[test]
fn test_should_suppress_with_body_non_path_never_suppresses() {
    let body = "<a href=\"/foo/PAY\">link</a>";
    assert!(!should_suppress_path_reflection_with_body(
        &Location::Query,
        404,
        body,
        "PAY",
    ));
}

#[test]
fn test_should_suppress_with_body_drops_percent_encoded_only_echo() {
    // Firing-range / App Engine 404: server URL-encodes the echoed path
    // (`%3Csvg…%3E`). The upstream reflection detector still finds the
    // payload via URL-decoded matching, but the browser would render the
    // percent escapes as literal text — no `<` tag is parsed, no XSS.
    // Suppress to avoid the false positive even though status is 4xx.
    let body = "<html><body><tr><th>URI:</th><td>/foo/%3Csvg/onload=alert(1)%3E/bar</td></tr></body></html>";
    let raw_payload = "<svg/onload=alert(1)>";
    assert!(
        !body.contains(raw_payload),
        "test fixture must contain only the percent-encoded form"
    );
    assert!(should_suppress_path_reflection_with_body(
        &Location::Path,
        404,
        body,
        raw_payload,
    ));
}

#[test]
fn test_should_suppress_with_body_empty_body_falls_back_to_strict() {
    // No body to classify — preserve the legacy conservative behaviour so
    // we don't surface findings from responses we can't actually inspect.
    assert!(should_suppress_path_reflection_with_body(
        &Location::Path,
        404,
        "",
        "PAY",
    ));
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
