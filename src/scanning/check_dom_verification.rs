//! # Stage 6: DOM Verification
//!
//! Confirms that a reflected payload actually creates exploitable DOM structure
//! (not just textual reflection). This upgrades a finding from type "R"
//! (Reflected) to "V" (DOM-verified).
//!
//! **Input:** `(Param, payload: &str)` — a parameter + payload that already
//! passed Stage 5 reflection check.
//!
//! **Output:** `(bool, Option<String>)` — whether DOM evidence was found, and
//! the response HTML body. Evidence requires *both* reflection *and* one of:
//! - Dalfox marker element (class/id `dlx`-hex or legacy `dalfox`) found via
//!   CSS selector in parsed DOM
//! - Executable URL protocol (`javascript:`, `data:text/html`, `vbscript:`)
//!   reflected into a dangerous attribute (href, src, action, etc.)
//!
//! **Side effects:** One HTTP request (with rate-limit retry). For stored XSS
//! (`--sxss`), sends the injection request then checks a secondary URL for
//! the stored payload. Applies `pre_encoding` as `encoded_payload` for the
//! request but checks DOM evidence against the raw `payload`.

use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use reqwest::Client;
use std::sync::OnceLock;
use tokio::time::{Duration, sleep};

use super::selectors;

fn cached_class_marker_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        let marker = crate::scanning::markers::class_marker();
        scraper::Selector::parse(&format!(".{}", marker)).expect("valid class marker selector")
    })
}

fn cached_id_marker_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        let marker = crate::scanning::markers::id_marker();
        scraper::Selector::parse(&format!("#{}", marker)).expect("valid id marker selector")
    })
}

fn cached_legacy_class_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| scraper::Selector::parse(".dalfox").expect("valid selector"))
}

fn cached_legacy_id_selector() -> &'static scraper::Selector {
    static SEL: OnceLock<scraper::Selector> = OnceLock::new();
    SEL.get_or_init(|| scraper::Selector::parse("#dalfox").expect("valid selector"))
}

fn payload_uses_legacy_class_marker(payload: &str) -> bool {
    payload.contains("class=dalfox")
        || payload.contains("class=\"dalfox\"")
        || payload.contains("class='dalfox'")
}

fn payload_uses_legacy_id_marker(payload: &str) -> bool {
    payload.contains("id=dalfox")
        || payload.contains("id=\"dalfox\"")
        || payload.contains("id='dalfox'")
}

pub(crate) fn has_marker_evidence(payload: &str, text: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let has_class = payload.contains(class_marker);
    let has_legacy_class = payload_uses_legacy_class_marker(payload);
    let has_id = payload.contains(id_marker);
    let has_legacy_id = payload_uses_legacy_id_marker(payload);

    // Avoid promoting raw reflection to DOM-verified unless payload carries Dalfox marker(s).
    if !has_class && !has_legacy_class && !has_id && !has_legacy_id {
        return false;
    }

    let document = scraper::Html::parse_document(text);

    let class_ok = if has_class || has_legacy_class {
        let mut found = false;
        if has_class {
            found = document.select(cached_class_marker_selector()).next().is_some();
        }
        if !found && has_legacy_class {
            found = document.select(cached_legacy_class_selector()).next().is_some();
        }
        found
    } else {
        true
    };

    let id_ok = if has_id || has_legacy_id {
        let mut found = false;
        if has_id {
            found = document.select(cached_id_marker_selector()).next().is_some();
        }
        if !found && has_legacy_id {
            found = document.select(cached_legacy_id_selector()).next().is_some();
        }
        found
    } else {
        true
    };

    class_ok && id_ok
}

fn payload_is_executable_url_protocol(payload: &str) -> bool {
    let lowered = payload.trim().to_ascii_lowercase();
    lowered.starts_with("javascript:")
        || lowered.starts_with("data:text/html")
        || lowered.starts_with("vbscript:")
}

fn has_executable_url_attribute_evidence(payload: &str, text: &str) -> bool {
    if !payload_is_executable_url_protocol(payload) {
        return false;
    }

    let payload_lower = payload.trim().to_ascii_lowercase();
    let document = scraper::Html::parse_document(text);
    let selector = selectors::universal();
    let dangerous_attrs = ["href", "src", "data", "action", "formaction", "xlink:href"];

    document.select(selector).any(|node| {
        node.value().attrs().any(|(name, value)| {
            dangerous_attrs.contains(&name.to_ascii_lowercase().as_str())
                && value.trim().to_ascii_lowercase() == payload_lower
        })
    })
}

pub async fn check_dom_verification(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }
    let client = target.build_client_or_default();
    check_dom_verification_with_client(&client, target, param, payload, args).await
}

/// Build the HTTP request for injecting the payload based on the parameter location.
fn build_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let default_method = target.parse_method();
    match param.location {
        Location::Header => build_header_request(client, target, param, encoded_payload, default_method),
        Location::Body => build_body_request(client, target, param, encoded_payload),
        Location::JsonBody => build_json_body_request(client, target, param, encoded_payload),
        Location::MultipartBody => build_multipart_request(client, target, param, encoded_payload),
        _ => build_url_inject_request(client, target, param, encoded_payload, default_method),
    }
}

fn build_header_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    let parsed_url = target.url.clone();
    if target.cookies.iter().any(|(name, _)| name == &param.name) {
        let others = crate::utils::compose_cookie_header_excluding(
            &target.cookies,
            Some(&param.name),
        );
        let cookie_header = match others {
            Some(rest) if !rest.is_empty() => {
                format!("{}={}; {}", param.name, encoded_payload, rest)
            }
            _ => format!("{}={}", param.name, encoded_payload),
        };
        crate::utils::build_request_with_cookie(
            client, target, method, parsed_url, target.data.clone(), Some(cookie_header),
        )
    } else {
        let base = crate::utils::build_request(
            client, target, method, parsed_url, target.data.clone(),
        );
        crate::utils::apply_header_overrides(
            base,
            &[(param.name.clone(), encoded_payload.to_string())],
        )
    }
}

fn resolve_form_action_url(param: &Param, target: &Target) -> url::Url {
    param
        .form_action_url
        .as_ref()
        .and_then(|u| url::Url::parse(u).ok())
        .unwrap_or_else(|| target.url.clone())
}

fn build_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let body = if let Some(ref data) = target.data {
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut found = false;
        for pair in &mut pairs {
            if pair.0 == param.name {
                pair.1 = encoded_payload.to_string();
                found = true;
                break;
            }
        }
        if !found {
            pairs.push((param.name.clone(), encoded_payload.to_string()));
        }
        Some(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish(),
        )
    } else {
        Some(format!(
            "{}={}",
            urlencoding::encode(&param.name),
            urlencoding::encode(encoded_payload)
        ))
    };
    let base = crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
    )
}

fn build_json_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let body = if let Some(ref data) = target.data {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.insert(
                    param.name.clone(),
                    serde_json::Value::String(encoded_payload.to_string()),
                );
            }
            Some(serde_json::to_string(&json_val).unwrap_or_else(|_| data.clone()))
        } else {
            Some(data.replace(&param.value, encoded_payload))
        }
    } else {
        Some(serde_json::json!({ &param.name: encoded_payload }).to_string())
    };
    let base = crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[("Content-Type".to_string(), "application/json".to_string())],
    )
}

fn build_multipart_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let mut form = reqwest::multipart::Form::new();
    if let Some(ref data) = target.data {
        for pair in data.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let k = urlencoding::decode(k).unwrap_or(std::borrow::Cow::Borrowed(k)).to_string();
                let v = urlencoding::decode(v).unwrap_or(std::borrow::Cow::Borrowed(v)).to_string();
                if k == param.name {
                    form = form.text(k, encoded_payload.to_string());
                } else {
                    form = form.text(k, v);
                }
            }
        }
    } else {
        form = form.text(param.name.clone(), encoded_payload.to_string());
    }
    crate::utils::build_request(client, target, reqwest::Method::POST, parsed_url, None)
        .multipart(form)
}

fn build_url_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    encoded_payload: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    let inject_url_str =
        crate::scanning::url_inject::build_injected_url(&target.url, param, encoded_payload);
    let inject_url =
        url::Url::parse(&inject_url_str).unwrap_or_else(|_| target.url.clone());
    crate::utils::build_request(client, target, method, inject_url, target.data.clone())
}

/// Verify DOM evidence in a stored XSS scenario by checking secondary URLs.
async fn verify_sxss_dom(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    let check_urls = crate::scanning::check_reflection::resolve_sxss_check_urls(target, param, args);
    for sxss_url in &check_urls {
        for attempt in 0u64..3 {
            if attempt > 0 {
                sleep(Duration::from_millis(500 * attempt)).await;
            }
            let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
            let check_request =
                crate::utils::build_request(client, target, method, sxss_url.clone(), None);

            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = check_request.send().await {
                let headers = resp.headers().clone();
                let ct = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if let Ok(text) = resp.text().await
                    && crate::utils::is_htmlish_content_type(ct)
                    && crate::scanning::check_reflection::classify_reflection(&text, payload)
                        .is_some()
                    && (has_marker_evidence(payload, &text)
                        || has_executable_url_attribute_evidence(payload, &text))
                {
                    return (true, Some(text));
                }
            }
        }
    }
    (false, None)
}

/// Verify DOM evidence from a normal (non-stored) injection response.
async fn verify_normal_dom(
    resp: reqwest::Response,
    payload: &str,
) -> (bool, Option<String>) {
    let status = resp.status();
    let headers = resp.headers().clone();

    // Check redirect Location header for executable URL protocols (e.g. javascript:alert(1))
    if status.is_redirection()
        && let Some(location) = headers.get(reqwest::header::LOCATION)
        && let Ok(loc_str) = location.to_str()
        && let Some(result) = check_redirect_location(loc_str, payload)
    {
        return result;
    }

    // Both HTML and non-HTML (JSONP, JSON with HTML) content types are accepted
    // as long as there is reflection + marker/executable-URL evidence in the response.
    if let Ok(text) = resp.text().await
        && crate::scanning::check_reflection::classify_reflection(&text, payload).is_some()
        && (has_marker_evidence(payload, &text)
            || has_executable_url_attribute_evidence(payload, &text))
    {
        return (true, Some(text));
    }

    (false, None)
}

/// Check if a redirect Location header contains evidence of payload injection.
fn check_redirect_location(loc_str: &str, payload: &str) -> Option<(bool, Option<String>)> {
    let loc_lower = loc_str.trim().to_ascii_lowercase();
    if payload_is_executable_url_protocol(payload)
        && loc_lower.starts_with(&payload.trim().to_ascii_lowercase())
    {
        let synthetic_body = format!(
            "<html><body><a href=\"{}\">redirect</a></body></html>",
            loc_str
        );
        return Some((true, Some(synthetic_body)));
    }
    if crate::scanning::check_reflection::classify_reflection(loc_str, payload).is_some() {
        let synthetic_body = format!(
            "<html><body>Redirect to: {}</body></html>",
            loc_str
        );
        return Some((true, Some(synthetic_body)));
    }
    None
}

pub async fn check_dom_verification_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }

    // Apply pre-encoding if the parameter requires it.
    // Use encoded_payload for building the HTTP request, but keep `payload`
    // (the raw/original payload) for response body analysis — the server
    // decodes the encoding and reflects the raw content.
    let encoded_payload = crate::encoding::pre_encoding::apply_pre_encoding(payload, &param.pre_encoding);

    let inject_request = build_inject_request(client, target, param, &encoded_payload);

    // Send the injection request (with rate-limit retry)
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let inject_resp = crate::utils::send_with_retry(inject_request, 3, 5000).await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    if args.sxss {
        verify_sxss_dom(client, target, param, payload, args).await
    } else if let Ok(resp) = inject_resp {
        verify_normal_dom(resp, payload).await
    } else {
        (false, None)
    }
}

#[cfg(test)]
mod tests {
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
            poc_type: "plain".to_string(),
            limit: None,
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
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
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

    async fn decoded_payload_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> Html<String> {
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
        assert!(!found, "application/json without marker should not pass DOM verification");
        assert!(body.is_none(), "non-html responses without marker should not be returned");
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
        assert!(found, "non-HTML responses with marker evidence should pass DOM verification for JSONP/JSON XSS");
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
        assert!(has_executable_url_attribute_evidence(payload, body));
    }

    #[tokio::test]
    async fn test_check_dom_verification_accepts_executable_url_attribute_protocol() {
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/dom/url-attribute");
        let param = make_param();
        let args = default_scan_args();

        let (found, body) =
            check_dom_verification(&target, &param, "javascript:alert(1)", &args).await;

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
}
