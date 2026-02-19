use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::Client;
use scraper;
use std::sync::OnceLock;

use tokio::time::{Duration, sleep};

#[allow(dead_code)]
static DALFOX_SELECTOR: OnceLock<scraper::Selector> = OnceLock::new();

pub(crate) fn has_marker_evidence(payload: &str, text: &str) -> bool {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let need_class = payload.contains(class_marker);
    let need_id = payload.contains(id_marker);

    // Avoid promoting raw reflection to DOM-verified unless payload carries Dalfox marker(s).
    if !need_class && !need_id {
        return false;
    }

    let document = scraper::Html::parse_document(text);

    let class_ok = if need_class {
        let sel = format!(".{}", class_marker);
        if let Ok(selector) = scraper::Selector::parse(&sel) {
            document.select(&selector).next().is_some()
        } else {
            false
        }
    } else {
        true
    };

    let id_ok = if need_id {
        let sel = format!("#{}", id_marker);
        if let Ok(selector) = scraper::Selector::parse(&sel) {
            document.select(&selector).next().is_some()
        } else {
            false
        }
    } else {
        true
    };

    class_ok && id_ok
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    check_dom_verification_with_client(&client, target, param, payload, args).await
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

    // Build URL or body based on param location for injection
    let inject_url_str =
        crate::scanning::url_inject::build_injected_url(&target.url, param, payload);
    let inject_url = url::Url::parse(&inject_url_str).unwrap_or_else(|_| target.url.clone());

    // Send injection request (centralized builder)
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let inject_request =
        crate::utils::build_request(&client, target, method, inject_url, target.data.clone());

    // Send the injection request
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let inject_resp = inject_request.send().await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    if args.sxss {
        // For Stored XSS, check DOM on sxss_url
        if let Some(sxss_url_str) = &args.sxss_url
            && let Ok(sxss_url) = url::Url::parse(sxss_url_str)
        {
            let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
            let check_request =
                crate::utils::build_request(&client, target, method, sxss_url, None);

            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = check_request.send().await {
                let headers = resp.headers().clone();
                let ct = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if let Ok(text) = resp.text().await
                    && crate::utils::is_htmlish_content_type(ct)
                    && text.contains(payload)
                    && has_marker_evidence(payload, &text)
                {
                    return (true, Some(text));
                }
            }
        }
    } else {
        // Normal DOM verification
        if let Ok(resp) = inject_resp {
            let headers = resp.headers().clone();
            let ct = headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if let Ok(text) = resp.text().await
                && crate::utils::is_htmlish_content_type(ct)
                && text.contains(payload)
                && has_marker_evidence(payload, &text)
            {
                return (true, Some(text));
            }
        }
    }

    (false, None)
}

#[cfg(test)]
mod tests {
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
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
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
            .route("/dom/xhtml", get(xhtml_handler))
            .route("/dom/json", get(json_handler))
            .route("/dom/no-payload", get(html_without_payload_handler))
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
    async fn test_check_dom_verification_rejects_non_html_content_type() {
        let payload = format!(
            "<script class={}>alert(1)</script>",
            crate::scanning::markers::class_marker()
        );
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/dom/json");
        let param = make_param();
        let args = default_scan_args();

        let (found, body) = check_dom_verification(&target, &param, &payload, &args).await;
        assert!(!found, "application/json should not pass DOM verification");
        assert!(body.is_none(), "non-html responses should not be returned");
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
}
