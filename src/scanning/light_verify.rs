use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::Client;

/// Lightweight (non-headless) verification for DOM-XSS candidates.
/// Heuristics:
/// - Build injected URL with provided payload and fetch once.
/// - If Content-Type is HTML-ish and response contains the raw payload, mark verified.
/// - Else, if response contains the class marker and a matching element exists, mark verified.
/// - Else, if CSP likely blocks inline handlers ('unsafe-inline' missing), add note.
///
/// Returns: (verified, response_text, note)
pub async fn verify_dom_xss_light(
    target: &Target,
    param: &Param,
    payload: &str,
) -> (bool, Option<String>, Option<String>) {
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    verify_dom_xss_light_with_client(&client, target, param, payload).await
}

pub async fn verify_dom_xss_light_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
) -> (bool, Option<String>, Option<String>) {
    let inject_url = crate::scanning::url_inject::build_injected_url(&target.url, param, payload);
    let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| target.url.clone());
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let request =
        crate::utils::build_request(client, target, method, parsed_url, target.data.clone());

    let mut note: Option<String> = None;
    if let Ok(resp) = request.send().await {
        let headers = resp.headers().clone();
        let ct = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let csp = headers
            .get("Content-Security-Policy")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if let Ok(text) = resp.text().await {
            // 1) Raw payload present
            if crate::utils::is_htmlish_content_type(&ct) && text.contains(payload) {
                if crate::scanning::check_dom_verification::has_marker_evidence(payload, &text) {
                    return (true, Some(text), Some("marker-reflected".to_string()));
                }
                note = Some("raw reflection without marker evidence".to_string());
            }
            // 2) Marker element present
            if crate::utils::is_htmlish_content_type(&ct)
                && crate::scanning::check_dom_verification::has_marker_evidence(payload, &text)
            {
                return (true, Some(text), Some("marker element present".to_string()));
            }
            // 3) CSP hint
            if let Some(cspv) = csp {
                let has_unsafe_inline = cspv
                    .split(';')
                    .any(|d| d.contains("script-src") && d.contains("'unsafe-inline'"));
                if !has_unsafe_inline {
                    note = Some("CSP may block inline handlers".to_string());
                }
            }
            return (false, Some(text), note);
        }
    }
    (false, None, note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::{Target, parse_target};
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
        class_marker: String,
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

    fn make_target(addr: SocketAddr, path: &str) -> Target {
        let target = format!("http://{}:{}{}?q=seed", addr.ip(), addr.port(), path);
        parse_target(&target).expect("valid target")
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

    async fn start_mock_server(class_marker: &str) -> SocketAddr {
        let app = Router::new()
            .route("/reflect", get(reflect_html))
            .route("/marker-only", get(marker_only_html))
            .route("/csp", get(csp_html))
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
        let target = make_target(addr, "/reflect");
        let param = make_param();
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
        let target = make_target(addr, "/reflect");
        let param = make_param();
        let payload = "<script>alert(1)</script>";
        let client = Client::new();

        let (verified, response, note) =
            verify_dom_xss_light_with_client(&client, &target, &param, payload).await;

        assert!(!verified);
        assert!(response.expect("response").contains(payload));
        assert_eq!(
            note,
            Some("raw reflection without marker evidence".to_string())
        );
    }

    #[tokio::test]
    async fn test_verify_dom_xss_light_marker_element_present_without_raw_payload() {
        let marker = crate::scanning::markers::class_marker().to_string();
        let addr = start_mock_server(&marker).await;
        let target = make_target(addr, "/marker-only");
        let param = make_param();
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
        let target = make_target(addr, "/csp");
        let param = make_param();
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
        let param = make_param();
        let payload = "x";
        let client = Client::new();

        let (verified, response, note) =
            verify_dom_xss_light_with_client(&client, &target, &param, payload).await;

        assert!(!verified);
        assert!(response.is_none());
        assert!(note.is_none());
    }
}
