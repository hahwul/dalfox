use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::{Client, redirect};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

pub async fn check_reflection(target: &Target, param: &Param, payload: &str) -> bool {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    client_builder = client_builder.redirect(if target.follow_redirects {
        redirect::Policy::limited(10)
    } else {
        redirect::Policy::none()
    });
    let client = client_builder.build().unwrap_or_else(|_| Client::new());

    // Build URL or body based on param location
    let url = match param.location {
        crate::parameter_analysis::Location::Query => {
            let mut pairs: Vec<(String, String)> = target
                .url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param.name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param.name.clone(), payload.to_string()));
            }
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        _ => target.url.clone(), // For simplicity, assume query for now
    };

    let mut request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
        url.clone(),
    );

    for (k, v) in &target.headers {
        request = request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        request = request.header("User-Agent", ua);
    }
    for (k, v) in &target.cookies {
        request = request.header("Cookie", format!("{}={}", k, v));
    }
    if let Some(data) = &target.data {
        request = request.body(data.clone());
    }

    if let Ok(resp) = request.send().await {
        if let Ok(text) = resp.text().await {
            if text.contains(payload) {
                return true;
            }
        }
    }

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    false
}
