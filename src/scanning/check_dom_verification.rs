use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::{Client, redirect};
use scraper;
use tokio::time::{Duration, sleep};

pub async fn check_dom_verification(
    target: &Target,
    param: &Param,
    payload: &str,
) -> (bool, Option<String>) {
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
            let mut url = target.url.clone();
            url.query_pairs_mut().append_pair(&param.name, payload);
            url
        }
        _ => target.url.clone(), // For simplicity, assume query for now
    };

    let mut request = client.request(target.method.parse().unwrap_or(reqwest::Method::GET), url);

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
            let document = scraper::Html::parse_document(&text);
            let selector = scraper::Selector::parse(".dalfox").unwrap();
            if document.select(&selector).next().is_some() {
                return (true, Some(text));
            }
        }
    }

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    (false, None)
}
