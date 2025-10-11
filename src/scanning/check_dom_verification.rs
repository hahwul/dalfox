use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::{Client, redirect};
use scraper;
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

pub async fn check_dom_verification(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
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

    // Build URL or body based on param location for injection
    let inject_url = match param.location {
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

    // Send injection request
    let mut inject_request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
        inject_url,
    );

    for (k, v) in &target.headers {
        inject_request = inject_request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        inject_request = inject_request.header("User-Agent", ua);
    }
    for (k, v) in &target.cookies {
        inject_request = inject_request.header("Cookie", format!("{}={}", k, v));
    }
    if let Some(data) = &target.data {
        inject_request = inject_request.body(data.clone());
    }

    // Send the injection request
    let inject_resp = inject_request.send().await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    if args.sxss {
        // For Stored XSS, check DOM on sxss_url
        if let Some(sxss_url_str) = &args.sxss_url {
            if let Ok(sxss_url) = url::Url::parse(sxss_url_str) {
                let mut check_request = client.request(
                    args.sxss_method.parse().unwrap_or(reqwest::Method::GET),
                    sxss_url,
                );

                // Use target's headers, user_agent, cookies for check request
                for (k, v) in &target.headers {
                    check_request = check_request.header(k, v);
                }
                if let Some(ua) = &target.user_agent {
                    check_request = check_request.header("User-Agent", ua);
                }
                for (k, v) in &target.cookies {
                    check_request = check_request.header("Cookie", format!("{}={}", k, v));
                }

                if let Ok(resp) = check_request.send().await {
                    if let Ok(text) = resp.text().await {
                        let document = scraper::Html::parse_document(&text);
                        let selector = scraper::Selector::parse(".dalfox").unwrap();
                        if document.select(&selector).next().is_some() {
                            return (true, Some(text));
                        }
                    }
                }
            }
        }
    } else {
        // Normal DOM verification
        if let Ok(resp) = inject_resp {
            if let Ok(text) = resp.text().await {
                let document = scraper::Html::parse_document(&text);
                let selector = scraper::Selector::parse(".dalfox").unwrap();
                if document.select(&selector).next().is_some() {
                    return (true, Some(text));
                }
            }
        }
    }

    (false, None)
}
