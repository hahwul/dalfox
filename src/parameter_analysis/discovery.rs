use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};

pub async fn check_discovery(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    if !args.skip_discovery {
        check_query_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        if !args.skip_reflection_header {
            check_header_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
        if !args.skip_reflection_cookie {
            check_cookie_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
    }
    target.reflection_params = reflection_params.lock().await.clone();
}

pub async fn check_query_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
    let test_value = "test'\"<script>";

    let mut handles = vec![];

    // Check existing query params for reflection
    for (name, value) in target.url.query_pairs() {
        let mut url = target.url.clone();
        url.query_pairs_mut().clear();
        for (n, v) in target.url.query_pairs() {
            if n == name {
                url.query_pairs_mut().append_pair(&n, test_value);
            } else {
                url.query_pairs_mut().append_pair(&n, &v);
            }
        }
        let client_clone = client.clone();
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let name = name.to_string();
        let value = value.to_string();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let mut request =
                client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), url);
            for (k, v) in &headers {
                request = request.header(k, v);
            }
            if let Some(ua) = &user_agent {
                request = request.header("User-Agent", ua);
            }
            for (k, v) in &cookies {
                request = request.header("Cookie", format!("{}={}", k, v));
            }
            if let Some(data) = &data {
                request = request.body(data.clone());
            }
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let param = Param {
                            name,
                            value,
                            location: crate::parameter_analysis::Location::Query,
                            injection_context: Some(
                                crate::parameter_analysis::InjectionContext::Html,
                            ),
                        };
                        reflection_params_clone.lock().await.push(param);
                    }
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

pub async fn check_header_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
    let test_value = "dalfox";

    let mut handles = vec![];

    for (header_name, header_value) in &target.headers {
        let client_clone = client.clone();
        let url = target.url.clone();
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let header_name = header_name.clone();
        let header_value = header_value.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let mut request =
                client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), url);
            for (k, v) in &headers {
                if k == &header_name {
                    request = request.header(k, test_value);
                } else {
                    request = request.header(k, v);
                }
            }
            if let Some(ua) = &user_agent {
                request = request.header("User-Agent", ua);
            }
            for (k, v) in &cookies {
                request = request.header("Cookie", format!("{}={}", k, v));
            }
            if let Some(data) = &data {
                request = request.body(data.clone());
            }
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let param = Param {
                            name: header_name,
                            value: header_value,
                            location: crate::parameter_analysis::Location::Header,
                            injection_context: Some(
                                crate::parameter_analysis::InjectionContext::Html,
                            ),
                        };
                        reflection_params_clone.lock().await.push(param);
                    }
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

pub async fn check_cookie_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
    let test_value = "dalfox";

    let mut handles = vec![];

    for (cookie_name, cookie_value) in &target.cookies {
        let client_clone = client.clone();
        let url = target.url.clone();
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let cookie_name = cookie_name.clone();
        let cookie_value = cookie_value.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let mut request =
                client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), url);
            for (k, v) in &headers {
                request = request.header(k, v);
            }
            if let Some(ua) = &user_agent {
                request = request.header("User-Agent", ua);
            }
            let mut cookie_header = String::new();
            for (k, v) in &cookies {
                if k == &cookie_name {
                    cookie_header.push_str(&format!("{}={}; ", k, test_value));
                } else {
                    cookie_header.push_str(&format!("{}={}; ", k, v));
                }
            }
            if !cookie_header.is_empty() {
                cookie_header.pop(); // Remove trailing space
                cookie_header.pop(); // Remove trailing semicolon
                request = request.header("Cookie", cookie_header);
            }
            if let Some(data) = &data {
                request = request.body(data.clone());
            }
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let param = Param {
                            name: cookie_name,
                            value: cookie_value,
                            location: crate::parameter_analysis::Location::Header, // Cookies are sent in Header
                            injection_context: Some(
                                crate::parameter_analysis::InjectionContext::Html,
                            ),
                        };
                        reflection_params_clone.lock().await.push(param);
                    }
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
