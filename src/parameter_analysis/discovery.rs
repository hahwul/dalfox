use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{Param, classify_special_chars, detect_injection_context};
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
        // Path discovery (no skip flag yet)
        check_path_discovery(target, reflection_params.clone(), semaphore.clone()).await;
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
    let test_value = "dalfox";

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
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let (valid, invalid) = classify_special_chars(&text);
                        let param = Param {
                            name,
                            value,
                            location: crate::parameter_analysis::Location::Query,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
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
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let (valid, invalid) = classify_special_chars(&text);
                        let param = Param {
                            name: header_name,
                            value: header_value,
                            location: crate::parameter_analysis::Location::Header,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::parse_target;

    #[tokio::test]
    async fn test_check_path_discovery_skips_existing_segment() {
        // URL with a single non-empty segment -> index 0
        let target = {
            let mut t = parse_target("https://example.com/only").unwrap();
            // Ensure deterministic small timeout to avoid long waits if something goes wrong
            t.timeout = 1;
            t
        };

        // reflection_params already contains path_segment_0 so discovery should skip it
        let reflection_params = Arc::new(Mutex::new(vec![Param {
            name: "path_segment_0".to_string(),
            value: "only".to_string(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        }]));

        // Limit parallelism to 1 to keep behavior deterministic
        let semaphore = Arc::new(Semaphore::new(1));

        let before_len = reflection_params.lock().await.len();
        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        let after_len = reflection_params.lock().await.len();

        // No new params should be added because the only segment was already discovered
        assert_eq!(before_len, 1);
        assert_eq!(after_len, 1);
    }

    #[tokio::test]
    async fn test_check_path_discovery_respects_semaphore_single_permit() {
        // No path segments ("/") => early return, but we still validate it handles a single-permit semaphore
        let target = {
            let mut t = parse_target("https://example.com/").unwrap();
            t.timeout = 1;
            t
        };

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        // Single permit semaphore; if the function tried to over-acquire, this could deadlock
        let semaphore = Arc::new(Semaphore::new(1));

        // Should complete without blocking and without adding params
        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        assert!(reflection_params.lock().await.is_empty());
    }
}

/// Discover reflections in path segments by replacing each segment with the test marker
pub async fn check_path_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let test_value = "dalfox";
    let path = target.url.path();
    // Split non-empty segments
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return;
    }

    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());

    let mut handles = Vec::new();

    for (idx, original) in segments.iter().enumerate() {
        let mut new_segments: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
        new_segments[idx] = test_value.to_string();
        let new_path = format!("/{}", new_segments.join("/"));

        let mut new_url = target.url.clone();
        new_url.set_path(&new_path);

        let client_clone = client.clone();
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let param_name = format!("path_segment_{}", idx);
        let original_value = original.to_string();

        // Skip if already discovered (e.g., duplicate path pattern)
        {
            let guard = reflection_params_clone.lock().await;
            if guard.iter().any(|p| {
                p.name == param_name && p.location == crate::parameter_analysis::Location::Path
            }) {
                continue;
            }
        }

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let mut request =
                client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), new_url);
            for (k, v) in &headers {
                request = request.header(k, v);
            }
            if let Some(ua) = &user_agent {
                request = request.header("User-Agent", ua);
            }
            if !cookies.is_empty() {
                let mut cookie_header = String::new();
                for (k, v) in &cookies {
                    cookie_header.push_str(&format!("{}={}; ", k, v));
                }
                if !cookie_header.is_empty() {
                    cookie_header.pop();
                    cookie_header.pop();
                    request = request.header("Cookie", cookie_header);
                }
            }
            if let Some(d) = &data {
                request = request.body(d.clone());
            }

            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let (valid, invalid) = classify_special_chars(&text);
                        let param = Param {
                            name: param_name,
                            value: original_value,
                            location: crate::parameter_analysis::Location::Path,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
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

    for h in handles {
        let _ = h.await;
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
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let (valid, invalid) = classify_special_chars(&text);
                        let param = Param {
                            name: cookie_name,
                            value: cookie_value,
                            location: crate::parameter_analysis::Location::Header, // Cookies are sent in Header
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
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
