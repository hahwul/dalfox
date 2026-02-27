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
        // Path discovery (respects --skip-reflection-path)
        if !args.skip_reflection_path {
            check_path_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
    }
    target.reflection_params = reflection_params.lock().await.clone();
}

pub async fn check_query_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    let test_value = crate::scanning::markers::open_marker();

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
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let name = name.to_string();
        let value = value.to_string();
        let target_clone = arc_target.clone();

        // Spawn a task that returns Option<Param> instead of locking per discovery.
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let m = method.parse().unwrap_or(reqwest::Method::GET);
            let request =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name,
                    value,
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect results to reduce mutex contention
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt_param) = handle.await
            && let Some(p) = opt_param
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

pub async fn check_header_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    let test_value = crate::scanning::markers::open_marker();

    let mut handles = vec![];

    for (header_name, header_value) in &target.headers {
        let client_clone = client.clone();
        let url = target.url.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let header_name = header_name.clone();
        let header_value = header_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> to batch reduce mutex contention
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let m = method.parse().unwrap_or(reqwest::Method::GET);
            let base =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            let overrides = vec![(header_name.clone(), test_value.to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: header_name,
                    value: header_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Discover reflections in path segments by replacing each segment with the test marker
pub async fn check_path_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let test_value = crate::scanning::markers::open_marker();
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

    let client = target.build_client().unwrap_or_else(|_| Client::new());

    let mut handles = Vec::new();

    for (idx, original) in segments.iter().enumerate() {
        let mut new_segments: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
        new_segments[idx] = test_value.to_string();
        let new_path = format!("/{}", new_segments.join("/"));

        let mut new_url = target.url.clone();
        new_url.set_path(&new_path);

        let client_clone = client.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name = format!("path_segment_{}", idx);
        let original_value = original.to_string();

        // Skip if already discovered (e.g., duplicate path pattern)
        {
            let guard = reflection_params.lock().await;
            if guard.iter().any(|p| {
                p.name == param_name && p.location == crate::parameter_analysis::Location::Path
            }) {
                continue;
            }
        }

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let m = method.parse().unwrap_or(reqwest::Method::GET);
            let request =
                crate::utils::build_request(&client_clone, &target_clone, m, new_url, data.clone());

            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: param_name,
                    value: original_value,
                    location: crate::parameter_analysis::Location::Path,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect discovered path params
    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(opt) = h.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

pub async fn check_cookie_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    let test_value = crate::scanning::markers::open_marker();

    let mut handles = vec![];

    for (cookie_name, cookie_value) in &target.cookies {
        let client_clone = client.clone();
        let url = target.url.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let cookie_name = cookie_name.clone();
        let cookie_value = cookie_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let m = method.parse().unwrap_or(reqwest::Method::GET);
            // Compose cookie header overriding the probed cookie while preserving others
            let others =
                crate::utils::compose_cookie_header_excluding(&cookies, Some(&cookie_name));
            let cookie_header = match others {
                Some(s) => format!("{}; {}={}", s, cookie_name, test_value),
                None => format!("{}={}", cookie_name, test_value),
            };
            let request = crate::utils::build_request_with_cookie(
                &client_clone,
                &target_clone,
                m,
                url,
                data.clone(),
                Some(cookie_header),
            );
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: cookie_name,
                    value: cookie_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect cookie params
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::parse_target;
    use axum::Router;
    use axum::extract::Query;
    use axum::http::{HeaderMap, Uri};
    use axum::routing::any;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};

    fn default_scan_args() -> crate::cmd::scan::ScanArgs {
        crate::cmd::scan::ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            mining_dict_word: None,
            remote_wordlists: vec![],
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
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
            workers: 4,
            max_concurrent_targets: 4,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            remote_payloads: vec![],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
        }
    }

    async fn discovery_reflect_handler(
        Query(params): Query<HashMap<String, String>>,
        headers: HeaderMap,
        uri: Uri,
    ) -> String {
        let mut values: Vec<String> = params.values().cloned().collect();
        values.sort();
        let query_values = values.join(",");
        let header_values: Vec<String> = headers
            .get_all("x-reflect-me")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        let header_value = header_values.join(",");
        let cookie_value = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        format!(
            "path={} query={} header={} cookie={}",
            uri.path(),
            query_values,
            header_value,
            cookie_value
        )
    }

    async fn start_discovery_mock_server() -> SocketAddr {
        let app = Router::new()
            .route("/", any(discovery_reflect_handler))
            .route("/*rest", any(discovery_reflect_handler));

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        sleep(Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn test_check_query_discovery_discovers_reflection_and_extends_batch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect?a=1&b=2", addr)).unwrap();
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_query_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(
            params
                .iter()
                .any(|p| p.name == "a" && p.location == Location::Query)
        );
        assert!(
            params
                .iter()
                .any(|p| p.name == "b" && p.location == Location::Query)
        );
        assert!(params.iter().all(|p| p.valid_specials.is_some()));
        assert!(params.iter().all(|p| p.invalid_specials.is_some()));
    }

    #[tokio::test]
    async fn test_check_header_discovery_discovers_reflected_header() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect?q=1", addr)).unwrap();
        target
            .headers
            .push(("X-Reflect-Me".to_string(), "orig".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_header_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 1);
        let p = &params[0];
        assert_eq!(p.name, "X-Reflect-Me");
        assert_eq!(p.value, "orig");
        assert_eq!(p.location, Location::Header);
        assert!(p.injection_context.is_some());
    }

    #[tokio::test]
    async fn test_check_cookie_discovery_single_cookie_branch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "session");
        assert_eq!(params[0].location, Location::Header);
    }

    #[tokio::test]
    async fn test_check_cookie_discovery_multiple_cookies_branch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));
        target
            .cookies
            .push(("theme".to_string(), "dark".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|p| p.name == "session"));
        assert!(params.iter().any(|p| p.name == "theme"));
    }

    #[tokio::test]
    async fn test_check_path_discovery_discovers_reflected_segments() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/one/two", addr)).unwrap();
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_path_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(
            params
                .iter()
                .any(|p| p.name == "path_segment_0" && p.value == "one")
        );
        assert!(
            params
                .iter()
                .any(|p| p.name == "path_segment_1" && p.value == "two")
        );
        assert!(params.iter().all(|p| p.location == Location::Path));
    }

    #[tokio::test]
    async fn test_check_discovery_skip_discovery_true_keeps_empty() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/a/b?q=1", addr)).unwrap();
        target
            .headers
            .push(("X-Reflect-Me".to_string(), "orig".to_string()));
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        let mut args = default_scan_args();
        args.skip_discovery = true;

        check_discovery(&mut target, &args, reflection_params, semaphore).await;
        assert!(target.reflection_params.is_empty());
    }

    #[tokio::test]
    async fn test_check_path_discovery_skips_existing_segment() {
        let target = {
            let mut t = parse_target("https://example.com/only").unwrap();
            t.timeout = 1;
            t
        };

        let reflection_params = Arc::new(Mutex::new(vec![Param {
            name: "path_segment_0".to_string(),
            value: "only".to_string(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        }]));

        let semaphore = Arc::new(Semaphore::new(1));

        let before_len = reflection_params.lock().await.len();
        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        let after_len = reflection_params.lock().await.len();

        assert_eq!(before_len, 1);
        assert_eq!(after_len, 1);
    }

    #[tokio::test]
    async fn test_check_path_discovery_respects_semaphore_single_permit() {
        let target = {
            let mut t = parse_target("https://example.com/").unwrap();
            t.timeout = 1;
            t
        };

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));

        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_check_discovery_skips_path_when_flag_set() {
        let mut target = parse_target("https://example.com/a/b").unwrap();
        target.timeout = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));

        let mut args = default_scan_args();
        args.workers = 1;
        args.max_concurrent_targets = 1;
        args.skip_reflection_path = true;

        check_discovery(
            &mut target,
            &args,
            reflection_params.clone(),
            semaphore.clone(),
        )
        .await;
        assert!(reflection_params.lock().await.is_empty());
    }
}
