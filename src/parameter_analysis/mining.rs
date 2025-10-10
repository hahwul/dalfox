use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{InjectionContext, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use reqwest::Client;
use scraper;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

pub fn detect_injection_context(text: &str) -> InjectionContext {
    let dalfox_pos = match text.find("dalfox") {
        Some(pos) => pos,
        None => return InjectionContext::Html,
    };

    // Check for JavaScript context
    if let Some(script_start) = text.find("<script") {
        if let Some(script_end) = text.find("</script>") {
            if script_start < dalfox_pos && dalfox_pos < script_end {
                // Check for delimiter type in JavaScript
                if text.contains("\"dalfox\"") {
                    return InjectionContext::Javascript(Some(
                        crate::parameter_analysis::DelimiterType::DoubleQuote,
                    ));
                } else if text.contains("'dalfox'") {
                    return InjectionContext::Javascript(Some(
                        crate::parameter_analysis::DelimiterType::SingleQuote,
                    ));
                } else {
                    return InjectionContext::Javascript(None);
                }
            }
        }
    }

    // Check for comment context
    if let Some(comment_start) = text.find("<!--") {
        if let Some(comment_end) = text.find("-->") {
            if comment_start < dalfox_pos && dalfox_pos < comment_end {
                // Check for delimiter type in comment
                if text.contains("\"dalfox\"") {
                    return InjectionContext::Comment(Some(
                        crate::parameter_analysis::DelimiterType::DoubleQuote,
                    ));
                } else if text.contains("'dalfox'") {
                    return InjectionContext::Comment(Some(
                        crate::parameter_analysis::DelimiterType::SingleQuote,
                    ));
                } else {
                    return InjectionContext::Comment(Some(
                        crate::parameter_analysis::DelimiterType::Comment,
                    ));
                }
            }
        }
    }

    // Check for attribute context
    if text.contains("=\"dalfox\"") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::DoubleQuote,
        ));
    } else if text.contains("='dalfox'") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::SingleQuote,
        ));
    }

    // Check for string contexts (fallback)
    if text.contains("\"dalfox\"") {
        return InjectionContext::StringDouble;
    }
    if text.contains("'dalfox'") {
        return InjectionContext::StringSingle;
    }

    // Default to HTML
    InjectionContext::Html
}

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
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

    // Get parameters from wordlist or default
    let params: Vec<String> = if let Some(wordlist_path) = &args.mining_dict_word {
        match std::fs::read_to_string(wordlist_path) {
            Ok(content) => content
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(e) => {
                eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                return;
            }
        }
    } else {
        GF_PATTERNS_PARAMS.iter().map(|s| s.to_string()).collect()
    };

    let mut handles = vec![];

    // Check for additional valid parameters
    for param in params {
        let existing = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == param);
        if existing {
            continue;
        }
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(&param, "dalfox");
        let client_clone = client.clone();
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let param = param.clone();

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
                    if text.contains("dalfox") {
                        let context = detect_injection_context(&text);
                        let param_struct = Param {
                            name: param.clone(),
                            value: "dalfox".to_string(),
                            location: crate::parameter_analysis::Location::Query,
                            injection_context: Some(context),
                        };
                        reflection_params_clone.lock().await.push(param_struct);
                        eprintln!("Discovered parameter: {}", param);
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

pub async fn probe_body_params(
    target: &Target,
    args: &ScanArgs,
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

    if let Some(data) = &args.data {
        // Assume form data for now (application/x-www-form-urlencoded)
        let params: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let mut handles = vec![];

        for (param_name, _) in params {
            let existing = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param_name);
            if existing {
                continue;
            }
            let new_data = form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| {
                    if k == param_name {
                        (k, "dalfox".to_string())
                    } else {
                        (k, v.to_string())
                    }
                })
                .collect::<Vec<_>>();
            let body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(new_data)
                .finish();

            let client_clone = client.clone();
            let url = target.url.clone();
            let headers = target.headers.clone();
            let user_agent = target.user_agent.clone();
            let cookies = target.cookies.clone();
            let method = target.method.clone();
            let delay = target.delay;
            let reflection_params_clone = reflection_params.clone();
            let semaphore_clone = semaphore.clone();
            let param_name = param_name.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.unwrap();
                let mut request =
                    client_clone.request(method.parse().unwrap_or(reqwest::Method::POST), url);
                for (k, v) in &headers {
                    request = request.header(k, v);
                }
                if let Some(ua) = &user_agent {
                    request = request.header("User-Agent", ua);
                }
                for (k, v) in &cookies {
                    request = request.header("Cookie", format!("{}={}", k, v));
                }
                request = request.header("Content-Type", "application/x-www-form-urlencoded");
                request = request.body(body);

                if let Ok(resp) = request.send().await {
                    if let Ok(text) = resp.text().await {
                        if text.contains("dalfox") {
                            let context = detect_injection_context(&text);
                            let param = Param {
                                name: param_name.clone(),
                                value: "dalfox".to_string(),
                                location: crate::parameter_analysis::Location::Body,
                                injection_context: Some(context),
                            };
                            reflection_params_clone.lock().await.push(param);
                            eprintln!("Discovered parameter: {}", param_name);
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
}

pub async fn probe_response_id_params(
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

    // First, get the HTML to find input ids and names
    let mut base_request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
        target.url.clone(),
    );
    for (k, v) in &target.headers {
        base_request = base_request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        base_request = base_request.header("User-Agent", ua);
    }
    for (k, v) in &target.cookies {
        base_request = base_request.header("Cookie", format!("{}={}", k, v));
    }
    if let Some(data) = &target.data {
        base_request = base_request.body(data.clone());
    }

    if let Ok(resp) = base_request.send().await {
        if let Ok(text) = resp.text().await {
            let document = scraper::Html::parse_document(&text);

            // Collect unique ids and names
            let mut params_to_check = std::collections::HashSet::new();
            let selector = scraper::Selector::parse("input[id], input[name]").unwrap();
            for element in document.select(&selector) {
                if let Some(id) = element.value().attr("id") {
                    params_to_check.insert(id.to_string());
                }
                if let Some(name) = element.value().attr("name") {
                    params_to_check.insert(name.to_string());
                }
            }

            let mut handles = vec![];

            // Check each param for reflection
            for param in params_to_check {
                let existing = reflection_params
                    .lock()
                    .await
                    .iter()
                    .any(|p| p.name == param);
                if existing {
                    continue;
                }
                let mut url = target.url.clone();
                url.query_pairs_mut().append_pair(&param, "dalfox");
                let client_clone = client.clone();
                let headers = target.headers.clone();
                let user_agent = target.user_agent.clone();
                let cookies = target.cookies.clone();
                let data = target.data.clone();
                let method = target.method.clone();
                let delay = target.delay;
                let reflection_params_clone = reflection_params.clone();
                let semaphore_clone = semaphore.clone();
                let param = param.clone();

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
                            if text.contains("dalfox") {
                                let context = detect_injection_context(&text);
                                let param_struct = Param {
                                    name: param.clone(),
                                    value: "dalfox".to_string(),
                                    location: crate::parameter_analysis::Location::Query,
                                    injection_context: Some(context),
                                };
                                reflection_params_clone.lock().await.push(param_struct);
                                eprintln!("Discovered parameter: {}", param);
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
    }
}

pub async fn mine_parameters(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    if !args.skip_mining {
        if !args.skip_mining_dict {
            probe_dictionary_params(target, args, reflection_params.clone(), semaphore.clone())
                .await;
            probe_body_params(target, args, reflection_params.clone(), semaphore.clone()).await;
        }
        if !args.skip_mining_dom {
            probe_response_id_params(target, reflection_params.clone(), semaphore.clone()).await;
        }
    }
}
