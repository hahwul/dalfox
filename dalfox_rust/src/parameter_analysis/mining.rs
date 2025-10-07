use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{InjectionContext, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use reqwest::blocking::Client;
use scraper;
use std::time::Duration;
use url::form_urlencoded;

fn detect_injection_context(text: &str) -> InjectionContext {
    let dalfox_pos = match text.find("dalfox") {
        Some(pos) => pos,
        None => return InjectionContext::Html,
    };

    // Check for JavaScript context
    if let Some(script_start) = text.find("<script") {
        if let Some(script_end) = text.find("</script>") {
            if script_start < dalfox_pos && dalfox_pos < script_end {
                return InjectionContext::Javascript;
            }
        }
    }

    // Check for comment context
    if let Some(comment_start) = text.find("<!--") {
        if let Some(comment_end) = text.find("-->") {
            if comment_start < dalfox_pos && dalfox_pos < comment_end {
                return InjectionContext::Comment;
            }
        }
    }

    // Check for attribute context (simple check)
    if text.contains("=\"dalfox\"") || text.contains("='dalfox'") {
        return InjectionContext::Attribute;
    }

    // Check for string contexts
    if text.contains("\"dalfox\"") {
        return InjectionContext::StringDouble;
    }
    if text.contains("'dalfox'") {
        return InjectionContext::StringSingle;
    }

    // Default to HTML
    InjectionContext::Html
}

pub fn probe_dictionary_params(target: &mut Target, args: &ScanArgs) {
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

    // Check for additional valid parameters
    for param in params {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(&param, "dalfox");
        let mut request =
            client.request(target.method.parse().unwrap_or(reqwest::Method::GET), url);
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
        if let Ok(resp) = request.send() {
            if let Ok(text) = resp.text() {
                if text.contains("dalfox") {
                    let context = detect_injection_context(&text);
                    target.reflection_params.push(Param {
                        name: param,
                        value: "dalfox".to_string(),
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(context),
                    });
                }
            }
        }
        if target.delay > 0 {
            std::thread::sleep(Duration::from_millis(target.delay));
        }
    }

    println!("Parameter mining completed for target: {}", target.url);
}

pub fn probe_body_params(target: &mut Target, args: &ScanArgs) {
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

        for (param_name, _) in params {
            if target
                .reflection_params
                .iter()
                .any(|p| p.name == param_name)
            {
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

            let mut request = client.request(
                target.method.parse().unwrap_or(reqwest::Method::POST),
                target.url.clone(),
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
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
            request = request.body(body);

            if let Ok(resp) = request.send() {
                if let Ok(text) = resp.text() {
                    if text.contains("dalfox") {
                        let context = detect_injection_context(&text);
                        target.reflection_params.push(Param {
                            name: param_name,
                            value: "dalfox".to_string(),
                            location: crate::parameter_analysis::Location::Body,
                            injection_context: Some(context),
                        });
                    }
                }
            }
            if target.delay > 0 {
                std::thread::sleep(Duration::from_millis(target.delay));
            }
        }
    }

    println!("Body parameter mining completed for target: {}", target.url);
}

pub fn probe_response_id_params(target: &mut Target) {
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

    if let Ok(resp) = base_request.send() {
        if let Ok(text) = resp.text() {
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

            // Check each param for reflection
            for param in params_to_check {
                if target.reflection_params.iter().any(|p| p.name == param) {
                    continue;
                }
                let mut url = target.url.clone();
                url.query_pairs_mut().append_pair(&param, "dalfox");
                let mut request =
                    client.request(target.method.parse().unwrap_or(reqwest::Method::GET), url);
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
                if let Ok(resp) = request.send() {
                    if let Ok(text) = resp.text() {
                        if text.contains("dalfox") {
                            let context = detect_injection_context(&text);
                            target.reflection_params.push(Param {
                                name: param,
                                value: "dalfox".to_string(),
                                location: crate::parameter_analysis::Location::Query,
                                injection_context: Some(context),
                            });
                        }
                    }
                }
                if target.delay > 0 {
                    std::thread::sleep(Duration::from_millis(target.delay));
                }
            }
        }
    }

    println!(
        "Response-based parameter mining completed for target: {}",
        target.url
    );
}

pub fn mine_parameters(target: &mut Target, args: &ScanArgs) {
    if !args.skip_mining {
        if !args.skip_mining_dict {
            probe_dictionary_params(target, args);
            probe_body_params(target, args);
        }
        if !args.skip_mining_dom {
            probe_response_id_params(target);
        }
    }
}
