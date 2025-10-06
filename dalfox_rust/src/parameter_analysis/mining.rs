use crate::parameter_analysis::{InjectionContext, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use reqwest::blocking::Client;
use scraper;

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

pub fn probe_dictionary_params(target: &mut Target) {
    let client = Client::new();

    // Check for additional valid parameters
    for &param in GF_PATTERNS_PARAMS {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(param, "dalfox");
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
                        name: param.to_string(),
                        value: "dalfox".to_string(),
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(context),
                    });
                }
            }
        }
    }

    println!("Parameter mining completed for target: {}", target.url);
}

pub fn probe_response_id_params(target: &mut Target) {
    let client = Client::new();

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
            }
        }
    }

    println!(
        "Response-based parameter mining completed for target: {}",
        target.url
    );
}

pub fn mine_parameters(target: &mut Target) {
    probe_dictionary_params(target);
    probe_response_id_params(target);
}
