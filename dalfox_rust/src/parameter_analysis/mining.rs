use crate::parameter_analysis::Param;
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use reqwest::blocking::Client;
use scraper;

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
                    target.reflection_params.push(Param {
                        name: param.to_string(),
                        value: "dalfox".to_string(),
                        location: crate::parameter_analysis::Location::Query,
                    });
                }
            }
        }
    }

    println!("Parameter mining completed for target: {}", target.url);
}

pub fn probe_response_id_params(target: &mut Target) {
    let client = Client::new();

    let mut request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
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
    if let Some(data) = &target.data {
        request = request.body(data.clone());
    }

    if let Ok(resp) = request.send() {
        if let Ok(text) = resp.text() {
            let document = scraper::Html::parse_document(&text);

            // Select input elements with id or name
            let selector = scraper::Selector::parse("input[id], input[name]").unwrap();
            for element in document.select(&selector) {
                if let Some(id) = element.value().attr("id") {
                    if !target.reflection_params.iter().any(|p| p.name == id) {
                        target.reflection_params.push(Param {
                            name: id.to_string(),
                            value: "".to_string(),
                            location: crate::parameter_analysis::Location::Query,
                        });
                    }
                }
                if let Some(name) = element.value().attr("name") {
                    if !target.reflection_params.iter().any(|p| p.name == name) {
                        target.reflection_params.push(Param {
                            name: name.to_string(),
                            value: "".to_string(),
                            location: crate::parameter_analysis::Location::Query,
                        });
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
