use crate::target_parser::Target;
use reqwest::blocking::Client;
use url::Url;

#[derive(Debug, Clone)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    Header,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: Location,
}

pub fn analyze_parameters(target: &mut Target) {
    let client = Client::new();

    // 1. Identify reflecting parameters from existing query params
    let mut url = target.url.clone();
    for (name, value) in target.url.query_pairs() {
        let test_value = "test'\"<script>";
        url.query_pairs_mut().clear();
        for (n, v) in target.url.query_pairs() {
            if n == name {
                url.query_pairs_mut().append_pair(&n, test_value);
            } else {
                url.query_pairs_mut().append_pair(&n, &v);
            }
        }
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
        if let Ok(resp) = request.send() {
            if let Ok(text) = resp.text() {
                if text.contains(test_value) {
                    target.reflection_params.push(Param {
                        name: name.to_string(),
                        value: value.to_string(),
                        location: Location::Query,
                    });
                }
            }
        }
        url = target.url.clone(); // Reset
    }

    println!(
        "Parameter reflection analysis completed for target: {}",
        target.url
    );

    // Mine for additional parameters
    mine_parameters(target);
}

pub fn mine_parameters(target: &mut Target) {
    let client = Client::new();

    // Check for additional valid parameters (a-z single letters)
    for c in 'a'..='z' {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(&c.to_string(), "dalfox");
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
                        name: c.to_string(),
                        value: "dalfox".to_string(),
                        location: Location::Query,
                    });
                }
            }
        }
    }

    println!("Parameter mining completed for target: {}", target.url);
}
