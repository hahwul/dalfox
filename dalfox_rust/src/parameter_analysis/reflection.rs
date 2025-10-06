use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::blocking::Client;

pub fn check_reflection(target: &mut Target) {
    let client = Client::new();
    let test_value = "test'\"<script>";

    // Check existing query params for reflection
    let mut url = target.url.clone();
    for (name, value) in target.url.query_pairs() {
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
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(crate::parameter_analysis::InjectionContext::Html),
                    });
                }
            }
        }
        url = target.url.clone(); // Reset
    }

    println!(
        "Parameter reflection check completed for target: {}",
        target.url
    );
}
