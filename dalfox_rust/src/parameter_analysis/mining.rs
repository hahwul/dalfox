use crate::parameter_analysis::Param;
use crate::payload::mining::PARAM_LIST;
use crate::target_parser::Target;
use reqwest::blocking::Client;

pub fn mine_parameters(target: &mut Target) {
    let client = Client::new();

    // Check for additional valid parameters
    for &param in PARAM_LIST {
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
