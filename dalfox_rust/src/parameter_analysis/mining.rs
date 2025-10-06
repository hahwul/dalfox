use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::blocking::Client;

pub fn mine_parameters(target: &mut Target) {
    let client = Client::new();

    // Check for additional valid parameters (a-z single letters)
    println!("Starting parameter mining for target: {}", target.url);
    for c in 'a'..='z' {
        println!("Checking param: {}", c);
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(&c.to_string(), "dalfox");
        println!("URL for param {}: {}", c, url);
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
        match request.send() {
            Ok(resp) => match resp.text() {
                Ok(text) => {
                    println!(
                        "Response for param {} contains 'dalfox': {}",
                        c,
                        text.contains("dalfox")
                    );
                    if text.contains("dalfox") {
                        println!("Found valid param: {}", c);
                        target.reflection_params.push(Param {
                            name: c.to_string(),
                            value: "dalfox".to_string(),
                            location: crate::parameter_analysis::Location::Query,
                        });
                    }
                }
                Err(e) => println!("Failed to read response text for param {}: {}", c, e),
            },
            Err(e) => println!("Request failed for param {}: {}", c, e),
        }
    }

    println!("Parameter mining completed for target: {}", target.url);
}
