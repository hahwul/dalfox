use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::blocking::Client;
use std::time::Duration;

pub fn check_discovery(target: &mut Target, args: &ScanArgs) {
    if !args.skip_discovery {
        check_query_discovery(target);
        if !args.skip_reflection_header {
            check_header_discovery(target);
        }
        if !args.skip_reflection_cookie {
            check_cookie_discovery(target);
        }
    }

    println!(
        "Parameter discovery check completed for target: {}",
        target.url
    );
}

pub fn check_query_discovery(target: &mut Target) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
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
        if target.delay > 0 {
            std::thread::sleep(Duration::from_millis(target.delay));
        }
        url = target.url.clone(); // Reset
    }
}

pub fn check_header_discovery(target: &mut Target) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
    let test_value = "dalfox";

    for (header_name, header_value) in &target.headers {
        let mut request = client.request(
            target.method.parse().unwrap_or(reqwest::Method::GET),
            target.url.clone(),
        );
        for (k, v) in &target.headers {
            if k == header_name {
                request = request.header(k, test_value);
            } else {
                request = request.header(k, v);
            }
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
                        name: header_name.clone(),
                        value: header_value.clone(),
                        location: crate::parameter_analysis::Location::Header,
                        injection_context: Some(crate::parameter_analysis::InjectionContext::Html),
                    });
                }
            }
        }
        if target.delay > 0 {
            std::thread::sleep(Duration::from_millis(target.delay));
        }
    }
}

pub fn check_cookie_discovery(target: &mut Target) {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());
    let test_value = "dalfox";

    for (cookie_name, cookie_value) in &target.cookies {
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
        let mut cookie_header = String::new();
        for (k, v) in &target.cookies {
            if k == cookie_name {
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
        if let Some(data) = &target.data {
            request = request.body(data.clone());
        }
        if let Ok(resp) = request.send() {
            if let Ok(text) = resp.text() {
                if text.contains(test_value) {
                    target.reflection_params.push(Param {
                        name: cookie_name.clone(),
                        value: cookie_value.clone(),
                        location: crate::parameter_analysis::Location::Header, // Cookies are sent in Header
                        injection_context: Some(crate::parameter_analysis::InjectionContext::Html),
                    });
                }
            }
        }
        if target.delay > 0 {
            std::thread::sleep(Duration::from_millis(target.delay));
        }
    }
}
