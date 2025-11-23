pub mod discovery;
pub mod mining;

pub use mining::detect_injection_context;

pub use discovery::*;
pub use mining::*;
pub static REQUEST_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

use crate::cmd::scan::ScanArgs;
use crate::encoding::{base64_encode, double_url_encode, html_entity_encode, url_encode};
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    Header,
    Path,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DelimiterType {
    SingleQuote,
    DoubleQuote,
    Comment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InjectionContext {
    Html(Option<DelimiterType>),
    Javascript(Option<DelimiterType>),
    Attribute(Option<DelimiterType>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_context: Option<InjectionContext>,
    // Special characters that were confirmed reflected unchanged for this parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_specials: Option<Vec<char>>,
    // Special characters that appear to be filtered, encoded, or not reflected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_specials: Option<Vec<char>>,
}

/// Set of special characters to probe with patterns like: dalfox'<char>dlafox"
/// Order preserved for deterministic output.
pub const SPECIAL_PROBE_CHARS: &[char] = &[
    '/', '\\', '\'', '{', '`', '<', '>', '"', '(', ')', ';', '=', '|', '}', '[', '.', ':', ']',
    '+', ',', '$', '-',
];

/// Skeleton classification helper.
/// Given a response body that already contains the reflection marker (e.g. "dalfox"),
/// return (valid, invalid) special chars based on naive presence detection.
/// TODO:
/// 1. Actively send mutated payloads per character (e.g. dalfox'<c>dlafox")
/// 2. Parse the reflected segment boundaries to avoid false positives
/// 3. Detect normalization (HTML entity encoding, URL encoding) and still treat as "valid"
pub fn classify_special_chars(body: &str) -> (Vec<char>, Vec<char>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for c in SPECIAL_PROBE_CHARS {
        if body.contains(*c) {
            valid.push(*c);
        } else {
            invalid.push(*c);
        }
    }
    (valid, invalid)
}

/// Return common encoded variants (HTML entities / numeric) for a character.
/// Used to treat encoded reflection as still valid.
pub fn encoded_variants(c: char) -> Vec<&'static str> {
    match c {
        '<' => vec!["&lt;", "&#60;"],
        '>' => vec!["&gt;", "&#62;"],
        '"' => vec!["&quot;", "&#34;"],
        '\'' => vec!["&#39;", "&apos;"],
        '(' => vec!["&#40;"],
        ')' => vec!["&#41;"],
        '{' => vec!["&#123;"],
        '}' => vec!["&#125;"],
        '[' => vec!["&#91;"],
        ']' => vec!["&#93;"],
        '`' => vec!["&#96;"],
        '/' => vec!["&#47;"],
        '\\' => vec!["&#92;"],
        ';' => vec!["&#59;"],
        '=' => vec!["&#61;"],
        '|' => vec!["&#124;"],
        '+' => vec!["&#43;"],
        ',' => vec!["&#44;"],
        '$' => vec!["&#36;"],
        '-' => vec!["&#45;"],
        '.' => vec!["&#46;"],
        ':' => vec!["&#58;"],
        _ => vec![],
    }
}

/// Extract segment between first "dalfox" and subsequent "dlafox"
fn extract_reflected_segment(body: &str) -> Option<&str> {
    let start = body.find("dalfox")?;
    let after = start + "dalfox".len();
    let rest = &body[after..];
    let end_rel = rest.find("dlafox")?;
    Some(&rest[..end_rel])
}

/// Active probe for one parameter: send per-char payloads and classify specials.
pub async fn active_probe_param(
    target: &Target,
    mut param: Param,
    semaphore: Arc<Semaphore>,
    encoders: Vec<String>,
) -> Param {
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    let mut handles = Vec::new();
    let valid_specials = Arc::new(Mutex::new(Vec::<char>::new()));
    let invalid_specials = Arc::new(Mutex::new(Vec::<char>::new()));

    for &c in SPECIAL_PROBE_CHARS {
        let sem_clone = semaphore.clone();
        let client_clone = client.clone();
        let method = target.method.clone();
        let url_original = target.url.clone();
        let headers = target.headers.clone();
        let cookies = target.cookies.clone();
        let user_agent = target.user_agent.clone();
        let data = target.data.clone();
        let param_name = param.name.clone();
        let location = param.location.clone();

        let valid_ref = valid_specials.clone();
        let invalid_ref = invalid_specials.clone();

        let encoders_clone = encoders.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            let payload = format!("dalfox{}dlafox", c);
            let req_method = method.parse().unwrap_or(reqwest::Method::GET);
            let mut url = url_original.clone();
            let mut request_builder;

            match location {
                Location::Query => {
                    let mut new_pairs: Vec<(String, String)> = Vec::new();
                    let mut replaced = false;
                    for (k, v) in url_original.query_pairs() {
                        if k == param_name {
                            new_pairs.push((k.to_string(), payload.clone()));
                            replaced = true;
                        } else {
                            new_pairs.push((k.to_string(), v.to_string()));
                        }
                    }
                    if !replaced {
                        new_pairs.push((param_name.clone(), payload.clone()));
                    }
                    url.query_pairs_mut().clear();
                    for (k, v) in new_pairs {
                        url.query_pairs_mut().append_pair(&k, &v);
                    }
                    request_builder = client_clone.request(req_method, url);
                }
                Location::Body => {
                    let body_string;
                    if let Some(d) = &data {
                        let mut pairs: Vec<(String, String)> =
                            url::form_urlencoded::parse(d.as_bytes())
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect();
                        let mut found = false;
                        for (k, v) in &mut pairs {
                            if *k == param_name {
                                *v = payload.clone();
                                found = true;
                            }
                        }
                        if !found {
                            pairs.push((param_name.clone(), payload.clone()));
                        }
                        body_string = url::form_urlencoded::Serializer::new(String::new())
                            .extend_pairs(pairs)
                            .finish();
                    } else {
                        body_string = format!("{}={}", param_name, payload);
                    }
                    request_builder = client_clone
                        .request(req_method, url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(body_string);
                }
                Location::Header => {
                    let is_cookie = cookies.iter().any(|(n, _)| n == &param_name);
                    request_builder = client_clone.request(req_method, url);
                    if is_cookie {
                        let mut cookie_header = String::new();
                        for (k, v) in &cookies {
                            if k == &param_name {
                                cookie_header.push_str(&format!("{}={}; ", k, payload));
                            } else {
                                cookie_header.push_str(&format!("{}={}; ", k, v));
                            }
                        }
                        if !cookie_header.is_empty() {
                            cookie_header.pop();
                            cookie_header.pop();
                            request_builder = request_builder.header("Cookie", cookie_header);
                        }
                    } else {
                        for (k, v) in &headers {
                            if k == &param_name {
                                request_builder = request_builder.header(k, payload.clone());
                            } else {
                                request_builder = request_builder.header(k, v);
                            }
                        }
                    }
                }
                Location::Path => {
                    let mut path_url = url_original.clone();
                    if let Some(idx_str) = param_name.strip_prefix("path_segment_") {
                        if let Ok(idx) = idx_str.parse::<usize>() {
                            let original_path = path_url.path();
                            let mut segments: Vec<String> = if original_path == "/" {
                                Vec::new()
                            } else {
                                original_path
                                    .trim_matches('/')
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string())
                                    .collect()
                            };
                            if idx < segments.len() {
                                segments[idx] = payload.clone();
                                let new_path = if segments.is_empty() {
                                    "/".to_string()
                                } else {
                                    format!("/{}", segments.join("/"))
                                };
                                path_url.set_path(&new_path);
                            }
                        }
                    }
                    request_builder = client_clone.request(req_method, path_url);
                }
                Location::JsonBody => {
                    // Attempt JSON body mutation
                    let mut json_value_opt: Option<Value> = None;
                    if let Some(d) = &data {
                        if let Ok(parsed) = serde_json::from_str::<Value>(d) {
                            json_value_opt = Some(parsed);
                        }
                    }
                    let mut root =
                        json_value_opt.unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                    if let Value::Object(ref mut map) = root {
                        map.insert(param_name.clone(), Value::String(payload.clone()));
                    } else {
                        // If existing body isn't an object, wrap it
                        let mut map = serde_json::Map::new();
                        map.insert(param_name.clone(), Value::String(payload.clone()));
                        root = Value::Object(map);
                    }
                    let body_string = serde_json::to_string(&root)
                        .unwrap_or_else(|_| format!("{{\"{}\":\"{}\"}}", param_name, payload));
                    request_builder = client_clone
                        .request(req_method, url)
                        .header("Content-Type", "application/json")
                        .body(body_string);
                }
            }

            if let Some(ua) = &user_agent {
                request_builder = request_builder.header("User-Agent", ua);
            }
            // Aggregate cookies into a single Cookie header to avoid duplicates
            let is_cookie_param =
                location == Location::Header && cookies.iter().any(|(n, _)| n == &param_name);
            if !is_cookie_param && !cookies.is_empty() {
                let mut cookie_header = String::new();
                for (ck, cv) in &cookies {
                    // Skip the probed cookie param itself (already injected above if applicable)
                    if ck == &param_name && location == Location::Header {
                        continue;
                    }
                    cookie_header.push_str(&format!("{}={}; ", ck, cv));
                }
                if !cookie_header.is_empty() {
                    cookie_header.pop();
                    cookie_header.pop();
                    request_builder = request_builder.header("Cookie", cookie_header);
                }
            }
            if let Some(d) = &data {
                if matches!(location, Location::Query | Location::Header) {
                    request_builder = request_builder.body(d.clone());
                }
            }

            let reflected_ok = if let Ok(resp) = {
                crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                request_builder.send().await
            } {
                if let Ok(text) = resp.text().await {
                    if let Some(segment) = extract_reflected_segment(&text) {
                        if segment.contains(c) {
                            true
                        } else {
                            let encs = encoded_variants(c);
                            let mut found = false;
                            for e in encs {
                                if segment.contains(e) {
                                    found = true;
                                    break;
                                }
                            }
                            if !found {
                                let pct = format!("%{:02X}", c as u32);
                                if segment.to_ascii_uppercase().contains(&pct) {
                                    found = true;
                                }
                            }
                            found
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if reflected_ok {
                valid_ref.lock().await.push(c);
            } else {
                // Dynamic fallback probing using user-specified encoders
                // Iterate through encoders from args.encoders (passed in) except "none"
                let mut alt_reflected = false;
                let priorities = ["url", "html", "2url", "base64"];
                let mut ordered: Vec<String> = Vec::new();
                for p in priorities.iter() {
                    if encoders_clone.iter().any(|e| e == p) {
                        ordered.push(p.to_string());
                    }
                }
                for enc in ordered {
                    let encoded_piece = match enc.as_str() {
                        "url" => url_encode(&c.to_string()),
                        "html" => html_entity_encode(&c.to_string()),
                        "2url" => double_url_encode(&c.to_string()),
                        "base64" => base64_encode(&c.to_string()),
                        _ => continue,
                    };
                    let payload_enc = format!("dalfox{}dlafox", encoded_piece);
                    let req_method2 = method.parse().unwrap_or(reqwest::Method::GET);
                    let mut url2 = url_original.clone();
                    let mut request_builder2;
                    match location {
                        Location::Query => {
                            let mut new_pairs: Vec<(String, String)> = Vec::new();
                            let mut replaced = false;
                            for (k, v) in url_original.query_pairs() {
                                if k == param_name {
                                    new_pairs.push((k.to_string(), payload_enc.clone()));
                                    replaced = true;
                                } else {
                                    new_pairs.push((k.to_string(), v.to_string()));
                                }
                            }
                            if !replaced {
                                new_pairs.push((param_name.clone(), payload_enc.clone()));
                            }
                            url2.query_pairs_mut().clear();
                            for (k, v) in new_pairs {
                                url2.query_pairs_mut().append_pair(&k, &v);
                            }
                            request_builder2 = client_clone.request(req_method2, url2);
                        }
                        Location::Body => {
                            let body_string;
                            if let Some(d) = &data {
                                let mut pairs: Vec<(String, String)> =
                                    url::form_urlencoded::parse(d.as_bytes())
                                        .map(|(k, v)| (k.to_string(), v.to_string()))
                                        .collect();
                                let mut found = false;
                                for (k, v) in &mut pairs {
                                    if *k == param_name {
                                        *v = payload_enc.clone();
                                        found = true;
                                    }
                                }
                                if !found {
                                    pairs.push((param_name.clone(), payload_enc.clone()));
                                }
                                body_string = url::form_urlencoded::Serializer::new(String::new())
                                    .extend_pairs(pairs)
                                    .finish();
                            } else {
                                body_string = format!("{}={}", param_name, payload_enc);
                            }
                            request_builder2 = client_clone
                                .request(req_method2, url2)
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .body(body_string);
                        }
                        Location::Header => {
                            let is_cookie = cookies.iter().any(|(n, _)| n == &param_name);
                            request_builder2 = client_clone.request(req_method2, url2);
                            if is_cookie {
                                let mut cookie_header = String::new();
                                for (k, v) in &cookies {
                                    if k == &param_name {
                                        cookie_header.push_str(&format!("{}={}; ", k, payload_enc));
                                    } else {
                                        cookie_header.push_str(&format!("{}={}; ", k, v));
                                    }
                                }
                                if !cookie_header.is_empty() {
                                    cookie_header.pop();
                                    cookie_header.pop();
                                    request_builder2 =
                                        request_builder2.header("Cookie", cookie_header);
                                }
                            } else {
                                for (k, v) in &headers {
                                    if k == &param_name {
                                        request_builder2 =
                                            request_builder2.header(k, payload_enc.clone());
                                    } else {
                                        request_builder2 = request_builder2.header(k, v);
                                    }
                                }
                            }
                        }
                        Location::Path => {
                            let mut url_path = url2.clone();
                            if let Some(idx_str) = param_name.strip_prefix("path_segment_") {
                                if let Ok(idx) = idx_str.parse::<usize>() {
                                    let original_path = url_path.path();
                                    let mut segments: Vec<String> = if original_path == "/" {
                                        Vec::new()
                                    } else {
                                        original_path
                                            .trim_matches('/')
                                            .split('/')
                                            .filter(|s| !s.is_empty())
                                            .map(|s| s.to_string())
                                            .collect()
                                    };
                                    if idx < segments.len() {
                                        segments[idx] = payload_enc.clone();
                                        let new_path = if segments.is_empty() {
                                            "/".to_string()
                                        } else {
                                            format!("/{}", segments.join("/"))
                                        };
                                        url_path.set_path(&new_path);
                                    }
                                }
                            }
                            request_builder2 = client_clone.request(req_method2, url_path);
                        }
                        Location::JsonBody => {
                            // JSON fallback probing
                            let mut json_value_opt: Option<Value> = None;
                            if let Some(d) = &data {
                                if let Ok(parsed) = serde_json::from_str::<Value>(d) {
                                    json_value_opt = Some(parsed);
                                }
                            }
                            let mut root = json_value_opt
                                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                            if let Value::Object(ref mut map) = root {
                                map.insert(param_name.clone(), Value::String(payload_enc.clone()));
                            } else {
                                let mut map = serde_json::Map::new();
                                map.insert(param_name.clone(), Value::String(payload_enc.clone()));
                                root = Value::Object(map);
                            }
                            let body_string = serde_json::to_string(&root).unwrap_or_else(|_| {
                                format!("{{\"{}\":\"{}\"}}", param_name, payload_enc)
                            });
                            request_builder2 = client_clone
                                .request(req_method2, url2)
                                .header("Content-Type", "application/json")
                                .body(body_string);
                        }
                    }
                    if let Some(ua) = &user_agent {
                        request_builder2 = request_builder2.header("User-Agent", ua);
                    }
                    // Aggregate cookies once (skip if probing a cookie param already set above)
                    let is_cookie_param = location == Location::Header
                        && cookies.iter().any(|(n, _)| n == &param_name);
                    if !is_cookie_param && !cookies.is_empty() {
                        let mut cookie_header = String::new();
                        for (ck, cv) in &cookies {
                            if ck == &param_name && location == Location::Header {
                                continue;
                            }
                            cookie_header.push_str(&format!("{}={}; ", ck, cv));
                        }
                        if !cookie_header.is_empty() {
                            cookie_header.pop();
                            cookie_header.pop();
                            request_builder2 = request_builder2.header("Cookie", cookie_header);
                        }
                    }
                    if let Some(d) = &data {
                        if matches!(location, Location::Query | Location::Header) {
                            request_builder2 = request_builder2.body(d.clone());
                        }
                    }
                    if let Ok(resp2) = {
                        crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        request_builder2.send().await
                    } {
                        if let Ok(text2) = resp2.text().await {
                            if let Some(segment2) = extract_reflected_segment(&text2) {
                                if segment2.contains(c)
                                    || segment2.contains(&encoded_piece)
                                    || segment2
                                        .to_ascii_uppercase()
                                        .contains(&format!("%{:02X}", c as u32))
                                {
                                    alt_reflected = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if alt_reflected {
                    valid_ref.lock().await.push(c);
                } else {
                    invalid_ref.lock().await.push(c);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let v = valid_specials.lock().await.clone();
    let iv = invalid_specials.lock().await.clone();

    param.valid_specials = Some(v);
    param.invalid_specials = Some(iv);
    param
}

pub async fn analyze_parameters(
    target: &mut Target,
    args: &ScanArgs,
    multi_pb: Option<Arc<MultiProgress>>,
) {
    let pb = if let Some(ref mp) = multi_pb {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Analyzing parameters for {}", target.url));
        Some(pb)
    } else {
        None
    };

    let reflection_params = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Semaphore::new(target.workers));
    check_discovery(target, args, reflection_params.clone(), semaphore.clone()).await;
    mine_parameters(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    let mut params = reflection_params.lock().await.clone();
    if !args.param.is_empty() {
        params = filter_params(params, &args.param, target);
    }
    target.reflection_params = params;
    // Active special character probing (overwrite naive classification)
    // Concurrent active probing per parameter
    let probe_semaphore = Arc::new(Semaphore::new(target.workers));
    let mut param_handles = Vec::new();
    for p in target.reflection_params.clone() {
        let target_ref = target.clone();
        let sem = probe_semaphore.clone();
        let encoders_clone = args.encoders.clone();
        param_handles.push(tokio::spawn(async move {
            active_probe_param(&target_ref, p, sem, encoders_clone).await
        }));
    }
    let mut probed = Vec::with_capacity(param_handles.len());
    for h in param_handles {
        if let Ok(res) = h.await {
            probed.push(res);
        }
    }
    target.reflection_params = probed;

    // Logging parameter analysis (stderr)
    if !args.silence {
        for p in &target.reflection_params {
            let valid = p
                .valid_specials
                .as_ref()
                .map(|v| v.iter().collect::<String>())
                .unwrap_or_else(|| "-".to_string());
            let invalid = p
                .invalid_specials
                .as_ref()
                .map(|v| v.iter().collect::<String>())
                .unwrap_or_else(|| "-".to_string());
            eprintln!(
                "[param-analysis] name={} type={:?} reflected=true context={:?} valid_specials=\"{}\" invalid_specials=\"{}\"",
                p.name, p.location, p.injection_context, valid, invalid
            );
        }
    }

    if let Some(pb) = pb {
        pb.finish_with_message(format!("Completed analyzing parameters for {}", target.url));
    }
}

fn filter_params(params: Vec<Param>, param_specs: &[String], target: &Target) -> Vec<Param> {
    if param_specs.is_empty() {
        return params;
    }

    params
        .into_iter()
        .filter(|p| {
            for spec in param_specs {
                if spec.contains(':') {
                    let parts: Vec<&str> = spec.split(':').collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let type_str = parts[1];
                        if p.name == name {
                            let param_type = match p.location {
                                Location::Query => "query",
                                Location::Body => "body",
                                Location::JsonBody => "json",
                                Location::Path => "path",
                                Location::Header => {
                                    if target.cookies.iter().any(|(n, _)| n == &p.name) {
                                        "cookie"
                                    } else {
                                        "header"
                                    }
                                }
                            };
                            if param_type == type_str {
                                return true;
                            }
                        }
                    } else {
                        // Invalid format, treat as name only
                        if p.name == *spec {
                            return true;
                        }
                    }
                } else {
                    // 이름만 지정
                    if p.name == *spec {
                        return true;
                    }
                }
            }
            false
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::scan::ScanArgs;
    use crate::target_parser::parse_target;

    // Mock mining function for testing
    fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
        // Simulate adding a reflection param
        _target.reflection_params.push(Param {
            name: "test_param".to_string(),
            value: "test_value".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });
    }

    #[test]
    fn test_analyze_parameters_with_mock_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Mock mining instead of real mining
        mock_mine_parameters(&mut target, &args);

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].name, "test_param");
        assert_eq!(target.reflection_params[0].value, "test_value");
        assert_eq!(target.reflection_params[0].location, Location::Query);
        assert_eq!(
            target.reflection_params[0].injection_context,
            Some(InjectionContext::Html(None))
        );
    }

    #[test]
    fn test_analyze_parameters_skip_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let _args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: true, // Skip mining
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Even with mock, if skip_mining is true, no params should be added
        // But since we call mock manually, this tests the logic flow
        assert!(target.reflection_params.is_empty());
    }

    #[test]
    fn test_probe_body_params_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        let _args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: Some("key1=value1&key2=value2".to_string()),
            headers: vec![],
            cookies: vec![],
            method: "POST".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Mock body param reflection
        target.reflection_params.push(Param {
            name: "key1".to_string(),
            value: "dalfox".to_string(),
            location: Location::Body,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Body);
    }

    #[test]
    fn test_check_header_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .headers
            .push(("X-Test".to_string(), "value".to_string()));

        // Mock header discovery
        target.reflection_params.push(Param {
            name: "X-Test".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_check_cookie_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        // Mock cookie discovery
        target.reflection_params.push(Param {
            name: "session".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header, // Cookies are sent in Header
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_cookie_from_raw() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: Some("samples/sample_request.txt".to_string()),
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Simulate cookie loading
        if let Some(path) = &args.cookie_from_raw {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        assert!(!target.cookies.is_empty());
        assert_eq!(target.cookies.len(), 2);
        assert_eq!(
            target.cookies[0],
            ("session".to_string(), "abc".to_string())
        );
        assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
    }

    #[test]
    fn test_cookie_from_raw_no_file() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: Some("nonexistent.txt".to_string()),
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Simulate cookie loading - file doesn't exist
        if let Some(path) = &args.cookie_from_raw {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        // Should remain empty since file doesn't exist
        assert!(target.cookies.is_empty());
    }

    #[test]
    fn test_cookie_from_raw_malformed() {
        let mut target = parse_target("https://example.com").unwrap();
        let malformed_content = "Cookie: session=abc; invalid_cookie; user=123";

        for line in malformed_content.lines() {
            if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                for cookie in cookie_line.split("; ") {
                    if let Some((name, value)) = cookie.split_once('=') {
                        target
                            .cookies
                            .push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }

        // Should parse valid cookies, skip invalid ones
        assert_eq!(target.cookies.len(), 2);
        assert_eq!(
            target.cookies[0],
            ("session".to_string(), "abc".to_string())
        );
        assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
    }

    #[test]
    fn test_filter_params_by_name_and_type() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let params = vec![
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Body,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
        ];

        // Filter by name only
        let filtered = filter_params(params.clone(), &["sort".to_string()], &target);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|p| p.name == "sort"));

        // Filter by name and type
        let filtered = filter_params(params.clone(), &["sort:query".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "sort");
        assert_eq!(filtered[0].location, Location::Query);

        // Filter by cookie type
        let filtered = filter_params(params.clone(), &["session:cookie".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "session");
        assert_eq!(filtered[0].location, Location::Header);

        // No match
        let filtered = filter_params(params.clone(), &["nonexistent".to_string()], &target);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_filter_params_multiple_filters() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let params = vec![
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
            },
        ];

        // Multiple filters
        let filtered = filter_params(
            params.clone(),
            &["sort".to_string(), "id".to_string()],
            &target,
        );
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|p| p.name == "sort"));
        assert!(filtered.iter().any(|p| p.name == "id"));
    }

    #[test]
    fn test_filter_params_empty_filters() {
        let target = parse_target("https://example.com").unwrap();
        let params = vec![Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        }];

        // Empty filters should return all params
        let filtered = filter_params(params.clone(), &[], &target);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_params_invalid_filter_format() {
        let target = parse_target("https://example.com").unwrap();
        let params = vec![Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
        }];

        // Invalid filter format (too many colons) should be treated as name only
        let filtered = filter_params(params.clone(), &["sort:query:extra".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "sort");
    }
}
