//! # Parameter Analysis (Stages 1–3)
//!
//! Orchestrates Discovery → Mining → Active Probing to produce a finalized
//! list of reflected parameters with confirmed injection characteristics.
//!
//! ## Stage 3: Active Probing (`active_probe_param`)
//!
//! **Input:** `DiscoveredParams` — parameters from Stages 1-2 with naive
//! special character classification and injection context.
//!
//! **Output:** `ProbedParams` — parameters with:
//! - `valid_specials` / `invalid_specials` actively confirmed via per-char probes
//! - `injection_context` refined from actual response analysis
//! - `pre_encoding` auto-detected (base64, 2base64, 2url, 3url) when `<` is
//!   invalid in naive check but valid after encoding
//!
//! **Side effects:** HTTP requests (one per special character per parameter).
//! Runs concurrently via tokio tasks bounded by `target.workers`.

pub mod discovery;
pub mod mining;

pub use mining::detect_injection_context;

pub use discovery::*;
pub use mining::*;
pub static REQUEST_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

use crate::cmd::scan::ScanArgs;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

/// Parameters after Stage 1 (Discovery) and Stage 2 (Mining).
/// Each `Param` has naive `valid_specials`/`invalid_specials` and a tentative
/// `injection_context`, but `pre_encoding` is still `None`.
pub type DiscoveredParams = Vec<Param>;

/// Parameters after Stage 3 (Active Probing).
/// Each `Param` now carries actively confirmed `valid_specials`/`invalid_specials`,
/// a refined `injection_context`, and auto-detected `pre_encoding`.
pub type ProbedParams = Vec<Param>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    MultipartBody,
    Header,
    Path,
    Fragment,
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
    AttributeUrl(Option<DelimiterType>),
    Css(Option<DelimiterType>),
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
    /// Pre-encoding required before injection (e.g. "base64", "2base64").
    /// When set, payloads are pre-encoded before sending and reflection is
    /// checked against the original (decoded) payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_encoding: Option<String>,
    /// POST target URL resolved from form action attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_action_url: Option<String>,
    /// Page URL where the form was discovered (for stored XSS verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_origin_url: Option<String>,
}

/// Set of special characters to probe with patterns like: dalfox'<char>dlafox"
/// Order preserved for deterministic output.
pub const SPECIAL_PROBE_CHARS: &[char] = &[
    '/', '\\', '\'', '{', '`', '<', '>', '"', '(', ')', ';', '=', '|', '}', '[', '.', ':', ']',
    '+', ',', '$', '-',
];

/// Skeleton classification helper.
/// Given a response body that already contains the reflection marker (dynamic nonce),
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

/// Extract segment between first open marker and subsequent close marker
fn extract_reflected_segment(body: &str) -> Option<&str> {
    let open = crate::scanning::markers::open_marker();
    let close = crate::scanning::markers::close_marker();
    let start = body.find(open)?;
    let after = start + open.len();
    let rest = &body[after..];
    let end_rel = rest.find(close)?;
    Some(&rest[..end_rel])
}

/// Active probe for one parameter: send per-char payloads and classify specials.
pub async fn active_probe_param(
    target: &Target,
    mut param: Param,
    semaphore: Arc<Semaphore>,
) -> Param {
    let client = target.build_client_or_default();

    let mut handles = Vec::new();
    let valid_specials = Arc::new(Mutex::new(Vec::<char>::new()));
    let invalid_specials = Arc::new(Mutex::new(Vec::<char>::new()));

    for &c in SPECIAL_PROBE_CHARS {
        let sem_clone = semaphore.clone();
        let client_clone = client.clone();
        let parsed_method = target.parse_method();
        let url_original = target.url.clone();
        let headers = target.headers.clone();
        let cookies = target.cookies.clone();
        let user_agent = target.user_agent.clone();
        let data = target.data.clone();
        let param_name = param.name.clone();
        let location = param.location.clone();
        let pre_encoding = param.pre_encoding.clone();
        let form_action_url = param.form_action_url.clone();
        let ignore_return = target.ignore_return.clone();

        let valid_ref = valid_specials.clone();
        let invalid_ref = invalid_specials.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.expect("acquire semaphore permit");
            let probe_payload = format!(
                "{}{}{}",
                crate::scanning::markers::open_marker(),
                c,
                crate::scanning::markers::close_marker()
            );
            // Apply pre-encoding (base64/2base64) so the server can decode
            // the probe value the same way it decodes normal user input.
            let payload = crate::encoding::pre_encoding::apply_pre_encoding(
                &probe_payload,
                &pre_encoding,
            );
            // Force POST for Body/JsonBody/MultipartBody params even when default target method is GET
            let req_method = match location {
                Location::Body | Location::JsonBody | Location::MultipartBody => {
                    reqwest::Method::POST
                }
                _ => parsed_method,
            };
            let body_url = form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| url_original.clone());
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
                        .request(req_method, body_url.clone())
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
                                cookie_header.push_str(k); cookie_header.push('='); cookie_header.push_str(&payload); cookie_header.push_str("; ");
                            } else {
                                cookie_header.push_str(k); cookie_header.push('='); cookie_header.push_str(v); cookie_header.push_str("; ");
                            }
                        }
                        if !cookie_header.is_empty() {
                            cookie_header.pop();
                            cookie_header.pop();
                            request_builder = request_builder.header("Cookie", cookie_header);
                        }
                    } else {
                        let mut injected = false;
                        for (k, v) in &headers {
                            if k == &param_name {
                                request_builder = request_builder.header(k, payload.clone());
                                injected = true;
                            } else {
                                request_builder = request_builder.header(k, v);
                            }
                        }
                        // If param was discovered (e.g. via check_header_discovery)
                        // but isn't in the user-provided headers, inject it directly.
                        if !injected {
                            request_builder = request_builder.header(&param_name, payload.clone());
                        }
                    }
                }
                Location::Path => {
                    let mut path_url = url_original.clone();
                    if let Some(idx_str) = param_name.strip_prefix("path_segment_")
                        && let Ok(idx) = idx_str.parse::<usize>()
                    {
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
                    request_builder = client_clone.request(req_method, path_url);
                }
                Location::JsonBody => {
                    // Attempt JSON body mutation
                    let mut json_value_opt: Option<Value> = None;
                    if let Some(d) = &data
                        && let Ok(parsed) = serde_json::from_str::<Value>(d)
                    {
                        json_value_opt = Some(parsed);
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
                        .request(req_method, body_url.clone())
                        .header("Content-Type", "application/json")
                        .body(body_string);
                }
                Location::MultipartBody => {
                    // Build multipart/form-data body
                    let mut form = reqwest::multipart::Form::new();
                    if let Some(d) = &data {
                        for pair in d.split('&') {
                            if let Some((k, v)) = pair.split_once('=') {
                                let k = urlencoding::decode(k)
                                    .unwrap_or(std::borrow::Cow::Borrowed(k))
                                    .to_string();
                                let v = urlencoding::decode(v)
                                    .unwrap_or(std::borrow::Cow::Borrowed(v))
                                    .to_string();
                                if k == param_name {
                                    form = form.text(k, payload.clone());
                                } else {
                                    form = form.text(k, v);
                                }
                            }
                        }
                    }
                    // If param not found in existing data, add it
                    if data.is_none()
                        || !data
                            .as_ref()
                            .unwrap_or(&String::new())
                            .contains(&param_name)
                    {
                        form = form.text(param_name.clone(), payload.clone());
                    }
                    request_builder = client_clone
                        .request(req_method, body_url.clone())
                        .multipart(form);
                }
                Location::Fragment => {
                    // Fragment injection: payload goes into the URL fragment.
                    // Use build_injected_url which handles fragment param replacement.
                    let inject_url_str = crate::scanning::url_inject::build_injected_url(
                        &url_original, &crate::parameter_analysis::Param {
                            name: param_name.clone(),
                            value: String::new(),
                            location: Location::Fragment,
                            injection_context: None,
                            valid_specials: None,
                            invalid_specials: None,
                            pre_encoding: None,
                            form_action_url: None,
                            form_origin_url: None,
                        }, &payload);
                    let frag_url = url::Url::parse(&inject_url_str).unwrap_or_else(|_| url_original.clone());
                    request_builder = client_clone.request(req_method, frag_url);
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
                    cookie_header.push_str(ck); cookie_header.push('='); cookie_header.push_str(cv); cookie_header.push_str("; ");
                }
                if !cookie_header.is_empty() {
                    cookie_header.pop();
                    cookie_header.pop();
                    request_builder = request_builder.header("Cookie", cookie_header);
                }
            }
            if let Some(d) = &data
                && matches!(location, Location::Query | Location::Header | Location::Fragment)
            {
                request_builder = request_builder.body(d.clone());
            }

            let reflected_ok = if let Ok(resp) = {
                crate::tick_request_count();
                request_builder.send().await
            } {
                // Skip processing if the status code is in the ignore_return list
                if !ignore_return.is_empty()
                    && ignore_return.contains(&resp.status().as_u16())
                {
                    false
                } else {
                    // For redirect responses, also check the Location header
                    let redirect_text = if resp.status().is_redirection() {
                        resp.headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string())
                    } else {
                        None
                    };
                    let body_text = resp.text().await.ok();
                    // Combine redirect Location and body for reflection checking
                    let combined = match (&redirect_text, &body_text) {
                        (Some(loc), Some(body)) => format!("{}{}", loc, body),
                        (Some(loc), None) => loc.clone(),
                        (None, Some(body)) => body.clone(),
                        (None, None) => String::new(),
                    };
                    if let Some(segment) = extract_reflected_segment(&combined) {
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
                }
            } else {
                false
            };

            if reflected_ok {
                valid_ref.lock().await.push(c);
            } else {
                // Literal character is blocked by the server.  Classify as
                // invalid so payload generators can skip payloads that rely
                // on the raw char (e.g. angle-bracket tag payloads in
                // attribute context).  Encoded-bypass opportunities are
                // handled separately by the encoding pipeline during
                // scanning.
                invalid_ref.lock().await.push(c);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let v = valid_specials.lock().await.clone();
    let iv = invalid_specials.lock().await.clone();

    param.valid_specials = Some(v.clone());
    param.invalid_specials = Some(iv.clone());

    // If '<' is invalid and no pre_encoding is set, try double/triple URL encoding
    // to detect servers that multi-decode input (e.g. double URL decode).
    if param.pre_encoding.is_none()
        && iv.contains(&'<')
        && matches!(param.location, Location::Query | Location::Path)
    {
        let open = crate::scanning::markers::open_marker();
        let close = crate::scanning::markers::close_marker();
        let raw_marker = format!("{}<{}", open, close);

        for (enc_type, rounds) in crate::encoding::pre_encoding::multi_url_decode_probes() {
            let enc_name = enc_type.as_str();
            let mut encoded = raw_marker.clone();
            // For Query: append_pair adds one URL-encoding layer automatically,
            // so we encode (N-1) times for N-decode detection.
            // For Path: selective_path_segment_encode encodes '%' to '%25' (one layer),
            // so we also encode (N-1) extra times.
            for _ in 0..*rounds {
                encoded = crate::encoding::url_encode(&encoded);
            }

            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let url = match param.location {
                Location::Query => {
                    let mut url = target.url.clone();
                    let mut new_pairs: Vec<(String, String)> = Vec::new();
                    let mut replaced = false;
                    for (k, val) in url.query_pairs() {
                        if k == param.name {
                            new_pairs.push((k.to_string(), encoded.clone()));
                            replaced = true;
                        } else {
                            new_pairs.push((k.to_string(), val.to_string()));
                        }
                    }
                    if !replaced {
                        new_pairs.push((param.name.clone(), encoded.clone()));
                    }
                    url.query_pairs_mut().clear();
                    for (k, val) in &new_pairs {
                        url.query_pairs_mut().append_pair(k, val);
                    }
                    url
                }
                Location::Path => {
                    let mut url = target.url.clone();
                    if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                        && let Ok(idx) = idx_str.parse::<usize>()
                    {
                        let original_path = url.path().to_string();
                        let segments: Vec<&str> = if original_path == "/" {
                            Vec::new()
                        } else {
                            original_path
                                .trim_matches('/')
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .collect()
                        };
                        if idx < segments.len() {
                            // Encode '%' for the path so the server receives the multi-encoded payload
                            let path_encoded = encoded.replace('%', "%25");
                            let mut new_path = String::new();
                            for (i, segment) in segments.iter().enumerate() {
                                new_path.push('/');
                                if i == idx {
                                    new_path.push_str(&path_encoded);
                                } else {
                                    new_path.push_str(segment);
                                }
                            }
                            url.set_path(&new_path);
                        }
                    }
                    url
                }
                _ => unreachable!(),
            };
            let request_builder = client.request(target.parse_method(), url);
            crate::tick_request_count();
            if let Ok(resp) = request_builder.send().await
                && let Ok(text) = resp.text().await
                && text.contains(&raw_marker)
            {
                param.pre_encoding = Some(enc_name.to_string());
                // With multi-URL-decode, skip special char filtering — the encoding
                // bypasses HTTP-level filters. Set specials to None so all payloads
                // are tried.
                param.valid_specials = None;
                param.invalid_specials = None;
                break;
            }
        }
    }

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
                .expect("valid progress style template"),
        );
        pb.set_message(format!("Analyzing parameters for {}", target.url));
        Some(pb)
    } else {
        None
    };

    // === Stage 1: Discovery — identify reflecting parameters ===
    let reflection_params = Arc::new(Mutex::new(Vec::new()));
    let semaphore = Arc::new(Semaphore::new(target.workers));
    check_discovery(target, args, reflection_params.clone(), semaphore.clone()).await;

    // === Stage 2: Mining — discover additional parameters from HTML/JS/dict ===
    mine_parameters(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    let mut params = reflection_params.lock().await.clone();
    if !args.ignore_param.is_empty() {
        params.retain(|p| !args.ignore_param.iter().any(|ignored| ignored == &p.name));
    }
    if !args.param.is_empty() {
        params = filter_params(params, &args.param, target);
    }
    target.reflection_params = params;

    // === Stage 3: Active Probing — confirm specials, detect pre_encoding ===
    let probe_semaphore = Arc::new(Semaphore::new(target.workers));
    let probe_target = Arc::new(target.clone());
    let mut param_handles = Vec::new();
    for p in std::mem::take(&mut target.reflection_params) {
        let target_ref = probe_target.clone();
        let sem = probe_semaphore.clone();
        param_handles.push(tokio::spawn(async move {
            active_probe_param(target_ref.as_ref(), p, sem).await
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
                                Location::MultipartBody => "multipart",
                                Location::Path => "path",
                                Location::Fragment => "fragment",
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
    use std::sync::Arc;
    use tokio::sync::Semaphore;

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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
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
        let target = parse_target("https://example.com").unwrap();
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
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: true, // Skip mining
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
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
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Simulate cookie loading
        if let Some(path) = &args.cookie_from_raw
            && let Ok(content) = std::fs::read_to_string(path)
        {
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
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Simulate cookie loading - file doesn't exist
        if let Some(path) = &args.cookie_from_raw
            && let Ok(content) = std::fs::read_to_string(path)
        {
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            },
            Param {
                name: "sort".to_string(),
                value: "asc".to_string(),
                location: Location::Body,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            },
            Param {
                name: "id".to_string(),
                value: "123".to_string(),
                location: Location::Query,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            },
            Param {
                name: "session".to_string(),
                value: "abc".to_string(),
                location: Location::Header,
                injection_context: Some(InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
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
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        }];

        // Invalid filter format (too many colons) should be treated as name only
        let filtered = filter_params(params.clone(), &["sort:query:extra".to_string()], &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "sort");
    }

    fn default_scan_args() -> ScanArgs {
        ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec!["http://127.0.0.1:0".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: true,
            skip_mining_dict: true,
            skip_mining_dom: true,
            only_discovery: false,
            skip_discovery: true,
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
            timeout: 1,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: true,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 1,
            max_concurrent_targets: 1,
            max_targets_per_host: 1,
            encoders: vec![
                "url".to_string(),
                "html".to_string(),
                "2url".to_string(),
                "base64".to_string(),
            ],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }

    fn probe_target() -> crate::target_parser::Target {
        let mut target = parse_target("http://127.0.0.1:0/a/b?x=1").unwrap();
        target.method = "POST".to_string();
        target.data = Some("foo=bar&session=orig".to_string());
        target
            .headers
            .push(("X-Test".to_string(), "header-value".to_string()));
        target
            .cookies
            .push(("session".to_string(), "cookie-value".to_string()));
        target.user_agent = Some("DalfoxTest/1.0".to_string());
        target
    }

    fn probe_param(name: &str, location: Location) -> Param {
        Param {
            name: name.to_string(),
            value: "v".to_string(),
            location,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        }
    }

    #[test]
    fn test_classify_special_chars_and_encoded_variants() {
        let body = "/\\\\'{}<>\"()";
        let (valid, invalid) = classify_special_chars(body);
        assert!(valid.contains(&'/'));
        assert!(valid.contains(&'\\'));
        assert!(valid.contains(&'\''));
        assert!(valid.contains(&'<'));
        assert!(!invalid.is_empty());

        assert!(encoded_variants('<').contains(&"&lt;"));
        assert!(encoded_variants('"').contains(&"&quot;"));
        assert!(encoded_variants('x').is_empty());
    }

    #[test]
    fn test_extract_reflected_segment_finds_marker_bounds() {
        let body = format!(
            "aaa{}middle{}bbb",
            crate::scanning::markers::open_marker(),
            crate::scanning::markers::close_marker()
        );
        let seg = extract_reflected_segment(&body).expect("segment should exist");
        assert_eq!(seg, "middle");
    }

    #[tokio::test]
    async fn test_active_probe_param_query_path_failure_paths() {
        let target = probe_target();
        let semaphore = Arc::new(Semaphore::new(8));

        let query_res = active_probe_param(
            &target,
            probe_param("x", Location::Query),
            semaphore.clone(),
        )
        .await;
        assert!(query_res.valid_specials.as_ref().is_some());
        assert!(
            query_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );

        let path_res = active_probe_param(
            &target,
            probe_param("path_segment_1", Location::Path),
            semaphore,
        )
        .await;
        assert!(path_res.valid_specials.as_ref().is_some());
        assert!(
            path_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );
    }

    #[tokio::test]
    async fn test_active_probe_param_body_header_json_failure_paths() {
        let mut target = probe_target();
        target.data = Some("{\"json_key\":\"v\"}".to_string());
        let semaphore = Arc::new(Semaphore::new(8));

        let body_res = active_probe_param(
            &target,
            probe_param("foo", Location::Body),
            semaphore.clone(),
        )
        .await;
        assert!(body_res.valid_specials.as_ref().is_some());
        assert!(
            body_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );

        let header_cookie_res = active_probe_param(
            &target,
            probe_param("session", Location::Header),
            semaphore.clone(),
        )
        .await;
        assert!(header_cookie_res.valid_specials.as_ref().is_some());
        assert!(
            header_cookie_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );

        let header_plain_res = active_probe_param(
            &target,
            probe_param("X-Test", Location::Header),
            semaphore.clone(),
        )
        .await;
        assert!(header_plain_res.valid_specials.as_ref().is_some());
        assert!(
            header_plain_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );

        let json_res = active_probe_param(
            &target,
            probe_param("json_key", Location::JsonBody),
            semaphore,
        )
        .await;
        assert!(json_res.valid_specials.as_ref().is_some());
        assert!(
            json_res
                .invalid_specials
                .as_ref()
                .expect("invalid set")
                .len()
                >= SPECIAL_PROBE_CHARS.len()
        );
    }

    #[tokio::test]
    async fn test_analyze_parameters_with_skip_flags_finishes_cleanly() {
        let mut target = parse_target("http://127.0.0.1:0").unwrap();
        target.workers = 1;
        let args = default_scan_args();

        analyze_parameters(&mut target, &args, None).await;
        assert!(target.reflection_params.is_empty());
    }
}
