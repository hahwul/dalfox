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
//! **Side effects:** One batched probe request per parameter that carries
//! every `SPECIAL_PROBE_CHARS` entry between the open/close markers; the
//! reflected segment is scanned to classify each char. Falls back to a
//! per-char fan-out (one request per char) only when the batched probe
//! reflects the markers but strips every special char — a likely WAF
//! tripwire on the dense payload that per-char probes can sidestep. All
//! work runs under `target.workers` semaphore gating.

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
    /// JavaScript template literal (backtick-quoted string). Distinct from
    /// `'` / `"` because the breakout payload is different — inside a
    /// template literal, `${expr}` evaluates the expression with no need
    /// to escape the surrounding quote.
    Backtick,
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
    /// Composable pre-encoding pipeline. Takes precedence over `pre_encoding`
    /// when present. Used for nested encodings that the legacy single-step
    /// field cannot express, e.g. `JsonField{pointer:"/move_url"} → Base64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_encoding_pipeline: Option<crate::encoding::pipeline::EncodingPipeline>,
    /// HTTP-layer parameter name used when the payload must be inserted at a
    /// different name than this `Param.name`. Set when `name` is a synthetic
    /// nested-field display label (e.g. `qs[move_url]`) but the wire-level
    /// substitution targets the parent parameter (`qs`). When `None`, callers
    /// fall back to `name`.
    ///
    /// Currently honored in the `Location::Query` substitution paths
    /// (`build_injected_url`, `active_probe_param`). `Location::Body`,
    /// `Header`, `JsonBody`, `MultipartBody` still substitute by `name`
    /// because nested-field discovery (`infer_nested_pipelines`) only
    /// emits Query params today. Extend those branches before enabling
    /// nested discovery on other locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_name: Option<String>,
    /// POST target URL resolved from form action attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_action_url: Option<String>,
    /// Page URL where the form was discovered (for stored XSS verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_origin_url: Option<String>,
    /// Framework-specific innerHTML-style sink the marker landed inside
    /// during discovery: `"v-html"`, `"data-bind"`, `"ng-bind-html"`,
    /// `"dangerouslySetInnerHTML"`. When set, the reflection is rendered
    /// as raw HTML by the framework at runtime — entity-encoded
    /// payloads also execute because the browser decodes them at
    /// attribute-value parse time before innerHTML assignment. Used to
    /// upgrade the finding's `inject_type` label so users can tell
    /// framework-sink reflections apart from generic attribute echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_sink: Option<String>,
}

impl Param {
    /// HTTP-level parameter name (parent param when this is a nested-field
    /// virtual param, otherwise `name`).
    pub fn effective_wire_name(&self) -> &str {
        self.wire_name.as_deref().unwrap_or(&self.name)
    }
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

/// Send one probe request that injects `payload` into `param`'s location and
/// return the response text combined with any redirect Location header. The
/// payload is sent verbatim — pre-encoding must already be applied by the
/// caller. Returns `None` when the request fails, the server returns a status
/// in `target.ignore_return`, or the body cannot be read.
async fn send_probe_request_for_param(
    client: &reqwest::Client,
    target: &Target,
    param: &Param,
    payload: &str,
) -> Option<String> {
    let parsed_method = target.parse_method();
    let url_original = target.url.clone();
    let headers = target.headers.clone();
    let cookies = target.cookies.clone();
    let user_agent = target.user_agent.clone();
    let data = target.data.clone();
    let param_name = param.name.clone();
    let wire_name = param.effective_wire_name().to_string();
    let location = param.location.clone();
    let form_action_url = param.form_action_url.clone();
    let ignore_return = target.ignore_return.clone();

    // Force POST for Body/JsonBody/MultipartBody params even when default target method is GET
    let req_method = match location {
        Location::Body | Location::JsonBody | Location::MultipartBody => reqwest::Method::POST,
        _ => parsed_method,
    };

    // When this param came from form discovery, `form_action_url` points at
    // the form's action endpoint, which may differ from the page URL where
    // the form was found. Every body-bearing location probes at the action;
    // Query must do the same so we exercise the sink rather than the
    // form-host page.
    let action_resolved_url = form_action_url
        .as_ref()
        .and_then(|u| url::Url::parse(u).ok())
        .unwrap_or_else(|| url_original.clone());
    let mut url = match location {
        Location::Query => action_resolved_url.clone(),
        _ => url_original.clone(),
    };
    let mut request_builder;

    match location {
        Location::Query => {
            let mut new_pairs: Vec<(String, String)> = Vec::new();
            let mut replaced = false;
            for (k, v) in url.query_pairs() {
                if k == wire_name {
                    new_pairs.push((k.to_string(), payload.to_string()));
                    replaced = true;
                } else {
                    new_pairs.push((k.to_string(), v.to_string()));
                }
            }
            if !replaced {
                new_pairs.push((wire_name.clone(), payload.to_string()));
            }
            url.query_pairs_mut().clear();
            for (k, v) in new_pairs {
                url.query_pairs_mut().append_pair(&k, &v);
            }
            request_builder = client.request(req_method, url);
        }
        Location::Body => {
            let body_string;
            if let Some(d) = &data {
                let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(d.as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                let mut found = false;
                for (k, v) in &mut pairs {
                    if *k == param_name {
                        *v = payload.to_string();
                        found = true;
                    }
                }
                if !found {
                    pairs.push((param_name.clone(), payload.to_string()));
                }
                body_string = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish();
            } else {
                body_string = format!("{}={}", param_name, payload);
            }
            request_builder = client
                .request(req_method, action_resolved_url.clone())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body_string);
        }
        Location::Header => {
            let is_cookie = cookies.iter().any(|(n, _)| n == &param_name);
            request_builder = client.request(req_method, url);
            if is_cookie {
                let mut cookie_header = String::new();
                for (k, v) in &cookies {
                    if k == &param_name {
                        cookie_header.push_str(k);
                        cookie_header.push('=');
                        cookie_header.push_str(payload);
                        cookie_header.push_str("; ");
                    } else {
                        cookie_header.push_str(k);
                        cookie_header.push('=');
                        cookie_header.push_str(v);
                        cookie_header.push_str("; ");
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
                        request_builder = request_builder.header(k, payload);
                        injected = true;
                    } else {
                        request_builder = request_builder.header(k, v);
                    }
                }
                if !injected {
                    request_builder = request_builder.header(&param_name, payload);
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
                        .map(ToString::to_string)
                        .collect()
                };
                if idx < segments.len() {
                    segments[idx] = payload.to_string();
                    let new_path = if segments.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", segments.join("/"))
                    };
                    path_url.set_path(&new_path);
                }
            }
            request_builder = client.request(req_method, path_url);
        }
        Location::JsonBody => {
            let mut json_value_opt: Option<Value> = None;
            if let Some(d) = &data
                && let Ok(parsed) = serde_json::from_str::<Value>(d)
            {
                json_value_opt = Some(parsed);
            }
            let mut root = json_value_opt.unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            if let Value::Object(ref mut map) = root {
                map.insert(param_name.clone(), Value::String(payload.to_string()));
            } else {
                let mut map = serde_json::Map::new();
                map.insert(param_name.clone(), Value::String(payload.to_string()));
                root = Value::Object(map);
            }
            let body_string = serde_json::to_string(&root)
                .unwrap_or_else(|_| format!("{{\"{}\":\"{}\"}}", param_name, payload));
            request_builder = client
                .request(req_method, action_resolved_url.clone())
                .header("Content-Type", "application/json")
                .body(body_string);
        }
        Location::MultipartBody => {
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
                            form = form.text(k, payload.to_string());
                        } else {
                            form = form.text(k, v);
                        }
                    }
                }
            }
            if data.is_none()
                || !data
                    .as_ref()
                    .unwrap_or(&String::new())
                    .contains(&param_name)
            {
                form = form.text(param_name.clone(), payload.to_string());
            }
            request_builder = client
                .request(req_method, action_resolved_url.clone())
                .multipart(form);
        }
        Location::Fragment => {
            let inject_url_str = crate::scanning::url_inject::build_injected_url(
                &url_original,
                &crate::parameter_analysis::Param {
                    name: param_name.clone(),
                    value: String::new(),
                    location: Location::Fragment,
                    injection_context: None,
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                },
                payload,
            );
            let frag_url =
                url::Url::parse(&inject_url_str).unwrap_or_else(|_| url_original.clone());
            request_builder = client.request(req_method, frag_url);
        }
    }

    if let Some(ua) = &user_agent {
        request_builder = request_builder.header("User-Agent", ua);
    }
    let is_cookie_param =
        location == Location::Header && cookies.iter().any(|(n, _)| n == &param_name);
    if !is_cookie_param && !cookies.is_empty() {
        let mut cookie_header = String::new();
        for (ck, cv) in &cookies {
            if ck == &param_name && location == Location::Header {
                continue;
            }
            cookie_header.push_str(ck);
            cookie_header.push('=');
            cookie_header.push_str(cv);
            cookie_header.push_str("; ");
        }
        if !cookie_header.is_empty() {
            cookie_header.pop();
            cookie_header.pop();
            request_builder = request_builder.header("Cookie", cookie_header);
        }
    }
    if let Some(d) = &data
        && matches!(
            location,
            Location::Query | Location::Header | Location::Fragment
        )
    {
        request_builder = request_builder.body(d.clone());
    }

    crate::tick_request_count();
    let resp = request_builder.send().await.ok()?;
    if !ignore_return.is_empty() && ignore_return.contains(&resp.status().as_u16()) {
        return None;
    }
    let redirect_text = if resp.status().is_redirection() {
        resp.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
    } else {
        None
    };
    let body_text = match resp.text().await {
        Ok(body) => Some(body),
        Err(e) => {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[DBG] discovery response body read failed: {}", e);
            }
            None
        }
    };
    Some(match (redirect_text, body_text) {
        (Some(loc), Some(body)) => format!("{}{}", loc, body),
        (Some(loc), None) => loc,
        (None, Some(body)) => body,
        (None, None) => String::new(),
    })
}

/// Check whether a single char `c` is observable in the reflected segment,
/// either as the literal char, one of its HTML/numeric entity variants, or
/// its `%HH` URL-encoded form. Matches the legacy per-char classification.
fn char_reflected_in_segment(segment: &str, c: char) -> bool {
    if segment.contains(c) {
        return true;
    }
    for e in encoded_variants(c) {
        if segment.contains(e) {
            return true;
        }
    }
    let pct = format!("%{:02X}", c as u32);
    if segment.to_ascii_uppercase().contains(&pct) {
        return true;
    }
    false
}

/// Active probe for one parameter. Sends a single **batched** probe carrying
/// all `SPECIAL_PROBE_CHARS` between the open/close markers, then classifies
/// each char by inspecting the reflected segment of the response. This
/// replaces the previous per-char fan-out (one request per character) with
/// one request per parameter — the dominant request-count reducer at scan
/// time.
///
/// Coverage safety net: if the batched probe is reflected but **no** char
/// survives in the reflected segment (likely the server's WAF tripped on the
/// dense special-char payload, while individual chars would pass), the
/// function falls back to the legacy per-char loop so payload generators
/// still see an accurate valid/invalid split.
pub async fn active_probe_param(
    target: &Target,
    mut param: Param,
    semaphore: Arc<Semaphore>,
) -> Param {
    let client = target.build_client_or_default();

    // Single batched probe — `OPEN + all special chars concatenated + CLOSE`.
    // `extract_reflected_segment` recovers the substring between markers, and
    // `classify_special_chars`-style per-char checks then split it into
    // valid/invalid. One request replaces SPECIAL_PROBE_CHARS.len()
    // requests.
    let batched_chars: String = SPECIAL_PROBE_CHARS.iter().collect();
    let batched_probe = format!(
        "{}{}{}",
        crate::scanning::markers::open_marker(),
        batched_chars,
        crate::scanning::markers::close_marker()
    );
    let batched_payload =
        crate::encoding::pre_encoding::apply_param_encoding(&batched_probe, &param);

    let permit = semaphore.acquire().await.expect("acquire semaphore permit");
    let batched_response =
        send_probe_request_for_param(&client, target, &param, &batched_payload).await;
    drop(permit);

    let mut valid: Vec<char> = Vec::new();
    let mut invalid: Vec<char> = Vec::new();
    let mut need_per_char_fallback = false;

    match batched_response
        .as_deref()
        .and_then(extract_reflected_segment)
    {
        Some(segment) => {
            for &c in SPECIAL_PROBE_CHARS {
                if char_reflected_in_segment(segment, c) {
                    valid.push(c);
                } else {
                    invalid.push(c);
                }
            }
            // Coverage safety net: if the server echoed the bracketed marker
            // but stripped every special char from the segment, the dense
            // batched payload likely tripped a WAF rule that wouldn't fire
            // on per-char probes. Re-probe individually to avoid blanket
            // false-positive "all invalid" classifications that would mute
            // the entire payload set during scanning.
            if valid.is_empty() {
                need_per_char_fallback = true;
            }
        }
        None => {
            // No reflected segment — either the request failed or the
            // server didn't echo the markers. Mark all chars invalid (same
            // as the legacy per-char path's failure behavior).
            invalid.extend_from_slice(SPECIAL_PROBE_CHARS);
        }
    }

    if need_per_char_fallback {
        valid.clear();
        invalid.clear();
        let mut handles = Vec::new();
        let valid_specials = Arc::new(Mutex::new(Vec::<char>::new()));
        let invalid_specials = Arc::new(Mutex::new(Vec::<char>::new()));
        for &c in SPECIAL_PROBE_CHARS {
            let sem = semaphore.clone();
            let client_clone = client.clone();
            let target_clone = target.clone();
            let param_clone = param.clone();
            let valid_ref = valid_specials.clone();
            let invalid_ref = invalid_specials.clone();
            handles.push(tokio::spawn(async move {
                let probe = format!(
                    "{}{}{}",
                    crate::scanning::markers::open_marker(),
                    c,
                    crate::scanning::markers::close_marker()
                );
                let pp = crate::encoding::pre_encoding::apply_param_encoding(&probe, &param_clone);
                let _permit = sem.acquire().await.expect("acquire semaphore permit");
                let resp =
                    send_probe_request_for_param(&client_clone, &target_clone, &param_clone, &pp)
                        .await;
                let ok = resp
                    .as_deref()
                    .and_then(extract_reflected_segment)
                    .map(|seg| char_reflected_in_segment(seg, c))
                    .unwrap_or(false);
                if ok {
                    valid_ref.lock().await.push(c);
                } else {
                    invalid_ref.lock().await.push(c);
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        valid = valid_specials.lock().await.clone();
        invalid = invalid_specials.lock().await.clone();
    }

    let iv = invalid.clone();
    param.valid_specials = Some(valid);
    param.invalid_specials = Some(invalid);

    // If '<' is invalid and no pre_encoding is set, try double/triple URL encoding
    // to detect servers that multi-decode input (e.g. double URL decode).
    // Skip when a pipeline is already set — the nested encoding is fixed by
    // structure inference and would clash with extra URL-decode rounds.
    if param.pre_encoding.is_none()
        && param.pre_encoding_pipeline.is_none()
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
    // Mining can push the same `(name, location)` slot again — most
    // commonly when DOM mining surfaces a param name that the query /
    // form / header discovery already registered. Run the collapse
    // pass here too so by the time payload generation reads
    // `target.reflection_params` every wire slot is unique. (The
    // earlier collapse inside `check_discovery` keeps internal
    // bookkeeping clean before mining starts; this one catches new
    // duplicates introduced by mining.)
    {
        let mut guard = reflection_params.lock().await;
        crate::parameter_analysis::discovery::dedupe_reflection_params(&mut guard);
    }
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

    // Logging parameter analysis (stderr). When an indicatif spinner is active,
    // route through `pb.println` so the redraw doesn't shred each log line.
    if !args.silence {
        for p in &target.reflection_params {
            let valid = p
                .valid_specials
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
            let invalid = p
                .invalid_specials
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| v.iter().collect::<String>());
            let line = format!(
                "[param-analysis] name={} type={:?} reflected=true context={:?} valid_specials=\"{}\" invalid_specials=\"{}\"",
                p.name, p.location, p.injection_context, valid, invalid
            );
            if let Some(ref pb) = pb {
                pb.println(line);
            } else {
                eprintln!("{}", line);
            }
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
mod tests;
