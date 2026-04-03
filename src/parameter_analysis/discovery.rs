//! # Stage 1: Discovery
//!
//! Identifies which parameters reflect user input in the HTTP response.
//!
//! **Input:** `Target` (URL, method, headers, cookies) + `ScanArgs` flags.
//!
//! **Output:** Appends `Param` entries to the shared `reflection_params` list.
//! Each `Param` carries:
//! - `name`, `value`, `location` (Query/Body/Header/Path/Fragment)
//! - `valid_specials` / `invalid_specials` — **naive** classification based on
//!   whether the character already appears in the response body (not yet
//!   actively probed).
//! - `injection_context` — **naive** guess from surrounding HTML/JS context.
//! - `pre_encoding` — `None` at this stage (set later in Stage 3).
//!
//! **Side effects:** HTTP requests (one per parameter per location type).
//! Respects `--skip-discovery`, `--skip-reflection-header`, etc.

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{Location, Param, classify_special_chars, detect_injection_context};
use crate::scanning::url_inject::build_injected_url;
use crate::target_parser::Target;
use scraper;
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};

use crate::scanning::selectors;

/// Cached regex for detecting JSON.stringify patterns in JavaScript source.
fn json_stringify_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"JSON\.stringify\(\s*\{([^}]+)\}\s*\)"#)
            .expect("json_stringify_regex is a valid pattern")
    })
}

/// Cached regex for extracting key names from JSON-like object literals.
fn json_key_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"["']?(\w+)["']?\s*:"#)
            .expect("json_key_regex is a valid pattern")
    })
}

pub async fn check_discovery(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    if !args.skip_discovery {
        check_query_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        if !args.skip_reflection_header {
            check_header_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
        if !args.skip_reflection_cookie {
            check_cookie_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
        // Path discovery (respects --skip-reflection-path)
        if !args.skip_reflection_path {
            check_path_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
        // Form discovery: parse HTML forms and test POST parameters
        check_form_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        // Fragment discovery: extract params from URL hash fragments (client-side only)
        check_fragment_discovery(target, reflection_params.clone()).await;
    }
    target.reflection_params = reflection_params.lock().await.clone();
}

/// Extract parameters from URL hash fragments and register them for scanning.
///
/// Handles two formats:
/// - SPA routing: `#/path?key=value&key2=value2`
/// - Simple fragments: `#key=value&key2=value2`
///
/// No HTTP requests are needed because fragments are client-side only (never sent to the server).
/// These params are relevant for DOM XSS detection where JavaScript reads `location.hash`.
pub async fn check_fragment_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
) {
    let frag = match target.url.fragment() {
        Some(f) if !f.is_empty() => f,
        _ => return,
    };

    // Split fragment into optional route prefix and query portion.
    // e.g. "/redir?url=value" => route prefix "/redir", query "url=value"
    // e.g. "key=value" => route prefix "", query "key=value"
    let query_part = if let Some(q_pos) = frag.find('?') {
        &frag[q_pos + 1..]
    } else {
        frag
    };

    if query_part.is_empty() {
        return;
    }

    let mut params = reflection_params.lock().await;
    for pair in query_part.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = if let Some((k, v)) = pair.split_once('=') {
            (k.to_string(), v.to_string())
        } else {
            (pair.to_string(), String::new())
        };
        if key.is_empty() {
            continue;
        }
        // Avoid duplicates
        if params.iter().any(|p| p.name == key && p.location == Location::Fragment) {
            continue;
        }
        params.push(Param {
            name: key,
            value,
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        });
    }
}

pub async fn check_query_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::open_marker();

    let mut handles = vec![];

    // Check existing query params for reflection
    for (name, value) in target.url.query_pairs() {
        let tmp_param = Param {
            name: name.to_string(),
            value: String::new(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let url_str = build_injected_url(&target.url, &tmp_param, test_value);
        let url = url::Url::parse(&url_str).expect("build_injected_url produces valid URL");
        let client_clone = client.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let name = name.to_string();
        let value = value.to_string();
        let target_clone = arc_target.clone();

        // Spawn a task that returns Option<Param> instead of locking per discovery.
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
            let m = parsed_method;
            let request =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await {
                // Check for redirect reflection: if the response is a 3xx redirect,
                // the Location header may contain the reflected marker value.
                let is_redirect = resp.status().is_redirection();
                let location_reflection = if is_redirect {
                    resp.headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(|loc| loc.contains(test_value))
                        .unwrap_or(false)
                } else {
                    false
                };

                if location_reflection {
                    // Redirect context: marker reflected in Location header.
                    // Use Attribute context since the value is placed in a URI attribute.
                    discovered = Some(Param {
                        name,
                        value,
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(
                            crate::parameter_analysis::InjectionContext::AttributeUrl(None),
                        ),
                        valid_specials: None,
                        invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                    });
                } else if let Ok(text) = resp.text().await {
                    if text.contains(test_value) {
                        let (valid, invalid) = classify_special_chars(&text);
                        discovered = Some(Param {
                            name,
                            value,
                            location: crate::parameter_analysis::Location::Query,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            form_action_url: None,
                            form_origin_url: None,
                        });
                    }
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect results to reduce mutex contention
    let mut batch: Vec<Param> = Vec::new();
    let mut discovered_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for handle in handles {
        if let Ok(opt_param) = handle.await
            && let Some(p) = opt_param
        {
            discovered_names.insert(p.name.clone());
            batch.push(p);
        }
    }

    // Encoding probe: for params not yet discovered, try base64-encoded markers
    let encoding_probes = crate::encoding::pre_encoding::encoding_probes();
    for (name, value) in target.url.query_pairs() {
        let name = name.to_string();
        if discovered_names.contains(&name) {
            continue;
        }
        for (enc_type, encode_fn) in encoding_probes {
            let enc_name = enc_type.as_str();
            let encoded_marker = encode_fn(test_value);
            let mut url = target.url.clone();
            url.query_pairs_mut().clear();
            for (n, v) in target.url.query_pairs() {
                if n.as_ref() == name.as_str() {
                    url.query_pairs_mut().append_pair(&n, &encoded_marker);
                } else {
                    url.query_pairs_mut().append_pair(&n, &v);
                }
            }
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request = crate::utils::build_request(
                &client, target, m, url, target.data.clone(),
            );
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                // For pre-encoded params (base64/2base64), skip special char
                // classification. The encoding bypasses HTTP-level filtering,
                // and leaving specials as None ensures all payload types are tried
                // without adaptive filtering that would incorrectly block payloads.
                discovered_names.insert(name.clone());
                batch.push(Param {
                    name: name.clone(),
                    value: value.to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: Some(enc_name.to_string()),
                    form_action_url: None,
                    form_origin_url: None,
                });
                break; // Found working encoding, no need to try more
            }
            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }

    // Letter-stripped reflection probe: for params not yet discovered,
    // send a purely numeric marker to detect filters that strip a-zA-Z.
    // This catches injection points like `<script>#{input.gsub(/[a-zA-Z]/, "")}</script>`.
    {
        let numeric_marker = "90197752"; // unique numeric-only probe
        for (name, value) in target.url.query_pairs() {
            let name = name.to_string();
            if discovered_names.contains(&name) {
                continue;
            }
            let tmp_param = Param {
                name: name.clone(),
                value: String::new(),
                location: Location::Query,
                injection_context: None,
                valid_specials: None,
                invalid_specials: None,
                pre_encoding: None,
                form_action_url: None,
                form_origin_url: None,
            };
            let url_str = build_injected_url(&target.url, &tmp_param, numeric_marker);
            let url = url::Url::parse(&url_str).expect("valid URL");
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request =
                crate::utils::build_request(&client, target, m, url, target.data.clone());
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(numeric_marker)
            {
                discovered_names.insert(name.clone());
                batch.push(Param {
                    name: name.clone(),
                    value: value.to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(
                        crate::parameter_analysis::mining::detect_injection_context_with_marker(
                            &text,
                            numeric_marker,
                        )
                    ),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }

    // Parameter key reflection: test if parameter NAMES are reflected in the
    // response body (e.g., ?<script>=a shows key in output).  We append an
    // extra query parameter whose key is the marker and check if the marker
    // appears in the response.
    {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(test_value, "1");
        let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
        let m = target.parse_method();
        let request =
            crate::utils::build_request(&client, target, m, url, target.data.clone());
        crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(resp) = request.send().await
            && let Ok(text) = resp.text().await
            && text.contains(test_value)
        {
            let (valid, invalid) = classify_special_chars(&text);
            batch.push(Param {
                name: "__dalfox_key_inject__".to_string(),
                value: String::new(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: Some(detect_injection_context(&text)),
                valid_specials: Some(valid),
                invalid_specials: Some(invalid),
                pre_encoding: None,
                form_action_url: None,
                form_origin_url: None,
            });
        }
        if target.delay > 0 {
            sleep(Duration::from_millis(target.delay)).await;
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Common HTTP headers to proactively test for reflection,
/// even when they are not explicitly provided by the user.
const COMMON_PROBE_HEADERS: &[&str] = &[
    "Referer",
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Authorization",
    "Cookie",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Custom-Header",
    "X-Debug",
    "Origin",
];

pub async fn check_header_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::open_marker();

    let mut handles = vec![];

    // Build a set of header names to test: explicit headers + common probes
    let mut headers_to_test: Vec<(String, String)> = target
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let existing_names: std::collections::HashSet<String> = headers_to_test
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    for &hdr in COMMON_PROBE_HEADERS {
        if !existing_names.contains(&hdr.to_ascii_lowercase()) {
            headers_to_test.push((hdr.to_string(), String::new()));
        }
    }

    for (header_name, header_value) in &headers_to_test {
        let client_clone = client.clone();
        let url = target.url.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let header_name = header_name.clone();
        let header_value = header_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> to batch reduce mutex contention
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
            let m = parsed_method;
            let base =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            let overrides = vec![(header_name.clone(), test_value.to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: header_name,
                    value: header_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Discover reflections in path segments by replacing each segment with the test marker
pub async fn check_path_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let test_value = crate::scanning::markers::open_marker();
    let path = target.url.path();
    // Split non-empty segments
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return;
    }

    let client = target.build_client_or_default();

    let mut handles = Vec::new();

    let mut new_segments: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
    for (idx, original) in segments.iter().enumerate() {
        let saved = std::mem::replace(&mut new_segments[idx], test_value.to_string());
        let new_path = format!("/{}", new_segments.join("/"));

        let mut new_url = target.url.clone();
        new_url.set_path(&new_path);

        let client_clone = client.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name = format!("path_segment_{}", idx);
        let original_value = original.to_string();

        // Skip if already discovered (e.g., duplicate path pattern)
        {
            let guard = reflection_params.lock().await;
            if guard.iter().any(|p| {
                p.name == param_name && p.location == crate::parameter_analysis::Location::Path
            }) {
                new_segments[idx] = saved;
                continue;
            }
        }

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
            let m = parsed_method;
            let request =
                crate::utils::build_request(&client_clone, &target_clone, m, new_url, data.clone());

            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: param_name,
                    value: original_value,
                    location: crate::parameter_analysis::Location::Path,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
        new_segments[idx] = saved;
    }

    // Batch collect discovered path params
    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(opt) = h.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

pub async fn check_cookie_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::open_marker();

    let mut handles = vec![];

    for (cookie_name, cookie_value) in &target.cookies {
        let client_clone = client.clone();
        let url = target.url.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let cookie_name = cookie_name.clone();
        let cookie_value = cookie_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
            let m = parsed_method;
            // Compose cookie header overriding the probed cookie while preserving others
            let others =
                crate::utils::compose_cookie_header_excluding(&cookies, Some(&cookie_name));
            let cookie_header = match others {
                Some(s) => format!("{}; {}={}", s, cookie_name, test_value),
                None => format!("{}={}", cookie_name, test_value),
            };
            let request = crate::utils::build_request_with_cookie(
                &client_clone,
                &target_clone,
                m,
                url,
                data.clone(),
                Some(cookie_header),
            );
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: cookie_name,
                    value: cookie_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect cookie params
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Discover POST form parameters by parsing HTML forms from the GET response.
pub async fn check_form_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    // Only discover forms when the target doesn't already have POST data
    if target.data.is_some() || target.method.eq_ignore_ascii_case("POST") {
        return;
    }

    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::open_marker();

    // Fetch the page via GET to find forms
    let method = reqwest::Method::GET;
    let request = crate::utils::build_request(&client, target, method, target.url.clone(), None);
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let html = match request.send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => text,
            Err(_) => return,
        },
        Err(_) => return,
    };

    // Parse forms
    let document = scraper::Html::parse_document(&html);
    let form_sel = selectors::form();
    let input_sel = selectors::input_textarea_select();

    let mut batch: Vec<Param> = Vec::new();

    for form in document.select(form_sel) {
        let form_method = form.value().attr("method").unwrap_or("get");
        let is_post = form_method.eq_ignore_ascii_case("post");
        let enctype = form.value().attr("enctype").unwrap_or("");
        let is_multipart = enctype.eq_ignore_ascii_case("multipart/form-data");

        // Resolve form action URL
        let action = form.value().attr("action").unwrap_or("");
        let form_url = if action.is_empty() || action == "#" {
            target.url.clone()
        } else if let Ok(resolved) = target.url.join(action) {
            resolved
        } else {
            continue;
        };

        // Collect form fields
        let mut fields: Vec<(String, String)> = Vec::new();
        for input in form.select(input_sel) {
            let name = input.value().attr("name").unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let value = input.value().attr("value").unwrap_or("").to_string();
            fields.push((name, value));
        }
        if fields.is_empty() {
            continue;
        }

        if is_post && is_multipart {
            // Multipart form: test each field via multipart/form-data POST
            for (field_idx, (field_name, field_value)) in fields.iter().enumerate() {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                let mut form = reqwest::multipart::Form::new();
                for (i, (n, v)) in fields.iter().enumerate() {
                    if i == field_idx {
                        form = form.text(n.clone(), test_value.to_string());
                    } else {
                        form = form.text(n.clone(), v.clone());
                    }
                }
                let rb = crate::utils::build_request(
                    &client,
                    target,
                    reqwest::Method::POST,
                    form_url.clone(),
                    None,
                )
                .multipart(form);
                crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && text.contains(test_value)
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::MultipartBody,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        } else if is_post {
            // Pre-encode field names and values once for form body construction
            let encoded_fields: Vec<(String, String)> = fields
                .iter()
                .map(|(n, v)| {
                    let enc_n =
                        url::form_urlencoded::byte_serialize(n.as_bytes()).collect::<String>();
                    let enc_v =
                        url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                    (enc_n, enc_v)
                })
                .collect();
            let encoded_test_value: String =
                url::form_urlencoded::byte_serialize(test_value.as_bytes()).collect();

            // Test each field for reflection via POST
            for (field_idx, (field_name, field_value)) in fields.iter().enumerate() {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                // Build body by joining pre-encoded pairs, substituting the target field
                let body = encoded_fields
                    .iter()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, (enc_n, enc_v))| {
                        if !acc.is_empty() { acc.push('&'); }
                        acc.push_str(enc_n);
                        acc.push('=');
                        if i == field_idx {
                            acc.push_str(&encoded_test_value);
                        } else {
                            acc.push_str(enc_v);
                        }
                        acc
                    });
                let m = reqwest::Method::POST;
                let rb =
                    crate::utils::build_request(&client, target, m, form_url.clone(), Some(body));
                let rb = crate::utils::apply_header_overrides(
                    rb,
                    &[(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                );
                crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && text.contains(test_value)
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::Body,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        } else {
            // GET form: test each field as query parameter on the form action URL
            for (field_name, field_value) in &fields {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                let mut test_url = form_url.clone();
                // Build query: set all fields, replace target field with test value
                {
                    let mut pairs = test_url.query_pairs_mut();
                    pairs.clear();
                    for (n, v) in &fields {
                        if n == field_name {
                            pairs.append_pair(n, test_value);
                        } else {
                            pairs.append_pair(n, v);
                        }
                    }
                }
                let m = reqwest::Method::GET;
                let rb =
                    crate::utils::build_request(&client, target, m, test_url.clone(), None);
                crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && text.contains(test_value)
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        }

        // Also try JSON body if the form has a single text-like field
        if fields.len() <= 3 {
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let json_body = {
                let mut map = serde_json::Map::new();
                for (n, _) in &fields {
                    map.insert(n.clone(), serde_json::Value::String(test_value.to_string()));
                }
                serde_json::Value::Object(map).to_string()
            };
            let m = reqwest::Method::POST;
            let rb = crate::utils::build_request(
                &client,
                target,
                m,
                form_url.clone(),
                Some(json_body),
            );
            let rb = crate::utils::apply_header_overrides(
                rb,
                &[("Content-Type".to_string(), "application/json".to_string())],
            );
            crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(resp) = rb.send().await
                && let Ok(text) = resp.text().await
                && text.contains(test_value)
            {
                let (valid, invalid) = classify_special_chars(&text);
                for (field_name, field_value) in &fields {
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::JsonBody,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid.clone()),
                        invalid_specials: Some(invalid.clone()),
                    pre_encoding: None,
                    form_action_url: Some(form_url.to_string()),
                    form_origin_url: Some(target.url.to_string()),
                    });
                }
            }
        }
    }

    // Detect inline JSON object hints in page body (e.g., {"name":"value"} in text or code).
    // This catches cases where the page documents a JSON API without using JSON.stringify.
    {
        static JSON_INLINE_RE: OnceLock<regex::Regex> = OnceLock::new();
        let inline_re = JSON_INLINE_RE.get_or_init(|| {
            regex::Regex::new(r#"\{["\s]*"(\w+)"["\s]*:["\s]*"[^"]*"[^}]*\}"#)
                .expect("inline JSON regex is valid")
        });
        for caps in inline_re.captures_iter(&html) {
            let full = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            // Try to parse as JSON
            if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(full) {
                let keys: Vec<String> = obj.keys().cloned().collect();
                if keys.is_empty() { continue; }
                // Skip if all keys are already known
                let all_known = {
                    let guard = reflection_params.lock().await;
                    keys.iter().all(|k| guard.iter().any(|p| p.name == *k && matches!(p.location, Location::JsonBody)))
                };
                if all_known { continue; }

                for key in &keys {
                    let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                    let mut map = serde_json::Map::new();
                    for (k, v) in &obj {
                        if k == key {
                            map.insert(k.clone(), serde_json::Value::String(test_value.to_string()));
                        } else {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_request(
                        &client, target, m, target.url.clone(), Some(json_body),
                    );
                    let rb = crate::utils::apply_header_overrides(
                        rb,
                        &[("Content-Type".to_string(), "application/json".to_string())],
                    );
                    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(resp) = rb.send().await
                        && let Ok(text) = resp.text().await
                        && text.contains(test_value)
                    {
                        let (valid, invalid) = classify_special_chars(&text);
                        batch.push(Param {
                            name: key.clone(),
                            value: "a".to_string(),
                            location: crate::parameter_analysis::Location::JsonBody,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            form_action_url: Some(target.url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                        });
                    }
                    if target.delay > 0 {
                        sleep(Duration::from_millis(target.delay)).await;
                    }
                }
            }
        }
    }

    // Also detect JSON POST endpoints from JavaScript (XHR / fetch with JSON.stringify)
    // Look for patterns like: JSON.stringify({"key":"value",...})
    {
        let re = json_stringify_regex();
        for caps in re.captures_iter(&html) {
            if let Some(inner) = caps.get(1) {
                // Parse key names from the JSON-like object literal
                let key_re = json_key_regex();
                let mut json_fields: Vec<(String, String)> = Vec::new();
                for kcap in key_re.captures_iter(inner.as_str()) {
                    if let Some(k) = kcap.get(1) {
                        json_fields.push((k.as_str().to_string(), "a".to_string()));
                    }
                }
                if json_fields.is_empty() {
                    continue;
                }

                // Try JSON body with each field replaced by test_value
                for (field_name, field_value) in &json_fields {
                    let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                    let mut map = serde_json::Map::new();
                    for (n, v) in &json_fields {
                        if n == field_name {
                            map.insert(n.clone(), serde_json::Value::String(test_value.to_string()));
                        } else {
                            map.insert(n.clone(), serde_json::Value::String(v.clone()));
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_request(
                        &client,
                        target,
                        m,
                        target.url.clone(),
                        Some(json_body),
                    );
                    let rb = crate::utils::apply_header_overrides(
                        rb,
                        &[("Content-Type".to_string(), "application/json".to_string())],
                    );
                    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(resp) = rb.send().await
                        && let Ok(text) = resp.text().await
                        && text.contains(test_value)
                    {
                        let (valid, invalid) = classify_special_chars(&text);
                        batch.push(Param {
                            name: field_name.clone(),
                            value: field_value.clone(),
                            location: crate::parameter_analysis::Location::JsonBody,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            form_action_url: Some(target.url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                        });
                    }
                    if target.delay > 0 {
                        sleep(Duration::from_millis(target.delay)).await;
                    }
                }
            }
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::parse_target;
    use axum::Router;
    use axum::extract::Query;
    use axum::http::{HeaderMap, Uri};
    use axum::routing::any;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};

    fn default_scan_args() -> crate::cmd::scan::ScanArgs {
        crate::cmd::scan::ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![],
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
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            mining_dict_word: None,
            remote_wordlists: vec![],
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
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
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 4,
            max_concurrent_targets: 4,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            remote_payloads: vec![],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
        }
    }

    async fn discovery_reflect_handler(
        Query(params): Query<HashMap<String, String>>,
        headers: HeaderMap,
        uri: Uri,
    ) -> String {
        let mut values: Vec<String> = params.values().cloned().collect();
        values.sort();
        let query_values = values.join(",");
        let header_values: Vec<String> = headers
            .get_all("x-reflect-me")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        let header_value = header_values.join(",");
        let cookie_value = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        format!(
            "path={} query={} header={} cookie={}",
            uri.path(),
            query_values,
            header_value,
            cookie_value
        )
    }

    async fn start_discovery_mock_server() -> SocketAddr {
        let app = Router::new()
            .route("/", any(discovery_reflect_handler))
            .route("/*rest", any(discovery_reflect_handler));

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        sleep(Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn test_check_query_discovery_discovers_reflection_and_extends_batch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect?a=1&b=2", addr)).unwrap();
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_query_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(
            params
                .iter()
                .any(|p| p.name == "a" && p.location == Location::Query)
        );
        assert!(
            params
                .iter()
                .any(|p| p.name == "b" && p.location == Location::Query)
        );
        assert!(params.iter().all(|p| p.valid_specials.is_some()));
        assert!(params.iter().all(|p| p.invalid_specials.is_some()));
    }

    #[tokio::test]
    async fn test_check_header_discovery_discovers_reflected_header() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect?q=1", addr)).unwrap();
        target
            .headers
            .push(("X-Reflect-Me".to_string(), "orig".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_header_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert!(!params.is_empty(), "should discover at least the explicit header");
        let p = params.iter().find(|p| p.name == "X-Reflect-Me").expect("X-Reflect-Me should be discovered");
        assert_eq!(p.value, "orig");
        assert_eq!(p.location, Location::Header);
        assert!(p.injection_context.is_some());
    }

    #[tokio::test]
    async fn test_check_cookie_discovery_single_cookie_branch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "session");
        assert_eq!(params[0].location, Location::Header);
    }

    #[tokio::test]
    async fn test_check_cookie_discovery_multiple_cookies_branch() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));
        target
            .cookies
            .push(("theme".to_string(), "dark".to_string()));
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|p| p.name == "session"));
        assert!(params.iter().any(|p| p.name == "theme"));
    }

    #[tokio::test]
    async fn test_check_path_discovery_discovers_reflected_segments() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/one/two", addr)).unwrap();
        target.delay = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        check_path_discovery(&target, reflection_params.clone(), semaphore).await;

        let params = reflection_params.lock().await.clone();
        assert_eq!(params.len(), 2);
        assert!(
            params
                .iter()
                .any(|p| p.name == "path_segment_0" && p.value == "one")
        );
        assert!(
            params
                .iter()
                .any(|p| p.name == "path_segment_1" && p.value == "two")
        );
        assert!(params.iter().all(|p| p.location == Location::Path));
    }

    #[tokio::test]
    async fn test_check_discovery_skip_discovery_true_keeps_empty() {
        let addr = start_discovery_mock_server().await;
        let mut target = parse_target(&format!("http://{}/a/b?q=1", addr)).unwrap();
        target
            .headers
            .push(("X-Reflect-Me".to_string(), "orig".to_string()));
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));
        let mut args = default_scan_args();
        args.skip_discovery = true;

        check_discovery(&mut target, &args, reflection_params, semaphore).await;
        assert!(target.reflection_params.is_empty());
    }

    #[tokio::test]
    async fn test_check_path_discovery_skips_existing_segment() {
        let target = {
            let mut t = parse_target("https://example.com/only").unwrap();
            t.timeout = 1;
            t
        };

        let reflection_params = Arc::new(Mutex::new(vec![Param {
            name: "path_segment_0".to_string(),
            value: "only".to_string(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        }]));

        let semaphore = Arc::new(Semaphore::new(1));

        let before_len = reflection_params.lock().await.len();
        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        let after_len = reflection_params.lock().await.len();

        assert_eq!(before_len, 1);
        assert_eq!(after_len, 1);
    }

    #[tokio::test]
    async fn test_check_path_discovery_respects_semaphore_single_permit() {
        let target = {
            let mut t = parse_target("https://example.com/").unwrap();
            t.timeout = 1;
            t
        };

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));

        check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_check_discovery_skips_path_when_flag_set() {
        let mut target = parse_target("https://example.com/a/b").unwrap();
        target.timeout = 1;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(Semaphore::new(1));

        let mut args = default_scan_args();
        args.workers = 1;
        args.max_concurrent_targets = 1;
        args.skip_reflection_path = true;

        check_discovery(
            &mut target,
            &args,
            reflection_params.clone(),
            semaphore.clone(),
        )
        .await;
        assert!(reflection_params.lock().await.is_empty());
    }
}
