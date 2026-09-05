//! Discovery surface: form. See the module docs in `mod.rs`.

use super::*;

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
    let test_value = crate::scanning::markers::bracketed_marker();

    // Fetch the page via GET to find forms
    let method = reqwest::Method::GET;
    let request = crate::utils::build_request(&client, target, method, target.url.clone(), None);
    crate::record_outbound_request().await;
    let html = match crate::utils::http::send_counted(request).await {
        Ok(resp) => match crate::utils::http::read_body(resp).await {
            Ok(text) => text,
            Err(_) => return,
        },
        Err(_) => return,
    };

    /// Most fields probed per discovered form. See the truncation site below:
    /// the probing cost is quadratic in the field count, so this bounds what a
    /// single hostile (or generated) page can make a scan spend.
    const MAX_FORM_FIELDS: usize = 200;

    // Fully-owned form descriptor extracted from the HTML. Keeping these as
    // Send-safe `String` / `Url` lets the scraper document get dropped before
    // the async probing loop below, which is a prerequisite for ever moving
    // this function off the current_thread runtime.
    struct FormInfo {
        url: url::Url,
        is_post: bool,
        is_multipart: bool,
        fields: Vec<(String, String)>,
    }

    // Parse forms in a tight scope so `scraper::Html` (which is !Send) never
    // escapes. Collect into `Vec<FormInfo>` before touching any await.
    let forms: Vec<FormInfo> = {
        let document = crate::utils::html::parse_document_bounded(&html);
        let form_sel = selectors::form();
        let input_sel = selectors::input_textarea_select();

        let mut out = Vec::new();
        for form in document.select(form_sel) {
            let form_method = form.value().attr("method").unwrap_or("get");
            let is_post = form_method.eq_ignore_ascii_case("post");
            let enctype = form.value().attr("enctype").unwrap_or("");
            let is_multipart = enctype.eq_ignore_ascii_case("multipart/form-data");

            let action = form.value().attr("action").unwrap_or("");
            let form_url = if action.is_empty() || action == "#" {
                target.url.clone()
            } else if let Ok(resolved) = target.url.join(action) {
                resolved
            } else {
                continue;
            };

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
            // Cap the field list. Probing a form is O(fields²) in work *and* in
            // bytes: each field gets its own request, and each of those
            // requests rebuilds the entire multipart body. A page serving a
            // form with 50 000 inputs therefore costs 50 000 requests carrying
            // ~2.5e9 field copies between them. `MAX_DISCOVERED_PARAMS` bounds
            // the params a scan carries, but only *after* discovery has already
            // paid for them, and only on the server/MCP paths.
            //
            // Note what is capped: the number of fields *probed*, not the field
            // list itself. Truncating `fields` looked equivalent but was not —
            // the same vector builds the submitted body, so a >200-field form
            // would be probed with an incomplete body. Servers reject a form
            // submission missing its required fields, so those probes come back
            // non-reflecting and the form can lose discovery of *every* one of
            // its parameters, not just the ones past the cap.
            if fields.len() > MAX_FORM_FIELDS {
                crate::dbg_log!(
                    "form at {} has {} fields; probing the first {} (all are still submitted)",
                    form_url,
                    fields.len(),
                    MAX_FORM_FIELDS
                );
            }

            out.push(FormInfo {
                url: form_url,
                is_post,
                is_multipart,
                fields,
            });
        }
        out
    };

    let mut batch: Vec<Param> = Vec::new();

    for FormInfo {
        url: form_url,
        is_post,
        is_multipart,
        fields,
    } in forms
    {
        if is_post && is_multipart {
            // Multipart form: test each field via multipart/form-data POST
            for (field_idx, (field_name, field_value)) in
                fields.iter().enumerate().take(MAX_FORM_FIELDS)
            {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                let mut form = reqwest::multipart::Form::new();
                for (i, (n, v)) in fields.iter().enumerate() {
                    if i == field_idx {
                        form = form.text(n.clone(), test_value.to_string());
                    } else {
                        form = form.text(n.clone(), v.clone());
                    }
                }
                let rb = crate::utils::build_body_request_base(
                    &client,
                    target,
                    reqwest::Method::POST,
                    form_url.clone(),
                    None,
                )
                .multipart(form);
                crate::record_outbound_request().await;
                if let Ok(resp) = crate::utils::http::send_counted(rb).await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    batch.push(
                        Param {
                            form_action_url: Some(form_url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            ..Param::new(
                                field_name.clone(),
                                field_value.clone(),
                                crate::parameter_analysis::Location::MultipartBody,
                            )
                        }
                        .with_reflection_analysis(&text),
                    );
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
            for (field_idx, (field_name, field_value)) in
                fields.iter().enumerate().take(MAX_FORM_FIELDS)
            {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                // Build body by joining pre-encoded pairs, substituting the target field
                let body = encoded_fields.iter().enumerate().fold(
                    String::new(),
                    |mut acc, (i, (enc_n, enc_v))| {
                        if !acc.is_empty() {
                            acc.push('&');
                        }
                        acc.push_str(enc_n);
                        acc.push('=');
                        if i == field_idx {
                            acc.push_str(&encoded_test_value);
                        } else {
                            acc.push_str(enc_v);
                        }
                        acc
                    },
                );
                let m = reqwest::Method::POST;
                let rb = crate::utils::build_body_request_base(
                    &client,
                    target,
                    m,
                    form_url.clone(),
                    Some(body),
                );
                let rb = crate::utils::apply_header_overrides(
                    rb,
                    &[(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                );
                crate::record_outbound_request().await;
                if let Ok(resp) = crate::utils::http::send_counted(rb).await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    batch.push(
                        Param {
                            form_action_url: Some(form_url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            ..Param::new(
                                field_name.clone(),
                                field_value.clone(),
                                crate::parameter_analysis::Location::Body,
                            )
                        }
                        .with_reflection_analysis(&text),
                    );
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
                let rb = crate::utils::build_request(&client, target, m, test_url.clone(), None);
                crate::record_outbound_request().await;
                if let Ok(resp) = crate::utils::http::send_counted(rb).await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    batch.push(
                        Param {
                            form_action_url: Some(form_url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            ..Param::new(
                                field_name.clone(),
                                field_value.clone(),
                                crate::parameter_analysis::Location::Query,
                            )
                        }
                        .with_reflection_analysis(&text),
                    );
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
            let rb = crate::utils::build_body_request_base(
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
            crate::record_outbound_request().await;
            if let Ok(resp) = crate::utils::http::send_counted(rb).await
                && let Ok(text) = crate::utils::http::read_body(resp).await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                let analysis = ReflectionAnalysis::of(&text);
                for (field_name, field_value) in &fields {
                    batch.push(
                        Param {
                            form_action_url: Some(form_url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            ..Param::new(
                                field_name.clone(),
                                field_value.clone(),
                                crate::parameter_analysis::Location::JsonBody,
                            )
                        }
                        .with_analysis(&analysis),
                    );
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
            let full = caps.get(0).map_or("", |m| m.as_str());
            // Try to parse as JSON
            if let Ok(serde_json::Value::Object(obj)) =
                serde_json::from_str::<serde_json::Value>(full)
            {
                let keys: Vec<String> = obj.keys().cloned().collect();
                if keys.is_empty() {
                    continue;
                }
                // Skip if all keys are already known
                let all_known = {
                    let guard = reflection_params.lock().await;
                    keys.iter().all(|k| {
                        guard
                            .iter()
                            .any(|p| p.name == *k && matches!(p.location, Location::JsonBody))
                    })
                };
                if all_known {
                    continue;
                }

                for key in &keys {
                    let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                    let mut map = serde_json::Map::new();
                    for (k, v) in &obj {
                        if k == key {
                            map.insert(
                                k.clone(),
                                serde_json::Value::String(test_value.to_string()),
                            );
                        } else {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_body_request_base(
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
                    crate::record_outbound_request().await;
                    if let Ok(resp) = crate::utils::http::send_counted(rb).await
                        && let Ok(text) = crate::utils::http::read_body(resp).await
                        && crate::scanning::markers::classify_probe_reflection(&text).detected()
                    {
                        batch.push(
                            Param {
                                form_action_url: Some(target.url.to_string()),
                                form_origin_url: Some(target.url.to_string()),
                                ..Param::new(
                                    key.clone(),
                                    "a".to_string(),
                                    crate::parameter_analysis::Location::JsonBody,
                                )
                            }
                            .with_reflection_analysis(&text),
                        );
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
                            map.insert(
                                n.clone(),
                                serde_json::Value::String(test_value.to_string()),
                            );
                        } else {
                            map.insert(n.clone(), serde_json::Value::String(v.clone()));
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_body_request_base(
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
                    crate::record_outbound_request().await;
                    if let Ok(resp) = crate::utils::http::send_counted(rb).await
                        && let Ok(text) = crate::utils::http::read_body(resp).await
                        && crate::scanning::markers::classify_probe_reflection(&text).detected()
                    {
                        batch.push(
                            Param {
                                form_action_url: Some(target.url.to_string()),
                                form_origin_url: Some(target.url.to_string()),
                                ..Param::new(
                                    field_name.clone(),
                                    field_value.clone(),
                                    crate::parameter_analysis::Location::JsonBody,
                                )
                            }
                            .with_reflection_analysis(&text),
                        );
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
