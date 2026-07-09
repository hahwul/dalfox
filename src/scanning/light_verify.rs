use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use reqwest::Client;

/// Lightweight (non-headless) verification for DOM-XSS candidates.
/// Heuristics:
/// - Build injected URL with provided payload and fetch once.
/// - If Content-Type is HTML-ish and response contains the raw payload, mark verified.
/// - Else, if response contains the class marker and a matching element exists, mark verified.
/// - Else, if CSP likely blocks inline handlers ('unsafe-inline' missing), add note.
///
/// Returns: (verified, response_text, note)
pub async fn verify_dom_xss_light(
    target: &Target,
    param: &Param,
    payload: &str,
) -> (bool, Option<String>, Option<String>) {
    let client = target.build_client_or_default();
    verify_dom_xss_light_with_client(&client, target, param, payload).await
}

pub async fn verify_dom_xss_light_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
) -> (bool, Option<String>, Option<String>) {
    let default_method = target.parse_method();
    let body_method =
        crate::scanning::url_inject::body_location_method_for_param(&target.method, param);
    let request = match param.location {
        Location::Header => {
            let parsed_url = target.url.clone();
            let rb = crate::utils::build_request(
                client,
                target,
                default_method,
                parsed_url,
                target.data.clone(),
            );
            crate::utils::apply_header_overrides(rb, &[(param.name.clone(), payload.to_string())])
        }
        Location::Body => {
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let body = if let Some(ref data) = target.data {
                let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(data.as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                let mut found = false;
                for pair in &mut pairs {
                    if pair.0 == param.name {
                        pair.1 = payload.to_string();
                        found = true;
                        break;
                    }
                }
                if !found {
                    pairs.push((param.name.clone(), payload.to_string()));
                }
                Some(
                    url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(&pairs)
                        .finish(),
                )
            } else {
                Some(format!(
                    "{}={}",
                    urlencoding::encode(&param.name),
                    urlencoding::encode(payload)
                ))
            };
            crate::utils::build_request(client, target, body_method, parsed_url, body)
        }
        Location::JsonBody => {
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let body = if let Some(ref data) = target.data {
                if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(obj) = json_val.as_object_mut() {
                        obj.insert(
                            param.name.clone(),
                            serde_json::Value::String(payload.to_string()),
                        );
                    }
                    Some(serde_json::to_string(&json_val).unwrap_or_else(|_| data.clone()))
                } else {
                    Some(data.replace(&param.value, payload))
                }
            } else {
                Some(serde_json::json!({ &param.name: payload }).to_string())
            };
            let rb = crate::utils::build_request(client, target, body_method, parsed_url, body);
            rb.header("Content-Type", "application/json")
        }
        Location::MultipartBody => {
            let parsed_url = param
                .form_action_url
                .as_ref()
                .and_then(|u| url::Url::parse(u).ok())
                .unwrap_or_else(|| target.url.clone());
            let mut form = reqwest::multipart::Form::new();
            if let Some(ref data) = target.data {
                for pair in data.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let k = urlencoding::decode(k)
                            .unwrap_or(std::borrow::Cow::Borrowed(k))
                            .to_string();
                        let v = urlencoding::decode(v)
                            .unwrap_or(std::borrow::Cow::Borrowed(v))
                            .to_string();
                        if k == param.name {
                            form = form.text(k, payload.to_string());
                        } else {
                            form = form.text(k, v);
                        }
                    }
                }
            } else {
                form = form.text(param.name.clone(), payload.to_string());
            }
            crate::utils::build_request(client, target, body_method, parsed_url, None)
                .multipart(form)
        }
        _ => {
            // GET form discovery sets form_action_url; light-verify must
            // follow it to the action endpoint — otherwise the reflection
            // we're confirming lives on a different URL.
            let base_url = crate::scanning::url_inject::effective_query_base(&target.url, param);
            let inject_url =
                crate::scanning::url_inject::build_injected_url(&base_url, param, payload);
            let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| base_url.clone());
            crate::utils::build_request(
                client,
                target,
                default_method,
                parsed_url,
                target.data.clone(),
            )
        }
    };

    let mut note: Option<String> = None;
    // Honor --rate-limit on this verification re-request without changing the
    // historical request tally (this path intentionally does not tick).
    crate::rate_limit_acquire().await;
    if let Ok(resp) = request.send().await {
        // Browsers do not render the body of a 3xx response, so any apparent
        // reflection/marker evidence inside that body cannot be exploited.
        // Skip body-based verification entirely on redirects — `Location`
        // header inspection is handled by `check_dom_verification`'s
        // `check_redirect_location` and does not belong here.
        if resp.status().is_redirection() {
            return (
                false,
                None,
                Some("3xx response — DOM verify skipped".to_string()),
            );
        }
        // Extract needed header values without cloning the entire HeaderMap
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        if let Ok(text) = crate::utils::http::read_body(resp).await {
            // 1) Payload reflection present after normalization
            if crate::utils::is_htmlish_content_type(&ct)
                && crate::scanning::check_reflection::classify_reflection(&text, payload).is_some()
            {
                if crate::scanning::check_dom_verification::has_marker_evidence(payload, &text) {
                    return (true, Some(text), Some("marker-reflected".to_string()));
                }
                note = Some("payload reflection without marker evidence".to_string());
            }
            // 2) Marker element present
            if crate::utils::is_htmlish_content_type(&ct)
                && crate::scanning::check_dom_verification::has_marker_evidence(payload, &text)
            {
                return (true, Some(text), Some("marker element present".to_string()));
            }
            // 3) CSP hint
            if let Some(cspv) = csp {
                let has_unsafe_inline = cspv
                    .split(';')
                    .any(|d| d.contains("script-src") && d.contains("'unsafe-inline'"));
                if !has_unsafe_inline {
                    note = Some("CSP may block inline handlers".to_string());
                }
            }
            return (false, Some(text), note);
        }
    }
    (false, None, note)
}

#[cfg(test)]
mod tests;
