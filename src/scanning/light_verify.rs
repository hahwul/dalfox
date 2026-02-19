use crate::parameter_analysis::Param;
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());
    let inject_url = crate::scanning::url_inject::build_injected_url(&target.url, param, payload);
    let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| target.url.clone());
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let request =
        crate::utils::build_request(&client, target, method, parsed_url, target.data.clone());

    let mut note: Option<String> = None;
    if let Ok(resp) = request.send().await {
        let headers = resp.headers().clone();
        let ct = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let csp = headers
            .get("Content-Security-Policy")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if let Ok(text) = resp.text().await {
            // 1) Raw payload present
            if crate::utils::is_htmlish_content_type(&ct) && text.contains(payload) {
                if crate::scanning::check_dom_verification::has_marker_evidence(payload, &text) {
                    return (true, Some(text), Some("marker-reflected".to_string()));
                }
                note = Some("raw reflection without marker evidence".to_string());
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
