use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use regex::Regex;
use reqwest::Client;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, sleep};

/// Decode a subset of HTML entities (numeric dec & hex) for reflection normalization.
/// Examples:
///   "&#x3c;script&#x3e;" -> "<script>"
///   "&#60;alert(1)&#62;"  -> "<alert(1)>"
fn decode_html_entities(input: &str) -> String {
    // Match patterns like &#xHH; or &#xHHHH; or &#DDDD;
    // We purposely limit to reasonable length to avoid catastrophic replacements.
    let re = Regex::new(r"&#(x[0-9a-fA-F]{2,6}|[0-9]{2,6});").unwrap();
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.find_iter(input) {
        out.push_str(&input[last..m.start()]);
        let entity = &input[m.start() + 2..m.end() - 1]; // strip &# and ;
        let decoded = if let Some(hex) = entity.strip_prefix('x') {
            u32::from_str_radix(hex, 16)
                .ok()
                .and_then(std::char::from_u32)
                .unwrap_or('\u{FFFD}')
        } else {
            entity
                .parse::<u32>()
                .ok()
                .and_then(std::char::from_u32)
                .unwrap_or('\u{FFFD}')
        };
        out.push(decoded);
        last = m.end();
    }
    out.push_str(&input[last..]);
    out
}

/// Generate normalization variants of a response body to test for reflected payload.
/// Order: raw, html-decoded, url-decoded(html-decoded(raw)) for broader coverage.
fn normalization_variants(raw: &str) -> Vec<String> {
    let html_dec = decode_html_entities(raw);
    let url_dec_once = urlencoding::decode(raw)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| raw.to_string());
    let url_dec_html_dec = urlencoding::decode(&html_dec)
        .map(|s| s.to_string())
        .unwrap_or(html_dec.clone());
    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for v in [raw.to_string(), html_dec, url_dec_once, url_dec_html_dec] {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

/// Determine if payload is reflected in any normalization variant.
fn is_payload_reflected(resp_text: &str, payload: &str) -> bool {
    // Direct match first (fast path)
    if resp_text.contains(payload) {
        return true;
    }
    // Try normalization variants
    for variant in normalization_variants(resp_text) {
        if variant.contains(payload) {
            return true;
        }
    }
    false
}

pub async fn check_reflection(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> bool {
    if args.skip_xss_scanning {
        return false;
    }
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    // Build URL or body based on param location for injection (refactored to shared helper)
    let inject_url = crate::scanning::url_inject::build_injected_url(&target.url, param, payload);

    // Send injection request (centralized builder)
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| target.url.clone());
    let inject_request =
        crate::utils::build_request(&client, target, method, parsed_url, target.data.clone());

    // Send the injection request
    let inject_resp = inject_request.send().await;
    crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    // For Stored XSS, check reflection on sxss_url
    if args.sxss {
        if let Some(sxss_url_str) = &args.sxss_url {
            if let Ok(sxss_url) = url::Url::parse(sxss_url_str) {
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(&client, target, method, sxss_url, None);

                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Ok(resp) = check_request.send().await {
                    if let Ok(text) = resp.text().await {
                        if is_payload_reflected(&text, payload) {
                            return true;
                        }
                    }
                }
            }
        }
    } else {
        // Normal reflection check
        if let Ok(resp) = inject_resp {
            if let Ok(text) = resp.text().await {
                if is_payload_reflected(&text, payload) {
                    return true;
                }
            }
        }
    }

    false
}

pub async fn check_reflection_with_response(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    // Build URL or body based on param location for injection (refactored to shared helper)
    let inject_url = crate::scanning::url_inject::build_injected_url(&target.url, param, payload);

    // Send injection request (centralized builder)
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let parsed_url = url::Url::parse(&inject_url).unwrap_or_else(|_| target.url.clone());
    let inject_request =
        crate::utils::build_request(&client, target, method, parsed_url, target.data.clone());

    // Send the injection request
    let inject_resp = inject_request.send().await;
    crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    // For Stored XSS, check reflection on sxss_url
    if args.sxss {
        if let Some(sxss_url_str) = &args.sxss_url {
            if let Ok(sxss_url) = url::Url::parse(sxss_url_str) {
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(&client, target, method, sxss_url, None);

                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Ok(resp) = check_request.send().await {
                    if let Ok(text) = resp.text().await {
                        if is_payload_reflected(&text, payload) {
                            return (true, Some(text));
                        } else {
                            return (false, Some(text));
                        }
                    }
                }
            }
        }
    } else {
        // Normal reflection check
        if let Ok(resp) = inject_resp {
            if let Ok(text) = resp.text().await {
                if is_payload_reflected(&text, payload) {
                    return (true, Some(text));
                } else {
                    return (false, Some(text));
                }
            }
        }
    }

    (false, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::parse_target;

    #[tokio::test]
    async fn test_check_reflection_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = Param {
            name: "q".to_string(),
            value: "1".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };
        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
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
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };
        let res = check_reflection(&target, &param, "PAY", &args).await;
        assert!(
            !res,
            "should early-return false when skip_xss_scanning=true"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = Param {
            name: "q".to_string(),
            value: "1".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };
        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
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
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };
        let res = check_reflection_with_response(&target, &param, "PAY", &args).await;
        assert_eq!(
            res,
            (false, None),
            "should early-return (false, None) when skip_xss_scanning=true"
        );
    }

    #[test]
    fn test_decode_html_entities_basic() {
        let s = "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;";
        let d = decode_html_entities(s);
        assert!(d.contains("<script>"));
        assert!(d.contains("</script>"));
    }

    #[test]
    fn test_normalization_variants_dedup() {
        let raw = "Hello";
        let vars = normalization_variants(raw);
        assert!(!vars.is_empty());
        assert_eq!(vars.iter().filter(|v| *v == "Hello").count(), 1);
    }

    #[test]
    fn test_is_payload_reflected_html_encoded() {
        let payload = "<script>alert(1)</script>";
        let resp = "prefix &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e; suffix";
        assert!(is_payload_reflected(resp, payload));
    }

    #[test]
    fn test_is_payload_reflected_url_encoded() {
        let payload = "<img src=x onerror=alert(1)>";
        let encoded = urlencoding::encode(payload).to_string();
        let resp = format!("ok {} end", encoded);
        assert!(is_payload_reflected(&resp, payload));
    }

    #[test]
    fn test_is_payload_reflected_negative() {
        let payload = "<svg/onload=alert(1)>";
        let resp = "benign content without the thing";
        assert!(!is_payload_reflected(resp, payload));
    }
}
