use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use regex::Regex;
use reqwest::Client;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, sleep};

static ENTITY_REGEX: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectionKind {
    Raw,
    HtmlEntityDecoded,
    UrlDecoded,
    HtmlThenUrlDecoded,
}

/// Decode a subset of HTML entities (numeric dec & hex) for reflection normalization.
/// Examples:
///   "&#x3c;script&#x3e;" -> "<script>"
///   "&#60;alert(1)&#62;"  -> "<alert(1)>"
fn decode_html_entities(input: &str) -> String {
    // Match patterns like &#xHH; or &#xHHHH; or &#DDDD; (hex 'x' is case-insensitive)
    // We purposely limit to reasonable length to avoid catastrophic replacements.
    let re =
        ENTITY_REGEX.get_or_init(|| Regex::new(r"&#([xX][0-9a-fA-F]{2,6}|[0-9]{2,6});").unwrap());
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.find_iter(input) {
        out.push_str(&input[last..m.start()]);
        let entity = &input[m.start() + 2..m.end() - 1]; // strip &# and ;
        let decoded = if entity.starts_with('x') || entity.starts_with('X') {
            let hex = &entity[1..];
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

    // Handle a minimal set of named entities commonly encountered in XSS contexts.
    // This is intentionally small to avoid unexpected transformations.
    let mut named = out;
    named = named.replace("&lt;", "<");
    named = named.replace("&gt;", ">");
    named = named.replace("&amp;", "&");
    named = named.replace("&quot;", "\"");
    named = named.replace("&apos;", "'");
    named
}

/// Determine if payload is reflected in any normalization variant.
fn classify_reflection(resp_text: &str, payload: &str) -> Option<ReflectionKind> {
    // Direct match first (fast path)
    if resp_text.contains(payload) {
        return Some(ReflectionKind::Raw);
    }

    let html_dec = decode_html_entities(resp_text);
    if html_dec.contains(payload) {
        return Some(ReflectionKind::HtmlEntityDecoded);
    }

    // Check URL decoded version of raw
    if let Ok(url_dec) = urlencoding::decode(resp_text) {
        if url_dec != resp_text && url_dec.contains(payload) {
            return Some(ReflectionKind::UrlDecoded);
        }
    }

    // Check URL decoded version of HTML decoded
    if let Ok(url_dec_html) = urlencoding::decode(&html_dec) {
        if url_dec_html != html_dec && url_dec_html.contains(payload) {
            return Some(ReflectionKind::HtmlThenUrlDecoded);
        }
    }

    None
}

async fn fetch_injection_response(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> Option<String> {
    if args.skip_xss_scanning {
        return None;
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
                    return resp.text().await.ok();
                }
            }
        }
        None
    } else {
        // Normal reflection check
        if let Ok(resp) = inject_resp {
            resp.text().await.ok()
        } else {
            None
        }
    }
}

pub async fn check_reflection(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> bool {
    if let Some(text) = fetch_injection_response(target, param, payload, args).await {
        classify_reflection(&text, payload).is_some()
    } else {
        false
    }
}

pub async fn check_reflection_with_response(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    if let Some(text) = fetch_injection_response(target, param, payload, args).await {
        let kind = classify_reflection(&text, payload);
        (kind, Some(text))
    } else {
        (None, None)
    }
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
            (None, None),
            "should early-return (None, None) when skip_xss_scanning=true"
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
    fn test_decode_html_entities_uppercase_hex_x() {
        let s = "&#X3C;img src=x onerror=alert(1)&#X3E;";
        let d = decode_html_entities(s);
        assert!(d.contains("<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn test_decode_html_entities_named_common() {
        let s = "&lt;svg onload=alert(1)&gt; &amp; &quot; &apos;";
        let d = decode_html_entities(s);
        assert!(d.contains("<svg onload=alert(1)>"));
        assert!(d.contains("&"));
        assert!(d.contains("\""));
        assert!(d.contains("'"));
    }

    #[test]
    fn test_is_payload_reflected_html_encoded() {
        let payload = "<script>alert(1)</script>";
        let resp = "prefix &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e; suffix";
        assert_eq!(classify_reflection(resp, payload), Some(ReflectionKind::HtmlEntityDecoded));
    }

    #[test]
    fn test_is_payload_reflected_url_encoded() {
        let payload = "<img src=x onerror=alert(1)>";
        let encoded = urlencoding::encode(payload).to_string();
        let resp = format!("ok {} end", encoded);
        assert_eq!(classify_reflection(&resp, payload), Some(ReflectionKind::UrlDecoded));
    }

    #[test]
    fn test_is_payload_reflected_double_layer_percent_entity_then_url() {
        // Server returns percent sign as HTML-entity, which then precedes URL-encoded payload
        let payload = "<script>alert(1)</script>";
        // Build a string like: &#37;3Cscript%3Ealert(1)%3C%2Fscript%3E
        let url_once = urlencoding::encode(payload).to_string();
        let resp = url_once.replace("%", "&#37;");
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::HtmlThenUrlDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_negative() {
        let payload = "<svg/onload=alert(1)>";
        let resp = "benign content without the thing";
        assert_eq!(classify_reflection(resp, payload), None);
    }
}
