use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use regex::Regex;
use reqwest::Client;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, sleep};

/// Safe HTML tags where reflected content cannot execute scripts.
const SAFE_TAGS: &[&str] = &["textarea", "noscript", "style", "xmp", "plaintext", "title"];

/// Check whether *all* occurrences of `payload` in `html` fall inside safe tags
/// (textarea, noscript, style, xmp, plaintext, title).  If the payload appears
/// at least once outside a safe tag, returns `false`.
///
/// Uses a simple tag-stack approach on the raw HTML for reliability, because DOM
/// parsers like `scraper` may normalize text content inside raw-text elements.
fn is_in_safe_context(html: &str, payload: &str) -> bool {
    // Quick check: payload must be present
    if !html.contains(payload) {
        return true; // nothing reflected, vacuously safe
    }

    let lower_html = html.to_lowercase();

    // Build safe-context ranges by scanning for opening/closing safe tags
    let mut safe_ranges: Vec<(usize, usize)> = Vec::new();
    for &tag in SAFE_TAGS {
        let open_pattern = format!("<{}", tag);
        let close_pattern = format!("</{}>", tag);
        let mut search_pos = 0;
        while let Some(open_start) = lower_html[search_pos..].find(&open_pattern) {
            let abs_open = search_pos + open_start;
            // Find the end of the opening tag '>'
            if let Some(tag_end_offset) = html[abs_open..].find('>') {
                let content_start = abs_open + tag_end_offset + 1;
                // Find closing tag
                if let Some(close_offset) = lower_html[content_start..].find(&close_pattern) {
                    let content_end = content_start + close_offset;
                    safe_ranges.push((content_start, content_end));
                    search_pos = content_end + close_pattern.len();
                } else {
                    // No closing tag found, rest of document is in safe context
                    safe_ranges.push((content_start, html.len()));
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Check every occurrence of the payload
    let payload_len = payload.len();
    let mut search_start = 0;
    while let Some(pos) = html[search_start..].find(payload) {
        let abs_pos = search_start + pos;
        let in_safe = safe_ranges
            .iter()
            .any(|&(start, end)| abs_pos >= start && abs_pos + payload_len <= end);
        if !in_safe {
            return false; // at least one occurrence is outside safe context
        }
        search_start = abs_pos + 1;
    }

    true
}

static ENTITY_REGEX: OnceLock<Regex> = OnceLock::new();
static NAMED_ENTITY_REGEX: OnceLock<Regex> = OnceLock::new();

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
    // Keep decoding narrow but case-insensitive (e.g., &LT; / &Lt;).
    let named_re =
        NAMED_ENTITY_REGEX.get_or_init(|| Regex::new(r"(?i)&(?:lt|gt|amp|quot|apos);").unwrap());
    named_re
        .replace_all(&out, |caps: &regex::Captures| {
            match caps[0].to_ascii_lowercase().as_str() {
                "&lt;" => "<",
                "&gt;" => ">",
                "&amp;" => "&",
                "&quot;" => "\"",
                "&apos;" => "'",
                _ => "",
            }
        })
        .to_string()
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
    if let Ok(url_dec) = urlencoding::decode(resp_text)
        && url_dec != resp_text
        && url_dec.contains(payload)
    {
        return Some(ReflectionKind::UrlDecoded);
    }

    // Check URL decoded version of HTML decoded
    if let Ok(url_dec_html) = urlencoding::decode(&html_dec)
        && url_dec_html != html_dec
        && url_dec_html.contains(payload)
    {
        return Some(ReflectionKind::HtmlThenUrlDecoded);
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
    fetch_injection_response_with_client(&client, target, param, payload, args).await
}

async fn fetch_injection_response_with_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> Option<String> {
    if args.skip_xss_scanning {
        return None;
    }

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

    // For Stored XSS, check reflection on sxss_url with retry logic
    if args.sxss {
        if let Some(sxss_url_str) = &args.sxss_url
            && let Ok(sxss_url) = url::Url::parse(sxss_url_str)
        {
            // Retry up to 3 times with delay to handle session propagation
            for attempt in 0..3 {
                if attempt > 0 {
                    sleep(Duration::from_millis(500 * attempt as u64)).await;
                }
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(&client, target, method, sxss_url.clone(), None);

                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Ok(resp) = check_request.send().await
                    && let Ok(text) = resp.text().await
                    && !text.is_empty()
                {
                    return Some(text);
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
        match classify_reflection(&text, payload) {
            Some(ReflectionKind::Raw) if is_in_safe_context(&text, payload) => false,
            Some(_) => true,
            None => false,
        }
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
        let kind = match kind {
            Some(ReflectionKind::Raw) if is_in_safe_context(&text, payload) => None,
            other => other,
        };
        (kind, Some(text))
    } else {
        (None, None)
    }
}

pub async fn check_reflection_with_response_client(
    client: &Client,
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (Option<ReflectionKind>, Option<String>) {
    if let Some(text) =
        fetch_injection_response_with_client(client, target, param, payload, args).await
    {
        let kind = classify_reflection(&text, payload);
        let kind = match kind {
            Some(ReflectionKind::Raw) if is_in_safe_context(&text, payload) => None,
            other => other,
        };
        (kind, Some(text))
    } else {
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::Target;
    use crate::target_parser::parse_target;
    use axum::{
        Router,
        extract::{Query, State},
        http::StatusCode,
        response::{Html, IntoResponse},
        routing::get,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    #[derive(Clone)]
    struct TestState {
        stored_payload: String,
    }

    fn make_param() -> Param {
        Param {
            name: "q".to_string(),
            value: "seed".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        }
    }

    fn default_scan_args() -> crate::cmd::scan::ScanArgs {
        crate::cmd::scan::ScanArgs {
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
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }

    fn make_target(addr: SocketAddr, path: &str) -> Target {
        let target = format!("http://{}:{}{}?q=seed", addr.ip(), addr.port(), path);
        parse_target(&target).expect("valid target")
    }

    fn html_named_encode_all(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                '&' => "&amp;".to_string(),
                '"' => "&quot;".to_string(),
                '\'' => "&apos;".to_string(),
                _ => c.to_string(),
            })
            .collect::<String>()
    }

    async fn raw_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", q))
    }

    async fn html_entity_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", html_named_encode_all(&q)))
    }

    async fn url_encoded_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let q = params.get("q").cloned().unwrap_or_default();
        Html(format!("<div>{}</div>", urlencoding::encode(&q)))
    }

    async fn none_handler() -> Html<&'static str> {
        Html("<div>not reflected</div>")
    }

    async fn json_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
        let q = params.get("q").cloned().unwrap_or_default();
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            format!("{{\"echo\":\"{}\"}}", q),
        )
    }

    async fn sxss_handler(State(state): State<TestState>) -> Html<String> {
        Html(format!("<div>{}</div>", state.stored_payload))
    }

    async fn start_mock_server(stored_payload: &str) -> SocketAddr {
        let app = Router::new()
            .route("/reflect/raw", get(raw_handler))
            .route("/reflect/html-entity", get(html_entity_handler))
            .route("/reflect/url-encoded", get(url_encoded_handler))
            .route("/reflect/none", get(none_handler))
            .route("/reflect/json", get(json_handler))
            .route("/sxss/stored", get(sxss_handler))
            .with_state(TestState {
                stored_payload: stored_payload.to_string(),
            });

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        sleep(Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn test_check_reflection_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = make_param();
        let mut args = default_scan_args();
        args.skip_xss_scanning = true;
        let res = check_reflection(&target, &param, "PAY", &args).await;
        assert!(
            !res,
            "should early-return false when skip_xss_scanning=true"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = make_param();
        let mut args = default_scan_args();
        args.skip_xss_scanning = true;
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
    fn test_decode_html_entities_decimal_and_hex_mix() {
        let s = "&#60;img src=x&#62; and &#x3C;svg&#x3E;";
        let d = decode_html_entities(s);
        assert_eq!(d, "<img src=x> and <svg>");
    }

    #[test]
    fn test_decode_html_entities_named_case_insensitive() {
        let s = "&LT;script&GT;1&LT;/script&GT; &QuOt;ok&QuOt;";
        let d = decode_html_entities(s);
        assert!(d.contains("<script>1</script>"));
        assert!(d.contains("\"ok\""));
    }

    #[test]
    fn test_decode_html_entities_ignores_invalid_numeric_sequences() {
        let s = "&#xZZ; &#;";
        let d = decode_html_entities(s);
        assert_eq!(d, s);
    }

    #[test]
    fn test_classify_reflection_prefers_raw_match() {
        let payload = "<script>alert(1)</script>";
        let resp = format!("raw:{} encoded:{}", payload, urlencoding::encode(payload));
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::Raw)
        );
    }

    #[test]
    fn test_is_payload_reflected_html_encoded() {
        let payload = "<script>alert(1)</script>";
        let resp = "prefix &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e; suffix";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::HtmlEntityDecoded)
        );
    }

    #[test]
    fn test_is_payload_reflected_url_encoded() {
        let payload = "<img src=x onerror=alert(1)>";
        let encoded = urlencoding::encode(payload).to_string();
        let resp = format!("ok {} end", encoded);
        assert_eq!(
            classify_reflection(&resp, payload),
            Some(ReflectionKind::UrlDecoded)
        );
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

    #[test]
    fn test_is_payload_reflected_html_named_uppercase() {
        let payload = "<svg onload=alert(1)>";
        let resp = "prefix &LT;svg onload=alert(1)&GT; suffix";
        assert_eq!(
            classify_reflection(resp, payload),
            Some(ReflectionKind::HtmlEntityDecoded)
        );
    }

    #[tokio::test]
    async fn test_check_reflection_detects_raw_response() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/raw");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "raw reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_detects_html_entity_response() {
        let payload = "<img src=x onerror=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/html-entity");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "entity-encoded reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_detects_url_encoded_response() {
        let payload = "<svg onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/url-encoded");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "URL-encoded reflection should be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_returns_false_when_not_reflected() {
        let payload = "<svg/onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let args = default_scan_args();

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(!found, "non-reflective response should not be detected");
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_reports_kind_and_body() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/html-entity");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, Some(ReflectionKind::HtmlEntityDecoded));
        assert!(body.unwrap_or_default().contains("&lt;script&gt;"));
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_not_reflected() {
        let payload = "<script>alert(1)</script>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, None);
        assert!(
            body.is_some(),
            "request succeeded so response body should be returned"
        );
    }

    #[tokio::test]
    async fn test_check_reflection_sxss_uses_secondary_url() {
        let payload = "STORED_XSS_PAYLOAD";
        let addr = start_mock_server(payload).await;
        let target = make_target(addr, "/reflect/none");
        let param = make_param();
        let mut args = default_scan_args();
        args.sxss = true;
        args.sxss_url = Some(format!("http://{}:{}/sxss/stored", addr.ip(), addr.port()));

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(found, "sxss mode should verify reflection via sxss_url");
    }

    #[tokio::test]
    async fn test_check_reflection_sxss_without_url_returns_false() {
        let payload = "STORED_XSS_PAYLOAD";
        let addr = start_mock_server(payload).await;
        let target = make_target(addr, "/reflect/raw");
        let param = make_param();
        let mut args = default_scan_args();
        args.sxss = true;
        args.sxss_url = None;

        let found = check_reflection(&target, &param, payload, &args).await;
        assert!(!found, "sxss mode without sxss_url should return false");
    }

    #[tokio::test]
    async fn test_check_reflection_with_response_handles_json_raw_reflection() {
        let payload = "<svg/onload=alert(1)>";
        let addr = start_mock_server("stored").await;
        let target = make_target(addr, "/reflect/json");
        let param = make_param();
        let args = default_scan_args();

        let (kind, body) = check_reflection_with_response(&target, &param, payload, &args).await;
        assert_eq!(kind, Some(ReflectionKind::Raw));
        assert!(body.unwrap_or_default().contains("echo"));
    }

    // --- Safe context filtering tests ---

    #[test]
    fn test_safe_context_textarea() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><textarea>{}</textarea></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_noscript() {
        let payload = "<img src=x onerror=alert(1)>";
        let html = format!("<html><noscript>{}</noscript></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_title() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><head><title>{}</title></head></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_style() {
        let payload = "expression(alert(1))";
        let html = format!("<html><style>{}</style></html>", payload);
        assert!(is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_mixed_safe_and_unsafe() {
        let payload = "<script>alert(1)</script>";
        let html = format!(
            "<html><textarea>{}</textarea><div>{}</div></html>",
            payload, payload
        );
        assert!(
            !is_in_safe_context(&html, payload),
            "mixed context should NOT be considered safe"
        );
    }

    #[test]
    fn test_safe_context_outside_safe_tag() {
        let payload = "<script>alert(1)</script>";
        let html = format!("<html><div>{}</div></html>", payload);
        assert!(!is_in_safe_context(&html, payload));
    }

    #[test]
    fn test_safe_context_no_payload() {
        assert!(is_in_safe_context("<html><body>nothing</body></html>", "PAYLOAD"));
    }
}
