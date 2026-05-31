use super::poc::{build_ast_dom_message, generate_poc};
use super::postprocess::{dedupe_ast_results, extract_context};
use super::preflight::{PreflightOutcome, is_allowed_content_type, preflight_content_type};
use super::{
    CLI_MAX_DELAY_MS, CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, DEFAULT_DELAY_MS, DEFAULT_ENCODERS,
    DEFAULT_MAX_CONCURRENT_TARGETS, DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD,
    DEFAULT_TIMEOUT_SECS, DEFAULT_WORKERS, ScanArgs, validate_numeric_args,
};
use crate::scanning::result::{FindingType, Result as ScanResult};
use crate::target_parser::parse_target;
use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;
use tokio::net::TcpListener;

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: DEFAULT_METHOD.to_string(),
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
        timeout: DEFAULT_TIMEOUT_SECS,
        scan_timeout: 0,
        delay: DEFAULT_DELAY_MS,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        workers: DEFAULT_WORKERS,
        max_concurrent_targets: DEFAULT_MAX_CONCURRENT_TARGETS,
        max_targets_per_host: DEFAULT_MAX_TARGETS_PER_HOST,
        encoders: DEFAULT_ENCODERS.iter().map(|s| s.to_string()).collect(),
        remote_payloads: vec![],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        targets: vec![],
    }
}

async fn spawn_preflight_server(
    csp_header: Option<(&'static str, &'static str)>,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(move || async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            if let Some((name, value)) = csp_header {
                headers.insert(
                    HeaderName::from_lowercase(name.as_bytes()).expect("valid static header name"),
                    HeaderValue::from_static(value),
                );
            }
            (headers, body)
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}/", addr), handle)
}

#[test]
fn validate_numeric_args_accepts_defaults() {
    let args = default_scan_args();
    assert!(validate_numeric_args(&args).is_ok());
}

#[test]
fn validate_numeric_args_rejects_zero_workers() {
    let mut args = default_scan_args();
    args.workers = 0;
    let err = validate_numeric_args(&args).unwrap_err();
    assert!(err.1.contains("workers"));
}

#[test]
fn validate_numeric_args_rejects_workers_over_cap() {
    let mut args = default_scan_args();
    args.workers = CLI_MAX_WORKERS + 1;
    assert!(validate_numeric_args(&args).is_err());
}

#[test]
fn validate_numeric_args_rejects_zero_timeout() {
    let mut args = default_scan_args();
    args.timeout = 0;
    let err = validate_numeric_args(&args).unwrap_err();
    assert!(err.1.contains("timeout"));
}

#[test]
fn validate_numeric_args_rejects_timeout_over_cap() {
    let mut args = default_scan_args();
    args.timeout = CLI_MAX_TIMEOUT_SECS + 1;
    assert!(validate_numeric_args(&args).is_err());
}

#[test]
fn validate_numeric_args_rejects_delay_over_cap() {
    let mut args = default_scan_args();
    args.delay = CLI_MAX_DELAY_MS + 1;
    assert!(validate_numeric_args(&args).is_err());
}

#[test]
fn validate_numeric_args_rejects_zero_concurrent_targets() {
    let mut args = default_scan_args();
    args.max_concurrent_targets = 0;
    assert!(validate_numeric_args(&args).is_err());
}

#[test]
fn validate_numeric_args_rejects_zero_targets_per_host() {
    let mut args = default_scan_args();
    args.max_targets_per_host = 0;
    let err = validate_numeric_args(&args).unwrap_err();
    assert!(err.1.contains("max-targets-per-host"));
}

#[test]
fn validate_numeric_args_accepts_waf_min_confidence_bounds() {
    for v in [0.0_f32, 0.5, 1.0] {
        let mut args = default_scan_args();
        args.waf_min_confidence = v;
        assert!(
            validate_numeric_args(&args).is_ok(),
            "{} should validate",
            v
        );
    }
}

#[test]
fn validate_numeric_args_rejects_waf_min_confidence_out_of_range() {
    let mut args = default_scan_args();
    args.waf_min_confidence = -0.1;
    assert!(validate_numeric_args(&args).is_err());
    args.waf_min_confidence = 1.5;
    assert!(validate_numeric_args(&args).is_err());
    args.waf_min_confidence = f32::NAN;
    assert!(validate_numeric_args(&args).is_err());
}

#[test]
fn test_allowed_content_types() {
    assert!(is_allowed_content_type("text/html"));
    assert!(is_allowed_content_type("text/html; charset=utf-8"));
    assert!(is_allowed_content_type("application/xml"));
    assert!(is_allowed_content_type("application/json"));
    assert!(is_allowed_content_type("application/javascript"));
    assert!(is_allowed_content_type("image/svg+xml"));
}

#[test]
fn test_denied_content_types() {
    assert!(!is_allowed_content_type("image/png"));
    assert!(!is_allowed_content_type("application/octet-stream"));
}

#[test]
fn test_edge_cases() {
    assert!(!is_allowed_content_type(""));
    assert!(!is_allowed_content_type("invalid"));
    assert!(is_allowed_content_type("application/json; charset=utf-8"));
}

#[test]
fn test_extract_context_basic() {
    let resp = "first line\nzzzPAYzzz\nlast line";
    let (line, ctx) = extract_context(resp, "PAY").expect("should find payload");
    assert_eq!(line, 2);
    assert_eq!(ctx, "zzzPAYzzz");
}

#[test]
fn test_extract_context_trims_long_line() {
    let prefix = "a".repeat(30);
    let suffix = "b".repeat(30);
    let line = format!("{}X{}", prefix, suffix);
    let (ln, ctx) = extract_context(&line, "X").expect("should find payload");
    assert_eq!(ln, 1);
    assert!(ctx.starts_with(&"a".repeat(20)));
    assert!(ctx.contains('X'));
    assert!(ctx.ends_with(&"b".repeat(20)));
}

#[test]
fn test_extract_context_none() {
    assert!(extract_context("no match here", "PAY").is_none());
}

#[test]
fn test_dedupe_ast_results_prefers_verified_variant() {
    let mut ast_a = ScanResult::new(
        FindingType::AstDetected,
        "DOM-XSS".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<img src=x onerror=alert(1)>".to_string(),
        "https://example.com:1:1 - desc (Source: location.search, Sink: innerHTML)".to_string(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        0,
        "desc (검증 필요) [경량 확인: 미검증]".to_string(),
    );
    ast_a.request = Some("GET /?q=... HTTP/1.1".to_string());

    let mut ast_v = ast_a.clone();
    ast_v.result_type = FindingType::Verified;
    ast_v.severity = "High".to_string();
    ast_v.message_str = "desc (검증 필요) [경량 확인: 검증됨]".to_string();

    let deduped = dedupe_ast_results(vec![ast_a, ast_v]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].result_type, FindingType::Verified);
    assert_eq!(deduped[0].severity, "High");
}

#[test]
fn test_dedupe_ast_results_collapses_cross_stage_duplicates() {
    let evidence =
        "https://example.com:3:9 - DOM-based XSS via location.search to innerHTML (Source: location.search, Sink: innerHTML)".to_string();
    let ast_preflight = ScanResult::new(
        FindingType::AstDetected,
        "DOM-XSS".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "-".to_string(),
        "<img src=x onerror=alert(1) class=dlxaaa111>".to_string(),
        evidence.clone(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        0,
        "preflight".to_string(),
    );
    let mut ast_param_verified = ScanResult::new(
        FindingType::Verified,
        "DOM-XSS".to_string(),
        "GET".to_string(),
        "https://example.com/?q=%3Cimg...%3E".to_string(),
        "q".to_string(),
        "<img src=x onerror=alert(1) class=dlxaaa111>".to_string(),
        evidence,
        "CWE-79".to_string(),
        "High".to_string(),
        0,
        "verified".to_string(),
    );
    ast_param_verified.request = Some("GET /?q=... HTTP/1.1".to_string());

    let deduped = dedupe_ast_results(vec![ast_preflight, ast_param_verified.clone()]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].result_type, FindingType::Verified);
    assert_eq!(deduped[0].message_str, ast_param_verified.message_str);
}

#[test]
fn test_dedupe_ast_results_keeps_non_ast_entries() {
    let r1 = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "PAY".to_string(),
        "e1".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        606,
        "m1".to_string(),
    );
    let r2 = r1.clone();
    let deduped = dedupe_ast_results(vec![r1, r2]);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_generate_poc_plain_query() {
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "plain");
    assert!(out.contains("[POC][R][GET][inHTML]"));
    assert!(out.contains("?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_curl() {
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "curl");
    assert!(out.starts_with("curl -X GET "));
    assert!(out.contains("?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_http_request_prefers_request_block() {
    let mut r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    r.request = Some("GET / HTTP/1.1\nHost: example.com".to_string());
    let out = generate_poc(&r, "http-request");
    assert!(out.contains("GET / HTTP/1.1"));
}

#[test]
fn test_generate_poc_plain_header_does_not_synthesize_query() {
    // Regression for the xss-quiz pattern: header reflection used to be
    // rendered as `?X-Custom-Header=<svg…>` (an invented query param),
    // which couldn't reproduce the finding. The plain POC must now leave
    // the URL untouched and tag the line with `[hdr]`.
    let mut r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "http://example.com/".to_string(),
        "X-Custom-Header".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    r.location = "Header".to_string();
    let out = generate_poc(&r, "plain");
    assert!(
        !out.contains("?X-Custom-Header"),
        "header POC must not synthesize ?X-Custom-Header=… in URL; got: {}",
        out
    );
    assert!(
        out.contains("[hdr]"),
        "plain header POC missing [hdr] tag: {}",
        out
    );
    assert!(out.contains("http://example.com/"));
}

#[test]
fn test_generate_poc_curl_header_uses_dash_h_flag() {
    let mut r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "http://example.com/".to_string(),
        "X-Custom-Header".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    r.location = "Header".to_string();
    let out = generate_poc(&r, "curl");
    assert!(
        out.contains("-H \"X-Custom-Header: <svg/onload=alert(1)>\""),
        "curl POC missing -H: {}",
        out
    );
    assert!(!out.contains("?X-Custom-Header"));
}

#[test]
fn test_generate_poc_cookie_uses_cookie_tag_and_dash_b() {
    let mut r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "http://example.com/".to_string(),
        "Cookie".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    r.location = "Header".to_string();
    let plain = generate_poc(&r, "plain");
    assert!(
        plain.contains("[cookie]"),
        "plain cookie POC missing [cookie] tag: {}",
        plain
    );
    let curl = generate_poc(&r, "curl");
    assert!(
        curl.contains("-b \"Cookie=<svg/onload=alert(1)>\""),
        "curl POC missing -b: {}",
        curl
    );
}

#[test]
fn test_generate_poc_body_emits_data_flag() {
    let mut r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "POST".to_string(),
        "http://example.com/login".to_string(),
        "username".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    r.location = "Body".to_string();
    let plain = generate_poc(&r, "plain");
    assert!(
        plain.contains("[body]"),
        "plain body POC missing [body] tag: {}",
        plain
    );
    assert!(
        !plain.contains("?username="),
        "body POC must not synthesize ?username=… in URL: {}",
        plain
    );
    let curl = generate_poc(&r, "curl");
    assert!(
        curl.contains("--data \"username=<svg/onload=alert(1)>\""),
        "curl POC missing --data: {}",
        curl
    );
}

#[test]
fn test_generate_poc_query_unchanged_when_location_empty() {
    // Older Result producers don't set `location` yet. The plain POC must
    // stay byte-identical to the pre-bug-5 format so unrelated downstream
    // parsers (CI, reporting scripts) don't break.
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "plain");
    assert!(
        out.contains("[POC][R][GET][inHTML]"),
        "format drift: {}",
        out
    );
    assert!(out.contains("?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_path_segment_append() {
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://ex.com/foo/bar".to_string(),
        "path_segment_1".to_string(),
        "PAY".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "plain");
    assert!(out.contains("https://ex.com/foo/bar/PAY"));
}

#[test]
fn test_generate_poc_http_request_without_request_falls_back_to_url() {
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "http-request");
    assert!(out.contains("https://example.com?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_unknown_type_defaults_to_plain_format() {
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "PAY".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "custom");
    assert!(out.starts_with("[POC][R][GET][inHTML]"));
}

#[test]
fn test_generate_poc_path_segment_selective_encoding_for_special_chars() {
    let payload = "A B#?%".to_string();
    let r = ScanResult::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        format!("https://ex.com/base/{}", payload),
        "path_segment_2".to_string(),
        payload,
        "evidence".to_string(),
        "CWE-79".to_string(),
        "Info".to_string(),
        0,
        "msg".to_string(),
    );
    let out = generate_poc(&r, "plain");
    assert!(out.contains("A%20B%23%3F%25"));
}

#[test]
fn test_build_ast_dom_message_keeps_url_source_wording() {
    let message = build_ast_dom_message(
        "DOM-based XSS via location.hash to innerHTML",
        "location.hash",
        "https://example.com/dom/level2/",
        "<img src=x onerror=alert(1)>",
    );
    assert_eq!(
        message,
        "DOM-based XSS via location.hash to innerHTML (검증 필요) [경량 확인: 파라미터 없음]"
    );
}

#[test]
fn test_build_ast_dom_message_adds_postmessage_manual_hint() {
    let message = build_ast_dom_message(
        "DOM-based XSS via e.data to innerHTML",
        "e.data",
        "https://example.com/dom/level23/",
        "<img src=x onerror=alert(1)>",
    );
    assert!(message.contains("[manual POC:"));
    assert!(message.contains("window.open"));
    assert!(message.contains("postMessage"));
}

#[test]
fn test_build_ast_dom_message_adds_referrer_manual_hint() {
    let message = build_ast_dom_message(
        "DOM-based XSS via document.referrer to document.write",
        "document.referrer",
        "https://example.com/dom/level14/",
        "<img src=x onerror=alert(1)>",
    );
    assert!(message.contains("[manual POC:"));
    assert!(message.contains("document.referrer"));
    assert!(message.contains("attacker-controlled page"));
}

#[test]
fn test_build_ast_dom_message_adds_cookie_manual_hint() {
    let message = build_ast_dom_message(
        "DOM-based XSS via document.cookie to document.write",
        "document.cookie",
        "https://example.com/dom/level12/",
        "<img src=x onerror=alert(1)>",
    );
    assert!(message.contains("[manual POC:"));
    assert!(message.contains("same-origin cookie"));
    assert!(message.contains("cookie-safe variant may be needed"));
}

#[test]
fn test_build_ast_dom_message_keeps_pathname_wording() {
    let message = build_ast_dom_message(
        "DOM-based XSS via location.pathname to document.write",
        "location.pathname",
        "https://example.com/dom/level28/",
        "<img src=x onerror=alert(1)>",
    );
    assert_eq!(
        message,
        "DOM-based XSS via location.pathname to document.write (검증 필요) [경량 확인: 파라미터 없음]"
    );
}

#[tokio::test]
async fn test_preflight_content_type_reads_http_csp_header() {
    let (url, handle) = spawn_preflight_server(
        Some(("content-security-policy", "default-src 'self'")),
        "ok",
    )
    .await;

    let mut target = parse_target(&url).expect("valid target");
    target.headers.push(("X-Test".to_string(), "1".to_string()));
    target.user_agent = Some("dalfox-test-agent".to_string());
    target.cookies.push(("sid".to_string(), "abc".to_string()));
    target.delay = 1;

    let mut args = default_scan_args();
    args.skip_waf_probe = true; // avoid extra request in test
    let preflight = match preflight_content_type(&target, &args).await {
        PreflightOutcome::WithContentType(r) => r,
        PreflightOutcome::NoContentType => panic!("preflight should return a Content-Type"),
        PreflightOutcome::Unreachable(_) => panic!("preflight target should be reachable in tests"),
    };
    handle.abort();

    assert!(preflight.content_type.contains("text/html"));
    let (name, value) = preflight.csp_header.expect("csp header should be present");
    assert_eq!(name, "Content-Security-Policy");
    assert_eq!(value, "default-src 'self'");
    assert_eq!(preflight.response_body.as_deref(), Some("ok"));
}

#[tokio::test]
async fn test_preflight_content_type_extracts_meta_csp_when_header_missing() {
    let html = "<html><head><meta http-equiv=\"Content-Security-Policy-Report-Only\" content=\"script-src 'none'\"></head><body>ok</body></html>";
    let (url, handle) = spawn_preflight_server(None, html).await;

    let target = parse_target(&url).expect("valid target");
    let mut args = default_scan_args();
    args.skip_waf_probe = true;
    let preflight = match preflight_content_type(&target, &args).await {
        PreflightOutcome::WithContentType(r) => r,
        PreflightOutcome::NoContentType => panic!("preflight should return a Content-Type"),
        PreflightOutcome::Unreachable(_) => panic!("preflight target should be reachable in tests"),
    };
    handle.abort();

    assert!(preflight.content_type.contains("text/html"));
    let (name, value) = preflight.csp_header.expect("meta csp should be parsed");
    assert_eq!(name, "Content-Security-Policy-Report-Only");
    assert_eq!(value, "script-src 'none'");
    assert!(
        preflight
            .response_body
            .expect("body expected")
            .contains("http-equiv")
    );
}
