use super::logging::{log_dbg, log_info, log_warn, start_spinner};
use super::output::{render_dry_run, render_only_discovery, render_results};
use super::poc::{build_ast_dom_message, generate_poc, render_finding_block};
use super::postprocess::{dedupe_ast_results, extract_context};
use super::preflight::{PreflightOutcome, is_allowed_content_type, preflight_content_type};
use super::{
    CLI_MAX_DELAY_MS, CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, DEFAULT_DELAY_MS, DEFAULT_ENCODERS,
    DEFAULT_MAX_CONCURRENT_TARGETS, DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD,
    DEFAULT_TIMEOUT_SECS, DEFAULT_WORKERS, ScanArgs, ScanOutcome, ScanState, validate_numeric_args,
};
use crate::parameter_analysis::{InjectionContext, Location, Param};
use crate::scanning::result::{FindingType, Result as ScanResult};
use crate::target_parser::{Target, parse_target};
use crate::waf::bypass::{MutationStats, MutationType};
use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        detect_outdated_libs: false,
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
    let mut ast_a = ScanResult::builder(FindingType::AstDetected)
        .inject_type("DOM-XSS")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<img src=x onerror=alert(1)>")
        .evidence("https://example.com:1:1 - desc (Source: location.search, Sink: innerHTML)")
        .cwe("CWE-79")
        .severity("Medium")
        .message_id(0)
        .message_str("desc (needs runtime confirmation) [light check: unverified]")
        .build();
    ast_a.request = Some("GET /?q=... HTTP/1.1".to_string());

    let mut ast_v = ast_a.clone();
    ast_v.result_type = FindingType::Verified;
    ast_v.severity = "High".to_string();
    ast_v.message_str = "desc (needs runtime confirmation) [light check: verified]".to_string();

    let deduped = dedupe_ast_results(vec![ast_a, ast_v]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].result_type, FindingType::Verified);
    assert_eq!(deduped[0].severity, "High");
}

#[test]
fn test_dedupe_ast_results_collapses_cross_stage_duplicates() {
    let evidence =
        "https://example.com:3:9 - DOM-based XSS via location.search to innerHTML (Source: location.search, Sink: innerHTML)".to_string();
    let ast_preflight = ScanResult::builder(FindingType::AstDetected)
        .inject_type("DOM-XSS")
        .method("GET")
        .data("https://example.com")
        .param("-")
        .payload("<img src=x onerror=alert(1) class=dlxaaa111>")
        .evidence(evidence.clone())
        .cwe("CWE-79")
        .severity("Medium")
        .message_id(0)
        .message_str("preflight")
        .build();
    let mut ast_param_verified = ScanResult::builder(FindingType::Verified)
        .inject_type("DOM-XSS")
        .method("GET")
        .data("https://example.com/?q=%3Cimg...%3E")
        .param("q")
        .payload("<img src=x onerror=alert(1) class=dlxaaa111>")
        .evidence(evidence)
        .cwe("CWE-79")
        .severity("High")
        .message_id(0)
        .message_str("verified")
        .build();
    ast_param_verified.request = Some("GET /?q=... HTTP/1.1".to_string());

    let deduped = dedupe_ast_results(vec![ast_preflight, ast_param_verified.clone()]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].result_type, FindingType::Verified);
    assert_eq!(deduped[0].message_str, ast_param_verified.message_str);
}

#[test]
fn test_dedupe_ast_results_keeps_non_ast_entries() {
    let r1 = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("PAY")
        .evidence("e1")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(606)
        .message_str("m1")
        .build();
    let r2 = r1.clone();
    let deduped = dedupe_ast_results(vec![r1, r2]);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_generate_poc_plain_query() {
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
    let out = generate_poc(&r, "plain");
    assert!(out.contains("[POC][R][GET][inHTML]"));
    assert!(out.contains("?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_curl() {
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
    let out = generate_poc(&r, "curl");
    assert!(out.starts_with("curl -X GET "));
    assert!(out.contains("?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_http_request_prefers_request_block() {
    let mut r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let mut r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("http://example.com/")
        .param("X-Custom-Header")
        .payload("<svg/onload=alert(1)>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let mut r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("http://example.com/")
        .param("X-Custom-Header")
        .payload("<svg/onload=alert(1)>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let mut r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("http://example.com/")
        .param("Cookie")
        .payload("<svg/onload=alert(1)>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let mut r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("POST")
        .data("http://example.com/login")
        .param("username")
        .payload("<svg/onload=alert(1)>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://ex.com/foo/bar")
        .param("path_segment_1")
        .payload("PAY")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
    let out = generate_poc(&r, "plain");
    assert!(out.contains("https://ex.com/foo/bar/PAY"));
}

#[test]
fn test_generate_poc_http_request_without_request_falls_back_to_url() {
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
    let out = generate_poc(&r, "http-request");
    assert!(out.contains("https://example.com?q=%3Cx%3E"));
}

#[test]
fn test_generate_poc_unknown_type_defaults_to_plain_format() {
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("q")
        .payload("PAY")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
    let out = generate_poc(&r, "custom");
    assert!(out.starts_with("[POC][R][GET][inHTML]"));
}

#[test]
fn test_generate_poc_path_segment_selective_encoding_for_special_chars() {
    let payload = "A B#?%".to_string();
    let r = ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data(format!("https://ex.com/base/{}", payload))
        .param("path_segment_2")
        .payload(payload)
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build();
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
        "DOM-based XSS via location.hash to innerHTML (needs runtime confirmation) [light check: no parameter]"
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
        "DOM-based XSS via location.pathname to document.write (needs runtime confirmation) [light check: no parameter]"
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

// ─────────────────────────────────────────────────────────────────────────
// Shared fixtures for the POC / output rendering tests below.
// ─────────────────────────────────────────────────────────────────────────

/// Minimal `Param` with sensible defaults; only `name`/`location` vary per test.
fn make_param(name: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: "v".to_string(),
        location,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

/// A `Target` carrying the given discovered reflection params.
fn target_with_params(url: &str, params: Vec<Param>) -> Target {
    let mut t = parse_target(url).expect("valid target");
    t.reflection_params = params;
    t
}

/// Wrap targets into the `host_groups` shape the output renderers consume.
fn host_group(targets: Vec<Target>) -> HashMap<String, Vec<Target>> {
    let mut m = HashMap::new();
    m.insert("host".to_string(), targets);
    m
}

/// A `Reflected` finding with the common boilerplate filled in.
fn reflected_result(url: &str, param: &str, payload: &str) -> ScanResult {
    ScanResult::builder(FindingType::Reflected)
        .inject_type("inHTML")
        .method("GET")
        .data(url.to_string())
        .param(param.to_string())
        .payload(payload.to_string())
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("Info")
        .message_id(0)
        .message_str("msg")
        .build()
}

/// A `ScanState` with empty shared handles and the supplied results preloaded.
fn make_scan_state(results: Vec<ScanResult>) -> ScanState {
    ScanState {
        results: Arc::new(Mutex::new(results)),
        findings_count: Arc::new(AtomicUsize::new(0)),
        skipped_targets: Arc::new(Mutex::new(HashMap::new())),
        target_meta: Arc::new(Mutex::new(HashMap::new())),
        target_mutation_stats: Arc::new(Mutex::new(HashMap::new())),
        multi_pb: None,
        preflight_idx: Arc::new(AtomicUsize::new(0)),
        analyze_idx: Arc::new(AtomicUsize::new(0)),
        scan_idx: Arc::new(AtomicUsize::new(0)),
        overall_done: Arc::new(AtomicUsize::new(0)),
        total_targets: 0,
        spinner_allowed: false,
        no_color: true,
    }
}

/// Per-test temp file path (test names are unique, so paths never collide).
fn temp_out_path(tag: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("dalfox_cov_{}.out", tag));
    p.to_string_lossy().into_owned()
}

// ─────────────────────────────────────────────────────────────────────────
// poc.rs — httpie POC rendering (was entirely uncovered)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_poc_httpie_query() {
    let r = reflected_result("https://example.com", "q", "<x>");
    let out = generate_poc(&r, "httpie");
    assert!(out.starts_with("http get "), "got: {}", out);
    assert!(out.contains("?q=%3Cx%3E"), "got: {}", out);
}

#[test]
fn test_generate_poc_httpie_header_uses_header_arg() {
    let mut r = reflected_result(
        "http://example.com/",
        "X-Custom-Header",
        "<svg/onload=alert(1)>",
    );
    r.location = "Header".to_string();
    let out = generate_poc(&r, "httpie");
    assert!(
        out.contains("\"X-Custom-Header:<svg/onload=alert(1)>\""),
        "httpie header POC missing header arg: {}",
        out
    );
    assert!(!out.contains("?X-Custom-Header"), "got: {}", out);
}

#[test]
fn test_generate_poc_httpie_cookie_uses_cookie_arg() {
    let mut r = reflected_result("http://example.com/", "Cookie", "<svg/onload=alert(1)>");
    r.location = "Header".to_string();
    let out = generate_poc(&r, "httpie");
    assert!(
        out.contains("\"Cookie:Cookie=<svg/onload=alert(1)>\""),
        "httpie cookie POC missing cookie arg: {}",
        out
    );
}

#[test]
fn test_generate_poc_httpie_body_uses_form_flag() {
    let mut r = reflected_result(
        "http://example.com/login",
        "username",
        "<svg/onload=alert(1)>",
    );
    r.method = "POST".to_string();
    r.location = "Body".to_string();
    let out = generate_poc(&r, "httpie");
    assert!(out.starts_with("http -f post "), "got: {}", out);
    assert!(
        out.contains("\"username=<svg/onload=alert(1)>\""),
        "httpie body POC missing form field: {}",
        out
    );
}

#[test]
fn test_generate_poc_httpie_jsonbody() {
    let mut r = reflected_result("http://example.com/api", "field", "<x>");
    r.method = "POST".to_string();
    r.location = "JsonBody".to_string();
    let out = generate_poc(&r, "httpie");
    assert!(out.starts_with("http post "), "got: {}", out);
    assert!(out.contains("\"field=<x>\""), "got: {}", out);
}

// ─────────────────────────────────────────────────────────────────────────
// poc.rs — curl JsonBody / MultipartBody and escaping (were uncovered)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_poc_curl_jsonbody_emits_json_content_type() {
    let mut r = reflected_result("http://example.com/api", "field", "<x>");
    r.method = "POST".to_string();
    r.location = "JsonBody".to_string();
    let out = generate_poc(&r, "curl");
    assert!(
        out.contains("-H \"Content-Type: application/json\""),
        "curl json POC missing content-type: {}",
        out
    );
    assert!(
        out.contains("--data \"{\\\"field\\\":\\\"<x>\\\"}\""),
        "curl json POC missing json body: {}",
        out
    );
}

#[test]
fn test_generate_poc_curl_multipart_uses_data_flag() {
    let mut r = reflected_result("http://example.com/upload", "file", "<x>");
    r.method = "POST".to_string();
    r.location = "MultipartBody".to_string();
    let out = generate_poc(&r, "curl");
    assert!(
        out.contains("--data \"file=<x>\""),
        "curl multipart POC missing --data: {}",
        out
    );
}

#[test]
fn test_generate_poc_curl_escapes_quotes_and_backslashes() {
    // The curl renderer escapes `"` and `\` in the payload so the shell
    // command stays well-formed.
    let mut r = reflected_result("http://example.com/", "X-H", "a\"b\\c");
    r.location = "Header".to_string();
    let out = generate_poc(&r, "curl");
    assert!(
        out.contains("-H \"X-H: a\\\"b\\\\c\""),
        "curl POC did not escape quotes/backslashes: {}",
        out
    );
}

// ─────────────────────────────────────────────────────────────────────────
// poc.rs — render_finding_block (full plain block; was uncovered)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_render_finding_block_reflected_plain() {
    let r = reflected_result("https://example.com", "q", "<x>");
    let block = render_finding_block(&r, "plain", false, false);
    // Reflected → yellow POC line.
    assert!(
        block.contains("\x1b[33m"),
        "missing reflected color: {}",
        block
    );
    assert!(block.contains("Issue:"), "missing Issue section: {}", block);
    assert!(block.contains("XSS payload reflected"), "got: {}", block);
    assert!(
        block.contains("Payload:"),
        "missing Payload section: {}",
        block
    );
    assert!(block.contains("<x>"), "missing payload text: {}", block);
    // Payload is the last section here → closing bullet.
    assert!(block.contains("└──"), "missing closing bullet: {}", block);
}

#[test]
fn test_render_finding_block_verified_with_context_and_response() {
    let mut r = reflected_result("https://example.com", "q", "PAYZ");
    r.result_type = FindingType::Verified;
    r.response = Some("line one\nzzzPAYZzz\nline three".to_string());
    let block = render_finding_block(&r, "plain", false, true);
    // Verified → red POC line.
    assert!(
        block.contains("\x1b[31m"),
        "missing verified color: {}",
        block
    );
    // Verified issue wording differs from Reflected.
    assert!(
        block.contains("XSS payload DOM object identified"),
        "got: {}",
        block
    );
    // Response contains the payload → context "Line" section is emitted.
    assert!(block.contains("L2:"), "missing context line: {}", block);
    // include_response → Response section with the body lines.
    assert!(
        block.contains("Response:"),
        "missing Response section: {}",
        block
    );
    assert!(
        block.contains("line three"),
        "missing response body: {}",
        block
    );
}

#[test]
fn test_render_finding_block_ast_with_request() {
    let mut r = reflected_result("https://example.com", "q", "<x>");
    r.result_type = FindingType::AstDetected;
    r.request = Some("GET /?q=<x> HTTP/1.1\nHost: example.com".to_string());
    let block = render_finding_block(&r, "plain", true, false);
    // AstDetected → magenta POC line.
    assert!(block.contains("\x1b[35m"), "missing ast color: {}", block);
    assert!(
        block.contains("Request:"),
        "missing Request section: {}",
        block
    );
    assert!(
        block.contains("Host: example.com"),
        "missing request body: {}",
        block
    );
}

#[test]
fn test_render_finding_block_curl_poc_type_has_no_ansi_on_poc_line() {
    // Non-plain POC types are meant to be copy-pasted, so the POC line must
    // not be wrapped in ANSI color codes.
    let r = reflected_result("https://example.com", "q", "<x>");
    let block = render_finding_block(&r, "curl", false, false);
    let first_line = block.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("curl -X GET "),
        "got: {}",
        first_line
    );
    assert!(
        !first_line.contains("\x1b["),
        "curl POC line should be plain: {}",
        first_line
    );
}

// ─────────────────────────────────────────────────────────────────────────
// output.rs — render_only_discovery (sync; json / jsonl / plain)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_render_only_discovery_plain() {
    let target = target_with_params(
        "https://example.com",
        vec![
            make_param("q", Location::Query),
            make_param("id", Location::Path),
        ],
    );
    let mut args = default_scan_args();
    args.format = "plain".to_string();
    let outcome = render_only_discovery(&args, &host_group(vec![target]));
    assert!(matches!(outcome, ScanOutcome::Clean));
}

#[test]
fn test_render_only_discovery_json() {
    let target = target_with_params(
        "https://example.com",
        vec![make_param("q", Location::Query)],
    );
    let mut args = default_scan_args();
    args.format = "json".to_string();
    let outcome = render_only_discovery(&args, &host_group(vec![target]));
    assert!(matches!(outcome, ScanOutcome::Clean));
}

#[test]
fn test_render_only_discovery_jsonl() {
    let target = target_with_params(
        "https://example.com",
        vec![make_param("q", Location::Query)],
    );
    let mut args = default_scan_args();
    args.format = "jsonl".to_string();
    let outcome = render_only_discovery(&args, &host_group(vec![target]));
    assert!(matches!(outcome, ScanOutcome::Clean));
}

// ─────────────────────────────────────────────────────────────────────────
// output.rs — render_dry_run (async; needs ScanState)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_render_dry_run_plain() {
    let mut p = make_param("q", Location::Query);
    p.injection_context = Some(InjectionContext::Html(None));
    let target = target_with_params(
        "https://example.com",
        vec![p, make_param("name", Location::Query)],
    );
    let mut args = default_scan_args();
    args.format = "plain".to_string();
    args.targets = vec!["https://example.com".to_string()];
    let state = make_scan_state(vec![]);
    let outcome = render_dry_run(&args, &host_group(vec![target]), &state).await;
    assert!(matches!(outcome, ScanOutcome::Clean));
}

#[tokio::test]
async fn test_render_dry_run_json_with_encoders() {
    let target = target_with_params(
        "https://example.com",
        vec![make_param("q", Location::Query)],
    );
    let mut args = default_scan_args();
    args.format = "json".to_string();
    args.targets = vec!["https://example.com".to_string()];
    // Non-"none" encoders exercise the request-estimation expansion factor.
    args.encoders = vec!["url".to_string(), "html".to_string()];
    args.max_payloads_per_param = 5;
    let state = make_scan_state(vec![]);
    let outcome = render_dry_run(&args, &host_group(vec![target]), &state).await;
    assert!(matches!(outcome, ScanOutcome::Clean));
}

// ─────────────────────────────────────────────────────────────────────────
// output.rs — render_results (async; all format branches via file output)
// ─────────────────────────────────────────────────────────────────────────

async fn render_results_to_file(
    mut args: ScanArgs,
    results: Vec<ScanResult>,
    urls: Vec<String>,
    tag: &str,
) -> String {
    let path = temp_out_path(tag);
    args.output = Some(path.clone());
    let state = make_scan_state(results);
    let _ = render_results(
        &args,
        &state,
        &urls,
        std::time::Duration::from_millis(7),
        42,
        false,
    )
    .await;
    let content = std::fs::read_to_string(&path).expect("output file written");
    let _ = std::fs::remove_file(&path);
    content
}

#[tokio::test]
async fn test_render_results_json_writes_envelope() {
    let mut args = default_scan_args();
    args.format = "json".to_string();
    let results = vec![reflected_result("https://example.com", "q", "<x>")];
    let urls = vec!["https://example.com".to_string()];
    let content = render_results_to_file(args, results, urls, "results_json").await;
    let v: serde_json::Value = serde_json::from_str(&content).expect("valid json");
    assert_eq!(v["meta"]["findings_count"], 1);
    assert_eq!(v["meta"]["total_requests"], 42);
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert_eq!(v["meta"]["target_summary"][0]["status"], "findings");
}

#[tokio::test]
async fn test_render_results_jsonl_meta_then_findings() {
    let mut args = default_scan_args();
    args.format = "jsonl".to_string();
    let results = vec![reflected_result("https://example.com", "q", "<x>")];
    let urls = vec!["https://example.com".to_string()];
    let content = render_results_to_file(args, results, urls, "results_jsonl").await;
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected meta line + one finding");
    let meta: serde_json::Value = serde_json::from_str(lines[0]).expect("meta json");
    assert_eq!(meta["meta"]["findings_count"], 1);
    let finding: serde_json::Value = serde_json::from_str(lines[1]).expect("finding json");
    assert_eq!(finding["param"], "q");
}

#[tokio::test]
async fn test_render_results_markdown() {
    let mut args = default_scan_args();
    args.format = "markdown".to_string();
    let results = vec![reflected_result("https://example.com", "q", "<x>")];
    let content = render_results_to_file(
        args,
        results,
        vec!["https://example.com".to_string()],
        "results_md",
    )
    .await;
    assert!(
        content.contains("# Dalfox Scan Results"),
        "got: {}",
        content
    );
}

#[tokio::test]
async fn test_render_results_sarif() {
    let mut args = default_scan_args();
    args.format = "sarif".to_string();
    let results = vec![reflected_result("https://example.com", "q", "<x>")];
    let content = render_results_to_file(
        args,
        results,
        vec!["https://example.com".to_string()],
        "results_sarif",
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&content).expect("valid sarif json");
    assert_eq!(v["version"], "2.1.0");
}

#[tokio::test]
async fn test_render_results_toml() {
    let mut args = default_scan_args();
    args.format = "toml".to_string();
    let results = vec![reflected_result("https://example.com", "q", "<x>")];
    let content = render_results_to_file(
        args,
        results,
        vec!["https://example.com".to_string()],
        "results_toml",
    )
    .await;
    assert!(content.contains("[[results]]"), "got: {}", content);
}

#[tokio::test]
async fn test_render_results_plain_summary() {
    let mut args = default_scan_args();
    args.format = "plain".to_string();
    let mut verified = reflected_result("https://example.com", "q", "<x>");
    verified.result_type = FindingType::Verified;
    let content = render_results_to_file(
        args,
        vec![verified],
        vec!["https://example.com".to_string()],
        "results_plain",
    )
    .await;
    // Plain renders the per-finding POC block when streaming is disabled.
    assert!(content.contains("[POC]"), "missing POC block: {}", content);
}

#[tokio::test]
async fn test_render_results_default_format_branch() {
    // An unrecognized format falls through to the "Found XSS: …" branch.
    let mut args = default_scan_args();
    args.format = "xml".to_string();
    let content = render_results_to_file(
        args,
        vec![reflected_result("https://example.com", "q", "PAY")],
        vec!["https://example.com".to_string()],
        "results_default",
    )
    .await;
    assert!(content.contains("Found XSS: q - PAY"), "got: {}", content);
}

#[tokio::test]
async fn test_render_results_only_poc_filter_drops_non_matching() {
    let mut args = default_scan_args();
    args.format = "json".to_string();
    args.only_poc = vec!["V".to_string()]; // keep only Verified
    let reflected = reflected_result("https://example.com", "q", "<x>");
    let mut verified = reflected_result("https://example.com", "id", "<y>");
    verified.result_type = FindingType::Verified;
    let content = render_results_to_file(
        args,
        vec![reflected, verified],
        vec!["https://example.com".to_string()],
        "results_onlypoc",
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&content).expect("json");
    assert_eq!(v["meta"]["findings_count"], 1);
    assert_eq!(v["findings"][0]["param"], "id");
}

#[tokio::test]
async fn test_render_results_limit_truncates() {
    let mut args = default_scan_args();
    args.format = "json".to_string();
    args.limit = Some(1);
    let results = vec![
        reflected_result("https://example.com", "q", "<x>"),
        reflected_result("https://example.com", "id", "<y>"),
    ];
    let content = render_results_to_file(
        args,
        results,
        vec!["https://example.com".to_string()],
        "results_limit",
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&content).expect("json");
    assert_eq!(v["meta"]["findings_count"], 1);
}

#[tokio::test]
async fn test_render_results_includes_waf_summary() {
    // Exercise the per-target WAF/bypass summary folding in render_results.
    let args = {
        let mut a = default_scan_args();
        a.format = "json".to_string();
        a
    };
    let url = "https://example.com".to_string();
    let path = temp_out_path("results_waf");
    let mut args = args;
    args.output = Some(path.clone());

    let state = make_scan_state(vec![reflected_result(&url, "q", "<x>")]);
    {
        let mut meta = state.target_meta.lock().await;
        meta.insert(
            url.clone(),
            serde_json::json!({
                "name": "ModSecurity",
                "bypass": { "strategy": "auto" },
            }),
        );
    }
    {
        let stats = Arc::new(MutationStats::default());
        stats.record_variant(MutationType::SlashSeparator);
        stats.record_request(false);
        stats.record_request(true);
        let mut sm = state.target_mutation_stats.lock().await;
        sm.insert(url.clone(), stats);
    }

    let _ = render_results(
        &args,
        &state,
        std::slice::from_ref(&url),
        std::time::Duration::from_millis(1),
        3,
        false,
    )
    .await;
    let content = std::fs::read_to_string(&path).expect("output written");
    let _ = std::fs::remove_file(&path);
    let v: serde_json::Value = serde_json::from_str(&content).expect("json");
    let waf = &v["meta"]["target_summary"][0]["waf"];
    assert_eq!(waf["name"], "ModSecurity");
    let applied = &waf["bypass"]["mutations_applied"];
    assert_eq!(applied[0]["type"], "SlashSeparator");
    assert_eq!(waf["bypass"]["requests_sent"], 2);
    assert_eq!(waf["bypass"]["requests_blocked"], 1);
}

#[tokio::test]
async fn test_render_results_stdout_path_returns_results() {
    // No --output → renders to stdout; the returned final_results still
    // reflects the deduped/filtered set.
    let args = {
        let mut a = default_scan_args();
        a.format = "plain".to_string();
        a
    };
    let state = make_scan_state(vec![reflected_result("https://example.com", "q", "<x>")]);
    let final_results = render_results(
        &args,
        &state,
        &["https://example.com".to_string()],
        std::time::Duration::from_millis(1),
        1,
        true, // stream_findings_enabled → skip per-finding re-render
    )
    .await;
    assert_eq!(final_results.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// logging.rs — log lines + spinner gating
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_log_helpers_emit_in_plain_mode() {
    // format=plain + not silenced → bodies execute (output goes to stdout).
    let mut args = default_scan_args();
    args.format = "plain".to_string();
    args.silence = false;
    log_info(&args, "info line");
    log_warn(&args, "warn line");
    // log_dbg is gated on the global DEBUG flag, which defaults to off here;
    // calling it exercises the early-return branch without touching globals.
    log_dbg("debug line");
}

#[test]
fn test_log_helpers_suppressed_when_silenced() {
    let args = default_scan_args(); // format=json, silence=true
    log_info(&args, "should be suppressed");
    log_warn(&args, "should be suppressed");
}

#[test]
fn test_start_spinner_returns_none_when_disabled() {
    assert!(start_spinner(true, false, "label".to_string()).is_none());
    assert!(start_spinner(false, true, "label".to_string()).is_none());
}

#[tokio::test]
async fn test_start_spinner_runs_and_stops() {
    let handle = start_spinner(true, true, "scanning".to_string());
    let (stop_tx, done_rx) = handle.expect("spinner should start when allowed and enabled");
    // Signal the spinner task to stop, then await its acknowledgement.
    let _ = stop_tx.send(());
    let _ = done_rx.await;
}

// ─────────────────────────────────────────────────────────────────────────
// input.rs — resolve_targets (target resolution, dedup, scope filters)
// ─────────────────────────────────────────────────────────────────────────

use super::input::resolve_targets;

/// Write `content` to a per-test temp file and return its path.
fn write_temp_file(tag: &str, content: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("dalfox_cov_input_{}.txt", tag));
    std::fs::write(&p, content).expect("write temp file");
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn test_resolve_targets_url_basic() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec!["https://example.com/?q=1".to_string()];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.as_str(), "https://example.com/?q=1");
    // No --user-agent → user_agent is set to an empty string sentinel.
    assert_eq!(targets[0].user_agent.as_deref(), Some(""));
}

#[tokio::test]
async fn test_resolve_targets_url_applies_cli_overrides() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec!["https://example.com/".to_string()];
    args.method = "POST".to_string();
    args.headers = vec!["X-Test: 1".to_string(), ": noname".to_string()];
    args.cookies = vec!["sid=abc".to_string()];
    args.user_agent = Some("dalfox-ua".to_string());
    args.data = Some("a=b".to_string());
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.method, "POST");
    assert_eq!(t.data.as_deref(), Some("a=b"));
    // Empty-named header is dropped; X-Test + appended User-Agent remain.
    assert!(t.headers.iter().any(|(n, v)| n == "X-Test" && v == "1"));
    assert!(t.headers.iter().any(|(n, _)| n == "User-Agent"));
    assert_eq!(t.user_agent.as_deref(), Some("dalfox-ua"));
    assert_eq!(t.cookies, vec![("sid".to_string(), "abc".to_string())]);
}

#[tokio::test]
async fn test_resolve_targets_dedupes_identical() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![
        "https://example.com/".to_string(),
        "https://example.com/".to_string(),
    ];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1, "identical url+method should dedupe");
}

#[tokio::test]
async fn test_resolve_targets_file_skips_blanks_and_comments() {
    let path = write_temp_file(
        "file_list",
        "https://a.example.com/\n# a comment\n\nhttps://b.example.com/\n",
    );
    let mut args = default_scan_args();
    args.input_type = "file".to_string();
    args.targets = vec![path];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 2);
}

#[tokio::test]
async fn test_resolve_targets_file_without_path_errors() {
    let mut args = default_scan_args();
    args.input_type = "file".to_string();
    args.targets = vec![];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

#[tokio::test]
async fn test_resolve_targets_file_missing_errors() {
    let mut args = default_scan_args();
    args.input_type = "file".to_string();
    args.targets = vec!["/nonexistent/dalfox/path/xyz.txt".to_string()];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

#[tokio::test]
async fn test_resolve_targets_invalid_input_type_errors() {
    let mut args = default_scan_args();
    args.input_type = "bogus".to_string();
    args.targets = vec!["https://example.com/".to_string()];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

#[tokio::test]
async fn test_resolve_targets_raw_http_literal() {
    let mut args = default_scan_args();
    args.input_type = "raw-http".to_string();
    args.targets = vec!["GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string()];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("example.com"));
    assert_eq!(targets[0].method, "GET");
}

#[tokio::test]
async fn test_resolve_targets_raw_http_invalid_errors() {
    let mut args = default_scan_args();
    args.input_type = "raw-http".to_string();
    // Looks raw-ish but missing a parseable request line / host.
    args.targets = vec!["NOTAMETHOD ?? HTTP/1.1\r\n\r\n".to_string()];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

#[tokio::test]
async fn test_resolve_targets_include_url_filter() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![
        "https://example.com/api/v1".to_string(),
        "https://example.com/home".to_string(),
    ];
    args.include_url = vec![".*/api/.*".to_string()];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert!(targets[0].url.as_str().contains("/api/"));
}

#[tokio::test]
async fn test_resolve_targets_exclude_url_filter() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![
        "https://example.com/admin".to_string(),
        "https://example.com/home".to_string(),
    ];
    args.exclude_url = vec![".*admin.*".to_string()];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert!(!targets[0].url.as_str().contains("admin"));
}

#[tokio::test]
async fn test_resolve_targets_scope_filter_emptying_all_errors() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec!["https://example.com/home".to_string()];
    args.include_url = vec!["this-matches-nothing".to_string()];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

#[tokio::test]
async fn test_resolve_targets_out_of_scope_domain_filter() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![
        "https://keep.example.com/".to_string(),
        "https://evil.com/".to_string(),
    ];
    args.out_of_scope = vec!["evil.com".to_string()];
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("keep.example.com"));
}

#[tokio::test]
async fn test_resolve_targets_out_of_scope_file() {
    let path = write_temp_file("oos", "evil.com\n# comment\n");
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![
        "https://keep.example.com/".to_string(),
        "https://evil.com/".to_string(),
    ];
    args.out_of_scope_file = Some(path);
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("keep.example.com"));
}

#[tokio::test]
async fn test_resolve_targets_cookie_from_raw_file() {
    let path = write_temp_file(
        "cookie_raw",
        "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc; foo=bar\r\n\r\n",
    );
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec!["https://example.com/".to_string()];
    args.cookie_from_raw = Some(path);
    let targets = resolve_targets(&args).await.expect("resolve ok");
    assert_eq!(targets.len(), 1);
    let cookies = &targets[0].cookies;
    assert!(cookies.iter().any(|(k, v)| k == "sid" && v == "abc"));
    assert!(cookies.iter().any(|(k, v)| k == "foo" && v == "bar"));
}

#[tokio::test]
async fn test_resolve_targets_parse_error_errors() {
    let mut args = default_scan_args();
    args.input_type = "url".to_string();
    // A scheme that parse_target_with_method can't turn into a usable target.
    args.targets = vec!["http://".to_string()];
    assert!(matches!(
        resolve_targets(&args).await,
        Err(ScanOutcome::Error)
    ));
}

// ─────────────────────────────────────────────────────────────────────────
// mod.rs — emit_error (structured stderr error for each format)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_emit_error_renders_all_format_branches() {
    // emit_error writes to stderr; we just exercise each format branch so a
    // formatting regression (e.g. a serde panic) would surface here.
    super::emit_error("json", crate::cmd::error_codes::NO_TARGETS, "no targets");
    super::emit_error("jsonl", crate::cmd::error_codes::PARSE_ERROR, "bad parse");
    super::emit_error("plain", crate::cmd::error_codes::FILE_READ_ERROR, "io fail");
}
