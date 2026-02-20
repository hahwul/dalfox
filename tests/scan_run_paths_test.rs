use dalfox::cmd::scan::{
    DEFAULT_DELAY_MS, DEFAULT_ENCODERS, DEFAULT_MAX_CONCURRENT_TARGETS,
    DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD, DEFAULT_TIMEOUT_SECS, DEFAULT_WORKERS, ScanArgs,
    run_scan,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn base_scan_args() -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: None,
        include_request: false,
        include_response: false,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: DEFAULT_METHOD.to_string(),
        user_agent: None,
        cookie_from_raw: None,
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
        delay: DEFAULT_DELAY_MS,
        proxy: None,
        follow_redirects: false,
        workers: DEFAULT_WORKERS,
        max_concurrent_targets: DEFAULT_MAX_CONCURRENT_TARGETS,
        max_targets_per_host: DEFAULT_MAX_TARGETS_PER_HOST,
        encoders: DEFAULT_ENCODERS.iter().map(|s| s.to_string()).collect(),
        remote_payloads: vec![],
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
        targets: vec![],
    }
}

fn non_network_url_args(url: &str) -> ScanArgs {
    let mut args = base_scan_args();
    args.input_type = "url".to_string();
    args.targets = vec![url.to_string()];
    args.deep_scan = true;
    args.skip_discovery = true;
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_reflection_header = true;
    args.skip_reflection_cookie = true;
    args.skip_reflection_path = true;
    args.skip_xss_scanning = true;
    args.skip_ast_analysis = true;
    args
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    path.push(format!(
        "dalfox-{}-{}-{}",
        prefix,
        std::process::id(),
        nanos
    ));
    path
}

#[tokio::test]
async fn test_run_scan_rejects_invalid_input_type() {
    let mut args = base_scan_args();
    args.input_type = "not-valid".to_string();
    args.targets = vec!["http://example.com".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_file_input_requires_path() {
    let mut args = base_scan_args();
    args.input_type = "file".to_string();
    args.targets.clear();
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_file_input_handles_missing_file() {
    let mut args = base_scan_args();
    args.input_type = "file".to_string();
    args.targets = vec!["/tmp/dalfox-missing-input-file.txt".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_raw_http_parse_error_path() {
    let mut args = base_scan_args();
    args.input_type = "raw-http".to_string();
    args.targets = vec!["INVALID RAW REQUEST".to_string()];
    args.silence = false;

    run_scan(&args).await;
}

#[tokio::test]
async fn test_run_scan_writes_json_output_for_empty_results() {
    let output_path = unique_temp_path("scan-output.json");
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.output = Some(output_path.to_string_lossy().to_string());
    args.silence = false;

    run_scan(&args).await;

    let content = std::fs::read_to_string(&output_path).expect("output should exist");
    assert_eq!(content.trim(), "[]");
    let _ = std::fs::remove_file(&output_path);
}

#[tokio::test]
async fn test_run_scan_handles_output_write_error() {
    let output_dir = unique_temp_path("scan-output-dir");
    std::fs::create_dir_all(&output_dir).expect("create temp directory");
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.output = Some(output_dir.to_string_lossy().to_string());
    args.silence = false;

    run_scan(&args).await;
    let _ = std::fs::remove_dir_all(&output_dir);
}

#[tokio::test]
async fn test_run_scan_unknown_format_fallback_path() {
    let mut args = non_network_url_args("http://example.com/?q=1");
    args.format = "custom-format".to_string();
    args.silence = true;

    run_scan(&args).await;
}
