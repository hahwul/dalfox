use super::*;
use tokio::time::{Duration, sleep};

/// Build GetResultsDalfoxParams with default pagination.
fn get_params(scan_id: &str) -> GetResultsDalfoxParams {
    GetResultsDalfoxParams {
        scan_id: scan_id.to_string(),
        offset: 0,
        limit: 0,
    }
}

/// Build a synthetic Job for tests with the given status and optional results.
fn test_job(status: JobStatus, results: Option<Vec<SanitizedResult>>) -> Job {
    let mut job = Job::new_queued(String::new());
    job.status = status.clone();
    job.results = results.map(Arc::new);
    if matches!(
        status,
        JobStatus::Done | JobStatus::Error | JobStatus::Cancelled
    ) {
        job.finished_at_ms = Some(now_ms());
    }
    job
}

fn default_scan_params(target: &str) -> ScanWithDalfoxParams {
    ScanWithDalfoxParams {
        target: target.to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        encoders: vec!["none".to_string()],
        timeout: 1,
        delay: 0,
        follow_redirects: false,
        proxy: None,
        include_request: false,
        include_response: false,
        skip_mining: false,
        skip_discovery: false,
        deep_scan: false,
        skip_ast_analysis: false,
        blind_callback_url: None,
        workers: 1,
    }
}

fn default_scan_args(target: &str) -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![target.to_string()],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 1,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
        encoders: vec!["none".to_string()],
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
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

fn parse_result_json(result: &CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    serde_json::from_str(&text).expect("json tool result")
}

#[test]
fn test_make_scan_id_shape() {
    let a = DalfoxMcp::make_scan_id("https://example.com");
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_default_constructor_initializes_empty_jobs() {
    let mcp = DalfoxMcp::default();
    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    assert!(jobs.is_empty());
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_empty_target() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        target: "".to_string(),
        ..default_scan_params("")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("empty target must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("missing required field 'target'"));
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_non_http_target() {
    let mcp = DalfoxMcp::new();
    let params = default_scan_params("ftp://example.com");
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("non-http scheme must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("http:// or https://"));
}

#[tokio::test]
async fn test_get_results_rejects_empty_scan_id() {
    let mcp = DalfoxMcp::new();
    let params = get_params("");
    let err = mcp
        .get_results_dalfox(Parameters(params))
        .await
        .expect_err("empty scan_id must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("must not be empty"));
}

#[tokio::test]
async fn test_get_results_rejects_unknown_scan_id() {
    let mcp = DalfoxMcp::new();
    let params = get_params("missing-id");
    let err = mcp
        .get_results_dalfox(Parameters(params))
        .await
        .expect_err("unknown scan_id must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("not found"));
}

#[tokio::test]
async fn test_run_job_sets_error_on_parse_failure() {
    let mcp = DalfoxMcp::new();
    let scan_id = "job-parse-fail".to_string();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(scan_id.clone(), test_job(JobStatus::Queued, None));
    }

    let mut args = default_scan_args("http://example.com");
    args.targets = vec!["not a valid target".to_string()];
    mcp.run_job(scan_id.clone(), Arc::new(args)).await;

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    let job = jobs.get(&scan_id).expect("job exists");
    assert_eq!(job.status, JobStatus::Error);
    assert!(
        job.error_message.is_some(),
        "error_message should be set on failure"
    );
    assert!(
        job.error_message.as_ref().unwrap().contains("parse_target"),
        "error_message should describe the failure"
    );
}

#[tokio::test]
async fn test_scan_with_dalfox_queues_and_can_be_queried() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        target: "http://127.0.0.1:1/?q=a".to_string(),
        include_request: true,
        include_response: true,
        param: vec!["q:query".to_string(), "id".to_string()],
        data: Some("a=1&b=2".to_string()),
        headers: vec!["X-Test: 1".to_string(), "X-Trace: 2".to_string()],
        cookies: vec!["sid=abc".to_string(), "uid=def".to_string()],
        method: "POST".to_string(),
        user_agent: Some("dalfox-mcp-test".to_string()),
        encoders: vec!["none".to_string(), "url".to_string()],
        timeout: 1,
        delay: 0,
        follow_redirects: false,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("scan_with_dalfox should queue");

    let payload = parse_result_json(&resp);
    assert_eq!(payload["status"], "queued");
    let scan_id = payload["scan_id"].as_str().expect("scan_id").to_string();

    sleep(Duration::from_millis(25)).await;
    let queried = mcp
        .get_results_dalfox(Parameters(get_params(&scan_id)))
        .await
        .expect("get_results should return a job");
    let queried_payload = parse_result_json(&queried);
    let status = queried_payload["status"].as_str().expect("status");
    assert!(matches!(status, "queued" | "running" | "done" | "error"));
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_out_of_range_timeout() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        timeout: 9999,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("out-of-range timeout must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("timeout must be between"));
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_zero_timeout() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        timeout: 0,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("zero timeout must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_out_of_range_delay() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        delay: 99_999,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("out-of-range delay must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("delay must be between"));
}

// Regression: a JSON request that still tries to set `cookie_from_raw`
// must not cause dalfox to open the supplied path. The field was removed
// from the MCP scan tool to close a server-side arbitrary-file-read /
// outbound-exfiltration vector matching v2's GHSA-35wr-x7v6-9fv2.
//
// serde's default behaviour silently drops unknown fields, so the
// request still deserializes and the scan still queues — but the host
// filesystem is never touched, even when the caller points the field at
// a sentinel "must not be read" path.
#[tokio::test]
async fn test_scan_with_dalfox_ignores_cookie_from_raw_field() {
    let mcp = DalfoxMcp::new();
    let body = serde_json::json!({
        "target": "http://127.0.0.1:1/?q=a",
        "method": "GET",
        "encoders": ["none"],
        "timeout": 1,
        "delay": 0,
        "follow_redirects": false,
        "include_request": false,
        "include_response": false,
        "skip_mining": false,
        "skip_discovery": false,
        "deep_scan": false,
        "skip_ast_analysis": false,
        "workers": 1,
        // Sentinel path that should never be opened. /dev/full would
        // surface as an io error if the read code path resurrected.
        "cookie_from_raw": "/dev/full",
    });
    let params: ScanWithDalfoxParams = serde_json::from_value(body)
        .expect("unknown field cookie_from_raw should be ignored, not error");
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("scan_with_dalfox should queue without reading cookie_from_raw");

    let payload = parse_result_json(&resp);
    assert_eq!(payload["status"], "queued");
    assert!(payload["scan_id"].as_str().is_some());
}

#[tokio::test]
async fn test_list_scans_returns_all_jobs() {
    let mcp = DalfoxMcp::new();
    // Queue two scans
    let p1 = default_scan_params("http://127.0.0.1:1/?a=1");
    let p2 = default_scan_params("http://127.0.0.1:1/?b=2");
    mcp.scan_with_dalfox(Parameters(p1)).await.unwrap();
    mcp.scan_with_dalfox(Parameters(p2)).await.unwrap();

    let resp = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams { status: None }))
        .await
        .expect("list_scans should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["total"], 2);
    assert_eq!(payload["scans"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_scans_filters_by_status() {
    let mcp = DalfoxMcp::new();
    // Manually insert a done job
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        let mut done = test_job(JobStatus::Done, Some(vec![]));
        done.target_url = "https://example.com/done".to_string();
        jobs.insert("done-job".to_string(), done);
        let mut queued = test_job(JobStatus::Queued, None);
        queued.target_url = "https://example.com/queued".to_string();
        jobs.insert("queued-job".to_string(), queued);
    }

    let resp = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: Some("done".to_string()),
        }))
        .await
        .expect("list_scans should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["total"], 1);
    assert_eq!(payload["scans"][0]["scan_id"], "done-job");
}

#[tokio::test]
async fn test_cancel_scan_removes_job() {
    let mcp = DalfoxMcp::new();
    let params = default_scan_params("http://127.0.0.1:1/?q=a");
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("queue scan");
    let scan_id = parse_result_json(&resp)["scan_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Cancel it
    let cancel_resp = mcp
        .cancel_scan_dalfox(Parameters(CancelScanDalfoxParams {
            scan_id: scan_id.clone(),
        }))
        .await
        .expect("cancel should succeed");
    let cancel_payload = parse_result_json(&cancel_resp);
    assert_eq!(cancel_payload["cancelled"], true);

    // Verify the job is still accessible but with cancelled status
    let result = mcp
        .get_results_dalfox(Parameters(get_params(&scan_id)))
        .await
        .expect("cancelled scan should still be retrievable");
    let payload = parse_result_json(&result);
    assert_eq!(payload["status"], "cancelled");
}

#[tokio::test]
async fn test_cancel_scan_rejects_unknown_id() {
    let mcp = DalfoxMcp::new();
    let err = mcp
        .cancel_scan_dalfox(Parameters(CancelScanDalfoxParams {
            scan_id: "nonexistent".to_string(),
        }))
        .await
        .expect_err("should fail for unknown scan_id");
    assert!(err.message.contains("not found"));
}

#[tokio::test]
async fn test_preflight_rejects_empty_target() {
    let mcp = DalfoxMcp::new();
    let params = PreflightDalfoxParams {
        target: "".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 10,
        proxy: None,
        follow_redirects: false,
        skip_mining: false,
        skip_discovery: false,
    };
    let err = mcp
        .preflight_dalfox(Parameters(params))
        .await
        .expect_err("empty target must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("missing required field"));
}

#[tokio::test]
async fn test_preflight_rejects_non_http_target() {
    let mcp = DalfoxMcp::new();
    let params = PreflightDalfoxParams {
        target: "ftp://example.com".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 10,
        proxy: None,
        follow_redirects: false,
        skip_mining: false,
        skip_discovery: false,
    };
    let err = mcp
        .preflight_dalfox(Parameters(params))
        .await
        .expect_err("non-http must fail");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("http:// or https://"));
}

#[tokio::test]
async fn test_preflight_unreachable_target_returns_reachable_false() {
    let mcp = DalfoxMcp::new();
    let params = PreflightDalfoxParams {
        target: "http://127.0.0.1:1/?q=test".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 1,
        proxy: None,
        follow_redirects: false,
        skip_mining: true,
        skip_discovery: true,
    };
    let resp = mcp
        .preflight_dalfox(Parameters(params))
        .await
        .expect("preflight should return success even for unreachable targets");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["reachable"], false);
    assert!(payload.get("error_code").is_some());
}

#[tokio::test]
async fn test_get_results_progress_includes_polling_hints() {
    let mcp = DalfoxMcp::new();
    // Manually insert a running job with progress
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        let job = test_job(JobStatus::Running, None);
        job.progress
            .params_total
            .store(10, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .params_tested
            .store(5, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .requests_sent
            .store(100, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .findings_so_far
            .store(2, std::sync::atomic::Ordering::Relaxed);
        jobs.insert("progress-test".to_string(), job);
    }

    let resp = mcp
        .get_results_dalfox(Parameters(get_params("progress-test")))
        .await
        .expect("get_results should succeed");
    let payload = parse_result_json(&resp);

    let progress = &payload["progress"];
    assert_eq!(progress["params_total"], 10);
    assert_eq!(progress["params_tested"], 5);
    assert_eq!(progress["requests_sent"], 100);
    assert_eq!(progress["findings_so_far"], 2);
    // Polling hint fields must exist
    assert_eq!(progress["estimated_completion_pct"], 50);
    assert!(progress["suggested_poll_interval_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_get_results_done_shows_100_pct_and_zero_poll_interval() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        let job = test_job(JobStatus::Done, Some(vec![]));
        job.progress
            .params_total
            .store(10, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .params_tested
            .store(10, std::sync::atomic::Ordering::Relaxed);
        jobs.insert("done-progress-test".to_string(), job);
    }

    let resp = mcp
        .get_results_dalfox(Parameters(get_params("done-progress-test")))
        .await
        .expect("get_results should succeed");
    let payload = parse_result_json(&resp);

    let progress = &payload["progress"];
    assert_eq!(progress["estimated_completion_pct"], 100);
    assert_eq!(progress["suggested_poll_interval_ms"], 0);
}

#[tokio::test]
async fn test_get_results_includes_timestamps() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        let mut job = test_job(JobStatus::Done, Some(vec![]));
        job.started_at_ms = Some(job.queued_at_ms + 5);
        job.finished_at_ms = Some(job.queued_at_ms + 50);
        jobs.insert("ts-job".to_string(), job);
    }
    let resp = mcp
        .get_results_dalfox(Parameters(get_params("ts-job")))
        .await
        .expect("get_results should succeed");
    let payload = parse_result_json(&resp);
    assert!(payload["queued_at_ms"].as_i64().is_some());
    assert!(payload["started_at_ms"].as_i64().is_some());
    assert!(payload["finished_at_ms"].as_i64().is_some());
    assert_eq!(payload["duration_ms"], 45);
}

#[tokio::test]
async fn test_list_scans_includes_timestamps() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(
            "ts-list".to_string(),
            test_job(JobStatus::Done, Some(vec![])),
        );
    }
    let resp = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams { status: None }))
        .await
        .expect("list_scans should succeed");
    let payload = parse_result_json(&resp);
    let entry = &payload["scans"][0];
    assert!(entry["queued_at_ms"].as_i64().is_some());
    assert!(entry["finished_at_ms"].as_i64().is_some());
}

#[tokio::test]
async fn test_delete_scan_removes_terminal_job() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(
            "done-del".to_string(),
            test_job(JobStatus::Done, Some(vec![])),
        );
    }
    let resp = mcp
        .delete_scan_dalfox(Parameters(DeleteScanDalfoxParams {
            scan_id: "done-del".to_string(),
        }))
        .await
        .expect("delete should succeed for terminal job");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["deleted"], true);
    assert_eq!(payload["previous_status"], "done");

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    assert!(!jobs.contains_key("done-del"));
}

#[tokio::test]
async fn test_delete_scan_rejects_running_job() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert("run-del".to_string(), test_job(JobStatus::Running, None));
    }
    let err = mcp
        .delete_scan_dalfox(Parameters(DeleteScanDalfoxParams {
            scan_id: "run-del".to_string(),
        }))
        .await
        .expect_err("delete must reject non-terminal jobs");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("cancel it first"));

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    assert!(jobs.contains_key("run-del"));
}

#[tokio::test]
async fn test_delete_scan_rejects_unknown_id() {
    let mcp = DalfoxMcp::new();
    let err = mcp
        .delete_scan_dalfox(Parameters(DeleteScanDalfoxParams {
            scan_id: "nonexistent".to_string(),
        }))
        .await
        .expect_err("delete must fail for unknown id");
    assert!(err.message.contains("not found"));
}

fn dummy_finding(id: u32) -> SanitizedResult {
    SanitizedResult {
        result_type: crate::scanning::result::FindingType::Reflected,
        type_description: "test".to_string(),
        inject_type: "test".to_string(),
        method: "GET".to_string(),
        data: String::new(),
        param: format!("p{}", id),
        payload: String::new(),
        evidence: String::new(),
        cwe: "CWE-79".to_string(),
        severity: "medium".to_string(),
        message_id: id,
        message_str: format!("finding-{}", id),
        location: String::new(),
        request: None,
        response: None,
    }
}

#[test]
fn test_paginate_results_first_page() {
    let findings: Vec<SanitizedResult> = (0..5).map(dummy_finding).collect();
    let (slice, pagination) = paginate_results(Some(&findings), 0, 2);
    let slice = slice.expect("slice");
    assert_eq!(slice.len(), 2);
    assert_eq!(slice[0].message_id, 0);
    assert_eq!(pagination["total"], 5);
    assert_eq!(pagination["returned"], 2);
    assert_eq!(pagination["has_more"], true);
}

#[test]
fn test_paginate_results_last_page() {
    let findings: Vec<SanitizedResult> = (0..5).map(dummy_finding).collect();
    let (slice, pagination) = paginate_results(Some(&findings), 4, 2);
    let slice = slice.expect("slice");
    assert_eq!(slice.len(), 1);
    assert_eq!(slice[0].message_id, 4);
    assert_eq!(pagination["returned"], 1);
    assert_eq!(pagination["has_more"], false);
}

#[test]
fn test_paginate_results_offset_past_end_is_empty() {
    let findings: Vec<SanitizedResult> = (0..3).map(dummy_finding).collect();
    let (slice, pagination) = paginate_results(Some(&findings), 99, 10);
    assert!(slice.expect("slice").is_empty());
    assert_eq!(pagination["returned"], 0);
    assert_eq!(pagination["has_more"], false);
}

#[test]
fn test_paginate_results_zero_limit_means_all_from_offset() {
    let findings: Vec<SanitizedResult> = (0..5).map(dummy_finding).collect();
    let (slice, pagination) = paginate_results(Some(&findings), 2, 0);
    assert_eq!(slice.expect("slice").len(), 3);
    assert_eq!(pagination["has_more"], false);
}

#[test]
fn test_paginate_results_none_results_preserves_null() {
    let (slice, pagination) = paginate_results(None, 0, 10);
    assert!(slice.is_none());
    assert_eq!(pagination["total"], 0);
    assert_eq!(pagination["has_more"], false);
}

#[tokio::test]
async fn test_get_results_pagination_end_to_end() {
    let mcp = DalfoxMcp::new();
    let findings: Vec<SanitizedResult> = (0..5).map(dummy_finding).collect();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert("pag".to_string(), test_job(JobStatus::Done, Some(findings)));
    }
    let resp = mcp
        .get_results_dalfox(Parameters(GetResultsDalfoxParams {
            scan_id: "pag".to_string(),
            offset: 1,
            limit: 2,
        }))
        .await
        .expect("get_results should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["results"].as_array().unwrap().len(), 2);
    assert_eq!(payload["pagination"]["total"], 5);
    assert_eq!(payload["pagination"]["offset"], 1);
    assert_eq!(payload["pagination"]["limit"], 2);
    assert_eq!(payload["pagination"]["returned"], 2);
    assert_eq!(payload["pagination"]["has_more"], true);
}

#[tokio::test]
async fn test_list_scans_rejects_invalid_status_filter() {
    let mcp = DalfoxMcp::new();
    let err = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: Some("bogus".to_string()),
        }))
        .await
        .expect_err("unknown status filter must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("invalid status filter"));
}

#[tokio::test]
async fn test_tick_request_count_is_scoped_per_job() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let job_a = Arc::new(AtomicU64::new(0));
    let job_b = Arc::new(AtomicU64::new(0));

    crate::REQUEST_COUNT_JOB
        .scope(job_a.clone(), async {
            crate::tick_request_count();
            crate::tick_request_count();
        })
        .await;

    crate::REQUEST_COUNT_JOB
        .scope(job_b.clone(), async {
            crate::tick_request_count();
        })
        .await;

    // Per-job scoping is the actual subject of this test. The global counter
    // (crate::REQUEST_COUNT) is shared across the entire test binary, so any
    // assertion against its delta is racy with concurrent tests that also
    // tick — verifying it here would mean serializing the whole test binary
    // for an invariant that isn't really about scoping.
    assert_eq!(job_a.load(Ordering::Relaxed), 2, "job A counter isolated");
    assert_eq!(job_b.load(Ordering::Relaxed), 1, "job B counter isolated");
}

#[tokio::test]
async fn test_tick_waf_block_is_scoped_per_job() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let job_a = Arc::new(AtomicU32::new(0));
    let job_b = Arc::new(AtomicU32::new(0));

    let a1 = crate::WAF_CONSECUTIVE_BLOCKS_JOB
        .scope(job_a.clone(), async { crate::tick_waf_block() })
        .await;
    let a2 = crate::WAF_CONSECUTIVE_BLOCKS_JOB
        .scope(job_a.clone(), async { crate::tick_waf_block() })
        .await;
    let b1 = crate::WAF_CONSECUTIVE_BLOCKS_JOB
        .scope(job_b.clone(), async { crate::tick_waf_block() })
        .await;

    assert_eq!(a1, 1, "job A first block");
    assert_eq!(a2, 2, "job A second block increments only its own counter");
    assert_eq!(b1, 1, "job B block is isolated from A");
    assert_eq!(job_a.load(Ordering::Relaxed), 2);
    assert_eq!(job_b.load(Ordering::Relaxed), 1);

    // reset_waf_consecutive under a scope clears only that scope
    crate::WAF_CONSECUTIVE_BLOCKS_JOB
        .scope(job_a.clone(), async { crate::reset_waf_consecutive() })
        .await;
    assert_eq!(job_a.load(Ordering::Relaxed), 0);
    assert_eq!(job_b.load(Ordering::Relaxed), 1, "B untouched");
}

#[tokio::test]
async fn test_purge_expired_jobs_removes_old_terminal_jobs() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        // Old terminal job — outside retention window
        let mut old = test_job(JobStatus::Done, Some(vec![]));
        old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
        jobs.insert("old".to_string(), old);
        // Recent terminal job — within retention window
        let mut fresh = test_job(JobStatus::Done, Some(vec![]));
        fresh.finished_at_ms = Some(now_ms());
        jobs.insert("fresh".to_string(), fresh);
        // Active job — must never be purged
        jobs.insert("active".to_string(), test_job(JobStatus::Running, None));
    }

    mcp.purge_expired_jobs();

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    assert!(
        !jobs.contains_key("old"),
        "old terminal job should be purged"
    );
    assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
    assert!(
        jobs.contains_key("active"),
        "active job must never be purged"
    );
}
