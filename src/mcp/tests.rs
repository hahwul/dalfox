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
        insecure: true,
        target: target.to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        encoders: vec!["none".to_string()],
        timeout: 1,
        scan_timeout: 0,
        delay: 0,
        follow_redirects: false,
        proxy: None,
        include_request: false,
        include_response: false,
        skip_mining: false,
        skip_discovery: false,
        deep_scan: false,
        skip_ast_analysis: false,
        analyze_external_js: false,
        detect_outdated_libs: false,
        blind_callback_url: None,
        workers: 1,
        rate_limit: 0,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE as f64,
        remote_payloads: vec![],
        remote_wordlists: vec![],
        max_payloads_per_param: 0,
        wait: false,
        wait_timeout_sec: 300,
    }
}

fn default_scan_args(target: &str) -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![target.to_string()],
        timeout: 1,
        silence: true,
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
        encoders: vec!["none".to_string()],
        waf_min_confidence: 0.0,
        ..Default::default()
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
    let a = crate::utils::make_scan_id("https://example.com");
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
async fn test_run_job_sets_error_on_unreachable_target() {
    // A parseable but unreachable target must end as Error with a
    // connection-failed message, mirroring preflight_dalfox — not finish
    // `done` with 0 findings, which a client can't tell apart from
    // "scanned, no XSS".
    let mcp = DalfoxMcp::new();
    let scan_id = "job-unreachable".to_string();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(scan_id.clone(), test_job(JobStatus::Queued, None));
    }

    let mut args = default_scan_args("http://127.0.0.1:1/");
    args.targets = vec!["http://127.0.0.1:1/".to_string()];
    args.timeout = 2;
    mcp.run_job(scan_id.clone(), Arc::new(args)).await;

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    let job = jobs.get(&scan_id).expect("job exists");
    assert_eq!(job.status, JobStatus::Error);
    assert!(
        job.error_message
            .as_deref()
            .is_some_and(|m| m.contains("unreachable") && m.contains("CONNECTION_FAILED")),
        "expected connection-failed error message, got {:?}",
        job.error_message
    );
}

/// A target that reflects while "authenticated" and answers `401` to everything
/// once `healthy_hits` requests have been served. The post-scan session probe is
/// the last request `run_job` makes, so it always lands after the flip.
async fn spawn_expiring_target(healthy_hits: usize) -> (String, tokio::task::JoinHandle<()>) {
    use axum::http::StatusCode;
    use axum::routing::any;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    let hits = Arc::new(AtomicUsize::new(0));
    let handler = {
        let hits = hits.clone();
        move || {
            let hits = hits.clone();
            async move {
                if hits.fetch_add(1, AtomicOrdering::SeqCst) < healthy_hits {
                    (
                        StatusCode::OK,
                        [("content-type", "text/html; charset=utf-8")],
                        "<html><body><div>ok</div></body></html>".to_string(),
                    )
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        [("content-type", "text/html; charset=utf-8")],
                        "<html><body>session expired</body></html>".to_string(),
                    )
                }
            }
        }
    };
    let app = axum::Router::new()
        .route("/", any(handler.clone()))
        .route("/{*rest}", any(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind expiring target");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    (format!("http://{}", addr), handle)
}

/// Run an MCP job to completion and return its settled (status, error_message).
async fn run_mcp_job(scan_id: &str, args: ScanArgs) -> (JobStatus, Option<String>) {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(scan_id.to_string(), test_job(JobStatus::Queued, None));
    }
    mcp.run_job(scan_id.to_string(), Arc::new(args)).await;
    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    let job = jobs.get(scan_id).expect("job exists");
    (job.status.clone(), job.error_message.clone())
}

// Issue #1273 on the MCP surface. A scan whose session dies mid-run used to
// settle `done` with zero findings, which an agent cannot tell apart from
// "scanned, no XSS" — the silent false negative the CLI already guards against.
#[tokio::test]
async fn test_run_job_reports_a_session_that_died_mid_scan() {
    let (base, server) = spawn_expiring_target(3).await;
    let target = format!("{}/?a=1&b=2", base);
    let mut args = default_scan_args(&target);
    args.timeout = 5;
    // Credentials are what switch monitoring on, here as on the CLI.
    args.cookies = vec!["sid=deadbeef".to_string()];
    args.skip_mining = true;

    let (status, error) = run_mcp_job("mcp-session-lost", args).await;
    server.abort();

    assert_eq!(
        status,
        JobStatus::Error,
        "a scan that lost its session must not settle as a clean done"
    );
    let error = error.expect("error_message must name the signal");
    assert!(
        error.starts_with(crate::cmd::error_codes::SESSION_LOST),
        "error_message must be machine-matchable: {error}"
    );
    assert!(
        error.contains("401"),
        "the triggering signal is carried verbatim: {error}"
    );
}

// The other baseline path: `skip_ast_analysis` leaves no preflight response to
// fingerprint, so the scan pays for one dedicated capture request instead.
#[tokio::test]
async fn test_run_job_detects_session_loss_without_the_ast_preflight() {
    let (base, server) = spawn_expiring_target(3).await;
    let mut args = default_scan_args(&format!("{}/?a=1", base));
    args.timeout = 5;
    args.cookies = vec!["sid=deadbeef".to_string()];
    args.skip_mining = true;
    args.skip_ast_analysis = true;

    let (status, error) = run_mcp_job("mcp-session-lost-no-ast", args).await;
    server.abort();

    assert_eq!(
        status,
        JobStatus::Error,
        "the dedicated-capture path must detect loss too: {error:?}"
    );
    assert!(
        error
            .as_deref()
            .is_some_and(|m| m.starts_with(crate::cmd::error_codes::SESSION_LOST)),
        "{error:?}"
    );
}

// The control: same credentials against a target that never expires. Monitoring
// must not turn a healthy authenticated scan into an error.
#[tokio::test]
async fn test_run_job_with_a_live_session_still_settles_done() {
    let (base, server) = spawn_expiring_target(usize::MAX).await;
    let target = format!("{}/?a=1", base);
    let mut args = default_scan_args(&target);
    args.timeout = 5;
    args.cookies = vec!["sid=deadbeef".to_string()];
    args.skip_mining = true;

    let (status, error) = run_mcp_job("mcp-session-alive", args).await;
    server.abort();

    assert_eq!(status, JobStatus::Done, "error_message={error:?}");
    assert!(error.is_none(), "{error:?}");
}

// Monitoring is opt-in-by-context: with no credentials there is no session to
// lose, so an expiring target must not be reported as a session loss.
#[tokio::test]
async fn test_run_job_without_credentials_is_untouched_by_session_monitoring() {
    let (base, server) = spawn_expiring_target(3).await;
    let target = format!("{}/?a=1", base);
    let mut args = default_scan_args(&target);
    args.timeout = 5;
    args.skip_mining = true;

    let (status, error) = run_mcp_job("mcp-session-none", args).await;
    server.abort();

    assert_eq!(
        status,
        JobStatus::Done,
        "an unauthenticated scan has no session to lose: {error:?}"
    );
    assert!(error.is_none(), "{error:?}");
}

#[tokio::test]
async fn test_mark_job_error_sync_preserves_terminal_status() {
    // Regression for the run_job parse-error path. run_job flips the job to
    // Running and releases the jobs lock before parse_target runs, so a
    // `cancel_scan_dalfox` racing the (now stderr-widened) parse-error window
    // can set Cancelled first. The parse-error path routes through
    // mark_job_error_sync — whose `!is_terminal()` guard must leave that
    // Cancelled state (and its finished_at_ms) intact rather than clobbering
    // it to Error and losing the user's cancel. Exercise the guard directly.
    let jobs: Arc<std::sync::Mutex<std::collections::HashMap<String, Job>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let scan_id = "job-cancel-race".to_string();
    let cancel_finished_at = now_ms();
    {
        let mut guard = jobs.lock().expect("jobs mutex poisoned");
        let mut job = Job::new_queued("http://[bad".to_string());
        job.status = JobStatus::Cancelled;
        job.finished_at_ms = Some(cancel_finished_at);
        guard.insert(scan_id.clone(), job);
    }

    mark_job_error_sync(&jobs, &scan_id, "parse_target failed: bad".to_string());

    let guard = jobs.lock().expect("jobs mutex poisoned");
    let job = guard.get(&scan_id).expect("job exists");
    assert_eq!(
        job.status,
        JobStatus::Cancelled,
        "a concurrent cancel must not be clobbered back to Error"
    );
    assert_eq!(
        job.finished_at_ms,
        Some(cancel_finished_at),
        "the cancel's finished_at_ms must be preserved"
    );
    assert!(
        job.error_message.is_none(),
        "no error message should be written over a terminal job"
    );
}

#[tokio::test]
async fn test_run_job_dispatches_blind_xss_when_callback_set() {
    // Regression: MCP previously accepted `blind_callback_url` but never
    // invoked blind_scanning (silent no-op). blind_scanning emits one extra
    // probe per query/body/header/cookie param, all counted in
    // `progress.requests_sent`, so a scan with a callback URL must issue
    // strictly more requests than the same scan without one.
    use axum::{Router, response::Html, routing::get};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering::Relaxed;

    async fn ok() -> Html<&'static str> {
        Html("<html><body>ok</body></html>")
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind blind target listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route("/", get(ok)).route("/{*rest}", get(ok));
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    let url = format!("http://{}/?a=1&b=2&c=3", addr);

    async fn run_count(mcp: &DalfoxMcp, id: &str, url: &str, blind: Option<String>) -> u64 {
        {
            let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
            jobs.insert(id.to_string(), test_job(JobStatus::Queued, None));
        }
        let progress = {
            let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
            jobs.get(id).expect("job").progress.clone()
        };
        let mut args = default_scan_args(url);
        args.targets = vec![url.to_string()];
        args.skip_mining = true;
        args.skip_mining_dict = true;
        args.skip_mining_dom = true;
        args.skip_ast_analysis = true;
        args.encoders = vec!["none".to_string()];
        args.blind_callback_url = blind;
        mcp.run_job(id.to_string(), Arc::new(args)).await;
        progress.requests_sent.load(Relaxed)
    }

    let mcp = DalfoxMcp::new();
    let without = run_count(&mcp, "blind-off", &url, None).await;
    let with = run_count(
        &mcp,
        "blind-on",
        &url,
        Some("http://callback.example/hook".to_string()),
    )
    .await;
    assert!(
        with > without,
        "blind_callback_url must trigger extra blind-XSS probes: with={} without={}",
        with,
        without
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
        detect_outdated_libs: true,
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

/// The MCP scan tool must not `.await` the remote payload/wordlist fetch.
///
/// The job is inserted (counting against `MAX_ACTIVE_SCANS_MCP`) before the
/// worker is spawned. A network await in between — against a caller-named host,
/// for up to the request timeout — is a window in which a cancelled tool call
/// drops this future: the worker is never spawned, nothing moves the job out of
/// `queued`, `purge_expired_jobs` only collects terminal jobs, and the capacity
/// slot is gone for the life of the process. The REST server never had this
/// hole because it spawns first and fetches inside the task; MCP now matches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scan_with_dalfox_does_not_await_remote_fetch_in_the_tool_call() {
    // A provider URL that accepts the connection and never answers, so the
    // fetch takes the full request timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind blackhole listener");
    let addr = listener.local_addr().expect("blackhole addr");
    let _blackhole = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream); // keep the connection open, never respond
        }
    });
    crate::payload::register_payload_provider(
        "mcp-blackhole-provider",
        vec![format!("http://{addr}/list.txt")],
    );

    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        // Unreachable target so the scan itself settles quickly once spawned.
        timeout: 5,
        remote_payloads: vec!["mcp-blackhole-provider".to_string()],
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };

    let outcome = tokio::time::timeout(
        Duration::from_millis(500),
        mcp.scan_with_dalfox(Parameters(params)),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "scan_with_dalfox must return as soon as the job is spawned; awaiting \
         the remote fetch here leaks the capacity slot if the call is cancelled"
    );
    let payload = parse_result_json(&outcome.unwrap().expect("scan_with_dalfox should queue"));
    assert_eq!(payload["status"], "queued");

    // And the job must actually be owned by a worker: it leaves `queued` on its
    // own rather than sitting there for the life of the process.
    for _ in 0..200 {
        {
            let jobs = mcp.lock_jobs();
            assert_eq!(jobs.len(), 1, "exactly one job was submitted");
            let job = jobs.values().next().expect("the job");
            if job.status != JobStatus::Queued {
                return;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("the submitted scan never left `queued` — no worker owns it");
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

#[test]
fn test_insecure_param_serde_defaults_true() {
    // Omitted `insecure` defaults to true (scanner posture) for both the scan
    // and preflight params; an explicit `false` opts into TLS validation.
    let scan: ScanWithDalfoxParams =
        serde_json::from_value(serde_json::json!({ "target": "https://example.com" }))
            .expect("minimal scan params deserialize");
    assert!(scan.insecure, "scan insecure should default to true");

    let scan_off: ScanWithDalfoxParams = serde_json::from_value(
        serde_json::json!({ "target": "https://example.com", "insecure": false }),
    )
    .expect("scan params with insecure=false deserialize");
    assert!(!scan_off.insecure);

    let pre: PreflightDalfoxParams =
        serde_json::from_value(serde_json::json!({ "target": "https://example.com" }))
            .expect("minimal preflight params deserialize");
    assert!(pre.insecure, "preflight insecure should default to true");

    let pre_off: PreflightDalfoxParams = serde_json::from_value(
        serde_json::json!({ "target": "https://example.com", "insecure": false }),
    )
    .expect("preflight params with insecure=false deserialize");
    assert!(!pre_off.insecure);
}

#[test]
fn test_waf_and_remote_params_serde() {
    // Omitted WAF / remote fields fall back to the CLI/server defaults instead
    // of being silently hardcoded inside the scan path.
    let defaults: ScanWithDalfoxParams =
        serde_json::from_value(serde_json::json!({ "target": "https://example.com" }))
            .expect("minimal scan params deserialize");
    assert_eq!(defaults.waf_bypass, "auto");
    assert!(!defaults.skip_waf_probe);
    assert!(defaults.force_waf.is_none());
    assert!(!defaults.waf_evasion);
    // Compared at f32 precision (the width `ScanArgs`/the WAF subsystem
    // actually use) rather than a raw f64 `==`: the MCP field is f64 purely
    // so the tool schema's default renders cleanly (see
    // `default_waf_min_confidence`), and an f32→f64 widening comparison here
    // would be exactly the precision trap that function's doc comment warns
    // about.
    assert_eq!(
        defaults.waf_min_confidence as f32,
        crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE
    );
    assert!(defaults.remote_payloads.is_empty());
    assert!(defaults.remote_wordlists.is_empty());

    // Explicit values deserialize through to the params struct (and thus to
    // ScanArgs), no longer ignored as they were before.
    let set: ScanWithDalfoxParams = serde_json::from_value(serde_json::json!({
        "target": "https://example.com",
        "waf_bypass": "off",
        "skip_waf_probe": true,
        "force_waf": "cloudflare",
        "waf_evasion": true,
        "waf_min_confidence": 0.75,
        "remote_payloads": ["portswigger"],
        "remote_wordlists": ["burp"],
    }))
    .expect("scan params with WAF/remote fields deserialize");
    assert_eq!(set.waf_bypass, "off");
    assert!(set.skip_waf_probe);
    assert_eq!(set.force_waf.as_deref(), Some("cloudflare"));
    assert!(set.waf_evasion);
    assert_eq!(set.waf_min_confidence, 0.75);
    assert_eq!(set.remote_payloads, vec!["portswigger".to_string()]);
    assert_eq!(set.remote_wordlists, vec!["burp".to_string()]);
}

#[test]
fn test_waf_min_confidence_default_renders_clean_in_json_schema() {
    // Regression test: the tool schema's `default` for `waf_min_confidence`
    // must render as a clean `0.3`, not the f32→f64 widening artifact
    // `0.30000001192092896` that `DEFAULT_WAF_MIN_CONFIDENCE as f64` would
    // produce (serde_json's `Value::Number` only has an f64 variant, so any
    // f32 default is widened when the schema is built).
    let value = serde_json::to_value(default_waf_min_confidence()).unwrap();
    assert_eq!(value, serde_json::json!(0.3));
    assert_eq!(value.to_string(), "0.3");

    // The literal must still agree with the canonical CLI/ScanArgs default at
    // the precision that actually governs scanning behavior (f32), so the two
    // can't silently drift apart if the canonical default ever changes.
    assert_eq!(
        default_waf_min_confidence() as f32,
        crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE
    );
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
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: None,
            offset: 0,
            limit: 0,
        }))
        .await
        .expect("list_scans should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["total"], 2);
    assert_eq!(payload["scans"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_scans_orders_newest_first_and_paginates() {
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        for (id, q) in [("oldest", 1_000_i64), ("middle", 2_000), ("newest", 3_000)] {
            let mut job = test_job(JobStatus::Done, Some(vec![]));
            job.target_url = format!("https://example.com/{id}");
            job.queued_at_ms = q;
            jobs.insert(id.to_string(), job);
        }
    }

    // Page 1: first two, newest-first.
    let resp = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: None,
            offset: 0,
            limit: 2,
        }))
        .await
        .expect("list_scans should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["total"], 3);
    let scans = payload["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 2);
    assert_eq!(scans[0]["scan_id"], "newest");
    assert_eq!(scans[1]["scan_id"], "middle");
    assert_eq!(payload["pagination"]["returned"], 2);
    assert_eq!(payload["pagination"]["has_more"], true);

    // Page 2: the remaining (oldest) entry.
    let resp2 = mcp
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: None,
            offset: 2,
            limit: 2,
        }))
        .await
        .expect("list_scans should succeed");
    let payload2 = parse_result_json(&resp2);
    let scans2 = payload2["scans"].as_array().unwrap();
    assert_eq!(scans2.len(), 1);
    assert_eq!(scans2[0]["scan_id"], "oldest");
    assert_eq!(payload2["pagination"]["has_more"], false);
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
            offset: 0,
            limit: 0,
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
async fn test_cancel_scan_on_terminal_job_is_a_noop() {
    // Cancelling a scan that already finished must not claim `cancelled: true`
    // — nothing was actually stopped, and the status must not change.
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(
            "done-job".to_string(),
            test_job(JobStatus::Done, Some(vec![])),
        );
    }

    let cancel_resp = mcp
        .cancel_scan_dalfox(Parameters(CancelScanDalfoxParams {
            scan_id: "done-job".to_string(),
        }))
        .await
        .expect("cancel should succeed (as a no-op)");
    let cancel_payload = parse_result_json(&cancel_resp);
    assert_eq!(cancel_payload["cancelled"], false);
    assert_eq!(cancel_payload["previous_status"], "done");

    let result = mcp
        .get_results_dalfox(Parameters(get_params("done-job")))
        .await
        .expect("job should still be retrievable");
    let payload = parse_result_json(&result);
    assert_eq!(payload["status"], "done");
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
        insecure: true,
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
        encoders: vec!["url".to_string(), "html".to_string()],
        max_payloads_per_param: 0,
        deep_scan: false,
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
        insecure: true,
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
        encoders: vec!["url".to_string(), "html".to_string()],
        max_payloads_per_param: 0,
        deep_scan: false,
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
        insecure: true,
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
        encoders: vec!["url".to_string(), "html".to_string()],
        max_payloads_per_param: 0,
        deep_scan: false,
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
async fn test_get_results_error_with_partial_params_reports_honest_pct() {
    // Regression for L1: a scan that settled `error` (e.g. worker panics) left
    // some parameters unfinished, so `run_job` must NOT promote params_tested to
    // params_total. get_results_dalfox then reports the honest partial percentage
    // instead of a misleading 100% that reads as a clean finish. This guards the
    // reporting contract the run_job promotion-gating fix upholds.
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        let job = test_job(JobStatus::Error, Some(vec![]));
        job.progress
            .params_total
            .store(10, std::sync::atomic::Ordering::Relaxed);
        job.progress
            .params_tested
            .store(7, std::sync::atomic::Ordering::Relaxed);
        jobs.insert("error-partial".to_string(), job);
    }

    let resp = mcp
        .get_results_dalfox(Parameters(get_params("error-partial")))
        .await
        .expect("get_results should succeed");
    let payload = parse_result_json(&resp);
    assert_eq!(
        payload["progress"]["estimated_completion_pct"], 70,
        "an error scan with 7/10 params tested must report 70%, not 100%"
    );
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
        .list_scans_dalfox(Parameters(ListScansDalfoxParams {
            status: None,
            offset: 0,
            limit: 0,
        }))
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
        let mut job = test_job(JobStatus::Done, Some(vec![]));
        job.target_url = "https://example.com/?q=x".to_string();
        jobs.insert("done-del".to_string(), job);
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
    // The response must carry `target` for parity with REST purge / MCP cancel.
    assert_eq!(payload["target"], "https://example.com/?q=x");

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
        detection_method: crate::scanning::result::FindingMethod::Reflection,
        confidence: Some(crate::scanning::result::Confidence::Low),
        confidence_reason: String::new(),
        new_since_baseline: None,
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
            offset: 0,
            limit: 0,
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
async fn test_scan_with_dalfox_rejects_zero_workers() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        workers: 0,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("zero workers must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("workers must be between"));
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_workers_over_max() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        workers: MAX_WORKERS + 1,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("workers over MAX_WORKERS must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("workers must be between"));
}

#[tokio::test]
async fn test_scan_with_dalfox_accepts_workers_at_max() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        workers: MAX_WORKERS,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    mcp.scan_with_dalfox(Parameters(params))
        .await
        .expect("workers == MAX_WORKERS must be accepted");
}

#[tokio::test]
async fn test_scan_with_dalfox_accepts_rate_limit() {
    // F2: a per-call rate_limit is accepted and the scan queues normally.
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        rate_limit: 5,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("scan with rate_limit must queue");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["status"], "queued");
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_scan_timeout_over_max() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        scan_timeout: MAX_SCAN_TIMEOUT_SECS + 1,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("scan_timeout over the ceiling must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("scan_timeout must be between"));
}

#[tokio::test]
async fn test_scan_with_dalfox_accepts_scan_timeout_zero() {
    // 0 means "no budget" and must be accepted (it's the default-equivalent).
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        scan_timeout: 0,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    mcp.scan_with_dalfox(Parameters(params))
        .await
        .expect("scan_timeout == 0 (unbounded) must be accepted");
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_max_payloads_over_cap() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        max_payloads_per_param: MAX_PAYLOADS_PER_PARAM_MCP + 1,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("max_payloads_per_param over MCP cap must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("max_payloads_per_param"));
}

#[tokio::test]
async fn test_scan_with_dalfox_accepts_max_payloads_per_param() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        max_payloads_per_param: 25,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    mcp.scan_with_dalfox(Parameters(params))
        .await
        .expect("reasonable max_payloads_per_param must queue");
}

#[tokio::test]
async fn test_max_payloads_per_param_serde_default_zero() {
    let params: ScanWithDalfoxParams =
        serde_json::from_value(serde_json::json!({ "target": "https://example.com" }))
            .expect("serde");
    assert_eq!(params.max_payloads_per_param, 0);
    assert!(!params.wait);
    assert_eq!(params.wait_timeout_sec, 300);
}

#[tokio::test]
async fn test_scan_with_dalfox_wait_rejects_zero_timeout() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        wait: true,
        wait_timeout_sec: 0,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("wait=true with wait_timeout_sec=0 must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("wait_timeout_sec"));
}

#[tokio::test]
async fn test_scan_with_dalfox_wait_returns_terminal_on_unreachable() {
    // Unreachable target finishes quickly as error; wait=true should surface it
    // without requiring a separate get_results call.
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        wait: true,
        wait_timeout_sec: 15,
        skip_mining: true,
        skip_discovery: true,
        param: vec!["q".to_string()],
        max_payloads_per_param: 3,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("wait mode should return a tool result");
    let payload = parse_result_json(&resp);
    let status = payload["status"].as_str().expect("status");
    assert!(
        matches!(status, "done" | "error" | "cancelled"),
        "wait mode must return a terminal status, got {status}"
    );
    assert!(
        payload.get("wait_timed_out").is_none() || payload["wait_timed_out"] == false,
        "fast-failing target should not set wait_timed_out"
    );
    assert!(payload.get("scan_id").is_some());
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

// ─────────────────────────────────────────────────────────────────────────
// mcp/mod.rs — analyze_external_js field on ScanWithDalfoxParams is wired
// through to ScanArgs and does not cause scan_with_dalfox to reject.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_scan_with_dalfox_analyze_external_js_queues_successfully() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        analyze_external_js: true,
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let resp = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect("analyze_external_js: true must queue without error");
    let payload = parse_result_json(&resp);
    assert_eq!(payload["status"], "queued");
    assert!(
        payload["scan_id"].as_str().is_some(),
        "scan_id must be present in queue response"
    );
}

/// run_job with analyze_external_js=true must produce findings that reference
/// the external JS file. Calls run_job directly (no polling) so the assertion
/// on job.results is deterministic.
#[tokio::test]
async fn test_run_scan_job_analyze_external_js_produces_external_js_findings() {
    use axum::{Router, http::header, response::Html, routing::get};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    // Host HTML: declares <script id="eval-me"> so the AST analyzer can
    // resolve getElementById('eval-me').innerText as an eval-equivalent sink.
    async fn html_page() -> Html<&'static str> {
        Html(
            r#"<html><body>
<script id="eval-me"></script>
<script src="/app.js"></script>
</body></html>"#,
        )
    }
    async fn app_js() -> impl axum::response::IntoResponse {
        (
            [(header::CONTENT_TYPE, "application/javascript")],
            r#"document.getElementById('eval-me').innerText = location.hash.substring(1);"#,
        )
    }

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ext-js mcp test server");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(html_page))
            .route("/app.js", get(app_js));
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let scan_id = "ext-js-run-job".to_string();
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
        jobs.insert(
            scan_id.clone(),
            crate::job::Job::new_queued(format!("http://{addr}/")),
        );
    }

    let mut args = default_scan_args(&format!("http://{addr}/"));
    args.targets = vec![format!("http://{addr}/")];
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_xss_scanning = true;
    args.skip_ast_analysis = false;
    args.analyze_external_js = true;
    args.encoders = vec!["none".to_string()];

    mcp.run_job(scan_id.clone(), Arc::new(args)).await;

    let jobs = mcp.jobs.lock().expect("jobs mutex poisoned");
    let job = jobs.get(&scan_id).expect("job must exist after run_job");
    let results = job
        .results
        .as_ref()
        .expect("job.results must be set after run_job");
    assert!(
        results
            .iter()
            .any(|r| r.message_str.contains("external JS")),
        "expected at least one finding referencing external JS; got: {results:?}"
    );
}

// ---------------------------------------------------------------------------
// Method / encoder normalization at the MCP boundary.
//
// The MCP request bypasses clap's value parsers exactly like a config file
// does (see `ScanConfig::normalize_and_validate`). `method` is put on the wire
// verbatim and compared case-sensitively downstream, so an un-normalized
// `"post"` was sent as the literal extension verb `post` — which real servers
// answer with 405/501 — and `"GET junk"` failed `Method::from_str` and silently
// degraded to GET. Either way the scan settled `done` with zero findings and no
// error, indistinguishable from a genuinely clean target.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_scan_with_dalfox_sends_uppercased_method_on_the_wire() {
    use axum::{Router, extract::Request, response::Html, routing::any};
    use std::net::{Ipv4Addr, SocketAddr};

    let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let seen_for_app = seen.clone();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind method-recorder listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route(
            "/{*rest}",
            any(move |req: Request| {
                let seen = seen_for_app.clone();
                async move {
                    seen.lock()
                        .expect("seen mutex poisoned")
                        .push(req.method().as_str().to_string());
                    Html("<html><body>ok</body></html>")
                }
            }),
        );
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        // Lowercase, as an agent may well send it.
        method: "post".to_string(),
        skip_mining: true,
        skip_ast_analysis: true,
        max_payloads_per_param: 1,
        wait: true,
        wait_timeout_sec: 30,
        ..default_scan_params(&format!("http://{addr}/page?q=a"))
    };
    mcp.scan_with_dalfox(Parameters(params))
        .await
        .expect("lowercase method must be accepted and normalized, not rejected");

    let methods = seen.lock().expect("seen mutex poisoned").clone();
    assert!(
        !methods.is_empty(),
        "the scan must have reached the target at least once"
    );
    assert!(
        !methods.iter().any(|m| m == "post"),
        "no request may go out with the un-normalized lowercase verb; saw {methods:?}"
    );
    assert!(
        methods.iter().all(|m| *m == m.to_ascii_uppercase()),
        "every wire method must be uppercase; saw {methods:?}"
    );
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_unsupported_method() {
    let mcp = DalfoxMcp::new();
    for bad in ["TRACE", "GET junk", "   "] {
        let params = ScanWithDalfoxParams {
            method: bad.to_string(),
            ..default_scan_params("http://127.0.0.1:1/?q=a")
        };
        let err = mcp
            .scan_with_dalfox(Parameters(params))
            .await
            .err()
            .unwrap_or_else(|| panic!("method {bad:?} must be rejected"));
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }
}

#[tokio::test]
async fn test_scan_with_dalfox_rejects_unknown_encoder() {
    let mcp = DalfoxMcp::new();
    let params = ScanWithDalfoxParams {
        encoders: vec!["url".to_string(), "urlencode".to_string()],
        ..default_scan_params("http://127.0.0.1:1/?q=a")
    };
    let err = mcp
        .scan_with_dalfox(Parameters(params))
        .await
        .expect_err("an unknown encoder silently shrinks coverage and must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("unknown encoder 'urlencode'"),
        "got: {}",
        err.message
    );
}

#[tokio::test]
async fn test_preflight_dalfox_rejects_bad_method_and_encoder() {
    let mcp = DalfoxMcp::new();
    fn preflight_params(target: &str) -> PreflightDalfoxParams {
        PreflightDalfoxParams {
            target: target.to_string(),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 1,
            proxy: None,
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: true,
            encoders: vec!["none".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
        }
    }

    let err = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            method: "TRACE".to_string(),
            ..preflight_params("http://127.0.0.1:1/?q=a")
        }))
        .await
        .expect_err("unsupported method must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

    let err = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            encoders: vec!["base-64".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
            ..preflight_params("http://127.0.0.1:1/?q=a")
        }))
        .await
        .expect_err("unknown encoder must be rejected");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
}

#[tokio::test]
async fn test_preflight_dalfox_reports_the_normalized_method() {
    use axum::{Router, response::Html, routing::any};
    use std::net::{Ipv4Addr, SocketAddr};

    async fn ok() -> Html<&'static str> {
        Html("<html><body>ok</body></html>")
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind preflight listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route("/{*rest}", any(ok));
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let mcp = DalfoxMcp::new();
    let res = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            target: format!("http://{addr}/page?q=a"),
            param: vec![],
            method: "post".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 5,
            proxy: None,
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: true,
            encoders: vec!["none".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
        }))
        .await
        .expect("lowercase method must be normalized, not rejected");

    let parsed = parse_result_json(&res);
    assert_eq!(parsed["reachable"], serde_json::json!(true));
    assert_eq!(
        parsed["method"],
        serde_json::json!("POST"),
        "preflight must report (and probe with) the normalized verb: {parsed}"
    );
}

#[tokio::test]
async fn test_scan_with_dalfox_bounds_retained_finished_scans() {
    // Parity with the REST server's --max-retained-scans: MAX_ACTIVE_SCANS_MCP
    // only counts active scans, so an agent loop of quick scans would otherwise
    // retain every result until the retention TTL expires.
    let mcp = DalfoxMcp::new();
    {
        let mut jobs = mcp.lock_jobs();
        // Recent timestamps: scan_with_dalfox purges by retention TTL first, so
        // epoch-ish values would be swept before the cap ever applies.
        let base = now_ms() - MAX_RETAINED_SCANS_MCP as i64;
        for i in 0..MAX_RETAINED_SCANS_MCP {
            let mut job = test_job(JobStatus::Done, None);
            job.finished_at_ms = Some(base + i as i64);
            jobs.insert(format!("old{:05}", i), job);
        }
    }

    let resp = mcp
        .scan_with_dalfox(Parameters(default_scan_params("http://127.0.0.1:1/")))
        .await
        .expect("scan_with_dalfox should queue");
    let scan_id = parse_result_json(&resp)["scan_id"]
        .as_str()
        .expect("scan_id")
        .to_string();

    let jobs = mcp.lock_jobs();
    assert_eq!(
        jobs.len(),
        MAX_RETAINED_SCANS_MCP,
        "the map must settle at the cap, not grow past it"
    );
    assert!(jobs.contains_key(&scan_id), "the new scan is retained");
    assert!(
        !jobs.contains_key("old00000"),
        "the oldest finished scan is evicted"
    );
}

// ---------------------------------------------------------------------------
// Proxy: accepted, then silently resolved away
//
// `Target::build_client` resolves the proxy with `reqwest::Proxy::all(..).ok()`
// and falls back to **no proxy** when that fails. A scan started with a typo'd
// `proxy` therefore connected straight to the target — bypassing the intercept
// proxy / tunnel the agent asked for, putting traffic on a path it did not
// intend — and still settled `done`, reporting a successful scan. Both MCP
// tools now refuse it at the boundary, matching the REST server.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_scan_with_dalfox_rejects_unusable_proxy() {
    let mcp = DalfoxMcp::new();
    for bad in ["not a url", "http://", "ftp://127.0.0.1:8080"] {
        let params = ScanWithDalfoxParams {
            proxy: Some(bad.to_string()),
            ..default_scan_params("http://127.0.0.1:1/")
        };
        let err = mcp
            .scan_with_dalfox(Parameters(params))
            .await
            .expect_err("an unusable proxy must be refused, not silently dropped");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("proxy"),
            "the error must name the offending option, got: {}",
            err.message
        );
    }
    assert!(
        mcp.lock_jobs().is_empty(),
        "a refused submission must not leave a queued job behind"
    );

    // A usable proxy spelling is still accepted (the scan then fails to reach
    // the dead proxy, which is a visible `error`, not a silent direct connect),
    // and an empty one still means "no proxy" rather than a hard rejection.
    for ok in ["socks5://127.0.0.1:1080", "  http://127.0.0.1:8080  ", ""] {
        let params = ScanWithDalfoxParams {
            proxy: Some(ok.to_string()),
            ..default_scan_params("http://127.0.0.1:1/")
        };
        assert!(
            mcp.scan_with_dalfox(Parameters(params)).await.is_ok(),
            "'{ok}' must be accepted"
        );
    }
}

/// `preflight_dalfox` exists to size the `scan_with_dalfox` call you are about
/// to make, so it must not accept a `max_payloads_per_param` the scan tool will
/// reject — that quotes an estimate for a scan that cannot be started.
#[tokio::test]
async fn test_preflight_dalfox_bounds_max_payloads_like_the_scan_tool() {
    let mcp = DalfoxMcp::new();
    let over = crate::job::MAX_PAYLOADS_PER_PARAM + 1;
    let err = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            target: "http://127.0.0.1:1/".to_string(),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 1,
            proxy: None,
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: true,
            encoders: vec!["none".to_string()],
            max_payloads_per_param: over,
            deep_scan: false,
        }))
        .await
        .expect_err("a cap the scan tool refuses must not be accepted for sizing");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("max_payloads_per_param"),
        "got: {}",
        err.message
    );
}

#[tokio::test]
async fn test_preflight_dalfox_rejects_unusable_proxy() {
    let mcp = DalfoxMcp::new();
    let err = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            target: "http://127.0.0.1:1/".to_string(),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 1,
            proxy: Some("ftp://127.0.0.1:8080".to_string()),
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: true,
            encoders: vec!["none".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
        }))
        .await
        .expect_err("an unusable proxy must be refused, not silently dropped");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("proxy"),
        "the error must name the offending option, got: {}",
        err.message
    );
}

/// The strongest statement of what the proxy fix buys: point preflight at a
/// **live** target through a proxy that is not listening. If the proxy is
/// honoured the probe fails and the tool reports `reachable: false`; if it were
/// silently resolved away — the old behaviour — the probe would reach the target
/// directly and report `reachable: true`, i.e. an answer about a network path
/// the caller never asked about.
#[tokio::test]
async fn test_preflight_dalfox_honours_the_proxy_instead_of_going_direct() {
    use axum::{Router, response::Html, routing::any};
    use std::net::{Ipv4Addr, SocketAddr};

    async fn ok() -> Html<&'static str> {
        Html("<html><body>ok</body></html>")
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind preflight listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route("/{*rest}", any(ok));
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    // A port nothing is listening on: bound, read, then released.
    let dead = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind throwaway listener");
    let dead_addr: SocketAddr = dead.local_addr().expect("dead addr");
    drop(dead);

    let mcp = DalfoxMcp::new();
    let res = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            target: format!("http://{addr}/page?q=a"),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 5,
            proxy: Some(format!("http://{dead_addr}")),
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: true,
            encoders: vec!["none".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
        }))
        .await
        .expect("a well-formed proxy must be accepted");

    let parsed = parse_result_json(&res);
    assert_eq!(
        parsed["reachable"],
        serde_json::json!(false),
        "the probe must go through the configured (dead) proxy, not around it: {parsed}"
    );
}

/// Exercises the estimate path on a target that actually reflects, so the shared
/// `estimate_param_requests` runs on the MCP side too, and pins the per-param
/// figures against the total the tool reports.
#[tokio::test]
async fn test_preflight_dalfox_estimate_sums_the_per_param_figures() {
    use axum::{Router, extract::Query as AxQuery, response::Html, routing::any};
    use std::collections::HashMap as StdMap;
    use std::net::{Ipv4Addr, SocketAddr};

    async fn reflect(AxQuery(q): AxQuery<StdMap<String, String>>) -> Html<String> {
        let mut body = String::from("<html><body>");
        for (k, v) in &q {
            body.push_str(&format!("<div>{k}={v}</div>"));
        }
        body.push_str("</body></html>");
        Html(body)
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind reflecting listener");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let app = Router::new().route("/{*rest}", any(reflect));
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let mcp = DalfoxMcp::new();
    let res = mcp
        .preflight_dalfox(Parameters(PreflightDalfoxParams {
            target: format!("http://{addr}/page?q=a"),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 5,
            proxy: None,
            follow_redirects: false,
            insecure: true,
            skip_mining: true,
            skip_discovery: false,
            encoders: vec!["url".to_string(), "html".to_string()],
            max_payloads_per_param: 0,
            deep_scan: false,
        }))
        .await
        .expect("reachable target must preflight");

    let parsed = parse_result_json(&res);
    assert_eq!(parsed["reachable"], serde_json::json!(true));
    let params = parsed["params"].as_array().expect("params array");
    assert!(
        !params.is_empty(),
        "reflecting target must discover a param"
    );

    let cap = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP as u64;
    let summed: u64 = params
        .iter()
        .map(|p| p["estimated_requests"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(
        parsed["estimated_total_requests"].as_u64().expect("total"),
        summed,
        "the total must be the sum of the per-param estimates: {parsed}"
    );
    for p in params {
        let est = p["estimated_requests"]
            .as_u64()
            .expect("per-param estimate");
        // Reflection and DOM are capped separately, so a scannable param costs
        // more than one cap and at most two. Counting only reflection (the old
        // behaviour) lands at or below `cap` and fails the lower bound.
        assert!(
            est > cap && est <= 2 * cap,
            "expected a two-phase estimate in ({cap}, {}], got {est} for {p}",
            2 * cap
        );
    }
}
