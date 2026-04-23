//! Dalfox MCP (Model Context Protocol) integration
//!
//! Exposes MCP tools over stdio when `dalfox mcp` is executed:
//! 1. `scan_with_dalfox`     - Start an asynchronous XSS scan on a single target URL
//! 2. `get_results_dalfox`   - Fetch status/results of a previously started scan (with polling hints)
//! 3. `list_scans_dalfox`    - List all tracked scans with their statuses
//! 4. `cancel_scan_dalfox`   - Cancel a queued or running scan
//! 5. `preflight_dalfox`     - Analyze target without attack payloads (parameter discovery + impact estimate)
//! 6. `delete_scan_dalfox`   - Remove a tracked scan from memory
//!
//! Design goals (minimal blocking server):
//! - In-memory job storage only (no persistence)
//! - Non-blocking scans via `tokio::spawn`
//! - Lean tool schemas (only input params are schematized)
//! - Result output as JSON (string content) to avoid complex schema for findings
//!
//! Example client flow (conceptual):
//!   call_tool(name="scan_with_dalfox", arguments={"target":"https://example.com"})
//!     -> {"scan_id":"<id>","status":"queued"}
//!   call_tool(name="get_results_dalfox", arguments={"scan_id":"<id>"})
//!     -> {"scan_id":"<id>","status":"running"}
//!     -> {"scan_id":"<id>","status":"done","results":[ ... ]}
//!
//! The MCP runtime (stdio JSON-RPC) is provided by the `rmcp` crate.

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use rmcp::{
    ErrorData,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    tool, tool_handler, tool_router,
};

use crate::{
    cmd::JobStatus,
    cmd::job::{
        JOB_RETENTION_SECS, Job, MAX_DELAY_MS, MAX_TIMEOUT_SECS, now_ms, parse_job_status,
        purge_expired_jobs as purge_jobs_map, send_reachability_probe,
    },
    cmd::scan::ScanArgs,
    parameter_analysis::analyze_parameters,
    scanning::result::{Result as ScanResult, SanitizedResult},
    target_parser::parse_target,
};

/// Render timestamp/duration fields into the given JSON object.
fn write_timestamps(job: &Job, out: &mut serde_json::Map<String, serde_json::Value>) {
    out.insert("queued_at_ms".into(), serde_json::json!(job.queued_at_ms));
    out.insert(
        "started_at_ms".into(),
        serde_json::json!(job.started_at_ms),
    );
    out.insert(
        "finished_at_ms".into(),
        serde_json::json!(job.finished_at_ms),
    );
    out.insert("duration_ms".into(), serde_json::json!(job.duration_ms()));
}

/// Apply (offset, limit) pagination to a result vector and return the sliced
/// payload plus a descriptor the client can use to request the next page.
///
/// - `offset` past the end yields an empty slice (not an error).
/// - `limit == 0` means "return everything from offset onward".
/// - When `results` is `None` (scan hasn't completed), returns `(None, …)`
///   with `total=0` so the client can distinguish "no findings yet" from
///   "zero findings".
fn paginate_results(
    results: Option<&Vec<SanitizedResult>>,
    offset: usize,
    limit: usize,
) -> (Option<Vec<SanitizedResult>>, serde_json::Value) {
    let Some(all) = results else {
        return (
            None,
            serde_json::json!({
                "total": 0,
                "offset": offset,
                "limit": limit,
                "returned": 0,
                "has_more": false,
            }),
        );
    };
    let total = all.len();
    let start = offset.min(total);
    let end = if limit == 0 {
        total
    } else {
        start.saturating_add(limit).min(total)
    };
    let slice = all[start..end].to_vec();
    let returned = slice.len();
    let pagination = serde_json::json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "has_more": end < total,
    });
    (Some(slice), pagination)
}

/// MCP handler state.
#[derive(Clone)]
pub struct DalfoxMcp {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    tool_router: ToolRouter<Self>,
}

impl Default for DalfoxMcp {
    fn default() -> Self {
        Self::new()
    }
}

impl DalfoxMcp {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            tool_router: Self::tool_router(),
        }
    }

    fn make_scan_id(s: &str) -> String {
        crate::utils::make_scan_id(s)
    }

    fn log(level: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        eprintln!("[{}] [{}] {}", ts, level, msg);
    }

    /// Thin wrapper that acquires the jobs lock before delegating to the
    /// shared retention helper.
    async fn purge_expired_jobs(&self) {
        let mut jobs = self.jobs.lock().await;
        purge_jobs_map(&mut jobs, JOB_RETENTION_SECS);
    }

    /// Execute a scan job (parameter discovery + scanning) using a fully prepared ScanArgs.
    async fn run_job(&self, scan_id: String, scan_args: ScanArgs) {
        // Grab shared progress counters and cancellation flag for this job
        let (progress, cancel_flag) = {
            let mut jobs = self.jobs.lock().await;
            if let Some(j) = jobs.get_mut(&scan_id) {
                if j.status == JobStatus::Cancelled
                    || j.cancelled.load(std::sync::atomic::Ordering::Relaxed)
                {
                    return;
                }
                j.status = JobStatus::Running;
                j.started_at_ms = Some(now_ms());
                (j.progress.clone(), j.cancelled.clone())
            } else {
                return;
            }
        };

        let url = scan_args
            .targets
            .first()
            .cloned()
            .unwrap_or_else(|| "<missing>".to_string());
        let include_request = scan_args.include_request;
        let include_response = scan_args.include_response;

        // Parse and hydrate a single target
        let mut target = match parse_target(&url) {
            Ok(mut t) => {
                t.method = scan_args.method.clone();
                t.timeout = scan_args.timeout;
                t.delay = scan_args.delay;
                t.proxy = scan_args.proxy.clone();
                t.follow_redirects = scan_args.follow_redirects;
                t.ignore_return = scan_args.ignore_return.clone();
                t.workers = scan_args.workers;
                t.user_agent = scan_args.user_agent.clone();
                t.headers = scan_args
                    .headers
                    .iter()
                    .filter_map(|h| h.split_once(":"))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                t.cookies = scan_args
                    .cookies
                    .iter()
                    .filter_map(|c| c.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                t.data = scan_args.data.clone();
                t
            }
            Err(e) => {
                let msg = format!("parse_target failed: {}", e);
                Self::log("ERR", &msg);
                let mut jobs = self.jobs.lock().await;
                if let Some(j) = jobs.get_mut(&scan_id) {
                    j.status = JobStatus::Error;
                    j.error_message = Some(msg);
                    j.finished_at_ms = Some(now_ms());
                }
                return;
            }
        };

        // Per-job request counter. All scanning code paths call
        // `crate::tick_request_count()` which increments both the global
        // counter and this task-local one, so concurrent scans don't
        // pollute each other's tallies. The WAF consecutive-block counter
        // gets the same per-job treatment so one scan's WAF backoff doesn't
        // throttle an unrelated scan.
        let job_requests = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let job_waf_consecutive = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let results_arc = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
        let param_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        crate::REQUEST_COUNT_JOB
            .scope(job_requests.clone(), async {
                crate::WAF_CONSECUTIVE_BLOCKS_JOB
                    .scope(job_waf_consecutive.clone(), async {
                        // Parameter discovery / mining
                        analyze_parameters(&mut target, &scan_args, None).await;

                        // Record discovered param count
                        progress.params_total.store(
                            target.reflection_params.len() as u32,
                            std::sync::atomic::Ordering::Relaxed,
                        );

                        crate::scanning::run_scanning(
                            &target,
                            Arc::new(scan_args.clone()),
                            results_arc.clone(),
                            None,
                            None,
                            param_counter.clone(),
                            Some(cancel_flag.clone()),
                        )
                        .await;
                    })
                    .await;
            })
            .await;

        progress.requests_sent.store(
            job_requests.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
        progress.params_tested.store(
            param_counter.load(std::sync::atomic::Ordering::Relaxed) as u32,
            std::sync::atomic::Ordering::Relaxed,
        );

        let sanitized = {
            let locked = results_arc.lock().await;
            progress.findings_so_far.store(
                locked.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            locked
                .iter()
                .map(|r| r.to_sanitized(include_request, include_response))
                .collect::<Vec<_>>()
        };

        // Check if cancelled during scanning
        let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

        {
            let mut jobs = self.jobs.lock().await;
            if let Some(j) = jobs.get_mut(&scan_id) {
                // Store partial or complete results
                j.results = Some(Arc::new(sanitized));
                // Only update status if not already cancelled (cancel sets status immediately)
                if j.status != JobStatus::Cancelled {
                    j.status = JobStatus::Done;
                }
                // finished_at_ms may already be set by cancel_scan_dalfox; preserve it
                // so we record the moment the user asked to stop, not when the task noticed.
                if j.finished_at_ms.is_none() {
                    j.finished_at_ms = Some(now_ms());
                }
            }
        }

        let status_label = if was_cancelled { "cancelled" } else { "finished" };
        Self::log(
            "JOB",
            &format!("scan {} scan_id={} url={}", status_label, scan_id, url),
        );
    }
}

/* ---------------------------
 * Tool Parameter Definitions
 * ---------------------------
 */

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ScanWithDalfoxParams {
    /// Target URL to scan for XSS vulnerabilities. Must start with http:// or https://.
    /// Example: "https://example.com/search?q=test"
    pub target: String,

    /// Specific parameters to test. Supports location hints via "name:location" syntax.
    /// Locations: query, body, header, cookie, path, json.
    /// Examples: ["q", "id:query", "user:body", "auth:header"]
    #[serde(default)]
    pub param: Vec<String>,

    /// HTTP method to use for requests (GET, POST, PUT, etc.).
    #[serde(default = "default_method")]
    pub method: String,

    /// Request body data for POST/PUT. Supports form-urlencoded and JSON.
    /// Example: "user=admin&pass=test" or "{\"user\":\"admin\"}"
    #[serde(default)]
    pub data: Option<String>,

    /// Custom HTTP headers. Each entry as "Name: Value".
    /// Example: ["Authorization: Bearer token", "X-Custom: value"]
    #[serde(default)]
    pub headers: Vec<String>,

    /// Cookies to include. Each entry as "name=value".
    /// Example: ["session=abc123", "lang=en"]
    #[serde(default)]
    pub cookies: Vec<String>,

    /// Custom User-Agent header string.
    #[serde(default)]
    pub user_agent: Option<String>,

    /// Path to a raw HTTP request file to extract cookies from (Cookie: header lines).
    #[serde(default)]
    pub cookie_from_raw: Option<String>,

    /// Encoding strategies to apply to payloads. Available: url, html, base64, 2url, 3url, 4url, none.
    /// Default: ["url", "html"]
    #[serde(default = "default_encoders")]
    pub encoders: Vec<String>,

    /// HTTP request timeout in seconds (1-299). Default: 10
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Delay between requests in milliseconds (0-9999). Default: 0
    #[serde(default)]
    pub delay: u64,

    /// Follow HTTP redirects (3xx). Default: false
    #[serde(default)]
    pub follow_redirects: bool,

    /// HTTP/SOCKS proxy URL. Example: "http://127.0.0.1:8080"
    #[serde(default)]
    pub proxy: Option<String>,

    /// Include the raw HTTP request text in each finding for forensic analysis.
    #[serde(default)]
    pub include_request: bool,

    /// Include the raw HTTP response body in each finding for forensic analysis.
    #[serde(default)]
    pub include_response: bool,

    /// Skip parameter mining (DOM and dictionary-based discovery). Default: false
    #[serde(default)]
    pub skip_mining: bool,

    /// Skip initial parameter discovery from HTML. Default: false
    #[serde(default)]
    pub skip_discovery: bool,

    /// Enable deep scan mode for more thorough testing. Default: false
    #[serde(default)]
    pub deep_scan: bool,

    /// Skip AST-based JavaScript analysis. Default: false
    #[serde(default)]
    pub skip_ast_analysis: bool,

    /// Blind XSS callback URL (e.g., your Burp Collaborator or interact.sh URL).
    #[serde(default)]
    pub blind_callback_url: Option<String>,

    /// Number of concurrent workers. Default: 50
    #[serde(default = "default_workers")]
    pub workers: usize,
}

fn default_method() -> String {
    crate::cmd::scan::DEFAULT_METHOD.to_string()
}
fn default_encoders() -> Vec<String> {
    crate::cmd::scan::DEFAULT_ENCODERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_timeout() -> u64 {
    crate::cmd::scan::DEFAULT_TIMEOUT_SECS
}
fn default_workers() -> usize {
    crate::cmd::scan::DEFAULT_WORKERS
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct GetResultsDalfoxParams {
    /// The scan_id returned by scan_with_dalfox when the scan was started.
    pub scan_id: String,

    /// Zero-based index of the first finding to return. Default: 0.
    /// Use with `limit` to page through large result sets.
    #[serde(default)]
    pub offset: usize,

    /// Maximum number of findings to return in this response. Omit or set
    /// to 0 to return all findings from `offset` onward.
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListScansDalfoxParams {
    /// Optional status filter: "queued", "running", "done", or "error". Omit to list all.
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CancelScanDalfoxParams {
    /// The scan_id of the scan to cancel.
    pub scan_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeleteScanDalfoxParams {
    /// The scan_id of the scan to delete from memory.
    /// The scan must be in a terminal state (done, error, cancelled).
    pub scan_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PreflightDalfoxParams {
    /// Target URL to analyze. Must start with http:// or https://.
    pub target: String,

    /// Specific parameters to test. Supports location hints via "name:location" syntax.
    #[serde(default)]
    pub param: Vec<String>,

    /// HTTP method to use. Default: GET
    #[serde(default = "default_method")]
    pub method: String,

    /// Request body data for POST/PUT.
    #[serde(default)]
    pub data: Option<String>,

    /// Custom HTTP headers. Each entry as "Name: Value".
    #[serde(default)]
    pub headers: Vec<String>,

    /// Cookies to include. Each entry as "name=value".
    #[serde(default)]
    pub cookies: Vec<String>,

    /// Custom User-Agent header string.
    #[serde(default)]
    pub user_agent: Option<String>,

    /// HTTP request timeout in seconds. Default: 10
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// HTTP/SOCKS proxy URL.
    #[serde(default)]
    pub proxy: Option<String>,

    /// Follow HTTP redirects. Default: false
    #[serde(default)]
    pub follow_redirects: bool,

    /// Skip parameter mining. Default: false
    #[serde(default)]
    pub skip_mining: bool,

    /// Skip parameter discovery. Default: false
    #[serde(default)]
    pub skip_discovery: bool,
}

/* ---------------------------
 * Tool Implementations
 * ---------------------------
 */

#[tool_router]
impl DalfoxMcp {
    /// Start an asynchronous Dalfox XSS scan (returns immediately with scan_id).
    #[tool(
        name = "scan_with_dalfox",
        description = "Start an asynchronous XSS vulnerability scan on a target URL. \
Returns immediately with {scan_id, target, status: \"queued\"}. \
Use get_results_dalfox to poll for results until status is done/error/cancelled. \
Scans for reflected, DOM-based, and stored XSS using parameter analysis, \
payload mutation, and AST-based JavaScript verification. \
Supports custom headers, cookies, POST data, and encoding strategies. \
Final results (via get_results_dalfox) include finding type \
(V=Verified, R=Reflected, A=AST-detected), severity, CWE, payload, and evidence."
    )]
    async fn scan_with_dalfox(
        &self,
        Parameters(params): Parameters<ScanWithDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let target = params.target.trim().to_string();
        if target.is_empty() {
            return Err(ErrorData::invalid_params(
                "missing required field 'target' (example: {\"target\":\"https://example.com\"})",
                None,
            ));
        }
        if !(target.starts_with("http://") || target.starts_with("https://")) {
            return Err(ErrorData::invalid_params(
                "target must start with http:// or https:// (example: \"https://example.com/page?q=test\")",
                None,
            ));
        }

        if params.timeout == 0 || params.timeout > MAX_TIMEOUT_SECS {
            return Err(ErrorData::invalid_params(
                format!(
                    "timeout must be between 1 and {} seconds (got {})",
                    MAX_TIMEOUT_SECS, params.timeout
                ),
                None,
            ));
        }
        if params.delay > MAX_DELAY_MS {
            return Err(ErrorData::invalid_params(
                format!(
                    "delay must be between 0 and {} ms (got {})",
                    MAX_DELAY_MS, params.delay
                ),
                None,
            ));
        }

        let scan_id = Self::make_scan_id(&target);

        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(scan_id.clone(), Job::new_queued(target.clone()));
        }

        Self::log(
            "JOB",
            &format!(
                "queued scan_id={} target={} include_request={} include_response={}",
                scan_id, target, params.include_request, params.include_response
            ),
        );

        // cookie_from_raw: read Cookie: line and append
        let mut all_cookies = params.cookies.clone();
        if let Some(raw_path) = &params.cookie_from_raw
            && let Ok(content) = std::fs::read_to_string(raw_path)
        {
            for line in content.lines() {
                if line.to_ascii_lowercase().starts_with("cookie:") {
                    let rest = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                    for part in rest.split(';') {
                        let trimmed = part.trim();
                        if trimmed.contains('=') {
                            all_cookies.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // Normalize encoders: if "none" present use only original payloads
        let encoders = if params.encoders.iter().any(|e| e == "none") {
            vec!["none".to_string()]
        } else {
            params.encoders.clone()
        };

        let scan_args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target.clone()],
            param: params.param.clone(),
            data: params.data.clone(),
            headers: params.headers.clone(),
            cookies: all_cookies,
            method: params.method.clone(),
            user_agent: params.user_agent.clone(),
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: params.skip_mining,
            skip_mining_dict: params.skip_mining,
            skip_mining_dom: params.skip_mining,
            only_discovery: false,
            skip_discovery: params.skip_discovery,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: params.timeout,
            delay: params.delay,
            proxy: params.proxy.clone(),
            follow_redirects: params.follow_redirects,
            ignore_return: vec![],
            output: None,
            include_request: params.include_request,
            include_response: params.include_response,
            include_all: false,
            silence: true,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            no_color: false,
            workers: params.workers,
            max_concurrent_targets: 50,
            max_targets_per_host: 100,
            encoders,
            custom_blind_xss_payload: None,
            blind_callback_url: params.blind_callback_url.clone(),
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: params.deep_scan,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: params.skip_ast_analysis,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // Run the scan on tokio's managed blocking-threadpool. We still need a
        // fresh current_thread runtime inside because analyze_parameters and
        // the scraper-based HTML inspection hold !Send types across awaits;
        // spawn_blocking at least reuses OS threads between scans.
        let handler = self.clone();
        let sid = scan_id.clone();
        tokio::task::spawn_blocking(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    rt.block_on(handler.run_job(sid, scan_args));
                }
                Err(e) => {
                    eprintln!("[MCP][ERR] runtime build failed for scan_id={}: {}", sid, e);
                }
            }
        });

        let out = serde_json::json!({
            "scan_id": scan_id,
            "target": target,
            "status": JobStatus::Queued
        });
        Ok(CallToolResult::success(vec![Content::text(
            out.to_string(),
        )]))
    }

    /// Fetch status and (if done) results for a scan.
    #[tool(
        name = "get_results_dalfox",
        description = "Poll scan status and retrieve results by scan_id. \
Returns {scan_id, target, status, results, pagination, progress}. \
Status is one of: queued, running, done, error, cancelled. \
When done, results is an array of findings. Each finding includes: type \
(V=Verified, A=AST-detected, R=Reflected), type_description, inject_type, \
method, param, payload, evidence, cwe, severity, and message_str. \
Use the optional `offset` and `limit` parameters to page through large \
result sets; pagination describes {total, offset, limit, returned, has_more}. \
When status is 'error', includes error_message explaining the failure reason. \
When running/done/cancelled, includes progress: {params_total, params_tested, \
requests_sent, findings_so_far, estimated_completion_pct (0-100), \
suggested_poll_interval_ms (recommended delay before next poll; 0 when done/cancelled)}. \
Call this repeatedly until status is 'done', 'error', or 'cancelled'."
    )]
    async fn get_results_dalfox(
        &self,
        Parameters(params): Parameters<GetResultsDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let job_opt = {
            let jobs = self.jobs.lock().await;
            jobs.get(&pid).cloned()
        };

        match job_opt {
            Some(job) => {
                let (results_slice, pagination) = paginate_results(
                    job.results.as_deref(),
                    params.offset,
                    params.limit,
                );
                let mut out = serde_json::json!({
                    "scan_id": pid,
                    "target": job.target_url,
                    "status": job.status,
                    "results": results_slice,
                    "pagination": pagination,
                });
                if let Some(obj) = out.as_object_mut() {
                    write_timestamps(&job, obj);
                }
                // Include error message when scan failed
                if let Some(ref err_msg) = job.error_message {
                    out["error_message"] = serde_json::json!(err_msg);
                }
                // Include progress info when scan is running, done, or cancelled
                if matches!(job.status, JobStatus::Running | JobStatus::Done | JobStatus::Cancelled) {
                    let params_total = job.progress.params_total.load(std::sync::atomic::Ordering::Relaxed);
                    let params_tested = job.progress.params_tested.load(std::sync::atomic::Ordering::Relaxed);
                    let requests_sent = job.progress.requests_sent.load(std::sync::atomic::Ordering::Relaxed);
                    let findings_so_far = job.progress.findings_so_far.load(std::sync::atomic::Ordering::Relaxed);

                    // Estimate completion percentage from params tested vs total
                    let estimated_completion_pct: u32 = if matches!(job.status, JobStatus::Done | JobStatus::Cancelled) {
                        if job.status == JobStatus::Done { 100 } else if params_total > 0 {
                            ((params_tested as f64 / params_total as f64) * 100.0) as u32
                        } else { 0 }
                    } else if params_total > 0 {
                        ((params_tested as f64 / params_total as f64) * 100.0).min(99.0) as u32
                    } else {
                        0
                    };

                    // Suggest poll interval based on progress:
                    // - queued/early: poll every 2s
                    // - mid-scan: poll every 3s
                    // - near completion (>80%): poll every 1s
                    // - done/cancelled: no more polling needed
                    let suggested_poll_interval_ms: u64 = if matches!(job.status, JobStatus::Done | JobStatus::Cancelled) {
                        0
                    } else if estimated_completion_pct > 80 {
                        1000
                    } else if estimated_completion_pct > 10 {
                        3000
                    } else {
                        2000
                    };

                    out["progress"] = serde_json::json!({
                        "params_total": params_total,
                        "params_tested": params_tested,
                        "requests_sent": requests_sent,
                        "findings_so_far": findings_so_far,
                        "estimated_completion_pct": estimated_completion_pct,
                        "suggested_poll_interval_ms": suggested_poll_interval_ms,
                    });
                }
                Ok(CallToolResult::success(vec![Content::text(
                    out.to_string(),
                )]))
            }
            None => Err(ErrorData::invalid_params("scan_id not found", None)),
        }
    }

    /// List all scans with their current status.
    #[tool(
        name = "list_scans_dalfox",
        description = "List all tracked scans and their statuses. \
Optionally filter by status (queued, running, done, error, cancelled). \
Returns {total, scans} where each scan has: scan_id, target (original URL), \
status, and result_count."
    )]
    async fn list_scans_dalfox(
        &self,
        Parameters(params): Parameters<ListScansDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let filter_status: Option<JobStatus> = match params
            .status
            .as_deref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
        {
            Some(ref s) => Some(parse_job_status(s).ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "invalid status filter '{}' — must be one of: queued, running, done, error, cancelled",
                        s
                    ),
                    None,
                )
            })?),
            None => None,
        };

        let jobs = self.jobs.lock().await;
        let entries: Vec<serde_json::Value> = jobs
            .iter()
            .filter(|(_, job)| filter_status.as_ref().is_none_or(|f| &job.status == f))
            .map(|(id, job)| {
                let mut entry = serde_json::json!({
                    "scan_id": id,
                    "target": job.target_url,
                    "status": job.status,
                    "result_count": job.results.as_ref().map(|r| r.len()).unwrap_or(0)
                });
                if let Some(obj) = entry.as_object_mut() {
                    write_timestamps(&job, obj);
                }
                entry
            })
            .collect();

        let out = serde_json::json!({
            "total": entries.len(),
            "scans": entries
        });
        Ok(CallToolResult::success(vec![Content::text(
            out.to_string(),
        )]))
    }

    /// Preflight check: discover parameters and estimate scan impact without sending attack payloads.
    #[tool(
        name = "preflight_dalfox",
        description = "Analyze a target URL without sending attack payloads. \
Performs parameter discovery and mining synchronously (no polling needed). \
Returns {target, reachable (bool), method, params_discovered (count), \
estimated_total_requests (int), params: [{name, location, estimated_requests}]}. \
If unreachable, returns reachable=false with error_code. \
Use before scan_with_dalfox to estimate scan impact and verify reachability."
    )]
    async fn preflight_dalfox(
        &self,
        Parameters(params): Parameters<PreflightDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let target_url = params.target.trim().to_string();
        if target_url.is_empty() {
            return Err(ErrorData::invalid_params(
                "missing required field 'target' (example: {\"target\":\"https://example.com\"})",
                None,
            ));
        }
        if !(target_url.starts_with("http://") || target_url.starts_with("https://")) {
            return Err(ErrorData::invalid_params(
                "target must start with http:// or https:// (example: \"https://example.com/page?q=test\")",
                None,
            ));
        }

        if params.timeout == 0 || params.timeout > MAX_TIMEOUT_SECS {
            return Err(ErrorData::invalid_params(
                format!(
                    "timeout must be between 1 and {} seconds (got {})",
                    MAX_TIMEOUT_SECS, params.timeout
                ),
                None,
            ));
        }

        let mut target = match parse_target(&target_url) {
            Ok(mut t) => {
                t.method = params.method.clone();
                t.timeout = params.timeout;
                t.proxy = params.proxy.clone();
                t.follow_redirects = params.follow_redirects;
                t.user_agent = params.user_agent.clone();
                t.headers = params
                    .headers
                    .iter()
                    .filter_map(|h| h.split_once(":"))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                t.cookies = params
                    .cookies
                    .iter()
                    .filter_map(|c| c.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                t.data = params.data.clone();
                t
            }
            Err(_) => {
                return Err(ErrorData::invalid_params(
                    "failed to parse target URL — must be a valid URL with scheme and host (example: \"https://example.com/path?q=test\")",
                    None,
                ));
            }
        };

        // Build minimal ScanArgs for parameter analysis only
        let scan_args = ScanArgs::for_preflight(crate::cmd::scan::PreflightOptions {
            target: target_url.clone(),
            param: params.param.clone(),
            method: params.method.clone(),
            data: params.data.clone(),
            headers: params.headers.clone(),
            cookies: params.cookies.clone(),
            user_agent: params.user_agent.clone(),
            timeout: params.timeout,
            proxy: params.proxy.clone(),
            follow_redirects: params.follow_redirects,
            skip_mining: params.skip_mining,
            skip_discovery: params.skip_discovery,
            encoders: crate::cmd::scan::DEFAULT_ENCODERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });

        // Run parameter discovery on tokio's blocking threadpool (reused
        // across calls) with a current_thread runtime inside, because
        // analyze_parameters and the scraper-based HTML inspection are !Send.
        let result = tokio::task::spawn_blocking(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    rt.block_on(async {
                        // Reachability check: send a probe via the target's fully-hydrated
                        // HTTP stack so proxy, custom headers, cookies, User-Agent, method,
                        // and body all match what the real scan would send.
                        let reachable = send_reachability_probe(&target).await;

                        if !reachable {
                            return serde_json::json!({
                                "target": target_url,
                                "reachable": false,
                                "error_code": crate::cmd::error_codes::CONNECTION_FAILED,
                                "params_discovered": 0,
                                "estimated_total_requests": 0,
                                "params": [],
                            });
                        }

                        analyze_parameters(&mut target, &scan_args, None).await;

                        // Estimate request count (encoder expansion factor)
                        let enc_factor = if scan_args.encoders.iter().any(|e| e == "none") {
                            1usize
                        } else {
                            let mut f = 1usize;
                            for e in ["url", "html", "2url", "3url", "4url", "base64"] {
                                if scan_args.encoders.iter().any(|x| x == e) {
                                    f += 1;
                                }
                            }
                            f
                        };
                        let mut estimated_requests: usize = 0;
                        let discovered_params: Vec<serde_json::Value> = target
                            .reflection_params
                            .iter()
                            .map(|p| {
                                let payload_count = if let Some(ctx) = &p.injection_context {
                                    crate::scanning::xss_common::get_dynamic_payloads(ctx, &scan_args)
                                        .unwrap_or_else(|_| vec![])
                                        .len()
                                } else {
                                    let html_len = crate::payload::get_dynamic_xss_html_payloads().len() * enc_factor;
                                    let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
                                    html_len + js_len
                                };
                                estimated_requests = estimated_requests.saturating_add(payload_count);
                                serde_json::json!({
                                    "name": p.name,
                                    "location": format!("{:?}", p.location),
                                    "estimated_requests": payload_count,
                                })
                            })
                            .collect();

                        serde_json::json!({
                            "target": target_url,
                            "reachable": true,
                            "method": target.method,
                            "params_discovered": discovered_params.len(),
                            "estimated_total_requests": estimated_requests,
                            "params": discovered_params,
                        })
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "target": target_url,
                        "reachable": false,
                        "error": format!("runtime error: {}", e),
                    })
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            serde_json::json!({
                "target": "",
                "reachable": false,
                "error": "preflight task panicked",
            })
        });

        Ok(CallToolResult::success(vec![Content::text(
            result.to_string(),
        )]))
    }

    /// Cancel a queued or running scan.
    #[tool(
        name = "cancel_scan_dalfox",
        description = "Cancel a scan by scan_id. Returns {scan_id, target, cancelled: true, \
previous_status}. For running scans, the background task stops at the next \
cancellation checkpoint (typically within seconds). \
The job remains in the list with status 'cancelled' so partial results can \
still be retrieved via get_results_dalfox."
    )]
    async fn cancel_scan_dalfox(
        &self,
        Parameters(params): Parameters<CancelScanDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let mut jobs = self.jobs.lock().await;
        match jobs.get_mut(&pid) {
            Some(job) => {
                let previous_status = job.status.clone();
                // Signal cancellation to the running scan
                job.cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                // Mark as cancelled immediately for both queued and running scans.
                // For running scans, the background task will exit at the next
                // cancellation checkpoint and store partial results.
                if matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                    job.status = JobStatus::Cancelled;
                    if job.finished_at_ms.is_none() {
                        job.finished_at_ms = Some(now_ms());
                    }
                }
                let out = serde_json::json!({
                    "scan_id": pid,
                    "target": job.target_url,
                    "cancelled": true,
                    "previous_status": previous_status
                });
                Ok(CallToolResult::success(vec![Content::text(
                    out.to_string(),
                )]))
            }
            None => Err(ErrorData::invalid_params("scan_id not found", None)),
        }
    }

    /// Delete a scan entry from the in-memory store.
    #[tool(
        name = "delete_scan_dalfox",
        description = "Delete a scan by scan_id, permanently removing it from memory. \
Only terminal scans (done, error, cancelled) can be deleted — a running or \
queued scan must be cancelled first via cancel_scan_dalfox. \
Returns {scan_id, deleted: true, previous_status}. \
Terminal scans are also auto-purged after 1 hour."
    )]
    async fn delete_scan_dalfox(
        &self,
        Parameters(params): Parameters<DeleteScanDalfoxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.purge_expired_jobs().await;

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let mut jobs = self.jobs.lock().await;
        let previous_status = match jobs.get(&pid) {
            Some(job) => {
                if !job.is_terminal() {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "cannot delete scan in status '{}' — cancel it first via cancel_scan_dalfox",
                            job.status
                        ),
                        None,
                    ));
                }
                job.status.clone()
            }
            None => return Err(ErrorData::invalid_params("scan_id not found", None)),
        };
        jobs.remove(&pid);
        let out = serde_json::json!({
            "scan_id": pid,
            "deleted": true,
            "previous_status": previous_status,
        });
        Ok(CallToolResult::success(vec![Content::text(
            out.to_string(),
        )]))
    }
}

#[tool_handler]
impl rmcp::handler::server::ServerHandler for DalfoxMcp {}

/// Run an MCP (stdio) server exposing Dalfox tools.
/// Blocks until the client disconnects or the process is terminated.
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{stdin, stdout};
    let transport = (stdin(), stdout());
    use rmcp::service::serve_server;
    let running = serve_server(DalfoxMcp::new(), transport).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
            cookie_from_raw: None,
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
        let jobs = mcp.jobs.lock().await;
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
            let mut jobs = mcp.jobs.lock().await;
            jobs.insert(scan_id.clone(), test_job(JobStatus::Queued, None));
        }

        let mut args = default_scan_args("http://example.com");
        args.targets = vec!["not a valid target".to_string()];
        mcp.run_job(scan_id.clone(), args).await;

        let jobs = mcp.jobs.lock().await;
        let job = jobs.get(&scan_id).expect("job exists");
        assert_eq!(job.status, JobStatus::Error);
        assert!(job.error_message.is_some(), "error_message should be set on failure");
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

    #[tokio::test]
    async fn test_scan_with_dalfox_handles_cookie_from_raw() {
        let mcp = DalfoxMcp::new();
        let cookie_file = std::env::temp_dir().join(format!(
            "dalfox-mcp-cookie-{}.txt",
            crate::utils::make_scan_id("cookie-raw")
        ));
        std::fs::write(
            &cookie_file,
            "GET / HTTP/1.1\nHost: example.com\nCookie: sid=abc; uid=def\n",
        )
        .expect("write cookie raw");

        let params = ScanWithDalfoxParams {
            cookie_from_raw: Some(cookie_file.to_string_lossy().to_string()),
            ..default_scan_params("http://127.0.0.1:1/?q=a")
        };
        let resp = mcp
            .scan_with_dalfox(Parameters(params))
            .await
            .expect("scan_with_dalfox should queue");

        let payload = parse_result_json(&resp);
        assert_eq!(payload["status"], "queued");
        assert!(payload["scan_id"].as_str().is_some());
        let _ = std::fs::remove_file(cookie_file);
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
            let mut jobs = mcp.jobs.lock().await;
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
            let mut jobs = mcp.jobs.lock().await;
            let job = test_job(JobStatus::Running, None);
            job.progress.params_total.store(10, std::sync::atomic::Ordering::Relaxed);
            job.progress.params_tested.store(5, std::sync::atomic::Ordering::Relaxed);
            job.progress.requests_sent.store(100, std::sync::atomic::Ordering::Relaxed);
            job.progress.findings_so_far.store(2, std::sync::atomic::Ordering::Relaxed);
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
            let mut jobs = mcp.jobs.lock().await;
            let job = test_job(JobStatus::Done, Some(vec![]));
            job.progress.params_total.store(10, std::sync::atomic::Ordering::Relaxed);
            job.progress.params_tested.store(10, std::sync::atomic::Ordering::Relaxed);
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
            let mut jobs = mcp.jobs.lock().await;
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
            let mut jobs = mcp.jobs.lock().await;
            jobs.insert("ts-list".to_string(), test_job(JobStatus::Done, Some(vec![])));
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
            let mut jobs = mcp.jobs.lock().await;
            jobs.insert("done-del".to_string(), test_job(JobStatus::Done, Some(vec![])));
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

        let jobs = mcp.jobs.lock().await;
        assert!(!jobs.contains_key("done-del"));
    }

    #[tokio::test]
    async fn test_delete_scan_rejects_running_job() {
        let mcp = DalfoxMcp::new();
        {
            let mut jobs = mcp.jobs.lock().await;
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

        let jobs = mcp.jobs.lock().await;
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
            let mut jobs = mcp.jobs.lock().await;
            jobs.insert(
                "pag".to_string(),
                test_job(JobStatus::Done, Some(findings)),
            );
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
        let global_before = crate::REQUEST_COUNT.load(Ordering::Relaxed);

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

        assert_eq!(job_a.load(Ordering::Relaxed), 2, "job A counter isolated");
        assert_eq!(job_b.load(Ordering::Relaxed), 1, "job B counter isolated");
        assert_eq!(
            crate::REQUEST_COUNT.load(Ordering::Relaxed) - global_before,
            3,
            "global counter sees both jobs"
        );
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
            let mut jobs = mcp.jobs.lock().await;
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

        mcp.purge_expired_jobs().await;

        let jobs = mcp.jobs.lock().await;
        assert!(!jobs.contains_key("old"), "old terminal job should be purged");
        assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
        assert!(jobs.contains_key("active"), "active job must never be purged");
    }
}
