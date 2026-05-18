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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use rmcp::{
    ErrorData,
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

thread_local! {
    /// Per-blocking-thread current_thread runtime. Built lazily on first use
    /// and reused for the lifetime of the worker thread, so the second scan
    /// scheduled onto the same blocking-pool slot doesn't pay
    /// `Builder::new_current_thread().build()` again.
    static SCAN_RUNTIME: std::cell::RefCell<Option<tokio::runtime::Runtime>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` on a current_thread runtime cached in thread-local storage and
/// return its result. The closure receives a borrow of the runtime so
/// callers can issue `block_on`. Returns `None` if runtime construction
/// fails — extremely rare; `tag` is logged to identify the call site.
fn run_on_thread_runtime<F, R>(tag: &str, f: F) -> Option<R>
where
    F: FnOnce(&tokio::runtime::Runtime) -> R,
{
    SCAN_RUNTIME.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => *slot = Some(rt),
                Err(e) => {
                    eprintln!("[MCP][ERR] runtime build failed for tag={}: {}", tag, e);
                    return None;
                }
            }
        }
        slot.as_ref().map(f)
    })
}

/// Cheap view of a `Job` containing only what a tool response needs. Built
/// while holding the jobs lock so the lock can be released before any
/// JSON serialization or computation runs.
struct JobSnapshot {
    status: JobStatus,
    target_url: String,
    results: Option<Arc<Vec<SanitizedResult>>>,
    progress: crate::cmd::job::JobProgress,
    error_message: Option<String>,
    queued_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
}

/// Render timestamp/duration fields into the given JSON object.
fn write_timestamps(job: &Job, out: &mut serde_json::Map<String, serde_json::Value>) {
    out.insert("queued_at_ms".into(), serde_json::json!(job.queued_at_ms));
    out.insert("started_at_ms".into(), serde_json::json!(job.started_at_ms));
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

/// Minimum interval between consecutive `purge_expired_jobs` sweeps. The
/// retention TTL is measured in hours, so a per-call O(n) scan over every job
/// is wasted work — sweeping at most once a minute keeps the map bounded
/// without paying for it on every tool dispatch.
const PURGE_MIN_INTERVAL_MS: i64 = 60_000;

/// MCP handler state.
//
// rmcp 1.x: `#[tool_router]` (line ~507) generates `Self::tool_router()` as an
// inherent method, and `#[tool_handler]` calls it automatically. No router
// field is needed; the 0.x pattern of storing `tool_router: ToolRouter<Self>`
// became unused dead-code in 1.x.
//
// The jobs map uses `std::sync::Mutex` rather than `tokio::sync::Mutex`: every
// critical section that touches it is non-async and bounded (insert / get /
// retain), so the async mutex's scheduler overhead is pure waste. Test code
// holds the lock the same way.
#[derive(Clone)]
pub struct DalfoxMcp {
    jobs: Arc<StdMutex<HashMap<String, Job>>>,
    last_purge_ms: Arc<AtomicI64>,
}

impl Default for DalfoxMcp {
    fn default() -> Self {
        Self::new()
    }
}

impl DalfoxMcp {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(StdMutex::new(HashMap::new())),
            last_purge_ms: Arc::new(AtomicI64::new(0)),
        }
    }

    fn make_scan_id(s: &str) -> String {
        crate::utils::make_scan_id(s)
    }

    fn log(level: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        eprintln!("[{}] [{}] {}", ts, level, msg);
    }

    /// Run the retention sweep, but at most once per `PURGE_MIN_INTERVAL_MS`.
    /// Retention is measured in hours so coarse-grained sweeping is fine, and
    /// the throttle avoids locking + scanning the whole map on every tool
    /// dispatch under bursty MCP traffic.
    fn purge_expired_jobs(&self) {
        let now = now_ms();
        let last = self.last_purge_ms.load(Ordering::Relaxed);
        if now - last < PURGE_MIN_INTERVAL_MS {
            return;
        }
        // CAS so concurrent tool calls can't both decide to sweep.
        if self
            .last_purge_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
        purge_jobs_map(&mut jobs, JOB_RETENTION_SECS);
    }

    /// Execute a scan job (parameter discovery + scanning) using a fully prepared ScanArgs.
    async fn run_job(&self, scan_id: String, scan_args: Arc<ScanArgs>) {
        // Grab shared progress counters and cancellation flag for this job
        let (progress, cancel_flag) = {
            let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
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
            .map(String::as_str)
            .unwrap_or("<missing>");
        let include_request = scan_args.include_request;
        let include_response = scan_args.include_response;

        // Parse and hydrate a single target
        let mut target = match parse_target(url) {
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
                    .filter_map(|h| h.split_once(':'))
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
                let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
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
                        analyze_parameters(&mut target, scan_args.as_ref(), None).await;

                        // Record discovered param count
                        progress.params_total.store(
                            target.reflection_params.len() as u32,
                            std::sync::atomic::Ordering::Relaxed,
                        );

                        crate::scanning::run_scanning(
                            &target,
                            scan_args.clone(),
                            results_arc.clone(),
                            None,
                            None,
                            param_counter.clone(),
                            Some(cancel_flag.clone()),
                            None,
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
            progress
                .findings_so_far
                .store(locked.len() as u64, std::sync::atomic::Ordering::Relaxed);
            locked
                .iter()
                .map(|r| r.to_sanitized(include_request, include_response))
                .collect::<Vec<_>>()
        };

        // Check if cancelled during scanning
        let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

        {
            let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
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

        let status_label = if was_cancelled {
            "cancelled"
        } else {
            "finished"
        };
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

    // NOTE: `cookie_from_raw` (CLI flag --cookie-from-raw) is intentionally
    // not exposed on the MCP API. It would let any caller drive a host-side
    // file open via std::fs::read_to_string, with the matching `Cookie:`
    // header lines forwarded to the attacker-supplied target URL — the same
    // class of arbitrary file read addressed in v2 by GHSA-35wr-x7v6-9fv2.
    // MCP callers can supply cookies directly via the `cookies` field.
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
        self.purge_expired_jobs();

        let ScanWithDalfoxParams {
            target,
            param,
            method,
            data,
            headers,
            cookies,
            user_agent,
            encoders,
            timeout,
            delay,
            follow_redirects,
            proxy,
            include_request,
            include_response,
            skip_mining,
            skip_discovery,
            deep_scan,
            skip_ast_analysis,
            blind_callback_url,
            workers,
        } = params;

        let target = target.trim().to_string();
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

        if timeout == 0 || timeout > MAX_TIMEOUT_SECS {
            return Err(ErrorData::invalid_params(
                format!(
                    "timeout must be between 1 and {} seconds (got {})",
                    MAX_TIMEOUT_SECS, timeout
                ),
                None,
            ));
        }
        if delay > MAX_DELAY_MS {
            return Err(ErrorData::invalid_params(
                format!(
                    "delay must be between 0 and {} ms (got {})",
                    MAX_DELAY_MS, delay
                ),
                None,
            ));
        }

        let scan_id = Self::make_scan_id(&target);

        {
            let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
            jobs.insert(scan_id.clone(), Job::new_queued(target.clone()));
        }

        Self::log(
            "JOB",
            &format!(
                "queued scan_id={} target={} include_request={} include_response={}",
                scan_id, target, include_request, include_response
            ),
        );

        // Normalize encoders: if "none" present use only original payloads.
        // Move ownership in — no caller after this point reads `encoders`.
        let encoders = if encoders.iter().any(|e| e == "none") {
            vec!["none".to_string()]
        } else {
            encoders
        };

        // Cookies come from the API field `cookies` only. The CLI's
        // `cookie_from_raw` flag (which reads cookies from a server-side
        // request file) is intentionally not honoured on the MCP path —
        // see the comment on `ScanWithDalfoxParams::cookies` for the reason.
        let scan_args = Arc::new(ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target.clone()],
            param,
            data,
            headers,
            cookies,
            method,
            user_agent,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining,
            skip_mining_dict: skip_mining,
            skip_mining_dom: skip_mining,
            only_discovery: false,
            skip_discovery,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout,
            delay,
            proxy,
            follow_redirects,
            ignore_return: vec![],
            output: None,
            include_request,
            include_response,
            include_all: false,
            silence: true,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            no_color: false,
            workers,
            max_concurrent_targets: 50,
            max_targets_per_host: 100,
            encoders,
            custom_blind_xss_payload: None,
            blind_callback_url,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            max_payloads_per_param: 0,
            deep_scan,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            waf_min_confidence: 0.0,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        });

        // Run the scan on tokio's managed blocking-threadpool. We still need a
        // current_thread runtime inside because analyze_parameters and the
        // scraper-based HTML inspection hold !Send types across awaits — but
        // we cache the runtime per blocking-pool worker thread so consecutive
        // scans on the same thread skip the rebuild (saves ~ms of setup).
        let handler = self.clone();
        let sid = scan_id.clone();
        tokio::task::spawn_blocking(move || {
            let sid_for_log = sid.clone();
            run_on_thread_runtime(&sid_for_log, |rt| {
                rt.block_on(handler.run_job(sid, scan_args));
            });
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
        self.purge_expired_jobs();

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        // Extract only the fields we need under the lock. `results` and
        // `progress` are already Arc/atomic-shareable, so this avoids the
        // deep clone of owned strings (`target_url`, `error_message`) that
        // `jobs.get(&pid).cloned()` used to perform on every poll.
        let snapshot = {
            let jobs = self.jobs.lock().expect("jobs mutex poisoned");
            jobs.get(&pid).map(|job| JobSnapshot {
                status: job.status.clone(),
                target_url: job.target_url.clone(),
                results: job.results.clone(),
                progress: job.progress.clone(),
                error_message: job.error_message.clone(),
                queued_at_ms: job.queued_at_ms,
                started_at_ms: job.started_at_ms,
                finished_at_ms: job.finished_at_ms,
            })
        };

        match snapshot {
            Some(snap) => {
                let (results_slice, pagination) =
                    paginate_results(snap.results.as_deref(), params.offset, params.limit);
                let duration_ms = match (snap.started_at_ms, snap.finished_at_ms) {
                    (Some(s), Some(f)) => Some(f - s),
                    (Some(s), None) => Some(now_ms() - s),
                    _ => None,
                };
                let mut out = serde_json::json!({
                    "scan_id": pid,
                    "target": snap.target_url,
                    "status": snap.status,
                    "results": results_slice,
                    "pagination": pagination,
                    "queued_at_ms": snap.queued_at_ms,
                    "started_at_ms": snap.started_at_ms,
                    "finished_at_ms": snap.finished_at_ms,
                    "duration_ms": duration_ms,
                });
                // Include error message when scan failed
                if let Some(ref err_msg) = snap.error_message {
                    out["error_message"] = serde_json::json!(err_msg);
                }
                // Include progress info when scan is running, done, or cancelled
                if matches!(
                    snap.status,
                    JobStatus::Running | JobStatus::Done | JobStatus::Cancelled
                ) {
                    let params_total = snap
                        .progress
                        .params_total
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let params_tested = snap
                        .progress
                        .params_tested
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let requests_sent = snap
                        .progress
                        .requests_sent
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let findings_so_far = snap
                        .progress
                        .findings_so_far
                        .load(std::sync::atomic::Ordering::Relaxed);

                    // Estimate completion percentage from params tested vs total
                    let estimated_completion_pct: u32 =
                        if matches!(snap.status, JobStatus::Done | JobStatus::Cancelled) {
                            if snap.status == JobStatus::Done {
                                100
                            } else if params_total > 0 {
                                ((params_tested as f64 / params_total as f64) * 100.0) as u32
                            } else {
                                0
                            }
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
                    let suggested_poll_interval_ms: u64 =
                        if matches!(snap.status, JobStatus::Done | JobStatus::Cancelled) {
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
        self.purge_expired_jobs();

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

        // Build the response under the lock but only on the JSON values we
        // need; serialization itself runs after the lock is released.
        let entries: Vec<serde_json::Value> = {
            let jobs = self.jobs.lock().expect("jobs mutex poisoned");
            jobs.iter()
                .filter(|(_, job)| filter_status.as_ref().is_none_or(|f| &job.status == f))
                .map(|(id, job)| {
                    let mut entry = serde_json::json!({
                        "scan_id": id,
                        "target": job.target_url,
                        "status": job.status,
                        "result_count": job.results.as_ref().map(|r| r.len()).unwrap_or(0)
                    });
                    if let Some(obj) = entry.as_object_mut() {
                        write_timestamps(job, obj);
                    }
                    entry
                })
                .collect()
        };

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
        self.purge_expired_jobs();

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

        // Run parameter discovery on tokio's blocking threadpool with a
        // thread-local current_thread runtime (analyze_parameters and the
        // scraper-based HTML inspection are !Send). The runtime is reused
        // across calls dispatched to the same blocking-pool worker.
        let target_url_for_err = target_url.clone();
        let result = tokio::task::spawn_blocking(move || {
            let target_url_for_err_inner = target_url_for_err.clone();
            run_on_thread_runtime(&target_url_for_err_inner, |rt| {
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
                                let html_len = crate::payload::get_dynamic_xss_html_payloads()
                                    .len()
                                    * enc_factor;
                                let js_len =
                                    crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
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
            })
            .unwrap_or_else(|| {
                serde_json::json!({
                    "target": target_url_for_err,
                    "reachable": false,
                    "error": "runtime build failed",
                })
            })
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
        self.purge_expired_jobs();

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
        match jobs.get_mut(&pid) {
            Some(job) => {
                let previous_status = job.status.clone();
                // Signal cancellation to the running scan
                job.cancelled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
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
        self.purge_expired_jobs();

        let pid = params.scan_id.trim().to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
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
mod tests;
