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
    cmd::scan::ScanArgs,
    job::{
        AbortOnDrop, JOB_RETENTION_SECS, Job, JobStatus, MAX_ACTIVE_SCANS_MCP, MAX_DELAY_MS,
        MAX_DISCOVERED_PARAMS, MAX_SCAN_TIMEOUT_SECS, MAX_TIMEOUT_SECS, MAX_WORKERS,
        cap_reflection_params, has_http_scheme, now_ms, parse_job_status,
        purge_expired_jobs as purge_jobs_map, run_within_scan_budget, send_reachability_probe,
        split_cookie_pairs, unreachable_error_message,
    },
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

/// Transition a non-terminal job into `Error` with the supplied message.
/// Safe to call after panic or runtime-build failure: gated on
/// `!is_terminal()` so it won't clobber a real outcome, and recovers from
/// mutex poisoning by taking the inner guard rather than re-panicking.
fn mark_job_error_sync(jobs: &Arc<StdMutex<HashMap<String, Job>>>, job_id: &str, msg: String) {
    let mut guard = match jobs.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(job) = guard.get_mut(job_id)
        && !job.is_terminal()
    {
        job.status = JobStatus::Error;
        job.error_message = Some(msg);
        if job.finished_at_ms.is_none() {
            job.finished_at_ms = Some(now_ms());
        }
    }
}

/// Cheap view of a `Job` containing only what a tool response needs. Built
/// while holding the jobs lock so the lock can be released before any
/// JSON serialization or computation runs.
struct JobSnapshot {
    status: JobStatus,
    target_url: String,
    results: Option<Arc<Vec<SanitizedResult>>>,
    progress: crate::job::JobProgress,
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
            .map_or("<missing>", String::as_str);
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
                // Parse via the shared helpers so MCP matches the REST server:
                // empty header names are rejected, and each cookie entry is
                // `;`-split + trimmed (a bare split_once would keep whitespace
                // and fold `a=b; c=d` into one value).
                t.headers = scan_args
                    .headers
                    .iter()
                    .filter_map(|h| crate::utils::http::parse_header_line(h))
                    .collect();
                t.cookies = scan_args
                    .cookies
                    .iter()
                    .flat_map(|c| split_cookie_pairs(c))
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

        // Reachability gate, mirroring preflight_dalfox and the REST server:
        // a parseable-but-unreachable target otherwise finishes `done` with 0
        // findings, which a client can't distinguish from "scanned, no XSS".
        // Any HTTP response (incl. 4xx/5xx) counts as reachable; only a
        // connection-level failure trips this.
        if !send_reachability_probe(&target).await {
            let msg = unreachable_error_message();
            Self::log("ERR", &msg);
            mark_job_error_sync(&self.jobs, &scan_id, msg);
            return;
        }

        // Per-job WAF consecutive-block counter so one scan's WAF backoff
        // doesn't throttle an unrelated scan. The request counter is the
        // public `progress.requests_sent` field itself — scoping it directly
        // lets `crate::tick_request_count()` write through to the visible
        // progress, so pollers see a live `requests_sent` value instead of 0.
        let job_waf_consecutive = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let results_arc = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
        // `run_scanning`'s 6th argument is the running findings tally, not a
        // parameter counter. Older code stored this into `params_tested`,
        // which conflated two different metrics.
        let findings_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Mirror the in-flight findings tally into `progress.findings_so_far`
        // so MCP pollers see progress before the scan finishes. The atomic
        // types differ (`AtomicUsize` inside scanning, `AtomicU64` here),
        // hence the copying task.
        let progress_findings = progress.findings_so_far.clone();
        let findings_count_for_updater = findings_count.clone();
        // RAII abort — covers the panic path too, not just the manual drop below.
        let findings_updater = AbortOnDrop(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                progress_findings.store(
                    findings_count_for_updater.load(std::sync::atomic::Ordering::Relaxed) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }));

        // Captured from inside the scoped/async blocks below so the worker-panic
        // count survives past the scan; assigned by the run_scanning call.
        let mut scan_report = crate::scanning::ScanRunReport::default();
        let scan_fut = crate::with_job_rate_limiter(
            scan_args.rate_limit,
            crate::REQUEST_COUNT_JOB.scope(progress.requests_sent.clone(), async {
                crate::WAF_CONSECUTIVE_BLOCKS_JOB
                    .scope(job_waf_consecutive.clone(), async {
                        // Dispatch blind-XSS probes when a callback URL was
                        // supplied. MCP exposes `blind_callback_url` in its
                        // scan schema and wires it into ScanArgs, but the
                        // execution path never invoked blind_scanning — so the
                        // documented option was a silent no-op, diverging from
                        // both the CLI and the REST server (which call this
                        // here). run_scanning does not cover blind scanning.
                        if let Some(callback_url) = &scan_args.blind_callback_url {
                            crate::scanning::blind_scanning(
                                &target,
                                callback_url,
                                scan_args.custom_blind_xss_payload.as_deref(),
                            )
                            .await;
                        }

                        // Initial AST DOM-XSS pass on the GET response so MCP
                        // scans match CLI for targets where the vulnerability
                        // lives entirely in JS (location.hash → innerHTML
                        // etc.). MCP previously skipped this because the
                        // scan path didn't run preflight; same divergence
                        // hit the REST server, now fixed in both places.
                        if !scan_args.skip_ast_analysis {
                            let client = target.build_client_or_default();
                            if let Ok(resp) = client.get(target.url.clone()).send().await
                                && let Ok(body) = resp.text().await
                            {
                                let ast_batch =
                                    crate::scanning::ast_integration::run_initial_ast_dom_analysis(
                                        &body,
                                        target.url.as_str(),
                                        &target.method,
                                    );
                                if !ast_batch.is_empty() {
                                    let added = ast_batch.len();
                                    let mut guard = results_arc.lock().await;
                                    guard.extend(ast_batch);
                                    findings_count
                                        .fetch_add(added, std::sync::atomic::Ordering::Relaxed);
                                }
                                let ext_batch = crate::scanning::fetch_and_analyze_external_js(
                                    &client,
                                    &target,
                                    &body,
                                    scan_args.as_ref(),
                                )
                                .await;
                                crate::scanning::accumulate_findings(
                                    &results_arc,
                                    &findings_count,
                                    ext_batch,
                                )
                                .await;
                            }
                        }

                        // Parameter discovery / mining
                        analyze_parameters(&mut target, scan_args.as_ref(), None).await;

                        // Bound the per-scan fan-out: a sprawling/hostile target
                        // can expose thousands of params, and scanning spawns
                        // O(params × payloads) workers. Truncate past the cap.
                        let dropped = cap_reflection_params(&mut target);
                        if dropped > 0 {
                            Self::log(
                                "WRN",
                                &format!(
                                    "scan_id={} discovered params capped to {} (dropped {})",
                                    scan_id, MAX_DISCOVERED_PARAMS, dropped
                                ),
                            );
                        }

                        // Record discovered param count
                        progress.params_total.store(
                            target.reflection_params.len() as u32,
                            std::sync::atomic::Ordering::Relaxed,
                        );

                        scan_report = crate::scanning::run_scanning(
                            &target,
                            scan_args.clone(),
                            results_arc.clone(),
                            None,
                            None,
                            findings_count.clone(),
                            Some(cancel_flag.clone()),
                            None,
                            // Feed the live per-parameter completion counter
                            // so get_results_dalfox reports `params_tested`
                            // (and estimated_completion_pct) advancing during
                            // the scan instead of staying at 0 until done.
                            Some(progress.params_tested.clone()),
                        )
                        .await;
                    })
                    .await;
            }),
        );

        // Enforce the whole-scan wall-clock budget. On expiry the cancel flag is
        // tripped so in-flight workers wind down at their next checkpoint and
        // the job settles as `cancelled` with partial results, mirroring a user
        // cancel — plus an error_message below so a timeout stays distinguishable.
        let timed_out =
            run_within_scan_budget(scan_args.scan_timeout, &cancel_flag, scan_fut).await;

        drop(findings_updater);

        // Check if cancelled during scanning. Read this BEFORE rewriting
        // `params_tested` — a cancelled scan exited early and almost
        // certainly did not finish every discovered parameter, so promoting
        // `params_tested` to `params_total` would lie about completion
        // (the client would compute estimated_completion_pct = 100 even
        // though the scan stopped at, say, 10/50 params).
        let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

        if !was_cancelled {
            // After natural completion, all discovered params have been
            // processed by `run_scanning`. No per-param counter is wired
            // today, so the most honest post-scan value is `params_total`.
            progress.params_tested.store(
                progress
                    .params_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
        }

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

        // A worker-task panic means a parameter's findings are incomplete;
        // surface it as `error` (partial results still attached) so a poller
        // can't mistake a crashed scan for a clean finish. Cancellation wins.
        let panicked = !was_cancelled && scan_report.worker_panics > 0;
        {
            let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
            if let Some(j) = jobs.get_mut(&scan_id) {
                // Store partial or complete results
                j.results = Some(Arc::new(sanitized));
                // Only update status if not already cancelled (cancel sets it
                // immediately). A scan_timeout trips cancel_flag (so was_cancelled
                // → Cancelled), a worker panic → Error, otherwise Done.
                if j.status != JobStatus::Cancelled {
                    j.status = if was_cancelled {
                        JobStatus::Cancelled
                    } else if panicked {
                        JobStatus::Error
                    } else {
                        JobStatus::Done
                    };
                }
                // panic and timeout are mutually exclusive (timeout trips the
                // cancel flag → panicked is false), so record whichever applies.
                if panicked && j.error_message.is_none() {
                    j.error_message = Some(format!(
                        "{} scan worker task(s) panicked; results are partial",
                        scan_report.worker_panics
                    ));
                } else if timed_out && j.error_message.is_none() {
                    j.error_message = Some(format!(
                        "scan exceeded scan_timeout ({}s); returning partial results",
                        scan_args.scan_timeout
                    ));
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
        } else if panicked {
            "error"
        } else {
            "finished"
        };
        Self::log(
            "JOB",
            &format!(
                "scan {}{} scan_id={} url={}",
                status_label,
                if timed_out { " (scan_timeout)" } else { "" },
                scan_id,
                url
            ),
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
    #[schemars(range(min = 1, max = 299))]
    pub timeout: u64,

    /// Whole-scan wall-clock budget in seconds (0-86400). When the budget is
    /// reached the scan stops, returns whatever partial results it gathered, and
    /// settles as `cancelled` with an error_message noting the timeout. 0 = no
    /// budget (unbounded). Use this to bound long/deep scans. Default: 0
    #[serde(default)]
    #[schemars(range(max = 86400))]
    pub scan_timeout: u64,

    /// Delay between requests in milliseconds (0-9999). Default: 0
    #[serde(default)]
    #[schemars(range(max = 9999))]
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

    /// Fetch and AST-analyze same-origin external <script src> bundles for DOM-XSS.
    /// Off by default to preserve request budget. Default: false
    #[serde(default)]
    pub analyze_external_js: bool,

    /// Also report outdated / known-vulnerable JS libraries (informational,
    /// CWE-1104, 0 extra requests). Default: false
    #[serde(default)]
    pub detect_outdated_libs: bool,

    /// Blind XSS callback URL (e.g., your Burp Collaborator or interact.sh URL).
    #[serde(default)]
    pub blind_callback_url: Option<String>,

    /// Number of concurrent workers (1-500). Default: 50
    #[serde(default = "default_workers")]
    #[schemars(range(min = 1, max = 500))]
    pub workers: usize,

    /// Cap the scan's outbound request rate (requests/second). 0 = unlimited
    /// (the default). Use this to be gentle on a fragile target or to stay
    /// under a WAF's threshold. Now enforced across all worker tasks.
    #[serde(default)]
    pub rate_limit: u32,
}

fn default_method() -> String {
    crate::cmd::scan::DEFAULT_METHOD.to_string()
}
fn default_encoders() -> Vec<String> {
    crate::cmd::scan::DEFAULT_ENCODERS
        .iter()
        .map(ToString::to_string)
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
    /// Optional status filter: "queued", "running", "done", "error", or "cancelled". Omit to list all.
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

    /// Accepted for symmetry with scan_with_dalfox but NOT used by preflight:
    /// preflight always reports the full auto-discovered parameter set (the
    /// impact estimate), matching the REST `/preflight` endpoint. Pass the
    /// filter to scan_with_dalfox when you actually run the scan.
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

    /// HTTP request timeout in seconds (1-299). Default: 10
    #[serde(default = "default_timeout")]
    #[schemars(range(min = 1, max = 299))]
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
            scan_timeout,
            delay,
            follow_redirects,
            proxy,
            include_request,
            include_response,
            skip_mining,
            skip_discovery,
            deep_scan,
            skip_ast_analysis,
            analyze_external_js,
            detect_outdated_libs,
            blind_callback_url,
            workers,
            rate_limit,
        } = params;

        let target = target.trim().to_string();
        if target.is_empty() {
            return Err(ErrorData::invalid_params(
                "missing required field 'target' (example: {\"target\":\"https://example.com\"})",
                None,
            ));
        }
        if !has_http_scheme(&target) {
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
        if workers == 0 || workers > MAX_WORKERS {
            return Err(ErrorData::invalid_params(
                format!(
                    "workers must be between 1 and {} (got {})",
                    MAX_WORKERS, workers
                ),
                None,
            ));
        }
        if scan_timeout > MAX_SCAN_TIMEOUT_SECS {
            return Err(ErrorData::invalid_params(
                format!(
                    "scan_timeout must be between 0 and {} seconds (got {})",
                    MAX_SCAN_TIMEOUT_SECS, scan_timeout
                ),
                None,
            ));
        }

        // Reserve a unique scan_id and insert the queued job under a single
        // lock. `make_scan_id` mixes in a nanosecond nonce, so collisions are
        // already vanishingly rare — but two same-target submissions landing
        // in the same nanosecond would otherwise have the second `insert`
        // silently clobber the first job (the original scan keeps running but
        // its entry is replaced, so its poller starts seeing a different
        // scan's results). Regenerating on collision makes the guarantee
        // explicit and cheap.
        // Enforce a concurrency cap and reserve the scan_id under one lock.
        // MCP has no config surface, so the bound is a constant; submissions
        // past it are rejected so an agent loop can't grow the job map /
        // blocking pool without bound.
        let scan_id = {
            let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
            let active = jobs.values().filter(|j| !j.is_terminal()).count();
            if active >= MAX_ACTIVE_SCANS_MCP {
                return Err(ErrorData::invalid_params(
                    format!(
                        "at capacity: {} scans already active (max {}); wait for some to finish or cancel/delete them",
                        active, MAX_ACTIVE_SCANS_MCP
                    ),
                    None,
                ));
            }
            let id = crate::utils::make_unique_scan_id(&target, |id| jobs.contains_key(id));
            jobs.insert(id.clone(), Job::new_queued(target.clone()));
            id
        };

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
            detect_outdated_libs,
            // One MCP scan call targets exactly one URL, with method/headers/
            // cookies/data supplied as explicit fields — the same per-request
            // fidelity a single HAR entry carries. The fan-out input shapes
            // (`file`, `pipe`, `raw-http`, `har`) stay CLI-only because they
            // expand one input into many targets, which this single-target tool
            // doesn't model; an agent replays a HAR by calling the tool per entry.
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
            // Whole-scan wall-clock budget; 0 = unbounded. Enforced in
            // `run_job` by wrapping the scan future (run_scanning doesn't honor
            // this field — the CLI applies the same budget in its scan loop).
            scan_timeout,
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
            stream_findings: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            // Match the REST server: scan output is silenced and serialized as
            // JSON, so strip ANSI from any diagnostic the pipeline emits.
            no_color: true,
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
            analyze_external_js,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            // Per-call request-rate cap, now honored across all worker tasks
            // (see crate::with_job_scopes). 0 = unlimited.
            rate_limit,
            retries: 0,
            retry_delay: 1000,
            // Match the server/CLI default so MCP doesn't surface low-confidence
            // WAF fingerprints the other front-ends filter out (was 0.0).
            waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        });

        // Run the scan on tokio's managed blocking-threadpool. We still need a
        // current_thread runtime inside because analyze_parameters and the
        // scraper-based HTML inspection hold !Send types across awaits — but
        // we cache the runtime per blocking-pool worker thread so consecutive
        // scans on the same thread skip the rebuild (saves ~ms of setup).
        //
        // Two failure modes used to leak the job into Queued forever:
        // 1) `run_on_thread_runtime` returns None when the cached runtime
        //    can't be built — `run_job` then never runs.
        // 2) A panic inside `run_job` (parameter analysis, scanning, etc.)
        //    bubbles out of the spawn_blocking task and is dropped because
        //    the JoinHandle isn't awaited.
        // Both paths now transition the job to Error via mark_job_error_sync
        // so clients see a terminal status and `purge_expired_jobs` can
        // collect the entry. Mirrors `server.rs::spawn_scan_task` recovery.
        let handler = self.clone();
        let sid = scan_id.clone();
        tokio::task::spawn_blocking(move || {
            let sid_for_log = sid.clone();
            let sid_for_recovery = sid.clone();
            let jobs_for_recovery = handler.jobs.clone();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let ran = run_on_thread_runtime(&sid_for_log, |rt| {
                    rt.block_on(handler.run_job(sid, scan_args));
                });
                if ran.is_none() {
                    mark_job_error_sync(
                        &jobs_for_recovery,
                        &sid_for_recovery,
                        "scan runtime build failed".to_string(),
                    );
                }
            }));

            if let Err(panic) = result {
                let payload = if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic.downcast_ref::<&str>() {
                    (*s).to_string()
                } else {
                    "unknown panic payload".to_string()
                };
                let msg = format!("scan task panicked: {}", payload);
                eprintln!("[MCP][ERR] {} scan_id={}", msg, sid_for_recovery);
                mark_job_error_sync(&jobs_for_recovery, &sid_for_recovery, msg);
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
                // Include progress for running/terminal jobs — Error too, so an
                // early infra failure still exposes any params/requests counted
                // before it failed instead of an opaque error_message alone.
                if matches!(
                    snap.status,
                    JobStatus::Running | JobStatus::Done | JobStatus::Cancelled | JobStatus::Error
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
                    let estimated_completion_pct: u32 = if matches!(
                        snap.status,
                        JobStatus::Done | JobStatus::Cancelled | JobStatus::Error
                    ) {
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
                    let suggested_poll_interval_ms: u64 = if matches!(
                        snap.status,
                        JobStatus::Done | JobStatus::Cancelled | JobStatus::Error
                    ) {
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
                        "result_count": job.results.as_ref().map_or(0, |r| r.len())
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
        if !has_http_scheme(&target_url) {
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
                // Shared parsers: reject empty header names and `;`-split +
                // trim each cookie, matching the scan path and the REST server.
                t.headers = params
                    .headers
                    .iter()
                    .filter_map(|h| crate::utils::http::parse_header_line(h))
                    .collect();
                t.cookies = params
                    .cookies
                    .iter()
                    .flat_map(|c| split_cookie_pairs(c))
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

        // Build minimal ScanArgs for parameter analysis only.
        // `param: vec![]` so preflight reports the FULL discovered set (impact
        // estimate), matching the REST server's /preflight — passing the
        // client's `param` filter here would under-report discovery.
        let scan_args = ScanArgs::for_preflight(crate::cmd::scan::PreflightOptions {
            target: target_url.clone(),
            param: vec![],
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
                .map(ToString::to_string)
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
                    // Apply the same per-scan parameter cap a real scan would,
                    // so the estimate reflects what scanning actually fans out to.
                    cap_reflection_params(&mut target);

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
