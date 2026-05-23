use clap::Args;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, options, post},
};

use serde::{Deserialize, Serialize};

use tokio::sync::Mutex;

use crate::cmd::JobStatus;
use crate::cmd::job::{
    AbortOnDrop, JOB_RETENTION_SECS, Job, JobProgress, MAX_DELAY_MS, MAX_TIMEOUT_SECS, MAX_WORKERS,
    now_ms, parse_job_status, purge_expired_jobs as purge_jobs_map, send_reachability_probe,
};
use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::{Result as ScanResult, SanitizedResult};
use crate::target_parser::parse_target;

#[derive(Args)]
pub struct ServerArgs {
    /// Port to run the server on
    #[clap(help_heading = "SERVER")]
    #[arg(short, long, default_value = "6664")]
    pub port: u16,

    /// Host to bind the server to
    #[clap(help_heading = "SERVER")]
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// API key required in X-API-KEY header (or set via DALFOX_API_KEY). Leave empty to disable auth.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "api-key")]
    pub api_key: Option<String>,

    /// Path to a log file to also write logs (plain text, no ANSI colors)
    #[clap(help_heading = "SERVER")]
    #[arg(long = "log-file")]
    pub log_file: Option<String>,

    /// Comma-separated list of allowed origins for CORS. Supports:
    /// - "*" (match all)
    /// - exact origins (http://localhost:3000)
    /// - "regex:<pattern>" for regex
    #[clap(help_heading = "CORS")]
    #[arg(
        long = "allowed-origins",
        help = "Comma-separated list of allowed origins for CORS.\nSupports:\n  - \"*\" wildcard (match all)\n  - exact origins (http://localhost:3000)\n  - \"regex:<pattern>\" for regex",
        long_help = "Comma-separated list of allowed origins for CORS.\nSupports:\n  - \"*\" wildcard (match all)\n  - exact origins (http://localhost:3000)\n  - \"regex:<pattern>\" for regex"
    )]
    pub allowed_origins: Option<String>,

    /// Allow JSONP responses (wrap JSON in callback())
    #[clap(help_heading = "JSONP")]
    #[arg(long = "jsonp")]
    pub jsonp: bool,

    /// JSONP callback parameter name (default: callback)
    #[clap(help_heading = "JSONP")]
    #[arg(long = "callback-param-name", default_value = "callback")]
    pub callback_param_name: String,

    /// CORS allow methods (comma-separated). Default: GET,POST,OPTIONS,PUT,PATCH,DELETE
    #[clap(help_heading = "CORS")]
    #[arg(long = "cors-allow-methods")]
    pub cors_allow_methods: Option<String>,

    /// CORS allow headers (comma-separated). Default: Content-Type,X-API-KEY,Authorization
    #[clap(help_heading = "CORS")]
    #[arg(long = "cors-allow-headers")]
    pub cors_allow_headers: Option<String>,
}

#[derive(Clone)]
struct AppState {
    api_key: Option<String>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    // optional log file path (plain logs only; no ANSI color codes)
    log_file: Option<String>,
    // raw allowed origins as provided (after split)
    allowed_origins: Option<Vec<String>>,
    // compiled regex patterns derived from allowed_origins entries starting with "regex:" or with wildcard '*'
    allowed_origin_regexes: Vec<regex::Regex>,
    // whether '*' was included explicitly
    allow_all_origins: bool,
    // CORS response headers config
    allow_methods: String,
    allow_headers: String,
    // JSONP
    jsonp_enabled: bool,
    callback_param_name: String,
}

/// Reject scan-option values that are outside the supported range so callers
/// get a precise 400 instead of having the server silently substitute defaults.
fn validate_scan_options(opts: &ScanOptions) -> Result<(), String> {
    if let Some(t) = opts.timeout
        && (t == 0 || t > MAX_TIMEOUT_SECS)
    {
        return Err(format!(
            "timeout must be between 1 and {} seconds (got {})",
            MAX_TIMEOUT_SECS, t
        ));
    }
    if let Some(d) = opts.delay
        && d > MAX_DELAY_MS
    {
        return Err(format!(
            "delay must be between 0 and {} ms (got {})",
            MAX_DELAY_MS, d
        ));
    }
    if let Some(w) = opts.worker
        && (w == 0 || w > MAX_WORKERS)
    {
        return Err(format!(
            "worker must be between 1 and {} (got {})",
            MAX_WORKERS, w
        ));
    }
    Ok(())
}

/// Thin wrapper over `cmd::job::purge_expired_jobs` that acquires the jobs
/// lock for the caller.
async fn purge_expired_jobs(state: &AppState) {
    let mut jobs = state.jobs.lock().await;
    purge_jobs_map(&mut jobs, JOB_RETENTION_SECS);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiResponse<T> {
    code: i32,
    msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

#[derive(Debug, Clone, Deserialize)]
struct ScanRequest {
    url: String,
    #[serde(default)]
    options: Option<ScanOptions>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ScanOptions {
    cookie: Option<String>,
    worker: Option<usize>,
    delay: Option<u64>,
    timeout: Option<u64>,
    blind: Option<String>,
    header: Option<Vec<String>>,
    method: Option<String>,
    data: Option<String>,
    user_agent: Option<String>,
    encoders: Option<Vec<String>>,
    remote_payloads: Option<Vec<String>>,
    remote_wordlists: Option<Vec<String>>,
    include_request: Option<bool>,
    include_response: Option<bool>,
    /// Webhook URL to POST scan results to upon completion.
    callback_url: Option<String>,
    /// Specific parameters to test. Supports location hints via "name:location" syntax.
    param: Option<Vec<String>>,
    /// HTTP/SOCKS proxy URL.
    proxy: Option<String>,
    /// Follow HTTP redirects (3xx).
    follow_redirects: Option<bool>,
    /// Skip parameter mining (DOM and dictionary-based discovery).
    skip_mining: Option<bool>,
    /// Skip initial parameter discovery from HTML.
    skip_discovery: Option<bool>,
    /// Enable deep scan mode (test all payloads even after finding XSS).
    deep_scan: Option<bool>,
    /// Skip AST-based JavaScript analysis.
    skip_ast_analysis: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct ResultPayload {
    /// The original target URL submitted for scanning.
    target: String,
    status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<SanitizedResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<ProgressPayload>,
    queued_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
    duration_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressPayload {
    params_total: u32,
    params_tested: u32,
    requests_sent: u64,
    findings_so_far: u64,
    estimated_completion_pct: u32,
    /// Recommended delay (ms) before next poll; 0 when done/cancelled.
    suggested_poll_interval_ms: u64,
}

/// Constant-time byte comparison. Returns false for differing lengths
/// without iterating, which leaks length only — never the contents. Used
/// for the API-key check so an attacker can't recover the key byte-by-byte
/// from response-time differences.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn check_api_key(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.api_key {
        Some(required) if !required.is_empty() => {
            if let Some(h) = headers.get("X-API-KEY")
                && let Ok(v) = h.to_str()
            {
                return constant_time_eq(v.as_bytes(), required.as_bytes());
            }
            false
        }
        _ => true, // no API key set -> allow all
    }
}

fn make_scan_id(s: &str) -> String {
    crate::utils::make_scan_id(s)
}

/// Split the server's HTTP-style `Cookie` header value (`a=b; c=d`) into
/// `(name, value)` pairs. Earlier code did a single `split_once('=')` on the
/// whole input, which silently folded `; c=d` into the value of the first
/// pair — `preflight_handler` already used the `;`-split form, so the two
/// endpoints disagreed on what a multi-cookie header meant.
fn split_cookie_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

// Validate JSONP callback name to prevent XSS via callback parameter.
// Rules:
// - 1..=64 length
// - First char: [A-Za-z_$]
// - Subsequent chars: [A-Za-z0-9_$\.]
fn validate_jsonp_callback(cb: &str) -> Option<String> {
    let cb = cb.trim();
    if cb.is_empty() || cb.len() > 64 {
        return None;
    }
    let mut chars = cb.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return None;
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '.') {
            return None;
        }
    }
    Some(cb.to_string())
}

/// Try to extract a valid JSONP callback from query params. Returns `Some(cb)` if JSONP is
/// enabled and a valid callback name is present; `None` otherwise.
fn extract_jsonp_callback(
    state: &AppState,
    params: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if !state.jsonp_enabled {
        return None;
    }
    params
        .get(&state.callback_param_name)
        .and_then(|s| validate_jsonp_callback(s))
}

/// Build the final HTTP response body, applying JSONP wrapping when a valid callback is present.
/// Returns `(content_type_override, body_string)`.  When `jsonp_cb` is `Some`, the body is
/// wrapped as `callback(json);` and the content-type is set to `application/javascript`.
fn build_response_body<T: Serialize>(
    resp: &T,
    jsonp_cb: Option<&str>,
) -> (Option<&'static str>, String) {
    let json = serde_json::to_string(resp).expect("serializable response");
    match jsonp_cb {
        Some(cb) => (
            Some("application/javascript; charset=utf-8"),
            format!("{}({});", cb, json),
        ),
        None => (None, json),
    }
}

/// Convenience: build a complete axum response tuple with CORS + optional JSONP.
fn make_api_response<T: Serialize>(
    state: &AppState,
    req_headers: &HeaderMap,
    params: &std::collections::HashMap<String, String>,
    status: StatusCode,
    resp: &T,
) -> (StatusCode, HeaderMap, String) {
    let mut cors = build_cors_headers(state, req_headers);
    let cb = extract_jsonp_callback(state, params);
    let (ct, body) = build_response_body(resp, cb.as_deref());
    if let Some(ct_val) = ct {
        cors.insert("Content-Type", ct_val.parse().expect("static content-type"));
    }
    (status, cors, body)
}

fn build_cors_headers(state: &AppState, req_headers: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if state.allowed_origins.is_none() {
        return headers;
    }

    // Methods/Headers (configured or defaults)
    let allow_methods = state.allow_methods.parse().unwrap_or_else(|_| {
        "GET,POST,OPTIONS,PUT,PATCH,DELETE"
            .parse()
            .expect("static CORS methods header")
    });
    let allow_headers = state.allow_headers.parse().unwrap_or_else(|_| {
        "Content-Type,X-API-KEY,Authorization"
            .parse()
            .expect("static CORS headers header")
    });

    // Wildcard
    if state.allow_all_origins {
        headers.insert(
            "Access-Control-Allow-Origin",
            "*".parse().expect("static wildcard origin"),
        );
        headers.insert("Access-Control-Allow-Methods", allow_methods);
        headers.insert("Access-Control-Allow-Headers", allow_headers);
        return headers;
    }

    // Reflect allowed origins
    if let Some(origin_val) = req_headers.get("Origin")
        && let Ok(origin_str) = origin_val.to_str()
    {
        let exact_allowed = state.allowed_origins.as_ref().is_some_and(|v| {
            v.iter()
                .any(|o| !o.starts_with("regex:") && o != "*" && o == origin_str)
        });
        let regex_allowed = state
            .allowed_origin_regexes
            .iter()
            .any(|re| re.is_match(origin_str));

        if exact_allowed || regex_allowed {
            headers.insert("Access-Control-Allow-Origin", origin_val.clone());
            headers.insert("Vary", "Origin".parse().expect("static Vary header"));
        }
    }

    headers.insert("Access-Control-Allow-Methods", allow_methods);
    headers.insert("Access-Control-Allow-Headers", allow_headers);
    headers
}

fn log(state: &AppState, level: &str, message: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let (color, lvl) = match level {
        "INF" => ("\x1b[36m", "INF"),
        "WRN" => ("\x1b[33m", "WRN"),
        "ERR" => ("\x1b[31m", "ERR"),
        "JOB" => ("\x1b[32m", "JOB"),
        "AUTH" => ("\x1b[35m", "AUTH"),
        "RESULT" => ("\x1b[34m", "RESULT"),
        "SERVER" => ("\x1b[36m", "SERVER"),
        other => ("\x1b[37m", other),
    };
    crate::cprintln!("\x1b[90m{}\x1b[0m {}{}\x1b[0m {}", ts, color, lvl, message);

    if let Some(path) = &state.log_file {
        let line = format!("[{}] [{}] {}\n", ts, lvl, message);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            });
    }
}

/// Spawn `run_scan_job` on the blocking pool with full panic / runtime-build
/// isolation. Without this wrapper, a panic inside the spawned task — or a
/// failure to build the inner current-thread runtime — silently drops the
/// `JoinHandle` and leaves the job pinned in `Queued`/`Running` forever.
/// `purge_expired_jobs` only collects terminal jobs, so the orphan also
/// leaks the job slot indefinitely.
fn spawn_scan_task(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    tokio::task::spawn_blocking(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("scan runtime build failed: {}", e);
                eprintln!("[server] {} for job {}", msg, job_id);
                fail_job_via_fresh_runtime(&state, &job_id, &url, msg);
                return;
            }
        };

        let state_for_recovery = state.clone();
        let job_id_for_recovery = job_id.clone();
        let url_for_recovery = url.clone();

        let rt_ref = &rt;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            rt_ref.block_on(run_scan_job(
                state,
                job_id,
                url,
                opts,
                include_request,
                include_response,
            ));
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
            eprintln!("[server] {} (job_id={})", msg, job_id_for_recovery);
            // The scan runtime itself is still valid after a panic inside the
            // future, so reuse it for the recovery write rather than spinning
            // up a second runtime just to update one map entry.
            rt.block_on(async {
                mark_job_error(
                    &state_for_recovery,
                    &job_id_for_recovery,
                    &url_for_recovery,
                    msg,
                )
                .await;
            });
        }
    });
}

/// Best-effort recovery path used when the scan runtime could not be built at
/// all. Builds a tiny one-shot runtime just to update the job map and fire
/// the terminal webhook; if even that fails, the job is unrecoverable from
/// this thread.
fn fail_job_via_fresh_runtime(state: &AppState, job_id: &str, url: &str, msg: String) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!(
            "[server] could not build recovery runtime to fail job {}",
            job_id
        );
        return;
    };
    let state = state.clone();
    let job_id = job_id.to_string();
    let url = url.to_string();
    rt.block_on(async move {
        mark_job_error(&state, &job_id, &url, msg).await;
    });
}

/// Transition a non-terminal job into `Error` and fire the terminal webhook
/// if the job had a callback_url. Safe to call even after the job has
/// reached a terminal state (the update is gated on `!is_terminal()`), so
/// panic / cancel races don't clobber a real outcome — and because we only
/// fire the webhook when the transition actually happened, subscribers
/// don't receive duplicate notifications.
///
/// The webhook is dispatched after the jobs lock is released so a slow
/// callback URL can't block concurrent job updates. We use the default
/// reqwest client because the panic / parse-error paths may not have a
/// fully-built target available; this still mirrors the contract that
/// every terminal state fires the webhook (see commit aeb8cdb).
async fn mark_job_error(state: &AppState, job_id: &str, url: &str, msg: String) {
    let (transitioned, callback_url) = {
        let mut jobs = state.jobs.lock().await;
        if let Some(job) = jobs.get_mut(job_id)
            && !job.is_terminal()
        {
            job.status = JobStatus::Error;
            job.error_message = Some(msg);
            if job.finished_at_ms.is_none() {
                job.finished_at_ms = Some(now_ms());
            }
            (true, job.callback_url.clone())
        } else {
            (false, None)
        }
    };
    if transitioned {
        send_terminal_webhook(state, callback_url, job_id, url, "error", &[], None).await;
    }
}

/// Decision made by the run_scan_job preamble after looking up the job.
/// Capturing it in a value type lets us release the jobs lock before any
/// awaits — important because the pre-cancelled path needs to fire a
/// webhook and we don't want to hold the lock across that network call.
enum StartDecision {
    Run {
        progress: JobProgress,
        cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    },
    /// Job was cancelled (or its cancel flag set) before the scan task got
    /// a chance to start. Caller must still fire the webhook so subscribers
    /// see a terminal callback for this scan_id.
    PreCancelled { callback_url: Option<String> },
    /// Job was deleted from the map between submission and dispatch.
    Missing,
}

async fn run_scan_job(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    // Grab progress counters and cancellation flag
    let decision = {
        let mut jobs = state.jobs.lock().await;
        match jobs.get_mut(&job_id) {
            Some(job) => {
                if job.status == JobStatus::Cancelled
                    || job.cancelled.load(std::sync::atomic::Ordering::Relaxed)
                {
                    StartDecision::PreCancelled {
                        callback_url: job.callback_url.clone(),
                    }
                } else {
                    job.status = JobStatus::Running;
                    job.started_at_ms = Some(now_ms());
                    StartDecision::Run {
                        progress: job.progress.clone(),
                        cancel_flag: job.cancelled.clone(),
                    }
                }
            }
            None => StartDecision::Missing,
        }
    };

    let (progress, cancel_flag) = match decision {
        StartDecision::Run {
            progress,
            cancel_flag,
        } => (progress, cancel_flag),
        StartDecision::PreCancelled { callback_url } => {
            // Previously this branch returned silently, so any subscriber
            // wired to the webhook never received a terminal callback for
            // scans that were cancelled before the task got a chance to
            // run. Mirror the mid-flight cancellation contract here so the
            // webhook fires for every terminal state, not just some.
            log(
                &state,
                "JOB",
                &format!("cancelled-pre-start id={} url={}", job_id, url),
            );
            // Honor opts.proxy / follow_redirects / TLS settings on this
            // path the same way the mid-flight cancel path does — otherwise
            // a webhook behind a corporate proxy would silently fail only
            // for "cancel-before-start" scans. Fall back to the default
            // client when parse_target can't make sense of the URL (the
            // user-submitted url may be invalid; we still want the
            // webhook to fire so subscribers see the terminal callback).
            let timeout_secs = opts
                .timeout
                .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS);
            let cb_client = hydrate_preflight_target(&url, &opts, timeout_secs)
                .ok()
                .map(|t| t.build_client_or_default());
            send_terminal_webhook(
                &state,
                callback_url,
                &job_id,
                &url,
                "cancelled",
                &[],
                cb_client,
            )
            .await;
            return;
        }
        StartDecision::Missing => return,
    };

    let args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
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

        param: opts.param.clone().unwrap_or_default(),
        data: opts.data.clone(),
        headers: opts.header.clone().unwrap_or_default(),
        cookies: {
            let mut v = vec![];
            if let Some(c) = &opts.cookie
                && !c.trim().is_empty()
            {
                v.push(c.clone());
            }
            v
        },
        method: opts.method.clone().unwrap_or_else(|| "GET".to_string()),
        user_agent: opts.user_agent.clone(),
        cookie_from_raw: None,
        no_color: true,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,

        only_discovery: false,
        skip_discovery: opts.skip_discovery.unwrap_or(false),
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,

        mining_dict_word: None,
        skip_mining: opts.skip_mining.unwrap_or(false),
        skip_mining_dict: opts.skip_mining.unwrap_or(false),
        skip_mining_dom: opts.skip_mining.unwrap_or(false),

        timeout: opts
            .timeout
            .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS),
        delay: opts.delay.unwrap_or(0),
        proxy: opts.proxy.clone(),
        follow_redirects: opts.follow_redirects.unwrap_or(false),
        ignore_return: vec![],

        workers: opts.worker.unwrap_or(50),
        max_concurrent_targets: 50,
        max_targets_per_host: 100,

        encoders: opts
            .encoders
            .clone()
            .unwrap_or_else(|| vec!["url".to_string(), "html".to_string()]),

        custom_blind_xss_payload: None,
        blind_callback_url: opts.blind.clone(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),

        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: opts.deep_scan.unwrap_or(false),
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: opts.skip_ast_analysis.unwrap_or(false),
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
        remote_payloads: opts.remote_payloads.clone().unwrap_or_default(),
        remote_wordlists: opts.remote_wordlists.clone().unwrap_or_default(),

        targets: vec![url.clone()],
    };

    // Initialize remote resources if requested (honor timeout/proxy)
    if !args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty() {
        let _ = crate::utils::init_remote_resources_with_options(
            &args.remote_payloads,
            &args.remote_wordlists,
            Some(args.timeout),
            args.proxy.clone(),
        )
        .await;
    }
    let results = Arc::new(Mutex::new(Vec::<ScanResult>::new()));

    let mut target = match parse_target(&url) {
        Ok(mut t) => {
            t.data = args.data.clone();
            t.headers = args
                .headers
                .iter()
                .filter_map(|h| {
                    let mut parts = h.splitn(2, ':');
                    let name = parts.next()?.trim();
                    let value = parts.next()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    Some((name.to_string(), value.to_string()))
                })
                .collect();
            t.method = args.method.clone();
            if let Some(ua) = &args.user_agent {
                t.headers.push(("User-Agent".to_string(), ua.clone()));
                t.user_agent = Some(ua.clone());
            } else {
                t.user_agent = Some("".to_string());
            }
            t.cookies = args
                .cookies
                .iter()
                .flat_map(|c| split_cookie_pairs(c))
                .collect();
            t.timeout = args.timeout;
            t.delay = args.delay;
            t.proxy = args.proxy.clone();
            t.follow_redirects = args.follow_redirects;
            t.ignore_return = args.ignore_return.clone();
            t.workers = args.workers;
            t
        }
        Err(e) => {
            // Webhook subscribers expect a terminal callback for every scan;
            // before, this branch transitioned the job to Error but never
            // fired the webhook, so a malformed URL silently left the
            // subscriber waiting indefinitely. mark_job_error now handles
            // both the status update and the webhook dispatch.
            let msg = format!("parse_target failed: {}", e);
            mark_job_error(&state, &job_id, &url, msg).await;
            return;
        }
    };

    // Per-job WAF consecutive-block counter so one scan's WAF backoff doesn't
    // throttle an unrelated scan.
    //
    // For the request counter, we scope `progress.requests_sent` directly
    // instead of a private local atomic — every `crate::tick_request_count()`
    // call then writes through to the publicly visible progress field, so
    // GET /scan/{id} returns a live `requests_sent` value during the scan
    // instead of `0` until completion.
    let job_waf_consecutive = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // `run_scanning`'s 6th argument is the running findings tally, not a
    // parameter counter (see scanning/mod.rs:findings_count). Older code
    // here called it `param_counter` and stored it into `params_tested`,
    // which conflated two unrelated metrics.
    let findings_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Mirror the in-flight findings tally into `progress.findings_so_far`
    // periodically so pollers see a non-zero value before the scan finishes.
    // The types differ (`AtomicUsize` inside scanning, `AtomicU64` in the
    // public progress struct), which is why a copying task is needed.
    let progress_findings = progress.findings_so_far.clone();
    let findings_count_for_updater = findings_count.clone();
    // RAII abort — covers the panic path too, not just the manual abort below.
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

    crate::REQUEST_COUNT_JOB
        .scope(progress.requests_sent.clone(), async {
            crate::WAF_CONSECUTIVE_BLOCKS_JOB
                .scope(job_waf_consecutive.clone(), async {
                    if let Some(callback_url) = &args.blind_callback_url {
                        crate::scanning::blind_scanning(&target, callback_url).await;
                    }

                    // Initial AST DOM-XSS pass on the GET response, mirroring
                    // the CLI flow. Server used to skip this because it
                    // didn't run preflight, so identical targets reported
                    // 0 findings via API even when CLI saw multiple
                    // DOM-XSS sinks (e.g. xss-game level3 with
                    // location.hash → html). Best-effort fetch — if it
                    // fails the regular scan path below still runs.
                    if !args.skip_ast_analysis {
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
                                let mut guard = results.lock().await;
                                guard.extend(ast_batch);
                                findings_count
                                    .fetch_add(added, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }

                    let mut silent_args = args.clone();
                    silent_args.silence = true;
                    analyze_parameters(&mut target, &silent_args, None).await;

                    progress.params_total.store(
                        target.reflection_params.len() as u32,
                        std::sync::atomic::Ordering::Relaxed,
                    );

                    crate::scanning::run_scanning(
                        &target,
                        Arc::new(args.clone()),
                        results.clone(),
                        None,
                        None,
                        findings_count.clone(),
                        Some(cancel_flag.clone()),
                        None,
                    )
                    .await;
                })
                .await;
        })
        .await;

    drop(findings_updater);

    let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

    if !was_cancelled {
        // After natural completion, every discovered parameter has been
        // processed by `run_scanning`, so reflect that in `params_tested`.
        // Skip this on cancellation: the scan stopped early and promoting
        // params_tested to params_total would falsely report 100%
        // completion to API pollers computing estimated_completion_pct.
        progress.params_tested.store(
            progress
                .params_total
                .load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    let final_results = {
        let locked = results.lock().await;
        progress
            .findings_so_far
            .store(locked.len() as u64, std::sync::atomic::Ordering::Relaxed);
        locked
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect::<Vec<_>>()
    };

    let final_results_arc = Arc::new(final_results);
    let callback_url = {
        let mut jobs = state.jobs.lock().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.results = Some(final_results_arc.clone());
            if job.status != JobStatus::Cancelled {
                job.status = if was_cancelled {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Done
                };
            }
            // Preserve an earlier finished_at_ms set by cancel_scan_handler
            // (which records when the user asked to stop, not when the task noticed).
            if job.finished_at_ms.is_none() {
                job.finished_at_ms = Some(now_ms());
            }
            job.callback_url.clone()
        } else {
            None
        }
    };
    let status_label = if was_cancelled { "cancelled" } else { "done" };
    log(
        &state,
        "JOB",
        &format!("{} id={} url={}", status_label, job_id, url),
    );

    // Reuse the target's HTTP configuration (proxy, TLS relaxation, redirect
    // policy) so webhook delivery respects the same network boundary as the
    // scan itself.
    let cb_client = target.build_client_or_default();
    send_terminal_webhook(
        &state,
        callback_url,
        &job_id,
        &url,
        status_label,
        &final_results_arc,
        Some(cb_client),
    )
    .await;
}

/// POST the scan-completion payload to the configured webhook, if any.
/// Only `http`/`https` URLs are dialed (mitigates SSRF via odd schemes such
/// as `file://`). The status string is the same one we put in the response
/// payload (`"done"` or `"cancelled"`) so downstream consumers can branch
/// on it without re-deriving terminal state.
async fn send_terminal_webhook(
    state: &AppState,
    callback_url: Option<String>,
    job_id: &str,
    url: &str,
    status_label: &str,
    results: &[SanitizedResult],
    client: Option<reqwest::Client>,
) {
    let Some(cb_url) = callback_url else { return };
    if !(cb_url.starts_with("http://") || cb_url.starts_with("https://")) {
        return;
    }
    let payload = serde_json::json!({
        "scan_id": job_id,
        "status": status_label,
        "url": url,
        "results": results,
    });
    // When the caller has no parsed target (e.g. pre-start cancellation),
    // fall back to a default client. Webhook delivery should not silently
    // drop just because the scan never got far enough to build a target.
    let client = client.unwrap_or_default();
    let result = client
        .post(&cb_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    match result {
        Ok(resp) => log(
            state,
            "CALLBACK",
            &format!("POST {} -> {}", cb_url, resp.status()),
        ),
        Err(e) => log(state, "CALLBACK", &format!("POST {} failed: {}", cb_url, e)),
    }
}

async fn start_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        log(&state, "AUTH", "Unauthorized access to /scan");
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    if req.url.trim().is_empty() {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    let opts = req.options.clone().unwrap_or_default();
    if let Err(msg) = validate_scan_options(&opts) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg,
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }
    let include_request = opts.include_request.unwrap_or(false);
    let include_response = opts.include_response.unwrap_or(false);
    let callback_url = opts.callback_url.clone();

    let id = make_scan_id(&req.url);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            id.clone(),
            Job {
                status: JobStatus::Queued,
                results: None,
                callback_url: callback_url.clone(),
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                target_url: req.url.clone(),
                queued_at_ms: now_ms(),
                started_at_ms: None,
                finished_at_ms: None,
            },
        );
    }
    log(&state, "JOB", &format!("queued id={} url={}", id, req.url));

    spawn_scan_task(
        state.clone(),
        id.clone(),
        req.url.clone(),
        opts,
        include_request,
        include_response,
    );

    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "scan_id": id, "target": req.url })),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
}

async fn get_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        log(&state, "AUTH", "Unauthorized access to /result");
        let resp = ApiResponse::<ResultPayload> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    let job = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).cloned()
    };

    match job {
        Some(j) => {
            let progress_data = if matches!(
                j.status,
                JobStatus::Running | JobStatus::Done | JobStatus::Cancelled
            ) {
                let params_total = j
                    .progress
                    .params_total
                    .load(std::sync::atomic::Ordering::Relaxed);
                let params_tested = j
                    .progress
                    .params_tested
                    .load(std::sync::atomic::Ordering::Relaxed);
                let estimated_completion_pct =
                    if matches!(j.status, JobStatus::Done | JobStatus::Cancelled) {
                        if j.status == JobStatus::Done {
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
                let suggested_poll_interval_ms: u64 =
                    if matches!(j.status, JobStatus::Done | JobStatus::Cancelled) {
                        0
                    } else if estimated_completion_pct > 80 {
                        1000
                    } else if estimated_completion_pct > 10 {
                        3000
                    } else {
                        2000
                    };
                Some(ProgressPayload {
                    params_total,
                    params_tested,
                    requests_sent: j
                        .progress
                        .requests_sent
                        .load(std::sync::atomic::Ordering::Relaxed),
                    findings_so_far: j
                        .progress
                        .findings_so_far
                        .load(std::sync::atomic::Ordering::Relaxed),
                    estimated_completion_pct,
                    suggested_poll_interval_ms,
                })
            } else {
                None
            };
            let duration_ms = j.duration_ms();
            let payload = ResultPayload {
                target: j.target_url.clone(),
                status: j.status.clone(),
                results: j.results.as_deref().cloned(),
                error_message: j.error_message.clone(),
                progress: progress_data,
                queued_at_ms: j.queued_at_ms,
                started_at_ms: j.started_at_ms,
                finished_at_ms: j.finished_at_ms,
                duration_ms,
            };
            log(&state, "RESULT", &format!("id={} status={}", id, j.status));
            let resp = ApiResponse {
                code: 200,
                msg: "ok".to_string(),
                data: Some(payload),
            };
            make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
        }
        None => {
            let resp = ApiResponse::<ResultPayload> {
                code: 404,
                msg: "not found".to_string(),
                data: None,
            };
            make_api_response(&state, &headers, &params, StatusCode::NOT_FOUND, &resp)
        }
    }
}

async fn options_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
}

// GET /scan handler for JSONP-friendly GET inputs (URL + options via query)
async fn get_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        log(&state, "AUTH", "Unauthorized access to /scan");
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    let url = params.get("url").cloned().unwrap_or_default();
    if url.trim().is_empty() {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    // Build ScanOptions from query parameters
    let headers_param = params.get("header").cloned().unwrap_or_default();
    let opt_headers: Vec<String> = if headers_param.is_empty() {
        vec![]
    } else {
        headers_param
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let encoders_param = params.get("encoders").cloned().unwrap_or_default();
    let encoders: Vec<String> = if encoders_param.is_empty() {
        vec!["url".to_string(), "html".to_string()]
    } else {
        encoders_param
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let cookie = params.get("cookie").cloned();
    let worker = params.get("worker").and_then(|s| s.parse::<usize>().ok());
    let delay = params.get("delay").and_then(|s| s.parse::<u64>().ok());
    let timeout = params.get("timeout").and_then(|s| s.parse::<u64>().ok());
    let blind = params.get("blind").cloned();
    let method = params
        .get("method")
        .cloned()
        .unwrap_or_else(|| "GET".to_string());
    let data_opt = params.get("data").cloned();
    let user_agent = params.get("user_agent").cloned();
    let include_request = params.get("include_request").is_some_and(|s| s == "true");
    let include_response = params.get("include_response").is_some_and(|s| s == "true");

    let param_list: Option<Vec<String>> = params.get("param").map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    });
    let proxy = params.get("proxy").cloned();
    let follow_redirects = params.get("follow_redirects").is_some_and(|s| s == "true");
    let skip_mining = params.get("skip_mining").is_some_and(|s| s == "true");
    let skip_discovery = params.get("skip_discovery").is_some_and(|s| s == "true");
    let deep_scan = params.get("deep_scan").is_some_and(|s| s == "true");
    let skip_ast_analysis = params.get("skip_ast_analysis").is_some_and(|s| s == "true");

    let opts = ScanOptions {
        cookie,
        worker,
        delay,
        timeout,
        blind,
        header: Some(opt_headers),
        method: Some(method),
        data: data_opt,
        user_agent,
        encoders: Some(encoders),
        remote_payloads: params.get("remote_payloads").map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
        }),
        remote_wordlists: params.get("remote_wordlists").map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
        }),
        include_request: Some(include_request),
        include_response: Some(include_response),
        callback_url: params.get("callback_url").cloned(),
        param: param_list,
        proxy,
        follow_redirects: Some(follow_redirects),
        skip_mining: Some(skip_mining),
        skip_discovery: Some(skip_discovery),
        deep_scan: Some(deep_scan),
        skip_ast_analysis: Some(skip_ast_analysis),
    };

    if let Err(msg) = validate_scan_options(&opts) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg,
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    let callback_url = opts.callback_url.clone();
    let id = make_scan_id(&url);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            id.clone(),
            Job {
                status: JobStatus::Queued,
                results: None,
                callback_url,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                target_url: url.clone(),
                queued_at_ms: now_ms(),
                started_at_ms: None,
                finished_at_ms: None,
            },
        );
    }
    log(&state, "JOB", &format!("queued id={} url={}", id, url));

    let id_for_resp = id.clone();
    spawn_scan_task(
        state.clone(),
        id,
        url.clone(),
        opts,
        include_request,
        include_response,
    );

    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "scan_id": id_for_resp, "target": url })),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
}

// GET /health — server info and capability discovery
async fn health_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let resp = ApiResponse {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "auth_required": state.api_key.is_some(),
            "endpoints": [
                {"method": "POST", "path": "/scan", "description": "Submit a new XSS scan"},
                {"method": "GET",  "path": "/scan", "description": "Submit a scan via query params (JSONP-friendly)"},
                {"method": "GET",  "path": "/scan/{id}", "description": "Get scan status and results"},
                {"method": "DELETE", "path": "/scan/{id}", "description": "Cancel a scan"},
                {"method": "GET",  "path": "/scans", "description": "List all scans"},
                {"method": "GET",  "path": "/result/{id}", "description": "Get scan status and results (alias)"},
                {"method": "POST", "path": "/preflight", "description": "Parameter discovery without attack payloads"},
                {"method": "GET",  "path": "/health", "description": "Server info and capability discovery"},
            ],
        })),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
}

async fn options_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
}

// DELETE /scan/{id} — cancel a scan
async fn cancel_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    // When ?purge=1, delete the job from memory instead of (or in addition to)
    // cancelling it. Only allowed when the job is already terminal — callers
    // must first cancel a running scan and wait for it to settle.
    let purge_requested = params
        .get("purge")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

    let mut jobs = state.jobs.lock().await;
    match jobs.get_mut(&id) {
        Some(job) => {
            if purge_requested {
                if !job.is_terminal() {
                    let resp = ApiResponse::<serde_json::Value> {
                        code: 409,
                        msg: format!(
                            "cannot purge scan in status '{}' — cancel it first and wait for it to settle",
                            job.status
                        ),
                        data: None,
                    };
                    drop(jobs);
                    return make_api_response(
                        &state,
                        &headers,
                        &params,
                        StatusCode::CONFLICT,
                        &resp,
                    );
                }
                let previous_status = job.status.clone();
                let target_url = job.target_url.clone();
                jobs.remove(&id);
                drop(jobs);
                log(&state, "JOB", &format!("purged id={}", id));
                let resp = ApiResponse {
                    code: 200,
                    msg: "ok".to_string(),
                    data: Some(serde_json::json!({
                        "scan_id": id,
                        "target": target_url,
                        "deleted": true,
                        "previous_status": previous_status,
                    })),
                };
                return make_api_response(&state, &headers, &params, StatusCode::OK, &resp);
            }

            let previous_status = job.status.clone();
            job.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                job.status = JobStatus::Cancelled;
                if job.finished_at_ms.is_none() {
                    job.finished_at_ms = Some(now_ms());
                }
            }
            log(&state, "JOB", &format!("cancelled id={}", id));
            let resp = ApiResponse {
                code: 200,
                msg: "ok".to_string(),
                data: Some(serde_json::json!({
                    "scan_id": id,
                    "target": job.target_url,
                    "cancelled": true,
                    "previous_status": previous_status
                })),
            };
            make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
        }
        None => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 404,
                msg: "not found".to_string(),
                data: None,
            };
            make_api_response(&state, &headers, &params, StatusCode::NOT_FOUND, &resp)
        }
    }
}

// GET /scans — list all scans with status
async fn list_scans_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    let filter_status: Option<JobStatus> = match params
        .get("status")
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        Some(ref s) => match parse_job_status(s) {
            Some(js) => Some(js),
            None => {
                let resp = ApiResponse::<serde_json::Value> {
                    code: 400,
                    msg: format!(
                        "invalid status filter '{}' — must be one of: queued, running, done, error, cancelled",
                        s
                    ),
                    data: None,
                };
                return make_api_response(
                    &state,
                    &headers,
                    &params,
                    StatusCode::BAD_REQUEST,
                    &resp,
                );
            }
        },
        None => None,
    };

    // Optional pagination. offset defaults to 0, limit == 0 means return all.
    let offset: usize = params
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let jobs = state.jobs.lock().await;

    // Collect matching entries with their sort key, then apply offset/limit
    // deterministically by queued_at_ms descending (newest first).
    let mut matching: Vec<(&String, &Job)> = jobs
        .iter()
        .filter(|(_, job)| filter_status.as_ref().is_none_or(|f| &job.status == f))
        .collect();
    matching.sort_by_key(|(_, job)| std::cmp::Reverse(job.queued_at_ms));

    let total = matching.len();
    let start = offset.min(total);
    let end = if limit == 0 {
        total
    } else {
        start.saturating_add(limit).min(total)
    };
    let entries: Vec<serde_json::Value> = matching[start..end]
        .iter()
        .map(|(id, job)| {
            serde_json::json!({
                "scan_id": id,
                "target": job.target_url,
                "status": job.status,
                "result_count": job.results.as_ref().map_or(0, |r| r.len()),
                "queued_at_ms": job.queued_at_ms,
                "started_at_ms": job.started_at_ms,
                "finished_at_ms": job.finished_at_ms,
                "duration_ms": job.duration_ms(),
            })
        })
        .collect();

    let resp = ApiResponse {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({
            "total": total,
            "scans": entries,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "returned": entries.len(),
                "has_more": end < total,
            }
        })),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
}

/// Internal error surface for the preflight pipeline. Produces the right
/// HTTP status code for each failure class instead of always returning 200.
enum PreflightError {
    /// User-supplied URL could not be parsed after the prefix check.
    BadUrl(String),
    /// Server failed to build the inner tokio runtime — infrastructure issue.
    RuntimeUnavailable(String),
    /// The blocking task panicked — infrastructure issue.
    TaskPanicked,
}

/// Build a hydrated Target from the preflight request options.
fn hydrate_preflight_target(
    target_url: &str,
    opts: &ScanOptions,
    timeout_secs: u64,
) -> Result<crate::target_parser::Target, String> {
    let mut t = parse_target(target_url).map_err(|e| format!("parse_target failed: {}", e))?;
    t.method = opts.method.clone().unwrap_or_else(|| "GET".to_string());
    t.timeout = timeout_secs;
    t.user_agent = opts.user_agent.clone();
    t.proxy = opts.proxy.clone();
    t.follow_redirects = opts.follow_redirects.unwrap_or(false);
    t.headers = opts
        .header
        .as_ref()
        .map(|h| {
            h.iter()
                .filter_map(|s| s.split_once(":"))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();
    t.cookies = opts
        .cookie
        .as_ref()
        .map(|c| {
            c.split(';')
                .filter_map(|p| p.trim().split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    t.data = opts.data.clone();
    Ok(t)
}

// POST /preflight — parameter discovery without attack payloads
async fn preflight_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::UNAUTHORIZED, &resp);
    }

    purge_expired_jobs(&state).await;

    let target_url = req.url.trim().to_string();
    if target_url.is_empty()
        || !(target_url.starts_with("http://") || target_url.starts_with("https://"))
    {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url must start with http:// or https://".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    let opts = req.options.clone().unwrap_or_default();
    if let Err(msg) = validate_scan_options(&opts) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg,
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    let timeout_secs = opts
        .timeout
        .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS);

    // Run the analysis on tokio's blocking pool (reused across calls) with a
    // current_thread runtime inside because analyze_parameters and scraper-
    // backed HTML inspection are !Send.
    let outcome: Result<serde_json::Value, PreflightError> =
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| PreflightError::RuntimeUnavailable(e.to_string()))?;
            rt.block_on(async {
                let mut target = hydrate_preflight_target(&target_url, &opts, timeout_secs)
                    .map_err(PreflightError::BadUrl)?;

                // Reachability probe via the target's HTTP stack so proxy,
                // headers, User-Agent, and method match what a real scan sends.
                if !send_reachability_probe(&target).await {
                    return Ok(serde_json::json!({
                        "target": target_url,
                        "reachable": false,
                        "error_code": crate::cmd::error_codes::CONNECTION_FAILED,
                        "params_discovered": 0,
                        "estimated_total_requests": 0,
                        "params": [],
                    }));
                }

                let scan_args = ScanArgs::for_preflight(crate::cmd::scan::PreflightOptions {
                    target: target_url.clone(),
                    param: vec![],
                    method: opts.method.clone().unwrap_or_else(|| "GET".to_string()),
                    data: opts.data.clone(),
                    headers: opts.header.clone().unwrap_or_default(),
                    cookies: opts
                        .cookie
                        .as_ref()
                        .map(|c| vec![c.clone()])
                        .unwrap_or_default(),
                    user_agent: opts.user_agent.clone(),
                    timeout: timeout_secs,
                    proxy: opts.proxy.clone(),
                    follow_redirects: opts.follow_redirects.unwrap_or(false),
                    skip_mining: opts.skip_mining.unwrap_or(false),
                    skip_discovery: opts.skip_discovery.unwrap_or(false),
                    encoders: opts
                        .encoders
                        .clone()
                        .unwrap_or_else(|| vec!["url".to_string(), "html".to_string()]),
                });

                analyze_parameters(&mut target, &scan_args, None).await;

                let enc_factor = {
                    let encs = &scan_args.encoders;
                    if encs.iter().any(|e| e == "none") {
                        1usize
                    } else {
                        let mut f = 1usize;
                        for e in ["url", "html", "2url", "3url", "4url", "base64"] {
                            if encs.iter().any(|x| x == e) {
                                f += 1;
                            }
                        }
                        f
                    }
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
                            let html_len =
                                crate::payload::get_dynamic_xss_html_payloads().len() * enc_factor;
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

                Ok(serde_json::json!({
                    "target": target_url,
                    "reachable": true,
                    "method": target.method,
                    "params_discovered": discovered_params.len(),
                    "estimated_total_requests": estimated_requests,
                    "params": discovered_params,
                }))
            })
        })
        .await
        .unwrap_or(Err(PreflightError::TaskPanicked));

    match outcome {
        Ok(body) => {
            let resp = ApiResponse {
                code: 200,
                msg: "ok".to_string(),
                data: Some(body),
            };
            make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
        }
        Err(PreflightError::BadUrl(msg)) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg: format!("invalid target URL: {}", msg),
                data: None,
            };
            make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp)
        }
        Err(PreflightError::RuntimeUnavailable(msg)) => {
            log(
                &state,
                "ERR",
                &format!("preflight runtime build failed: {}", msg),
            );
            let resp = ApiResponse::<serde_json::Value> {
                code: 500,
                msg: "preflight runtime unavailable".to_string(),
                data: None,
            };
            make_api_response(
                &state,
                &headers,
                &params,
                StatusCode::INTERNAL_SERVER_ERROR,
                &resp,
            )
        }
        Err(PreflightError::TaskPanicked) => {
            log(&state, "ERR", "preflight task panicked");
            let resp = ApiResponse::<serde_json::Value> {
                code: 500,
                msg: "preflight task panicked".to_string(),
                data: None,
            };
            make_api_response(
                &state,
                &headers,
                &params,
                StatusCode::INTERNAL_SERVER_ERROR,
                &resp,
            )
        }
    }
}

pub async fn run_server(args: ServerArgs) {
    let addr_str = format!("{}:{}", args.host, args.port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid bind address {}: {}", addr_str, e);
            return;
        }
    };

    let mut api_key = args.api_key.clone();
    if api_key.is_none()
        && let Ok(v) = std::env::var("DALFOX_API_KEY")
        && !v.is_empty()
    {
        api_key = Some(v);
    }

    // Parse allowed origins, build regex list and wildcard flag
    let allowed_origins_vec = args.allowed_origins.as_ref().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });

    let mut allowed_origin_regexes = Vec::new();
    let mut allow_all_origins = false;
    if let Some(list) = &allowed_origins_vec {
        for item in list {
            if item == "*" {
                allow_all_origins = true;
            } else if let Some(pat) = item.strip_prefix("regex:") {
                match regex::Regex::new(pat) {
                    Ok(re) => allowed_origin_regexes.push(re),
                    Err(e) => eprintln!(
                        "[WRN] ignoring invalid allowed-origins regex '{}': {}",
                        pat, e
                    ),
                }
            } else if item.contains('*') {
                // Convert simple wildcard to regex
                let mut pattern = regex::escape(item);
                pattern = pattern.replace("\\*", ".*");
                let anchored = format!("^{}$", pattern);
                match regex::Regex::new(&anchored) {
                    Ok(re) => allowed_origin_regexes.push(re),
                    Err(e) => eprintln!(
                        "[WRN] ignoring invalid allowed-origins wildcard '{}': {}",
                        item, e
                    ),
                }
            }
        }
    }

    let allow_methods = args
        .cors_allow_methods
        .clone()
        .unwrap_or_else(|| "GET,POST,OPTIONS,PUT,PATCH,DELETE".to_string());
    let allow_headers = args
        .cors_allow_headers
        .clone()
        .unwrap_or_else(|| "Content-Type,X-API-KEY,Authorization".to_string());

    let state = AppState {
        api_key,
        jobs: Arc::new(Mutex::new(HashMap::new())),
        log_file: args.log_file.clone(),
        allowed_origins: allowed_origins_vec,
        allowed_origin_regexes,
        allow_all_origins,
        allow_methods,
        allow_headers,
        jsonp_enabled: args.jsonp,
        callback_param_name: args.callback_param_name.clone(),
    };

    let app = Router::new()
        .route("/scan", post(start_scan_handler))
        .route("/scan", get(get_scan_handler))
        .route("/scan", options(options_scan_handler))
        .route("/scans", get(list_scans_handler))
        .route("/scans", options(options_scan_handler))
        .route("/preflight", post(preflight_handler))
        .route("/preflight", options(options_scan_handler))
        .route("/result/{id}", get(get_result_handler))
        .route("/result/{id}", options(options_result_handler))
        .route("/scan/{id}", get(get_result_handler))
        .route("/scan/{id}", axum::routing::delete(cancel_scan_handler))
        .route("/scan/{id}", options(options_result_handler))
        .route("/health", get(health_handler))
        .route("/health", options(options_scan_handler))
        .with_state(state.clone());

    log(
        &state,
        "SERVER",
        &format!("listening on http://{}", addr_str),
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log(
                &state,
                "ERR",
                &format!("Failed to bind {}: {}", addr_str, e),
            );
            return;
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {}", e);
    }
}

#[cfg(test)]
mod tests;
