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

/// Progress counters shared with a running scan task.
#[derive(Clone, Default)]
struct JobProgress {
    requests_sent: Arc<std::sync::atomic::AtomicU64>,
    findings_so_far: Arc<std::sync::atomic::AtomicU64>,
    params_total: Arc<std::sync::atomic::AtomicU32>,
    params_tested: Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Clone)]
struct Job {
    status: JobStatus,
    results: Option<Vec<SanitizedResult>>,
    #[allow(dead_code)] // Used indirectly via ScanArgs
    include_request: bool,
    #[allow(dead_code)] // Used indirectly via ScanArgs
    include_response: bool,
    callback_url: Option<String>,
    progress: JobProgress,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    error_message: Option<String>,
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
}

#[derive(Debug, Clone, Serialize)]
struct ResultPayload {
    status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<SanitizedResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<ProgressPayload>,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressPayload {
    params_total: u32,
    params_tested: u32,
    requests_sent: u64,
    findings_so_far: u64,
    estimated_completion_pct: u32,
}

fn check_api_key(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.api_key {
        Some(required) if !required.is_empty() => {
            if let Some(h) = headers.get("X-API-KEY")
                && let Ok(v) = h.to_str()
            {
                return v == required;
            }
            false
        }
        _ => true, // no API key set -> allow all
    }
}

fn make_scan_id(s: &str) -> String {
    crate::utils::make_scan_id(s)
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
        let exact_allowed = state
            .allowed_origins
            .as_ref()
            .map(|v| {
                v.iter()
                    .any(|o| !o.starts_with("regex:") && o != "*" && o == origin_str)
            })
            .unwrap_or(false);
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
    println!("\x1b[90m{}\x1b[0m {}{}\x1b[0m {}", ts, color, lvl, message);

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

async fn run_scan_job(
    state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    // Grab progress counters and cancellation flag
    let (progress, cancel_flag) = {
        let mut jobs = state.jobs.lock().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Running;
            (job.progress.clone(), job.cancelled.clone())
        } else {
            return;
        }
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
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],

        param: vec![],
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
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,

        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,

        timeout: opts
            .timeout
            .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS),
        delay: opts.delay.unwrap_or(0),
        proxy: None,
        follow_redirects: false,
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
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
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
                .filter_map(|c| c.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
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
            let msg = format!("parse_target failed: {}", e);
            let mut jobs = state.jobs.lock().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.status = JobStatus::Error;
                job.error_message = Some(msg);
                job.results = None;
            }
            return;
        }
    };

    if let Some(callback_url) = &args.blind_callback_url {
        crate::scanning::blind_scanning(&target, callback_url).await;
    }

    let mut silent_args = args.clone();
    silent_args.silence = true;
    analyze_parameters(&mut target, &silent_args, None).await;

    // Snapshot request count before scanning
    let req_count_before = crate::REQUEST_COUNT.load(std::sync::atomic::Ordering::Relaxed);

    // Record discovered param count
    progress.params_total.store(
        target.reflection_params.len() as u32,
        std::sync::atomic::Ordering::Relaxed,
    );

    let param_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    crate::scanning::run_scanning(
        &target,
        Arc::new(args.clone()),
        results.clone(),
        None,
        None,
        param_counter.clone(),
        Some(cancel_flag.clone()),
    )
    .await;

    // Final progress snapshot
    let req_count_after = crate::REQUEST_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    progress.requests_sent.store(
        req_count_after.saturating_sub(req_count_before),
        std::sync::atomic::Ordering::Relaxed,
    );
    progress.params_tested.store(
        param_counter.load(std::sync::atomic::Ordering::Relaxed) as u32,
        std::sync::atomic::Ordering::Relaxed,
    );

    let was_cancelled = cancel_flag.load(std::sync::atomic::Ordering::Relaxed);

    let final_results = {
        let locked = results.lock().await;
        progress.findings_so_far.store(
            locked.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        locked
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect::<Vec<_>>()
    };

    let callback_url = {
        let mut jobs = state.jobs.lock().await;
        let cb = if let Some(job) = jobs.get_mut(&job_id) {
            job.results = Some(final_results.clone());
            if job.status != JobStatus::Cancelled {
                job.status = if was_cancelled {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Done
                };
            }
            job.callback_url.clone()
        } else {
            None
        };
        cb
    };
    let status_label = if was_cancelled { "cancelled" } else { "done" };
    log(&state, "JOB", &format!("{} id={} url={}", status_label, job_id, url));

    // Fire webhook callback if configured (only http/https to mitigate SSRF)
    if let Some(cb_url) = callback_url
        && (cb_url.starts_with("http://") || cb_url.starts_with("https://"))
    {
        let payload = serde_json::json!({
            "scan_id": job_id,
            "status": "done",
            "url": url,
            "results": final_results
        });
        let cb_result: Result<reqwest::Response, reqwest::Error> = reqwest::Client::new()
            .post(&cb_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;
        match cb_result {
            Ok(resp) => {
                log(
                    &state,
                    "CALLBACK",
                    &format!("POST {} -> {}", cb_url, resp.status()),
                );
            }
            Err(e) => {
                log(
                    &state,
                    "CALLBACK",
                    &format!("POST {} failed: {}", cb_url, e),
                );
            }
        }
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

    if req.url.trim().is_empty() {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }

    let opts = req.options.clone().unwrap_or_default();
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
                include_request,
                include_response,
                callback_url: callback_url.clone(),
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
            },
        );
    }
    log(&state, "JOB", &format!("queued id={} url={}", id, req.url));

    // Spawn the scanning task (run !Send future inside blocking thread with local runtime)
    let state_clone = state.clone();
    let url = req.url.clone();
    let job_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build current-thread runtime");
        rt.block_on(run_scan_job(
            state_clone,
            job_id,
            url,
            opts.clone(),
            include_request,
            include_response,
        ));
    });

    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "scan_id": id })),
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

    let job = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).cloned()
    };

    match job {
        Some(j) => {
            let progress_data = if matches!(j.status, JobStatus::Running | JobStatus::Done | JobStatus::Cancelled) {
                let params_total = j.progress.params_total.load(std::sync::atomic::Ordering::Relaxed);
                let params_tested = j.progress.params_tested.load(std::sync::atomic::Ordering::Relaxed);
                let estimated_completion_pct = if matches!(j.status, JobStatus::Done | JobStatus::Cancelled) {
                    if j.status == JobStatus::Done { 100 } else if params_total > 0 {
                        ((params_tested as f64 / params_total as f64) * 100.0) as u32
                    } else { 0 }
                } else if params_total > 0 {
                    ((params_tested as f64 / params_total as f64) * 100.0).min(99.0) as u32
                } else {
                    0
                };
                Some(ProgressPayload {
                    params_total,
                    params_tested,
                    requests_sent: j.progress.requests_sent.load(std::sync::atomic::Ordering::Relaxed),
                    findings_so_far: j.progress.findings_so_far.load(std::sync::atomic::Ordering::Relaxed),
                    estimated_completion_pct,
                })
            } else {
                None
            };
            let payload = ResultPayload {
                status: j.status.clone(),
                results: j.results.clone(),
                error_message: j.error_message.clone(),
                progress: progress_data,
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
    let include_request = params
        .get("include_request")
        .map(|s| s == "true")
        .unwrap_or(false);
    let include_response = params
        .get("include_response")
        .map(|s| s == "true")
        .unwrap_or(false);

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
    };

    let callback_url = opts.callback_url.clone();
    let id = make_scan_id(&url);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            id.clone(),
            Job {
                status: JobStatus::Queued,
                results: None,
                include_request,
                include_response,
                callback_url,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
            },
        );
    }
    log(&state, "JOB", &format!("queued id={} url={}", id, url));

    let id_for_resp = id.clone();
    let state_clone = state.clone();
    let url_clone = url.clone();
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build current-thread runtime");
        rt.block_on(run_scan_job(
            state_clone,
            id,
            url_clone,
            opts,
            include_request,
            include_response,
        ));
    });

    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "scan_id": id_for_resp })),
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

// DELETE /scan/:id — cancel a scan
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

    let mut jobs = state.jobs.lock().await;
    match jobs.get_mut(&id) {
        Some(job) => {
            let previous_status = job.status.clone();
            job.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                job.status = JobStatus::Cancelled;
            }
            log(&state, "JOB", &format!("cancelled id={}", id));
            let resp = ApiResponse {
                code: 200,
                msg: "ok".to_string(),
                data: Some(serde_json::json!({
                    "scan_id": id,
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

    let filter_status = params.get("status").map(|s| s.trim().to_lowercase());
    let jobs = state.jobs.lock().await;
    let entries: Vec<serde_json::Value> = jobs
        .iter()
        .filter(|(_, job)| {
            if let Some(ref f) = filter_status {
                job.status.to_string() == *f
            } else {
                true
            }
        })
        .map(|(id, job)| {
            serde_json::json!({
                "scan_id": id,
                "status": job.status,
                "result_count": job.results.as_ref().map(|r| r.len()).unwrap_or(0)
            })
        })
        .collect();

    let resp = ApiResponse {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({
            "total": entries.len(),
            "scans": entries
        })),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
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

    // Run preflight synchronously in a blocking thread
    let result = tokio::task::spawn_blocking(move || {
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(async {
                // Reachability check
                let timeout_secs = opts.timeout.unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS);
                let reachable = {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(timeout_secs))
                        .danger_accept_invalid_certs(true)
                        .redirect(reqwest::redirect::Policy::none())
                        .build();
                    match client {
                        Ok(c) => c.get(&target_url).send().await.is_ok(),
                        Err(_) => false,
                    }
                };
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

                let mut target = match parse_target(&target_url) {
                    Ok(mut t) => {
                        t.method = opts.method.clone().unwrap_or_else(|| "GET".to_string());
                        t.timeout = timeout_secs;
                        t.user_agent = opts.user_agent.clone().or(Some("".to_string()));
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
                        t
                    }
                    Err(_) => {
                        return serde_json::json!({
                            "target": target_url,
                            "reachable": true,
                            "error_code": crate::cmd::error_codes::PARSE_ERROR,
                            "params_discovered": 0,
                            "estimated_total_requests": 0,
                            "params": [],
                        });
                    }
                };

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
                    proxy: None,
                    follow_redirects: false,
                    skip_mining: false,
                    skip_discovery: false,
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
            }),
            Err(e) => serde_json::json!({
                "target": target_url,
                "reachable": false,
                "error": format!("runtime error: {}", e),
            }),
        }
    })
    .await
    .unwrap_or_else(|_| serde_json::json!({"error": "preflight thread panicked"}));

    let resp = ApiResponse {
        code: 200,
        msg: "ok".to_string(),
        data: Some(result),
    };
    make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
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
                if let Ok(re) = regex::Regex::new(pat) {
                    allowed_origin_regexes.push(re);
                }
            } else if item.contains('*') {
                // Convert simple wildcard to regex
                let mut pattern = regex::escape(item);
                pattern = pattern.replace("\\*", ".*");
                let anchored = format!("^{}$", pattern);
                if let Ok(re) = regex::Regex::new(&anchored) {
                    allowed_origin_regexes.push(re);
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
        .route("/result/:id", get(get_result_handler))
        .route("/result/:id", options(options_result_handler))
        .route("/scan/:id", get(get_result_handler))
        .route("/scan/:id", axum::routing::delete(cancel_scan_handler))
        .route("/scan/:id", options(options_result_handler))
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
mod tests {
    use super::*;
    use axum::{
        Router, body,
        extract::{Path, Query, State},
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
        routing::any,
    };
    use std::collections::HashMap as Map;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn make_state(
        api_key: Option<&str>,
        origins: Option<Vec<&str>>,
        allow_all: bool,
        jsonp: bool,
        cb_name: &str,
    ) -> AppState {
        AppState {
            api_key: api_key.map(|s| s.to_string()),
            jobs: Arc::new(Mutex::new(std::collections::HashMap::new())),
            log_file: None,
            allowed_origins: origins.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
            allowed_origin_regexes: vec![],
            allow_all_origins: allow_all,
            allow_methods: "GET,POST,OPTIONS,PUT,PATCH,DELETE".to_string(),
            allow_headers: "Content-Type,X-API-KEY,Authorization".to_string(),
            jsonp_enabled: jsonp,
            callback_param_name: cb_name.to_string(),
        }
    }

    fn temp_log_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dalfox-server-{}-{}.log",
            name,
            crate::utils::make_scan_id(name)
        ))
    }

    async fn response_body_string(resp: axum::response::Response) -> String {
        let bytes = body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response bytes");
        String::from_utf8(bytes.to_vec()).expect("utf8 response")
    }

    async fn target_ok_handler() -> impl IntoResponse {
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            "<html><body>ok</body></html>",
        )
    }

    async fn start_target_server() -> SocketAddr {
        let app = Router::new()
            .route("/", any(target_ok_handler))
            .route("/*rest", any(target_ok_handler));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target listener");
        let addr = listener.local_addr().expect("target local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    #[test]
    fn test_check_api_key_variants() {
        let state_no_key = make_state(None, None, false, false, "callback");
        let headers = HeaderMap::new();
        assert!(check_api_key(&state_no_key, &headers));

        let state_with_key = make_state(Some("secret"), None, false, false, "callback");
        assert!(!check_api_key(&state_with_key, &headers));

        let mut ok_headers = HeaderMap::new();
        ok_headers.insert("X-API-KEY", HeaderValue::from_static("secret"));
        assert!(check_api_key(&state_with_key, &ok_headers));

        let mut bad_headers = HeaderMap::new();
        bad_headers.insert("X-API-KEY", HeaderValue::from_static("wrong"));
        assert!(!check_api_key(&state_with_key, &bad_headers));
    }

    #[test]
    fn test_make_and_short_scan_id_shape() {
        let id = make_scan_id("https://example.com");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(crate::utils::short_scan_id(&id).len(), 7);
        assert_eq!(crate::utils::short_scan_id("abc"), "abc");
    }

    #[test]
    fn test_validate_jsonp_callback_accepts_and_rejects() {
        assert_eq!(
            validate_jsonp_callback(" cb.func_1 "),
            Some("cb.func_1".to_string())
        );
        assert_eq!(validate_jsonp_callback("$name"), Some("$name".to_string()));
        assert!(validate_jsonp_callback("").is_none());
        assert!(validate_jsonp_callback("1abc").is_none());
        assert!(validate_jsonp_callback("a-b").is_none());
        assert!(validate_jsonp_callback(&"a".repeat(65)).is_none());
    }

    #[test]
    fn test_build_cors_headers_none_all_exact_regex_and_fallbacks() {
        let req_headers = HeaderMap::new();
        let state_none = make_state(None, None, false, false, "callback");
        let none_headers = build_cors_headers(&state_none, &req_headers);
        assert!(none_headers.is_empty());

        let state_all = make_state(None, Some(vec!["*"]), true, false, "callback");
        let all_headers = build_cors_headers(&state_all, &req_headers);
        assert_eq!(
            all_headers
                .get("Access-Control-Allow-Origin")
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );

        let state_exact = make_state(
            None,
            Some(vec!["http://localhost:3000"]),
            false,
            false,
            "callback",
        );
        let mut exact_req_headers = HeaderMap::new();
        exact_req_headers.insert("Origin", HeaderValue::from_static("http://localhost:3000"));
        let exact_headers = build_cors_headers(&state_exact, &exact_req_headers);
        assert_eq!(
            exact_headers
                .get("Access-Control-Allow-Origin")
                .and_then(|v| v.to_str().ok()),
            Some("http://localhost:3000")
        );
        assert_eq!(
            exact_headers.get("Vary").and_then(|v| v.to_str().ok()),
            Some("Origin")
        );

        let mut state_regex =
            make_state(None, Some(vec!["http://dummy"]), false, false, "callback");
        state_regex.allowed_origin_regexes =
            vec![regex::Regex::new(r"^https://.*\.example\.com$").expect("valid regex")];
        let mut regex_req_headers = HeaderMap::new();
        regex_req_headers.insert(
            "Origin",
            HeaderValue::from_static("https://api.example.com"),
        );
        let regex_headers = build_cors_headers(&state_regex, &regex_req_headers);
        assert_eq!(
            regex_headers
                .get("Access-Control-Allow-Origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://api.example.com")
        );

        let mut state_fallback = make_state(None, Some(vec!["http://x"]), false, false, "callback");
        state_fallback.allow_methods = "\n".to_string();
        state_fallback.allow_headers = "\n".to_string();
        let fallback_headers = build_cors_headers(&state_fallback, &HeaderMap::new());
        assert!(
            fallback_headers
                .get("Access-Control-Allow-Methods")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("GET"))
                .unwrap_or(false)
        );
        assert!(
            fallback_headers
                .get("Access-Control-Allow-Headers")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("Content-Type"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn test_log_writes_to_file_and_supports_unknown_level() {
        let mut state = make_state(None, None, false, false, "callback");
        let path = temp_log_path("log-test");
        let _ = std::fs::remove_file(&path);
        state.log_file = Some(path.to_string_lossy().to_string());

        log(&state, "CUSTOM", "hello-log");
        let content = std::fs::read_to_string(&path).expect("log file should be readable");
        assert!(content.contains("[CUSTOM] hello-log"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_run_scan_job_invalid_target_sets_error() {
        let state = make_state(None, None, false, false, "callback");
        let id = "scan-job-error".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Queued,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        run_scan_job(
            state.clone(),
            id.clone(),
            "not a valid target".to_string(),
            ScanOptions::default(),
            false,
            false,
        )
        .await;

        let jobs = state.jobs.lock().await;
        let job = jobs.get(&id).expect("job should exist");
        assert_eq!(job.status, JobStatus::Error);
    }

    #[tokio::test]
    async fn test_get_scan_handler_unauthorized_and_bad_request_jsonp() {
        let state_auth = make_state(Some("secret"), None, false, true, "cb");
        let mut params_auth = Map::new();
        params_auth.insert("cb".to_string(), "myFn".to_string());
        params_auth.insert("url".to_string(), "http://example.com".to_string());
        let headers_missing_key = HeaderMap::new();

        let unauthorized_resp =
            get_scan_handler(State(state_auth), headers_missing_key, Query(params_auth))
                .await
                .into_response();
        assert_eq!(unauthorized_resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            unauthorized_resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .starts_with("application/javascript")
        );

        let state_no_key = make_state(None, None, false, true, "cb");
        let mut params_bad_req = Map::new();
        params_bad_req.insert("cb".to_string(), "myFn".to_string());
        let bad_req_resp =
            get_scan_handler(State(state_no_key), HeaderMap::new(), Query(params_bad_req))
                .await
                .into_response();
        assert_eq!(bad_req_resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            bad_req_resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .starts_with("application/javascript")
        );
    }

    #[tokio::test]
    async fn test_get_result_handler_not_found_jsonp() {
        let state = make_state(None, None, false, true, "cb");
        let mut q = Map::new();
        q.insert("cb".to_string(), "resultCb".to_string());
        let resp = get_result_handler(
            State(state),
            HeaderMap::new(),
            Path("missing-id".to_string()),
            Query(q),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .starts_with("application/javascript")
        );
    }

    #[tokio::test]
    async fn test_options_scan_handler_returns_no_content() {
        let state = make_state(None, Some(vec!["*"]), true, false, "callback");
        let mut headers = HeaderMap::new();
        headers.insert("Origin", HeaderValue::from_static("http://any.origin"));

        let resp = options_scan_handler(State(state), headers)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
    }

    #[tokio::test]
    async fn test_cors_headers_on_result_exact_origin() {
        let state = make_state(
            Some("secret"),
            Some(vec!["http://localhost:3000"]),
            false,
            false,
            "callback",
        );

        // Insert a dummy job
        let id = "job1".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Done,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        // Build headers with API key and Origin
        let mut headers = HeaderMap::new();
        headers.insert("X-API-KEY", HeaderValue::from_static("secret"));
        headers.insert("Origin", HeaderValue::from_static("http://localhost:3000"));

        let resp = super::get_result_handler(
            State(state.clone()),
            headers,
            Path(id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(allow_origin, "http://localhost:3000");

        let allow_methods = resp
            .headers()
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(allow_methods.contains("GET"));
        assert!(allow_methods.contains("POST"));
        assert!(allow_methods.contains("OPTIONS"));
    }

    #[tokio::test]
    async fn test_jsonp_unauthorized_with_callback() {
        let state = make_state(Some("secret"), None, false, true, "cb");

        // No API key header provided to trigger 401
        let mut headers = HeaderMap::new();
        headers.insert("Origin", HeaderValue::from_static("http://evil.test"));

        // Provide ?cb=myFunc in query to request JSONP
        let mut q = Map::new();
        q.insert("cb".to_string(), "myFunc".to_string());

        let resp = super::get_result_handler(
            State(state.clone()),
            headers,
            Path("nojob".to_string()),
            Query(q),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ctype.starts_with("application/javascript"));
    }

    #[tokio::test]
    async fn test_auth_success_and_failure() {
        let state = make_state(Some("secret"), None, false, false, "callback");

        // Insert a dummy job for success case
        let ok_id = "ok".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                ok_id.clone(),
                Job {
                    status: JobStatus::Done,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        // Failure (no key)
        let headers_fail = HeaderMap::new();
        let resp_fail = super::get_result_handler(
            State(state.clone()),
            headers_fail,
            Path(ok_id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp_fail.status(), StatusCode::UNAUTHORIZED);

        // Success
        let mut headers_ok = HeaderMap::new();
        headers_ok.insert("X-API-KEY", HeaderValue::from_static("secret"));
        let resp_ok = super::get_result_handler(
            State(state.clone()),
            headers_ok,
            Path(ok_id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp_ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_options_preflight_headers() {
        let state = make_state(None, Some(vec!["*"]), true, false, "callback");

        let mut headers = HeaderMap::new();
        headers.insert("Origin", HeaderValue::from_static("http://any.example"));

        let resp =
            super::options_result_handler(State(state.clone()), headers, Path("any".to_string()))
                .await
                .into_response();

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(allow_origin, "*");

        let allow_methods = resp
            .headers()
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(allow_methods.contains("OPTIONS"));
    }

    #[tokio::test]
    async fn test_scan_alternate_path_uses_same_handler_semantics() {
        // This test validates that the result handler semantics (used by /result/:id)
        // are suitable for /scan/:id as well (same handler wired).
        let state = make_state(Some("secret"), None, false, false, "callback");

        // Insert job
        let id = "alt".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Running,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert("X-API-KEY", HeaderValue::from_static("secret"));

        // Directly call the same handler that is wired to both /result/:id and /scan/:id
        let resp = super::get_result_handler(
            State(state.clone()),
            headers,
            Path(id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_start_scan_handler_unauthorized_and_bad_request_jsonp() {
        let state_auth = make_state(Some("secret"), None, false, true, "cb");
        let mut params_auth = Map::new();
        params_auth.insert("cb".to_string(), "startCb".to_string());
        let unauthorized_resp = start_scan_handler(
            State(state_auth),
            HeaderMap::new(),
            Query(params_auth),
            Json(ScanRequest {
                url: "http://example.com".to_string(),
                options: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(unauthorized_resp.status(), StatusCode::UNAUTHORIZED);
        let unauthorized_body = response_body_string(unauthorized_resp).await;
        assert!(unauthorized_body.starts_with("startCb("));

        let state_no_key = make_state(None, None, false, true, "cb");
        let mut params_bad_req = Map::new();
        params_bad_req.insert("cb".to_string(), "startCb".to_string());
        let bad_req_resp = start_scan_handler(
            State(state_no_key),
            HeaderMap::new(),
            Query(params_bad_req),
            Json(ScanRequest {
                url: "   ".to_string(),
                options: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(bad_req_resp.status(), StatusCode::BAD_REQUEST);
        let bad_req_body = response_body_string(bad_req_resp).await;
        assert!(bad_req_body.starts_with("startCb("));
    }

    #[tokio::test]
    async fn test_start_scan_handler_success_creates_queued_job() {
        let state = make_state(None, None, false, false, "cb");
        let resp = start_scan_handler(
            State(state.clone()),
            HeaderMap::new(),
            Query(Map::new()),
            Json(ScanRequest {
                url: "not-a-valid-target".to_string(),
                options: Some(ScanOptions {
                    include_request: Some(true),
                    include_response: Some(true),
                    ..ScanOptions::default()
                }),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json response");
        let id = parsed["data"]["scan_id"]
            .as_str()
            .expect("scan id should be present")
            .to_string();
        let jobs = state.jobs.lock().await;
        let job = jobs.get(&id).expect("job should be inserted");
        // The spawned task may move from Queued to Running/Done/Error very quickly
        assert!(
            matches!(job.status, JobStatus::Queued | JobStatus::Running | JobStatus::Done | JobStatus::Error),
            "job should have been created with a valid status, got: {:?}",
            job.status
        );
        assert!(job.include_request);
        assert!(job.include_response);
    }

    #[tokio::test]
    async fn test_start_scan_handler_success_jsonp_response() {
        let state = make_state(None, None, false, true, "cb");
        let mut q = Map::new();
        q.insert("cb".to_string(), "scanCb".to_string());
        let resp = start_scan_handler(
            State(state),
            HeaderMap::new(),
            Query(q),
            Json(ScanRequest {
                url: "still-not-valid-target".to_string(),
                options: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body_string(resp).await;
        assert!(body.starts_with("scanCb("));
    }

    #[tokio::test]
    async fn test_get_result_handler_plain_json_branches() {
        let state_auth = make_state(Some("secret"), None, false, false, "callback");
        let unauthorized = get_result_handler(
            State(state_auth),
            HeaderMap::new(),
            Path("id".to_string()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let body = response_body_string(unauthorized).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(parsed["code"], 401);

        let state_no_key = make_state(None, None, false, false, "callback");
        let not_found = get_result_handler(
            State(state_no_key),
            HeaderMap::new(),
            Path("missing".to_string()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
        let nf_body = response_body_string(not_found).await;
        let nf_parsed: serde_json::Value = serde_json::from_str(&nf_body).expect("json body");
        assert_eq!(nf_parsed["code"], 404);
    }

    #[tokio::test]
    async fn test_get_result_handler_running_message_branch() {
        let state = make_state(None, None, false, false, "callback");
        let id = "running-job".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Running,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        let resp = get_result_handler(State(state), HeaderMap::new(), Path(id), Query(Map::new()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(parsed["msg"], "ok");
        assert_eq!(parsed["data"]["status"], "running");
    }

    #[tokio::test]
    async fn test_get_scan_handler_success_parses_query_options_and_jsonp() {
        let state = make_state(None, None, false, true, "cb");
        let mut params = Map::new();
        params.insert("cb".to_string(), "getCb".to_string());
        params.insert("url".to_string(), "bad-target-for-fast-fail".to_string());
        params.insert("header".to_string(), "X-A:1,Invalid,X-B:2".to_string());
        params.insert("encoders".to_string(), "url,html,base64".to_string());
        params.insert("worker".to_string(), "3".to_string());
        params.insert("delay".to_string(), "1".to_string());
        params.insert("blind".to_string(), "http://callback.local".to_string());
        params.insert("method".to_string(), "POST".to_string());
        params.insert("data".to_string(), "k=v".to_string());
        params.insert("user_agent".to_string(), "Dalfox-Test-UA".to_string());
        params.insert("include_request".to_string(), "true".to_string());
        params.insert("include_response".to_string(), "true".to_string());
        params.insert(
            "remote_payloads".to_string(),
            "unknown-provider".to_string(),
        );
        params.insert(
            "remote_wordlists".to_string(),
            "unknown-provider".to_string(),
        );

        let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body_string(resp).await;
        assert!(body.starts_with("getCb("));
        let inner = body.trim_start_matches("getCb(").trim_end_matches(");");
        let parsed: serde_json::Value = serde_json::from_str(inner).expect("jsonp payload");
        let id = parsed["data"]["scan_id"].as_str().expect("scan id").to_string();

        let jobs = state.jobs.lock().await;
        let job = jobs.get(&id).expect("job inserted");
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.include_request);
        assert!(job.include_response);
    }

    #[tokio::test]
    async fn test_run_scan_job_success_marks_done() {
        let addr = start_target_server().await;
        let state = make_state(None, None, false, false, "callback");
        let id = "scan-job-success".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Queued,
                    results: None,
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        let opts = ScanOptions {
            cookie: Some("session=abc".to_string()),
            worker: Some(4),
            delay: Some(0),
            timeout: None,
            blind: None,
            header: Some(vec![
                "X-Test: 1".to_string(),
                "InvalidHeaderLine".to_string(),
                ":empty-name".to_string(),
            ]),
            method: Some("GET".to_string()),
            data: None,
            user_agent: Some("Dalfox-Server-Test".to_string()),
            encoders: Some(vec!["none".to_string()]),
            remote_payloads: Some(vec!["unknown-provider".to_string()]),
            remote_wordlists: Some(vec!["unknown-provider".to_string()]),
            include_request: Some(false),
            include_response: Some(false),
            callback_url: None,
        };

        let run = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run_scan_job(
                state.clone(),
                id.clone(),
                format!("http://{}/", addr),
                opts,
                false,
                false,
            ),
        )
        .await;
        assert!(run.is_ok(), "run_scan_job should complete in time");

        let jobs = state.jobs.lock().await;
        let job = jobs.get(&id).expect("job should remain");
        assert_eq!(job.status, JobStatus::Done);
        assert!(job.results.is_some());
    }

    #[tokio::test]
    async fn test_get_result_handler_jsonp_done_branch() {
        let state = make_state(None, None, false, true, "cb");
        let id = "done-jsonp".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                id.clone(),
                Job {
                    status: JobStatus::Done,
                    results: Some(Vec::new()),
                    include_request: false,
                    include_response: false,
                callback_url: None,
                progress: JobProgress::default(),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error_message: None,
                },
            );
        }

        let mut q = Map::new();
        q.insert("cb".to_string(), "doneCb".to_string());
        let resp = get_result_handler(State(state), HeaderMap::new(), Path(id), Query(q))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .starts_with("application/javascript")
        );
        let body = response_body_string(resp).await;
        assert!(body.starts_with("doneCb("));
    }

    #[tokio::test]
    async fn test_get_scan_handler_success_plain_json_defaults() {
        let state = make_state(None, None, false, false, "cb");
        let mut params = Map::new();
        params.insert("url".to_string(), "still-invalid-for-fast-fail".to_string());

        let resp = get_scan_handler(State(state.clone()), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
        let id = parsed["data"]["scan_id"].as_str().expect("scan id").to_string();

        let jobs = state.jobs.lock().await;
        let job = jobs.get(&id).expect("job inserted");
        assert_eq!(job.status, JobStatus::Queued);
        assert!(!job.include_request);
        assert!(!job.include_response);
    }

    #[tokio::test]
    async fn test_run_server_returns_on_invalid_bind_address() {
        run_server(ServerArgs {
            port: 6664,
            host: "not a valid host".to_string(),
            api_key: None,
            log_file: None,
            allowed_origins: None,
            jsonp: false,
            callback_param_name: "callback".to_string(),
            cors_allow_methods: None,
            cors_allow_headers: None,
        })
        .await;
    }

    #[tokio::test]
    async fn test_run_server_returns_on_bind_failure_after_state_build() {
        let guard_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind guard listener");
        let guard_addr = guard_listener.local_addr().expect("guard addr");

        run_server(ServerArgs {
            port: guard_addr.port(),
            host: Ipv4Addr::LOCALHOST.to_string(),
            api_key: Some("server-key".to_string()),
            log_file: None,
            allowed_origins: Some(
                "*,regex:^https://.*\\.example\\.com$,https://*.corp.local".to_string(),
            ),
            jsonp: true,
            callback_param_name: "cb".to_string(),
            cors_allow_methods: Some("GET,POST,OPTIONS".to_string()),
            cors_allow_headers: Some("Content-Type,X-API-KEY".to_string()),
        })
        .await;

        drop(guard_listener);
    }

    // ---- Tests for new endpoints: cancel, list, preflight ----

    #[tokio::test]
    async fn test_cancel_scan_handler_cancels_queued_job() {
        let state = make_state(None, None, false, false, "cb");
        let scan_id = "cancel-test-id".to_string();
        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(
                scan_id.clone(),
                Job {
                    status: JobStatus::Queued,
                    results: None,
                    include_request: false,
                    include_response: false,
                    callback_url: None,
                    progress: JobProgress::default(),
                    cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    error_message: None,
                },
            );
        }

        let resp = cancel_scan_handler(
            State(state.clone()),
            HeaderMap::new(),
            Path(scan_id.clone()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["data"]["cancelled"], true);
        assert_eq!(parsed["data"]["previous_status"], "queued");

        let jobs = state.jobs.lock().await;
        let job = jobs.get(&scan_id).expect("job still exists");
        assert_eq!(job.status, JobStatus::Cancelled);
        assert!(job.cancelled.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_cancel_scan_handler_returns_404_for_unknown_id() {
        let state = make_state(None, None, false, false, "cb");
        let resp = cancel_scan_handler(
            State(state),
            HeaderMap::new(),
            Path("nonexistent".to_string()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cancel_scan_handler_requires_auth() {
        let state = make_state(Some("secret"), None, false, false, "cb");
        let resp = cancel_scan_handler(
            State(state),
            HeaderMap::new(),
            Path("any".to_string()),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_scans_handler_returns_all_jobs() {
        let state = make_state(None, None, false, false, "cb");
        {
            let mut jobs = state.jobs.lock().await;
            for (id, status) in [("a", JobStatus::Done), ("b", JobStatus::Running)] {
                jobs.insert(
                    id.to_string(),
                    Job {
                        status,
                        results: None,
                        include_request: false,
                        include_response: false,
                        callback_url: None,
                        progress: JobProgress::default(),
                        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        error_message: None,
                    },
                );
            }
        }

        let resp = list_scans_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["data"]["total"], 2);
        assert_eq!(parsed["data"]["scans"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_scans_handler_filters_by_status() {
        let state = make_state(None, None, false, false, "cb");
        {
            let mut jobs = state.jobs.lock().await;
            for (id, status) in [("a", JobStatus::Done), ("b", JobStatus::Running)] {
                jobs.insert(
                    id.to_string(),
                    Job {
                        status,
                        results: None,
                        include_request: false,
                        include_response: false,
                        callback_url: None,
                        progress: JobProgress::default(),
                        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        error_message: None,
                    },
                );
            }
        }

        let mut params = Map::new();
        params.insert("status".to_string(), "done".to_string());
        let resp = list_scans_handler(
            State(state),
            HeaderMap::new(),
            Query(params),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["data"]["total"], 1);
        assert_eq!(parsed["data"]["scans"][0]["status"], "done");
    }

    #[tokio::test]
    async fn test_list_scans_handler_requires_auth() {
        let state = make_state(Some("secret"), None, false, false, "cb");
        let resp = list_scans_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_preflight_handler_rejects_invalid_url() {
        let state = make_state(None, None, false, false, "cb");
        let resp = preflight_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
            Json(ScanRequest {
                url: "not-http".to_string(),
                options: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_preflight_handler_requires_auth() {
        let state = make_state(Some("secret"), None, false, false, "cb");
        let resp = preflight_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
            Json(ScanRequest {
                url: "http://example.com".to_string(),
                options: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_preflight_handler_unreachable_target() {
        let state = make_state(None, None, false, false, "cb");
        let resp = preflight_handler(
            State(state),
            HeaderMap::new(),
            Query(Map::new()),
            Json(ScanRequest {
                url: "http://127.0.0.1:1/unreachable".to_string(),
                options: Some(ScanOptions {
                    timeout: Some(1),
                    ..ScanOptions::default()
                }),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["data"]["reachable"], false);
        assert_eq!(parsed["data"]["error_code"], "CONNECTION_FAILED");
    }
}
