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

#[derive(Clone)]
struct Job {
    status: String, // queued | running | done | error
    results: Option<Vec<SanitizedResult>>,
    include_request: bool,
    include_response: bool,
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
}

#[derive(Debug, Clone, Serialize)]
struct ResultPayload {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<SanitizedResult>>,
}

fn check_api_key(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.api_key {
        Some(required) if !required.is_empty() => {
            if let Some(h) = headers.get("X-API-KEY") {
                if let Ok(v) = h.to_str() {
                    return v == required;
                }
            }
            false
        }
        _ => true, // no API key set -> allow all
    }
}

fn make_scan_id(s: &str) -> String {
    crate::utils::make_scan_id(s)
}

/// Return a compact, 7-character prefix of a scan id for log display.
fn short_scan_id(id: &str) -> String {
    crate::utils::short_scan_id(id)
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
    let first = match chars.next() {
        Some(c) => c,
        None => return None,
    };
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

fn build_cors_headers(state: &AppState, req_headers: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if state.allowed_origins.is_none() {
        return headers;
    }

    // Methods/Headers (configured or defaults)
    let allow_methods = state
        .allow_methods
        .parse()
        .unwrap_or_else(|_| "GET,POST,OPTIONS,PUT,PATCH,DELETE".parse().unwrap());
    let allow_headers = state
        .allow_headers
        .parse()
        .unwrap_or_else(|_| "Content-Type,X-API-KEY,Authorization".parse().unwrap());

    // Wildcard
    if state.allow_all_origins {
        headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
        headers.insert("Access-Control-Allow-Methods", allow_methods);
        headers.insert("Access-Control-Allow-Headers", allow_headers);
        return headers;
    }

    // Reflect allowed origins
    if let Some(origin_val) = req_headers.get("Origin") {
        if let Ok(origin_str) = origin_val.to_str() {
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
                headers.insert("Vary", "Origin".parse().unwrap());
            }
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
    mut state: AppState,
    job_id: String,
    url: String,
    opts: ScanOptions,
    include_request: bool,
    include_response: bool,
) {
    {
        let mut jobs = state.jobs.lock().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = "running".to_string();
        }
    }

    let mut args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: None,
        include_request,
        include_response,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,

        param: vec![],
        data: opts.data.clone(),
        headers: opts.header.clone().unwrap_or_default(),
        cookies: {
            let mut v = vec![];
            if let Some(c) = &opts.cookie {
                if !c.trim().is_empty() {
                    v.push(c.clone());
                }
            }
            v
        },
        method: opts.method.clone().unwrap_or_else(|| "GET".to_string()),
        user_agent: opts.user_agent.clone(),
        cookie_from_raw: None,

        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,

        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,

        timeout: 10,
        delay: opts.delay.unwrap_or(0),
        proxy: None,
        follow_redirects: false,

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

        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
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
            t.workers = args.workers;
            t
        }
        Err(_) => {
            let mut jobs = state.jobs.lock().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.status = "error".to_string();
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

    crate::scanning::run_scanning(&target, Arc::new(args.clone()), results.clone(), None, None)
        .await;

    let final_results = {
        let locked = results.lock().await;
        locked
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect::<Vec<_>>()
    };

    let mut jobs = state.jobs.lock().await;
    if let Some(job) = jobs.get_mut(&job_id) {
        job.status = "done".to_string();
        job.results = Some(final_results);
    }
    log(&state, "JOB", &format!("done id={} url={}", job_id, url));
}

async fn start_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let mut cors = build_cors_headers(&state, &headers);
        log(&state, "AUTH", "Unauthorized access to /scan");
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .and_then(|s| validate_jsonp_callback(s))
                .and_then(|raw_cb| {
                    let cb = raw_cb.trim();
                    if cb.is_empty() || cb.len() > 64 {
                        None
                    } else {
                        let mut it = cb.chars();
                        match it.next() {
                            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                if it.all(|ch| {
                                    ch.is_ascii_alphanumeric()
                                        || ch == '_'
                                        || ch == '$'
                                        || ch == '.'
                                }) {
                                    Some(cb.to_string())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                })
            {
                cors.insert(
                    "Content-Type",
                    "application/javascript; charset=utf-8".parse().unwrap(),
                );
                let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                return (StatusCode::UNAUTHORIZED, cors, body);
            }
        }
        let body = serde_json::to_string(&resp).unwrap();
        return (StatusCode::UNAUTHORIZED, cors, body);
    }

    if req.url.trim().is_empty() {
        let mut cors = build_cors_headers(&state, &headers);
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .and_then(|s| validate_jsonp_callback(s))
                .and_then(|raw_cb| {
                    let cb = raw_cb.trim();
                    if cb.is_empty() || cb.len() > 64 {
                        None
                    } else {
                        let mut it = cb.chars();
                        match it.next() {
                            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                if it.all(|ch| {
                                    ch.is_ascii_alphanumeric()
                                        || ch == '_'
                                        || ch == '$'
                                        || ch == '.'
                                }) {
                                    Some(cb.to_string())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                })
            {
                cors.insert(
                    "Content-Type",
                    "application/javascript; charset=utf-8".parse().unwrap(),
                );
                let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                return (StatusCode::BAD_REQUEST, cors, body);
            }
        }
        let body = serde_json::to_string(&resp).unwrap();
        return (StatusCode::BAD_REQUEST, cors, body);
    }

    let opts = req.options.clone().unwrap_or_default();
    let include_request = opts.include_request.unwrap_or(false);
    let include_response = opts.include_response.unwrap_or(false);

    let id = make_scan_id(&req.url);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            id.clone(),
            Job {
                status: "queued".to_string(),
                results: None,
                include_request,
                include_response,
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

    let mut cors = build_cors_headers(&state, &headers);
    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: id,
        data: None,
    };
    if state.jsonp_enabled {
        if let Some(cb) = params
            .get(&state.callback_param_name)
            .and_then(|s| validate_jsonp_callback(s))
            .and_then(|raw_cb| {
                let cb = raw_cb.trim();
                if cb.is_empty() || cb.len() > 64 {
                    None
                } else {
                    let mut it = cb.chars();
                    match it.next() {
                        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                            if it.all(|ch| {
                                ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '.'
                            }) {
                                Some(cb.to_string())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                }
            })
        {
            cors.insert(
                "Content-Type",
                "application/javascript; charset=utf-8".parse().unwrap(),
            );
            let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
            return (StatusCode::OK, cors, body);
        }
    }
    let body = serde_json::to_string(&resp).unwrap();
    (StatusCode::OK, cors, body)
}

async fn get_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let mut cors = build_cors_headers(&state, &headers);
        log(&state, "AUTH", "Unauthorized access to /result");
        let resp = ApiResponse::<ResultPayload> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .and_then(|s| validate_jsonp_callback(s))
                .and_then(|raw_cb| {
                    let cb = raw_cb.trim();
                    if cb.is_empty() || cb.len() > 64 {
                        None
                    } else {
                        let mut it = cb.chars();
                        match it.next() {
                            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                if it.all(|ch| {
                                    ch.is_ascii_alphanumeric()
                                        || ch == '_'
                                        || ch == '$'
                                        || ch == '.'
                                }) {
                                    Some(cb.to_string())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                })
            {
                cors.insert(
                    "Content-Type",
                    "application/javascript; charset=utf-8".parse().unwrap(),
                );
                let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                return (StatusCode::UNAUTHORIZED, cors, body);
            }
        }
        let body = serde_json::to_string(&resp).unwrap();
        return (StatusCode::UNAUTHORIZED, cors, body);
    }

    let job = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).cloned()
    };

    let mut cors = build_cors_headers(&state, &headers);

    match job {
        Some(j) => {
            let payload = ResultPayload {
                status: j.status.clone(),
                results: j.results.clone(),
            };
            log(&state, "RESULT", &format!("id={} status={}", id, j.status));
            let resp = ApiResponse {
                code: 200,
                msg: if j.status == "done" {
                    "ok".to_string()
                } else {
                    "running".to_string()
                },
                data: Some(payload),
            };
            if state.jsonp_enabled {
                if let Some(cb) = params
                    .get(&state.callback_param_name)
                    .and_then(|s| validate_jsonp_callback(s))
                    .and_then(|raw_cb| {
                        let cb = raw_cb.trim();
                        if cb.is_empty() || cb.len() > 64 {
                            None
                        } else {
                            let mut it = cb.chars();
                            match it.next() {
                                Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                    if it.all(|ch| {
                                        ch.is_ascii_alphanumeric()
                                            || ch == '_'
                                            || ch == '$'
                                            || ch == '.'
                                    }) {
                                        Some(cb.to_string())
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        }
                    })
                {
                    cors.insert(
                        "Content-Type",
                        "application/javascript; charset=utf-8".parse().unwrap(),
                    );
                    let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                    return (StatusCode::OK, cors, body);
                }
            }
            let body = serde_json::to_string(&resp).unwrap();
            (StatusCode::OK, cors, body)
        }
        None => {
            let resp = ApiResponse::<ResultPayload> {
                code: 404,
                msg: "not found".to_string(),
                data: None,
            };
            if state.jsonp_enabled {
                if let Some(cb) = params
                    .get(&state.callback_param_name)
                    .and_then(|s| validate_jsonp_callback(s))
                    .and_then(|raw_cb| {
                        let cb = raw_cb.trim();
                        if cb.is_empty() || cb.len() > 64 {
                            None
                        } else {
                            let mut it = cb.chars();
                            match it.next() {
                                Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                    if it.all(|ch| {
                                        ch.is_ascii_alphanumeric()
                                            || ch == '_'
                                            || ch == '$'
                                            || ch == '.'
                                    }) {
                                        Some(cb.to_string())
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        }
                    })
                {
                    cors.insert(
                        "Content-Type",
                        "application/javascript; charset=utf-8".parse().unwrap(),
                    );
                    let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                    return (StatusCode::NOT_FOUND, cors, body);
                }
            }
            let body = serde_json::to_string(&resp).unwrap();
            (StatusCode::NOT_FOUND, cors, body)
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
        let mut cors = build_cors_headers(&state, &headers);
        log(&state, "AUTH", "Unauthorized access to /scan");
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .and_then(|s| validate_jsonp_callback(s))
                .and_then(|raw_cb| {
                    let cb = raw_cb.trim();
                    if cb.is_empty() || cb.len() > 64 {
                        None
                    } else {
                        let mut it = cb.chars();
                        match it.next() {
                            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                if it.all(|ch| {
                                    ch.is_ascii_alphanumeric()
                                        || ch == '_'
                                        || ch == '$'
                                        || ch == '.'
                                }) {
                                    Some(cb.to_string())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                })
            {
                cors.insert(
                    "Content-Type",
                    "application/javascript; charset=utf-8".parse().unwrap(),
                );
                let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                return (StatusCode::UNAUTHORIZED, cors, body);
            }
        }
        let body = serde_json::to_string(&resp).unwrap();
        return (StatusCode::UNAUTHORIZED, cors, body);
    }

    let url = params.get("url").cloned().unwrap_or_default();
    if url.trim().is_empty() {
        let mut cors = build_cors_headers(&state, &headers);
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .and_then(|s| validate_jsonp_callback(s))
                .and_then(|raw_cb| {
                    let cb = raw_cb.trim();
                    if cb.is_empty() || cb.len() > 64 {
                        None
                    } else {
                        let mut it = cb.chars();
                        match it.next() {
                            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                                if it.all(|ch| {
                                    ch.is_ascii_alphanumeric()
                                        || ch == '_'
                                        || ch == '$'
                                        || ch == '.'
                                }) {
                                    Some(cb.to_string())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                })
            {
                cors.insert(
                    "Content-Type",
                    "application/javascript; charset=utf-8".parse().unwrap(),
                );
                let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
                return (StatusCode::BAD_REQUEST, cors, body);
            }
        }
        let body = serde_json::to_string(&resp).unwrap();
        return (StatusCode::BAD_REQUEST, cors, body);
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

    // Reuse POST handler flow by building a ScanRequest and calling the same internal logic:
    let req = ScanRequest {
        url: url.clone(),
        options: Some(ScanOptions {
            cookie,
            worker,
            delay,
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
        }),
    };

    // Call the same pipeline as POST (duplicating minimal code to avoid refactor)
    // Start job (reuse code from start_scan_handler but adapted for GET inputs)
    let opts = req.options.clone().unwrap_or_default();
    let include_request = opts.include_request.unwrap_or(false);
    let include_response = opts.include_response.unwrap_or(false);

    let id = make_scan_id(&req.url);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            id.clone(),
            Job {
                status: "queued".to_string(),
                results: None,
                include_request,
                include_response,
            },
        );
    }
    log(&state, "JOB", &format!("queued id={} url={}", id, req.url));

    let id_for_resp = id.clone();
    let state_clone = state.clone();
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build current-thread runtime");
        rt.block_on(run_scan_job(
            state_clone,
            id.clone(),
            req.url.clone(),
            opts.clone(),
            include_request,
            include_response,
        ));
    });

    let mut cors = build_cors_headers(&state, &headers);
    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: id_for_resp,
        data: None,
    };
    if state.jsonp_enabled {
        if let Some(cb) = params
            .get(&state.callback_param_name)
            .and_then(|s| validate_jsonp_callback(s))
        {
            cors.insert(
                "Content-Type",
                "application/javascript; charset=utf-8".parse().unwrap(),
            );
            let body = format!("{}({});", cb, serde_json::to_string(&resp).unwrap());
            return (StatusCode::OK, cors, body);
        }
    }
    let body = serde_json::to_string(&resp).unwrap();
    (StatusCode::OK, cors, body)
}

async fn options_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
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
    if api_key.is_none() {
        if let Ok(v) = std::env::var("DALFOX_API_KEY") {
            if !v.is_empty() {
                api_key = Some(v);
            }
        }
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
        .route("/result/:id", get(get_result_handler))
        .route("/result/:id", options(options_result_handler))
        .route("/scan/:id", get(get_result_handler))
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
        extract::{Path, Query, State},
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
    };
    use std::collections::HashMap as Map;

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
                    status: "done".to_string(),
                    results: None,
                    include_request: false,
                    include_response: false,
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
                    status: "done".to_string(),
                    results: None,
                    include_request: false,
                    include_response: false,
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
                    status: "running".to_string(),
                    results: None,
                    include_request: false,
                    include_response: false,
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
}
