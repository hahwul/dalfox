use clap::Args;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, options, post},
};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", s, now));
    let digest = hasher.finalize();
    hex::encode(digest)
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

        targets: vec![url.clone()],
    };

    let results = Arc::new(Mutex::new(Vec::<ScanResult>::new()));

    let mut target = match parse_target(&url) {
        Ok(mut t) => {
            t.data = args.data.clone();
            t.headers = args
                .headers
                .iter()
                .filter_map(|h| h.split_once(": "))
                .map(|(k, v)| (k.to_string(), v.to_string()))
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
}

async fn start_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if !check_api_key(&state, &headers) {
        let mut cors = build_cors_headers(&state, &headers);
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .filter(|s| !s.is_empty())
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
                .filter(|s| !s.is_empty())
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

    // Spawn the scanning task
    let state_clone = state.clone();
    let url = req.url.clone();
    let job_id = id.clone();
    std::thread::spawn(move || {
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
            .filter(|s| !s.is_empty())
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
        let resp = ApiResponse::<ResultPayload> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .filter(|s| !s.is_empty())
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
                    .filter(|s| !s.is_empty())
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
                    .filter(|s| !s.is_empty())
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
        let resp = ApiResponse::<serde_json::Value> {
            code: 401,
            msg: "unauthorized".to_string(),
            data: None,
        };
        if state.jsonp_enabled {
            if let Some(cb) = params
                .get(&state.callback_param_name)
                .filter(|s| !s.is_empty())
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
                .filter(|s| !s.is_empty())
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

    let id_for_resp = id.clone();
    let state_clone = state.clone();
    std::thread::spawn(move || {
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
            .filter(|s| !s.is_empty())
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
        .with_state(state);

    println!("dalfox server listening on http://{}", addr_str);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", addr_str, e);
            return;
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {}", e);
    }
}
