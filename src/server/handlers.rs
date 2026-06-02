//! Axum route handlers for the HTTP API. Each handler authenticates, purges
//! expired jobs, and funnels every response through `make_api_response` so
//! CORS + JSONP stay consistent across endpoints.

use super::*;

pub(crate) async fn start_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    // Accept the rejection ourselves so a missing `url` field or any
    // other JSON-deserialization failure surfaces as our `{"code":400,
    // "msg":...}` envelope instead of axum's default 422 with a raw
    // `Failed to deserialize the JSON body...` string. The wire shape
    // is now consistent across happy and error paths for clients.
    req: Result<Json<ScanRequest>, JsonRejection>,
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

    let req = match req {
        Ok(Json(r)) => r,
        Err(rej) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg: format!("invalid request body: {}", rej),
                data: None,
            };
            return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
        }
    };

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

pub(crate) async fn get_result_handler(
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

pub(crate) async fn options_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
}

// GET /scan handler for JSONP-friendly GET inputs (URL + options via query)
pub(crate) async fn get_scan_handler(
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
pub(crate) async fn health_handler(
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
            // Match `check_api_key`: an empty `Some("")` falls through to
            // the no-auth branch ("Leave empty to disable auth" per
            // --api-key help). Previously /health advertised
            // `auth_required: true` for empty-string keys while the rest
            // of the API accepted unauth requests, confusing clients.
            "auth_required": state.api_key.as_deref().is_some_and(|s| !s.is_empty()),
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

pub(crate) async fn options_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
}

// DELETE /scan/{id} — cancel a scan
pub(crate) async fn cancel_scan_handler(
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
            // Release the jobs lock before serializing the response, the same
            // way the purge branch above does — otherwise the scan task (and
            // every other handler) is blocked on the mutex while we build
            // CORS headers and JSON for this one reply.
            let target_url = job.target_url.clone();
            drop(jobs);
            log(&state, "JOB", &format!("cancelled id={}", id));
            let resp = ApiResponse {
                code: 200,
                msg: "ok".to_string(),
                data: Some(serde_json::json!({
                    "scan_id": id,
                    "target": target_url,
                    "cancelled": true,
                    "previous_status": previous_status
                })),
            };
            make_api_response(&state, &headers, &params, StatusCode::OK, &resp)
        }
        None => {
            drop(jobs);
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
pub(crate) async fn list_scans_handler(
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

// POST /preflight — parameter discovery without attack payloads
pub(crate) async fn preflight_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    // See start_scan_handler — surface JSON-deserialization failures
    // through our `{"code","msg","data"}` envelope instead of axum's
    // default 422 raw error string so clients can parse error
    // responses the same shape as success responses.
    req: Result<Json<ScanRequest>, JsonRejection>,
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

    let req = match req {
        Ok(Json(r)) => r,
        Err(rej) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg: format!("invalid request body: {}", rej),
                data: None,
            };
            return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
        }
    };

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
