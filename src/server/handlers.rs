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

    // Trim once and use the trimmed value throughout (validation, scan_id,
    // stored target, dispatch) so whitespace variants stay consistent.
    let url = req.url.trim().to_string();
    if url.is_empty() {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }
    // Require an http(s) scheme, matching /preflight and the MCP scan tool.
    // Without this, a garbage target (e.g. "ftp://x" or a bare host) was
    // queued and "scanned", silently finishing as `done` with 0 findings —
    // indistinguishable from a real target that simply had no XSS.
    if !has_http_scheme(&url) {
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
    let include_request = opts.include_request.unwrap_or(false);
    let include_response = opts.include_response.unwrap_or(false);
    let callback_url = opts.callback_url.clone();

    // Reserve a unique scan_id and insert the queued job under one lock so a
    // same-target resubmission in the same nanosecond can't clobber an
    // in-flight job (see make_scan_id's nonce), and so the concurrency cap is
    // checked race-free against the live job count. 503 when at capacity.
    let id = match try_admit_and_queue(&state, &url, callback_url).await {
        Some(id) => id,
        None => {
            let resp = at_capacity_response(&state);
            return make_api_response(
                &state,
                &headers,
                &params,
                StatusCode::SERVICE_UNAVAILABLE,
                &resp,
            );
        }
    };
    log(&state, "JOB", &format!("queued id={} url={}", id, url));

    spawn_scan_task(
        state.clone(),
        id.clone(),
        url.clone(),
        opts,
        include_request,
        include_response,
    );

    let resp = ApiResponse::<serde_json::Value> {
        code: 200,
        msg: "ok".to_string(),
        data: Some(serde_json::json!({ "scan_id": id, "target": url })),
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
            // Include Error so an early infra failure (parse/reachability/panic)
            // still exposes params_total / requests_sent gathered before it
            // failed, instead of an opaque error_message with no progress.
            let progress_data = if matches!(
                j.status,
                JobStatus::Running | JobStatus::Done | JobStatus::Cancelled | JobStatus::Error
            ) {
                let params_total = j
                    .progress
                    .params_total
                    .load(std::sync::atomic::Ordering::Relaxed);
                let params_tested = j
                    .progress
                    .params_tested
                    .load(std::sync::atomic::Ordering::Relaxed);
                let estimated_completion_pct = if matches!(
                    j.status,
                    JobStatus::Done | JobStatus::Cancelled | JobStatus::Error
                ) {
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
                let suggested_poll_interval_ms: u64 = if matches!(
                    j.status,
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

    // Trim once and use the trimmed value throughout, so whitespace variants
    // of the same URL validate, hash to the same scan_id, and store the same
    // target consistently.
    let url = params
        .get("url")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    if url.is_empty() {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url is required".to_string(),
            data: None,
        };
        return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
    }
    // Require an http(s) scheme, matching POST /scan, /preflight, and MCP.
    if !has_http_scheme(&url) {
        let resp = ApiResponse::<serde_json::Value> {
            code: 400,
            msg: "url must start with http:// or https://".to_string(),
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
    // A present-but-unparseable numeric query param is a 400, not a silent
    // fallback to the default (which is what `.parse().ok()` used to do).
    // Types infer from the `parse_num_query` turbofishes — worker:usize,
    // delay/timeout/scan_timeout:u64, rate_limit:u32, each wrapped in Option.
    let (worker, delay, timeout, rate_limit, scan_timeout) = match (
        parse_num_query::<usize>(&params, "worker"),
        parse_num_query::<u64>(&params, "delay"),
        parse_num_query::<u64>(&params, "timeout"),
        parse_num_query::<u32>(&params, "rate_limit"),
        parse_num_query::<u64>(&params, "scan_timeout"),
    ) {
        (Ok(w), Ok(d), Ok(t), Ok(rl), Ok(st)) => (w, d, t, rl, st),
        (Err(msg), ..)
        | (_, Err(msg), ..)
        | (_, _, Err(msg), ..)
        | (_, _, _, Err(msg), _)
        | (.., Err(msg)) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg,
                data: None,
            };
            return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
        }
    };
    let blind = params.get("blind").cloned();
    let method = params
        .get("method")
        .cloned()
        .unwrap_or_else(|| "GET".to_string());
    let data_opt = params.get("data").cloned();
    let user_agent = params.get("user_agent").cloned();
    // Lenient boolean parse (1/true/yes/on) shared with DELETE; see parse_bool_query.
    let include_request = parse_bool_query(&params, "include_request");
    let include_response = parse_bool_query(&params, "include_response");

    let param_list: Option<Vec<String>> = params.get("param").map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    });
    let proxy = params.get("proxy").cloned();
    let follow_redirects = parse_bool_query(&params, "follow_redirects");
    let skip_mining = parse_bool_query(&params, "skip_mining");
    let skip_discovery = parse_bool_query(&params, "skip_discovery");
    let deep_scan = parse_bool_query(&params, "deep_scan");
    let skip_ast_analysis = parse_bool_query(&params, "skip_ast_analysis");
    let analyze_external_js = parse_bool_query(&params, "analyze_external_js");
    let detect_outdated_libs = parse_bool_query(&params, "detect_outdated_libs");
    let waf_bypass = params.get("waf_bypass").cloned();
    let skip_waf_probe = parse_opt_bool_query(&params, "skip_waf_probe");
    let force_waf = params.get("force_waf").cloned();
    let waf_evasion = parse_opt_bool_query(&params, "waf_evasion");
    // Present-but-unparseable is a 400 (same policy as the numeric params
    // above); the [0.0, 1.0] range is enforced by `validate_scan_options`.
    let waf_min_confidence = match parse_num_query::<f32>(&params, "waf_min_confidence") {
        Ok(v) => v,
        Err(msg) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg,
                data: None,
            };
            return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
        }
    };

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
        // Absent ?insecure leaves None so the scan path applies its
        // insecure-by-default; ?insecure=false opts into TLS validation.
        insecure: parse_opt_bool_query(&params, "insecure"),
        follow_redirects: Some(follow_redirects),
        skip_mining: Some(skip_mining),
        skip_discovery: Some(skip_discovery),
        deep_scan: Some(deep_scan),
        skip_ast_analysis: Some(skip_ast_analysis),
        analyze_external_js: Some(analyze_external_js),
        detect_outdated_libs: Some(detect_outdated_libs),
        waf_bypass,
        skip_waf_probe,
        force_waf,
        waf_evasion,
        waf_min_confidence,
        rate_limit,
        scan_timeout,
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
    // Reserve a unique scan_id and enforce the concurrency cap under one lock
    // (see POST /scan). 503 when at capacity.
    let id = match try_admit_and_queue(&state, &url, callback_url).await {
        Some(id) => id,
        None => {
            let resp = at_capacity_response(&state);
            return make_api_response(
                &state,
                &headers,
                &params,
                StatusCode::SERVICE_UNAVAILABLE,
                &resp,
            );
        }
    };
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
    let purge_requested = parse_bool_query(&params, "purge");

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
    // A present-but-unparseable value is a 400, not a silent fallback — matching
    // GET /scan's strict numeric handling (parse_num_query) rather than the old
    // `.parse().ok()` that turned `?limit=abc` into "return everything".
    let (offset, limit): (usize, usize) = match (
        parse_num_query::<usize>(&params, "offset"),
        parse_num_query::<usize>(&params, "limit"),
    ) {
        (Ok(o), Ok(l)) => (o.unwrap_or(0), l.unwrap_or(0)),
        (Err(msg), _) | (_, Err(msg)) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 400,
                msg,
                data: None,
            };
            return make_api_response(&state, &headers, &params, StatusCode::BAD_REQUEST, &resp);
        }
    };

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
    if target_url.is_empty() || !has_http_scheme(&target_url) {
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

    // Bound concurrent preflights: each one pins a blocking-pool thread for the
    // full request timeout against an attacker-controlled target, so an
    // unthrottled burst could exhaust the blocking pool and stall every scan.
    // Shed excess load with 503 instead. The permit is moved into the blocking
    // closure below so it is held until that thread actually frees.
    let preflight_permit = match state.preflight_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let resp = ApiResponse::<serde_json::Value> {
                code: 503,
                msg: "preflight capacity reached; retry shortly".to_string(),
                data: None,
            };
            return make_api_response(
                &state,
                &headers,
                &params,
                StatusCode::SERVICE_UNAVAILABLE,
                &resp,
            );
        }
    };

    // Run the analysis on tokio's blocking pool (reused across calls) with a
    // current_thread runtime inside because analyze_parameters and scraper-
    // backed HTML inspection are !Send.
    let outcome: Result<serde_json::Value, PreflightError> =
        tokio::task::spawn_blocking(move || {
            // Hold the admission permit for the lifetime of this blocking thread.
            let _preflight_permit = preflight_permit;
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
                    insecure: opts.insecure.unwrap_or(true),
                    follow_redirects: opts.follow_redirects.unwrap_or(false),
                    skip_mining: opts.skip_mining.unwrap_or(false),
                    skip_discovery: opts.skip_discovery.unwrap_or(false),
                    encoders: opts
                        .encoders
                        .clone()
                        .unwrap_or_else(|| vec!["url".to_string(), "html".to_string()]),
                });

                analyze_parameters(&mut target, &scan_args, None).await;
                // Apply the same per-scan parameter cap a real scan would, so
                // the estimate reflects what scanning actually fans out to.
                cap_reflection_params(&mut target);

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
