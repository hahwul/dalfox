//! Axum route handlers for the HTTP API. Each handler authenticates, purges
//! expired jobs, and funnels every response through `make_api_response` so
//! CORS + JSONP stay consistent across endpoints.

use super::*;

/// Status for a body the `Json` extractor refused. Only the two classes the
/// docs promise keep axum's own status — a body over `--max-body-bytes` (413)
/// and a missing/foreign `Content-Type` (415); malformed JSON and schema
/// errors (axum would answer 422) stay the documented 400.
fn json_rejection_status(rej: &JsonRejection) -> StatusCode {
    match rej.status() {
        s @ (StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNSUPPORTED_MEDIA_TYPE) => s,
        _ => StatusCode::BAD_REQUEST,
    }
}

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
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/scan").await {
        return refused;
    }

    let req = match req {
        Ok(Json(req)) => req,
        Err(rej) => {
            let msg = format!("invalid request body: {}", rej);
            return r.err(json_rejection_status(&rej), msg);
        }
    };

    // Trim once and use the trimmed value throughout (validation, scan_id,
    // stored target, dispatch) so whitespace variants stay consistent.
    let url = req.target.trim().to_string();
    if let Err(msg) = check_scan_target(&url) {
        return r.err(StatusCode::BAD_REQUEST, msg);
    }
    queue_scan(&r, url, req.options.unwrap_or_default()).await
}

/// Target checks shared by POST and GET /scan. The http(s) scheme requirement
/// matches /preflight and the MCP scan tool: without it a garbage target (e.g.
/// "ftp://x" or a bare host) was queued and "scanned", silently finishing as
/// `done` with 0 findings — indistinguishable from a real target that simply
/// had no XSS.
fn check_scan_target(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("target is required".to_string());
    }
    if !has_http_scheme(url) {
        return Err("target must start with http:// or https://".to_string());
    }
    crate::job::check_target_parses(url)
}

/// Shared tail of POST and GET /scan: validate, admit, dispatch.
async fn queue_scan(r: &Reply<'_>, url: String, mut opts: ScanOptions) -> ApiReply {
    // `&mut`: validation also normalizes (e.g. uppercases `method`), and the
    // normalized options are what gets dispatched to the scan below.
    if let Err(msg) = validate_scan_options(&mut opts) {
        return r.err(StatusCode::BAD_REQUEST, msg);
    }

    // Reserve a unique scan_id and insert the queued job under one lock so a
    // same-target resubmission in the same nanosecond can't clobber an
    // in-flight job (see make_scan_id's nonce), and so the concurrency cap is
    // checked race-free against the live job count. 503 when at capacity.
    let callback_url = opts.callback_url.clone();
    let Some((id, lease)) = try_admit_and_queue(r.state, &url, callback_url).await else {
        return r.err(
            StatusCode::SERVICE_UNAVAILABLE,
            at_capacity_message(r.state),
        );
    };
    log(r.state, "JOB", &format!("queued id={} url={}", id, url));

    let body = serde_json::json!({ "scan_id": id, "target": url });
    spawn_scan_task(r.state.clone(), id, url, opts, lease);
    r.ok(body)
}

pub(crate) async fn get_result_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/result").await {
        return refused;
    }

    let job = {
        let jobs = state.jobs.lock().await;
        jobs.get(&id).cloned()
    };

    match job {
        Some(j) => {
            let progress_data = j.progress_payload(0);
            let duration_ms = j.duration_ms();
            let payload = ResultPayload {
                target: j.target_url.clone(),
                status: j.status.clone(),
                results: j.results.as_deref().map(Vec::as_slice),
                error_message: j.error_message.clone(),
                warnings: &j.warnings,
                progress: progress_data,
                queued_at_ms: j.queued_at_ms,
                started_at_ms: j.started_at_ms,
                finished_at_ms: j.finished_at_ms,
                duration_ms,
            };
            // Only log the terminal fetch. Interim running/queued polls arrive
            // on a high-frequency client loop, and every `log()` call does a
            // synchronous open/write/close of the log file — flooding it with no
            // audit value (the JOB lifecycle lines already record queue/finish).
            if j.is_terminal() {
                log(&state, "RESULT", &format!("id={} status={}", id, j.status));
            }
            r.ok(payload)
        }
        None => r.err(StatusCode::NOT_FOUND, "not found"),
    }
}

/// CORS preflight. No API key is checked — a browser never attaches one to a
/// preflight — but the source gate still applies, for the same reason
/// `/health` carries it: without it a page the operator visits can use a 204
/// to fingerprint a dalfox server on their machine, and a rebound `Host` gets
/// an answer here that it is refused everywhere else. A genuine preflight from
/// an allowed origin passes on the `Origin` branch; one from a disallowed
/// origin is refused instead of getting a 204 with no `Access-Control-Allow-Origin`,
/// which fails the browser's preflight either way. Also serves the id-bearing
/// routes; the `{id}` segment needs no extractor.
pub(crate) async fn options_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(denied) = check_request_source(&state, &headers) {
        return (denied.status(), HeaderMap::new());
    }
    let cors = build_cors_headers(&state, &headers);
    (StatusCode::NO_CONTENT, cors)
}

// GET /scan handler for JSONP-friendly GET inputs (URL + options via query)
/// Split the `GET /scan` `header=` query value into individual headers.
///
/// The query form has always packed several headers into one comma-separated
/// value, but a comma is also perfectly legal *inside* a header value —
/// `Accept: text/html,application/xhtml+xml` is the canonical example. A blind
/// `split(',')` therefore chopped that into `Accept: text/html` plus a
/// nameless `application/xhtml+xml` fragment: before header validation existed
/// the fragment was silently dropped and a truncated `Accept` went on the wire;
/// with validation it would 400 an otherwise valid request.
///
/// So only split at a comma that actually starts a new header — one followed by
/// `Name:`. Commas inside a value are kept, and the multi-header form keeps
/// working. (`POST /scan` takes a JSON array and needs none of this.)
pub(crate) fn split_header_query_param(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return vec![];
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b',' {
            continue;
        }
        // Does a `Name:` begin right after this comma?
        let rest = raw[i + 1..].trim_start();
        let name_len = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            .count();
        if name_len > 0 && rest[name_len..].starts_with(':') {
            let piece = raw[start..i].trim();
            if !piece.is_empty() {
                out.push(piece.to_string());
            }
            start = i + 1;
        }
    }
    let last = raw[start..].trim();
    if !last.is_empty() {
        out.push(last.to_string());
    }
    out
}

/// Split a comma-separated `GET /scan` list value, trimming each item and
/// dropping empty ones.
pub(super) fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// `?blind_oob=` takes a boolean or a comma-separated server list, mirroring
/// the JSON body's `true` / `[...]` forms. Empty and the false spellings mean
/// off; the true spellings mean the public mesh.
pub(super) fn blind_oob_query(raw: &str) -> Option<crate::job::spec::BlindOobRequest> {
    use crate::job::spec::BlindOobRequest;
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => None,
        "1" | "true" | "yes" | "on" => Some(BlindOobRequest::Enabled(true)),
        _ => {
            // An all-blank list (`,`, ` , `) is off, not the public mesh — a
            // template that rendered to nothing should not silently arm OOB.
            // Non-host junk (`ture`) survives here and is rejected with a clear
            // 400 by `normalize_blind_oob`'s single-label / host check.
            let servers = split_csv(raw);
            (!servers.is_empty()).then_some(BlindOobRequest::Servers(servers))
        }
    }
}

pub(crate) async fn get_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/scan").await {
        return refused;
    }

    // Trim once and use the trimmed value throughout, so whitespace variants
    // of the same URL validate, hash to the same scan_id, and store the same
    // target consistently.
    // `target` is the canonical param (matches POST/MCP); `url` stays as a
    // backwards-compatible alias for existing query-string / JSONP callers. An
    // empty `target` (e.g. a templated `?target=&url=...`) falls through to the
    // alias so it can't shadow a real `url` — preserving the old behavior for
    // any caller still sending `url`.
    let url = params
        .get("target")
        .filter(|t| !t.trim().is_empty())
        .or_else(|| params.get("url"))
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    if let Err(msg) = check_scan_target(&url) {
        return r.err(StatusCode::BAD_REQUEST, msg);
    }
    match scan_options_from_query(&params) {
        Ok(opts) => queue_scan(&r, url, opts).await,
        Err(msg) => r.err(StatusCode::BAD_REQUEST, msg),
    }
}

/// `ScanOptions` from the `GET /scan` query. A present-but-unparseable number
/// is an `Err` (a 400) naming the first bad key in the order below, not a silent
/// fallback to the default (which is what `.parse().ok()` used to do). Absent
/// keys stay `None` and take the JSON body's defaults.
fn scan_options_from_query(params: &HashMap<String, String>) -> Result<ScanOptions, String> {
    let s = |k: &str| params.get(k).cloned();
    let csv = |k: &str| params.get(k).map(|v| split_csv(v));
    // Lenient boolean parse (1/true/yes/on) shared with DELETE; see parse_bool_query.
    let flag = |k: &str| parse_opt_bool_query(params, k);
    Ok(ScanOptions {
        worker: parse_num_query(params, "worker")?,
        delay: parse_num_query(params, "delay")?,
        timeout: parse_num_query(params, "timeout")?,
        rate_limit: parse_num_query(params, "rate_limit")?,
        scan_timeout: parse_num_query(params, "scan_timeout")?,
        max_payloads_per_param: parse_num_query(params, "max_payloads_per_param")?,
        blind_oob_wait: parse_num_query(params, "blind_oob_wait")?,
        // The [0.0, 1.0] range is enforced by `validate_scan_options`.
        waf_min_confidence: parse_num_query(params, "waf_min_confidence")?,
        cookie: s("cookie"),
        blind: s("blind"),
        header: params.get("header").map(|h| split_header_query_param(h)),
        method: s("method"),
        data: s("data"),
        user_agent: s("user_agent"),
        // An empty `?encoders=` is "unset", not "no encoders".
        encoders: params
            .get("encoders")
            .filter(|v| !v.is_empty())
            .map(|v| split_csv(v)),
        remote_payloads: csv("remote_payloads"),
        remote_wordlists: csv("remote_wordlists"),
        include_request: flag("include_request"),
        include_response: flag("include_response"),
        callback_url: s("callback_url"),
        param: csv("param"),
        proxy: s("proxy"),
        // Absent ?insecure leaves None so the scan path applies its
        // insecure-by-default; ?insecure=false opts into TLS validation.
        insecure: flag("insecure"),
        follow_redirects: flag("follow_redirects"),
        skip_mining: flag("skip_mining"),
        skip_discovery: flag("skip_discovery"),
        deep_scan: flag("deep_scan"),
        skip_ast_analysis: flag("skip_ast_analysis"),
        analyze_external_js: flag("analyze_external_js"),
        detect_outdated_libs: flag("detect_outdated_libs"),
        waf_bypass: s("waf_bypass"),
        skip_waf_probe: flag("skip_waf_probe"),
        force_waf: s("force_waf"),
        waf_evasion: flag("waf_evasion"),
        min_confidence: s("min_confidence"),
        blind_oob: params.get("blind_oob").and_then(|v| blind_oob_query(v)),
        session_check: s("session_check"),
        session_check_url: s("session_check_url"),
    })
}

// GET /health — server info and capability discovery
pub(crate) async fn health_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // No API key: /health is capability discovery and stays open to
    // unauthenticated callers. The source gate still applies, so a web page
    // the operator visits can't use it to fingerprint whether a dalfox server
    // is listening on their machine.
    let r = Reply::new(&state, &headers, &params);
    if let Err(denied) = check_request_source(&state, &headers) {
        return r.deny(&denied, "/health");
    }

    r.ok(serde_json::json!({
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
    }))
}

// DELETE /scan/{id} — cancel a scan
pub(crate) async fn cancel_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/scan/{id}").await {
        return refused;
    }

    // When ?purge=1, delete the job from memory instead of (or in addition to)
    // cancelling it. Only allowed once the job is evictable (terminal and its
    // worker released the lease, or wedged past the drain grace) — callers
    // must first cancel a running scan and wait for it to settle. Removing a
    // still-draining entry would drop its Weak lease, so `admit_job` would
    // stop counting a worker that is still running and the cap is bypassed.
    let purge_requested = parse_bool_query(&params, "purge");

    let mut jobs = state.jobs.lock().await;
    match jobs.get_mut(&id) {
        Some(job) => {
            if purge_requested {
                if !job.is_evictable() {
                    let msg = if job.is_terminal() {
                        format!(
                            "cannot purge scan in status '{}' while its worker is still draining — retry once it settles",
                            job.status
                        )
                    } else {
                        format!(
                            "cannot purge scan in status '{}' — cancel it first and wait for it to settle",
                            job.status
                        )
                    };
                    drop(jobs);
                    return r.err(StatusCode::CONFLICT, msg);
                }
                let previous_status = job.status.clone();
                let target_url = job.target_url.clone();
                jobs.remove(&id);
                drop(jobs);
                log(&state, "JOB", &format!("purged id={}", id));
                return r.ok(serde_json::json!({
                    "scan_id": id,
                    "target": target_url,
                    "deleted": true,
                    "previous_status": previous_status,
                }));
            }

            let previous_status = job.status.clone();
            // `cancelled` is false for an already-terminal job: that cancel was
            // a no-op, and reporting `true` made it look like a real one.
            let was_active = job.cancel();
            // Release the jobs lock before serializing the response, the same
            // way the purge branch above does — otherwise the scan task (and
            // every other handler) is blocked on the mutex while we build
            // CORS headers and JSON for this one reply.
            let target_url = job.target_url.clone();
            drop(jobs);
            log(&state, "JOB", &format!("cancelled id={}", id));
            r.ok(serde_json::json!({
                "scan_id": id,
                "target": target_url,
                "cancelled": was_active,
                "previous_status": previous_status
            }))
        }
        None => {
            drop(jobs);
            r.err(StatusCode::NOT_FOUND, "not found")
        }
    }
}

// GET /scans — list all scans with status
pub(crate) async fn list_scans_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/scans").await {
        return refused;
    }

    let filter_status =
        match crate::job::parse_status_filter(params.get("status").map(String::as_str)) {
            Ok(f) => f,
            Err(msg) => return r.err(StatusCode::BAD_REQUEST, msg),
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
        (Err(msg), _) | (_, Err(msg)) => return r.err(StatusCode::BAD_REQUEST, msg),
    };

    // Built under the lock, serialized after it is released: holding the
    // shared `state.jobs` mutex across serialization stalls the hot get_result
    // poll path and concurrent scans' terminal status writes.
    let body = crate::job::scan_list_json(
        &*state.jobs.lock().await,
        filter_status.as_ref(),
        offset,
        limit,
        false,
    );
    r.ok(body)
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
    /// The analysis outlived the effective scan budget (`--scan-timeout` cap).
    TimedOut(u64),
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
    let r = Reply::new(&state, &headers, &params);
    if let Some(refused) = r.authorize("/preflight").await {
        return refused;
    }

    let req = match req {
        Ok(Json(req)) => req,
        Err(rej) => {
            let msg = format!("invalid request body: {}", rej);
            return r.err(json_rejection_status(&rej), msg);
        }
    };

    let target_url = req.target.trim().to_string();
    if target_url.is_empty() || !has_http_scheme(&target_url) {
        return r.err(
            StatusCode::BAD_REQUEST,
            "target must start with http:// or https://",
        );
    }

    // `&mut`: validation normalizes too (see queue_scan), and the normalized
    // `method` is what the preflight target and its request-count estimate
    // are built from.
    let mut opts = req.options.unwrap_or_default();
    if let Err(msg) = validate_scan_options(&mut opts) {
        return r.err(StatusCode::BAD_REQUEST, msg);
    }

    let timeout_secs = opts
        .timeout
        .unwrap_or(crate::cmd::scan::DEFAULT_TIMEOUT_SECS);

    // Preflight is not a dry run in network terms: discovery and mining send
    // real requests to the target (20+ against a two-parameter URL). Those
    // sends go through `crate::record_outbound_request`, which acquires from
    // whichever rate limiter is in scope — and nothing bound one here, so this
    // route ran flat out. That silently voided both the caller's `rate_limit`
    // *and* the operator's server-wide `--rate-limit`, which is documented as
    // applying to "every submitted scan": a client refused a fast scan could
    // simply hammer the same target through `/preflight`. Resolve it through
    // the same `effective_rate_limit` ceiling the scan path uses so the
    // operator's cap wins over the request's value.
    let preflight_rate = effective_rate_limit(opts.rate_limit, state.rate_limit);
    // Same wall-clock ceiling `/scan` jobs get: a target that answers the
    // reachability HEAD and then stalls every probe would otherwise hold this
    // request (and its permit and blocking thread) for minutes, and graceful
    // shutdown waits on in-flight requests.
    let preflight_budget = effective_scan_timeout(opts.scan_timeout, state.scan_timeout);

    // Bound concurrent preflights: each one pins a blocking-pool thread for the
    // full request timeout against an attacker-controlled target, so an
    // unthrottled burst could exhaust the blocking pool and stall every scan.
    // Shed excess load with 503 instead. The permit is moved into the blocking
    // closure below so it is held until that thread actually frees.
    let preflight_permit = match state.preflight_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return r.err(
                StatusCode::SERVICE_UNAVAILABLE,
                "preflight capacity reached; retry shortly",
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
            // Everything that touches the network runs inside the per-job
            // limiter scope (`RATE_LIMITER_JOB`), which is what
            // `record_outbound_request` looks for. `with_job_rate_limiter` is a
            // plain await when the effective rate is 0 (unlimited), so the
            // default path pays nothing.
            let work = crate::with_job_rate_limiter(preflight_rate, async {
                let mut target = hydrate_preflight_target(&target_url, &opts, timeout_secs)
                    .map_err(PreflightError::BadUrl)?;

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
                Ok(crate::job::runner::preflight(
                    &mut target,
                    &target_url,
                    &scan_args,
                    opts.max_payloads_per_param.unwrap_or(0),
                    opts.deep_scan.unwrap_or(false),
                )
                .await)
            });
            // Dropping `work` on expiry aborts the in-flight probes; the
            // runtime (and any task they spawned) goes with it.
            rt.block_on(async {
                if preflight_budget == 0 {
                    return work.await;
                }
                tokio::time::timeout(Duration::from_secs(preflight_budget), work)
                    .await
                    .unwrap_or(Err(PreflightError::TimedOut(preflight_budget)))
            })
        })
        .await
        .unwrap_or(Err(PreflightError::TaskPanicked));

    match outcome {
        Ok(body) => r.ok(body),
        Err(PreflightError::BadUrl(msg)) => r.err(
            StatusCode::BAD_REQUEST,
            format!("invalid target URL: {}", msg),
        ),
        Err(PreflightError::RuntimeUnavailable(msg)) => {
            log(
                &state,
                "ERR",
                &format!("preflight runtime build failed: {}", msg),
            );
            r.err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "preflight runtime unavailable",
            )
        }
        Err(PreflightError::TimedOut(secs)) => r.err(
            StatusCode::GATEWAY_TIMEOUT,
            format!("preflight exceeded the {secs}s scan timeout"),
        ),
        Err(PreflightError::TaskPanicked) => {
            log(&state, "ERR", "preflight task panicked");
            r.err(StatusCode::INTERNAL_SERVER_ERROR, "preflight task panicked")
        }
    }
}
