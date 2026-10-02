//! Small server-wide helpers: structured logging, scan-id derivation, cookie
//! parsing, scan-option validation, and the job-retention purge wrapper.

use super::*;

/// Normalize and range-check scan options so callers get a precise 400 instead
/// of having the server silently substitute defaults — or, worse, run a scan
/// that quietly does the wrong thing. The shared checks live in
/// [`crate::job::ScanOptionChecks`]; only `callback_url` is REST-specific.
pub(crate) fn validate_scan_options(opts: &mut ScanOptions) -> Result<(), String> {
    crate::job::ScanOptionChecks {
        method: opts.method.as_mut(),
        encoders: opts.encoders.as_deref().unwrap_or_default(),
        remote_payloads: opts.remote_payloads.as_deref().unwrap_or_default(),
        remote_wordlists: opts.remote_wordlists.as_deref().unwrap_or_default(),
        timeout: opts.timeout,
        delay: opts.delay,
        workers: opts.worker.map(|w| (w, "worker")),
        max_payloads_per_param: opts.max_payloads_per_param,
        scan_timeout: opts.scan_timeout,
        waf_bypass: opts.waf_bypass.as_deref(),
        force_waf: opts.force_waf.as_mut(),
        waf_min_confidence: opts.waf_min_confidence,
        headers: opts.header.as_deref().unwrap_or_default(),
        user_agent: opts.user_agent.as_deref(),
        cookies: opts.cookie.as_slice(),
        proxy: Some(&mut opts.proxy),
        blind: Some((&mut opts.blind, "blind")),
    }
    .validate()?;
    // `send_terminal_webhook` dials http(s) only and returns silently for
    // anything else, so a `callback_url` with another scheme was accepted with
    // `200 OK` and then never fired — leaving the subscriber waiting forever for
    // a callback that was discarded at submission time.
    //
    // Normalizing (trim) rather than only checking is load-bearing: the stored
    // `callback_url` is what the dispatcher later dials, so a value with
    // surrounding whitespace would pass a check on the trimmed form and then be
    // dropped by the dispatcher's scheme test on the untrimmed one.
    if let Some(cb) = &opts.callback_url {
        let cb = cb.trim();
        if cb.is_empty() {
            // Empty already meant "no webhook" and still does. Refusing it would
            // break the routine `?callback_url=` templated-query shape without
            // closing any silent-drop hole.
            opts.callback_url = None;
        } else if !has_http_scheme(cb) {
            return Err(format!(
                "callback_url must start with http:// or https:// (got '{}')",
                crate::utils::log::sanitize_log_message(cb)
            ));
        } else {
            opts.callback_url = Some(cb.to_string());
        }
    }
    Ok(())
}

/// Minimum interval between job-retention sweeps. Retention is hours-granular,
/// so deferring a sweep by up to a minute is invisible to clients while keeping
/// the O(n) scan off the hot per-request path. Mirrors the MCP server.
pub(crate) const PURGE_MIN_INTERVAL_MS: i64 = 60_000;

/// Cap on concurrent `/preflight` operations. Each preflight pins a blocking-pool
/// thread for the full request timeout, so this is sized well below tokio's
/// default 512-thread blocking pool to guarantee scan jobs always have threads.
pub(crate) const MAX_CONCURRENT_PREFLIGHT: usize = 32;

/// Thin wrapper over `crate::job::purge_expired_jobs` that acquires the jobs
/// lock for the caller. Throttled to at most once per [`PURGE_MIN_INTERVAL_MS`]
/// so the O(n) retention sweep doesn't run (and serialize all handlers on the
/// jobs lock) on every request, including the high-frequency poll path.
pub(crate) async fn purge_expired_jobs(state: &AppState) {
    use std::sync::atomic::Ordering;
    let now = crate::job::now_ms();
    let last = state.last_purge_ms.load(Ordering::Relaxed);
    if now - last < PURGE_MIN_INTERVAL_MS {
        return;
    }
    // CAS so concurrent requests can't both decide to sweep.
    if state
        .last_purge_ms
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let mut jobs = state.jobs.lock().await;
    purge_jobs_map(&mut jobs, JOB_RETENTION_SECS);
}

/// Parse an optional numeric query parameter, distinguishing "absent" (→
/// `Ok(None)`, use the default) from "present but unparseable" (→ `Err`).
/// GET /scan used to swallow `?timeout=abc` / `?worker=-5` via
/// `.and_then(|s| s.parse().ok())`, silently dropping the caller's override
/// and running with the default — while `?timeout=0` was correctly rejected.
/// This makes the bad-input handling consistent: a malformed value is a 400,
/// not a silent fallback.
pub(crate) fn parse_num_query<T>(
    params: &HashMap<String, String>,
    key: &str,
) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    match params.get(key) {
        Some(raw) => raw
            .trim()
            .parse::<T>()
            .map(Some)
            // Type-neutral wording: this helper also parses `waf_min_confidence`
            // as an f32, where "must be a non-negative integer" was simply wrong
            // advice for a value like `0.5x`.
            .map_err(|_| format!("{} must be a valid number (got '{}')", key, raw)),
        None => Ok(None),
    }
}

/// Lenient boolean query-parameter parse shared by GET /scan and DELETE
/// /scan/{id}. `?flag=1` / `true` / `yes` / `on` (any case, trimmed) read as
/// true; absent or anything else reads as false. Previously GET /scan accepted
/// only the exact string `"true"` while DELETE's `?purge` accepted `"1"` and
/// `"true"`, so the same `?include_request=1` silently did nothing.
pub(crate) fn parse_bool_query(params: &HashMap<String, String>, key: &str) -> bool {
    parse_opt_bool_query(params, key).unwrap_or(false)
}

/// Like [`parse_bool_query`] but preserves the present/absent distinction:
/// returns `None` when the key is absent and `Some(bool)` when present. Used
/// for flags whose default is *not* `false` (e.g. `insecure`, which defaults
/// to true), so the caller can apply its own default only when the query
/// parameter was omitted.
pub(crate) fn parse_opt_bool_query(params: &HashMap<String, String>, key: &str) -> Option<bool> {
    params.get(key).map(|v| {
        let v = v.trim();
        v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    })
}

/// Admit a new scan and insert a queued `Job` for `url` under a single
/// jobs-lock, or return `None` when the server is already at its
/// `max_concurrent_scans` capacity (`0` = unlimited). Counting active
/// (non-terminal) jobs and inserting under the *same* lock keeps the check
/// race-free. Shared by POST and GET /scan so both paths enforce the cap and
/// build the queued job identically.
///
/// On success returns the reserved scan_id together with the worker lease the
/// caller must move into the scan task (see [`crate::job::Job::is_evictable`]).
pub(crate) async fn try_admit_and_queue(
    state: &AppState,
    url: &str,
    callback_url: Option<String>,
) -> Option<(String, WorkerLease)> {
    let mut jobs = state.jobs.lock().await;
    if state.max_concurrent_scans > 0
        && jobs.values().filter(|j| j.occupies_capacity()).count() >= state.max_concurrent_scans
    {
        return None;
    }
    let id = crate::utils::make_unique_scan_id(url, |id| jobs.contains_key(id));
    let mut job = Job::new_queued(url.to_string());
    job.callback_url = callback_url;
    let lease = job.issue_worker_lease();
    jobs.insert(id.clone(), job);
    // Bound retained finished scans. The admission cap above counts only active
    // jobs, so without this the map grows with every quick scan until the
    // retention TTL expires. Applied after the insert so the steady state is
    // exactly `max_retained_scans`; the job just added is non-terminal and so
    // is never a candidate for eviction.
    enforce_retention_cap(&mut jobs, state.max_retained_scans);
    Some((id, lease))
}

/// Build the standard 503 "at capacity" response body for a rejected admission.
pub(crate) fn at_capacity_response(state: &AppState) -> ApiResponse<serde_json::Value> {
    ApiResponse::<serde_json::Value> {
        code: 503,
        msg: format!(
            "server at capacity: {} concurrent scans already in flight (raise or disable with --max-concurrent-scans)",
            state.max_concurrent_scans
        ),
        data: None,
    }
}

/// Open (creating if needed) the `--log-file` for appending.
///
/// On Unix the file is created `0600`. The log records target URLs verbatim,
/// and a scan target routinely carries the credential that made it worth
/// scanning — a session id, a signed URL, an `?api_key=` — so the default
/// `0644` published every submitted URL to every local account on the host.
/// The mode only applies at creation, so an existing file keeps whatever
/// permissions the operator gave it.
pub(crate) fn open_log_file(path: &str) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Emit a structured server log line — gray `{ts}` + colored `{level}` token +
/// message — to stdout and, when `--log-file` is set, append it to that file.
/// The message is run through [`sanitize_log_message`](crate::utils::log::sanitize_log_message)
/// first because it embeds attacker-supplied bytes (target URLs, error strings).
pub(crate) fn log(state: &AppState, level: &str, message: &str) {
    let message = crate::utils::log::sanitize_log_message(message);
    let message = message.as_ref();
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
        let _ = open_log_file(path).and_then(|mut f| {
            use std::io::Write;
            f.write_all(line.as_bytes())
        });
    }
}
