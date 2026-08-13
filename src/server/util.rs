//! Small server-wide helpers: structured logging, scan-id derivation, cookie
//! parsing, scan-option validation, and the job-retention purge wrapper.

use super::*;

/// Normalize and range-check scan options so callers get a precise 400 instead
/// of having the server silently substitute defaults — or, worse, run a scan
/// that quietly does the wrong thing.
///
/// Normalization matters because the REST body bypasses clap's value parsers
/// exactly like a config file does (see `ScanConfig::normalize_and_validate`).
/// `method` is the important one: it is compared case-sensitively downstream
/// and is put on the wire verbatim, so `"post"` used to be sent as the literal
/// extension verb `post` (which real servers answer with 405/501) while
/// `"GET junk"` failed `Method::from_str` and silently degraded to GET. Both
/// produced a `done` scan with zero findings and no error.
pub(crate) fn validate_scan_options(opts: &mut ScanOptions) -> Result<(), String> {
    // Uppercase + validate against the same method set `--method` accepts.
    if let Some(m) = &opts.method {
        opts.method = Some(crate::cmd::scan::parse_http_method_arg(m)?);
    }
    if let Some(encs) = &opts.encoders {
        crate::job::validate_encoders(encs)?;
    }
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
    if let Some(m) = opts.max_payloads_per_param
        && m > crate::job::MAX_PAYLOADS_PER_PARAM
    {
        return Err(format!(
            "max_payloads_per_param must be between 0 and {} (got {})",
            crate::job::MAX_PAYLOADS_PER_PARAM,
            m
        ));
    }
    if let Some(st) = opts.scan_timeout
        && st > MAX_SCAN_TIMEOUT_SECS
    {
        return Err(format!(
            "scan_timeout must be between 0 and {} seconds (got {})",
            MAX_SCAN_TIMEOUT_SECS, st
        ));
    }
    // Shared value list (also backing clap's parser and the config validator)
    // so the accepted set can't drift between the three entry points.
    if let Some(mode) = opts.waf_bypass.as_deref()
        && !crate::cmd::scan::WAF_BYPASS_VALUES.contains(&mode)
    {
        return Err(format!(
            "waf_bypass must be one of {} (got '{}')",
            crate::cmd::scan::WAF_BYPASS_VALUES.join(", "),
            mode
        ));
    }
    // Reuse the CLI's WAF-name normalizer so server/CLI accept the same set.
    if let Some(name) = opts.force_waf.as_deref() {
        crate::cmd::scan::parse_force_waf_arg(name)?;
    }
    if let Some(c) = opts.waf_min_confidence
        && !(0.0..=1.0).contains(&c)
    {
        return Err(format!(
            "waf_min_confidence must be between 0.0 and 1.0 (got {})",
            c
        ));
    }
    // Header syntax, checked here rather than discovered mid-scan. Shared with
    // MCP so both front ends refuse the same inputs.
    if let Some(headers) = &opts.header {
        crate::job::validate_header_list(headers)?;
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
    params.get(key).is_some_and(|v| {
        let v = v.trim();
        v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    })
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
/// race-free. Returns the reserved scan_id on success. Shared by POST and GET
/// /scan so both paths enforce the cap and build the queued job identically.
pub(crate) async fn try_admit_and_queue(
    state: &AppState,
    url: &str,
    callback_url: Option<String>,
) -> Option<String> {
    let mut jobs = state.jobs.lock().await;
    if state.max_concurrent_scans > 0
        && jobs.values().filter(|j| !j.is_terminal()).count() >= state.max_concurrent_scans
    {
        return None;
    }
    let id = crate::utils::make_unique_scan_id(url, |id| jobs.contains_key(id));
    jobs.insert(
        id.clone(),
        Job {
            status: JobStatus::Queued,
            results: None,
            callback_url,
            progress: JobProgress::default(),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            error_message: None,
            target_url: url.to_string(),
            queued_at_ms: now_ms(),
            started_at_ms: None,
            finished_at_ms: None,
        },
    );
    // Bound retained finished scans. The admission cap above counts only active
    // jobs, so without this the map grows with every quick scan until the
    // retention TTL expires. Applied after the insert so the steady state is
    // exactly `max_retained_scans`; the job just added is non-terminal and so
    // is never a candidate for eviction.
    enforce_retention_cap(&mut jobs, state.max_retained_scans);
    Some(id)
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
