//! Small server-wide helpers: structured logging, scan-id derivation, cookie
//! parsing, scan-option validation, and the job-retention purge wrapper.

use super::*;

/// Reject scan-option values that are outside the supported range so callers
/// get a precise 400 instead of having the server silently substitute defaults.
pub(crate) fn validate_scan_options(opts: &ScanOptions) -> Result<(), String> {
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

/// Thin wrapper over `crate::job::purge_expired_jobs` that acquires the jobs
/// lock for the caller.
pub(crate) async fn purge_expired_jobs(state: &AppState) {
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
            .map_err(|_| format!("{} must be a non-negative integer (got '{}')", key, raw)),
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

/// Defang ASCII control characters in a (possibly user-controlled) log message
/// so a submitter can't forge extra log lines. Log calls embed the target URL
/// and error strings, which carry attacker-supplied bytes; `has_http_scheme`
/// only checks the prefix, so an embedded `\n`/`\r` would otherwise inject a
/// whole fabricated `[ts] [LVL] ...` line into the file and onto stdout.
/// CR/LF become `\n`/`\r`; other C0 controls become `\xNN`; tab is kept. Returns
/// a borrowed string on the common (clean) path so non-injecting logs allocate
/// nothing.
pub(crate) fn sanitize_log_message(msg: &str) -> std::borrow::Cow<'_, str> {
    if !msg.bytes().any(|b| b < 0x20 && b != b'\t') {
        return std::borrow::Cow::Borrowed(msg);
    }
    let mut out = String::with_capacity(msg.len() + 8);
    for c in msg.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push('\t'),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

pub(crate) fn log(state: &AppState, level: &str, message: &str) {
    let message = sanitize_log_message(message);
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
