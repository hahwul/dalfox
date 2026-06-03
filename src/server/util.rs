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

/// Split the server's HTTP-style `Cookie` header value (`a=b; c=d`) into
/// `(name, value)` pairs. Earlier code did a single `split_once('=')` on the
/// whole input, which silently folded `; c=d` into the value of the first
/// pair — `preflight_handler` already used the `;`-split form, so the two
/// endpoints disagreed on what a multi-cookie header meant.
pub(crate) fn split_cookie_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub(crate) fn log(state: &AppState, level: &str, message: &str) {
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
