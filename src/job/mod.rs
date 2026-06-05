//! Shared job-lifecycle domain for the REST server and MCP runtime.
//!
//! Both interfaces track asynchronous scans in an in-memory `HashMap<String, Job>`
//! with identical requirements: status transitions, progress counters, retention
//! TTL, reachability probing that respects the scan's HTTP config, and bounds
//! validation on scan options. This module owns those pieces so the two
//! interfaces stay in lockstep. It lives at the crate root (rather than under
//! `cmd`) because it is a subsystem shared by `server` and `mcp`, not a command.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use serde::{Deserialize, Serialize};

use crate::scanning::result::SanitizedResult;
use crate::target_parser::Target;

/// Status of an asynchronous scan job (used by both REST server and MCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Error,
    Cancelled,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Done => write!(f, "done"),
            Self::Error => write!(f, "error"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// How long terminal jobs (done/error/cancelled) are retained in memory before
/// being auto-purged. Prevents unbounded growth in long-running processes.
pub const JOB_RETENTION_SECS: i64 = 3600;

/// Maximum HTTP request timeout accepted via scan options (inclusive).
pub const MAX_TIMEOUT_SECS: u64 = 299;
/// Maximum delay-between-requests accepted via scan options (inclusive).
pub const MAX_DELAY_MS: u64 = 9999;
/// Maximum worker count accepted via scan options (inclusive).
pub const MAX_WORKERS: usize = 500;

/// Cap on the number of distinct parameters a single async (server/MCP) scan
/// will test. `analyze_parameters` can discover/mine a very large parameter set
/// on a hostile or sprawling target, and scanning fans out O(params × payloads)
/// worker tasks — so an uncapped count amplifies CPU / memory / outbound load
/// from one submission. Beyond this the candidate set is truncated with a log.
pub const MAX_DISCOVERED_PARAMS: usize = 512;

/// Default ceiling on concurrently active (queued + running) scans for the MCP
/// runtime, which — unlike the REST server's `--max-concurrent-scans` — has no
/// config surface. Submissions past this are rejected so an agent loop can't
/// grow the job map / blocking pool without bound.
pub const MAX_ACTIVE_SCANS_MCP: usize = 100;

/// Resolve the effective per-scan request-rate limit (requests/second) from a
/// per-request value and an optional server-side cap.
///
/// - `0` means "no limit" (unlimited), matching the CLI's `--rate-limit 0`.
/// - When the server sets a cap (`Some(c)` with `c > 0`) it is an *upper bound*
///   on outbound RPS: a request may ask for a lower rate but cannot raise it
///   past the cap or disable it (a requested `0` is clamped down to the cap).
///   This lets an operator bound the load every submitted scan can put on a
///   target, regardless of what an (authenticated) client requests.
pub fn effective_rate_limit(requested: Option<u32>, server_cap: Option<u32>) -> u32 {
    match (requested, server_cap.filter(|c| *c > 0)) {
        (Some(r), Some(cap)) => {
            if r == 0 {
                cap
            } else {
                r.min(cap)
            }
        }
        (Some(r), None) => r,
        (None, Some(cap)) => cap,
        (None, None) => 0,
    }
}

/// Truncate a target's discovered parameter set to [`MAX_DISCOVERED_PARAMS`],
/// returning how many were dropped (0 if already under the cap). Shared by the
/// REST server, MCP, and both preflight paths so every async front-end bounds
/// the per-scan fan-out identically. Callers should log when the return is > 0.
pub fn cap_reflection_params(target: &mut Target) -> usize {
    let n = target.reflection_params.len();
    if n > MAX_DISCOVERED_PARAMS {
        target.reflection_params.truncate(MAX_DISCOVERED_PARAMS);
        n - MAX_DISCOVERED_PARAMS
    } else {
        0
    }
}

/// Split an HTTP-style `Cookie` header value (`a=b; c=d`) into `(name, value)`
/// pairs, trimming whitespace around each pair and around the `=`. Shared by the
/// REST server and the MCP scan/preflight paths so a multi-cookie value parses
/// identically everywhere (a single `split_once('=')` would fold `; c=d` into
/// the first value and leave `=`-adjacent whitespace in).
pub fn split_cookie_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Current unix time in milliseconds (UTC).
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Parse a lowercase status string back into `JobStatus`. Returns `None` for
/// unknown values so callers can surface a precise error instead of silently
/// matching nothing.
pub fn parse_job_status(s: &str) -> Option<JobStatus> {
    match s {
        "queued" => Some(JobStatus::Queued),
        "running" => Some(JobStatus::Running),
        "done" => Some(JobStatus::Done),
        "error" => Some(JobStatus::Error),
        "cancelled" => Some(JobStatus::Cancelled),
        _ => None,
    }
}

/// Progress counters shared with a running scan task.
#[derive(Clone, Default)]
pub struct JobProgress {
    pub requests_sent: Arc<AtomicU64>,
    pub findings_so_far: Arc<AtomicU64>,
    pub params_total: Arc<AtomicU32>,
    pub params_tested: Arc<AtomicU32>,
}

/// Single in-memory representation of an asynchronous scan used by both the
/// REST server and the MCP runtime. `callback_url` is only populated by the
/// REST server's webhook feature; MCP leaves it `None`.
#[derive(Clone)]
pub struct Job {
    pub status: JobStatus,
    /// Sanitized findings, wrapped in `Arc` so cloning a Job for outbound
    /// responses is a pointer bump rather than a deep copy of potentially
    /// large raw request/response bodies.
    pub results: Option<Arc<Vec<SanitizedResult>>>,
    pub progress: JobProgress,
    pub cancelled: Arc<AtomicBool>,
    pub error_message: Option<String>,
    /// The original target URL submitted for scanning.
    pub target_url: String,
    /// Optional webhook URL to POST results to. REST-server only.
    pub callback_url: Option<String>,
    /// Unix ms when the scan was enqueued.
    pub queued_at_ms: i64,
    /// Unix ms when the scan transitioned to Running.
    pub started_at_ms: Option<i64>,
    /// Unix ms when the scan reached a terminal state (done/error/cancelled).
    pub finished_at_ms: Option<i64>,
}

impl Job {
    /// Construct a freshly-queued Job for `target_url`, with timestamps and
    /// flags set to their initial "just enqueued" state.
    pub fn new_queued(target_url: String) -> Self {
        Self {
            status: JobStatus::Queued,
            results: None,
            progress: JobProgress::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            error_message: None,
            target_url,
            callback_url: None,
            queued_at_ms: now_ms(),
            started_at_ms: None,
            finished_at_ms: None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            JobStatus::Done | JobStatus::Error | JobStatus::Cancelled
        )
    }

    /// Total elapsed ms from `started_at_ms` to `finished_at_ms` (or now, for
    /// still-running jobs). `None` if the scan never started.
    pub fn duration_ms(&self) -> Option<i64> {
        match (self.started_at_ms, self.finished_at_ms) {
            (Some(s), Some(f)) => Some(f - s),
            (Some(s), None) => Some(now_ms() - s),
            _ => None,
        }
    }
}

/// Remove terminal jobs whose `finished_at_ms` is older than `retention_secs`
/// seconds ago. The caller is expected to hold the jobs map's lock.
pub fn purge_expired_jobs(jobs: &mut HashMap<String, Job>, retention_secs: i64) {
    let cutoff = now_ms() - retention_secs * 1000;
    jobs.retain(|_, job| match job.finished_at_ms {
        Some(finished) => finished >= cutoff,
        None => true,
    });
}

/// RAII guard that aborts a background `JoinHandle` on drop, including the
/// panic path. Both the REST server and MCP spawn a small progress-mirroring
/// task that must not outlive `run_scan_job` — without this guard, a panic
/// between the spawn and the manual `abort()` call would leak the task.
pub struct AbortOnDrop<T>(pub tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send one request mirroring the scan's HTTP configuration (method, headers,
/// cookies, User-Agent, body, proxy, timeout, redirects). Returns true iff a
/// response came back — content/status are not inspected.
///
/// Used by preflight reachability probes so the result reflects what a real
/// scan would see, not what a default reqwest client sees.
/// True when `url` (after trimming) carries an `http`/`https` scheme. The
/// scheme is matched case-insensitively because URI schemes are
/// case-insensitive (RFC 3986 §3.1) and `parse_target` already lowercases the
/// scheme — so `HTTP://x` is a valid target the scanner would otherwise dial.
/// Shared by the REST server (`/scan`, `/preflight`) and the MCP scan/preflight
/// tools so the accepted-target contract is identical everywhere. Allocation-
/// and panic-free (byte-prefix compare, never slices on a char boundary).
pub fn has_http_scheme(url: &str) -> bool {
    let b = url.trim().as_bytes();
    let starts_with = |p: &[u8]| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p);
    starts_with(b"http://") || starts_with(b"https://")
}

/// The `error_message` recorded when a scan target can't be connected to.
/// Shared by the REST server and MCP so the client-facing string — which
/// callers grep to tell "unreachable" apart from "scanned, no findings" —
/// has a single source of truth. Carries the `CONNECTION_FAILED` code that
/// `/preflight` already returns in its `error_code` field.
pub fn unreachable_error_message() -> String {
    format!(
        "target unreachable: connection failed ({})",
        crate::cmd::error_codes::CONNECTION_FAILED
    )
}

pub async fn send_reachability_probe(target: &Target) -> bool {
    let client = target.build_client_or_default();
    let mut req = client.request(target.parse_method(), target.url.clone());
    for (k, v) in &target.headers {
        req = req.header(k, v);
    }
    if !target.cookies.is_empty() {
        let cookie_header = target
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        req = req.header("Cookie", cookie_header);
    }
    if let Some(ua) = target.user_agent.as_deref().filter(|s| !s.is_empty()) {
        req = req.header("User-Agent", ua);
    }
    if let Some(body) = &target.data {
        req = req.body(body.clone());
    }
    req.send().await.is_ok()
}

#[cfg(test)]
mod tests;
