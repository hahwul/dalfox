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
