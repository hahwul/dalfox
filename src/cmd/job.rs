//! Shared job-lifecycle primitives for the REST server and MCP runtime.
//!
//! Both interfaces track asynchronous scans in an in-memory `HashMap<String, Job>`
//! with identical requirements: status transitions, progress counters, retention
//! TTL, reachability probing that respects the scan's HTTP config, and bounds
//! validation on scan options. This module owns those pieces so the two
//! interfaces stay in lockstep.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use crate::cmd::JobStatus;
use crate::scanning::result::SanitizedResult;
use crate::target_parser::Target;

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
mod tests {
    use super::*;

    #[test]
    fn test_parse_job_status_round_trip() {
        for status in [
            JobStatus::Queued,
            JobStatus::Running,
            JobStatus::Done,
            JobStatus::Error,
            JobStatus::Cancelled,
        ] {
            let s = status.to_string();
            assert_eq!(parse_job_status(&s), Some(status));
        }
        assert_eq!(parse_job_status("unknown"), None);
    }

    #[test]
    fn test_new_queued_initializes_timestamps() {
        let before = now_ms();
        let job = Job::new_queued("https://example.com".to_string());
        let after = now_ms();
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.queued_at_ms >= before && job.queued_at_ms <= after);
        assert!(job.started_at_ms.is_none());
        assert!(job.finished_at_ms.is_none());
        assert!(!job.is_terminal());
    }

    #[test]
    fn test_duration_ms_computed_from_timestamps() {
        let mut job = Job::new_queued("https://example.com".to_string());
        assert_eq!(job.duration_ms(), None);
        job.started_at_ms = Some(1000);
        job.finished_at_ms = Some(1250);
        assert_eq!(job.duration_ms(), Some(250));
    }

    #[test]
    fn test_purge_expired_jobs_removes_old_terminal_jobs() {
        let mut jobs = HashMap::new();
        let mut old = Job::new_queued("old".to_string());
        old.status = JobStatus::Done;
        old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
        jobs.insert("old".to_string(), old);

        let mut fresh = Job::new_queued("fresh".to_string());
        fresh.status = JobStatus::Done;
        fresh.finished_at_ms = Some(now_ms());
        jobs.insert("fresh".to_string(), fresh);

        jobs.insert("active".to_string(), Job::new_queued("active".to_string()));

        purge_expired_jobs(&mut jobs, JOB_RETENTION_SECS);

        assert!(!jobs.contains_key("old"), "old terminal job should be purged");
        assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
        assert!(jobs.contains_key("active"), "active job must never be purged");
    }
}
