use super::*;

#[test]
fn test_has_http_scheme() {
    // Accepts http/https, case-insensitively, after trimming.
    for ok in [
        "http://example.com",
        "https://example.com/p?q=1",
        "HTTP://EXAMPLE.COM",
        "HtTpS://x",
        "  http://x  ",
    ] {
        assert!(has_http_scheme(ok), "should accept {:?}", ok);
    }
    // Rejects other schemes, bare hosts, and empties.
    for bad in [
        "ftp://x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "example.com",
        "",
        "   ",
        "httpx://x",
    ] {
        assert!(!has_http_scheme(bad), "should reject {:?}", bad);
    }
}

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

    assert!(
        !jobs.contains_key("old"),
        "old terminal job should be purged"
    );
    assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
    assert!(
        jobs.contains_key("active"),
        "active job must never be purged"
    );
}

#[test]
fn job_status_display_matches_lowercase_variant_name() {
    assert_eq!(JobStatus::Queued.to_string(), "queued");
    assert_eq!(JobStatus::Running.to_string(), "running");
    assert_eq!(JobStatus::Done.to_string(), "done");
    assert_eq!(JobStatus::Error.to_string(), "error");
    assert_eq!(JobStatus::Cancelled.to_string(), "cancelled");
}

/// The Display impl and the `#[serde(rename_all = "lowercase")]`
/// representation must agree — REST and MCP clients parse the JSON
/// form, and CLI logs print the Display form. Drift between them
/// would silently break consumers that compare the two strings.
#[test]
fn job_status_serde_matches_display() {
    let variants = [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Done,
        JobStatus::Error,
        JobStatus::Cancelled,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        // serde_json wraps the variant name in quotes.
        assert_eq!(json, format!("\"{}\"", v));
        let round: JobStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(round, v);
    }
}

#[test]
fn job_status_deserializes_from_lowercase_string() {
    let s: JobStatus = serde_json::from_str("\"queued\"").unwrap();
    assert_eq!(s, JobStatus::Queued);
    let s: JobStatus = serde_json::from_str("\"cancelled\"").unwrap();
    assert_eq!(s, JobStatus::Cancelled);
}

#[test]
fn effective_rate_limit_resolves_request_and_cap() {
    // No request, no cap → unlimited.
    assert_eq!(effective_rate_limit(None, None), 0);
    // No request, cap set → the cap applies to everyone.
    assert_eq!(effective_rate_limit(None, Some(20)), 20);
    // Cap explicitly 0 → still unlimited.
    assert_eq!(effective_rate_limit(None, Some(0)), 0);
    // Request only → used as-is (including an explicit unlimited).
    assert_eq!(effective_rate_limit(Some(50), None), 50);
    assert_eq!(effective_rate_limit(Some(0), None), 0);
    // Request below the cap → request wins (a client may ask for less).
    assert_eq!(effective_rate_limit(Some(5), Some(20)), 5);
    // Request above the cap → clamped down to the cap.
    assert_eq!(effective_rate_limit(Some(100), Some(20)), 20);
    // Request tries to go unlimited while a cap is set → clamped to the cap.
    assert_eq!(effective_rate_limit(Some(0), Some(20)), 20);
}

#[test]
fn split_cookie_pairs_splits_and_trims_multi_cookie_value() {
    // The bug F4 fixes: a bare split_once('=') would fold "; lang=en" into the
    // first value and keep the surrounding whitespace.
    let pairs = split_cookie_pairs("session = abc ; lang=en");
    assert_eq!(
        pairs,
        vec![
            ("session".to_string(), "abc".to_string()),
            ("lang".to_string(), "en".to_string()),
        ]
    );
}

#[test]
fn job_status_rejects_unknown_variant() {
    assert!(serde_json::from_str::<JobStatus>("\"finished\"").is_err());
}

#[test]
fn effective_scan_timeout_resolves_request_and_cap() {
    // No request, no cap → unbounded.
    assert_eq!(effective_scan_timeout(None, None), 0);
    // No request, cap set → the cap applies to everyone.
    assert_eq!(effective_scan_timeout(None, Some(30)), 30);
    // No request, cap explicitly 0 → still unbounded (a 0 cap is "no cap").
    assert_eq!(effective_scan_timeout(None, Some(0)), 0);
    // Request only → used as-is, including an explicit disable.
    assert_eq!(effective_scan_timeout(Some(45), None), 45);
    assert_eq!(effective_scan_timeout(Some(0), None), 0);
    // Request under the cap → request wins (a client may ask for less).
    assert_eq!(effective_scan_timeout(Some(10), Some(30)), 10);
    // Request over the cap → clamped down to the cap (can't exceed it).
    assert_eq!(effective_scan_timeout(Some(120), Some(30)), 30);
    // Request tries to disable while a cap is set → clamped up to the cap
    // (a client cannot opt out of a server-enforced budget).
    assert_eq!(effective_scan_timeout(Some(0), Some(30)), 30);
    // Equal values → that value.
    assert_eq!(effective_scan_timeout(Some(30), Some(30)), 30);
}

#[tokio::test]
async fn run_within_scan_budget_trips_and_sets_cancel_on_expiry() {
    let cancel = Arc::new(AtomicBool::new(false));
    // Budget of 1s against a future that would take 3s → must abort at the
    // budget (~1s), set the cancel flag, and report that it timed out.
    let timed_out = run_within_scan_budget(1, &cancel, async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    })
    .await;
    assert!(timed_out, "an over-budget scan must report timed_out");
    assert!(
        cancel.load(std::sync::atomic::Ordering::Relaxed),
        "expiry must trip the shared cancel flag so workers wind down"
    );
}

#[tokio::test]
async fn run_within_scan_budget_passes_through_when_under_budget() {
    let cancel = Arc::new(AtomicBool::new(false));
    // Completes well inside the budget → no timeout, cancel flag untouched.
    let timed_out = run_within_scan_budget(5, &cancel, async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    })
    .await;
    assert!(!timed_out, "a scan that finishes in time must not time out");
    assert!(!cancel.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn run_within_scan_budget_zero_disables_the_cap() {
    let cancel = Arc::new(AtomicBool::new(false));
    // budget_secs == 0 takes the no-cap branch: it just awaits the future and
    // returns false without ever arming a timer or touching the cancel flag.
    let timed_out = run_within_scan_budget(0, &cancel, async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    })
    .await;
    assert!(!timed_out, "a 0 budget must never report a timeout");
    assert!(!cancel.load(std::sync::atomic::Ordering::Relaxed));
}
