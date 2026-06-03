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
fn job_status_rejects_unknown_variant() {
    assert!(serde_json::from_str::<JobStatus>("\"finished\"").is_err());
}
