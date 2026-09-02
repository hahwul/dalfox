use super::*;

#[test]
fn test_normalize_proxy_empty_is_absent_unroutable_is_error() {
    // REST/MCP treat empty as "no proxy" (templated `?proxy=`). The CLI's
    // `validate_proxy_url` rejects empty instead — that split is deliberate.
    assert_eq!(normalize_proxy("").unwrap(), None);
    assert_eq!(normalize_proxy("   ").unwrap(), None);

    assert_eq!(
        normalize_proxy("  http://127.0.0.1:8080  ")
            .unwrap()
            .as_deref(),
        Some("http://127.0.0.1:8080")
    );
    assert_eq!(
        normalize_proxy("\u{a0}socks5://127.0.0.1:1080")
            .unwrap()
            .as_deref(),
        Some("socks5://127.0.0.1:1080")
    );

    // `ftp://` parses and passes `Proxy::all` but is not routed — must not
    // survive as a stored proxy, or the scan goes DIRECT.
    let err = normalize_proxy("ftp://127.0.0.1:8080").unwrap_err();
    assert!(
        err.contains("not routable"),
        "unroutable scheme must be named, got: {err}"
    );
    assert!(
        !err.contains("S3cr3t"),
        "must not echo a proxy that could carry credentials"
    );
    let secret_err = normalize_proxy("ftp://user:S3cr3t@host:8080").unwrap_err();
    assert!(
        !secret_err.contains("S3cr3t"),
        "error leaked credentials: {secret_err}"
    );
}

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
fn test_duration_ms_clamps_clock_stepback_to_zero() {
    // A wall-clock step-back (NTP/VM) between started_at and finished_at must
    // not surface a negative duration in the serialized API output.
    let mut job = Job::new_queued("https://example.com".to_string());
    job.started_at_ms = Some(5_000);
    job.finished_at_ms = Some(4_000);
    assert_eq!(job.duration_ms(), Some(0));
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

#[test]
fn enforce_retention_cap_evicts_oldest_finished_first() {
    let mut jobs: HashMap<String, Job> = HashMap::new();
    for i in 0..5i64 {
        let mut job = Job::new_queued(format!("http://example.com/{}", i));
        job.status = JobStatus::Done;
        job.finished_at_ms = Some(1_000 + i);
        jobs.insert(format!("job{}", i), job);
    }

    enforce_retention_cap(&mut jobs, 3);

    assert_eq!(jobs.len(), 3);
    assert!(!jobs.contains_key("job0"), "oldest evicted first");
    assert!(!jobs.contains_key("job1"));
    assert!(jobs.contains_key("job4"), "newest retained");
}

#[test]
fn enforce_retention_cap_never_evicts_active_jobs() {
    let mut jobs: HashMap<String, Job> = HashMap::new();
    // Two active jobs with no finished_at, plus one finished job.
    jobs.insert(
        "queued".to_string(),
        Job::new_queued("http://a".to_string()),
    );
    let mut running = Job::new_queued("http://b".to_string());
    running.status = JobStatus::Running;
    jobs.insert("running".to_string(), running);
    let mut done = Job::new_queued("http://c".to_string());
    done.status = JobStatus::Done;
    done.finished_at_ms = Some(now_ms());
    jobs.insert("done".to_string(), done);

    enforce_retention_cap(&mut jobs, 1);

    // Only the finished one can go; the map stays over cap rather than
    // stranding a worker that is still writing to its entry.
    assert_eq!(jobs.len(), 2);
    assert!(jobs.contains_key("queued"));
    assert!(jobs.contains_key("running"));
    assert!(!jobs.contains_key("done"));
}

// ---------------------------------------------------------------------------
// Worker leases: a cancelled job is stamped terminal while its worker drains
// ---------------------------------------------------------------------------
//
// `cancel_scan_handler` sets `status = Cancelled` and `finished_at_ms` the
// moment the user asks, so `is_terminal()` is true while the worker is still
// running — it has partial results to store, a status to reconcile and (REST) a
// terminal webhook to fire. Retention used to evict on `is_terminal()` alone,
// so a burst of new submissions could collect that entry out from under the
// worker: `jobs.get_mut(&id)` then returns None, the results are dropped, the
// webhook never fires, and a GET on the caller's scan_id 404s.

#[test]
fn cancelled_job_with_a_live_worker_is_not_evictable() {
    let mut job = Job::new_queued("http://a".to_string());
    let lease = job.issue_worker_lease();

    // What DELETE /scan/{id} does to a running job.
    job.status = JobStatus::Cancelled;
    job.finished_at_ms = Some(now_ms());

    assert!(
        job.is_terminal(),
        "cancel stamps the terminal state at once"
    );
    assert!(job.worker_alive(), "but the worker is still draining");
    assert!(
        !job.is_evictable(),
        "retention must not collect a job a worker is still writing to"
    );

    // Worker finishes (or panics): the lease drops and the entry is collectable.
    drop(lease);
    assert!(!job.worker_alive());
    assert!(job.is_evictable());
}

#[test]
fn enforce_retention_cap_never_evicts_a_draining_job() {
    let mut jobs: HashMap<String, Job> = HashMap::new();

    let mut draining = Job::new_queued("http://draining".to_string());
    let _lease = draining.issue_worker_lease();
    draining.status = JobStatus::Cancelled;
    // Oldest by finished_at, so it is the *first* candidate the cap would take.
    draining.finished_at_ms = Some(1_000);
    jobs.insert("draining".to_string(), draining);

    let mut settled = Job::new_queued("http://settled".to_string());
    settled.status = JobStatus::Done;
    settled.finished_at_ms = Some(2_000);
    jobs.insert("settled".to_string(), settled);

    enforce_retention_cap(&mut jobs, 1);

    assert!(
        jobs.contains_key("draining"),
        "a cancelled-but-draining job must survive the retention cap"
    );
    assert!(
        !jobs.contains_key("settled"),
        "the settled job is the one that should have been evicted"
    );
}

#[test]
fn purge_expired_jobs_keeps_a_draining_job_past_its_ttl() {
    let mut jobs: HashMap<String, Job> = HashMap::new();
    let mut draining = Job::new_queued("http://draining".to_string());
    let _lease = draining.issue_worker_lease();
    draining.status = JobStatus::Cancelled;
    draining.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
    jobs.insert("draining".to_string(), draining);

    purge_expired_jobs(&mut jobs, JOB_RETENTION_SECS);

    assert!(
        jobs.contains_key("draining"),
        "the retention TTL must not collect an entry a worker still owns"
    );

    // Same job once the worker is gone: now it is past its TTL and collectable.
    jobs.get_mut("draining")
        .expect("still present")
        .worker_lease = None;
    purge_expired_jobs(&mut jobs, JOB_RETENTION_SECS);
    assert!(jobs.is_empty(), "an expired settled job is still purged");
}

#[test]
fn a_job_with_no_worker_is_evictable_as_soon_as_it_is_terminal() {
    // Jobs staged by hand (tests, and any future path that records a terminal
    // job without spawning a worker) carry no lease, so the lease check must
    // not turn into "never evict anything".
    let mut job = Job::new_queued("http://a".to_string());
    job.status = JobStatus::Done;
    job.finished_at_ms = Some(now_ms());
    assert!(!job.worker_alive());
    assert!(job.is_evictable());
}

#[test]
fn enforce_retention_cap_zero_disables_the_cap() {
    let mut jobs: HashMap<String, Job> = HashMap::new();
    for i in 0..4 {
        let mut job = Job::new_queued(format!("http://example.com/{}", i));
        job.status = JobStatus::Done;
        job.finished_at_ms = Some(now_ms());
        jobs.insert(format!("job{}", i), job);
    }

    enforce_retention_cap(&mut jobs, 0);

    assert_eq!(jobs.len(), 4);
}

// ---------------------------------------------------------------------------
// job::spec — the shared REST/MCP request → ScanArgs mapping
// ---------------------------------------------------------------------------

use crate::job::spec::ScanRequestSpec;

/// The surface policy every agent-facing scan gets regardless of what the
/// caller asked for. Previously written out twice (once in `job_runner`, once
/// in the MCP tool) and drifted; pin it once.
#[test]
fn into_scan_args_applies_the_fixed_surface_policy() {
    let args = ScanRequestSpec {
        target: "http://example.com/?q=1".to_string(),
        skip_mining: true,
        ..Default::default()
    }
    .into_scan_args();

    assert_eq!(args.input_type, "url");
    assert_eq!(args.targets, vec!["http://example.com/?q=1".to_string()]);
    assert_eq!(args.format, "json");
    assert!(args.silence, "job output is serialized, never printed");
    assert!(args.no_color, "diagnostics must not carry ANSI into JSON");
    // One request-level switch drives all three mining stages.
    assert!(args.skip_mining && args.skip_mining_dict && args.skip_mining_dom);
    assert!(
        args.oob.blind_oob.is_none(),
        "OOB/OAST blind XSS stays CLI-only on these surfaces"
    );
}

/// A REST request that names nothing must land on the CLI's own defaults. The
/// REST path used to spell them as literals (`50`, `"GET"`, `["url", "html"]`),
/// so changing a `DEFAULT_*` moved the CLI and MCP but silently left the server
/// behind.
#[test]
fn rest_defaults_track_the_cli_constants() {
    let opts = crate::server::types::ScanOptions::default();
    let spec = ScanRequestSpec::from_rest_options(
        "http://example.com".to_string(),
        &opts,
        false,
        false,
        0,
        0,
        None,
    );

    assert_eq!(spec.workers, crate::cmd::scan::DEFAULT_WORKERS);
    assert_eq!(spec.method, crate::cmd::scan::DEFAULT_METHOD);
    assert_eq!(spec.timeout, crate::cmd::scan::DEFAULT_TIMEOUT_SECS);
    assert_eq!(spec.waf_bypass, crate::cmd::scan::DEFAULT_WAF_BYPASS);
    assert_eq!(
        spec.waf_min_confidence,
        crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE
    );
    assert_eq!(spec.encoders, crate::cmd::scan::DEFAULT_ENCODERS);
    assert_eq!(
        spec.insecure, None,
        "an unspecified `insecure` stays unspecified; the Target decides"
    );
}

/// The two front-ends describe the same scan in two request shapes. Given
/// equivalent input they must produce byte-identical `ScanArgs` — that equality
/// is the whole reason the mapping was pulled into one place.
#[test]
fn rest_and_mcp_requests_agree_on_scan_args() {
    let mcp_params: crate::mcp::ScanWithDalfoxParams =
        serde_json::from_str(r#"{"target":"http://example.com/?q=1"}"#)
            .expect("minimal MCP scan request deserializes");

    // The MCP tool schema fills its own defaults via serde; the REST body
    // leaves everything `None` and resolves defaults on the way into the spec.
    let rest = ScanRequestSpec::from_rest_options(
        "http://example.com/?q=1".to_string(),
        &crate::server::types::ScanOptions::default(),
        false,
        false,
        0,
        0,
        None,
    )
    .into_scan_args();

    let mcp = ScanRequestSpec {
        target: "http://example.com/?q=1".to_string(),
        param: mcp_params.param,
        data: mcp_params.data,
        headers: mcp_params.headers,
        cookies: mcp_params.cookies,
        method: mcp_params.method,
        user_agent: mcp_params.user_agent,
        encoders: mcp_params.encoders,
        timeout: mcp_params.timeout,
        scan_timeout: mcp_params.scan_timeout,
        delay: mcp_params.delay,
        follow_redirects: mcp_params.follow_redirects,
        // The only deliberate divergence: MCP's schema always yields a concrete
        // bool, and its default (`true`) is the same posture the REST path
        // reaches by leaving the choice to the Target. Normalize it here so the
        // rest of the comparison is meaningful.
        insecure: None,
        proxy: mcp_params.proxy,
        include_request: mcp_params.include_request,
        include_response: mcp_params.include_response,
        skip_mining: mcp_params.skip_mining,
        skip_discovery: mcp_params.skip_discovery,
        deep_scan: mcp_params.deep_scan,
        skip_ast_analysis: mcp_params.skip_ast_analysis,
        analyze_external_js: mcp_params.analyze_external_js,
        detect_outdated_libs: mcp_params.detect_outdated_libs,
        blind_callback_url: mcp_params.blind_callback_url,
        workers: mcp_params.workers,
        rate_limit: mcp_params.rate_limit,
        waf_bypass: mcp_params.waf_bypass,
        skip_waf_probe: mcp_params.skip_waf_probe,
        force_waf: mcp_params.force_waf,
        waf_evasion: mcp_params.waf_evasion,
        waf_min_confidence: mcp_params.waf_min_confidence as f32,
        remote_payloads: mcp_params.remote_payloads,
        remote_wordlists: mcp_params.remote_wordlists,
        max_payloads_per_param: mcp_params.max_payloads_per_param,
    }
    .into_scan_args();

    assert_eq!(
        rest, mcp,
        "a default REST scan and a default MCP scan must run identically"
    );
}

#[test]
fn validate_header_value_matches_reqwest_builder_semantics() {
    // What reqwest's `.header()` accepts for a &str value, this must accept —
    // and reject the control bytes that fail the builder. Obs-text (a UTF-8
    // User-Agent) is legal; CR/LF/NUL are not.
    assert!(validate_header_value("user_agent", "Mozilla/5.0 (caf\u{e9})").is_ok());
    assert!(validate_header_value("cookie", "sid=abc; theme=dark").is_ok());
    assert!(validate_header_value("user_agent", "Mozilla\r\nX: 1").is_err());
    assert!(validate_header_value("user_agent", "Mozilla\nX: 1").is_err());
    assert!(validate_header_value("cookie", "sid=a\0b").is_err());
}
