//! End-to-end coverage for mid-scan session-loss detection (issue #1273).
//!
//! The unit tests in `cmd::scan::session` pin the classifier in isolation.
//! These drive the whole pipeline against a live server — preflight captures
//! the authenticated baseline, the scan loop re-probes after the injection
//! stage, and the verdict has to survive all the way out to the JSON envelope
//! and the process exit code. The regression these guard against is the one the
//! issue is about: a run that reports `"status": "clean"` and exits 0 because
//! it was talking to a login page the whole time.

use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, ScanOutcome, run_scan};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const SIGNED_IN: &str = "<html><body><h1>Signed in as alice</h1></body></html>";
const LOGGED_OUT: &str = "<html><body>session expired</body></html>";
const LOGIN_MARKUP: &str = "<form><input type=\"password\" name=\"pw\"></form>";

fn html_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers
}

/// An app with three faces:
///   `/`         — the authenticated landing page (the scan target).
///   `/expire`   — a probe endpoint that answers authenticated for its first
///                 `healthy_hits` requests and `401`s after that.
///   `/alive`    — a probe endpoint that always answers authenticated.
///
/// Splitting the probe endpoint off the scan target is what makes these tests
/// deterministic. `healthy_hits` has to cover the *baseline* hits: with a
/// `--session-check-url`, preflight takes each target's baseline from that same
/// endpoint (one hit per target), and the post-scan probe is the hit after
/// those. So one target ⇒ `healthy_hits = 1`, two targets ⇒ `2`.
async fn spawn_app(healthy_hits: usize) -> (String, tokio::task::JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", get(|| async { (html_headers(), SIGNED_IN) }))
        .route(
            "/expire",
            get(move || {
                let hits = hits.clone();
                async move {
                    if hits.fetch_add(1, Ordering::SeqCst) < healthy_hits {
                        (StatusCode::OK, html_headers(), SIGNED_IN)
                    } else {
                        (StatusCode::UNAUTHORIZED, html_headers(), LOGGED_OUT)
                    }
                }
            }),
        )
        .route("/alive", get(|| async { (html_headers(), SIGNED_IN) }))
        // A login-shaped path that is nevertheless a perfectly good probe
        // endpoint while authenticated.
        .route(
            "/auth/session",
            get(|| async { (html_headers(), SIGNED_IN) }),
        )
        // An authenticated landing page that lives behind a redirect onto a
        // login-shaped path. Real apps do this (`/` -> `/auth/home`).
        .route(
            "/redirect-home",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "/auth/home")],
                    html_headers(),
                    "",
                )
            }),
        )
        .route("/auth/home", get(|| async { (html_headers(), SIGNED_IN) }))
        // The same shape, but redirecting onto the sign-in page itself — a
        // real logged-out response, which must stay a `SESSION_LOST`.
        .route(
            "/redirect-login",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "/login")],
                    html_headers(),
                    "",
                )
            }),
        )
        .route("/login", get(|| async { (html_headers(), LOGIN_MARKUP) }))
        // A large authenticated shell whose login markup sits past the
        // preflight Range budget (8 KiB), served by an origin that honors
        // Range — so the baseline sees a prefix and the probe sees the lot.
        .route(
            "/big-shell",
            get(|headers: HeaderMap| async move {
                let body = format!("{}{}", "<!-- pad -->".repeat(3000), LOGIN_MARKUP);
                match headers.get("range") {
                    Some(_) => (
                        StatusCode::PARTIAL_CONTENT,
                        html_headers(),
                        body[..8192].to_string(),
                    ),
                    None => (StatusCode::OK, html_headers(), body),
                }
            }),
        )
        // Credentials that were already dead before the scan began.
        .route(
            "/stale",
            get(|| async { (StatusCode::UNAUTHORIZED, html_headers(), LOGGED_OUT) }),
        )
        // Reflects `q` straight into the document — a real finding, so the
        // exit-code interaction with session loss can be exercised.
        .route(
            "/reflect",
            get(|q: Query<HashMap<String, String>>| async move {
                let v = q.get("q").cloned().unwrap_or_default();
                (
                    html_headers(),
                    format!("<html><body><div>{}</div></body></html>", v),
                )
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), handle)
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    path.push(format!(
        "dalfox-{}-{}-{}.json",
        prefix,
        std::process::id(),
        nanos
    ));
    path
}

/// A lean single-target scan: no discovery, no mining, no WAF probe. We are
/// exercising the session path, not the payload engine, so every other request
/// source is switched off to keep the run fast and the traffic predictable.
fn lean_args(target: &str, output: &Path) -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: Some(output.to_string_lossy().to_string()),
        silence: true,
        targets: vec![target.to_string()],
        // Credentials: also what switches session monitoring on by default.
        cookies: vec!["sid=deadbeef".to_string()],
        skip_discovery: true,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        skip_waf_probe: true,
        skip_ast_analysis: true,
        insecure: Some(true),
        ..ScanArgs::default()
    }
}

fn read_meta(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("output should exist");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    parsed["meta"].clone()
}

#[tokio::test]
async fn session_loss_marks_the_target_incomplete_and_fails_the_exit_code() {
    let (base, server) = spawn_app(1).await;
    let out = unique_temp_path("session-lost");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/expire", base));

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    let summary = &meta["target_summary"][0];
    assert_eq!(
        summary["status"], "incomplete",
        "a target whose session died must not be reported as clean: {}",
        summary
    );
    assert_eq!(summary["error_code"], "SESSION_LOST");
    assert!(
        summary["error_message"]
            .as_str()
            .expect("error_message present")
            .contains("HTTP 401"),
        "the message should name the signal that fired: {}",
        summary
    );
    assert_eq!(
        meta["incomplete"], true,
        "meta.incomplete is the one-field answer to 'are these results trustworthy?'"
    );
    // The whole point: `dalfox scan ... && echo clean` must not print "clean".
    assert_eq!(outcome, ScanOutcome::Error);
}

#[tokio::test]
async fn a_live_session_leaves_the_run_clean() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-alive");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/alive", base));

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(meta["target_summary"][0]["status"], "clean");
    assert_eq!(meta["incomplete"], false);
    assert_eq!(outcome, ScanOutcome::Clean);
}

#[tokio::test]
async fn session_check_regex_drives_the_verdict_when_supplied() {
    let (base, server) = spawn_app(0).await;

    // The probe endpoint answers 200 with a perfectly ordinary page — every
    // heuristic says "alive". Only the operator's marker is missing.
    let out = unique_temp_path("session-regex-miss");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/alive", base));
    args.session_check = Some("Signed in as bob".to_string());
    let outcome = run_scan(&args).await;
    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);
    assert_eq!(meta["target_summary"][0]["status"], "incomplete");
    assert_eq!(outcome, ScanOutcome::Error);

    // Same endpoint, a marker that IS present: alive.
    let out = unique_temp_path("session-regex-hit");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/alive", base));
    args.session_check = Some("Signed in as alice".to_string());
    let outcome = run_scan(&args).await;
    server.abort();
    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);
    assert_eq!(meta["target_summary"][0]["status"], "clean");
    assert_eq!(outcome, ScanOutcome::Clean);
}

// A `--session-check-url` whose own path looks like a login endpoint
// (`/auth/session`, `/login-status`, …) must not read as a loss on the first
// probe. It only doesn't because the baseline for a check URL is taken from
// that same endpoint — compared against a `/dashboard` baseline, the login-URL
// signal would fire immediately and, under the default `abort`, kill the scan.
#[tokio::test]
async fn a_login_shaped_check_url_is_not_mistaken_for_a_logout() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-login-shaped-url");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/auth/session", base));

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(meta["target_summary"][0]["status"], "clean");
    assert_eq!(meta["incomplete"], false);
    assert_eq!(outcome, ScanOutcome::Clean);
}

// `--on-session-loss continue` is the escape hatch for targets where the
// heuristic misfires: it must still record the loss (so the report is honest)
// but must NOT turn the exit code red, or the flag would be pointless.
#[tokio::test]
async fn on_session_loss_continue_reports_but_does_not_fail_the_run() {
    let (base, server) = spawn_app(1).await;
    let out = unique_temp_path("session-continue");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/expire", base));
    args.on_session_loss_arg = Some("continue".to_string());

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(meta["target_summary"][0]["status"], "incomplete");
    assert_eq!(meta["incomplete"], true);
    assert_eq!(outcome, ScanOutcome::Clean);
}

// Under `abort`, a dead session must take the *rest of the host* with it —
// continuing to spend the request budget on a login page has no upside. Pinned
// at one concurrent target so the ordering is deterministic: the first target
// finishes (and discovers the loss) before the second is dispatched.
#[tokio::test]
async fn abort_skips_the_remaining_targets_for_that_host() {
    let (base, server) = spawn_app(2).await;
    let out = unique_temp_path("session-abort-group");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.targets.push(format!("{}/?q=2", base));
    args.session_check_url = Some(format!("{}/expire", base));
    args.max_concurrent_targets = 1;

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    let summary = meta["target_summary"].as_array().expect("summary array");
    assert_eq!(summary.len(), 2);
    // Whichever ran first is `incomplete`; the one behind it never ran at all
    // and is `skipped`. Both carry SESSION_LOST, and neither is "clean".
    let statuses: Vec<&str> = summary
        .iter()
        .map(|t| t["status"].as_str().unwrap_or("?"))
        .collect();
    assert!(
        statuses.contains(&"incomplete") && statuses.contains(&"skipped"),
        "expected one incomplete + one skipped, got {:?}",
        statuses
    );
    for t in summary {
        assert_eq!(t["error_code"], "SESSION_LOST", "{}", t);
    }
    assert_eq!(meta["incomplete"], true);
    assert_eq!(outcome, ScanOutcome::Error);
}

// An unauthenticated scan must not pay for a feature it can't use: no
// credentials, no `--session-check*`, so no baseline, no probes, and nothing
// about sessions in the envelope.
#[tokio::test]
async fn scans_without_credentials_are_untouched_by_session_monitoring() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-off");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.cookies.clear();

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(meta["target_summary"][0]["status"], "clean");
    assert!(meta["target_summary"][0]["error_code"].is_null());
    assert_eq!(meta["incomplete"], false);
    assert_eq!(outcome, ScanOutcome::Clean);
}

// A bad `--session-check` must fail before any request goes out, not an hour
// into the scan when the first probe tries to compile it.
#[tokio::test]
async fn an_invalid_session_check_regex_fails_fast() {
    let out = unique_temp_path("session-bad-regex");
    let mut args = lean_args("http://127.0.0.1:1/?q=1", &out);
    args.session_check = Some("(unclosed".to_string());

    assert_eq!(run_scan(&args).await, ScanOutcome::Error);
    assert!(
        !out.exists(),
        "the run must abort before producing any output"
    );
}

#[tokio::test]
async fn a_relative_session_check_url_fails_fast() {
    let out = unique_temp_path("session-bad-url");
    let mut args = lean_args("http://127.0.0.1:1/?q=1", &out);
    args.session_check_url = Some("/me".to_string());

    assert_eq!(run_scan(&args).await, ScanOutcome::Error);
    assert!(!out.exists());
}

// Regression: under `--follow-redirects` the baseline must record where the
// response actually landed, not the request URL. An app that serves its
// authenticated home behind `302 -> /auth/home` otherwise compares `/?q=1`
// against `/auth/home` on every probe, reads the `auth` segment as a login
// redirect, and aborts a scan nobody was logged out of.
#[tokio::test]
async fn a_followed_redirect_onto_a_login_shaped_path_is_not_a_logout() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-followed-redirect");
    let mut args = lean_args(&format!("{}/redirect-home?q=1", base), &out);
    args.follow_redirects = true;

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(
        meta["target_summary"][0]["status"], "clean",
        "the authenticated landing page is /auth/home; that is not a logout: {}",
        meta["target_summary"][0]
    );
    assert_eq!(meta["incomplete"], false);
    assert_eq!(outcome, ScanOutcome::Clean);
}

// Regression, and the reason `baseline_warning` uses `is_login_endpoint_url`:
// the same app scanned WITHOUT `--follow-redirects` (the default). The baseline
// is then the 302 itself, and its landing is resolved from the `Location`
// header — `/auth/home`. Reading the `auth` segment as a login wall reported
// SESSION_LOST, `incomplete: true` and exit 2 on a session that was never lost.
#[tokio::test]
async fn an_unfollowed_redirect_onto_an_auth_shaped_path_is_not_a_logout() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-unfollowed-redirect");
    let args = lean_args(&format!("{}/redirect-home?q=1", base), &out);
    assert!(!args.follow_redirects, "the default, and the point");

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(
        meta["target_summary"][0]["status"], "clean",
        "a 302 onto /auth/home is an authenticated landing page, not a logout: {}",
        meta["target_summary"][0]
    );
    assert_eq!(meta["incomplete"], false);
    assert_eq!(outcome, ScanOutcome::Clean, "must not exit 2");
}

// The other half of the same rule: narrowing the token list must not cost the
// detection it exists for. A 302 onto the sign-in page itself — no
// `--follow-redirects` either — is still an unusable baseline.
#[tokio::test]
async fn an_unfollowed_redirect_onto_the_login_page_is_still_a_logout() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-unfollowed-login-redirect");
    let args = lean_args(&format!("{}/redirect-login?q=1", base), &out);

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(
        meta["target_summary"][0]["error_code"], "SESSION_LOST",
        "{}",
        meta["target_summary"][0]
    );
    assert_eq!(meta["incomplete"], true);
    assert_eq!(
        outcome,
        ScanOutcome::Error,
        "an empty run must still exit 2"
    );
}

// Regression: preflight reads the body under `Range: bytes=0-8191` while a
// probe reads up to 64 KiB. On a Range-honoring origin, login markup past 8 KiB
// is invisible to the baseline and visible to every probe — a permanent false
// SESSION_LOST on any SPA shell with its login form below the fold.
#[tokio::test]
async fn login_markup_past_the_preflight_range_budget_is_not_a_logout() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-range-asymmetry");
    let args = lean_args(&format!("{}/big-shell?q=1", base), &out);

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert_eq!(
        meta["target_summary"][0]["status"], "clean",
        "the baseline never saw that region of the page, so it is not evidence: {}",
        meta["target_summary"][0]
    );
    assert_eq!(outcome, ScanOutcome::Clean);
}

// Credentials that were already dead at preflight are the worst variant: the
// login page becomes the baseline, so no later probe can ever detect a change.
// That must still reach the envelope and the exit code, not just stderr.
#[tokio::test]
async fn credentials_already_stale_at_preflight_are_reported_not_just_logged() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-stale-at-preflight");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check_url = Some(format!("{}/stale", base));

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    let summary = &meta["target_summary"][0];
    assert_eq!(summary["status"], "incomplete", "{}", summary);
    assert_eq!(summary["error_code"], "SESSION_LOST");
    assert!(
        summary["error_message"]
            .as_str()
            .unwrap_or_default()
            .contains("already looks unauthenticated"),
        "{}",
        summary
    );
    assert_eq!(meta["incomplete"], true);
    assert_eq!(outcome, ScanOutcome::Error);
}

// A `--session-check` marker that never matched the baseline is a typo or a
// wrong page, not a logout — but it *would* make every probe report a loss. It
// has to be caught at preflight and named for what it is.
#[tokio::test]
async fn a_session_check_marker_absent_from_the_baseline_is_named_as_such() {
    let (base, server) = spawn_app(0).await;
    let out = unique_temp_path("session-marker-typo");
    let mut args = lean_args(&format!("{}/?q=1", base), &out);
    args.session_check = Some("Signed in as nobody".to_string());

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    let summary = &meta["target_summary"][0];
    assert_eq!(summary["status"], "incomplete");
    assert!(
        summary["error_message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not match the baseline"),
        "the operator needs to know the marker is wrong, not that they were logged out: {}",
        summary
    );
    assert_eq!(outcome, ScanOutcome::Error);
}

// Exit codes have to stay distinguishable: 1 means "vulnerabilities found",
// 2 means "this run failed". A scan that confirmed a finding and *then* lost
// its session found something real — reporting it as an infrastructure error
// would make CI that separates the two treat a successful detection as a
// broken job. `meta.incomplete` carries the incompleteness for both codes.
#[tokio::test]
async fn a_run_with_findings_still_exits_one_after_a_session_loss() {
    let (base, server) = spawn_app(1).await;
    let out = unique_temp_path("session-lost-with-findings");
    let mut args = lean_args(&format!("{}/reflect?q=1", base), &out);
    args.session_check_url = Some(format!("{}/expire", base));
    // Let the injection stage actually run against the reflecting parameter.
    args.skip_discovery = false;

    let outcome = run_scan(&args).await;
    server.abort();

    let meta = read_meta(&out);
    let _ = std::fs::remove_file(&out);

    assert!(
        meta["findings_count"].as_u64().unwrap_or(0) > 0,
        "the reflecting endpoint should produce at least one finding: {}",
        meta
    );
    assert_eq!(meta["target_summary"][0]["status"], "incomplete");
    assert_eq!(
        meta["incomplete"], true,
        "the run is still flagged as incomplete"
    );
    assert_eq!(
        outcome,
        ScanOutcome::Findings,
        "findings outrank the session loss for the exit code"
    );
}
