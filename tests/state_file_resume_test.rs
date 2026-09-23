//! End-to-end coverage for `--state-file` resume (issue #1275).
//!
//! The unit tests in `cmd::scan::state_file` pin the file format and the
//! hashing rules in isolation. These drive the whole pipeline against a live
//! server and assert on the thing that actually matters to an operator: a
//! resumed run must not re-request the targets a previous run finished, and it
//! must re-request everything else.
//!
//! Request counting is the assertion of record here — a log line or a meta
//! field could report a skip that did not happen, but a server that never sees
//! the request cannot lie.

use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue};
use axum::routing::{any, get};
use dalfox::cmd::scan::{ScanArgs, ScanOutcome, run_scan};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn html_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers
}

/// A reflecting app that counts every request it serves.
///
/// `/a` and `/b` reflect `q` into HTML. `/pdf` answers with a content type the
/// scanner refuses, so it is dropped during preflight — the `error` outcome
/// that must be retried rather than skipped.
async fn spawn_app() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let reflect = {
        let hits = hits.clone();
        move |Query(params): Query<HashMap<String, String>>| {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                let q = params.get("q").cloned().unwrap_or_default();
                (
                    html_headers(),
                    format!("<html><body>echo {}</body></html>", q),
                )
            }
        }
    };
    let pdf = {
        let hits = hits.clone();
        move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                let mut headers = HeaderMap::new();
                headers.insert("content-type", HeaderValue::from_static("application/pdf"));
                (headers, "%PDF-1.4")
            }
        }
    };
    let app = Router::new()
        .route("/a", get(reflect.clone()))
        .route("/b", get(reflect))
        .route("/pdf", get(pdf));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), hits, handle)
}

/// A tiny HTTP server that answers preflight (`q=1`) and drops injection
/// requests while `drop_injections` is set. The closed sockets exercise real
/// transport failures, which the scanner counts toward `meta.incomplete`.
async fn spawn_drop_injections_app() -> (
    String,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let hits = Arc::new(AtomicUsize::new(0));
    let drop_injections = Arc::new(AtomicBool::new(true));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_hits = hits.clone();
    let server_drop = drop_injections.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let hits = server_hits.clone();
            let drop_injections = server_drop.clone();
            tokio::spawn(async move {
                let mut request = vec![0; 8192];
                let Ok(n) = socket.read(&mut request).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                hits.fetch_add(1, Ordering::Relaxed);
                let request = String::from_utf8_lossy(&request[..n]);
                let request_line = request.lines().next().unwrap_or_default();
                let is_preflight = request_line.contains("q=1 ");
                if !is_preflight && drop_injections.load(Ordering::Relaxed) {
                    return; // Drop the socket without a response.
                }

                let body = b"<html><body>static page</body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                if !request_line.starts_with("HEAD ") {
                    let _ = socket.write_all(body).await;
                }
            });
        }
    });
    (format!("http://{addr}"), hits, drop_injections, handle)
}

fn unique_temp_path(prefix: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    path.push(format!(
        "dalfox-{}-{}-{}.{}",
        prefix,
        std::process::id(),
        nanos,
        ext
    ));
    path
}

/// A scan trimmed to the reflection stage — enough to reach a terminal state
/// per target without spending the discovery/mining budget the resume logic
/// does not care about.
fn lean_args(targets: &[String], output: &Path, state: &Path) -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: Some(output.to_string_lossy().to_string()),
        state_file: Some(state.to_string_lossy().to_string()),
        silence: true,
        targets: targets.to_vec(),
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

fn outcomes(state: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(state)
        .expect("state file exists")
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("dalfox_state").is_none())
        .map(|v| {
            (
                v["target"].as_str().unwrap_or_default().to_string(),
                v["outcome"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

// The headline behavior: re-running the same scan sends nothing at all,
// because every target was recorded `completed`.
#[tokio::test]
async fn a_second_run_reissues_no_request_for_completed_targets() {
    let (base, hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-state", "jsonl");
    let targets = vec![format!("{}/a?q=1", base), format!("{}/b?q=1", base)];

    let out1 = unique_temp_path("resume-run1", "json");
    run_scan(&lean_args(&targets, &out1, &state)).await;
    let after_first = hits.load(Ordering::Relaxed);
    assert!(after_first > 0, "the first run has to actually scan");
    let recorded = outcomes(&state);
    assert_eq!(
        recorded.len(),
        2,
        "both targets reach a terminal state: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|(_, o)| o == "completed"),
        "an uninterrupted scan completes every target: {recorded:?}"
    );

    let out2 = unique_temp_path("resume-run2", "json");
    run_scan(&lean_args(&targets, &out2, &state)).await;
    server.abort();

    assert_eq!(
        hits.load(Ordering::Relaxed),
        after_first,
        "a resumed run must not re-request completed targets"
    );

    let meta = read_meta(&out2);
    assert_eq!(
        meta["resumed"]["targets_skipped_completed"], 2,
        "the report has to disclose the skip, or a short run reads as full coverage: {meta}"
    );
    // `meta.total_requests` is deliberately not asserted: it reads a
    // process-global counter that sibling tests in this binary share.

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}

// Only `completed` may be skipped. A target dropped in preflight was never
// tested, so it is recorded `error` and re-requested on the next run.
#[tokio::test]
async fn a_preflight_dropped_target_is_recorded_error_and_retried() {
    let (base, hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-error", "jsonl");
    let targets = vec![format!("{}/a?q=1", base), format!("{}/pdf?q=1", base)];

    let out1 = unique_temp_path("resume-error1", "json");
    run_scan(&lean_args(&targets, &out1, &state)).await;
    let recorded = outcomes(&state);
    assert!(
        recorded
            .iter()
            .any(|(t, o)| t.contains("/pdf") && o == "error"),
        "the skipped target must be accounted for, not silently missing: {recorded:?}"
    );
    let after_first = hits.load(Ordering::Relaxed);

    let out2 = unique_temp_path("resume-error2", "json");
    run_scan(&lean_args(&targets, &out2, &state)).await;
    server.abort();

    assert!(
        hits.load(Ordering::Relaxed) > after_first,
        "an `error` target has unknown coverage and must be attempted again"
    );
    let meta = read_meta(&out2);
    assert_eq!(
        meta["resumed"]["targets_skipped_completed"], 1,
        "only the completed target is skipped: {meta}"
    );

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}

// A run under different scan-affecting settings cannot reuse the file: those
// targets were never tested this way. The file resets and everything is
// scanned again.
#[tokio::test]
async fn changing_a_scan_affecting_flag_rescans_everything() {
    let (base, hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-rehash", "jsonl");
    let targets = vec![format!("{}/a?q=1", base)];

    let out1 = unique_temp_path("resume-rehash1", "json");
    run_scan(&lean_args(&targets, &out1, &state)).await;
    let after_first = hits.load(Ordering::Relaxed);

    let out2 = unique_temp_path("resume-rehash2", "json");
    let mut changed = lean_args(&targets, &out2, &state);
    changed.encoders = vec!["base64".to_string()];
    run_scan(&changed).await;
    server.abort();

    assert!(
        hits.load(Ordering::Relaxed) > after_first,
        "a changed payload configuration must not reuse prior completions"
    );
    let meta = read_meta(&out2);
    assert_eq!(
        meta["resumed"]["targets_skipped_completed"], 0,
        "nothing may be skipped after a reset: {meta}"
    );

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}

// Raw HTTP and HAR targets carry request data inside the input file rather
// than ScanArgs. Rewriting a capture can change which body parameters Dalfox
// tests while leaving its URL, method, input path, and config hash unchanged.
#[tokio::test]
async fn changing_a_raw_http_body_does_not_reuse_the_old_completion() {
    let hits = Arc::new(AtomicUsize::new(0));
    let route_hits = hits.clone();
    let app = Router::new().route(
        "/submit",
        any(move |request: axum::extract::Request| {
            let hits = route_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                    .await
                    .expect("read request body");
                (
                    [("content-type", "text/html; charset=utf-8")],
                    format!(
                        "<html><body>{}</body></html>",
                        String::from_utf8_lossy(&body)
                    ),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let state = unique_temp_path("resume-raw-http-body", "jsonl");
    let capture = unique_temp_path("resume-raw-http-input", "http");
    let output1 = unique_temp_path("resume-raw-http-run1", "json");
    let output2 = unique_temp_path("resume-raw-http-run2", "json");
    let capture_for = |name: &str| {
        format!(
            "POST http://{addr}/submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{name}=1"
        )
    };
    std::fs::write(&capture, capture_for("old")).expect("write first request capture");

    let args = ScanArgs {
        input_type: "raw-http".to_string(),
        format: "json".to_string(),
        output: Some(output1.to_string_lossy().to_string()),
        state_file: Some(state.to_string_lossy().to_string()),
        targets: vec![capture.to_string_lossy().to_string()],
        skip_discovery: true,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        skip_waf_probe: true,
        skip_ast_analysis: true,
        max_payloads_per_param: 1,
        insecure: Some(true),
        silence: true,
        ..ScanArgs::default()
    };
    let _ = run_scan(&args).await;
    let after_first = hits.load(Ordering::Relaxed);
    assert!(
        after_first > 0,
        "the first capture must reach the local app"
    );
    let header_before: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&state)
            .expect("state file written")
            .lines()
            .next()
            .expect("state header"),
    )
    .expect("state header JSON");

    std::fs::write(&capture, capture_for("new")).expect("rewrite request capture");
    let changed_args = ScanArgs {
        output: Some(output2.to_string_lossy().to_string()),
        ..args
    };
    let _ = run_scan(&changed_args).await;
    server.abort();

    let meta = read_meta(&output2);
    let header_after: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&state)
            .expect("state file remains readable")
            .lines()
            .next()
            .expect("state header"),
    )
    .expect("state header JSON");
    assert_eq!(header_after["config_hash"], header_before["config_hash"]);
    assert_eq!(
        meta["resumed"]["targets_skipped_completed"], 0,
        "a changed body parameter must reach the scanner again: {meta}"
    );
    assert!(
        hits.load(Ordering::Relaxed) > after_first,
        "the changed request must be sent to the app rather than skipped"
    );

    let _ = std::fs::remove_file(state);
    let _ = std::fs::remove_file(capture);
    let _ = std::fs::remove_file(output1);
    let _ = std::fs::remove_file(output2);
}

#[tokio::test]
async fn transport_incomplete_targets_are_retried_on_resume() {
    let (base, hits, drop_injections, server) = spawn_drop_injections_app().await;
    let target = format!("{base}/?q=1");
    let out = unique_temp_path("incomplete-resume", "json");
    let state = unique_temp_path("incomplete-resume", "jsonl");
    let mut args = lean_args(std::slice::from_ref(&target), &out, &state);
    args.param = vec!["q".to_string()];
    args.skip_discovery = true;
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_reflection_header = true;
    args.skip_reflection_cookie = true;
    args.skip_reflection_path = true;
    args.skip_waf_probe = true;
    args.skip_ast_analysis = true;
    args.timeout = 2;
    args.max_payloads_per_param = 10;

    let first = run_scan(&args).await;
    let first_report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("first report"))
            .expect("valid JSON");
    assert_eq!(
        first_report["meta"]["incomplete"],
        true,
        "expected injection requests to fail; hit count {}, report {}",
        hits.load(Ordering::Relaxed),
        first_report
    );
    assert!(first_report["meta"]["failed_requests"].as_u64().unwrap() >= 3);
    assert_eq!(first, ScanOutcome::Error);

    let before_resume = hits.load(Ordering::Relaxed);
    drop_injections.store(false, Ordering::Relaxed);
    let second = run_scan(&args).await;
    let second_report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("second report"))
            .expect("valid JSON");
    assert_eq!(
        second_report["meta"]["resumed"]["targets_skipped_completed"], 0,
        "transport-incomplete coverage must not be written as a reusable completion"
    );
    assert!(
        hits.load(Ordering::Relaxed) > before_resume,
        "resume must issue requests for the incomplete target"
    );
    assert_eq!(second, ScanOutcome::Clean);

    server.abort();
    let _ = std::fs::remove_file(out);
    let _ = std::fs::remove_file(state);
}

// `--dry-run` prices out a *different* flag set against the same state file —
// the hash will not match. It must not cost the operator the campaign: the
// preview reads the file and leaves it exactly as it found it.
#[tokio::test]
async fn a_dry_run_never_writes_or_resets_the_state_file() {
    let (base, _hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-dryrun", "jsonl");
    let targets = vec![format!("{}/a?q=1", base)];

    let out1 = unique_temp_path("resume-dryrun1", "json");
    run_scan(&lean_args(&targets, &out1, &state)).await;
    let before = std::fs::read_to_string(&state).expect("state written by the real run");

    let out2 = unique_temp_path("resume-dryrun2", "json");
    let mut preview = lean_args(&targets, &out2, &state);
    preview.dry_run = true;
    preview.deep_scan = true; // a different configuration ⇒ hash mismatch
    run_scan(&preview).await;
    server.abort();

    assert_eq!(
        std::fs::read_to_string(&state).expect("state still there"),
        before,
        "a preview must leave the state file byte-identical"
    );
    assert!(
        !PathBuf::from(format!("{}.bak", state.display())).exists(),
        "a preview must not set the file aside either"
    );

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}

// A fresh path must not be created by a preview either — `--dry-run` with a
// state file that does not exist yet should stay a no-op on disk.
#[tokio::test]
async fn a_dry_run_does_not_create_a_missing_state_file() {
    let (base, _hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-dryrun-new", "jsonl");
    let out = unique_temp_path("resume-dryrun-new-out", "json");

    let mut preview = lean_args(&[format!("{}/a?q=1", base)], &out, &state);
    preview.dry_run = true;
    run_scan(&preview).await;
    server.abort();

    assert!(!state.exists(), "a preview creates nothing on disk");

    let _ = std::fs::remove_file(&out);
}

// An unusable `--state-file` fails the run *before* any traffic goes out.
// Discovering after a two-hour scan that nothing was recorded is the failure
// this feature exists to prevent, so it cannot be a warning.
#[tokio::test]
async fn an_unusable_state_file_path_fails_before_any_request() {
    let (base, hits, server) = spawn_app().await;
    // A directory can never be opened as a state file.
    let mut dir = std::env::temp_dir();
    dir.push(format!("dalfox-state-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");

    let out = unique_temp_path("resume-unusable", "json");
    let args = lean_args(&[format!("{}/a?q=1", base)], &out, &dir);
    let outcome = run_scan(&args).await;
    server.abort();

    assert_eq!(
        outcome,
        ScanOutcome::Error,
        "an unusable state file must fail the run, not degrade it silently"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "the failure has to land before the first request, not after the scan"
    );

    let _ = std::fs::remove_dir(&dir);
    let _ = std::fs::remove_file(&out);
}

// `--only-discovery` applies the resume filter, so its envelope has to disclose
// the skip the same way the scan and dry-run envelopes do — otherwise a
// consumer cannot tell a resumed partial enumeration from a complete one.
#[tokio::test]
async fn only_discovery_discloses_the_resume_skip() {
    let (base, _hits, server) = spawn_app().await;
    let state = unique_temp_path("resume-discovery", "jsonl");
    let targets = vec![format!("{}/a?q=1", base), format!("{}/b?q=1", base)];

    let out = unique_temp_path("resume-discovery-out", "json");
    run_scan(&lean_args(&targets, &out, &state)).await;

    // Second run enumerates only what is left, and says so on stdout.
    let out2 = unique_temp_path("resume-discovery-out2", "json");
    let mut discovery = lean_args(&targets, &out2, &state);
    discovery.only_discovery = true;
    discovery.skip_discovery = false;
    discovery.output = None; // only-discovery renders to stdout
    let outcome = run_scan(&discovery).await;
    server.abort();

    assert_eq!(outcome, ScanOutcome::Clean);
    // The state file must be untouched by the preview: two records, no more.
    let records = outcomes(&state);
    assert_eq!(
        records.len(),
        2,
        "an only-discovery run records nothing: {records:?}"
    );

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&out2);
}

// Without the flag nothing changes: no file is written, and the second run
// scans exactly as the first did.
#[tokio::test]
async fn without_the_flag_nothing_is_recorded_or_skipped() {
    let (base, hits, server) = spawn_app().await;
    let targets = vec![format!("{}/a?q=1", base)];
    let state = unique_temp_path("resume-absent", "jsonl");

    let out1 = unique_temp_path("resume-absent1", "json");
    let mut args = lean_args(&targets, &out1, &state);
    args.state_file = None;
    run_scan(&args).await;
    let after_first = hits.load(Ordering::Relaxed);

    let out2 = unique_temp_path("resume-absent2", "json");
    let mut args2 = lean_args(&targets, &out2, &state);
    args2.state_file = None;
    run_scan(&args2).await;
    server.abort();

    assert!(
        hits.load(Ordering::Relaxed) > after_first,
        "opt-in means the default path is untouched"
    );
    assert!(!state.exists(), "no state file may be created implicitly");
    assert!(
        read_meta(&out2).get("resumed").is_none(),
        "the resume block is absent when the feature is off"
    );

    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}
