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
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, run_scan};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
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
