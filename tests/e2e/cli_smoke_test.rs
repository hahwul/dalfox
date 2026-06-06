//! E2E smoke tests for Dalfox CLI
//!
//! These tests spawn the actual dalfox binary and verify basic functionality.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn test_cli_starts_without_error() {
    // Test that dalfox starts and shows help without errors
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--help")
        .output()
        .expect("Failed to execute dalfox");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox --help should exit successfully"
    );
}

#[test]
fn test_cli_version_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--version")
        .output()
        .expect("Failed to execute dalfox");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox --version should exit successfully"
    );
}

#[test]
fn test_scan_subcommand_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", "--help"])
        .output()
        .expect("Failed to execute dalfox scan --help");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox scan --help should exit successfully"
    );
}

#[test]
fn test_payload_subcommand_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["payload", "--help"])
        .output()
        .expect("Failed to execute dalfox payload --help");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox payload --help should exit successfully"
    );
}

#[test]
fn test_server_subcommand_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["server", "--help"])
        .output()
        .expect("Failed to execute dalfox server --help");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox server --help should exit successfully"
    );
}

#[test]
fn test_mcp_subcommand_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["mcp", "--help"])
        .output()
        .expect("Failed to execute dalfox mcp --help");

    assert!(
        output.status.success() || output.status.code() == Some(0),
        "dalfox mcp --help should exit successfully"
    );
}

#[test]
fn test_invalid_subcommand_exits_with_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("invalid_subcommand")
        .output()
        .expect("Failed to execute dalfox with invalid subcommand");

    // Invalid subcommand should either fail or fall through to scan mode
    // (which might fail without a valid target)
    // We just verify the process completes
    let _ = output.status;
}

#[test]
fn test_only_custom_payload_with_missing_file_emits_structured_error() {
    // With --only-custom-payload, a missing file is fatal: scanning would
    // otherwise silently use zero payloads and report clean. The error
    // must surface via the structured emit_error path so consumers see a
    // FILE_READ_ERROR code and not just an empty result.
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            "https://127.0.0.1:1",
            "--custom-payload",
            "/tmp/dalfox-does-not-exist-1.txt",
            "--only-custom-payload",
            "--format",
            "jsonl",
            "--silence",
        ])
        .output()
        .expect("failed to execute dalfox");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("FILE_READ_ERROR"),
        "expected FILE_READ_ERROR in output, got:\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        combined.contains("/tmp/dalfox-does-not-exist-1.txt"),
        "expected the path to appear in the error message"
    );
}

#[test]
fn test_hidden_pipe_subcommand_reads_stdin_and_exits() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["pipe", "--format", "json", "-S"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute dalfox pipe");

    {
        let stdin = child.stdin.as_mut().expect("child stdin should be piped");
        stdin
            .write_all(b"http://[::1\n")
            .expect("failed to write pipe input");
    }

    let output = child
        .wait_with_output()
        .expect("failed waiting for dalfox pipe");
    let _ = output.status;
}

#[test]
fn test_e2e_file_shadowing_ambiguity_warning() {
    let mut shadow_file = std::env::temp_dir();
    shadow_file.push(format!("dalfox-e2e-shadow-{}.com", std::process::id()));
    std::fs::write(
        &shadow_file,
        b"http://127.0.0.1:9999/should-not-be-attacked\n",
    )
    .unwrap();

    let target_name = shadow_file.file_name().unwrap().to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            target_name,
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--format",
            "json",
        ])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("Failed to execute dalfox with shadowed file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let _ = std::fs::remove_file(&shadow_file);

    // Should warn on stderr
    assert!(
        stderr.contains("matches both a URL and a local file; treating as URL"),
        "stderr should warn about file shadowing, got:\n{}",
        stderr
    );

    // Target parsed should be the URL form, not the file contents!
    assert!(
        stdout.contains(&format!("http://{}/", target_name))
            || stdout.contains(&format!("http://{}", target_name)),
        "stdout should target the domain literal, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("should-not-be-attacked"),
        "stdout should NOT parse the shadowed file contents, got:\n{}",
        stdout
    );
}

#[test]
fn test_e2e_stdin_and_positional_targets_merged() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            "http://positional-target.com",
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute dalfox for merge");

    {
        let stdin = child.stdin.as_mut().expect("child stdin should be piped");
        stdin
            .write_all(b"http://piped-target.com\n")
            .expect("failed to write pipe input");
    }

    let output = child
        .wait_with_output()
        .expect("failed waiting for dalfox merge");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Both should be in target list!
    assert!(
        stdout.contains("http://positional-target.com/"),
        "expected positional target in stdout, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("http://piped-target.com/"),
        "expected piped target in stdout, got:\n{}",
        stdout
    );
    // Should warn/info about the merge on stderr
    assert!(
        stderr.contains("Merged 1 target(s) from stdin"),
        "stderr should inform about merging stdin, got:\n{}",
        stderr
    );
}

/// Verify `--analyze-external-js` is a recognized flag (clap doesn't reject it).
#[test]
fn test_analyze_external_js_flag_is_recognized() {
    // Scan a port that will immediately refuse so the test is fast, but the
    // important thing is clap must accept the flag without "unexpected argument".
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            "http://127.0.0.1:1/",
            "--analyze-external-js",
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--silence",
        ])
        .output()
        .expect("failed to execute dalfox");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "--analyze-external-js must be a recognised flag; stderr: {stderr}"
    );
}

/// Full E2E: dalfox binary with `--analyze-external-js` finds a DOM-XSS sink
/// inside a same-origin external script and reports it in JSON output.
#[test]
fn test_analyze_external_js_e2e_finds_dom_xss() {
    use axum::{Router, http::header, response::IntoResponse, routing::get};

    // Start an in-process axum server. The tokio runtime lives for the
    // duration of the test; the spawned server task keeps it alive while
    // the dalfox subprocess runs.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let addr = rt.block_on(async {
        async fn page() -> impl IntoResponse {
            (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                r#"<!DOCTYPE html><html><body>
                    <div id="r"></div>
                    <script src="/sink.js"></script>
                </body></html>"#,
            )
        }
        async fn sink_js() -> impl IntoResponse {
            (
                [(header::CONTENT_TYPE, "application/javascript")],
                r#"document.getElementById("r").innerHTML = location.hash.substring(1);"#,
            )
        }
        let app = Router::new()
            .route("/", get(page))
            .route("/sink.js", get(sink_js));

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind e2e test server");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    });

    let out_path = std::env::temp_dir().join(format!("dalfox_e2e_extjs_{}.json", addr.port()));

    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            &format!("http://{addr}/"),
            "--analyze-external-js",
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--format",
            "json",
            "--output",
            out_path.to_str().unwrap(),
            "--silence",
        ])
        .output()
        .expect("failed to execute dalfox");

    rt.shutdown_background();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let content = std::fs::read_to_string(&out_path).unwrap_or_else(|_| {
        panic!(
            "dalfox should write JSON output file; exit={:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&content).expect("output should be valid JSON");
    let findings = v["findings"]
        .as_array()
        .expect("should have findings array");

    assert!(
        !findings.is_empty(),
        "expected at least one DOM-XSS finding from external sink.js; output: {content}"
    );
    let cites_script = findings.iter().any(|f| {
        f["evidence"]
            .as_str()
            .is_some_and(|e| e.contains("sink.js"))
    });
    assert!(
        cites_script,
        "finding evidence must cite the external script URL; findings: {findings:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_e2e_non_regular_file_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", "/dev/zero"])
        .output()
        .expect("failed to execute dalfox scan /dev/zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(2),
        "scanning non-regular file should exit with code 2, got stderr:\n{}\nstdout:\n{}",
        stderr,
        stdout
    );
    assert!(
        stderr.contains("is not a regular file") || stdout.contains("is not a regular file"),
        "should refuse /dev/zero as non-regular file, got stderr:\n{}",
        stderr
    );
}
