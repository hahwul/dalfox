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
fn test_no_color_disables_forced_clap_colors() {
    for (args, expected_exit) in [
        (&["--help"][..], 0),
        (&["scan", "--help"][..], 0),
        (&["--invalid-argument"][..], 2),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .env_remove("NO_COLOR")
            .env("CLICOLOR_FORCE", "1")
            .env("TERM", "xterm-256color")
            .arg("--no-color")
            .args(args)
            .output()
            .expect("run dalfox with --no-color");

        assert_eq!(output.status.code(), Some(expected_exit), "{args:?}");
        assert!(!output.stdout.contains(&0x1b), "{args:?}");
        assert!(!output.stderr.contains(&0x1b), "{args:?}");
    }
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
fn test_payload_exits_cleanly_when_stdout_pipe_closes() {
    let config = tempfile::NamedTempFile::new().unwrap();
    for args in [&[][..], &["--json"], &["all"], &["useful-tags"]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("--config")
            .arg(config.path())
            .arg("payload")
            .args(args)
            .stdout(writer)
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_payload_reports_stdout_write_errors() {
    let config = tempfile::NamedTempFile::new().unwrap();
    for args in [&[][..], &["--json"], &["all"], &["useful-tags"]] {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("--config")
            .arg(config.path())
            .arg("payload")
            .args(args)
            .stdout(full)
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("failed to write output"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    }
}

#[test]
fn test_payload_escapes_control_characters_in_unknown_selector() {
    let config = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--config")
        .arg(config.path())
        .args(["payload", "invalid\nselector\u{1b}"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("Unknown selector: invalid\\nselector\\x1b\n"));
    assert_eq!(stderr.lines().count(), 2);
}

#[test]
fn test_payload_reports_unknown_selector_status_with_closed_stderr() {
    let config = tempfile::NamedTempFile::new().unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let status = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--config")
        .arg(config.path())
        .args(["payload", "invalid-selector"])
        .stderr(writer)
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(2));
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
fn test_silence_still_reports_fatal_input_errors() {
    // `-S` silences scan logs, not the reason the run failed: an unreadable
    // target list used to exit 2 with nothing on either stream.
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            "-i",
            "file",
            "/tmp/dalfox-does-not-exist-2.txt",
            "--format",
            "json",
            "-S",
        ])
        .output()
        .expect("failed to execute dalfox");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FILE_READ_ERROR"), "stderr: {stderr}");
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
fn test_pipe_input_lists_its_targets_in_meta() {
    // `meta.targets` echoed only the positional args, so a piped list — the
    // whole input — reported `"targets": []`. It names the source (`-`, stdin),
    // like a list file is named by its path, not by its expanded URLs.
    let mut child = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["pipe", "--format", "json", "-S"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute dalfox pipe");
    child
        .stdin
        .take()
        .expect("child stdin should be piped")
        .write_all(b"http://127.0.0.1:1/?q=1\n")
        .expect("failed to write pipe input");
    let output = child
        .wait_with_output()
        .expect("failed waiting for dalfox pipe");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(json["meta"]["targets"], serde_json::json!(["-"]));
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

/// Run `dalfox` with an idle (open but silent) pipe on stdin, holding the write
/// end for the whole run. Returns `(exited_in_time, stdout, stderr)`.
///
/// stdout/stderr are drained on their own threads: the child must never stall
/// on a full pipe buffer, or a hang here would mean "we didn't read" rather
/// than "dalfox blocked".
fn run_with_idle_stdin_pipe(
    args: &[&str],
    env: &[(&str, &str)],
    write_after: Option<(std::time::Duration, &'static str)>,
    limit: std::time::Duration,
) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dalfox"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("failed to execute dalfox");

    let mut stdin = child.stdin.take().expect("child stdin should be piped");
    let mut stdout_pipe = child.stdout.take().expect("child stdout should be piped");
    let mut stderr_pipe = child.stderr.take().expect("child stderr should be piped");
    let out_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout_pipe, &mut s);
        s
    });
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr_pipe, &mut s);
        s
    });
    // With no payload the write end is held open and silent for the whole run
    // (the #1239 shape); with one, it sends late and then closes so the child
    // reaches EOF.
    let mut held_stdin = None;
    let writer = if let Some((delay, payload)) = write_after {
        Some(std::thread::spawn(move || {
            std::thread::sleep(delay);
            let _ = stdin.write_all(payload.as_bytes());
            drop(stdin);
        }))
    } else {
        held_stdin = Some(stdin);
        None
    };

    let deadline = std::time::Instant::now() + limit;
    let exited = loop {
        match child.try_wait().expect("failed polling dalfox") {
            Some(_) => break true,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    drop(held_stdin);
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    if let Some(w) = writer {
        let _ = w.join();
    }
    (exited, stdout, stderr)
}

/// Regression test for #1239: an explicit target on the command line must be
/// scanned even when a parent process leaves an open, idle pipe on stdin
/// (`sleep 60 | dalfox scan <URL>` — the shape CI harnesses and job runners
/// produce). Before the fix, dalfox blocked in `read()` on fd 0 forever.
#[test]
fn test_e2e_idle_stdin_pipe_does_not_block_explicit_target() {
    let (exited, stdout, stderr) = run_with_idle_stdin_pipe(
        &[
            "scan",
            "http://127.0.0.1:1/?q=test",
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--format",
            "json",
        ],
        &[],
        None,
        std::time::Duration::from_secs(30),
    );

    assert!(
        exited,
        "dalfox blocked on an idle stdin pipe despite an explicit target (#1239)\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("http://127.0.0.1:1/?q=test"),
        "the command-line target should still be scanned, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("stdin is an open pipe but sent no data"),
        "skipping an idle stdin should be announced, got stderr:\n{stderr}"
    );
}

/// The grace window is an estimate, so `DALFOX_STDIN_WAIT_MS` has to be able to
/// stretch it for a producer that takes seconds to emit its first URL.
#[test]
fn test_e2e_stdin_wait_env_extends_the_merge_window() {
    let (exited, stdout, stderr) = run_with_idle_stdin_pipe(
        &[
            "scan",
            "http://127.0.0.1:1/?cli=1",
            "--skip-xss-scanning",
            "--skip-discovery",
            "--skip-mining",
            "--format",
            "json",
        ],
        &[("DALFOX_STDIN_WAIT_MS", "20000")],
        Some((
            std::time::Duration::from_millis(1500),
            "http://127.0.0.1:1/?piped=1\n",
        )),
        std::time::Duration::from_secs(60),
    );

    assert!(
        exited,
        "dalfox should finish once the slow producer sends its target\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("Merged 1 target(s) from stdin"),
        "a target that arrives inside the widened window must still merge, got stderr:\n{stderr}"
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

#[test]
fn test_alibaba_block_page_report_in_plain_output() {
    use axum::{Router, http::StatusCode, routing::get};

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let address = runtime.block_on(async {
        let app = Router::new().route(
            "/",
            get(|| async {
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    [("content-type", "text/html")],
                    r#"<p>Sorry, your request has been blocked as it may cause potential threats to the server's security.</p>
                    <img src="https://errors.aliyun.com/images/block.png">"#,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve test page") });
        address
    });
    let config_dir = tempfile::tempdir().expect("config directory");
    let config = config_dir.path().join("config.toml");
    std::fs::write(&config, "[scan]\n").expect("write test config");

    for (threshold, expected) in [("0.3", true), ("0.9", false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("--config")
            .arg(&config)
            .args([
                "--no-color",
                "scan",
                &format!("http://{address}/"),
                "--format",
                "plain",
                "--waf-bypass",
                "off",
                "--skip-xss-scanning",
                "--skip-ast-analysis",
                "--skip-discovery",
                "--skip-mining",
                "--waf-min-confidence",
                threshold,
            ])
            .output()
            .expect("run dalfox");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            stdout.contains("AlibabaCloud detected (confidence: 85%, evidence: Alibaba Cloud WAF default HTTP 405 block page)"),
            expected,
            "confidence floor {threshold}: {stdout}"
        );
    }
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

#[test]
fn test_e2e_invalid_scope_regex_is_fatal() {
    // A glob typed as a regex used to be dropped with a warning, so the
    // excluded URL was scanned anyway.
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "scan",
            "--dry-run",
            "--format",
            "json",
            "--exclude-url",
            "*/admin*",
            "http://127.0.0.1:1/admin?q=1",
        ])
        .output()
        .expect("failed to execute dalfox scan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(
        stderr.contains("PARSE_ERROR") && stderr.contains("--exclude-url"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn test_e2e_preview_modes_refuse_formats_they_cannot_render() {
    // The dry-run / only-discovery reports exist only as plain text and JSON;
    // `-f sarif|toml` used to print the plain summary on stdout, which no
    // SARIF/TOML consumer can parse.
    for mode in ["--dry-run", "--only-discovery"] {
        for fmt in ["sarif", "toml"] {
            let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
                .args(["scan", mode, "-f", fmt, "http://127.0.0.1:1/?q=1"])
                .output()
                .expect("failed to execute dalfox scan");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{mode} {fmt}:\n{stderr}");
            assert!(output.stdout.is_empty(), "{mode} {fmt} wrote stdout");
            assert!(stderr.contains(mode), "{mode} {fmt}:\n{stderr}");
        }
        // Markdown is for a human reader: it keeps the plain report.
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["scan", mode, "-f", "markdown", "http://127.0.0.1:1/?q=1"])
            .output()
            .expect("failed to execute dalfox scan");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("does not support --format"),
            "{mode} markdown:\n{stderr}"
        );
    }
}

/// Every shell `dalfox completion` accepts (i.e. every `clap_complete::Shell`).
const COMPLETION_SHELLS: [&str; 5] = ["bash", "zsh", "fish", "powershell", "elvish"];

/// How each shell's generator declares one subcommand, with `{}` standing in
/// for its name. Asserting a *visible* subcommand matches keeps these patterns
/// honest: if a `clap_complete` upgrade changes the emitted shape, the
/// visible-subcommand half fails instead of the hidden-subcommand half quietly
/// passing against a pattern that can no longer match anything.
const SUBCOMMAND_DECLARATION: [(&str, &str); 5] = [
    ("bash", "dalfox,{})"),
    // zsh indents the first `case` arm and no others, so the pattern anchors on
    // the trailing newline only.
    ("zsh", "({})\n"),
    ("fish", "__fish_dalfox_using_subcommand {}"),
    ("powershell", "'dalfox;{}'"),
    ("elvish", "&'dalfox;{}'="),
];

fn completion_script(shell: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["completion", shell])
        .output()
        .unwrap_or_else(|e| panic!("failed to execute dalfox completion {shell}: {e}"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "dalfox completion {shell} should exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "dalfox completion {shell} should write nothing to stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("dalfox completion {shell} emitted non-UTF-8: {e}"))
}

/// The subcommand returns before the banner/config machinery runs, so the
/// script is the *only* thing on stdout. Users redirect this straight into
/// `/etc/bash_completion.d/dalfox`, so a stray banner line is a broken shell,
/// not cosmetic noise.
#[test]
fn test_completion_writes_only_the_script_to_stdout() {
    for shell in COMPLETION_SHELLS {
        let script = completion_script(shell);

        assert!(
            script.contains("only-poc"),
            "dalfox completion {shell} should carry the scan subtree's flags"
        );
        assert!(
            script.contains("completion"),
            "dalfox completion {shell} should carry the completion subcommand itself"
        );
        // `█` is unique to the ASCII-art banner, which must never reach stdout
        // on this path.
        assert!(
            !script.contains('█'),
            "dalfox completion {shell} leaked the banner into the script"
        );
    }
}

/// `clap_complete`'s generators walk `Command::get_subcommands()` without
/// filtering `hide = true` entries — unlike `clap_mangen`, which drops them —
/// so the completion scripts are the one surface where the deprecated compat
/// commands (`url` / `file` / `pipe`) and the packaging helper (`man`) can be
/// advertised to users. `completion_command()` in `src/main.rs` filters them.
#[test]
fn test_completion_omits_hidden_subcommands() {
    for (shell, declaration) in SUBCOMMAND_DECLARATION {
        let script = completion_script(shell);

        for visible in ["scan", "server", "payload", "mcp", "completion"] {
            assert!(
                script.contains(&declaration.replace("{}", visible)),
                "dalfox completion {shell} should declare the `{visible}` subcommand"
            );
        }

        for hidden in ["man", "url", "file", "pipe"] {
            assert!(
                !script.contains(&declaration.replace("{}", hidden)),
                "dalfox completion {shell} advertises the hidden `{hidden}` subcommand"
            );
        }
    }
}

/// `dalfox man` shares the completion path's stdout contract: one generated
/// artifact and nothing else. Every packaging surface pipes it straight into
/// `dalfox.1`, so a banner line here ships a corrupt man page — and unlike the
/// completion scripts, it also has to stay *pure roff*.
#[test]
fn test_man_writes_only_roff_to_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("man")
        .output()
        .expect("failed to execute dalfox man");

    assert_eq!(
        output.status.code(),
        Some(0),
        "dalfox man should exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "dalfox man should write nothing to stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let page = String::from_utf8(output.stdout).expect("dalfox man emitted non-UTF-8");

    // roff from the first byte: a leading banner would push the `.ie` escape
    // off line 1 and troff would render it as text.
    assert!(
        page.starts_with(".ie "),
        "dalfox man should open with roff, got: {:?}",
        page.chars().take(40).collect::<String>()
    );
    assert!(
        page.contains(".TH dalfox 1"),
        "dalfox man should carry the title header"
    );
    // The hidden subcommands stay out of the man page too — `clap_mangen`
    // filters them on its own, unlike `clap_complete`; see
    // `completion_command()` in `src/main.rs`. As in
    // `test_completion_omits_hidden_subcommands`, asserting the visible half
    // against the same `dalfox\-<name>(1)` shape keeps the pattern honest.
    for visible in ["scan", "server", "payload", "mcp", "completion"] {
        assert!(
            page.contains(&format!("dalfox\\-{visible}(1)")),
            "dalfox man should document the `{visible}` subcommand"
        );
    }
    for hidden in ["man", "url", "file", "pipe"] {
        assert!(
            !page.contains(&format!("dalfox\\-{hidden}(1)")),
            "dalfox man should not document the hidden `{hidden}` subcommand"
        );
    }
}

/// `█` is unique to the ASCII-art banner; its absence is how these tests assert
/// stdout stayed a clean machine-readable document.
const BANNER_GLYPH: char = '█';

/// A target that is rejected without any network round trip, so the machine
/// document is produced instantly and deterministically.
const UNREACHABLE_TARGET: &str = "http://127.0.0.1:1/?q=1";

/// Flags that keep a run to target resolution + one reachability probe.
const NO_SCAN_FLAGS: [&str; 3] = ["--skip-xss-scanning", "--skip-discovery", "--skip-mining"];

#[test]
fn test_scan_jsonl_stdout_has_no_empty_records() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", UNREACHABLE_TARGET])
        .args(NO_SCAN_FLAGS)
        .args(["--format", "jsonl", "-S"])
        .stdin(Stdio::null())
        .output()
        .expect("run dalfox");
    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 scan output");
    let record = stdout.strip_suffix('\n').expect("newline-terminated JSONL");
    assert!(!record.contains('\n'), "expected one record: {stdout:?}");
    let report: serde_json::Value = serde_json::from_str(record).expect("JSONL metadata record");
    assert_eq!(report["meta"]["findings_count"], 0);
}

#[test]
fn test_report_file_confirmation_uses_stderr() {
    let dir =
        std::env::temp_dir().join(format!("dalfox-output-confirmation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create output directory");
    let (filename, displayed_filename) = if cfg!(unix) {
        ("report\nname.json", r"report\nname.json")
    } else {
        ("report.json", "report.json")
    };
    let path = dir.join(filename);
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", UNREACHABLE_TARGET])
        .args(NO_SCAN_FLAGS)
        .args(["--dry-run", "--format", "json", "--output"])
        .arg(&path)
        .stdin(Stdio::null())
        .output()
        .expect("run dalfox");
    let report = std::fs::read(&path);
    std::fs::remove_dir_all(dir).expect("remove output directory");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.stdout.is_empty(),
        "machine stdout should be empty: {output:?}"
    );
    let confirmation = stderr
        .lines()
        .find(|line| line.starts_with("Results written to "))
        .expect("report confirmation on stderr");
    assert!(
        confirmation.ends_with(displayed_filename),
        "stderr: {stderr}"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&report.expect("read report file")).expect("JSON report on disk");
    assert_eq!(report["dry_run"], true);
}

#[test]
fn test_report_cannot_overwrite_resume_state() {
    let dir = std::env::temp_dir().join(format!("dalfox-state-aliases-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("subdir")).expect("create fixture directory");
    std::fs::write(dir.join("config.toml"), "[scan]\n").expect("write isolated config");
    let state = dir.join("state.jsonl");
    let journal = "{\"dalfox_state\":2,\"version\":\"3.3.0\",\"config_hash\":\"fixture\",\"created\":\"fixture\"}\n";
    std::fs::write(&state, journal).expect("write resume file");
    std::fs::hard_link(&state, dir.join("hardlink.jsonl")).expect("create hard link");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("state.jsonl", dir.join("symlink.jsonl")).expect("create existing symlink");
        symlink("new.jsonl", dir.join("dangling.jsonl")).expect("create dangling symlink");
    }

    let run_with_paths = |state_name: &str, output_name: &str, mode: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .current_dir(&dir)
            .args(["--config", "config.toml"])
            .args(["scan", UNREACHABLE_TARGET])
            .args(NO_SCAN_FLAGS)
            .args(mode)
            .args(["--state-file", state_name, "--output", output_name])
            .args(["--format", "json", "-S"])
            .stdin(Stdio::null())
            .output()
            .expect("run dalfox");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stderr)
            .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&output.stderr)))
    };

    let assert_conflict = |state_name: &str, output_name: &str, mode: &[&str]| {
        let error = run_with_paths(state_name, output_name, mode);
        assert_eq!(error["code"], "INVALID_INPUT_TYPE");
        assert_eq!(
            error["message"],
            "--output and --state-file must use separate files"
        );
    };

    assert_conflict("state.jsonl", "state.jsonl", &["--dry-run"]);
    assert_conflict(
        "state.jsonl",
        "subdir/../state.jsonl",
        &["--only-discovery"],
    );
    assert_conflict("state.jsonl", "hardlink.jsonl", &["--dry-run"]);
    assert_conflict("new.jsonl", "subdir/../new.jsonl", &[]);
    #[cfg(unix)]
    {
        assert_conflict("state.jsonl", "symlink.jsonl", &["--dry-run"]);
        assert_conflict("new.jsonl", "dangling.jsonl", &["--only-discovery"]);
    }

    // The fixture hash requires a reset. A report targeting the planned
    // backup must fail before the existing journal is moved.
    let backup_error = run_with_paths("state.jsonl", "subdir/../state.jsonl.bak", &[]);
    assert_eq!(backup_error["code"], "FILE_READ_ERROR");
    assert_eq!(
        backup_error["message"],
        "--output must use a different file from the --state-file backup"
    );
    assert!(!dir.join("state.jsonl.bak").exists());

    assert_eq!(std::fs::read_to_string(&state).unwrap(), journal);
    assert!(!dir.join("new.jsonl").exists());

    // Filesystems that ignore case can reveal this alias only after the
    // backup is moved into place. The previous journal must still be intact.
    if dir.join("STATE.JSONL").is_file() {
        let error = run_with_paths("state.jsonl", "STATE.JSONL.BAK", &[]);
        assert_eq!(error["code"], "FILE_READ_ERROR");
        assert!(error["message"].as_str().unwrap().contains("backup"));
        let backup = dir.join("state.jsonl.bak");
        let preserved = if backup.exists() { backup } else { state };
        assert_eq!(std::fs::read_to_string(preserved).unwrap(), journal);
    }
    std::fs::remove_dir_all(dir).expect("remove fixture directory");
}

fn assert_method_target_whitespace(input_type: &str) {
    let dir = std::env::temp_dir().join(format!(
        "dalfox-method-whitespace-{input_type}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    let config = dir.join("config.json");
    std::fs::write(&config, "{}").expect("write empty config");
    let targets = [
        "POST\thttp://127.0.0.1:9/tab-method?c=1 name=John Doe",
        "POST  http://127.0.0.1:9/spaces?c=1  name=John Doe",
        "POST http://127.0.0.1:9/tab-body?c=1\tname=John Doe",
    ];
    let list = dir.join("targets.txt");
    std::fs::write(&list, targets.join("\n")).expect("write target list");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dalfox"));
    cmd.arg("--config")
        .arg(&config)
        .args(["scan", "-i", input_type])
        .args(NO_SCAN_FLAGS)
        // Even the buggy parser's invented hostname must never reach DNS or
        // an external host. Every preflight request uses this loopback proxy.
        .args([
            "--proxy",
            "http://127.0.0.1:1",
            "--dry-run",
            "--format",
            "json",
            "-S",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match input_type {
        "url" => {
            cmd.args(targets).stdin(Stdio::null());
        }
        "file" => {
            cmd.arg(&list).stdin(Stdio::null());
        }
        "pipe" => {
            cmd.stdin(Stdio::piped());
        }
        _ => unreachable!(),
    }
    let mut child = cmd.spawn().expect("run dalfox");
    if input_type == "pipe" {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(targets.join("\n").as_bytes())
            .expect("write target list to stdin");
    }
    let output = child.wait_with_output().expect("wait for dalfox");
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    let doc: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected JSON ({e}):\n{stdout}\nstderr: {stderr}"));
    assert_eq!(doc["dry_run"], true);
    assert_eq!(doc["meta"]["targets_input"], 3);
    assert!(doc["meta"].get("targets_unparsable").is_none());
    let skipped = doc["meta"]["skipped"].as_array().expect("skipped targets");
    let actual: Vec<_> = skipped
        .iter()
        .map(|t| (t["method"].as_str(), t["target"].as_str()))
        .collect();
    assert_eq!(
        actual,
        vec![
            (Some("POST"), Some("http://127.0.0.1:9/spaces?c=1")),
            (Some("POST"), Some("http://127.0.0.1:9/tab-body?c=1")),
            (Some("POST"), Some("http://127.0.0.1:9/tab-method?c=1")),
        ],
        "whitespace must not change target methods or URLs; stdout:\n{stdout}"
    );
}

#[test]
fn test_cli_method_target_whitespace_url() {
    assert_method_target_whitespace("url");
}

#[test]
fn test_cli_method_target_whitespace_file() {
    assert_method_target_whitespace("file");
}

#[test]
fn test_cli_method_target_whitespace_pipe() {
    assert_method_target_whitespace("pipe");
}

/// Every scan-bearing subcommand flattens a `ScanArgs`, so `--format` has to be
/// read from *its* parsed args. Only `scan` was consulted; `url` / `file` /
/// `pipe` fell back to a raw-argv scan for the literal two-token
/// `["--format", "json"]` window, which no `--format=json` / `-f=json` /
/// `-fjson` spelling ever matches. The banner was then prepended to the JSON /
/// SARIF / TOML document on stdout — the exact breakage
/// `test_config_set_machine_format_suppresses_banner_on_stdout` guards for the
/// config path.
#[test]
fn test_machine_format_suppresses_banner_for_every_subcommand_and_spelling() {
    let list = std::env::temp_dir().join(format!("dalfox-fmt-list-{}.txt", std::process::id()));
    std::fs::write(&list, format!("{UNREACHABLE_TARGET}\n")).expect("write target list");
    let list_path = list.to_str().expect("utf8 path").to_string();

    // (subcommand args, format flag spelling) — the space-separated form is the
    // control that always worked.
    let subcommands: [Vec<String>; 4] = [
        vec!["scan".into(), UNREACHABLE_TARGET.into()],
        vec!["url".into(), "-u".into(), UNREACHABLE_TARGET.into()],
        vec!["file".into(), list_path.clone()],
        vec!["pipe".into()],
    ];
    let spellings: [Vec<&str>; 4] = [
        vec!["--format", "json"],
        vec!["--format=json"],
        vec!["-f", "json"],
        vec!["-fjson"],
    ];

    for sub in &subcommands {
        for spelling in &spellings {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_dalfox"));
            cmd.args(sub)
                .args(spelling)
                .args(NO_SCAN_FLAGS)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().expect("failed to execute dalfox");
            {
                let stdin = child.stdin.as_mut().expect("child stdin should be piped");
                let _ = stdin.write_all(format!("{UNREACHABLE_TARGET}\n").as_bytes());
            }
            let output = child.wait_with_output().expect("failed waiting for dalfox");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let label = format!("{} {}", sub.join(" "), spelling.join(" "));

            assert!(
                !stdout.contains(BANNER_GLYPH),
                "`dalfox {label}` leaked the banner into the JSON document; stdout was:\n{stdout}"
            );
            serde_json::from_str::<serde_json::Value>(stdout.trim())
                .unwrap_or_else(|e| panic!("`dalfox {label}` stdout is not JSON ({e}):\n{stdout}"));
        }
    }

    let _ = std::fs::remove_file(&list);
}

/// `-H`, `--user-agent` and `--cookies` all end up as HTTP header values, and
/// both ways they can be wrong used to be silent on the CLI:
///
///  * a spec with no `:` (`-H 'Authorization Bearer …'`) was dropped by a
///    `filter_map`, so the scan ran unauthenticated and reported clean;
///  * a byte reqwest cannot put in a header failed the request *builder*, so a
///    live target came back `CONNECTION_FAILED` — the scanner blaming the target
///    for the operator's input.
///
/// REST and MCP have refused both at submission since #1404 through the shared
/// `job::validate_header_list` / `validate_header_value`; this pins the CLI to
/// the same answer.
#[test]
fn test_malformed_header_inputs_are_refused_before_the_scan() {
    for (flag, value, needle) in [
        ("-H", "Authorization Bearer TOKEN", "--headers"),
        ("-H", ": novalue", "--headers"),
        ("-H", "X-Bad: va\nlue", "--headers"),
        ("--user-agent", "Bad\nUA", "--user-agent"),
        ("--cookies", "a=b\nc", "--cookies"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["scan", UNREACHABLE_TARGET])
            .args(NO_SCAN_FLAGS)
            .args([flag, value])
            .stdin(Stdio::null())
            .output()
            .expect("failed to execute dalfox");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "`{flag} {value:?}` should be rejected as a configuration error; stderr:\n{stderr}"
        );
        assert!(
            stderr.contains(needle),
            "the error should name `{needle}`; stderr was:\n{stderr}"
        );
    }
}

/// Control for the check above: a well-formed header set still runs.
#[test]
fn test_wellformed_header_inputs_are_accepted() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", UNREACHABLE_TARGET])
        .args(NO_SCAN_FLAGS)
        .args([
            "-H",
            "Authorization: Bearer TOKEN",
            "-H",
            "X-Empty:",
            "--user-agent",
            "Dalfox/3 (테스트)",
            "--cookies",
            "a=1; b=2",
            "--format",
            "json",
            "-S",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to execute dalfox");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--headers") && !stderr.contains("--user-agent"),
        "valid header inputs must not be rejected; stderr:\n{stderr}"
    );
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .unwrap_or_else(|e| panic!("expected a JSON document ({e}):\n{stdout}"));
}

/// A URL list written on Windows starts with a UTF-8 BOM. `str::trim` leaves
/// U+FEFF alone, so the *first* target used to reach the parser as
/// `\u{feff}http://host/…`, get re-prefixed to `http://http//host/…`, and fail
/// DNS — while every later line scanned fine and the run still exited 0.
#[test]
fn test_bom_prefixed_target_list_scans_the_first_target() {
    let list = std::env::temp_dir().join(format!("dalfox-bom-list-{}.txt", std::process::id()));
    std::fs::write(&list, "\u{feff}http://127.0.0.1:1/?q=1\r\n").expect("write BOM target list");

    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", "-i", "file", list.to_str().expect("utf8 path")])
        .args(NO_SCAN_FLAGS)
        .args(["--format", "json", "-S"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to execute dalfox");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let _ = std::fs::remove_file(&list);

    let doc: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected JSON ({e}):\n{stdout}"));
    let targets: Vec<&str> = doc["meta"]["target_summary"]
        .as_array()
        .expect("target_summary array")
        .iter()
        .map(|t| t["target"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        targets,
        vec!["http://127.0.0.1:1/?q=1"],
        "a leading BOM must not mangle the first target; stdout was:\n{stdout}"
    );
}

/// `dalfox mcp` used to hard-code a clean exit, so a supervisor or MCP host
/// could not tell "the stdio server never came up" from "it shut down cleanly".
/// With stdin closed the handshake cannot complete, which is the cheapest
/// deterministic form of that failure.
#[test]
fn test_mcp_startup_failure_exits_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("mcp")
        .stdin(Stdio::null())
        .output()
        .expect("failed to execute dalfox mcp");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MCP server error"),
        "a failed MCP start should say so on stderr, got:\n{stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a failed MCP start must not exit 0; stderr:\n{stderr}"
    );
}

#[test]
fn test_server_startup_reports_bind_failure_with_closed_stdout() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port().to_string();
    let config = tempfile::NamedTempFile::new().unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);

    let status = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--config")
        .arg(config.path())
        .args(["server", "--host", "127.0.0.1", "--port", &port])
        .stdout(writer)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "the bind error must reach the caller"
    );
}

#[test]
fn test_mcp_startup_initializes_with_a_config_warning_and_closed_stderr() {
    let dir = tempfile::tempdir().unwrap();
    // An explicitly requested missing config emits a diagnostic during startup.
    let config = dir.path().join("config.toml");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);

    let mut child = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .arg("--config")
        .arg(&config)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(writer)
        .spawn()
        .unwrap();
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}
        }
    });
    writeln!(child.stdin.as_mut().unwrap(), "{initialize}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(config.is_file());
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["serverInfo"]["name"], "dalfox");
}

/// `dalfox server` must exit 0 on SIGTERM. The signal path — handler install,
/// the cancel sweep, the bounded scan drain — only runs in a real process.
#[cfg(unix)]
#[test]
fn test_server_exits_cleanly_on_sigterm() {
    use std::io::{BufRead, BufReader};

    // A free port: bind to 0, read it back, release it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe listener")
        .local_addr()
        .expect("probe addr")
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["server", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dalfox server");

    // "listening on" is the server's own "it came up" line.
    let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
    let came_up = lines
        .by_ref()
        .map_while(Result::ok)
        .any(|line| line.contains("listening on"));
    assert!(came_up, "the server never announced its listener");

    // A scan in flight when the signal lands: its target accepts the
    // connection and never answers, so the job is still active.
    let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stalled target");
    let body = format!(
        r#"{{"target":"http://{}/?q=1"}}"#,
        stalled.local_addr().expect("stalled addr")
    );
    let mut conn =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    write!(
        conn,
        "POST /scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("send the scan request");
    let mut reply = String::new();
    std::io::Read::read_to_string(&mut conn, &mut reply).expect("read the reply");
    assert!(
        reply.contains("scan_id"),
        "the scan must be accepted: {reply}"
    );

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(killed.success());

    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    let status = child.wait().expect("wait for the server");
    assert_eq!(status.code(), Some(0), "a clean shutdown exits 0: {rest:?}");
    assert!(
        rest.iter().any(|l| l.contains("shutdown signal received")),
        "the shutdown must be logged: {rest:?}"
    );
    assert!(
        rest.iter()
            .any(|l| l.contains("cancelling 1 active scan(s)")),
        "the in-flight scan must be cancelled, not abandoned: {rest:?}"
    );
}

/// Kills the daemon under test when the test ends, however it ends: a failed
/// assertion must not leave a `dalfox` process listening.
#[cfg(unix)]
struct KillOnDrop(std::process::Child);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One HTTP/1.1 request against a local server; returns the raw reply, or
/// nothing when the server cannot be reached.
#[cfg(unix)]
fn http_once(port: u16, request: &str) -> String {
    let Ok(mut conn) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = conn.write_all(request.as_bytes());
    let mut reply = String::new();
    let _ = std::io::Read::read_to_string(&mut conn, &mut reply);
    reply
}

/// A daemon must outlive its log sink. `log()` used `println!`, which panics
/// on a pipe whose reader is gone, and the panic hook turned that into
/// `exit(0)`: `dalfox server | tee` died, reporting success, on the first line
/// logged after `tee` went away.
#[cfg(unix)]
#[test]
fn test_server_outlives_its_log_reader() {
    use std::io::{BufRead, BufReader};

    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["server", "--port", "0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dalfox server"),
    );
    let mut stdout = BufReader::new(child.0.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    while !line.contains("listening on") {
        line.clear();
        assert!(
            stdout.read_line(&mut line).expect("read stdout") > 0,
            "the server never announced its listener"
        );
    }
    let (_, addr) = line.trim_end().rsplit_once("listening on http://").unwrap();
    let port = addr.parse::<std::net::SocketAddr>().unwrap().port();
    assert_ne!(port, 0, "the log must report the assigned port");
    // The reader goes away; every later log line is written to a broken pipe.
    drop(stdout);

    let body = r#"{"target":"http://127.0.0.1:1/?q=1"}"#;
    let queued = http_once(
        port,
        &format!(
            "POST /scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    );
    let health = http_once(
        port,
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    let exited = child.0.try_wait().expect("poll the server");
    assert!(
        queued.contains("scan_id"),
        "the scan must be accepted: {queued}"
    );
    assert!(
        health.contains("200 OK"),
        "the server must still answer after its log reader went away \
         (exit status: {exited:?}): {health}"
    );
}

/// Same for `dalfox mcp`, whose log goes to stderr: a client that closes its
/// end must not end the server on the next log line — nor, with `--debug`,
/// fail every scan on the first debug line its worker prints.
#[cfg(unix)]
#[test]
fn test_mcp_outlives_a_closed_stderr() {
    use std::io::{BufRead, BufReader};

    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["--debug", "mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dalfox mcp"),
    );
    drop(child.0.stderr.take());
    let mut stdin = child.0.stdin.take().expect("piped stdin");
    // Replies are read on a thread so a server that stops answering fails the
    // test instead of hanging it.
    let stdout = child.0.stdout.take().expect("piped stdout");
    let (reply_tx, replies) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if reply_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut call = |message: &str, id: u64| -> String {
        let _ = writeln!(stdin, "{message}");
        let wanted = format!("\"id\":{id}");
        loop {
            match replies.recv_timeout(std::time::Duration::from_secs(20)) {
                Ok(line) if line.contains(&wanted) => return line,
                Ok(_) => {}
                Err(_) => return String::new(),
            }
        }
    };

    call(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        1,
    );
    // The scan submission logs a `queued` line to the closed stderr.
    let queued = call(
        concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_with_dalfox","arguments":{"target":"http://127.0.0.1:1/?q=1","skip_mining":true}}}"#
        ),
        2,
    );
    // Nothing listens on port 1, so the scan ends `error` — for that reason,
    // not because its worker panicked on a debug line.
    let mut listed = String::new();
    for id in 3..60 {
        listed = call(
            &format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"list_scans_dalfox","arguments":{{}}}}}}"#
            ),
            id,
        );
        // An empty reply is a server that stopped answering: fail now, not
        // after waiting out every remaining call.
        if listed.is_empty() || listed.contains("unreachable") || listed.contains("panicked") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        queued.contains("scan_id"),
        "the scan must be accepted: {queued}"
    );
    assert!(
        listed.contains("unreachable") && !listed.contains("panicked"),
        "the scan must run to its own outcome after stderr was closed: {listed}"
    );
}

/// A log reader that stops reading without closing — a paused terminal, a
/// stuck collector — must not freeze the server. Logging straight to stdout
/// blocked every handler that logged once the pipe buffer was full.
#[cfg(unix)]
#[test]
fn test_server_outlives_a_stalled_log_reader() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe listener")
        .local_addr()
        .expect("probe addr")
        .port();
    // stdout is held open and never read, for the life of the test.
    let _child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["server", "--port", &port.to_string(), "--api-key", "k"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dalfox server"),
    );
    let health = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let up = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
    assert!(up, "the server never came up");

    // Each refused request logs one AUTH line; 3000 of them are several times
    // any pipe buffer. Pipelined 100 to a connection: 3000 short connections
    // would leave that many sockets in TIME_WAIT and starve the tests that
    // run next of ephemeral ports.
    let denied = "GET /scans HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let last = "GET /scans HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let batch = format!("{}{last}", denied.repeat(99));
    // Stops at the first batch left unanswered: once the server is stuck,
    // every further one would wait out its read timeout.
    let refused: usize = (0..30)
        .map(|_| http_once(port, &batch).matches("HTTP/1.1 401").count())
        .take_while(|answered| *answered == 100)
        .sum();
    let after = http_once(port, health);
    assert_eq!(refused, 3000, "every request must be answered");
    assert!(after.contains("200 OK"), "{after}");
}
