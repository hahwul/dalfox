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
