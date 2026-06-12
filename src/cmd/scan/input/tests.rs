//! Tests for target input resolution (`resolve_targets`) and its helpers.
//!
//! Every case pins an explicit `--input-type` so the resolver never touches
//! stdin — under `cargo test` stdin is not a TTY, and an `auto` path could
//! otherwise block or read the harness's stream. The `url`/`file`/`raw-http`/
//! `har` branches with explicit targets are entirely file/literal-driven.

use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    scan: ScanArgs,
}

/// Parse a `ScanArgs` from a CLI-style token list (the leading binary name is
/// prepended for you).
fn args_from(argv: &[&str]) -> ScanArgs {
    let mut full = Vec::with_capacity(argv.len() + 1);
    full.push("dalfox");
    full.extend_from_slice(argv);
    TestCli::try_parse_from(full)
        .expect("test args should parse")
        .scan
}

/// Write `contents` to a uniquely named temp file and return its path.
fn tmp_file(name: &str, contents: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox-input-test-{}-{}-{}",
        std::process::id(),
        nanos,
        name
    ));
    std::fs::write(&p, contents).expect("write temp file");
    p
}

const SAMPLE_HAR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.har");

// ── resolve_targets: url mode ───────────────────────────────────────

#[tokio::test]
async fn url_mode_parses_single_target() {
    let args = args_from(&["-i", "url", "-S", "https://example.com/?q=1"]);
    let targets = resolve_targets(&args).await.expect("one URL resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.as_str(), "https://example.com/?q=1");
}

#[tokio::test]
async fn url_mode_dedupes_identical_targets() {
    // Same URL twice collapses to one (URL+method dedup), e.g. a noisy pipe.
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "https://example.com/?q=1",
        "https://example.com/?q=1",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1, "duplicate URL must be deduped");
}

#[tokio::test]
async fn url_mode_applies_method_and_header_overrides() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "-X",
        "POST",
        "-H",
        "X-Test: v1",
        "--user-agent",
        "DalfoxTest/1.0",
        "https://example.com/",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.method, "POST");
    assert!(t.headers.iter().any(|(k, v)| k == "X-Test" && v == "v1"));
    assert_eq!(t.user_agent.as_deref(), Some("DalfoxTest/1.0"));
}

#[tokio::test]
async fn invalid_input_type_is_an_error() {
    let args = args_from(&["-i", "bogus", "-S", "https://example.com/"]);
    assert!(resolve_targets(&args).await.is_err());
}

// ── resolve_targets: auto mode (no stdin data) ──────────────────────
//
// Under `cargo test` stdin is `/dev/null` (CI) or a TTY (local): the auto
// path either reads an immediately-empty stream or skips it, so these stay
// deterministic and never block. They exercise the positional-input
// classification that the explicit-type cases bypass.

#[tokio::test]
async fn auto_mode_classifies_url_literal() {
    let args = args_from(&["-i", "auto", "-S", "https://auto.example/?q=1"]);
    let targets = resolve_targets(&args).await.expect("auto URL resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("auto.example"));
}

#[tokio::test]
async fn auto_mode_reads_url_list_file() {
    // A positional arg that is a readable file of URLs is classified as a
    // target list and expanded line by line.
    let p = tmp_file(
        "auto-list",
        "https://one.example/\n# comment\nhttps://two.example/\n",
    );
    let args = args_from(&["-i", "auto", "-S", p.to_str().unwrap()]);
    let targets = resolve_targets(&args).await.expect("auto file resolves");
    let _ = std::fs::remove_file(&p);
    let hosts: Vec<Option<&str>> = targets.iter().map(|t| t.url.host_str()).collect();
    assert_eq!(hosts, vec![Some("one.example"), Some("two.example")]);
}

// ── resolve_targets: file mode ──────────────────────────────────────

#[tokio::test]
async fn file_mode_reads_lines_and_skips_comments_and_blanks() {
    let p = tmp_file(
        "targets",
        "https://a.example/?x=1\n# a comment\n\n  https://b.example/?y=2  \n",
    );
    let args = args_from(&["-i", "file", "-S", p.to_str().unwrap()]);
    let targets = resolve_targets(&args).await.expect("file resolves");
    let _ = std::fs::remove_file(&p);
    let urls: Vec<&str> = targets.iter().map(|t| t.url.as_str()).collect();
    assert_eq!(
        urls,
        vec!["https://a.example/?x=1", "https://b.example/?y=2"]
    );
}

#[tokio::test]
async fn file_mode_without_path_is_an_error() {
    let args = args_from(&["-i", "file", "-S"]);
    assert!(resolve_targets(&args).await.is_err());
}

#[tokio::test]
async fn file_mode_missing_file_is_an_error() {
    let args = args_from(&[
        "-i",
        "file",
        "-S",
        "/dalfox/no/such/target/list/xyz.txt",
    ]);
    assert!(resolve_targets(&args).await.is_err());
}

// ── resolve_targets: scope filters ──────────────────────────────────

#[tokio::test]
async fn include_url_keeps_only_matching_targets() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--include-url",
        ".*/api/.*",
        "https://example.com/api/users",
        "https://example.com/page",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    assert!(targets[0].url.as_str().contains("/api/"));
}

#[tokio::test]
async fn exclude_url_drops_matching_targets() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--exclude-url",
        ".*/admin.*",
        "https://example.com/admin/panel",
        "https://example.com/ok",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    assert!(targets[0].url.as_str().ends_with("/ok"));
}

#[tokio::test]
async fn invalid_scope_regex_is_skipped_not_fatal() {
    // An unparseable --include-url is warned about and dropped; with no other
    // valid include pattern the filter is a no-op, so the target survives.
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--include-url",
        "(unbalanced",
        "https://example.com/",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
}

// ── resolve_targets: out-of-scope domain filters ────────────────────

#[tokio::test]
async fn out_of_scope_domain_is_excluded() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--out-of-scope",
        "evil.example",
        "https://evil.example/",
        "https://good.example/",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("good.example"));
}

#[tokio::test]
async fn out_of_scope_file_domains_are_excluded() {
    let p = tmp_file("oos", "evil.example\n# skip me\n\n");
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--out-of-scope-file",
        p.to_str().unwrap(),
        "https://evil.example/",
        "https://good.example/",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    let _ = std::fs::remove_file(&p);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("good.example"));
}

#[tokio::test]
async fn all_targets_filtered_out_is_an_error() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--out-of-scope",
        "example.com",
        "https://example.com/",
    ]);
    assert!(resolve_targets(&args).await.is_err());
}

// ── resolve_targets: raw-http + har modes ───────────────────────────

#[tokio::test]
async fn raw_http_literal_is_parsed() {
    // A raw request pasted as a positional literal (not a path on disk).
    let raw = "GET /search?q=1 HTTP/1.1\r\nHost: raw.example\r\n\r\n";
    let args = args_from(&["-i", "raw-http", "-S", raw]);
    let targets = resolve_targets(&args).await.expect("raw http resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.host_str(), Some("raw.example"));
    assert_eq!(targets[0].method, "GET");
}

#[tokio::test]
async fn raw_http_from_file_is_parsed() {
    let p = tmp_file(
        "raw",
        "POST /login HTTP/1.1\r\nHost: file.example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=a",
    );
    let args = args_from(&["-i", "raw-http", "-S", p.to_str().unwrap()]);
    let targets = resolve_targets(&args).await.expect("raw http file resolves");
    let _ = std::fs::remove_file(&p);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].method, "POST");
    assert_eq!(targets[0].url.host_str(), Some("file.example"));
}

#[tokio::test]
async fn raw_http_invalid_is_an_error() {
    let args = args_from(&["-i", "raw-http", "-S", "not a real http request"]);
    assert!(resolve_targets(&args).await.is_err());
}

#[tokio::test]
async fn har_fixture_expands_to_multiple_targets() {
    let args = args_from(&["-i", "har", "-S", SAMPLE_HAR_PATH]);
    let targets = resolve_targets(&args).await.expect("HAR resolves");
    assert_eq!(targets.len(), 2, "fixture has a GET and a POST entry");
    assert!(targets.iter().any(|t| t.method == "GET"));
    assert!(targets.iter().any(|t| t.method == "POST"));
}

#[tokio::test]
async fn har_invalid_document_is_an_error() {
    let args = args_from(&["-i", "har", "-S", "{ not valid har }"]);
    assert!(resolve_targets(&args).await.is_err());
}

// ── resolve_targets: cookie-from-raw ────────────────────────────────

#[tokio::test]
async fn cookie_from_raw_appends_cookies_to_targets() {
    let p = tmp_file(
        "cookies",
        "GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1; b=2\r\n\r\n",
    );
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--cookie-from-raw",
        p.to_str().unwrap(),
        "https://example.com/",
    ]);
    let targets = resolve_targets(&args).await.expect("resolves");
    let _ = std::fs::remove_file(&p);
    assert_eq!(targets.len(), 1);
    let cookies = &targets[0].cookies;
    assert!(cookies.iter().any(|(k, v)| k == "a" && v == "1"));
    assert!(cookies.iter().any(|(k, v)| k == "b" && v == "2"));
}

// ── load_request_source ─────────────────────────────────────────────

#[test]
fn load_request_source_reads_existing_file() {
    let p = tmp_file("src", "raw body contents");
    let args = args_from(&["-i", "url", "-S", "https://e.example/"]);
    let out = load_request_source(p.to_str().unwrap(), &args, "raw HTTP request")
        .expect("existing file reads");
    let _ = std::fs::remove_file(&p);
    assert_eq!(out, "raw body contents");
}

#[test]
fn load_request_source_treats_non_path_as_literal() {
    let args = args_from(&["-i", "url", "-S", "https://e.example/"]);
    let literal = "GET / HTTP/1.1\r\nHost: literal.example\r\n\r\n";
    let out = load_request_source(literal, &args, "raw HTTP request").expect("literal passes through");
    assert_eq!(out, literal);
}

// ── apply_request_cli_overrides ─────────────────────────────────────

#[test]
fn apply_request_cli_overrides_only_overrides_explicit_flags() {
    let mut target = crate::target_parser::parse_raw_http_request(
        "GET /p HTTP/1.1\r\nHost: ov.example\r\n\r\n",
    )
    .expect("raw request parses");

    let args = args_from(&[
        "-i",
        "raw-http",
        "-S",
        "-X",
        "POST",
        "-d",
        "k=v",
        "-H",
        "X-Extra: yes",
        "--user-agent",
        "Agent/9",
        "--cookies",
        "sid=abc",
        "ignored.example",
    ]);

    apply_request_cli_overrides(&mut target, &args);

    assert_eq!(target.method, "POST");
    assert_eq!(target.data.as_deref(), Some("k=v"));
    assert!(target.headers.iter().any(|(k, v)| k == "X-Extra" && v == "yes"));
    assert!(target.headers.iter().any(|(k, v)| k == "User-Agent" && v == "Agent/9"));
    assert_eq!(target.user_agent.as_deref(), Some("Agent/9"));
    assert!(target.cookies.iter().any(|(k, v)| k == "sid" && v == "abc"));
}

#[test]
fn apply_request_cli_overrides_keeps_request_method_without_flag() {
    let mut target = crate::target_parser::parse_raw_http_request(
        "DELETE /thing HTTP/1.1\r\nHost: keep.example\r\n\r\n",
    )
    .expect("raw request parses");

    // No -X flag: the captured request's own method (DELETE) must survive
    // rather than being clobbered with the GET default.
    let args = args_from(&["-i", "raw-http", "-S", "keep.example"]);
    apply_request_cli_overrides(&mut target, &args);
    assert_eq!(target.method, "DELETE");
}
