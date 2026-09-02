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

/// [`resolve_targets`] reduced to just the target list, for the cases that
/// don't assert on dedup statistics.
async fn resolve(args: &ScanArgs) -> std::result::Result<Vec<Target>, ScanOutcome> {
    resolve_targets(args).await.map(|r| r.targets)
}

// ── resolve_targets: url mode ───────────────────────────────────────

#[tokio::test]
async fn url_mode_parses_single_target() {
    let args = args_from(&["-i", "url", "-S", "https://example.com/?q=1"]);
    let targets = resolve(&args).await.expect("one URL resolves");
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
    let targets = resolve(&args).await.expect("resolves");
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
    let targets = resolve(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.method, "POST");
    assert!(t.headers.iter().any(|(k, v)| k == "X-Test" && v == "v1"));
    assert_eq!(t.user_agent.as_deref(), Some("DalfoxTest/1.0"));
}

#[tokio::test]
async fn invalid_input_type_is_an_error() {
    let args = args_from(&["-i", "bogus", "-S", "https://example.com/"]);
    assert!(resolve(&args).await.is_err());
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
    let targets = resolve(&args).await.expect("auto URL resolves");
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
    let targets = resolve(&args).await.expect("auto file resolves");
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
    let targets = resolve(&args).await.expect("file resolves");
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
    assert!(resolve(&args).await.is_err());
}

#[tokio::test]
async fn file_mode_missing_file_is_an_error() {
    let args = args_from(&["-i", "file", "-S", "/dalfox/no/such/target/list/xyz.txt"]);
    assert!(resolve(&args).await.is_err());
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
    let targets = resolve(&args).await.expect("resolves");
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
    let targets = resolve(&args).await.expect("resolves");
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
    let targets = resolve(&args).await.expect("resolves");
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
    let targets = resolve(&args).await.expect("resolves");
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
    let targets = resolve(&args).await.expect("resolves");
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
    assert!(resolve(&args).await.is_err());
}

// ── resolve_targets: raw-http + har modes ───────────────────────────

#[tokio::test]
async fn raw_http_literal_is_parsed() {
    // A raw request pasted as a positional literal (not a path on disk).
    let raw = "GET /search?q=1 HTTP/1.1\r\nHost: raw.example\r\n\r\n";
    let args = args_from(&["-i", "raw-http", "-S", raw]);
    let targets = resolve(&args).await.expect("raw http resolves");
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
    let targets = resolve(&args).await.expect("raw http file resolves");
    let _ = std::fs::remove_file(&p);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].method, "POST");
    assert_eq!(targets[0].url.host_str(), Some("file.example"));
}

#[tokio::test]
async fn raw_http_invalid_is_an_error() {
    let args = args_from(&["-i", "raw-http", "-S", "not a real http request"]);
    assert!(resolve(&args).await.is_err());
}

#[tokio::test]
async fn har_fixture_expands_to_multiple_targets() {
    let args = args_from(&["-i", "har", "-S", SAMPLE_HAR_PATH]);
    let targets = resolve(&args).await.expect("HAR resolves");
    assert_eq!(targets.len(), 2, "fixture has a GET and a POST entry");
    assert!(targets.iter().any(|t| t.method == "GET"));
    assert!(targets.iter().any(|t| t.method == "POST"));
}

#[tokio::test]
async fn har_invalid_document_is_an_error() {
    let args = args_from(&["-i", "har", "-S", "{ not valid har }"]);
    assert!(resolve(&args).await.is_err());
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
    let targets = resolve(&args).await.expect("resolves");
    let _ = std::fs::remove_file(&p);
    assert_eq!(targets.len(), 1);
    let cookies = &targets[0].cookies;
    assert!(cookies.iter().any(|(k, v)| k == "a" && v == "1"));
    assert!(cookies.iter().any(|(k, v)| k == "b" && v == "2"));
}

/// A `--cookie-from-raw` the operator supplied but that cannot be read must
/// stop the run. Continuing means scanning *logged out*: the scan reports
/// `0 XSS` and exits 0, which the CI gate that asked for the credentials
/// cannot tell apart from a clean target. Note `-S` (silence) is set here —
/// this used to print nothing at all in that mode.
#[tokio::test]
async fn cookie_from_raw_unreadable_file_is_fatal() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--cookie-from-raw",
        "/nonexistent/dalfox-cookie-file",
        "https://example.com/",
    ]);
    assert!(
        resolve(&args).await.is_err(),
        "an unreadable --cookie-from-raw must not fall through to a logged-out scan"
    );
}

/// The quieter half of the same failure: the file reads fine but carries no
/// `Cookie:` header, so zero cookies are attached. That produced no message at
/// any verbosity and scanned logged out.
#[tokio::test]
async fn cookie_from_raw_without_cookie_header_is_fatal() {
    let p = tmp_file(
        "nocookie",
        "GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
    );
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--cookie-from-raw",
        p.to_str().unwrap(),
        "https://example.com/",
    ]);
    let outcome = resolve(&args).await;
    let _ = std::fs::remove_file(&p);
    assert!(
        outcome.is_err(),
        "a --cookie-from-raw file with no Cookie: header must not scan logged out"
    );
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
    let out =
        load_request_source(literal, &args, "raw HTTP request").expect("literal passes through");
    assert_eq!(out, literal);
}

// ── apply_request_cli_overrides ─────────────────────────────────────

#[test]
fn apply_request_cli_overrides_only_overrides_explicit_flags() {
    let mut target =
        crate::target_parser::parse_raw_http_request("GET /p HTTP/1.1\r\nHost: ov.example\r\n\r\n")
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
    assert!(
        target
            .headers
            .iter()
            .any(|(k, v)| k == "X-Extra" && v == "yes")
    );
    assert!(
        target
            .headers
            .iter()
            .any(|(k, v)| k == "User-Agent" && v == "Agent/9")
    );
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

// ── dedup_targets: --dedup-urls exact / signature / off ─────────────

/// Parse `url` into a Target the way the non-request input paths do.
fn target_at(url: &str) -> Target {
    crate::target_parser::parse_target_with_method(url).expect("target parses")
}

/// Signature key of a URL scanned with `method` and an optional body.
fn sig(url: &str, method: &str, data: Option<&str>, headers: &[(&str, &str)]) -> String {
    let mut t = target_at(url);
    t.method = method.to_string();
    t.data = data.map(ToString::to_string);
    t.headers = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    target_signature_key(&t)
}

#[test]
fn exact_mode_only_collapses_identical_urls() {
    let mut targets = vec![
        target_at("https://ex.example/p?id=1"),
        target_at("https://ex.example/p?id=1"),
        target_at("https://ex.example/p?id=2"),
    ];
    let stats = dedup_targets(&mut targets, "exact");
    assert_eq!(stats.mode, "exact");
    assert_eq!(stats.collapsed, 1);
    assert_eq!(targets.len(), 2, "differing values stay distinct targets");
}

#[test]
fn signature_mode_collapses_value_only_variants() {
    // The `gau`/`katana` shape: one endpoint, one parameter, many harvested
    // values. All of them are one injection point.
    let mut targets: Vec<Target> = (1..=50)
        .map(|i| target_at(&format!("https://ex.example/p?id={i}")))
        .collect();
    let stats = dedup_targets(&mut targets, "signature");
    assert_eq!(stats.mode, "signature");
    assert_eq!(stats.collapsed, 49);
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].url.as_str(),
        "https://ex.example/p?id=1",
        "the first listed URL is the surviving representative"
    );
    assert_eq!(
        stats.sample.len(),
        DEDUP_SAMPLE_LIMIT,
        "the log line quotes a bounded sample of what was dropped"
    );
    assert_eq!(stats.sample[0], "https://ex.example/p?id=2");
}

#[test]
fn signature_mode_keeps_distinct_endpoints_and_param_sets() {
    let mut targets = vec![
        target_at("https://ex.example/p?id=1"),
        target_at("https://ex.example/p?id=2&debug=1"), // extra param name
        target_at("https://ex.example/other?id=1"),     // other path
        target_at("https://other.example/p?id=1"),      // other host
        target_at("http://ex.example/p?id=1"),          // other scheme
    ];
    let stats = dedup_targets(&mut targets, "signature");
    assert_eq!(stats.collapsed, 0);
    assert_eq!(targets.len(), 5);
}

#[test]
fn signature_mode_ignores_param_order_and_default_port() {
    assert_eq!(
        sig("https://ex.example/p?a=1&b=2", "GET", None, &[]),
        sig("https://ex.example/p?b=9&a=8", "GET", None, &[]),
        "same name set in a different order is the same endpoint"
    );
    assert_eq!(
        sig("https://ex.example/p?a=1", "GET", None, &[]),
        sig("https://ex.example:443/p?a=1", "GET", None, &[]),
        "the scheme's default port must not split a signature"
    );
    assert_ne!(
        sig("https://ex.example/p?a=1", "GET", None, &[]),
        sig("https://ex.example:8443/p?a=1", "GET", None, &[]),
        "a non-default port is a different endpoint"
    );
    assert_ne!(
        sig("https://ex.example/p?a=1", "GET", None, &[]),
        sig("https://ex.example/p?a=1", "POST", None, &[]),
        "method is part of the signature"
    );
}

#[test]
fn signature_mode_counts_body_param_names() {
    // form-urlencoded: values differ, names don't.
    assert_eq!(
        sig("https://ex.example/p", "POST", Some("user=a&pw=1"), &[]),
        sig("https://ex.example/p", "POST", Some("user=b&pw=2"), &[]),
    );
    assert_ne!(
        sig("https://ex.example/p", "POST", Some("user=a"), &[]),
        sig("https://ex.example/p", "POST", Some("user=a&pw=1"), &[]),
        "an extra body param is an extra injection point"
    );
    // JSON: top-level keys, matching what the JSON body miner probes.
    assert_eq!(
        sig("https://ex.example/p", "POST", Some(r#"{"q":"a"}"#), &[]),
        sig("https://ex.example/p", "POST", Some(r#"{"q":"zzz"}"#), &[]),
    );
    assert_ne!(
        sig("https://ex.example/p", "POST", Some(r#"{"q":"a"}"#), &[]),
        sig("https://ex.example/p", "POST", Some(r#"{"r":"a"}"#), &[]),
    );
    // multipart: field names off the Content-Disposition lines.
    let multipart = |v: &str| {
        format!("--X\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{v}\r\n--X--\r\n")
    };
    let ct = [("Content-Type", "multipart/form-data; boundary=X")];
    assert_eq!(
        sig("https://ex.example/p", "POST", Some(&multipart("a")), &ct),
        sig("https://ex.example/p", "POST", Some(&multipart("b")), &ct),
    );
    assert!(
        sig("https://ex.example/p", "POST", Some(&multipart("a")), &ct).ends_with("|note"),
        "the multipart field name lands in the signature"
    );
}

#[test]
fn off_mode_keeps_every_input_line() {
    let mut targets = vec![
        target_at("https://ex.example/p?id=1"),
        target_at("https://ex.example/p?id=1"),
    ];
    let stats = dedup_targets(&mut targets, "off");
    assert_eq!(stats.mode, "off");
    assert_eq!(stats.collapsed, 0);
    assert_eq!(targets.len(), 2, "off must not drop even exact duplicates");
}

#[tokio::test]
async fn dedup_urls_signature_flows_through_resolve_targets() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--dedup-urls",
        "signature",
        "https://ex.example/p?id=1",
        "https://ex.example/p?id=2",
        "https://ex.example/q?id=1",
    ]);
    let resolved = resolve_targets(&args).await.expect("resolves");
    assert_eq!(resolved.targets.len(), 2);
    assert_eq!(resolved.dedup.mode, "signature");
    assert_eq!(resolved.dedup.collapsed, 1);
}

#[tokio::test]
async fn dedup_urls_defaults_to_exact() {
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "https://ex.example/p?id=1",
        "https://ex.example/p?id=2",
    ]);
    let resolved = resolve_targets(&args).await.expect("resolves");
    assert_eq!(resolved.dedup.mode, "exact");
    assert_eq!(resolved.dedup.collapsed, 0);
    assert_eq!(
        resolved.targets.len(),
        2,
        "the default must keep the historical behavior"
    );
}

#[test]
fn signature_mode_prefers_a_representative_with_values() {
    // Recon dumps commonly list the stale valueless form first; that URL often
    // 404s, and letting it stand in for the family reports everything clean.
    let mut targets = vec![
        target_at("https://ex.example/p?id="),
        target_at("https://ex.example/p?id=42"),
        target_at("https://ex.example/p?id=43"),
    ];
    let stats = dedup_targets(&mut targets, "signature");
    assert_eq!(stats.collapsed, 2);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url.as_str(), "https://ex.example/p?id=42");
    assert!(
        stats
            .sample
            .contains(&"https://ex.example/p?id=".to_string()),
        "the demoted placeholder is reported as dropped: {:?}",
        stats.sample
    );
}

#[test]
fn signature_mode_keeps_a_valueless_representative_when_thats_all_there_is() {
    let mut targets = vec![
        target_at("https://ex.example/p?id="),
        target_at("https://ex.example/p?id="),
    ];
    let stats = dedup_targets(&mut targets, "signature");
    assert_eq!(stats.collapsed, 1);
    assert_eq!(targets[0].url.as_str(), "https://ex.example/p?id=");
}

#[test]
fn signature_mode_ignores_non_form_bodies() {
    // Running the form parser over XML would return the whole document as one
    // pseudo-name: no collapse, and a multi-KiB dedup key.
    let xml = |v: &str| format!("<order><item>{v}</item></order>");
    let ct = [("Content-Type", "application/xml")];
    assert_eq!(
        sig("https://ex.example/p", "POST", Some(&xml("a")), &ct),
        sig("https://ex.example/p", "POST", Some(&xml("b")), &ct),
        "an unparseable body contributes no names, so the endpoint decides"
    );
    assert!(
        sig("https://ex.example/p", "POST", Some(&xml("a")), &ct).ends_with('|'),
        "no body names in the key"
    );
}

#[test]
fn multipart_field_name_is_not_confused_by_filename() {
    let body = |name: &str| {
        format!(
            "--X\r\nContent-Disposition: form-data; filename=\"report.txt\"; name=\"{name}\"\r\n\r\nx\r\n--X--\r\n"
        )
    };
    let ct = [("Content-Type", "multipart/form-data; boundary=X")];
    let key = sig("https://ex.example/p", "POST", Some(&body("upload")), &ct);
    assert!(
        key.ends_with("|upload"),
        "the field name, not the filename, belongs in the key: {key}"
    );
    assert_ne!(
        key,
        sig("https://ex.example/p", "POST", Some(&body("avatar")), &ct),
        "different field names must not collapse"
    );
}

#[tokio::test]
async fn scope_filters_run_before_signature_dedup() {
    // The include filter must get to rule family members out first: otherwise
    // the representative picked here (`q=user`) is excluded afterwards and the
    // whole family — including the `q=admin` the operator asked for — is gone.
    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--dedup-urls",
        "signature",
        "--include-url",
        "q=admin",
        "https://ex.example/p?q=user",
        "https://ex.example/p?q=admin",
    ]);
    let resolved = resolve_targets(&args).await.expect("resolves");
    assert_eq!(resolved.targets.len(), 1);
    assert_eq!(
        resolved.targets[0].url.as_str(),
        "https://ex.example/p?q=admin"
    );
    assert_eq!(
        resolved.dedup.collapsed, 0,
        "only one member survived scope"
    );
}

#[tokio::test]
async fn explicit_dedup_urls_flag_beats_an_unset_default() {
    // `dedup_urls` is an Option so config precedence can tell "unset" from an
    // explicit choice; the effective mode is read through `dedup_urls_mode`.
    let args = args_from(&["-i", "url", "-S", "https://ex.example/p?id=1"]);
    assert_eq!(args.dedup_urls, None);
    assert_eq!(args.dedup_urls_mode(), "exact");

    let args = args_from(&[
        "-i",
        "url",
        "-S",
        "--dedup-urls",
        "exact",
        "https://ex.example/p?id=1",
    ]);
    assert_eq!(args.dedup_urls.as_deref(), Some("exact"));
}

// ── target-list line shape (`target_list_lines`) ────────────────────

#[test]
fn target_list_lines_skips_blanks_and_comments() {
    let content = "https://a.example/\n\n   \n# a comment\n  https://b.example/  \n";
    assert_eq!(
        target_list_lines(content).collect::<Vec<_>>(),
        vec!["https://a.example/", "https://b.example/"]
    );
}

#[test]
fn target_list_lines_strips_a_leading_utf8_bom() {
    // `str::trim` leaves U+FEFF alone (it is not `White_Space`), so without an
    // explicit strip the first entry reaches the target parser as
    // `\u{feff}https://…` — a string with no parseable scheme.
    let content = "\u{feff}https://a.example/\nhttps://b.example/\n";
    assert_eq!(
        target_list_lines(content).collect::<Vec<_>>(),
        vec!["https://a.example/", "https://b.example/"]
    );
}

#[tokio::test]
async fn file_mode_ignores_a_leading_utf8_bom_in_the_list() {
    // A URL list saved by Notepad / Excel / PowerShell `Out-File` starts with a
    // BOM. It used to corrupt the *first* target only: the byte defeated the
    // scheme check, the fallback re-prefixed the whole string, and dalfox
    // scanned `http://http//a.example/…`. Every later line was fine, so the run
    // still exited 0 and the operator never heard that the first target was
    // never reached.
    let p = tmp_file(
        "bom-list",
        "\u{feff}https://a.example/?q=1\r\nhttps://b.example/?q=2\r\n",
    );
    let args = args_from(&["-i", "file", "-S", p.to_str().unwrap()]);
    let targets = resolve(&args).await.expect("resolves");
    let _ = std::fs::remove_file(&p);

    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].url.as_str(), "https://a.example/?q=1");
    assert_eq!(targets[1].url.as_str(), "https://b.example/?q=2");
}

// ── `-X/--method` against a target that carries its own method ──────

/// Like [`args_from`], but also records which flags the operator actually
/// typed, the way `main.rs` does from clap's `ArgMatches`. Needed by anything
/// that reads [`ScanArgs::was_explicit`]: the plain derive parse leaves
/// `explicit` empty (it is an `#[arg(skip)]` field), so a test built with
/// `args_from` can never tell an explicit flag from its default.
fn args_from_explicit(argv: &[&str]) -> ScanArgs {
    use clap::{CommandFactory, FromArgMatches};
    let mut full = Vec::with_capacity(argv.len() + 1);
    full.push("dalfox");
    full.extend_from_slice(argv);
    let matches = TestCli::command()
        .try_get_matches_from(full)
        .expect("test args should parse");
    let mut args = TestCli::from_arg_matches(&matches)
        .expect("test args should map")
        .scan;
    args.explicit = crate::cmd::scan::ExplicitArgs::from_matches(&matches);
    args
}

#[tokio::test]
async fn explicit_get_overrides_a_captured_raw_http_method() {
    // `-X GET` is the one method a `ScanArgs` also holds by default, so the old
    // `args.method != DEFAULT_METHOD` guard read it as "the operator said
    // nothing" and kept replaying the captured POST — writing to an endpoint the
    // operator explicitly asked to only read.
    let raw = "POST /login HTTP/1.1\r\nHost: raw.example\r\n\r\nu=a";
    let args = args_from_explicit(&["-i", "raw-http", "-S", "-X", "GET", raw]);
    let targets = resolve(&args).await.expect("raw http resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].method, "GET");
}

#[tokio::test]
async fn explicit_get_overrides_a_method_embedded_in_the_target_line() {
    let args = args_from_explicit(&[
        "-i",
        "url",
        "-S",
        "-X",
        "GET",
        "POST https://example.com/?q=1",
    ]);
    let targets = resolve(&args).await.expect("resolves");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].method, "GET");
}

#[tokio::test]
async fn absent_method_flag_keeps_a_captured_raw_http_method() {
    // The other half of the contract: without `-X`, an imported request keeps
    // the method it was captured with.
    let raw = "POST /login HTTP/1.1\r\nHost: raw.example\r\n\r\nu=a";
    let args = args_from_explicit(&["-i", "raw-http", "-S", raw]);
    let targets = resolve(&args).await.expect("raw http resolves");
    assert_eq!(targets[0].method, "POST");
}

#[tokio::test]
async fn non_cli_scan_args_still_override_with_a_non_default_method() {
    // Server / MCP build `ScanArgs` directly, so `explicit` is empty there. The
    // `!= DEFAULT_METHOD` half of the guard is what keeps their `method: "PUT"`
    // applying, and must not regress.
    let raw = "POST /login HTTP/1.1\r\nHost: raw.example\r\n\r\nu=a";
    let args = ScanArgs {
        input_type: "raw-http".to_string(),
        method: "PUT".to_string(),
        silence: true,
        targets: vec![raw.to_string()],
        ..Default::default()
    };
    assert!(args.explicit.is_empty());
    let targets = resolve(&args).await.expect("raw http resolves");
    assert_eq!(targets[0].method, "PUT");
}
