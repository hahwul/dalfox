//! End-to-end recall guards for the *interaction* between a real sink and the
//! scanner's fan-out cuts.
//!
//! Both regressions these cover shipped while their ingredients were already
//! under test — and that is the point of this file:
//!
//! * `src/scanning/mod.rs` unit-tests every cut helper (`next_blocked_streak`,
//!   `dom_phase_should_early_exit`, …) in isolation, which says nothing about
//!   whether a cut fires while a real vulnerability is still undiscovered.
//! * `tests/functional/mock_cases/realworld/framework_error_pages.toml` has 5xx
//!   error-page cases, and other corpus files have `<title>` sinks — but no case
//!   combines them, and the corpus runner is `#[ignore]`d out of CI anyway.
//! * `mining::tests::test_probe_dictionary_params_sentinel_pre_probe_collapses`
//!   asserted the collapse for the whole life of the `any` bug, because it
//!   starts from an *empty* parameter set and so could never observe the
//!   deletion.
//!
//! So these two tests deliberately sit at the intersection: a target where the
//! cut *does* fire, and detection is only correct if it fires without taking
//! the finding with it. Both run by default — no `#[ignore]`.

use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, run_scan};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Two targets, each modelled on a real application:
///
/// `/boom` — a framework development error page. Kemal, Werkzeug, Rails and
/// Symfony all build the page title from the exception message, applications
/// build that message from user input (`raise "User #{name} not found"`), and
/// the response is a **500 by construction**. The sink is inside `<title>`, so
/// every ordinary HTML payload is echoed inert and only an end-tag breakout can
/// verify — the payload arrives well after the first response. That is exactly
/// the window in which a "the server is failing, give up" heuristic can eat the
/// finding. (Kemal GHSA-2x8p-5jvx-v7jw.)
///
/// `/echo` — a page that dumps every query parameter it received (escaped, so
/// the dump itself is inert) *and* reflects `name` into the document raw. The
/// dump makes an arbitrary parameter name appear to reflect, which is what
/// trips Stage 2's "this target echoes everything" collapse; `name` is the real
/// vulnerability the collapse must not take with it.
async fn spawn_app() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/boom",
            get(|q: Query<HashMap<String, String>>| async move {
                let name = q.get("name").cloned().unwrap_or_default();
                let mut names: Vec<&String> = q.keys().collect();
                names.sort();
                let dump: String = names
                    .iter()
                    .map(|k| {
                        format!(
                            "<dt>{}</dt><dd><pre>{}</pre></dd>",
                            escape(k),
                            escape(q.get(*k).map(String::as_str).unwrap_or(""))
                        )
                    })
                    .collect();
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    html_headers(),
                    // The shape these pages actually have: the message is raw in
                    // <title> (the sink) and escaped everywhere it is displayed,
                    // plus a dump of the request that echoes every parameter.
                    format!(
                        "<html><head><title>Internal Server Error at GET /boom - \
                         User '{name}' not found</title></head><body>\
                         <h1 class=\"title\">User '{escaped}' not found</h1>\
                         <div class=\"trace\"><pre>app.rb:42:in `lookup'\n  \
                         raise \"User '{escaped}' not found\"</pre></div>\
                         <h3>Query params</h3><dl>{dump}</dl></body></html>",
                        escaped = escape(&name)
                    ),
                )
            }),
        )
        .route(
            "/echo",
            get(|q: Query<HashMap<String, String>>| async move {
                let mut names: Vec<&String> = q.keys().collect();
                names.sort();
                let rows: String = names
                    .iter()
                    .map(|k| {
                        format!(
                            "<tr><td>{}</td><td>{}</td></tr>",
                            escape(k),
                            escape(q.get(*k).map(String::as_str).unwrap_or(""))
                        )
                    })
                    .collect();
                let raw = q.get("name").cloned().unwrap_or_default();
                (
                    html_headers(),
                    format!(
                        "<html><body><table>{rows}</table><div id=out>{raw}</div></body></html>"
                    ),
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

/// Discovery stays ON (the target's own `name` param is the point of both
/// tests); everything not under test is switched off to keep the runs quick.
fn base_args(target: &str, output: &Path) -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        output: Some(output.to_string_lossy().to_string()),
        silence: true,
        targets: vec![target.to_string()],
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        skip_waf_probe: true,
        skip_ast_analysis: true,
        insecure: Some(true),
        ..ScanArgs::default()
    }
}

fn read_findings(path: &Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).expect("output should exist");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    parsed["findings"]
        .as_array()
        .cloned()
        .unwrap_or_else(Vec::new)
}

fn summarize(findings: &[serde_json::Value]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            format!(
                "{}:{}",
                f["type"].as_str().unwrap_or("?"),
                f["param"].as_str().unwrap_or("?")
            )
        })
        .collect()
}

/// A 5xx that hands our payload back is a rendered error page, not a dead
/// server — DOM verification has to keep going long enough to reach the
/// breakout payload that escapes `<title>`.
///
/// Before the fix, every response scored `status >= 500`, `blocked_streak` hit
/// `BLOCKED_STREAK_LIMIT` (64) before any end-tag payload was tried, the DOM
/// phase quit, and this parameter could only ever be reported `[R]` — while
/// `--deep-scan`, which disables the cut, verified it.
#[tokio::test]
async fn error_page_rawtext_sink_is_verified_not_merely_reflected() {
    let (base, server) = spawn_app().await;
    let out = unique_temp_path("error-page-rawtext");
    let mut args = base_args(&format!("{}/boom?name=test", base), &out);
    // The sink is the URL's own parameter; mining would only add noise here.
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;

    let _ = run_scan(&args).await;
    server.abort();

    let findings = read_findings(&out);
    let _ = std::fs::remove_file(&out);

    assert!(
        findings
            .iter()
            .any(|f| f["type"] == "V" && f["param"] == "name"),
        "a 500 error page reflecting `name` into <title> must be VERIFIED, not just \
         reported reflected — got {:?}",
        summarize(&findings)
    );
}

/// Stage 2's collapse may fold away the parameters it mined itself; it may not
/// take the target's own parameters with them.
///
/// Before the fix, `/echo`'s parameter dump made all three sentinel probes
/// reflect, the collapse cleared every `Query` param, and the scan reported a
/// POC against the synthetic `any` — a parameter this application does not
/// have — while `name`, which discovery had already confirmed reflects, was
/// gone before the payload stages ever saw it.
#[tokio::test]
async fn reflect_everything_page_keeps_the_parameter_the_target_really_has() {
    let (base, server) = spawn_app().await;
    let out = unique_temp_path("reflect-everything");
    // Mining must run: the dictionary stage is what probes the sentinels and
    // fires the collapse. It stays cheap precisely because the collapse fires —
    // the wordlist is skipped after three probes.
    let args = base_args(&format!("{}/echo?name=test", base), &out);

    let _ = run_scan(&args).await;
    server.abort();

    let findings = read_findings(&out);
    let _ = std::fs::remove_file(&out);

    assert!(
        !findings.is_empty(),
        "the raw `name` reflection must still be found at all"
    );
    assert!(
        findings.iter().any(|f| f["param"] == "name"),
        "the collapse must not delete the parameter the target actually carries \
         — got {:?}",
        summarize(&findings)
    );
    assert!(
        findings
            .iter()
            .any(|f| f["type"] == "V" && f["param"] == "name"),
        "`name` reflects raw into the document, so it must verify — got {:?}",
        summarize(&findings)
    );
}
