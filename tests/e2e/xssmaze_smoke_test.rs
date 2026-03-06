use serde_json::Value;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn xssmaze_dir() -> PathBuf {
    repo_root().join("xssmaze")
}

fn build_xssmaze_binary() -> PathBuf {
    let output_path = repo_root().join("target/tmp/xssmaze-smoke-bin");
    let status = Command::new("crystal")
        .args([
            "build",
            "src/xssmaze.cr",
            "-o",
            output_path.to_str().expect("utf-8 output path"),
        ])
        .current_dir(xssmaze_dir())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("build xssmaze binary");

    assert!(status.success(), "xssmaze build should succeed");
    output_path
}

fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent directory");
    }
}

fn reserve_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral port addr")
        .port()
}

async fn wait_for_xssmaze(port: u16) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("build reqwest client");
    let map_url = format!("http://127.0.0.1:{port}/map/json");

    for _ in 0..60 {
        if let Ok(resp) = client.get(&map_url).send().await
            && resp.status().is_success()
            && let Ok(body) = resp.text().await
            && body.contains("\"endpoints\"")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    panic!("xssmaze did not become ready at {map_url}");
}

fn extract_json_array(stdout: &str) -> Vec<Value> {
    let start = stdout
        .lines()
        .position(|line| line.trim_start().starts_with('['))
        .expect("dalfox stdout should contain a JSON array");
    let json = stdout.lines().skip(start).collect::<Vec<_>>().join("\n");
    serde_json::from_str::<Vec<Value>>(&json)
        .expect("dalfox output should be valid JSON")
        .into_iter()
        .filter(|item| item.get("type").and_then(Value::as_str).is_some())
        .collect()
}

fn run_dalfox_scan(extra_args: &[&str], target: &str) -> Vec<Value> {
    let mut args = vec!["scan", "-S", "-f", "json"];
    args.extend_from_slice(extra_args);
    args.push(target);

    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(&args)
        .output()
        .expect("run dalfox scan");

    assert!(
        output.status.success(),
        "dalfox scan failed for {target}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    extract_json_array(&String::from_utf8_lossy(&output.stdout))
}

fn assert_non_empty_scan(extra_args: &[&str], target: &str) -> Vec<Value> {
    let findings = run_dalfox_scan(extra_args, target);
    assert!(
        !findings.is_empty(),
        "expected findings for {target}, got none"
    );
    findings
}

struct SmokeCase {
    name: &'static str,
    extra_args: &'static [&'static str],
    target: String,
    expect_type: Option<&'static str>,
    expect_dom_hash_poc: bool,
    expect_evidence_contains: Option<&'static str>,
    expect_data_contains: Option<&'static str>,
    expect_message_contains: Option<&'static str>,
}

fn assert_smoke_case(case: &SmokeCase) {
    let findings = assert_non_empty_scan(case.extra_args, &case.target);

    if let Some(expected_type) = case.expect_type {
        let matched = findings.iter().any(|finding| {
            finding
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|actual_type| actual_type == expected_type)
        });
        assert!(
            matched,
            "expected finding type {expected_type:?} for {} ({}), got {findings:?}",
            case.name, case.target,
        );
    }

    if case.expect_dom_hash_poc {
        let dom_hash_poc = findings
            .iter()
            .find(|finding| {
                finding
                    .get("inject_type")
                    .and_then(Value::as_str)
                    .is_some_and(|inject_type| inject_type == "DOM-XSS")
            })
            .and_then(|finding| finding.get("data"))
            .and_then(Value::as_str)
            .unwrap_or("");
        assert!(
            dom_hash_poc.contains('#'),
            "expected DOM hash finding to include a fragment PoC URL for {} ({}), got {}",
            case.name,
            case.target,
            dom_hash_poc
        );
    }

    if let Some(needle) = case.expect_evidence_contains {
        let matched = findings.iter().any(|finding| {
            finding
                .get("evidence")
                .and_then(Value::as_str)
                .is_some_and(|evidence| evidence.contains(needle))
        });
        assert!(
            matched,
            "expected finding evidence containing {needle:?} for {} ({}), got {findings:?}",
            case.name, case.target,
        );
    }

    if let Some(needle) = case.expect_data_contains {
        let matched = findings.iter().any(|finding| {
            finding
                .get("data")
                .and_then(Value::as_str)
                .is_some_and(|data| data.contains(needle))
        });
        assert!(
            matched,
            "expected finding data containing {needle:?} for {} ({}), got {findings:?}",
            case.name, case.target,
        );
    }

    if let Some(needle) = case.expect_message_contains {
        let needle = needle.to_ascii_lowercase();
        let matched = findings.iter().any(|finding| {
            finding
                .get("message_str")
                .and_then(Value::as_str)
                .map(|message| message.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        });
        assert!(
            matched,
            "expected finding message containing {needle:?} for {} ({}), got {findings:?}",
            case.name, case.target,
        );
    }
}

#[tokio::test]
#[ignore = "requires local xssmaze binary and starts an external Crystal app"]
async fn test_cli_scans_xssmaze_json_endpoint_without_deep_scan() {
    let xssmaze_bin = repo_root().join("target/tmp/xssmaze-smoke-bin");
    ensure_parent_dir(&xssmaze_bin);
    let xssmaze_bin = build_xssmaze_binary();

    let port = reserve_port();
    let child = Command::new(&xssmaze_bin)
        .args(["-b", "127.0.0.1", "-p", &port.to_string()])
        .current_dir(xssmaze_dir())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn xssmaze");
    let _guard = ChildGuard { child };

    wait_for_xssmaze(port).await;

    let cases = vec![
        SmokeCase {
            name: "basic reflected",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/basic/level1/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "json reflected",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/json/level2/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "dom hash poc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level2/"),
            expect_type: None,
            expect_dom_hash_poc: true,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "polyglot comment breakout",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/polyglot/level1/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "advanced web components",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/advanced/level4/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "advanced trusted types",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/advanced/level5/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "advanced proxy object",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/advanced/level6/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "template client-side render",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/template/level2/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "template eval render",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/template/level3/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "svg foreignobject",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/svg/level3/?query=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "polyglot meta refresh",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/polyglot/level2/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "polyglot deep decode",
            extra_args: &["-e", "url,html,4url"],
            target: format!("http://127.0.0.1:{port}/polyglot/level3/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "polyglot deep decode 4url only",
            extra_args: &["-e", "4url"],
            target: format!("http://127.0.0.1:{port}/polyglot/level3/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "decode deep decode 4url only",
            extra_args: &["-e", "4url"],
            target: format!("http://127.0.0.1:{port}/decode/level3/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "inframe protocol payload priority",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/inframe/level1/?url=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("javascript%3Aalert%281%29"),
            expect_message_contains: Some("javascript:alert(1)"),
        },
        SmokeCase {
            name: "redirect protocol payload priority",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/redirect/level1/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: None,
            expect_data_contains: Some("javascript%3Aalert%281%29"),
            expect_message_contains: Some("javascript:alert(1)"),
        },
        SmokeCase {
            name: "dom referrer manual poc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level14/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("document.referrer"),
            expect_data_contains: None,
            expect_message_contains: Some("manual"),
        },
        SmokeCase {
            name: "dom cookie manual poc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level12/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("document.cookie"),
            expect_data_contains: None,
            expect_message_contains: Some("cookie"),
        },
        SmokeCase {
            name: "dom postmessage manual poc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level23/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("event.data"),
            expect_data_contains: None,
            expect_message_contains: Some("manual"),
        },
        SmokeCase {
            name: "dom pathname poc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level28/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("location.pathname"),
            expect_data_contains: Some("%3Cimg"),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "dom reparsing fragment sink",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level31/"),
            expect_type: None,
            expect_dom_hash_poc: true,
            expect_evidence_contains: Some("createContextualFragment"),
            expect_data_contains: None,
            expect_message_contains: None,
        },
        SmokeCase {
            name: "dom parser query source",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level32/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(query)"),
            expect_data_contains: Some("?query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "dom multi param query source",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/dom/level33/"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(query)"),
            expect_data_contains: Some("?query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "browser state window name",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/browser-state/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("window.name"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "browser state local storage",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/browser-state/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("localStorage.getItem"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "browser state session storage",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/browser-state/level3/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("sessionStorage.getItem"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "browser state postMessage relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/browser-state/level4/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("event.data"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "browser state referrer bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/browser-state/level5/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("document.referrer"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "referrer contextual fragment bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/referrer/level1/?seed=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("document.referrer"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("manual"),
        },
        SmokeCase {
            name: "referrer template clone bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/referrer/level2/?seed=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("document.referrer"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("manual"),
        },
        SmokeCase {
            name: "opener bootstrap innerhtml",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/opener/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("window.opener"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "opener bootstrap srcdoc",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/opener/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("window.opener"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "storage event newValue bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/storage-event/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("event.newValue"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "storage event oldValue bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/storage-event/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("event.oldValue"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "channel broadcast relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/channel/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("BroadcastChannel.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "channel message port relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/channel/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("MessagePort.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "channel worker relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/channel/level3/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("Worker.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "channel json srcdoc relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/channel/level4/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("BroadcastChannel.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "websocket onmessage bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/websocket/level6/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("WebSocket.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "eventsource onmessage bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/websocket/level7/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("EventSource.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "stream eventsource dispatch bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/stream/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("EventSource.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "stream websocket dispatch bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/stream/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("WebSocket.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "stream shared worker relay",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/stream/level3/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("SharedWorker.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "service worker dispatch bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/service-worker/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("ServiceWorker.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "service worker json srcdoc bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/service-worker/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("ServiceWorker.message"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "history state bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/history-state/level1/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("history.state"),
            expect_data_contains: Some("seed="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "history state object bootstrap",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/history-state/level2/?seed=a"),
            expect_type: Some("V"),
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("history.state"),
            expect_data_contains: Some("seed="),
            expect_message_contains: Some("self-bootstrap"),
        },
        SmokeCase {
            name: "reparse synthetic url query source",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/reparse/level1/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(query)"),
            expect_data_contains: Some("?query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "reparse nested blob flow",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/reparse/level2/?blob=query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(blob).get(query)"),
            expect_data_contains: Some("blob=query%3D"),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "reparse srcdoc wrapper",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/reparse/level3/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(query)"),
            expect_data_contains: Some("?query="),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "reparse nested blob srcdoc wrapper",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/reparse/level4/?blob=html=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(blob).get(html)"),
            expect_data_contains: Some("blob=html%3D"),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "reparse double nested blob flow",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/reparse/level5/?blob=outer=query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("URLSearchParams.get(blob).get(outer).get(query)"),
            expect_data_contains: Some("blob=outer%3Dquery%3D"),
            expect_message_contains: None,
        },
        SmokeCase {
            name: "service worker message flow",
            extra_args: &[],
            target: format!("http://127.0.0.1:{port}/advanced/level3/?query=a"),
            expect_type: None,
            expect_dom_hash_poc: false,
            expect_evidence_contains: Some("ServiceWorker.message"),
            expect_data_contains: None,
            expect_message_contains: Some("manual"),
        },
    ];

    for case in &cases {
        assert_smoke_case(case);
    }
}
