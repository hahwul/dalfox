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

struct CompareCase {
    name: &'static str,
    target_path: &'static str,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn xssmaze_dir() -> PathBuf {
    repo_root().join("xssmaze")
}

fn build_xssmaze_binary() -> PathBuf {
    let output_path = repo_root().join("target/tmp/xssmaze-compare-bin");
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

fn resolve_v2_binary() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("DALFOX_V2_BIN") {
        let path = PathBuf::from(custom);
        if path.exists() {
            return Some(path);
        }
    }

    let homebrew = PathBuf::from("/opt/homebrew/bin/dalfox");
    if homebrew.exists() {
        return Some(homebrew);
    }

    let output = Command::new("which")
        .arg("dalfox")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn assert_v2_binary(binary: &Path) {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .expect("run v2 baseline binary");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("v2."),
        "baseline binary must be Dalfox v2.x, got output: {combined}"
    );
}

fn extract_json_array(stdout: &str) -> Vec<Value> {
    // JSON output is now wrapped: {"meta": {...}, "findings": [...]}
    let start = stdout
        .lines()
        .position(|line| line.trim_start().starts_with('{') || line.trim_start().starts_with('['))
        .expect("dalfox stdout should contain JSON output");
    let json = stdout.lines().skip(start).collect::<Vec<_>>().join("\n");
    let v: Value = serde_json::from_str(&json).expect("dalfox output should be valid JSON");
    if let Some(findings) = v.get("findings") {
        findings.as_array().cloned().unwrap_or_default()
    } else {
        v.as_array().cloned().unwrap_or_default()
    }
}

fn meaningful_findings(findings: Vec<Value>) -> Vec<Value> {
    findings
        .into_iter()
        .filter(|finding| {
            finding
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                || finding
                    .get("inject_type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                || finding
                    .get("message_str")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
        })
        .collect()
}

fn run_v3_scan(target: &str) -> Vec<Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", "-S", "-f", "json", target])
        .output()
        .expect("run dalfox v3 scan");
    assert!(
        output.status.success(),
        "dalfox v3 scan failed for {target}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    meaningful_findings(extract_json_array(&String::from_utf8_lossy(&output.stdout)))
}

fn run_v2_scan(binary: &Path, target: &str) -> Vec<Value> {
    let output = Command::new(binary)
        .args(["url", "-S", "--format", "json", target])
        .output()
        .expect("run dalfox v2 scan");
    assert!(
        output.status.success(),
        "dalfox v2 scan failed for {target}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    meaningful_findings(extract_json_array(&String::from_utf8_lossy(&output.stdout)))
}

fn best_result_score(findings: &[Value]) -> u8 {
    findings
        .iter()
        .filter_map(|finding| finding.get("type").and_then(Value::as_str))
        .map(|result_type| match result_type {
            "V" => 3,
            "A" => 2,
            "R" => 1,
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

#[tokio::test]
#[ignore = "requires local xssmaze binary and a local dalfox v2 binary"]
async fn test_v3_is_not_worse_than_local_v2_on_xssmaze_subset() {
    let Some(v2_binary) = resolve_v2_binary() else {
        eprintln!("skipping: no local dalfox v2 baseline binary found");
        return;
    };
    assert_v2_binary(&v2_binary);

    let xssmaze_bin = repo_root().join("target/tmp/xssmaze-compare-bin");
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

    let parity_cases = [
        CompareCase {
            name: "basic reflected",
            target_path: "/basic/level1/?query=a",
        },
        CompareCase {
            name: "json reflected",
            target_path: "/json/level2/?query=a",
        },
        CompareCase {
            name: "inframe protocol",
            target_path: "/inframe/level1/?url=a",
        },
        CompareCase {
            name: "redirect protocol",
            target_path: "/redirect/level1/?query=a",
        },
        CompareCase {
            name: "browser state window.name",
            target_path: "/browser-state/level1/?seed=a",
        },
        CompareCase {
            name: "browser state localStorage",
            target_path: "/browser-state/level2/?seed=a",
        },
        CompareCase {
            name: "channel broadcast",
            target_path: "/channel/level1/?seed=a",
        },
        CompareCase {
            name: "advanced web components",
            target_path: "/advanced/level4/?query=a",
        },
        CompareCase {
            name: "advanced trusted types",
            target_path: "/advanced/level5/?query=a",
        },
        CompareCase {
            name: "advanced proxy object",
            target_path: "/advanced/level6/?query=a",
        },
        CompareCase {
            name: "template client-side render",
            target_path: "/template/level2/?query=a",
        },
        CompareCase {
            name: "template eval render",
            target_path: "/template/level3/?query=a",
        },
        CompareCase {
            name: "svg foreignobject",
            target_path: "/svg/level3/?query=a",
        },
        CompareCase {
            name: "stream eventsource",
            target_path: "/stream/level1/?seed=a",
        },
        CompareCase {
            name: "service worker bootstrap",
            target_path: "/service-worker/level1/?seed=a",
        },
        CompareCase {
            name: "service worker srcdoc bootstrap",
            target_path: "/service-worker/level2/?seed=a",
        },
        CompareCase {
            name: "history state",
            target_path: "/history-state/level1/?seed=a",
        },
        CompareCase {
            name: "history state object bootstrap",
            target_path: "/history-state/level2/?seed=a",
        },
        CompareCase {
            name: "websocket onmessage bootstrap",
            target_path: "/websocket/level6/?seed=a",
        },
        CompareCase {
            name: "eventsource onmessage bootstrap",
            target_path: "/websocket/level7/?seed=a",
        },
    ];

    for case in parity_cases {
        let target = format!("http://127.0.0.1:{port}{}", case.target_path);
        let v2_findings = run_v2_scan(&v2_binary, &target);
        let v3_findings = run_v3_scan(&target);
        let v2_score = best_result_score(&v2_findings);
        let v3_score = best_result_score(&v3_findings);

        assert!(
            v3_score > 0,
            "expected current dalfox v3 to find parity case {} ({}), got {:?}",
            case.name,
            target,
            v3_findings
        );
        assert!(
            v3_score >= v2_score,
            "expected current dalfox v3 to be at least as strong as local v2 for parity case {} ({}), v3_score={} v2_score={} v3_findings={:?} v2_findings={:?}",
            case.name,
            target,
            v3_score,
            v2_score,
            v3_findings,
            v2_findings
        );
    }

    let modern_cases = [
        CompareCase {
            name: "dom hash",
            target_path: "/dom/level2/",
        },
        CompareCase {
            name: "dom postMessage",
            target_path: "/dom/level23/",
        },
        CompareCase {
            name: "storage event newValue",
            target_path: "/storage-event/level1/?seed=a",
        },
        CompareCase {
            name: "storage event oldValue",
            target_path: "/storage-event/level2/?seed=a",
        },
        CompareCase {
            name: "browser state referrer bootstrap",
            target_path: "/browser-state/level5/?seed=a",
        },
        CompareCase {
            name: "referrer contextual fragment",
            target_path: "/referrer/level1/?seed=a",
        },
        CompareCase {
            name: "referrer template clone",
            target_path: "/referrer/level2/?seed=a",
        },
        CompareCase {
            name: "channel srcdoc relay",
            target_path: "/channel/level4/?seed=a",
        },
        CompareCase {
            name: "stream shared worker",
            target_path: "/stream/level3/?seed=a",
        },
        CompareCase {
            name: "reparse nested blob",
            target_path: "/reparse/level2/?blob=query=a",
        },
        CompareCase {
            name: "reparse blob html",
            target_path: "/reparse/level4/?blob=html=a",
        },
        CompareCase {
            name: "reparse double nested blob",
            target_path: "/reparse/level5/?blob=outer=query=a",
        },
    ];

    for case in modern_cases {
        let target = format!("http://127.0.0.1:{port}{}", case.target_path);
        let v2_findings = run_v2_scan(&v2_binary, &target);
        let v3_findings = run_v3_scan(&target);
        let v2_score = best_result_score(&v2_findings);
        let v3_score = best_result_score(&v3_findings);

        assert!(
            v3_score > v2_score,
            "expected current dalfox v3 to be strictly stronger than local v2 for modern case {} ({}), v3_score={} v2_score={} v3_findings={:?} v2_findings={:?}",
            case.name,
            target,
            v3_score,
            v2_score,
            v3_findings,
            v2_findings
        );
    }
}
