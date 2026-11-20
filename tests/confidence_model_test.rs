//! Exercise confidence grading and tier rendering through the real CLI.
use axum::{Router, extract::Query, response::Html, routing::get};
use std::collections::HashMap;
use tokio::process::Command;

async fn scan(url: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let config = std::env::temp_dir().join(format!(
        "dalfox-confidence-{}-{}.toml",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&config, "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["scan", url, "--config"])
        .arg(&config)
        .args([
            "--format",
            "json",
            "--no-color",
            "-S",
            "--skip-mining",
            "--skip-discovery",
            "-p",
            "q",
            "--skip-reflection-header",
            "--skip-reflection-cookie",
            "--skip-reflection-path",
            "--skip-waf-probe",
            "--waf-bypass",
            "off",
            "--skip-ast-analysis",
            "--encoders",
            "none",
            "--timeout",
            "3",
            "--scan-timeout",
            "30",
        ])
        .args(extra)
        .output()
        .await
        .unwrap();
    std::fs::remove_file(config).unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid report: {e}: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), report)
}

#[tokio::test]
async fn reflection_delivery_grades_header_cookie_query_and_stored_header() {
    use axum::{extract::State, http::HeaderMap};
    use std::sync::Arc;
    let stored = Arc::new(tokio::sync::Mutex::new(String::new()));
    let app = Router::new()
        .route(
            "/",
            get(|Query(q): Query<HashMap<String, String>>, headers: HeaderMap| async move {
                let value = format!("{} {} {}",
                    q.get("q").map(String::as_str).unwrap_or(""),
                    headers.get("q").and_then(|v| v.to_str().ok()).unwrap_or(""),
                    headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("")
                );
                Html(format!("<html><body>{value}</body></html>"))
            }),
        )
        .route(
            "/write",
            get(|State(stored): State<Arc<tokio::sync::Mutex<String>>>, headers: HeaderMap| async move {
                *stored.lock().await = headers.get("q").unwrap().to_str().unwrap().to_string();
                Html("<html>saved</html>")
            }),
        )
        .route(
            "/read",
            get(|State(stored): State<Arc<tokio::sync::Mutex<String>>>| async move {
                Html(format!("<html><body>{}</body></html>", *stored.lock().await))
            }),
        )
        .with_state(stored);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let payload = std::env::temp_dir().join(format!(
        "dalfox-header-cookie-confidence-{}-{}.txt",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&payload, "<img src=x onerror=alert(1)>").unwrap();
    let read = format!("http://{addr}/read");
    for (path, options, grade, surface) in [
        (
            "/",
            vec!["-H", "q: seed", "-p", "q:header"],
            "low",
            "request header",
        ),
        (
            "/",
            vec!["--cookies", "q=seed", "-p", "q:cookie"],
            "low",
            "cookie",
        ),
        ("/?q=seed", vec![], "high", ""),
        (
            "/write",
            vec![
                "-H",
                "q: seed",
                "-p",
                "q:header",
                "--sxss",
                "--sxss-url",
                &read,
                "--sxss-retries",
                "1",
            ],
            "high",
            "",
        ),
    ] {
        let mut options = options;
        options.extend([
            "--custom-payload",
            payload.to_str().unwrap(),
            "--only-custom-payload",
            "--fail-on",
            "high",
        ]);
        let url = format!("http://{addr}{path}");
        let (code, report) = scan(&url, &options).await;
        assert_eq!(
            code,
            if grade == "high" { 1 } else { 0 },
            "{path}: {report}"
        );
        let rows = report["findings"].as_array().unwrap();
        assert!(!rows.is_empty(), "{path}: {report}");
        for row in rows {
            assert_eq!(row["type"], "V", "{row}");
            assert_eq!(row["severity"], "High", "{row}");
            assert_eq!(row["confidence"], grade, "{row}");
            if grade == "low" {
                assert_eq!(
                    row["confidence_reason"],
                    format!("injected through a {surface}; a link or form cannot deliver it")
                );
                assert_eq!(row["inject_type"], "inHTML");
            } else {
                assert!(
                    !row["confidence_reason"]
                        .as_str()
                        .unwrap()
                        .contains("a link or form")
                );
            }
        }
        if grade == "low" {
            let mut mapped_options = options.clone();
            mapped_options.extend(["--tier-model", "confidence"]);
            let (_, mapped) = scan(&url, &mapped_options).await;
            assert!(
                !mapped["findings"].as_array().unwrap().is_empty(),
                "{mapped}"
            );
            assert!(
                mapped["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["type"] == "R" && f["severity"] == "Info")
            );
            let mut filtered_options = options.clone();
            filtered_options.extend(["--min-confidence", "high", "--limit", "1"]);
            let (code, filtered) = scan(&url, &filtered_options).await;
            assert_eq!(code, 0, "{filtered}");
            assert!(filtered["findings"].as_array().unwrap().is_empty());
            let baseline = payload.with_extension("json");
            let mut previous = report.clone();
            for row in previous["findings"].as_array_mut().unwrap() {
                row["confidence"] = "high".into();
                row["confidence_reason"] = "previous grade".into();
            }
            std::fs::write(&baseline, previous.to_string()).unwrap();
            let mut baseline_options = options.clone();
            baseline_options.extend(["--baseline", baseline.to_str().unwrap()]);
            let (_, compared) = scan(&url, &baseline_options).await;
            assert!(
                compared["findings"].as_array().unwrap().is_empty(),
                "{compared}"
            );
            std::fs::remove_file(baseline).unwrap();
        }
    }
    // Both injection slots must survive, even though their display names match.
    let url = format!("http://{addr}/?q=seed");
    let options = [
        "-H",
        "q: seed",
        "-p",
        "q:header",
        "--custom-payload",
        payload.to_str().unwrap(),
        "--only-custom-payload",
    ];
    let (_, report) = scan(&url, &options).await;
    let rows = report["findings"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|f| f["location"] == "Header" && f["confidence"] == "low"),
        "{report}"
    );
    assert!(
        rows.iter()
            .any(|f| f["location"] == "Query" && f["confidence"] == "high"),
        "{report}"
    );
    let mut filtered_options = options.to_vec();
    filtered_options.extend(["--min-confidence", "high", "--limit", "1"]);
    let (code, filtered) = scan(&url, &filtered_options).await;
    assert_eq!(code, 1, "{filtered}");
    let rows = filtered["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{filtered}");
    assert_eq!(rows[0]["location"], "Query");
    std::fs::remove_file(payload).unwrap();
    server.abort();
}

#[tokio::test]
async fn response_csp_grades_reflection_without_changing_legacy_tiers() {
    let app = Router::new().route(
        "/",
        get(|Query(q): Query<HashMap<String, String>>| async move {
            let value = q.get("q").map(String::as_str).unwrap_or("");
            let mode = q.get("policy").map(String::as_str).unwrap_or("strict");
            let mut headers = axum::http::HeaderMap::new();
            // Preflight sees no restrictive policy for `dynamic`, while attack
            // responses do. `removed` proves absence on an attack response wins
            // over a restrictive preflight policy as well.
            let attack = value.contains('<') || value.contains("javascript:");
            if mode == "strict" || (mode == "dynamic" && attack) || (mode == "removed" && !attack) {
                headers.insert(
                    "content-security-policy",
                    "script-src 'self'; object-src 'none'; base-uri 'none'"
                        .parse()
                        .unwrap(),
                );
            } else if mode == "inline" {
                headers.insert(
                    "content-security-policy",
                    "script-src 'self' 'unsafe-inline'".parse().unwrap(),
                );
            } else if mode == "report" {
                headers.insert(
                    "content-security-policy-report-only",
                    "script-src 'self'".parse().unwrap(),
                );
            }
            (
                headers,
                Html(format!("<html><head></head><body>{value}</body></html>")),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for (policy, grade, exit) in [
        ("strict", "low", 0),
        ("inline", "high", 1),
        ("report", "high", 1),
        ("dynamic", "low", 0),
        ("removed", "high", 1),
    ] {
        let url = format!("http://{addr}/?q=seed&policy={policy}");
        let (code, report) = scan(&url, &["--fail-on", "high"]).await;
        assert_eq!(code, exit, "{policy}: {report}");
        let findings = report["findings"].as_array().unwrap();
        assert!(!findings.is_empty(), "{policy}: {report}");
        let verified = findings
            .iter()
            .find(|f| f["type"] == "V")
            .expect("legacy V retained");
        assert_eq!(verified["confidence"], grade, "{policy}: {verified}");
        assert_eq!(verified["severity"], "High");
        assert!(verified.get("request").is_none());
        assert!(verified.get("response").is_none());
        assert_eq!(report["meta"]["target_summary"][0]["status"], "findings");
        if grade == "low" {
            assert_eq!(
                verified["confidence_reason"],
                "CSP does not permit inline script"
            );
        }
        let (_, mapped) = scan(&url, &["--tier-model", "confidence"]).await;
        for f in mapped["findings"].as_array().unwrap() {
            assert_eq!(f["type"], if f["confidence"] == "high" { "V" } else { "R" });
            assert_eq!(
                f["severity"],
                if f["confidence"] == "high" {
                    "High"
                } else {
                    "Info"
                }
            );
        }
    }
    server.abort();
}

#[tokio::test]
async fn authorized_execution_contexts_keep_high_confidence() {
    let app = Router::new().route("/{kind}", get(|axum::extract::Path(kind): axum::extract::Path<String>, Query(q): Query<HashMap<String, String>>| async move {
        let q = q.get("q").map(String::as_str).unwrap_or("");
        let policy = match kind.as_str() {
            "attr" => "script-src 'nonce-test'; script-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'none'",
            "meta" => "",
            _ => "script-src 'nonce-test'; object-src 'none'; base-uri 'none'",
        };
        let html = match kind.as_str() {
            "js" => format!("<html><head><script nonce=test>var q='{q}';</script></head></html>"),
            "meta" => format!("<html><head>{q}<meta http-equiv=Content-Security-Policy content=\"script-src 'self'\"></head></html>"),
            "handler" => format!("<html><button onclick=\"var q='{q}';\">click</button></html>"),
            _ => format!("<html><body>{q}</body></html>"),
        };
        let mut headers = axum::http::HeaderMap::new();
        if !policy.is_empty() { headers.insert("content-security-policy", policy.parse().unwrap()); }
        (headers, Html(html))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for (kind, payload, expected) in [
        ("js", "';alert(1);//javascript:", "high"),
        ("attr", "<img src=x onerror=alert(1)>", "high"),
        ("nonce", "<script nonce=test>alert(1)</script>", "high"),
        ("wrongnonce", "<script nonce=wrong>alert(1)</script>", "low"),
        ("meta", "<script>alert(1)</script>", "high"),
        ("handler", "';alert(1);//", "low"),
    ] {
        let file = std::env::temp_dir().join(format!(
            "dalfox-confidence-payload-{kind}-{}.txt",
            std::process::id()
        ));
        std::fs::write(&file, payload).unwrap();
        let (code, report) = scan(
            &format!("http://{addr}/{kind}?q=seed"),
            &[
                "--fail-on",
                "high",
                "--custom-payload",
                file.to_str().unwrap(),
                "--only-custom-payload",
            ],
        )
        .await;
        std::fs::remove_file(file).unwrap();
        assert_eq!(
            code,
            if expected == "high" { 1 } else { 0 },
            "{kind}: {report}"
        );
        let rows = report["findings"].as_array().unwrap();
        assert!(
            rows.iter()
                .any(|r| r["type"] == "V" && r["confidence"] == expected),
            "{kind}: {report}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn stored_xss_uses_retrieval_csp_instead_of_write_csp() {
    use axum::{
        extract::{Path, State},
        http::HeaderMap,
    };
    use std::sync::Arc;
    let stored = Arc::new(tokio::sync::Mutex::new(String::new()));
    let app = Router::new()
        .route(
            "/write/{policy}",
            get(
                |Path(policy): Path<String>,
                 Query(q): Query<HashMap<String, String>>,
                 State(stored): State<Arc<tokio::sync::Mutex<String>>>| async move {
                    *stored.lock().await = q.get("q").cloned().unwrap_or_default();
                    let mut headers = HeaderMap::new();
                    if policy == "open" {
                        headers.insert(
                            "content-security-policy",
                            "script-src 'self'; object-src 'none'; base-uri 'none'"
                                .parse()
                                .unwrap(),
                        );
                    }
                    (headers, Html("<html>saved</html>"))
                },
            ),
        )
        .route(
            "/read/{policy}",
            get(
                |Path(policy): Path<String>,
                 State(stored): State<Arc<tokio::sync::Mutex<String>>>| async move {
                    let mut headers = HeaderMap::new();
                    if policy == "strict" {
                        headers.insert(
                            "content-security-policy",
                            "script-src 'self'; object-src 'none'; base-uri 'none'"
                                .parse()
                                .unwrap(),
                        );
                    }
                    (
                        headers,
                        Html(format!(
                            "<html><body>{}</body></html>",
                            *stored.lock().await
                        )),
                    )
                },
            ),
        )
        .with_state(stored);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let payload = std::env::temp_dir().join(format!(
        "dalfox-confidence-stored-{}.txt",
        std::process::id()
    ));
    std::fs::write(&payload, "<img src=x onerror=alert(1)>").unwrap();
    for (policy, grade, exit) in [("strict", "low", 0), ("open", "high", 1)] {
        let read = format!("http://{addr}/read/{policy}");
        let (code, report) = scan(
            &format!("http://{addr}/write/{policy}?q=seed"),
            &[
                "--sxss",
                "--sxss-url",
                &read,
                "--sxss-retries",
                "1",
                "--fail-on",
                "high",
                "--custom-payload",
                payload.to_str().unwrap(),
                "--only-custom-payload",
            ],
        )
        .await;
        assert_eq!(code, exit, "{policy}: {report}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["type"] == "V" && f["confidence"] == grade),
            "{policy}: {report}"
        );
    }
    std::fs::remove_file(payload).unwrap();
    server.abort();
}
