//! Ad-hoc probe: measure outbound HTTP requests for several reflected-param
//! shapes. Not part of the regular suite (no `#[test]` runs unless invoked
//! by name); run with:
//!
//!   cargo test --test request_count_probe -- --nocapture --include-ignored
//!
//! Prints request counts per shape so we can compare the per-param budget
//! across plain reflection, kakao-shape (base64-of-JSON nested), JWT, and
//! URL-encoded JSON. The mock server is local and always reflects, so these
//! numbers represent the *favorable* path (early R/V short-circuit).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::{
    Router,
    extract::Query,
    response::{Html, IntoResponse},
    routing::get,
};

use dalfox::cmd::scan::{self, ScanArgs};

fn make_args() -> ScanArgs {
    ScanArgs {
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 10,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: true,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 5,
        max_concurrent_targets: 1,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: true,
        analyze_external_js: false,       
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
        max_payloads_per_param: 0,
    }
}

async fn handler_plain(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><body><p>Q: {q}</p></body></html>"
    ))
}

async fn handler_b64_json(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let qs = p.get("qs").cloned().unwrap_or_default();
    let v = STANDARD
        .decode(&qs)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
        .unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><body><p>{v}</p></body></html>"
    ))
}

async fn handler_jwt(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let token = p.get("token").cloned().unwrap_or_default();
    let segs: Vec<&str> = token.split('.').collect();
    let v = if segs.len() == 3 {
        URL_SAFE_NO_PAD
            .decode(segs[1])
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Html(format!(
        "<!DOCTYPE html><html><body><p>{v}</p></body></html>"
    ))
}

async fn handler_url_json(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let blob = p.get("blob").cloned().unwrap_or_default();
    let v = serde_json::from_str::<serde_json::Value>(&blob)
        .ok()
        .and_then(|v| v.get("q").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><body><p>{v}</p></body></html>"
    ))
}

/// Reflect-everything page: dumps every query parameter into the response
/// body. Without sentinel pre-collapse, dictionary mining would mark every
/// wordlist entry as reflected, ballooning Stage 3-6 cost into the
/// thousands of requests.
async fn handler_echo_all(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut body = String::from("<!DOCTYPE html><html><body>");
    for (k, v) in &p {
        body.push_str(&format!("<p>{k}={v}</p>"));
    }
    body.push_str("</body></html>");
    Html(body)
}

/// Reflects `q` inside an attribute value while stripping every `<` / `>`
/// byte from the input. The attribute context exposes autotrigger event
/// handler / quote-break payloads (no angle brackets needed), so a finding
/// is still reachable — but every raw `<svg…>` style payload becomes a
/// guaranteed miss. Used to measure the request savings from the
/// adaptive-prune step in `scanning/mod.rs::run_scanning` that drops raw
/// `<`/`>` payloads when `Param.invalid_specials` flags them.
async fn handler_filter_angles(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let stripped: String = q.chars().filter(|c| *c != '<' && *c != '>').collect();
    Html(format!(
        "<!DOCTYPE html><html><body><input value=\"{stripped}\"></body></html>"
    ))
}

async fn start_server() -> SocketAddr {
    let app = Router::new()
        .route("/plain", get(handler_plain))
        .route("/b64", get(handler_b64_json))
        .route("/jwt", get(handler_jwt))
        .route("/urljson", get(handler_url_json))
        .route("/echo_all", get(handler_echo_all))
        .route("/filter_angles", get(handler_filter_angles));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                tokio::time::sleep(Duration::from_secs(120)).await;
            })
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn measure(label: &str, target: String) {
    dalfox::REQUEST_COUNT.store(0, Ordering::Relaxed);
    let mut args = make_args();
    args.targets = vec![target.clone()];
    let out_path = std::env::temp_dir().join(format!("rcp_{}_{}.json", label, std::process::id()));
    args.output = Some(out_path.to_string_lossy().to_string());
    scan::run_scan(&args).await;
    let count = dalfox::REQUEST_COUNT.load(Ordering::Relaxed);
    let findings_n = std::fs::read_to_string(&out_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["findings"].as_array().map(|a| a.len()))
        .unwrap_or(0);
    let _ = std::fs::remove_file(&out_path);
    println!(
        "[{:14}] requests={:4}  findings={}  target={}",
        label, count, findings_n, target
    );
}

#[tokio::test]
#[ignore = "performance probe; run explicitly with --include-ignored"]
async fn measure_request_counts() {
    let addr = start_server().await;

    measure("plain_query", format!("http://{addr}/plain?q=hello")).await;

    let b64 = {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.encode(r#"{"name":"alice","domain":"k.com"}"#)
    };
    measure("b64_json", format!("http://{addr}/b64?qs={b64}")).await;

    let jwt = {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let p = URL_SAFE_NO_PAD.encode(r#"{"name":"alice","sub":"u"}"#);
        let s = URL_SAFE_NO_PAD.encode("sig");
        format!("{h}.{p}.{s}")
    };
    measure("jwt", format!("http://{addr}/jwt?token={jwt}")).await;

    let blob = urlencoding::encode(r#"{"q":"hello"}"#).to_string();
    measure("url_json", format!("http://{addr}/urljson?blob={blob}")).await;

    measure(
        "non_reflected",
        format!("http://{addr}/plain?other=ignored"),
    )
    .await;

    // Angle-filtering server: `<` / `>` get stripped, so any raw-angle
    // reflection payload is doomed. Stage 3 marks both chars as invalid
    // and the scanning hot path prunes them out, so the request budget
    // should be visibly smaller than `plain_query` even though both
    // produce one finding.
    measure(
        "angle_filtered",
        format!("http://{addr}/filter_angles?q=hello"),
    )
    .await;

    // Compare reflect-everything page with vs without dictionary mining
    // disabled by the user. With mining ON, the sentinel pre-probe should
    // catch the echo behavior and skip the wordlist.
    let mut args_mining_on = make_args();
    args_mining_on.skip_mining = false;
    args_mining_on.skip_mining_dict = false;
    args_mining_on.skip_mining_dom = false;
    measure_with(
        "echo_all (mining ON)",
        format!("http://{addr}/echo_all?seed=hi"),
        args_mining_on,
    )
    .await;

    let mut args_mining_off = make_args();
    args_mining_off.skip_mining = true;
    args_mining_off.skip_mining_dict = true;
    args_mining_off.skip_mining_dom = true;
    measure_with(
        "echo_all (mining OFF)",
        format!("http://{addr}/echo_all?seed=hi"),
        args_mining_off,
    )
    .await;

    // Larger wordlist to amplify the sentinel benefit. Without sentinel,
    // EWMA needs ≥15 attempts to collapse; with a 500-entry user wordlist
    // the chunk-of-500 spawns all 500 tasks in flight before any collapse
    // signal can stop them.
    let big_wordlist_path =
        std::env::temp_dir().join(format!("rcp_big_wordlist_{}.txt", std::process::id()));
    let entries: Vec<String> = (0..500).map(|i| format!("custom_word_{}", i)).collect();
    std::fs::write(&big_wordlist_path, entries.join("\n")).expect("write wordlist");

    let mut args_big_dict = make_args();
    args_big_dict.skip_mining = false;
    args_big_dict.skip_mining_dict = false;
    args_big_dict.skip_mining_dom = true;
    args_big_dict.silence = false;
    args_big_dict.mining_dict_word = Some(big_wordlist_path.to_string_lossy().to_string());
    measure_with(
        "echo_all (500-word dict)",
        format!("http://{addr}/echo_all?seed=hi"),
        args_big_dict,
    )
    .await;

    let _ = std::fs::remove_file(&big_wordlist_path);
}

async fn measure_with(label: &str, target: String, mut args: ScanArgs) {
    dalfox::REQUEST_COUNT.store(0, Ordering::Relaxed);
    args.targets = vec![target.clone()];
    let out_path = std::env::temp_dir().join(format!("rcp_{}_{}.json", label, std::process::id()));
    args.output = Some(out_path.to_string_lossy().to_string());
    scan::run_scan(&args).await;
    let count = dalfox::REQUEST_COUNT.load(Ordering::Relaxed);
    let findings_n = std::fs::read_to_string(&out_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["findings"].as_array().map(|a| a.len()))
        .unwrap_or(0);
    let _ = std::fs::remove_file(&out_path);
    println!(
        "[{:24}] requests={:5}  findings={}  target={}",
        label, count, findings_n, target
    );
}
