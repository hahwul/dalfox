use super::*;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::parse_target;
use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, Uri};
use axum::routing::any;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
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
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        mining_dict_word: None,
        remote_wordlists: vec![],
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        timeout: 10,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 4,
        max_concurrent_targets: 4,
        max_targets_per_host: 100,
        encoders: vec!["none".to_string()],
        remote_payloads: vec![],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: true,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
    }
}

async fn discovery_reflect_handler(
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    uri: Uri,
) -> String {
    let mut values: Vec<String> = params.values().cloned().collect();
    values.sort();
    let query_values = values.join(",");
    let header_values: Vec<String> = headers
        .get_all("x-reflect-me")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();
    let header_value = header_values.join(",");
    let cookie_value = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    format!(
        "path={} query={} header={} cookie={}",
        uri.path(),
        query_values,
        header_value,
        cookie_value
    )
}

async fn start_discovery_mock_server() -> SocketAddr {
    let app = Router::new()
        .route("/", any(discovery_reflect_handler))
        .route("/{*rest}", any(discovery_reflect_handler));

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_check_query_discovery_discovers_reflection_and_extends_batch() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/reflect?a=1&b=2", addr)).unwrap();
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_query_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert_eq!(params.len(), 2);
    assert!(
        params
            .iter()
            .any(|p| p.name == "a" && p.location == Location::Query)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "b" && p.location == Location::Query)
    );
    assert!(params.iter().all(|p| p.valid_specials.is_some()));
    assert!(params.iter().all(|p| p.invalid_specials.is_some()));
}

/// Mock that mirrors xss-quiz.int21h.jp / phpinfo: every incoming
/// request header value is echoed into the response body. Used to
/// verify the blanket-echo differential filter.
async fn start_printenv_style_mock_server() -> SocketAddr {
    async fn echo_all_headers(headers: axum::http::HeaderMap) -> String {
        let mut out = String::from("<html><body><table>");
        for (k, v) in headers.iter() {
            let v = v.to_str().unwrap_or("");
            out.push_str(&format!(
                "<tr><th>HTTP_{}</th><td>{}</td></tr>",
                k.as_str().to_ascii_uppercase().replace('-', "_"),
                v
            ));
        }
        out.push_str("</table></body></html>");
        out
    }
    let app = Router::new()
        .route("/", any(echo_all_headers))
        .route("/{*rest}", any(echo_all_headers));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_check_header_discovery_blanket_echo_skips_default_probes() {
    // Site echoes every header back. Without the differential filter,
    // each of the 11 `COMMON_PROBE_HEADERS` becomes a noisy
    // reflection finding with identical payloads. The blanket-echo
    // guard should pre-detect this and skip the default probe set.
    let addr = start_printenv_style_mock_server().await;
    let target = parse_target(&format!("http://{}/", addr)).unwrap();

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_header_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    let common_hit = names
        .iter()
        .any(|n| COMMON_PROBE_HEADERS.iter().any(|h| n.eq_ignore_ascii_case(h)));
    assert!(
        !common_hit,
        "blanket-echo guard must suppress COMMON_PROBE_HEADERS probes (got {:?})",
        names
    );
}

#[tokio::test]
async fn test_check_header_discovery_blanket_echo_keeps_user_supplied_headers() {
    // Even on a blanket-echo site, an operator who explicitly passes
    // `-H "X-Reflect-Me: x"` is asking dalfox to look at that header.
    // Don't suppress that finding — it's user intent.
    let addr = start_printenv_style_mock_server().await;
    let mut target = parse_target(&format!("http://{}/", addr)).unwrap();
    target
        .headers
        .push(("X-Reflect-Me".to_string(), "orig".to_string()));

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_header_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params.iter().any(|p| p.name == "X-Reflect-Me"),
        "user-supplied X-Reflect-Me must survive blanket-echo suppression"
    );
}

#[tokio::test]
async fn test_check_header_discovery_discovers_reflected_header() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/reflect?q=1", addr)).unwrap();
    target
        .headers
        .push(("X-Reflect-Me".to_string(), "orig".to_string()));
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_header_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        !params.is_empty(),
        "should discover at least the explicit header"
    );
    let p = params
        .iter()
        .find(|p| p.name == "X-Reflect-Me")
        .expect("X-Reflect-Me should be discovered");
    assert_eq!(p.value, "orig");
    assert_eq!(p.location, Location::Header);
    assert!(p.injection_context.is_some());
}

#[tokio::test]
async fn test_check_cookie_discovery_single_cookie_branch() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "session");
    assert_eq!(params[0].location, Location::Header);
}

#[tokio::test]
async fn test_check_cookie_discovery_multiple_cookies_branch() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));
    target
        .cookies
        .push(("theme".to_string(), "dark".to_string()));
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_cookie_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert_eq!(params.len(), 2);
    assert!(params.iter().any(|p| p.name == "session"));
    assert!(params.iter().any(|p| p.name == "theme"));
}

#[tokio::test]
async fn test_check_path_discovery_discovers_reflected_segments() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/one/two", addr)).unwrap();
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_path_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert_eq!(params.len(), 2);
    assert!(
        params
            .iter()
            .any(|p| p.name == "path_segment_0" && p.value == "one")
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "path_segment_1" && p.value == "two")
    );
    assert!(params.iter().all(|p| p.location == Location::Path));
}

#[tokio::test]
async fn test_check_discovery_skip_discovery_true_keeps_empty() {
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/a/b?q=1", addr)).unwrap();
    target
        .headers
        .push(("X-Reflect-Me".to_string(), "orig".to_string()));
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    let mut args = default_scan_args();
    args.skip_discovery = true;

    check_discovery(&mut target, &args, reflection_params, semaphore).await;
    assert!(target.reflection_params.is_empty());
}

/// Mock that mimics Firing Range / App Engine 404 pages: any path that
/// doesn't match the known route returns 404 with the requested URI
/// echoed in an HTML `<td>...</td>` — exploitable text-content context.
async fn start_404_td_echo_mock_server() -> SocketAddr {
    async fn echo_404(uri: Uri) -> (axum::http::StatusCode, String) {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "<html><body><tr><th>URI:</th><td>{}</td></tr></body></html>",
                uri.path()
            ),
        )
    }
    async fn ok_root() -> &'static str {
        "ok"
    }
    let app = Router::new()
        .route("/", any(ok_root))
        .fallback(any(echo_404));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

/// Mock that mimics a generic 404 page echoing the path only inside an
/// `<a href>` breadcrumb — URL-attribute echo with no script-execution
/// surface, the noise pattern that should still be suppressed.
async fn start_404_anchor_echo_mock_server() -> SocketAddr {
    async fn echo_404(uri: Uri) -> (axum::http::StatusCode, String) {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "<html><body>Page not found. Try <a href=\"{}\">again</a>.</body></html>",
                uri.path()
            ),
        )
    }
    async fn ok_root() -> &'static str {
        "ok"
    }
    let app = Router::new()
        .route("/", any(ok_root))
        .fallback(any(echo_404));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_check_path_discovery_keeps_exploitable_404_td_echo() {
    // Firing-range / App Engine 404 template: URI rendered inside
    // `<td>...</td>`. Pre-TP-fix this was suppressed wholesale on
    // non-2xx; the scan-time filter had the same blanket drop.
    // Both paths now classify the response and KEEP the finding,
    // because `<td>` is plain text content and a `<svg/onload=...>`
    // payload would actually break out and execute.
    let addr = start_404_td_echo_mock_server().await;
    let mut target = parse_target(&format!("http://{}/no/such/route", addr)).unwrap();
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_path_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"path_segment_0"),
        "exploitable 404 td-echo path discovery must surface path_segment_0 (got {:?})",
        names
    );
}

#[tokio::test]
async fn test_check_path_discovery_drops_url_attr_only_404_echo() {
    // Generic 404 page that echoes the path only inside `<a href>` —
    // unexploitable URL echo. Discovery must continue to skip it
    // so we don't waste payload-set requests on noise.
    let addr = start_404_anchor_echo_mock_server().await;
    let mut target = parse_target(&format!("http://{}/no/such/route", addr)).unwrap();
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_path_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params.is_empty(),
        "url-attr-only 404 echo must NOT surface path segments (got {:?})",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_check_path_discovery_skips_existing_segment() {
    let target = {
        let mut t = parse_target("https://example.com/only").unwrap();
        t.timeout = 1;
        t
    };

    let reflection_params = Arc::new(Mutex::new(vec![Param {
        name: "path_segment_0".to_string(),
        value: "only".to_string(),
        location: Location::Path,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
    }]));

    let semaphore = Arc::new(Semaphore::new(1));

    let before_len = reflection_params.lock().await.len();
    check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
    let after_len = reflection_params.lock().await.len();

    assert_eq!(before_len, 1);
    assert_eq!(after_len, 1);
}

#[tokio::test]
async fn test_check_path_discovery_respects_semaphore_single_permit() {
    let target = {
        let mut t = parse_target("https://example.com/").unwrap();
        t.timeout = 1;
        t
    };

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));

    check_path_discovery(&target, reflection_params.clone(), semaphore.clone()).await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_check_discovery_skips_path_when_flag_set() {
    let mut target = parse_target("https://example.com/a/b").unwrap();
    target.timeout = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));

    let mut args = default_scan_args();
    args.workers = 1;
    args.max_concurrent_targets = 1;
    args.skip_reflection_path = true;

    check_discovery(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore.clone(),
    )
    .await;
    assert!(reflection_params.lock().await.is_empty());
}
