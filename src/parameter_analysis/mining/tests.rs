use super::*;
use crate::target_parser::parse_target;
use axum::{Router, extract::Query, response::Html, routing::get};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::{Duration, sleep};

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec!["http://127.0.0.1:1".to_string()],
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
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 1,
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
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
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
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

#[test]
fn test_mining_sample_stats_collapses_after_sustained_reflection() {
    let mut stats = MiningSampleStats::new();
    assert!(!stats.should_collapse());

    for _ in 0..15 {
        stats.record_attempt();
        stats.record_reflection();
    }

    assert!(stats.reflections >= 5);
    assert!(stats.attempts >= 15);
    assert!(stats.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD);
    assert!(stats.should_collapse());
}

#[test]
fn test_mining_sample_stats_non_reflection_keeps_low_ewma() {
    let mut stats = MiningSampleStats::new();
    for _ in 0..20 {
        stats.record_attempt();
        stats.record_non_reflection();
    }
    assert_eq!(stats.reflections, 0);
    assert!(!stats.should_collapse());
}

#[test]
fn test_detect_injection_context_without_marker_is_html() {
    let ctx = detect_injection_context("<html><body>plain</body></html>");
    assert_eq!(ctx, InjectionContext::Html(None));
}

#[test]
fn test_detect_injection_context_comment_delimiter() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<!-- {} -->", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(ctx, InjectionContext::Html(Some(DelimiterType::Comment)));
}

#[test]
fn test_detect_injection_context_script_single_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var x='{}';</script>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote))
    );
}

#[test]
fn test_detect_injection_context_attribute_double_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<img alt=\"{}\">", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote))
    );
}

#[test]
fn test_detect_injection_context_url_attribute_double_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<iframe src=\"{}\"></iframe>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote))
    );
}

#[tokio::test]
async fn test_probe_dictionary_params_returns_when_wordlist_file_missing() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.mining_dict_word = Some("/definitely/not/found/dalfox-wordlist.txt".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    probe_dictionary_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_probe_body_params_without_data_is_noop() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

    probe_body_params(&target, &args, reflection_params.clone(), semaphore, None).await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_probe_json_body_params_returns_for_invalid_or_non_object_data() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

    let mut invalid_json_args = default_scan_args();
    invalid_json_args.data = Some("{not-json".to_string());
    probe_json_body_params(
        &target,
        &invalid_json_args,
        reflection_params.clone(),
        semaphore.clone(),
        None,
    )
    .await;
    assert!(reflection_params.lock().await.is_empty());

    let mut non_object_json_args = default_scan_args();
    non_object_json_args.data = Some("[1,2,3]".to_string());
    probe_json_body_params(
        &target,
        &non_object_json_args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_mine_parameters_skip_mining_leaves_params_untouched() {
    let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = true;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_mine_parameters_dom_only_on_unreachable_target_does_not_panic() {
    let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = false;
    args.skip_mining_dict = true;
    args.skip_mining_dom = false;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    assert!(reflection_params.lock().await.is_empty());
}

async fn dom_mining_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let marker = params.get("search").cloned().unwrap_or_default();
    Html(format!(
        "<form><input id=\"search\" name=\"search\" value=\"seed\"></form><div>{}</div>",
        marker
    ))
}

async fn start_dom_mining_server() -> SocketAddr {
    let app = Router::new().route("/dom-mining", get(dom_mining_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_response_id_params_discovers_reflected_input_name() {
    let addr = start_dom_mining_server().await;
    let target = parse_target(&format!("http://{}:{}/dom-mining", addr.ip(), addr.port()))
        .expect("parse target");
    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

    probe_response_id_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(params.iter().any(|p| {
        p.name == "search"
            && p.location == Location::Query
            && p.value == crate::scanning::markers::bracketed_marker()
    }));
}
