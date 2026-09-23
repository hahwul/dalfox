use super::*;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::parse_target;
use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, Uri};
use axum::response::Html;
use axum::routing::any;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        input_type: "url".to_string(),
        format: "json".to_string(),
        silence: true,
        workers: 4,
        max_concurrent_targets: 4,
        encoders: vec!["none".to_string()],
        skip_xss_scanning: true,
        waf_min_confidence: 0.0,
        ..Default::default()
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

async fn reflect_last_query_value(uri: Uri) -> String {
    uri.query()
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .filter(|(name, _)| name == "q")
        .last()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

async fn reflect_x_dual_header(headers: HeaderMap) -> String {
    headers
        .get("x-dual")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn same_named_header_and_cookie_keep_distinct_injection_locations() {
    // Headers and cookies share Location::Header in the parameter model. If a
    // target carries both with the same name, inferring cookie-ness from the
    // target alone misroutes the reflected header payload into Cookie.
    let app = Router::new().route("/", any(reflect_x_dual_header));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let mut target = parse_target(&format!("http://{addr}/")).expect("target parses");
    target
        .headers
        .push(("X-Dual".to_string(), "header-seed".to_string()));
    target
        .cookies
        .push(("X-Dual".to_string(), "cookie-seed".to_string()));

    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(2));
    check_header_discovery(&target, &args, reflection_params.clone(), semaphore.clone()).await;
    check_cookie_discovery(&target, &args, reflection_params.clone(), semaphore).await;
    {
        let mut params = reflection_params.lock().await;
        dedupe_reflection_params(&mut params);
    }

    let param = reflection_params
        .lock()
        .await
        .iter()
        .find(|param| param.name == "X-Dual" && param.location == Location::Header)
        .expect("header reflection should be discovered")
        .clone();
    let target = Arc::new(target);
    let client = target.build_client_or_default();
    let response =
        crate::scanning::url_inject::build_inject_request(&client, &target, &param, "PAY")
            .send()
            .await
            .expect("injection request should reach the mock server");
    assert_eq!(
        response.text().await.expect("read response"),
        "PAY",
        "the payload must be sent in the header slot that discovery found"
    );
}

#[tokio::test]
async fn query_discovery_reaches_last_value_duplicate_parameters() {
    // Some servers use the last occurrence of a repeated query key. Since the
    // scanner represents that key as one named parameter, its payload sender
    // must mutate every occurrence or only the first receives the payload.
    let app = Router::new().route("/", any(reflect_last_query_value));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/?q=first&q=last")).unwrap();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_query_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(1)),
    )
    .await;

    let params = reflection_params.lock().await;
    let param = params
        .iter()
        .find(|param| param.name == "q" && param.location == Location::Query)
        .expect("query discovery should find the repeated q parameter")
        .clone();
    drop(params);

    // Exercise the same sender the reflection and verification phases use,
    // including any pre-encoding discovery attached to the parameter. A
    // successful discovery alone is insufficient if scan payloads still land
    // only in the duplicate occurrence this server ignores.
    let target = Arc::new(target);
    let client = target.build_client_or_default();
    let payload = crate::encoding::pre_encoding::apply_param_encoding("PAY", &param);
    let response =
        crate::scanning::url_inject::build_inject_request(&client, &target, &param, &payload)
            .send()
            .await
            .expect("scan injection request should reach the mock server");
    let reflected = response.text().await.expect("read mock response");
    assert_eq!(
        reflected, "PAY",
        "the scanner payload must replace the value consumed by last-value servers"
    );
}

async fn reflect_only_double_slash_path(uri: Uri) -> String {
    if uri.path().contains("//") {
        format!("<body>{}</body>", uri.path())
    } else {
        "<body>no matching route</body>".to_string()
    }
}

#[tokio::test]
async fn path_discovery_preserves_empty_route_segments() {
    // Repeated slashes are empty path segments and can be part of a route.
    // This sink responds only on paths retaining the original `//`, so a
    // discovery request that flattens the path misses both path parameters.
    let app = Router::new().route("/{*rest}", any(reflect_only_double_slash_path));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/a//b/")).unwrap();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_path_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(1)),
    )
    .await;

    let params = reflection_params.lock().await;
    assert_eq!(
        params
            .iter()
            .filter(|param| param.location == Location::Path)
            .count(),
        2,
        "both non-empty path segments should be probed on the original route"
    );
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
    check_header_discovery(
        &target,
        &default_scan_args(),
        reflection_params.clone(),
        semaphore,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    let common_hit = names.iter().any(|n| {
        COMMON_PROBE_HEADERS
            .iter()
            .any(|h| n.eq_ignore_ascii_case(h))
    });
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
    check_header_discovery(
        &target,
        &default_scan_args(),
        reflection_params.clone(),
        semaphore,
    )
    .await;

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
    check_header_discovery(
        &target,
        &default_scan_args(),
        reflection_params.clone(),
        semaphore,
    )
    .await;

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
    check_cookie_discovery(
        &target,
        &default_scan_args(),
        reflection_params.clone(),
        semaphore,
    )
    .await;

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
    check_cookie_discovery(
        &target,
        &default_scan_args(),
        reflection_params.clone(),
        semaphore,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    assert_eq!(params.len(), 2);
    assert!(params.iter().any(|p| p.name == "session"));
    assert!(params.iter().any(|p| p.name == "theme"));
}

#[tokio::test]
async fn test_check_header_discovery_explicit_param_survives_skip_flag() {
    // Regression: `-p Name:header` is an explicit injection point and must be
    // probed even under `--skip-reflection-header`, which only disables the
    // blanket common-header sweep — not operator-named headers.
    let addr = start_discovery_mock_server().await;
    let target = parse_target(&format!("http://{}/reflect?q=1", addr)).unwrap();
    let mut args = default_scan_args();
    args.skip_reflection_header = true;
    args.param = vec!["X-Reflect-Me:header".to_string()];

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_header_discovery(&target, &args, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.name == "X-Reflect-Me" && p.location == Location::Header),
        "explicit -p X-Reflect-Me:header must be probed under --skip-reflection-header, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_check_header_discovery_skip_flag_without_explicit_is_noop() {
    // Control: with the sweep off and nothing explicit, no headers are probed.
    let addr = start_discovery_mock_server().await;
    let target = parse_target(&format!("http://{}/reflect?q=1", addr)).unwrap();
    let mut args = default_scan_args();
    args.skip_reflection_header = true;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_header_discovery(&target, &args, reflection_params.clone(), semaphore).await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_check_cookie_discovery_explicit_param_survives_skip_flag() {
    // Regression: `-p name:cookie` is probed even under
    // `--skip-reflection-cookie`; other supplied cookies stay suppressed.
    let addr = start_discovery_mock_server().await;
    let mut target = parse_target(&format!("http://{}/reflect", addr)).unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));
    target
        .cookies
        .push(("theme".to_string(), "dark".to_string()));
    target.delay = 1;
    let mut args = default_scan_args();
    args.skip_reflection_cookie = true;
    args.param = vec!["session:cookie".to_string()];

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_cookie_discovery(&target, &args, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params.iter().any(|p| p.name == "session"),
        "explicit -p session:cookie must be probed under --skip-reflection-cookie"
    );
    assert!(
        !params.iter().any(|p| p.name == "theme"),
        "non-explicit cookie must stay suppressed under --skip-reflection-cookie"
    );
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
        // Mirror a real "exploitable" 404 template: server decodes the
        // URL path (`%3C` → `<`) before emitting it into the response.
        // Without that decode, the bracket-survival probe used by
        // `check_path_discovery` correctly skips the endpoint as
        // structurally inert, which would defeat this test's intent.
        let decoded = urlencoding::decode(uri.path())
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| uri.path().to_string());
        (
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "<html><body><tr><th>URI:</th><td>{}</td></tr></body></html>",
                decoded
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

/// Mock that mimics the xssmaze 404 template: path echoed inside a
/// `<span>` text-content element with `<` / `>` HTML-entity-escaped.
/// The URL-attr-only filter keeps this candidate (text content, not a
/// URL attribute), so it's the bracket-survival probe that has to
/// reject it — without that gate, every 4xx error page like this
/// would burn the full payload set on guaranteed-negative requests.
async fn start_404_escaped_text_echo_mock_server() -> SocketAddr {
    async fn echo_404(uri: Uri) -> (axum::http::StatusCode, String) {
        // Decode the percent-encoded path first (mirrors a real
        // template's URL parsing) and then HTML-entity-escape the
        // brackets the way `html_escape`-style helpers do. The result:
        // the marker survives but `<MARKER>` shows up as `&lt;MARKER&gt;`,
        // so the structural probe should treat the segment as inert.
        let decoded = urlencoding::decode(uri.path())
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| uri.path().to_string());
        let escaped = decoded.replace('<', "&lt;").replace('>', "&gt;");
        (
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "<html><body><span class='path'>{}</span></body></html>",
                escaped
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
async fn test_check_path_discovery_drops_escaped_text_echo_404() {
    // xssmaze-style 404 page: server decodes `%3C` but then HTML-entity-
    // escapes the brackets before emitting them into text content. The
    // URL-attr-only filter keeps the candidate (it's not a URL attribute),
    // so this case is the bracket-survival probe's contract: `<MARKER>`
    // never appears literally in the response, so no tag-shaped payload
    // can ever land — discovery must skip the segment.
    let addr = start_404_escaped_text_echo_mock_server().await;
    let mut target = parse_target(&format!("http://{}/no/such/route", addr)).unwrap();
    target.delay = 1;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(Semaphore::new(1));
    check_path_discovery(&target, reflection_params.clone(), semaphore).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params.is_empty(),
        "bracket-escaped 404 echo must NOT surface path segments (got {:?})",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
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

    let reflection_params = Arc::new(Mutex::new(vec![Param::new(
        "path_segment_0".to_string(),
        "only".to_string(),
        Location::Path,
    )]));

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

#[test]
fn test_dedupe_collapses_same_name_location_pair() {
    let mut params = vec![
        Param {
            valid_specials: Some(vec!['<', '>']),
            invalid_specials: Some(vec!['"', '\'']),
            ..Param::new("query".to_string(), "v".to_string(), Location::Query)
        },
        Param {
            injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
            valid_specials: Some(vec!['<', '/']),
            invalid_specials: Some(vec!['"']),
            form_action_url: Some("https://x/y".to_string()),
            ..Param::new("query".to_string(), String::new(), Location::Query)
        },
    ];
    dedupe_reflection_params(&mut params);
    assert_eq!(params.len(), 1, "duplicates must collapse");
    // injection_context filled in from the second entry
    assert!(params[0].injection_context.is_some());
    // form_action_url filled in from the second entry
    assert_eq!(params[0].form_action_url.as_deref(), Some("https://x/y"));
    // valid_specials union: {<, >, /}
    let v = params[0].valid_specials.as_ref().unwrap();
    assert!(v.contains(&'<'));
    assert!(v.contains(&'>'));
    assert!(v.contains(&'/'));
    // invalid_specials intersection: only `"` (since `'` wasn't in the second set)
    let i = params[0].invalid_specials.as_ref().unwrap();
    assert!(i.contains(&'"'));
    assert!(!i.contains(&'\''));
}

#[test]
fn test_dedupe_keeps_different_locations_distinct() {
    let mut params = vec![
        Param::new("q".to_string(), String::new(), Location::Query),
        Param::new("q".to_string(), String::new(), Location::Body),
    ];
    dedupe_reflection_params(&mut params);
    assert_eq!(params.len(), 2);
}

#[test]
fn test_dedupe_is_noop_for_unique_entries() {
    let mut params = vec![
        Param::new("a".to_string(), String::new(), Location::Query),
        Param::new("b".to_string(), String::new(), Location::Query),
    ];
    let before = params.clone();
    dedupe_reflection_params(&mut params);
    assert_eq!(params.len(), 2);
    assert_eq!(params[0].name, before[0].name);
    assert_eq!(params[1].name, before[1].name);
}

#[test]
fn test_dedupe_fills_remaining_metadata_from_duplicate() {
    // The canonical (first) entry is bare; the duplicate carries every
    // optional carrier the merge is supposed to graft back in. Exercises
    // the js_breakout / framework_sink / pre_encoding / form_origin_url
    // carry-over branches plus the `None`-base arm of the char-set merge
    // helpers (the existing dedupe tests only cover Some+Some).
    let mut params = vec![
        Param::new("p".to_string(), "v".to_string(), Location::Query),
        Param {
            valid_specials: Some(vec!['<', '>']),
            invalid_specials: Some(vec!['"']),
            pre_encoding: Some("url".to_string()),
            form_origin_url: Some("https://origin/form".to_string()),
            framework_sink: Some("v-html".to_string()),
            js_breakout: Some("';alert(1)//".to_string()),
            ..Param::new("p".to_string(), String::new(), Location::Query)
        },
    ];
    dedupe_reflection_params(&mut params);
    assert_eq!(params.len(), 1, "same name+location must collapse");
    let merged = &params[0];
    assert_eq!(merged.js_breakout.as_deref(), Some("';alert(1)//"));
    assert_eq!(merged.framework_sink.as_deref(), Some("v-html"));
    assert_eq!(merged.pre_encoding.as_deref(), Some("url"));
    assert_eq!(
        merged.form_origin_url.as_deref(),
        Some("https://origin/form")
    );
    // None-base char-set merge takes the duplicate's set wholesale.
    assert_eq!(merged.valid_specials.as_deref(), Some(&['<', '>'][..]));
    assert_eq!(merged.invalid_specials.as_deref(), Some(&['"'][..]));
}

#[test]
fn test_dedupe_keeps_canonical_metadata_over_duplicate() {
    // When the canonical entry already carries a value, the duplicate's
    // competing value must not clobber it — guards the `is_none()` carry-over
    // gate against a future regression that blindly overwrites.
    let mut params = vec![
        Param {
            injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
            pre_encoding: Some("base-enc".to_string()),
            form_origin_url: Some("https://base/form".to_string()),
            framework_sink: Some("ng-bind-html".to_string()),
            js_breakout: Some("base-breakout".to_string()),
            ..Param::new("p".to_string(), "v".to_string(), Location::Query)
        },
        Param {
            injection_context: Some(crate::parameter_analysis::InjectionContext::Attribute(None)),
            pre_encoding: Some("dup-enc".to_string()),
            form_origin_url: Some("https://dup/form".to_string()),
            framework_sink: Some("v-html".to_string()),
            js_breakout: Some("dup-breakout".to_string()),
            ..Param::new("p".to_string(), String::new(), Location::Query)
        },
    ];
    dedupe_reflection_params(&mut params);
    assert_eq!(params.len(), 1);
    let merged = &params[0];
    assert_eq!(merged.pre_encoding.as_deref(), Some("base-enc"));
    assert_eq!(merged.js_breakout.as_deref(), Some("base-breakout"));
    assert_eq!(merged.framework_sink.as_deref(), Some("ng-bind-html"));
    assert_eq!(merged.form_origin_url.as_deref(), Some("https://base/form"));
}

#[test]
fn test_merge_char_sets_treats_none_as_unconstrained() {
    assert_eq!(merge_char_sets(None, Some(vec!['a'])), Some(vec!['a']));
    assert_eq!(merge_char_sets(Some(vec!['a']), None), Some(vec!['a']));
    assert_eq!(merge_char_sets(None, None), None);
    assert_eq!(merge_char_sets(Some(vec![]), None), Some(vec![]));
}

#[test]
fn test_merge_char_sets_unions_preserving_first_occurrence_order() {
    // Discovery inputs are internally unique; deduplication is needed across probes.
    assert_eq!(
        merge_char_sets(Some(vec!['>', '<']), Some(vec!['<', '/'])),
        Some(vec!['>', '<', '/'])
    );
}

#[test]
fn test_intersect_char_sets_treats_none_as_unconstrained() {
    assert_eq!(intersect_char_sets(None, Some(vec!['a'])), Some(vec!['a']));
    assert_eq!(intersect_char_sets(Some(vec!['a']), None), Some(vec!['a']));
    assert_eq!(intersect_char_sets(None, None), None);
}

#[test]
fn test_intersect_char_sets_keeps_only_shared_chars() {
    assert_eq!(
        intersect_char_sets(Some(vec!['a', 'b']), Some(vec!['b', 'c'])),
        Some(vec!['b'])
    );
    assert_eq!(
        intersect_char_sets(Some(vec!['a']), Some(vec!['b'])),
        Some(vec![])
    );
    assert_eq!(
        intersect_char_sets(Some(vec![]), Some(vec!['a'])),
        Some(vec![])
    );
}

// Exercises the pure `-p name:<type>` spec parser directly. In production it is
// only reached from async, network-bound discovery/mining call sites (issue
// #1202), so its four match-arm behaviors are asserted here in isolation.
#[test]
fn test_explicit_param_names() {
    // Matching type returns the name.
    assert_eq!(
        explicit_param_names(&["sid:cookie".to_string()], "cookie"),
        vec!["sid".to_string()],
    );

    // Mismatched type returns nothing.
    assert!(explicit_param_names(&["sid:cookie".to_string()], "header").is_empty());

    // Empty-name spec is rejected (guard `!name.is_empty()`).
    assert!(explicit_param_names(&[":header".to_string()], "header").is_empty());

    // A spec with no colon is rejected: the single-element slice fails the
    // `[name, ty, ..]` arity.
    assert!(explicit_param_names(&["foo".to_string()], "header").is_empty());

    // A trailing third field (`name:type:extra`) is tolerated by the `..` rest
    // pattern and still matches on the type.
    assert_eq!(
        explicit_param_names(&["file:multipart:extra".to_string()], "multipart"),
        vec!["file".to_string()],
    );

    // Multiple specs: only the matching-type entries are collected, in order.
    let specs = vec![
        "a:header".to_string(),
        "b:cookie".to_string(),
        "c:header".to_string(),
    ];
    assert_eq!(
        explicit_param_names(&specs, "header"),
        vec!["a".to_string(), "c".to_string()],
    );
}

/// Discovery fans its per-parameter probes out with `tokio::spawn`, and tokio
/// task-locals are NOT inherited across `spawn`. Before those workers re-entered
/// the captured scopes they wrote only to the process-wide globals, so a
/// REST/MCP job's `requests_sent` under-counted the discovery and mining phase
/// — and, the part that actually matters, those requests bypassed the per-job
/// rate limiter, letting a job submitted with `rate_limit: N` hammer the target
/// unthrottled for its whole analysis phase.
///
/// The assertion compares the per-job counter against what the server actually
/// received. Asserting merely `> 0` is NOT enough and does not fail without the
/// fix: `check_query_discovery` also issues several probes inline (outside any
/// spawn), and those tick the per-job counter either way.
#[tokio::test]
async fn spawned_discovery_requests_reach_the_per_job_counter() {
    crate::ensure_crypto_provider();

    // Count what the server truly received, independent of dalfox's bookkeeping.
    static SERVER_HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    SERVER_HITS.store(0, std::sync::atomic::Ordering::SeqCst);

    async fn counting_handler(uri: Uri) -> axum::response::Html<String> {
        SERVER_HITS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let q = uri.query().unwrap_or("").to_string();
        axum::response::Html(format!("<html><body><div>{q}</div></body></html>"))
    }

    let app = Router::new()
        .route("/", any(counting_handler))
        .route("/{*rest}", any(counting_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/?a=1&b=2&c=3")).expect("target");
    let per_job = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let params = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

    crate::REQUEST_COUNT_JOB
        .scope(per_job.clone(), async {
            check_query_discovery(
                &target,
                params.clone(),
                std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            )
            .await;
        })
        .await;

    let counted = per_job.load(std::sync::atomic::Ordering::Relaxed) as usize;
    let served = SERVER_HITS.load(std::sync::atomic::Ordering::SeqCst);
    assert!(served > 0, "the mock server should have been probed at all");
    // `>=` rather than `==`: `record_outbound_request()` ticks *before*
    // `send()`, so a request that fails at the transport layer is counted but
    // never served, and this repo has a documented ephemeral-port-exhaustion
    // flake class under parallel test runs. `>=` still fails loudly on the
    // regression (uncounted spawned workers give counted < served) without
    // turning an environment hiccup into a false regression report.
    assert!(
        counted >= served,
        "every request the server saw must be billed to the per-job counter; \
         {counted} counted vs {served} served means the spawned workers fell back \
         to the process-wide globals — which is also the rate-limit bypass"
    );
}

/// Serves a page holding one POST form whose `action` the test chooses, and
/// echoes any submitted body back so a probe that lands here reflects its
/// marker. The listener is bound before the HTML is built so an action can
/// point at this same server's port.
async fn start_form_page_server(make_action: impl FnOnce(SocketAddr) -> String) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind form page listener");
    let addr = listener.local_addr().expect("local addr");
    let html = format!(
        "<html><body><form action=\"{}\" method=\"POST\">\
         <input name=\"q\" value=\"search\">\
         <input name=\"user\" value=\"test\">\
         </form></body></html>",
        make_action(addr)
    );
    let app = Router::new()
        .route(
            "/",
            any(move || {
                let html = html.clone();
                async move { html }
            }),
        )
        .route(
            "/{*rest}",
            any(|body: String| async move { format!("echo {body}") }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

/// Stands in for the attacker's collector: counts every request it receives and
/// echoes the body, so a probe that reaches it both trips the counter and would
/// be recorded as a discovered parameter.
async fn start_foreign_origin_server(hits: Arc<std::sync::atomic::AtomicUsize>) -> SocketAddr {
    let app = Router::new().route(
        "/{*rest}",
        any(move |body: String| {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                format!("echo {body}")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind foreign listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

async fn discover_form_params(page: SocketAddr) -> Vec<Param> {
    let mut target = parse_target(&format!("http://{}/?q=test", page)).unwrap();
    target.delay = 1;
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_form_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(4)),
    )
    .await;
    reflection_params.lock().await.clone()
}

async fn reflect_get_form_route_state(uri: Uri) -> String {
    let pairs: Vec<(String, String)> = uri
        .query()
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let mode = pairs
        .iter()
        .find(|(name, _)| name == "mode")
        .map(|(_, value)| value.as_str());
    if mode == Some("search") {
        pairs
            .iter()
            .filter(|(name, _)| name == "q")
            .map(|(_, value)| value.as_str())
            .next_back()
            .unwrap_or("missing q")
            .to_string()
    } else {
        "missing route state".to_string()
    }
}

async fn reflect_first_q_or_form(uri: Uri) -> Html<String> {
    let first_q = uri
        .query()
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .find(|(name, _)| name == "q")
        .map(|(_, value)| value.into_owned());
    match first_q.as_deref() {
        Some("foo") => Html(
            "<html><body><form method=\"GET\"><input name=\"q\" value=\"seed\"></form></body></html>"
                .to_string(),
        ),
        Some(value) => Html(format!("<html><body>{value}</body></html>")),
        None => Html("<html><body>missing q</body></html>".to_string()),
    }
}

#[tokio::test]
async fn get_form_discovery_replaces_page_query_collision_for_first_value_server() {
    // An action-less GET form resolves to the page URL. If its `q` control is
    // appended to the page's `?q=foo`, a first-value server never sees the
    // probe marker and discovery misses the field.
    let app = Router::new().route("/", any(reflect_first_q_or_form));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first-value form listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/?q=foo")).expect("target parses");
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_form_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(4)),
    )
    .await;

    let param = reflection_params
        .lock()
        .await
        .iter()
        .find(|param| param.name == "q" && param.location == Location::Query)
        .expect("discovery must replace the action's first q value")
        .clone();
    let target = Arc::new(target);
    let client = target.build_client_or_default();
    let response =
        crate::scanning::url_inject::build_inject_request(&client, &target, &param, "PAY")
            .send()
            .await
            .expect("scan injection request should reach the page");
    assert_eq!(
        response.text().await.expect("read response"),
        "<html><body>PAY</body></html>",
        "the scan sender and discovery probe must both replace the colliding page query"
    );
}

#[tokio::test]
async fn get_form_discovery_preserves_action_query_for_probe_and_injection() {
    // Discovery and injection retain unrelated action-query state such as
    // `mode=search`; clearing it sends the probe to a different route.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind form listener");
    let addr = listener.local_addr().expect("local addr");
    let html = "<form action=\"/search?mode=search\" method=\"GET\"><input name=\"q\" value=\"seed\"></form>";
    let app = Router::new()
        .route("/", any(move || async move { html.to_string() }))
        .route("/{*rest}", any(reflect_get_form_route_state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/")).expect("target parses");
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_form_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(4)),
    )
    .await;

    let param = reflection_params
        .lock()
        .await
        .iter()
        .find(|param| param.name == "q" && param.location == Location::Query)
        .expect("GET form discovery should find q when action state is retained")
        .clone();
    assert!(
        param
            .form_action_url
            .as_deref()
            .is_some_and(|action| { action.contains("?mode=search") })
    );

    // Verify the ordinary payload request takes the same action URL and keeps
    // the route-state query that made discovery possible.
    let target = Arc::new(target);
    let client = target.build_client_or_default();
    let response =
        crate::scanning::url_inject::build_inject_request(&client, &target, &param, "PAY")
            .send()
            .await
            .expect("scan injection request should reach the form action");
    assert_eq!(response.text().await.expect("read response"), "PAY");
}

#[tokio::test]
async fn test_check_form_discovery_probes_same_origin_form_action() {
    // Relative and absolute spellings of the target's own origin both resolve
    // through `Url::join`, so both must survive the origin gate. This is the
    // control for the two skip tests below: without it they would still pass
    // if form discovery stopped working altogether.
    for action in ["/submit", "ABSOLUTE"] {
        let page = start_form_page_server(|addr| {
            if action == "ABSOLUTE" {
                format!("http://{}/submit", addr)
            } else {
                action.to_string()
            }
        })
        .await;

        let params = discover_form_params(page).await;
        // Assert the `Location`, not just the name: this two-field form also
        // trips the `fields.len() <= 3` JSON-body probe, which records every
        // field as `JsonBody` on a single reflecting response. Matching on the
        // name alone would stay green even if the per-field urlencoded POST
        // loop — the path this control exists to cover — stopped working.
        for field in ["q", "user"] {
            assert!(
                params
                    .iter()
                    .any(|p| p.name == field && p.location == Location::Body),
                "same-origin form action {action} should discover `{field}` as a \
                 urlencoded body param, got {:?}",
                params
                    .iter()
                    .map(|p| (&p.name, &p.location))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[tokio::test]
async fn test_check_form_discovery_skips_cross_origin_form_action() {
    // A scanned page that points its form at another origin must not make
    // dalfox send the operator's credentials there. The foreign server echoes,
    // so a regression shows up twice: as a request count and as a discovered
    // param carrying that host in `form_action_url`.
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let foreign = start_foreign_origin_server(hits.clone()).await;
    let page = start_form_page_server(|_| format!("http://{}/collect", foreign)).await;

    let params = discover_form_params(page).await;

    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no request may be sent to a cross-origin form action"
    );
    assert!(
        params.is_empty(),
        "a cross-origin form must not yield discovered params, got {:?}",
        params
            .iter()
            .map(|p| (&p.name, &p.form_action_url))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_check_form_discovery_skips_backslash_authority_form_action() {
    // `http://foreign\@page/submit` resolves — correctly, per WHATWG — to the
    // authority *before* the backslash, so it reaches `foreign` while reading
    // as if it named `page`. The gate compares parsed origins precisely so this
    // cannot slip through; a textual prefix check against the target URL would
    // let it past.
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let foreign = start_foreign_origin_server(hits.clone()).await;
    let page = start_form_page_server(|addr| format!("http://{}\\@{}/submit", foreign, addr)).await;

    let params = discover_form_params(page).await;

    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a backslash-authority action must not be probed either"
    );
    assert!(params.is_empty(), "got {:?}", params);
}

/// `MAX_FORM_FIELDS` must bound the GET-form branch too. It bounded only the
/// POST and multipart loops, so a hostile page could serve a GET form with tens
/// of thousands of inputs and buy one request per input — while the debug log
/// claimed only the first 200 were probed.
#[tokio::test]
async fn test_check_form_discovery_caps_get_form_fields() {
    const FIELDS: usize = 260;

    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let inputs: String = (0..FIELDS)
        .map(|i| format!("<input name=\"f{i}\" value=\"v\">"))
        .collect();
    let html =
        format!("<html><body><form action=\"/s\" method=\"GET\">{inputs}</form></body></html>");
    let app = Router::new()
        .route(
            "/",
            any(move || {
                let html = html.clone();
                async move { html }
            }),
        )
        .route(
            "/{*rest}",
            any(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    "no reflection here".to_string()
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let mut target = parse_target(&format!("http://{}/?q=test", addr)).unwrap();
    target.delay = 0;
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    check_form_discovery(
        &target,
        reflection_params.clone(),
        Arc::new(Semaphore::new(4)),
    )
    .await;

    let probed = hits.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        probed <= 201,
        "a {FIELDS}-field GET form must be capped at MAX_FORM_FIELDS probes \
         (plus the single JSON-body probe), got {probed}"
    );
}

/// Under `--sxss`, form fields are kept even when the write response does not
/// echo the probe (a stored sink answers "saved"), carrying the form URLs the
/// stored-XSS stages resolve their check URLs from. Without `--sxss` the same
/// non-echoing form still yields nothing.
#[tokio::test]
async fn test_check_form_discovery_keeps_unreflected_fields_only_when_asked() {
    use axum::{Router, response::Html, routing::get};
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(r#"<form action="/save" method="post"><input name="c"></form>"#) }),
        )
        .route("/save", axum::routing::post(|| async { Html("saved") }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let target = crate::target_parser::parse_target(&format!("http://{addr}/")).expect("target");

    for keep in [false, true] {
        let params = Arc::new(Mutex::new(Vec::new()));
        check_form_discovery_with(&target, params.clone(), Arc::new(Semaphore::new(4)), keep).await;
        let params = params.lock().await;
        let body: Vec<_> = params
            .iter()
            .filter(|p| p.location == Location::Body)
            .collect();
        if keep {
            assert_eq!(body.len(), 1, "{params:?}");
            assert_eq!(body[0].name, "c");
            assert_eq!(
                body[0].form_action_url.as_deref(),
                Some(format!("http://{addr}/save").as_str())
            );
            assert_eq!(
                body[0].form_origin_url.as_deref(),
                Some(format!("http://{addr}/").as_str())
            );
        } else {
            assert!(params.is_empty(), "{params:?}");
        }
    }
}
