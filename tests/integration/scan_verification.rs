//! Integration tests: spin up a local vulnerable server, run dalfox scans,
//! and assert that findings match expectations.
//!
//! These tests are NOT #[ignore]'d so they run in CI via `cargo test`.
//!
//! Coverage matrix:
//!   - Reflected XSS: raw HTML, attribute, JS string, JS template literal,
//!     event handler, href/src URL attributes, textarea/title breakout,
//!     CSS context, HTML comment, unquoted attribute, multi-param
//!   - DOM XSS: innerHTML sink, document.write sink, location.hash source
//!   - POST body: form-encoded reflection
//!   - Encoding: server-side HTML-entity encoded reflection
//!   - Negative: alphanumeric-only strip, angle-bracket removal, static page

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Router,
    extract::{Form, Query},
    response::{Html, IntoResponse},
    routing::{get, post},
};

use dalfox::cmd::scan::{self, ScanArgs};

use crate::common::create_test_scan_args;

/// Monotonic counter for unique temp file names across parallel tests.
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Serializes every call to `scan::run_scan` in this binary. `run_scan`
/// resets the process-wide `REQUEST_COUNT` atomic at startup
/// (`src/cmd/scan.rs`), so any two overlapping scans race on that reset
/// — a `run_scan_and_count` assertion would observe `count = 0` if a
/// neighbouring `run_scan_and_collect` re-entered `run_scan` between
/// its store/load. See issue #939 (reproduced on Ubuntu CI).
static SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ===========================================================================
// Vulnerable endpoint handlers
// ===========================================================================

// --- Reflected: HTML body contexts ---

/// Raw reflection in HTML body (no sanitisation)
async fn vuln_reflected_raw(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Search</title></head>
<body><h1>Results</h1><p>You searched for: {q}</p></body></html>"#
    ))
}

/// Reflection inside `<textarea>` — requires breakout (`</textarea>`)
async fn vuln_textarea(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Note</title></head>
<body><textarea id="note">{q}</textarea></body></html>"#
    ))
}

/// Reflection inside `<title>` — requires breakout (`</title>`)
async fn vuln_title(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>{q}</title></head>
<body><p>Page</p></body></html>"#
    ))
}

/// Reflection inside HTML comment
async fn vuln_comment(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Comment</title></head>
<body><!-- user: {q} --><p>Page</p></body></html>"#
    ))
}

// --- Reflected: attribute contexts ---

/// Reflection inside a double-quoted attribute value
async fn vuln_attr_dq(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<input type="text" name="search" value="{q}"><p>Results</p></body></html>"#
    ))
}

/// Reflection inside a single-quoted attribute value
async fn vuln_attr_sq(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<img alt='{q}' src="/img.png"></body></html>"#
    ))
}

/// Reflection in an unquoted attribute
async fn vuln_attr_unquoted(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<div class={q}>content</div></body></html>"#
    ))
}

/// Reflection in `href` — URL attribute context (javascript: protocol injection)
async fn vuln_href(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<a href="{q}">Click here</a></body></html>"#
    ))
}

/// Reflection in `src` — URL attribute context (e.g. iframe/img src)
async fn vuln_iframe_src(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<iframe src="{q}"></iframe></body></html>"#
    ))
}

/// Reflection in event-handler attribute (`onerror`)
async fn vuln_event_handler(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<img src=x onerror="{q}"></body></html>"#
    ))
}

/// Reflection in form `action` attribute
async fn vuln_form_action(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<form action="{q}" method="GET"><input name="x"><button>Go</button></form></body></html>"#
    ))
}

// --- Reflected: JavaScript contexts ---

/// Reflection inside a double-quoted JavaScript string
async fn vuln_js_dq(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<script>var search = "{q}"; console.log(search);</script></body></html>"#
    ))
}

/// Reflection inside a single-quoted JavaScript string
async fn vuln_js_sq(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<script>var search = '{q}'; console.log(search);</script></body></html>"#
    ))
}

/// Reflection inside a JavaScript template literal
async fn vuln_js_template(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><body>\n\
         <script>const msg = `{q}`; console.log(msg);</script></body></html>"
    ))
}

/// Reflection directly inside a `<script>` block (no string wrapping)
async fn vuln_js_raw(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<script>{q}</script></body></html>"#
    ))
}

/// JSONP-style fixture: reflects the param as the callable identifier in a
/// pure-JS body served as application/javascript. `?q=alert(1);foo` becomes
/// `alert(1);foo({"data":1})` which executes the alert in the browser.
async fn vuln_jsonp_callback(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        format!("{q}({{\"data\":1}})"),
    )
}

/// Mirrors brutelogic c1 / c5: HTML-entity-encodes `'` and `<` of the param
/// and reflects inside a single-quoted JS string. Not exploitable: entities
/// don't decode inside `<script>`. Used to verify R suppression.
async fn safe_js_apos_encoded(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let encoded = q
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;");
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<script>var c1 = '{encoded}'; console.log(c1);</script></body></html>"#
    ))
}

/// Reflection in an inline event handler via HTML attribute
async fn vuln_inline_event(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><body>\n\
         <a href=\"/link\" onclick=\"handler('{q}')\">Link</a></body></html>"
    ))
}

// --- Reflected: CSS context ---

/// Reflection inside a `<style>` tag
async fn vuln_css_style(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><style>body {{ background: {q}; }}</style></head>
<body><p>Styled</p></body></html>"#
    ))
}

/// Reflection in inline `style` attribute
async fn vuln_css_inline(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<div style="color:{q}">Text</div></body></html>"#
    ))
}

// --- Reflected: server-side encoding ---

/// Server HTML-entity encodes `<` and `>` but NOT quotes — attribute breakout possible
async fn vuln_partial_encode(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let encoded = q.replace('<', "&lt;").replace('>', "&gt;");
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<input type="text" value="{encoded}">
<p>Searched: {encoded}</p></body></html>"#
    ))
}

// --- POST body ---

/// Reflected XSS via POST body parameter
async fn vuln_body_reflected(Form(p): Form<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("msg").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<div class="message">{q}</div></body></html>"#
    ))
}

// --- DOM XSS ---

/// DOM XSS: URLSearchParams → innerHTML
async fn vuln_dom_innerhtml(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<div id="output"></div>
<script>
var params = new URLSearchParams(window.location.search);
var q = params.get("q") || "{q}";
document.getElementById("output").innerHTML = q;
</script></body></html>"#
    ))
}

/// DOM XSS: location.hash → document.write
async fn vuln_dom_docwrite(Query(_p): Query<HashMap<String, String>>) -> impl IntoResponse {
    Html(
        r#"<!DOCTYPE html><html><body>
<script>
var data = decodeURIComponent(location.hash.substring(1));
document.write("<div>" + data + "</div>");
</script></body></html>"#
            .to_string(),
    )
}

/// DOM XSS: location.search → eval
async fn vuln_dom_eval(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<script>
var params = new URLSearchParams(window.location.search);
var code = params.get("q") || "{q}";
eval(code);
</script></body></html>"#
    ))
}

// --- Multi-param ---

/// Two reflected params in different contexts (HTML body + CSS inline)
async fn vuln_multi_param(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let name = p.get("name").cloned().unwrap_or_default();
    let color = p.get("color").cloned().unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<h1>{name}</h1><div style="color:{color}">Hello</div></body></html>"#
    ))
}

// --- Safe / negative endpoints ---

/// Input stripped to alphanumeric only — no XSS possible
async fn safe_stripped(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let stripped: String = q
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ')
        .collect();
    Html(format!(
        r#"<!DOCTYPE html><html><body><p>{stripped}</p></body></html>"#
    ))
}

/// Truncate input to 5 chars — too short for any payload to survive
async fn safe_truncated(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let truncated: String = q.chars().take(5).collect();
    Html(format!(
        r#"<!DOCTYPE html><html><body><p>{truncated}</p></body></html>"#
    ))
}

/// Strip the first 4 characters of every query value before reflecting.
/// Without bracketed-marker probing, Stage 0 would inject `dlx<8hex>` (11
/// chars), the server would echo only `<8hex>`, and the legacy
/// `text.contains(open_marker())` check would miss it. With the sandwich
/// probe (OPEN+INNER+CLOSE), the server still strips the first 4 bytes of
/// OPEN — but INNER and CLOSE survive, so `classify_probe_reflection`
/// reports `SuffixOnly` and the param is recorded.
async fn vuln_strip_prefix4(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let trimmed: String = q.chars().skip(4).collect();
    Html(format!(
        r#"<!DOCTYPE html><html><body><p>Echo: {trimmed}</p></body></html>"#
    ))
}

/// Strip the last 4 characters of every query value before reflecting —
/// mirror of `vuln_strip_prefix4`. With the sandwich probe, OPEN and
/// INNER survive while the trailing 4 bytes of CLOSE are removed, so
/// `classify_probe_reflection` reports `PrefixOnly`.
async fn vuln_strip_suffix4(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    let kept_chars = q.chars().count().saturating_sub(4);
    let trimmed: String = q.chars().take(kept_chars).collect();
    Html(format!(
        r#"<!DOCTYPE html><html><body><p>Echo: {trimmed}</p></body></html>"#
    ))
}

/// Extract a hex-only run from the input via regex `[0-9a-f]+` — drops
/// the `dlx`/`xld` prefixes/suffixes and `dlxmid` separator alike,
/// surfacing only the inner hex segments. The bracketed probe surfaces
/// at least the inner marker as a contiguous hex run, which the
/// classifier reports as `InnerOnly`.
async fn vuln_extract_hex(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = p.get("q").cloned().unwrap_or_default();
    // Naive hex extractor: keep the longest run of [0-9a-f].
    let mut best = String::new();
    let mut current = String::new();
    for c in q.chars() {
        if c.is_ascii_hexdigit() {
            current.push(c);
        } else {
            if current.len() > best.len() {
                best = current.clone();
            }
            current.clear();
        }
    }
    if current.len() > best.len() {
        best = current;
    }
    Html(format!(
        r#"<!DOCTYPE html><html><body><p>Hex: {best}</p></body></html>"#
    ))
}

/// Static page — no reflection at all
async fn safe_static() -> impl IntoResponse {
    Html(r#"<!DOCTYPE html><html><body><p>Hello, world!</p></body></html>"#.to_string())
}

/// Mock JWT-protected endpoint that does NOT verify the signature and
/// reflects a string field of the JWT payload into HTML. Represents the
/// real-world class where a frontend or proxy decodes the token for
/// display purposes without going through a verifying parser.
async fn vuln_jwt_unverified(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let token = p.get("token").cloned().unwrap_or_default();
    let segs: Vec<&str> = token.split('.').collect();
    let name = if segs.len() == 3 {
        URL_SAFE_NO_PAD
            .decode(segs[1])
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Welcome</title></head>
<body><h1>Hello, {name}</h1></body></html>"#
    ))
}

/// Mock endpoint receiving a parameter whose value is bare URL-encoded JSON
/// (no base64 layer). Reflects the `q` field from the decoded object into
/// HTML.
async fn vuln_url_json(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    let blob = p.get("blob").cloned().unwrap_or_default();
    let q = serde_json::from_str::<serde_json::Value>(&blob)
        .ok()
        .and_then(|v| v.get("q").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Search</title></head>
<body><p>Query: {q}</p></body></html>"#
    ))
}

/// Mirrors the shape of the unfixed kakaoinvestment endpoint:
/// `?qs=BASE64({"move_url":"...","acc_domain":"...","auth_domain":"..."})`
/// where the server decodes/parses the JSON and reflects the `move_url`
/// field verbatim into the HTML response. Both legacy single-step base64
/// pre-encoding and a plain-string `qs` fail the reflection check; only
/// the nested-pipeline probe should discover this parameter.
async fn vuln_b64_json_field(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let qs = p.get("qs").cloned().unwrap_or_default();
    let move_url = STANDARD
        .decode(&qs)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("move_url").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_default();
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Auth</title></head>
<body><p>Redirecting to: {move_url}</p></body></html>"#
    ))
}

// ===========================================================================
// Test server setup
// ===========================================================================

async fn start_test_server() -> SocketAddr {
    let app = Router::new()
        // Reflected: HTML body
        .route("/reflected", get(vuln_reflected_raw))
        .route("/textarea", get(vuln_textarea))
        .route("/title", get(vuln_title))
        .route("/comment", get(vuln_comment))
        // Reflected: attribute
        .route("/attr/dq", get(vuln_attr_dq))
        .route("/attr/sq", get(vuln_attr_sq))
        .route("/attr/unquoted", get(vuln_attr_unquoted))
        .route("/attr/href", get(vuln_href))
        .route("/attr/iframe-src", get(vuln_iframe_src))
        .route("/attr/event", get(vuln_event_handler))
        .route("/attr/form-action", get(vuln_form_action))
        // Reflected: JS
        .route("/js/dq", get(vuln_js_dq))
        .route("/js/sq", get(vuln_js_sq))
        .route("/js/template", get(vuln_js_template))
        .route("/js/raw", get(vuln_js_raw))
        .route("/js/inline-event", get(vuln_inline_event))
        .route("/safe/js-apos-encoded", get(safe_js_apos_encoded))
        .route("/jsonp", get(vuln_jsonp_callback))
        // Reflected: CSS
        .route("/css/style", get(vuln_css_style))
        .route("/css/inline", get(vuln_css_inline))
        // Reflected: encoding
        .route("/encode/partial", get(vuln_partial_encode))
        // POST body
        .route("/body", post(vuln_body_reflected))
        // DOM XSS
        .route("/dom/innerhtml", get(vuln_dom_innerhtml))
        .route("/dom/docwrite", get(vuln_dom_docwrite))
        .route("/dom/eval", get(vuln_dom_eval))
        // Multi-param
        .route("/multi", get(vuln_multi_param))
        // Partial reflection: prefix/suffix strip and regex extract
        .route("/strip/prefix4", get(vuln_strip_prefix4))
        .route("/strip/suffix4", get(vuln_strip_suffix4))
        .route("/extract/hex", get(vuln_extract_hex))
        // Nested encoding: base64-of-JSON with leaf-field reflection
        .route("/auth/authentication.cm", get(vuln_b64_json_field))
        // Nested encoding: JWT (unverified signature) with payload-field reflection
        .route("/auth/jwt", get(vuln_jwt_unverified))
        // Nested encoding: bare URL-encoded JSON
        .route("/api/blob", get(vuln_url_json))
        // Safe / negative
        .route("/safe/stripped", get(safe_stripped))
        .route("/safe/truncated", get(safe_truncated))
        .route("/safe/static", get(safe_static));

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                tokio::time::sleep(Duration::from_secs(300)).await;
            })
            .await
            .ok();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Build `ScanArgs` tuned for fast, focused integration testing.
fn base_scan_args() -> ScanArgs {
    let mut args = create_test_scan_args();
    args.input_type = "url".to_string();
    args.silence = true;
    args.no_color = true;
    args.skip_mining = true;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.skip_reflection_header = true;
    args.skip_reflection_cookie = true;
    args.skip_reflection_path = true;
    args.skip_ast_analysis = true;
    args.workers = 5;
    args.max_concurrent_targets = 5;
    args
}

/// Run a scan and return the JSON findings array.
async fn run_scan_and_collect(mut args: ScanArgs) -> Vec<serde_json::Value> {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let out_path = std::env::temp_dir().join(format!("dalfox_scan_verify_{id}.json"));
    args.output = Some(out_path.to_string_lossy().to_string());

    let _guard = SCAN_LOCK.lock().await;
    scan::run_scan(&args).await;

    let content = match std::fs::read_to_string(&out_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let _ = std::fs::remove_file(&out_path);

    let v: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    // JSON output is now wrapped: {"meta": {...}, "findings": [...]}
    v["findings"].as_array().cloned().unwrap_or_default()
}

/// Like `run_scan_and_collect` but also resets and reads `REQUEST_COUNT`
/// so callers can assert that the scan actually progressed past the
/// early no-reflection short-circuit (~10 requests).
async fn run_scan_and_count(mut args: ScanArgs) -> (Vec<serde_json::Value>, u64) {
    use std::sync::atomic::Ordering as AtomicOrdering;
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let out_path = std::env::temp_dir().join(format!("dalfox_scan_count_{id}.json"));
    args.output = Some(out_path.to_string_lossy().to_string());

    let _guard = SCAN_LOCK.lock().await;
    dalfox::REQUEST_COUNT.store(0, AtomicOrdering::Relaxed);
    scan::run_scan(&args).await;
    let count = dalfox::REQUEST_COUNT.load(AtomicOrdering::Relaxed);

    let findings = std::fs::read_to_string(&out_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v["findings"].as_array().cloned())
        .unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    (findings, count)
}

/// Assert at least one finding exists, with a descriptive label on failure.
fn assert_detected(findings: &[serde_json::Value], context: &str) {
    assert!(
        !findings.is_empty(),
        "[{context}] expected XSS detection but got no findings"
    );
}

/// Assert zero findings, with debug output on failure.
fn assert_not_detected(findings: &[serde_json::Value], context: &str) {
    assert!(
        findings.is_empty(),
        "[{context}] expected no findings but got: {:?}",
        findings
    );
}

/// Assert at least one finding of the given short type ("V", "R", "A").
fn assert_has_type(findings: &[serde_json::Value], expected: &str, context: &str) {
    let any = findings
        .iter()
        .any(|f| f["type"].as_str() == Some(expected));
    assert!(
        any,
        "[{context}] expected at least one '{expected}' finding, got: {:?}",
        findings
            .iter()
            .map(|f| f["type"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

// ===========================================================================
// Tests — Reflected XSS: HTML body contexts
// ===========================================================================

#[tokio::test]
async fn test_reflected_raw_html() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/reflected?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "raw HTML body");
}

#[tokio::test]
async fn test_reflected_textarea_breakout() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/textarea?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "textarea breakout (</textarea>)",
    );
}

#[tokio::test]
async fn test_reflected_title_breakout() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/title?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "title breakout (</title>)",
    );
}

#[tokio::test]
async fn test_reflected_html_comment() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/comment?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "HTML comment context");
}

// ===========================================================================
// Tests — Reflected XSS: attribute contexts
// ===========================================================================

#[tokio::test]
async fn test_reflected_attr_double_quote() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/dq?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "double-quoted attribute value",
    );
}

#[tokio::test]
async fn test_reflected_attr_single_quote() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/sq?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "single-quoted attribute value",
    );
}

#[tokio::test]
async fn test_reflected_attr_unquoted() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/unquoted?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "unquoted attribute value",
    );
}

#[tokio::test]
async fn test_reflected_href_attribute() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/href?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "href URL attribute (javascript: protocol)",
    );
}

#[tokio::test]
async fn test_reflected_iframe_src_attribute() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/iframe-src?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "iframe src URL attribute",
    );
}

#[tokio::test]
async fn test_reflected_event_handler_attribute() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/event?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "event handler attribute (onerror)",
    );
}

#[tokio::test]
async fn test_reflected_form_action() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/attr/form-action?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "form action attribute");
}

// ===========================================================================
// Tests — Reflected XSS: JavaScript contexts
// ===========================================================================

#[tokio::test]
async fn test_reflected_js_double_quote_string() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/dq?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "JS double-quoted string");
}

#[tokio::test]
async fn test_reflected_js_single_quote_string() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/sq?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "JS single-quoted string");
}

#[tokio::test]
async fn test_reflected_js_template_literal() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/template?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "JS template literal");
}

#[tokio::test]
async fn test_reflected_js_raw_script_block() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/raw?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "raw <script> block");
}

#[tokio::test]
async fn test_reflected_inline_event_js() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/inline-event?q=test")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "inline onclick handler JS string",
    );
}

#[tokio::test]
async fn test_js_double_quote_string_upgrades_to_verified() {
    // The JS-context AST verifier should upgrade a R finding to V when the
    // injected breakout produces a real sink call inside the script body.
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/dq?q=test")];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "JS double-quoted string");
    assert_has_type(
        &findings,
        "V",
        "JS double-quoted string should produce a Verified finding via JS-context AST",
    );
}

#[tokio::test]
async fn test_js_single_quote_string_upgrades_to_verified() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/js/sq?q=test")];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "JS single-quoted string");
    assert_has_type(
        &findings,
        "V",
        "JS single-quoted string should produce a Verified finding via JS-context AST",
    );
}

#[tokio::test]
async fn test_jsonp_callback_endpoint_yields_verified() {
    // application/javascript response with payload reflected as the callable
    // identifier — JSONP-style XSS. JS-context AST fallback should produce V.
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/jsonp?q=test")];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "JSONP callback");
    assert_has_type(
        &findings,
        "V",
        "JSONP callback reflection should produce V via JS-context fallback",
    );
}

#[tokio::test]
async fn test_inert_js_apos_encoded_reflection_is_not_reported() {
    // Mirrors brutelogic c1 / c5: server HTML-encodes `'` and `<` before
    // reflecting into a JS string. Inside <script> entities don't decode,
    // so the reflection is text only and must NOT yield any finding.
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/safe/js-apos-encoded?q=test")];
    let findings = run_scan_and_collect(args).await;
    assert_not_detected(
        &findings,
        "entity-encoded JS-string reflection should be classified inert",
    );
}

// ===========================================================================
// Tests — Reflected XSS: CSS contexts
// ===========================================================================

#[tokio::test]
async fn test_reflected_css_style_tag() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/css/style?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "<style> tag context");
}

#[tokio::test]
async fn test_reflected_css_inline_style() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/css/inline?q=test")];
    assert_detected(&run_scan_and_collect(args).await, "inline style attribute");
}

// ===========================================================================
// Tests — Reflected XSS: encoding edge cases
// ===========================================================================

#[tokio::test]
async fn test_reflected_partial_encode_angle_only() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/encode/partial?q=test")];
    // Server encodes < > but NOT quotes — attribute breakout should still work
    assert_detected(
        &run_scan_and_collect(args).await,
        "partial encoding (angles only, quotes open)",
    );
}

// ===========================================================================
// Tests — POST body
// ===========================================================================

#[tokio::test]
async fn test_body_reflected_xss() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/body")];
    args.method = "POST".to_string();
    args.data = Some("msg=test".to_string());
    // Body param discovery requires probe_body_params in mining phase
    // (gated by skip_mining_dict; see src/parameter_analysis/mining.rs:1152)
    args.skip_mining = false;
    args.skip_mining_dict = false;
    args.skip_mining_dom = true;
    assert_detected(&run_scan_and_collect(args).await, "POST body param");
}

// ===========================================================================
// Tests — DOM XSS (AST analysis)
// ===========================================================================

#[tokio::test]
async fn test_dom_xss_innerhtml_sink() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/dom/innerhtml?q=test")];
    args.skip_ast_analysis = false;
    assert_detected(
        &run_scan_and_collect(args).await,
        "DOM XSS: URLSearchParams → innerHTML",
    );
}

#[tokio::test]
async fn test_dom_xss_document_write_sink() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/dom/docwrite?q=test")];
    args.skip_ast_analysis = false;
    assert_detected(
        &run_scan_and_collect(args).await,
        "DOM XSS: location.hash → document.write",
    );
}

#[tokio::test]
async fn test_dom_xss_eval_sink() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/dom/eval?q=test")];
    args.skip_ast_analysis = false;
    assert_detected(
        &run_scan_and_collect(args).await,
        "DOM XSS: URLSearchParams → eval",
    );
}

// ===========================================================================
// Tests — Multi-parameter
// ===========================================================================

#[tokio::test]
async fn test_multi_param_xss() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/multi?name=test&color=red")];
    assert_detected(
        &run_scan_and_collect(args).await,
        "multi-param (HTML body + CSS inline)",
    );
}

// ===========================================================================
// Tests — Negative / false-positive guards
// ===========================================================================

#[tokio::test]
async fn test_safe_stripped_no_fp() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/safe/stripped?q=test")];
    assert_not_detected(&run_scan_and_collect(args).await, "alphanumeric-only strip");
}

#[tokio::test]
async fn test_safe_truncated_no_fp() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/safe/truncated?q=test")];
    assert_not_detected(
        &run_scan_and_collect(args).await,
        "truncated to 5 chars (payload can't fit)",
    );
}

#[tokio::test]
async fn test_safe_static_no_fp() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/safe/static?q=test")];
    assert_not_detected(
        &run_scan_and_collect(args).await,
        "static page, no reflection",
    );
}

// ===========================================================================
// Tests — Nested encoding (base64-of-JSON with leaf field reflection)
// ===========================================================================

/// Mirrors the unfixed kakaoinvestment auth/authentication.cm shape:
/// `?qs=BASE64({"move_url":"...", ...})` reflects the `move_url` value into
/// HTML. Plain and single-step base64 probes both miss this — discovery has
/// to peek inside the parameter value, recognise the JSON structure, and
/// register `qs.move_url` as a virtual sub-parameter with a composable
/// `JsonField → Base64` pre-encoding pipeline.
#[tokio::test]
async fn test_nested_b64_json_field_xss() {
    let addr = start_test_server().await;
    // Base64-encoded JSON identical in shape to the real-world payload.
    let qs_value = "eyJtb3ZlX3VybCI6ICJhcyIsICJhY2NfZG9tYWluIjogImtha2FvaW52ZXN0bWVudC5jb20iLCAiYXV0aF9kb21haW4iOiAiZW4ua2FrYW9pbnZlc3RtZW50LmNvbSJ9";
    let mut args = base_scan_args();
    args.targets = vec![format!(
        "http://{addr}/auth/authentication.cm?qs={qs_value}"
    )];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "nested b64-of-JSON: qs.move_url");
    // The synthetic sub-param name should appear so reports can point at the
    // exact JSON field that was exploitable.
    let exact_move_url = findings
        .iter()
        .any(|f| f["param"].as_str() == Some("qs[move_url]"));
    assert!(
        exact_move_url,
        "expected at least one finding param == `qs[move_url]`; got params: {:?}",
        findings
            .iter()
            .map(|f| f["param"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
    // Now that Stage 3 (active probing) routes the marker through the
    // pipeline at the correct wire-name, raw `<script>...` payloads should
    // survive and produce a DOM-verified (`V`) finding rather than only
    // encoded fallbacks.
    assert_has_type(
        &findings,
        "V",
        "nested b64-of-JSON: expected DOM-verified finding",
    );
}

/// JWT-protected endpoint that doesn't verify the signature. Discovery's
/// JWT inference must pick up the 3-segment dotted shape, decode the
/// middle (b64url-of-JSON) payload, register `token[name]` as a virtual
/// sub-parameter with a `JsonField → Base64Url → JwtAssemble` pipeline,
/// and surface a finding when the marker survives reflection.
#[tokio::test]
async fn test_nested_jwt_payload_xss() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let addr = start_test_server().await;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"u","name":"alice"}"#);
    let signature = URL_SAFE_NO_PAD.encode("fake_signature_bytes");
    let token = format!("{header}.{payload}.{signature}");
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/auth/jwt?token={token}")];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "JWT unverified-signature: token[name]");
    let exact = findings
        .iter()
        .any(|f| f["param"].as_str() == Some("token[name]"));
    assert!(
        exact,
        "expected at least one finding param == `token[name]`; got: {:?}",
        findings
            .iter()
            .map(|f| f["param"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
    assert_has_type(&findings, "V", "JWT: expected DOM-verified finding");
}

/// Bare URL-encoded JSON in a query param. After URL-decoding (which axum
/// performs at extract time), the value starts with `{`; discovery's
/// `infer_url_json` strategy should register `blob[q]` as a virtual
/// sub-parameter with a single `JsonField` step (no base64 layer).
#[tokio::test]
async fn test_nested_url_encoded_json_xss() {
    let addr = start_test_server().await;
    // Use raw `{`/`}` characters; reqwest/axum handle the URL-encoding.
    let blob = r#"{"q":"hello"}"#;
    let mut args = base_scan_args();
    args.targets = vec![format!(
        "http://{addr}/api/blob?blob={}",
        urlencoding::encode(blob)
    )];
    let findings = run_scan_and_collect(args).await;
    assert_detected(&findings, "URL-encoded JSON: blob[q]");
    let exact = findings
        .iter()
        .any(|f| f["param"].as_str() == Some("blob[q]"));
    assert!(
        exact,
        "expected `blob[q]`; got: {:?}",
        findings
            .iter()
            .map(|f| f["param"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
    assert_has_type(&findings, "V", "URL-encoded JSON: expected DOM-verified");
}

// ===========================================================================
// Tests — Partial reflection (prefix-strip / suffix-strip / regex extract)
// ===========================================================================
//
// These servers strip parts of the input before echoing it. Real XSS
// payloads rarely survive such strips intact, so R/V findings may not
// fire — the goal here is to verify that *discovery* still recognises
// the param as reflected so downstream stages get a chance to try.
// We assert that the request count exceeds the non-reflected-param
// short-circuit baseline (~10 requests) as proxy for "Stage 5+ ran".

const PARTIAL_REFLECTION_BASELINE_REQUESTS: u64 = 20;

/// Server strips the first 4 chars before echoing. The legacy
/// single-token probe (open_marker only) would lose its `dlx` prefix
/// and the `text.contains(open_marker())` check would miss reflection.
/// The bracketed sandwich probe survives as `inner+close` (SuffixOnly),
/// so discovery still records the param and the scan proceeds.
#[tokio::test]
async fn test_partial_reflection_prefix_strip() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/strip/prefix4?q=test")];
    let (_findings, count) = run_scan_and_count(args).await;
    assert!(
        count > PARTIAL_REFLECTION_BASELINE_REQUESTS,
        "[prefix-strip] expected scan to progress past the no-reflection \
         short-circuit (>{} requests), got {}",
        PARTIAL_REFLECTION_BASELINE_REQUESTS,
        count
    );
}

/// Mirror of the above: trailing 4 chars stripped. The bracketed probe
/// survives as `open+inner` (PrefixOnly).
#[tokio::test]
async fn test_partial_reflection_suffix_strip() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/strip/suffix4?q=test")];
    let (_findings, count) = run_scan_and_count(args).await;
    assert!(
        count > PARTIAL_REFLECTION_BASELINE_REQUESTS,
        "[suffix-strip] expected >{} requests, got {}",
        PARTIAL_REFLECTION_BASELINE_REQUESTS,
        count
    );
}

/// Server extracts a hex-only substring — drops every non-hex byte.
/// `dlx` / `xld` / `dlxmid` non-hex letters are stripped, but the
/// random hex segments survive concatenated. `inner_marker()` is
/// `dlxmid<8hex>`, whose 8-hex tail survives as a contiguous run and
/// is detected by `classify_probe_reflection`'s InnerOnly branch.
#[tokio::test]
async fn test_partial_reflection_hex_extract() {
    let addr = start_test_server().await;
    let mut args = base_scan_args();
    args.targets = vec![format!("http://{addr}/extract/hex?q=test")];
    let (_findings, count) = run_scan_and_count(args).await;
    assert!(
        count > PARTIAL_REFLECTION_BASELINE_REQUESTS,
        "[hex-extract] expected >{} requests, got {}",
        PARTIAL_REFLECTION_BASELINE_REQUESTS,
        count
    );
}
