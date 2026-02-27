//! Integration test: run dalfox scan against a local mock server
//! and verify that reflected XSS is detected and reported.
//!
//! This version uses structured mock cases loaded from TOML files.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::prelude::*;

use super::mock_case_loader::{self, MockCase};
use dalfox::cmd::scan::{self, ScanArgs};
use dalfox::parameter_analysis::analyze_parameters;
use dalfox::target_parser::parse_target;

/// Application state holding all loaded mock cases
#[derive(Clone)]
struct AppState {
    query_cases: Arc<HashMap<u32, MockCase>>,
    header_cases: Arc<HashMap<u32, MockCase>>,
    cookie_cases: Arc<HashMap<u32, MockCase>>,
    path_cases: Arc<HashMap<u32, MockCase>>,
    body_cases: Arc<HashMap<u32, MockCase>>,
    realworld_cases: Arc<HashMap<u32, MockCase>>,
}

// Helpers for mock encoding behaviors
fn html_named_encode_all(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            _ => c.to_string(),
        })
        .collect::<String>()
}

fn html_numeric_hex_lower(input: &str) -> String {
    input
        .chars()
        .map(|c| format!("&#x{:02x};", c as u32))
        .collect::<String>()
}

fn html_numeric_hex_upper_x(input: &str) -> String {
    input
        .chars()
        .map(|c| format!("&#X{:02X};", c as u32))
        .collect::<String>()
}

/// Apply the reflection pattern defined in the mock case
fn apply_reflection(reflection_pattern: &str, input: &str) -> String {
    match reflection_pattern {
        "encoded_html_named" => html_named_encode_all(input),
        "encoded_html_hex_lower" => html_numeric_hex_lower(input),
        "encoded_html_hex_upper" => html_numeric_hex_upper_x(input),
        "percent_to_entity" => input.replace('%', "&#37;"),
        "encoded_base64" => BASE64_STANDARD.encode(input),
        "encoded_url" => urlencoding::encode(input).to_string(),
        _ => reflection_pattern.replace("{input}", input),
    }
}

/// Apply server-side filter chain to input.
/// Filters are pipe-separated, e.g. "strip_script|encode_angles"
fn apply_filter(input: &str, filter_chain: &str) -> String {
    let mut result = input.to_string();
    for filter in filter_chain.split('|') {
        let filter = filter.trim();
        if filter.is_empty() {
            continue;
        }
        result = match filter {
            // Tag removal filters
            "strip_tags" => {
                // Remove all HTML tags
                let re = regex::Regex::new(r"<[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_script" => {
                // Remove <script>...</script> and <script ...>
                let re = regex::Regex::new(r"(?i)<script[^>]*>.*?</script>|<script[^>]*>|</script>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_on_events" => {
                // Remove on* event handlers
                let re = regex::Regex::new(r"(?i)\bon\w+\s*=").unwrap();
                re.replace_all(&result, "").to_string()
            }
            // Character removal filters
            "remove_angles" => result.replace('<', "").replace('>', ""),
            "remove_quotes" => result.replace('"', "").replace('\'', ""),
            "remove_parens" => result.replace('(', "").replace(')', ""),
            "remove_semicolons" => result.replace(';', ""),
            // Partial encoding filters
            "encode_angles" => result.replace('<', "&lt;").replace('>', "&gt;"),
            "encode_quotes" => result.replace('"', "&quot;").replace('\'', "&#39;"),
            "encode_double_quotes" => result.replace('"', "&quot;"),
            "encode_single_quotes" => result.replace('\'', "&#39;"),
            // WAF simulation filters
            "waf_basic" => {
                // Block <script and </script
                let re = regex::Regex::new(r"(?i)</?script").unwrap();
                if re.is_match(&result) {
                    "".to_string()
                } else {
                    result
                }
            }
            "waf_moderate" => {
                // Block script tags, event handlers, and some dangerous tags
                let re = regex::Regex::new(r"(?i)</?script|on\w+\s*=|</?iframe|</?object|</?embed").unwrap();
                if re.is_match(&result) {
                    "".to_string()
                } else {
                    result
                }
            }
            "waf_strict" => {
                // Block script, events, angles, and keywords
                let re = regex::Regex::new(r"(?i)</?script|on\w+\s*=|javascript:|alert|confirm|prompt|<|>").unwrap();
                if re.is_match(&result) {
                    "".to_string()
                } else {
                    result
                }
            }
            // Keyword removal
            _ if filter.starts_with("remove_keyword:") => {
                let keyword = &filter["remove_keyword:".len()..];
                let re = regex::Regex::new(&format!("(?i){}", regex::escape(keyword))).unwrap();
                re.replace_all(&result, "").to_string()
            }
            // Character removal (extended)
            "remove_newlines" => result.replace('\n', "").replace('\r', ""),
            "remove_backslash" => result.replace('\\', ""),
            "remove_colon" => result.replace(':', ""),
            "remove_equals" => result.replace('=', ""),
            "alphanumeric_only" => result.chars().filter(|c| c.is_alphanumeric() || *c == ' ').collect(),
            // Tag-specific stripping
            "strip_iframe" => {
                let re = regex::Regex::new(r"(?i)</?iframe[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_img" => {
                let re = regex::Regex::new(r"(?i)<img[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_svg" => {
                let re = regex::Regex::new(r"(?i)</?svg[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            // Encoding (extended)
            "encode_ampersand" => result.replace('&', "&amp;"),
            "encode_full_html" => result
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;"),
            // WAF extended
            "waf_svg_aware" => {
                // Block script, svg, math tags and event handlers
                let re = regex::Regex::new(r"(?i)</?script|</?svg|</?math|on\w+\s*=").unwrap();
                if re.is_match(&result) { "".to_string() } else { result }
            }
            "waf_url_protocol" => {
                // Block javascript: and data: protocols
                let re = regex::Regex::new(r"(?i)javascript\s*:|data\s*:").unwrap();
                re.replace_all(&result, "").to_string()
            }
            // Replace (not remove) filter
            "replace_script_text" => {
                let re = regex::Regex::new(r"(?i)<(/?script)").unwrap();
                re.replace_all(&result, "&lt;$1").to_string()
            }
            // Allow-list based sanitization
            "allow_basic_html" => {
                // Strip all tags except p, b, i, em, strong, br, ul, ol, li, a
                let re = regex::Regex::new(r"(?i)<(?!/?(p|b|i|em|strong|br|ul|ol|li|a)\b)[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_style" => {
                let re = regex::Regex::new(r"(?i)<style[^>]*>.*?</style>|</?style[^>]*>").unwrap();
                re.replace_all(&result, "").to_string()
            }
            "strip_dangerous_attrs" => {
                // Remove href with javascript:, src with data:, and on* events
                let re = regex::Regex::new(r#"(?i)\bon\w+\s*=|href\s*=\s*["']?\s*javascript:|src\s*=\s*["']?\s*data:"#).unwrap();
                re.replace_all(&result, "").to_string()
            }
            // Additional character removal
            "remove_backtick" => result.replace('`', ""),
            "remove_dollar" => result.replace('$', ""),
            "remove_curly_braces" => result.replace('{', "").replace('}', ""),
            // WAF (extended)
            "waf_cloudflare_sim" => {
                // Simulates Cloudflare-like WAF: blocks script/svg/iframe/on*=/javascript:/alert/eval
                let re = regex::Regex::new(r#"(?i)</?script|</?svg|</?iframe|on\w+\s*=|javascript:|alert\s*\(|eval\s*\(|document\.(cookie|write|domain)"#).unwrap();
                if re.is_match(&result) { "".to_string() } else { result }
            }
            "waf_akamai_sim" => {
                // Simulates Akamai-like WAF: blocks common XSS patterns in request
                let re = regex::Regex::new(r#"(?i)<script|on(error|load|click|mouse)\s*=|javascript:|<img[^>]+onerror|<svg|alert\(|String\.fromCharCode"#).unwrap();
                if re.is_match(&result) { "".to_string() } else { result }
            }
            // Normalize/replace
            "normalize_whitespace" => {
                let re = regex::Regex::new(r"\s+").unwrap();
                re.replace_all(&result, " ").trim().to_string()
            }
            "double_encode_angles" => {
                result.replace('<', "&amp;lt;").replace('>', "&amp;gt;")
            }
            // Case transformation
            "lowercase" => result.to_lowercase(),
            "uppercase" => result.to_uppercase(),
            // Truncation
            _ if filter.starts_with("truncate:") => {
                if let Ok(n) = filter["truncate:".len()..].parse::<usize>() {
                    if result.len() > n {
                        result[..n].to_string()
                    } else {
                        result
                    }
                } else {
                    result
                }
            }
            _ => result,
        };
    }
    result
}

/// Generate a page template with the reflected input inserted
fn get_page_template(template_key: &str, reflected: &str) -> String {
    match template_key {
        "search_page" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<div class="header"><h1>Search</h1></div>
<form action="/search" method="GET">
  <input type="text" name="q" value="{reflected}">
  <button type="submit">Search</button>
</form>
<div class="results">
  <p>Search results for: {reflected}</p>
  <div class="no-results">No results found for "{reflected}"</div>
</div>
<script>
  var searchTerm = "{reflected}";
  console.log("Search: " + searchTerm);
</script>
</body></html>"#
        ),
        "error_page" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Error</title></head>
<body>
<div class="error-container">
  <h1>Error Occurred</h1>
  <div class="error-message">Error: {reflected}</div>
  <div class="error-details">
    <pre class="stack-trace">at handleRequest({reflected})</pre>
  </div>
</div>
<script>
  console.log("Error page loaded: {reflected}");
</script>
</body></html>"#
        ),
        "user_profile" => format!(
            r#"<!DOCTYPE html>
<html><head><title>User Profile</title></head>
<body>
<div class="profile">
  <h2 class="username">{reflected}</h2>
  <div class="bio">{reflected}</div>
  <a href="{reflected}" class="website">Website</a>
  <img src="/avatar.png" alt="{reflected}" onerror="this.src='/default.png'">
</div>
</body></html>"#
        ),
        "login_form" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<div class="login-container">
  <form action="/login" method="POST">
    <input type="hidden" name="redirect" value="{reflected}">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
  <div class="error-msg">{reflected}</div>
</div>
</body></html>"#
        ),
        "admin_panel" => format!(
            r#"<!DOCTYPE html>
<html><head>
<title>Admin Panel - {reflected}</title>
<script>
  var config = {{
    "appName": "{reflected}",
    "version": "1.0",
    "debug": true
  }};
  document.title = "Admin: " + config.appName;
</script>
</head>
<body>
<div class="admin-panel">
  <h1>Admin Panel</h1>
  <input type="text" id="setting" value="{reflected}">
</div>
</body></html>"#
        ),
        "comment_section" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Comments</title></head>
<body>
<div class="comments">
  <div class="comment" data-author="{reflected}">
    <span class="author">{reflected}</span>
    <p class="content">{reflected}</p>
  </div>
  <form action="/comment" method="POST">
    <textarea name="body">{reflected}</textarea>
    <button type="submit">Post</button>
  </form>
</div>
</body></html>"#
        ),
        "404_page" => format!(
            r#"<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body>
<div class="error-404">
  <h1>404</h1>
  <p>The page <code>{reflected}</code> was not found.</p>
  <p>Try searching for: <a href="/search?q={reflected}">{reflected}</a></p>
</div>
</body></html>"#
        ),
        "redirect_page" => format!(
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0;url={reflected}">
<title>Redirecting...</title>
</head>
<body>
<p>Redirecting to <a href="{reflected}">{reflected}</a>...</p>
<script>window.location = "{reflected}";</script>
</body></html>"#
        ),
        "api_json" => format!(
            r#"{{"status":"ok","data":{{"message":"{reflected}","query":"{reflected}"}}}}"#
        ),
        "jsonp_callback" => format!(
            r#"/**/ {}({{"status":"ok","data":"result"}});"#,
            reflected
        ),
        "dashboard" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
<div class="dashboard">
  <div class="widget" data-config="{reflected}">
    <h3>Widget</h3>
    <div class="content">{reflected}</div>
  </div>
  <script>
    var settings = "{reflected}";
    document.getElementById("output").innerHTML = settings;
  </script>
</div>
</body></html>"#
        ),
        "file_upload" => format!(
            r#"<!DOCTYPE html>
<html><head><title>File Upload</title></head>
<body>
<div class="upload-form">
  <h2>Upload File</h2>
  <p>Selected file: {reflected}</p>
  <form enctype="multipart/form-data" action="/upload" method="POST">
    <input type="file" name="file" accept="{reflected}">
    <button type="submit">Upload</button>
  </form>
</div>
</body></html>"#
        ),
        "ecommerce_product" => format!(
            r#"<!DOCTYPE html>
<html><head><title>{reflected} - Shop</title></head>
<body>
<nav class="breadcrumb"><a href="/">Home</a> &gt; <a href="/search">{reflected}</a></nav>
<div class="product">
  <h1 class="product-name">{reflected}</h1>
  <img src="/img/product.jpg" alt="{reflected}">
  <div class="price">$19.99</div>
  <div class="description">{reflected}</div>
  <button onclick="addToCart('{reflected}')">Add to Cart</button>
</div>
<div class="reviews">
  <h3>Reviews for {reflected}</h3>
  <div class="review"><span class="author">{reflected}</span><p>Great product!</p></div>
</div>
<script>var productName = "{reflected}"; analytics.track("view", productName);</script>
</body></html>"#
        ),
        "email_preview" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Email Preview</title></head>
<body>
<div class="email-preview">
  <div class="email-header">
    <div class="from">From: {reflected}</div>
    <div class="subject">Subject: {reflected}</div>
  </div>
  <div class="email-body">{reflected}</div>
  <div class="email-footer"><a href="mailto:{reflected}">Reply</a></div>
</div>
</body></html>"#
        ),
        "chat_message" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Chat</title></head>
<body>
<div class="chat-container">
  <div class="message" data-sender="{reflected}">
    <span class="sender">{reflected}</span>
    <p class="text">{reflected}</p>
    <span class="time">12:00</span>
  </div>
</div>
<div class="input-area">
  <textarea placeholder="Type a message...">{reflected}</textarea>
  <button>Send</button>
</div>
<script>var lastMsg = "{reflected}";</script>
</body></html>"#
        ),
        "api_docs" => format!(
            r#"<!DOCTYPE html>
<html><head><title>API Documentation</title></head>
<body>
<div class="api-docs">
  <h1>API Reference</h1>
  <div class="endpoint">
    <h3>GET /api/{reflected}</h3>
    <p>Description: Fetch {reflected} resource</p>
    <div class="params"><code>?q={reflected}</code></div>
    <div class="example"><pre>curl "https://api.example.com/{reflected}?q={reflected}"</pre></div>
  </div>
  <div class="try-it">
    <input type="text" value="{reflected}" id="param-input">
    <button onclick="tryApi('{reflected}')">Try it</button>
  </div>
</div>
</body></html>"#
        ),
        "notification" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Notifications</title></head>
<body>
<div class="notifications">
  <div class="notification unread" data-type="{reflected}">
    <strong>{reflected}</strong>
    <p>{reflected}</p>
    <a href="{reflected}">View Details</a>
  </div>
</div>
<script>new Notification("{reflected}");</script>
</body></html>"#
        ),
        "form_builder" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Form Builder</title></head>
<body>
<div class="form-builder">
  <h2>Form Preview</h2>
  <form>
    <label for="field1">{reflected}</label>
    <input id="field1" name="{reflected}" placeholder="{reflected}" type="text">
    <select name="select1"><option value="{reflected}">{reflected}</option></select>
    <button type="submit">{reflected}</button>
  </form>
</div>
<script>var formConfig = {{fields: [{{name: "{reflected}", label: "{reflected}"}}]}};</script>
</body></html>"#
        ),
        "oauth_callback" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Authorization</title></head>
<body>
<div class="oauth-container">
  <h2>Authorize Application</h2>
  <p>Application <strong>{reflected}</strong> is requesting access.</p>
  <div class="scopes"><span class="scope">{reflected}</span></div>
  <form action="/oauth/authorize" method="POST">
    <input type="hidden" name="client_id" value="{reflected}">
    <input type="hidden" name="redirect_uri" value="{reflected}">
    <button type="submit" name="action" value="allow">Allow</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</div>
</body></html>"#
        ),
        "payment_form" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Payment</title></head>
<body>
<div class="payment">
  <h2>Complete Payment</h2>
  <div class="order-summary"><p>Order: {reflected}</p><p>Amount: $99.00</p></div>
  <form action="/pay" method="POST">
    <input type="hidden" name="description" value="{reflected}">
    <input type="hidden" name="return_url" value="{reflected}">
    <label>Card Number</label><input name="card" type="text">
    <button>Pay Now</button>
  </form>
</div>
<script>var orderDesc = "{reflected}"; gtag("event", "begin_checkout", {{item: "{reflected}"}});</script>
</body></html>"#
        ),
        "social_share" => format!(
            r#"<!DOCTYPE html>
<html><head>
<title>{reflected}</title>
<meta property="og:title" content="{reflected}">
<meta property="og:description" content="{reflected}">
<meta property="og:url" content="{reflected}">
<meta property="og:image" content="{reflected}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{reflected}">
</head>
<body>
<h1>{reflected}</h1>
<div class="share-buttons">
  <a href="https://twitter.com/share?text={reflected}&url={reflected}">Twitter</a>
  <a href="https://www.facebook.com/sharer.php?u={reflected}">Facebook</a>
</div>
<script>var shareData = {{title: "{reflected}", url: "{reflected}"}};</script>
</body></html>"#
        ),
        "markdown_preview" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Preview</title></head>
<body>
<div class="markdown-body">
  <h1>{reflected}</h1>
  <p>{reflected}</p>
  <a href="{reflected}">{reflected}</a>
  <img src="{reflected}" alt="{reflected}">
  <code>{reflected}</code>
  <blockquote>{reflected}</blockquote>
</div>
</body></html>"#
        ),
        "data_table" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Data View</title></head>
<body>
<div class="data-view">
  <h2>Results for: {reflected}</h2>
  <div class="toolbar"><input type="text" id="filter" value="{reflected}" onkeyup="filterTable('{reflected}')"></div>
  <table id="data-table">
    <thead><tr><th>{reflected}</th><th>Value</th><th>Actions</th></tr></thead>
    <tbody><tr><td>{reflected}</td><td>100</td><td><a href="/edit?id={reflected}">Edit</a></td></tr></tbody>
  </table>
</div>
<script>var columnName = "{reflected}"; document.title = "Data: " + columnName;</script>
</body></html>"#
        ),
        "analytics_dashboard" => format!(
            r#"<!DOCTYPE html>
<html><head><title>Analytics - {reflected}</title></head>
<body>
<div class="analytics">
  <h1>Analytics for {reflected}</h1>
  <div class="filter-bar">
    <label>Campaign</label><input value="{reflected}">
    <label>Source</label><select><option value="{reflected}">{reflected}</option></select>
  </div>
  <div class="chart" data-label="{reflected}" data-source="{reflected}"></div>
</div>
<script>
  var campaign = "{reflected}";
  var utm = {{source: "{reflected}", medium: "{reflected}"}};
  analytics.page({{campaign: campaign}});
</script>
</body></html>"#
        ),
        "deep_link" => format!(
            r#"<!DOCTYPE html>
<html><head>
<title>Open in App</title>
<meta name="apple-itunes-app" content="app-id=123456, app-argument={reflected}">
</head>
<body>
<div class="deep-link">
  <h2>Open in App</h2>
  <a href="myapp://open?url={reflected}" id="app-link">Open in App</a>
  <a href="{reflected}" class="fallback">Open in Browser</a>
</div>
<script>
  var deepLink = "myapp://open?url={reflected}";
  window.location = deepLink;
  setTimeout(function(){{ window.location = "{reflected}"; }}, 2000);
</script>
</body></html>"#
        ),
        "i18n_page" => format!(
            r#"<!DOCTYPE html>
<html lang="{reflected}">
<head><title>{reflected}</title></head>
<body>
<div class="lang-selector">
  <a href="?lang={reflected}" class="active">{reflected}</a>
  <a href="?lang=en">English</a>
</div>
<div class="content">
  <h1>{reflected}</h1>
  <p>{reflected}</p>
</div>
<script>var locale = "{reflected}"; document.documentElement.lang = locale;</script>
</body></html>"#
        ),
        _ => format!(
            r#"<html><head><title>mock</title></head><body><div id=out>{reflected}</div></body></html>"#
        ),
    }
}

/// Handler for realworld test cases
async fn realworld_handler(
    Path(case_id): Path<u32>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let q = params.get("query").cloned().unwrap_or_default();

    let case = state.realworld_cases.get(&case_id);

    // Apply filter chain if specified
    let filtered = if let Some(c) = case {
        if let Some(ref filter) = c.filter {
            apply_filter(&q, filter)
        } else {
            q.clone()
        }
    } else {
        q.clone()
    };

    // Apply reflection pattern
    let reflected = if let Some(c) = case {
        apply_reflection(&c.reflection, &filtered)
    } else {
        filtered
    };

    // Generate page body using template or default
    let body = if let Some(c) = case {
        if let Some(ref template) = c.page_template {
            get_page_template(template, &reflected)
        } else {
            format!(
                "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
                reflected
            )
        }
    } else {
        format!(
            "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
            reflected
        )
    };

    // Build response with custom status code, content-type, and headers
    let status = case
        .and_then(|c| c.status_code)
        .map(|code| StatusCode::from_u16(code).unwrap_or(StatusCode::OK))
        .unwrap_or(StatusCode::OK);

    let content_type = case
        .and_then(|c| c.content_type.as_deref())
        .unwrap_or("text/html; charset=utf-8");

    let mut response_headers = vec![(
        axum::http::header::CONTENT_TYPE,
        content_type.parse().unwrap(),
    )];

    if let Some(c) = case {
        for h in &c.response_headers {
            if let Some((name, value)) = h.split_once(':') {
                if let (Ok(hn), Ok(hv)) = (
                    axum::http::header::HeaderName::from_bytes(name.trim().as_bytes()),
                    axum::http::header::HeaderValue::from_str(value.trim()),
                ) {
                    response_headers.push((hn, hv));
                }
            }
        }
    }

    let mut builder = axum::http::Response::builder().status(status);
    for (name, value) in response_headers {
        builder = builder.header(name, value);
    }
    builder.body(body).unwrap()
}

async fn query_handler_v2(
    Path(case_id): Path<u32>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let q = params.get("query").cloned().unwrap_or_default();

    let reflected = if let Some(case) = state.query_cases.get(&case_id) {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn header_handler_v2(
    Path(case_id): Path<u32>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let case = state.header_cases.get(&case_id);

    let header_name = case
        .and_then(|c| c.header_name.as_ref())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "x-test".to_string());

    let q = headers
        .get(header_name.as_str())
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn cookie_handler_v2(
    Path(case_id): Path<u32>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let case = state.cookie_cases.get(&case_id);

    let cookie_name = case
        .and_then(|c| c.cookie_name.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("test");

    let cookie_header = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let q = cookie_header
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            let prefix = format!("{}=", cookie_name);
            if c.starts_with(&prefix) {
                Some(c[prefix.len()..].to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn path_handler_v2(
    Path((case_id, param)): Path<(u32, String)>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let reflected = if let Some(case) = state.path_cases.get(&case_id) {
        apply_reflection(&case.reflection, &param)
    } else {
        param.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn body_handler_v2(
    State(state): State<AppState>,
    Path(case_id): Path<u32>,
    Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let case = state.body_cases.get(&case_id);

    let param_name = case
        .and_then(|c| c.param_name.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("query");

    let q = params.get(param_name).cloned().unwrap_or_default();

    let reflected = if let Some(case) = case {
        apply_reflection(&case.reflection, &q)
    } else {
        q.clone()
    };

    let body = format!(
        "<html><head><title>mock</title></head><body><div id=out>{}</div></body></html>",
        reflected
    );
    (StatusCode::OK, Html(body))
}

async fn start_mock_server_v2() -> (SocketAddr, AppState) {
    // Load all mock cases
    let base_dir = mock_case_loader::get_mock_cases_base_dir();
    let cases_by_type =
        mock_case_loader::load_all_mock_cases(&base_dir).expect("Failed to load mock cases");

    // Organize cases by ID for quick lookup
    let mut query_cases = HashMap::new();
    let mut header_cases = HashMap::new();
    let mut cookie_cases = HashMap::new();
    let mut path_cases = HashMap::new();
    let mut body_cases = HashMap::new();
    let mut realworld_cases = HashMap::new();

    for (handler_type, cases) in cases_by_type {
        for case in cases {
            match handler_type.as_str() {
                "query" => {
                    query_cases.insert(case.id, case);
                }
                "header" => {
                    header_cases.insert(case.id, case);
                }
                "cookie" => {
                    cookie_cases.insert(case.id, case);
                }
                "path" => {
                    path_cases.insert(case.id, case);
                }
                "body" => {
                    body_cases.insert(case.id, case);
                }
                "realworld" => {
                    realworld_cases.insert(case.id, case);
                }
                _ => {}
            }
        }
    }

    let state = AppState {
        query_cases: Arc::new(query_cases),
        header_cases: Arc::new(header_cases),
        cookie_cases: Arc::new(cookie_cases),
        path_cases: Arc::new(path_cases),
        body_cases: Arc::new(body_cases),
        realworld_cases: Arc::new(realworld_cases),
    };

    let app = Router::new()
        .route("/query/:case_id", get(query_handler_v2))
        .route("/header/:case_id", get(header_handler_v2))
        .route("/cookie/:case_id", get(cookie_handler_v2))
        .route("/path/:case_id/:param", get(path_handler_v2))
        .route("/body/:case_id", post(body_handler_v2))
        .route("/realworld/query/:case_id", get(realworld_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                // Keep server alive for the duration of the test
                tokio::time::sleep(Duration::from_secs(300)).await;
            })
            .await
            .ok();
    });

    (addr, state)
}

/// Load query mock cases grouped by source TOML file name (category).
fn load_query_cases_by_file() -> Result<HashMap<String, Vec<MockCase>>, String> {
    let query_dir = mock_case_loader::get_mock_cases_base_dir().join("query");
    if !query_dir.exists() {
        return Err(format!(
            "Query mock cases directory does not exist: {}",
            query_dir.display()
        ));
    }

    let entries = std::fs::read_dir(&query_dir)
        .map_err(|e| format!("Failed to read query cases directory: {}", e))?;

    let mut by_file = HashMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }

        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("Invalid query case file name: {}", path.display()))?;

        let mut cases = mock_case_loader::load_mock_cases_from_file(&path)?;
        cases.sort_by_key(|c| c.id);
        by_file.insert(file_stem.to_string(), cases);
    }

    Ok(by_file)
}

/// Helper to run a scan test for a specific case
async fn run_scan_test(
    addr: SocketAddr,
    endpoint: &str,
    case_id: u32,
    scan_config: ScanTestConfig,
) -> Vec<serde_json::Value> {
    let target = format!(
        "http://{}:{}/{}{}",
        addr.ip(),
        addr.port(),
        endpoint,
        scan_config.url_suffix
    );

    let out_path = std::env::temp_dir().join(format!(
        "dalfox_mock_{}_case{}_{}_{}.json",
        endpoint.replace('/', "_"),
        case_id,
        addr.ip(),
        addr.port()
    ));
    let out_path_str = out_path.to_string_lossy().to_string();

    let args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![target],
        param: scan_config.param.clone(),
        data: scan_config.data.clone(),
        headers: scan_config.headers.clone(),
        cookies: scan_config.cookies.clone(),
        method: scan_config.method.clone(),
        user_agent: None,
        cookie_from_raw: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        skip_discovery: false,
        skip_reflection_header: scan_config.skip_reflection_header,
        skip_reflection_cookie: scan_config.skip_reflection_cookie,
        skip_reflection_path: scan_config.skip_reflection_path,
        timeout: 5,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        output: Some(out_path_str.clone()),
        include_request: false,
        include_response: false,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string(), "base64".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        skip_xss_scanning: false,
        deep_scan: true,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        skip_ast_analysis: false,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    scan::run_scan(&args).await;

    let content = std::fs::read_to_string(&out_path).expect("scan should write JSON output file");
    let v: serde_json::Value =
        serde_json::from_str(&content).expect("output should be valid JSON array");

    v.as_array().expect("json should be an array").clone()
}

/// Run only discovery phase against a single target and report if any reflection params were found.
async fn run_discovery_once(
    addr: SocketAddr,
    url_path: String,
    method: String,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: Option<String>,
    skip_reflection_header: bool,
    skip_reflection_cookie: bool,
    skip_reflection_path: bool,
) -> bool {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), url_path);
    let mut target = parse_target(&url).unwrap();
    target.method = method;
    let body_clone = body.clone();
    target.data = body_clone.clone();
    target.headers = headers;
    target.cookies = cookies;
    target.user_agent = Some("".to_string());
    target.timeout = 5;
    target.workers = 10;

    let args = ScanArgs {
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url.clone()],
        param: vec![],
        data: body_clone,
        headers: vec![],
        cookies: vec![],
        method: target.method.clone(),
        user_agent: None,
        cookie_from_raw: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_discovery: false,
        skip_reflection_header,
        skip_reflection_cookie,
        skip_reflection_path,
        timeout: 5,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        output: None,
        include_request: false,
        include_response: false,
        silence: true,
        poc_type: "plain".to_string(),
        limit: None,
        workers: 10,
        max_concurrent_targets: 10,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        skip_ast_analysis: true,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    analyze_parameters(&mut target, &args, None).await;
    !target.reflection_params.is_empty()
}

struct ScanTestConfig {
    url_suffix: String,
    param: Vec<String>,
    data: Option<String>,
    headers: Vec<String>,
    cookies: Vec<String>,
    method: String,
    skip_reflection_header: bool,
    skip_reflection_cookie: bool,
    skip_reflection_path: bool,
}

#[tokio::test]
#[ignore]
async fn test_query_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    // Wait a moment for server to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut case_ids: Vec<u32> = state.query_cases.keys().copied().collect();
    case_ids.sort_unstable();
    let total_cases = case_ids.len();
    println!("Testing {} query reflection cases", total_cases);

    let mut detected = 0usize;
    let mut expected_total = 0usize;
    let mut expected_detected = 0usize;
    let mut missed_expected_ids = Vec::new();
    let mut false_positive_ids = Vec::new();
    let mut mismatches = Vec::new();
    // Known coverage gaps in query full corpus (as of current scanner behavior).
    let known_gap_ids: HashSet<u32> = [3, 4, 193, 194].into_iter().collect();

    for case_id in case_ids {
        let case = state
            .query_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("missing query case {}", case_id));
        println!(
            "Testing case {}: {} - {}",
            case.id, case.name, case.description
        );

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}?query=seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
        };

        let results = run_scan_test(addr, "query", case_id, config).await;
        let case_detected = !results.is_empty();

        if case_detected {
            detected += 1;
        }

        if case.expected_detection {
            expected_total += 1;
            if case_detected {
                expected_detected += 1;
            } else {
                missed_expected_ids.push(case.id);
                mismatches.push(format!(
                    "case {} ({}) expected_detection=true actual_detection=false",
                    case.id, case.name
                ));
            }
        } else if case_detected {
            false_positive_ids.push(case.id);
            mismatches.push(format!(
                "case {} ({}) expected_detection=false actual_detection=true",
                case.id, case.name
            ));
        }
    }

    let positive_detection_rate = if expected_total > 0 {
        expected_detected as f64 / expected_total as f64
    } else {
        0.0
    };

    println!(
        "query full corpus detected: {}/{} ({:.1}%)",
        detected,
        total_cases,
        (detected as f64 / total_cases as f64) * 100.0
    );
    println!(
        "query expected-positive coverage: {}/{} ({:.1}%)",
        expected_detected,
        expected_total,
        positive_detection_rate * 100.0
    );

    let unexpected_missed: Vec<u32> = missed_expected_ids
        .iter()
        .copied()
        .filter(|id| !known_gap_ids.contains(id))
        .collect();

    if !mismatches.is_empty() {
        println!("query full corpus mismatches:");
        for m in &mismatches {
            println!("  - {}", m);
        }
    }

    assert!(
        mismatches.len() <= 8,
        "query full corpus mismatches exceeded baseline (>{}):\n{}",
        8,
        mismatches.join("\n")
    );
    assert!(
        unexpected_missed.is_empty(),
        "query full corpus introduced unexpected missed cases: {:?} (known gaps: {:?})",
        unexpected_missed,
        known_gap_ids
    );
    assert!(
        missed_expected_ids.len() <= known_gap_ids.len(),
        "query full corpus missed case count exceeded known gaps: {} > {}",
        missed_expected_ids.len(),
        known_gap_ids.len()
    );
    assert!(
        false_positive_ids.is_empty(),
        "query full corpus produced unexpected false positives: {:?}",
        false_positive_ids
    );
    assert!(
        positive_detection_rate >= 0.95,
        "query full corpus positive detection rate dropped below baseline: {:.1}%",
        positive_detection_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_query_reflection_diverse_xss_contexts_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Representative cases across major reflected-XSS contexts.
    let case_ids = vec![
        1,   // raw html reflection
        7,   // javascript string
        12,  // href attribute
        29,  // javascript: protocol
        31,  // event handler
        41,  // svg script context
        46,  // style context
        91,  // template literal
        168, // plain element body
        191, // encoded reflection variant
    ];

    let mut failed = Vec::new();

    for case_id in case_ids {
        let case = state
            .query_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing query case id {}", case_id));

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}?query=seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
        };

        let results = run_scan_test(addr, "query", case_id, config).await;
        let detected = !results.is_empty();

        if detected != case.expected_detection {
            failed.push(format!(
                "case {} ({}) expected_detection={} actual_detection={}",
                case.id, case.name, case.expected_detection, detected
            ));
        }
    }

    assert!(
        failed.is_empty(),
        "diverse query context mismatches:\n{}",
        failed.join("\n")
    );
}

#[tokio::test]
#[ignore]
async fn test_query_reflection_advanced_xss_coverage_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Advanced/evasive contexts: encoding bypass, multilayer contexts, and unicode edge cases.
    let case_ids = vec![191, 193, 194, 199, 205, 226, 230, 234, 239, 247, 250, 254];

    let mut detected = 0usize;
    let mut mismatches = Vec::new();

    for case_id in case_ids {
        let case = state
            .query_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing query case id {}", case_id));

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}?query=seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
        };

        let results = run_scan_test(addr, "query", case_id, config).await;
        let case_detected = !results.is_empty();
        if case_detected {
            detected += 1;
        }
        if case_detected != case.expected_detection {
            mismatches.push(format!(
                "case {} ({}) expected_detection={} actual_detection={}",
                case.id, case.name, case.expected_detection, case_detected
            ));
        }
    }

    let total = 12usize;
    let detection_rate = detected as f64 / total as f64;

    assert!(
        mismatches.len() <= 2,
        "advanced query context mismatches (>{}):\n{}",
        2,
        mismatches.join("\n")
    );
    assert!(
        detection_rate >= 0.80,
        "advanced query context detection rate below baseline: {}/{} ({:.1}%)",
        detected,
        total,
        detection_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_query_reflection_category_baselines_v2() {
    let (addr, _state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let by_file = load_query_cases_by_file().expect("query category files should load");
    assert!(
        by_file.len() >= 10,
        "expected multiple query categories, got {}",
        by_file.len()
    );

    let mut categories: Vec<String> = by_file.keys().cloned().collect();
    categories.sort();

    let mut zero_hit_categories = Vec::new();
    let mut total_expected = 0usize;
    let mut total_expected_detected = 0usize;

    for category in categories {
        let cases = by_file
            .get(&category)
            .unwrap_or_else(|| panic!("missing category {}", category));

        let mut detected = 0usize;
        let mut expected_total = 0usize;
        let mut expected_detected = 0usize;
        let mut mismatches = 0usize;

        for case in cases {
            let config = ScanTestConfig {
                url_suffix: format!("/{}?query=seed", case.id),
                param: vec![],
                data: None,
                headers: vec![],
                cookies: vec![],
                method: "GET".to_string(),
                skip_reflection_header: true,
                skip_reflection_cookie: true,
                skip_reflection_path: true,
            };

            let results = run_scan_test(addr, "query", case.id, config).await;
            let case_detected = !results.is_empty();

            if case_detected {
                detected += 1;
            }
            if case.expected_detection {
                expected_total += 1;
                if case_detected {
                    expected_detected += 1;
                } else {
                    mismatches += 1;
                }
            } else if case_detected {
                mismatches += 1;
            }
        }

        total_expected += expected_total;
        total_expected_detected += expected_detected;

        let positive_detection_rate = if expected_total > 0 {
            expected_detected as f64 / expected_total as f64
        } else {
            0.0
        };

        println!(
            "query category {}: detected={}/{} positive_coverage={}/{} ({:.1}%) mismatches={}",
            category,
            detected,
            cases.len(),
            expected_detected,
            expected_total,
            positive_detection_rate * 100.0,
            mismatches
        );

        if expected_detected == 0 {
            zero_hit_categories.push(category.clone());
        }

        let category_min_rate = match category.as_str() {
            "encoding_bypass" => 0.85,
            "html_contexts" => 0.90,
            _ => 0.95,
        };
        let category_max_mismatch = match category.as_str() {
            "encoding_bypass" => 3usize,
            "html_contexts" => 3usize,
            _ => 1usize,
        };

        assert!(
            positive_detection_rate >= category_min_rate,
            "query category baseline dropped for {}: {:.1}% < {:.1}%",
            category,
            positive_detection_rate * 100.0,
            category_min_rate * 100.0
        );
        assert!(
            mismatches <= category_max_mismatch,
            "query category mismatches exceeded baseline for {}: {} > {}",
            category,
            mismatches,
            category_max_mismatch
        );
    }

    let overall_positive_rate = if total_expected > 0 {
        total_expected_detected as f64 / total_expected as f64
    } else {
        0.0
    };
    println!(
        "query category baseline overall positive coverage: {}/{} ({:.1}%)",
        total_expected_detected,
        total_expected,
        overall_positive_rate * 100.0
    );

    assert!(
        zero_hit_categories.is_empty(),
        "query categories with zero detections: {}",
        zero_hit_categories.join(", ")
    );
    assert!(
        overall_positive_rate >= 0.97,
        "query category baseline overall coverage dropped: {:.1}% < 97.0%",
        overall_positive_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_header_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.header_cases.len();
    println!("Testing {} header reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.header_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let header_name = case.header_name.as_deref().unwrap_or("X-Test");
        let header_name_lc = header_name.to_ascii_lowercase();

        // Simple functional check: server reflects the header value (transformed)
        let client = reqwest::Client::new();
        let url = format!("http://{}:{}/header/{}", addr.ip(), addr.port(), case_id);
        let resp = client
            .get(&url)
            .header(&header_name_lc, "seed")
            .send()
            .await
            .expect("header request");
        let text = resp.text().await.expect("header text");
        let expected = apply_reflection(&case.reflection, "seed");
        if text.contains(&expected) {
            detected += 1;
        }
    }
    assert!(
        detected > 0,
        "header tests: expected at least one detection"
    );
}

#[tokio::test]
#[ignore]
async fn test_cookie_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.cookie_cases.len();
    println!("Testing {} cookie reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.cookie_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let cookie_name = case.cookie_name.as_deref().unwrap_or("test");

        let found = run_discovery_once(
            addr,
            format!("/cookie/{}", case_id),
            "GET".to_string(),
            vec![],
            vec![(cookie_name.to_string(), "seed".to_string())],
            None,
            true,
            false,
            true,
        )
        .await;
        if found {
            detected += 1;
        }
    }
    assert!(
        detected > 0,
        "cookie tests: expected at least one detection"
    );
}

#[tokio::test]
#[ignore]
async fn test_path_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.path_cases.len();
    println!("Testing {} path reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.path_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}/seed"),
            // Leave empty so discovery can add path_segment_* entries
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: false,
        };

        let results = run_scan_test(addr, "path", *case_id, config).await;

        if !results.is_empty() {
            detected += 1;
        }
    }
    assert!(detected > 0, "path tests: expected at least one detection");
}

#[tokio::test]
#[ignore]
async fn test_body_reflection_v2() {
    let (addr, state) = start_mock_server_v2().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let total_cases = state.body_cases.len();
    println!("Testing {} body reflection cases", total_cases);

    let mut detected = 0usize;
    for (case_id, case) in state.body_cases.iter() {
        println!(
            "Testing case {}: {} - {}",
            case_id, case.name, case.description
        );

        let param_name = case.param_name.as_deref().unwrap_or("query");

        // Simple functional check: server reflects the body param (transformed)
        let client = reqwest::Client::new();
        let url = format!("http://{}:{}/body/{}", addr.ip(), addr.port(), case_id);
        let form = [(param_name.to_string(), "seed".to_string())];
        let resp = client
            .post(&url)
            .form(&form)
            .send()
            .await
            .expect("body request");
        let text = resp.text().await.expect("body text");
        let expected = apply_reflection(&case.reflection, "seed");
        if text.contains(&expected) {
            detected += 1;
        }
    }
    assert!(detected > 0, "body tests: expected at least one detection");
}

#[tokio::test]
#[ignore]
async fn test_header_reflection_diverse_xss_contexts_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Representative header contexts: raw/script/attribute/js-string/style/encoded.
    let case_ids = vec![1, 9, 23, 32, 35, 41, 46, 49];
    let mut failed = Vec::new();
    let client = reqwest::Client::new();

    for case_id in case_ids {
        let case = state
            .header_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing header case id {}", case_id));
        let header_name = case.header_name.as_deref().unwrap_or("X-Test");
        let header_name_lc = header_name.to_ascii_lowercase();

        let url = format!("http://{}:{}/header/{}", addr.ip(), addr.port(), case_id);
        let resp = client
            .get(&url)
            .header(&header_name_lc, "seed")
            .send()
            .await
            .expect("header request");
        let text = resp.text().await.expect("header text");
        let reflected = text.contains(&apply_reflection(&case.reflection, "seed"));

        if reflected != case.expected_detection {
            failed.push(format!(
                "case {} ({}) expected_detection={} actual_reflection={}",
                case.id, case.name, case.expected_detection, reflected
            ));
        }
    }

    assert!(
        failed.is_empty(),
        "diverse header context mismatches:\n{}",
        failed.join("\n")
    );
}

#[tokio::test]
#[ignore]
async fn test_header_reflection_advanced_xss_coverage_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Advanced/evasive header contexts.
    let case_ids = vec![42, 43, 45, 47, 48, 50, 34, 40];
    let mut reflected_count = 0usize;
    let mut mismatches = Vec::new();
    let client = reqwest::Client::new();

    for case_id in case_ids {
        let case = state
            .header_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing header case id {}", case_id));
        let header_name = case.header_name.as_deref().unwrap_or("X-Test");
        let header_name_lc = header_name.to_ascii_lowercase();

        let url = format!("http://{}:{}/header/{}", addr.ip(), addr.port(), case_id);
        let resp = client
            .get(&url)
            .header(&header_name_lc, "seed")
            .send()
            .await
            .expect("header request");
        let text = resp.text().await.expect("header text");
        let reflected = text.contains(&apply_reflection(&case.reflection, "seed"));

        if reflected {
            reflected_count += 1;
        }
        if reflected != case.expected_detection {
            mismatches.push(format!(
                "case {} ({}) expected_detection={} actual_reflection={}",
                case.id, case.name, case.expected_detection, reflected
            ));
        }
    }

    let total = 8usize;
    let reflection_rate = reflected_count as f64 / total as f64;

    assert!(
        mismatches.len() <= 2,
        "advanced header context mismatches (>{}):\n{}",
        2,
        mismatches.join("\n")
    );
    assert!(
        reflection_rate >= 0.90,
        "advanced header context reflection rate below baseline: {}/{} ({:.1}%)",
        reflected_count,
        total,
        reflection_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_cookie_reflection_diverse_xss_contexts_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![1, 9, 11, 16, 20, 29, 31, 35, 37];
    let mut failed = Vec::new();

    for case_id in case_ids {
        let case = state
            .cookie_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing cookie case id {}", case_id));
        let cookie_name = case.cookie_name.as_deref().unwrap_or("test");

        let found = run_discovery_once(
            addr,
            format!("/cookie/{}", case_id),
            "GET".to_string(),
            vec![],
            vec![(cookie_name.to_string(), "seed".to_string())],
            None,
            true,
            false,
            true,
        )
        .await;
        if found != case.expected_detection {
            failed.push(format!(
                "case {} ({}) expected_detection={} actual_discovery={}",
                case.id, case.name, case.expected_detection, found
            ));
        }
    }

    assert!(
        failed.is_empty(),
        "diverse cookie context mismatches:\n{}",
        failed.join("\n")
    );
}

#[tokio::test]
#[ignore]
async fn test_cookie_reflection_advanced_xss_coverage_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![32, 33, 34, 36, 38, 39, 40, 27];
    let mut found_count = 0usize;
    let mut mismatches = Vec::new();

    for case_id in case_ids {
        let case = state
            .cookie_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing cookie case id {}", case_id));
        let cookie_name = case.cookie_name.as_deref().unwrap_or("test");

        let found = run_discovery_once(
            addr,
            format!("/cookie/{}", case_id),
            "GET".to_string(),
            vec![],
            vec![(cookie_name.to_string(), "seed".to_string())],
            None,
            true,
            false,
            true,
        )
        .await;
        if found {
            found_count += 1;
        }
        if found != case.expected_detection {
            mismatches.push(format!(
                "case {} ({}) expected_detection={} actual_discovery={}",
                case.id, case.name, case.expected_detection, found
            ));
        }
    }

    let total = 8usize;
    let discovery_rate = found_count as f64 / total as f64;

    assert!(
        mismatches.len() <= 2,
        "advanced cookie context mismatches (>{}):\n{}",
        2,
        mismatches.join("\n")
    );
    assert!(
        discovery_rate >= 0.85,
        "advanced cookie context discovery rate below baseline: {}/{} ({:.1}%)",
        found_count,
        total,
        discovery_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_path_reflection_diverse_xss_contexts_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![1, 9, 11, 12, 15, 17, 18, 22, 24, 28];
    let mut failed = Vec::new();

    for case_id in case_ids {
        let case = state
            .path_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing path case id {}", case_id));
        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}/seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: false,
        };

        let results = run_scan_test(addr, "path", case_id, config).await;
        let detected = !results.is_empty();
        if detected != case.expected_detection {
            failed.push(format!(
                "case {} ({}) expected_detection={} actual_detection={}",
                case.id, case.name, case.expected_detection, detected
            ));
        }
    }

    assert!(
        failed.len() <= 1,
        "diverse path context mismatches (>{}):\n{}",
        1,
        failed.join("\n")
    );
}

#[tokio::test]
#[ignore]
async fn test_path_reflection_advanced_xss_coverage_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![25, 26, 27, 29, 30, 31, 32, 33];
    let mut detected = 0usize;
    let mut mismatches = Vec::new();

    for case_id in case_ids {
        let case = state
            .path_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing path case id {}", case_id));
        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}/seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: false,
        };

        let results = run_scan_test(addr, "path", case_id, config).await;
        let case_detected = !results.is_empty();
        if case_detected {
            detected += 1;
        }
        if case_detected != case.expected_detection {
            mismatches.push(format!(
                "case {} ({}) expected_detection={} actual_detection={}",
                case.id, case.name, case.expected_detection, case_detected
            ));
        }
    }

    let total = 8usize;
    let detection_rate = detected as f64 / total as f64;

    assert!(
        mismatches.len() <= 2,
        "advanced path context mismatches (>{}):\n{}",
        2,
        mismatches.join("\n")
    );
    assert!(
        detection_rate >= 0.75,
        "advanced path context detection rate below baseline: {}/{} ({:.1}%)",
        detected,
        total,
        detection_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn test_body_reflection_diverse_xss_contexts_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![1, 9, 11, 14, 18, 21, 26, 31, 33];
    let mut failed = Vec::new();
    let client = reqwest::Client::new();

    for case_id in case_ids {
        let case = state
            .body_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing body case id {}", case_id));
        let param_name = case.param_name.as_deref().unwrap_or("query");

        let url = format!("http://{}:{}/body/{}", addr.ip(), addr.port(), case_id);
        let form = [(param_name.to_string(), "seed".to_string())];
        let resp = client
            .post(&url)
            .form(&form)
            .send()
            .await
            .expect("body request");
        let text = resp.text().await.expect("body text");
        let reflected = text.contains(&apply_reflection(&case.reflection, "seed"));

        if reflected != case.expected_detection {
            failed.push(format!(
                "case {} ({}) expected_detection={} actual_reflection={}",
                case.id, case.name, case.expected_detection, reflected
            ));
        }
    }

    assert!(
        failed.len() <= 1,
        "diverse body context mismatches (>{}):\n{}",
        1,
        failed.join("\n")
    );
}

#[tokio::test]
#[ignore]
async fn test_body_reflection_advanced_xss_coverage_v2() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let case_ids = vec![27, 28, 29, 30, 32, 34, 35, 36];
    let mut reflected_count = 0usize;
    let mut mismatches = Vec::new();
    let client = reqwest::Client::new();

    for case_id in case_ids {
        let case = state
            .body_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("Missing body case id {}", case_id));
        let param_name = case.param_name.as_deref().unwrap_or("query");

        let url = format!("http://{}:{}/body/{}", addr.ip(), addr.port(), case_id);
        let form = [(param_name.to_string(), "seed".to_string())];
        let resp = client
            .post(&url)
            .form(&form)
            .send()
            .await
            .expect("body request");
        let text = resp.text().await.expect("body text");
        let reflected = text.contains(&apply_reflection(&case.reflection, "seed"));

        if reflected {
            reflected_count += 1;
        }
        if reflected != case.expected_detection {
            mismatches.push(format!(
                "case {} ({}) expected_detection={} actual_reflection={}",
                case.id, case.name, case.expected_detection, reflected
            ));
        }
    }

    let total = 8usize;
    let reflection_rate = reflected_count as f64 / total as f64;

    assert!(
        mismatches.len() <= 2,
        "advanced body context mismatches (>{}):\n{}",
        2,
        mismatches.join("\n")
    );
    assert!(
        reflection_rate >= 0.90,
        "advanced body context reflection rate below baseline: {}/{} ({:.1}%)",
        reflected_count,
        total,
        reflection_rate * 100.0
    );
}

/// Load realworld mock cases grouped by source TOML file name (category).
fn load_realworld_cases_by_file() -> Result<HashMap<String, Vec<MockCase>>, String> {
    let rw_dir = mock_case_loader::get_mock_cases_base_dir().join("realworld");
    if !rw_dir.exists() {
        return Err(format!(
            "Realworld mock cases directory does not exist: {}",
            rw_dir.display()
        ));
    }

    let entries = std::fs::read_dir(&rw_dir)
        .map_err(|e| format!("Failed to read realworld cases directory: {}", e))?;

    let mut by_file = HashMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }

        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("Invalid realworld case file name: {}", path.display()))?;

        let mut cases = mock_case_loader::load_mock_cases_from_file(&path)?;
        cases.sort_by_key(|c| c.id);
        by_file.insert(file_stem.to_string(), cases);
    }

    Ok(by_file)
}

#[tokio::test]
#[ignore]
async fn test_realworld_xss_scenarios() {
    let (addr, state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut case_ids: Vec<u32> = state.realworld_cases.keys().copied().collect();
    case_ids.sort_unstable();
    let total_cases = case_ids.len();

    if total_cases == 0 {
        println!("No realworld cases found, skipping");
        return;
    }

    println!("Testing {} realworld XSS scenarios", total_cases);

    let mut detected = 0usize;
    let mut expected_total = 0usize;
    let mut expected_detected = 0usize;
    let mut missed_expected_ids = Vec::new();
    let mut false_positive_ids = Vec::new();
    let mut mismatches = Vec::new();

    for case_id in case_ids {
        let case = state
            .realworld_cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("missing realworld case {}", case_id));
        println!(
            "Testing realworld case {}: {} - {}",
            case.id, case.name, case.description
        );

        let config = ScanTestConfig {
            url_suffix: format!("/{case_id}?query=seed"),
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            skip_reflection_header: true,
            skip_reflection_cookie: true,
            skip_reflection_path: true,
        };

        let results = run_scan_test(addr, "realworld/query", case_id, config).await;
        let case_detected = !results.is_empty();

        if case_detected {
            detected += 1;
        }

        if case.expected_detection {
            expected_total += 1;
            if case_detected {
                expected_detected += 1;
            } else {
                missed_expected_ids.push(case.id);
                mismatches.push(format!(
                    "case {} ({}) expected_detection=true actual_detection=false [{}]",
                    case.id,
                    case.name,
                    case.category.as_deref().unwrap_or("unknown")
                ));
            }
        } else if case_detected {
            false_positive_ids.push(case.id);
            mismatches.push(format!(
                "case {} ({}) expected_detection=false actual_detection=true [{}]",
                case.id,
                case.name,
                case.category.as_deref().unwrap_or("unknown")
            ));
        }
    }

    let positive_detection_rate = if expected_total > 0 {
        expected_detected as f64 / expected_total as f64
    } else {
        0.0
    };

    println!(
        "\nrealworld corpus detected: {}/{} ({:.1}%)",
        detected,
        total_cases,
        (detected as f64 / total_cases as f64) * 100.0
    );
    println!(
        "realworld expected-positive coverage: {}/{} ({:.1}%)",
        expected_detected,
        expected_total,
        positive_detection_rate * 100.0
    );

    if !mismatches.is_empty() {
        println!("\nrealworld mismatches:");
        for m in &mismatches {
            println!("  - {}", m);
        }
    }

    // Realworld scenarios are harder; require 75% detection rate minimum
    assert!(
        positive_detection_rate >= 0.75,
        "realworld positive detection rate below 75%: {:.1}% ({}/{})",
        positive_detection_rate * 100.0,
        expected_detected,
        expected_total
    );
}

#[tokio::test]
#[ignore]
async fn test_realworld_xss_by_category() {
    let (addr, _state) = start_mock_server_v2().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let by_file = match load_realworld_cases_by_file() {
        Ok(f) => f,
        Err(e) => {
            println!("Skipping realworld category test: {}", e);
            return;
        }
    };

    if by_file.is_empty() {
        println!("No realworld category files found, skipping");
        return;
    }

    let mut categories: Vec<String> = by_file.keys().cloned().collect();
    categories.sort();

    println!("Testing {} realworld categories", categories.len());

    let mut total_expected = 0usize;
    let mut total_expected_detected = 0usize;

    for category in &categories {
        let cases = by_file
            .get(category)
            .unwrap_or_else(|| panic!("missing category {}", category));

        let mut detected = 0usize;
        let mut expected_total = 0usize;
        let mut expected_detected = 0usize;

        for case in cases {
            let config = ScanTestConfig {
                url_suffix: format!("/{}?query=seed", case.id),
                param: vec![],
                data: None,
                headers: vec![],
                cookies: vec![],
                method: "GET".to_string(),
                skip_reflection_header: true,
                skip_reflection_cookie: true,
                skip_reflection_path: true,
            };

            let results = run_scan_test(addr, "realworld/query", case.id, config).await;
            let case_detected = !results.is_empty();

            if case_detected {
                detected += 1;
            }
            if case.expected_detection {
                expected_total += 1;
                if case_detected {
                    expected_detected += 1;
                }
            }
        }

        total_expected += expected_total;
        total_expected_detected += expected_detected;

        let positive_rate = if expected_total > 0 {
            expected_detected as f64 / expected_total as f64
        } else {
            0.0
        };

        println!(
            "realworld category {}: detected={}/{} positive_coverage={}/{} ({:.1}%)",
            category,
            detected,
            cases.len(),
            expected_detected,
            expected_total,
            positive_rate * 100.0
        );

        // Category-specific minimum detection thresholds
        let category_min_rate = match category.as_str() {
            "search_pages" => 0.90,
            "error_pages" => 0.75,
            "login_forms" => 0.75,
            "api_responses" => 0.60,
            "admin_panels" => 0.65,
            "waf_bypass_scenarios" => 0.40,
            "cve_patterns" => 0.60,
            "redirect_pages" => 0.65,
            "comment_sections" => 0.65,
            "multi_context" => 0.60,
            _ => 0.50,
        };

        assert!(
            positive_rate >= category_min_rate || expected_total == 0,
            "realworld category baseline dropped for {}: {:.1}% < {:.1}%",
            category,
            positive_rate * 100.0,
            category_min_rate * 100.0
        );
    }

    let overall_rate = if total_expected > 0 {
        total_expected_detected as f64 / total_expected as f64
    } else {
        0.0
    };
    println!(
        "\nrealworld overall positive coverage: {}/{} ({:.1}%)",
        total_expected_detected, total_expected,
        overall_rate * 100.0
    );

    assert!(
        overall_rate >= 0.70,
        "realworld overall positive coverage dropped below 70%: {:.1}%",
        overall_rate * 100.0
    );
}
