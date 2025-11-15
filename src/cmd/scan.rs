use clap::Args;
use indicatif::MultiProgress;
use reqwest::header::CONTENT_TYPE;

use scraper::{Html, Selector};
use std::fs;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};
use tokio::task::LocalSet;

use urlencoding;

use crate::encoding::{base64_encode, double_url_encode, html_entity_encode, url_encode};
use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::Result;
use crate::target_parser::*;

/// Default encoders used when the user does not specify any via CLI or config.
/// Centralizing this allows config.rs to reference the same canonical defaults.
pub const DEFAULT_ENCODERS: &[&str] = &["url", "html"];
// Centralized numeric defaults (used by CLI default_value_t and config precedence logic)
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_DELAY_MS: u64 = 0;
pub const DEFAULT_WORKERS: usize = 50;
pub const DEFAULT_MAX_CONCURRENT_TARGETS: usize = 50;
pub const DEFAULT_MAX_TARGETS_PER_HOST: usize = 100;
// Default HTTP method (used by CLI and target parsing)
pub const DEFAULT_METHOD: &str = "GET";

static GLOBAL_ENCODERS: OnceLock<Vec<String>> = OnceLock::new();

fn generate_poc(result: &crate::scanning::result::Result, poc_type: &str) -> String {
    // Helper: selective path encoding (space, #, ?, % only) to keep exploit chars visible.
    fn selective_path_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for ch in s.chars() {
            match ch {
                ' ' => out.push_str("%20"),
                '#' => out.push_str("%23"),
                '?' => out.push_str("%3F"),
                '%' => out.push_str("%25"),
                _ => out.push(ch),
            }
        }
        out
    }

    // Apply user-specified encoders (highest precedence first) to path payload if requested.
    // We only transform the payload portion inside the path (if any); query/body already handled upstream.
    fn apply_path_encoders_if_requested(raw_payload: &str) -> String {
        let encoders = GLOBAL_ENCODERS.get();
        if encoders.is_none() {
            return selective_path_encode(raw_payload);
        }
        let encs = encoders.unwrap();
        // Priority order: explicit user order (stop at first transforming encoder that is not 'none')
        for enc in encs {
            match enc.as_str() {
                "none" => continue,
                "url" => return url_encode(raw_payload),
                "2url" => return double_url_encode(raw_payload),
                "html" => return html_entity_encode(raw_payload),
                "base64" => return base64_encode(raw_payload),
                _ => {}
            }
        }
        // Fallback to selective path encode
        selective_path_encode(raw_payload)
    }

    let attack_url = {
        let mut url = result.data.clone();
        if result.param.starts_with("path_segment_") {
            // Determine if payload (raw or already selectively encoded) is present
            let sel = selective_path_encode(&result.payload);
            let transformed = apply_path_encoders_if_requested(&result.payload);
            if url.contains(&result.payload) {
                // Replace raw with transformed (which might be url/html/base64 etc.)
                url = url.replace(&result.payload, &transformed);
            } else if url.contains(&sel) {
                // Already selectively encoded; consider upgrading if user asked for stronger encoding
                if sel != transformed {
                    url = url.replace(&sel, &transformed);
                }
            } else {
                // Payload not visible (unexpected) – append as synthetic segment
                if !url.ends_with('/') {
                    url.push('/');
                }
                url.push_str(&transformed);
            }
        } else if url.contains('?') {
            // Query mutation already embedded
        } else {
            if !url.contains(&result.payload) {
                let sep = if url.contains('?') { '&' } else { '?' };
                url = format!(
                    "{}{}{}={}",
                    url,
                    sep,
                    result.param,
                    urlencoding::encode(&result.payload)
                );
            }
        }
        url
    };

    match poc_type {
        "plain" => format!(
            "[POC][{}][{}][{}] {}\n",
            result.result_type, result.method, result.inject_type, attack_url
        ),
        "curl" => format!("curl -X {} \"{}\"\n", result.method, attack_url),
        "httpie" => format!("http {} \"{}\"\n", result.method.to_lowercase(), attack_url),
        "http-request" => {
            if let Some(request) = &result.request {
                format!("{}\n", request)
            } else {
                format!("{}\n", attack_url)
            }
        }
        _ => format!(
            "[POC][{}][{}][{}] {}\n",
            result.result_type, result.method, result.inject_type, attack_url
        ),
    }
}

fn extract_context(response: &str, payload: &str) -> Option<(usize, String)> {
    for (line_num, line) in response.lines().enumerate() {
        if line.contains(payload) {
            let mut context = line.to_string();
            if context.len() > 40 {
                if let Some(pos) = line.find(payload) {
                    let start = pos.saturating_sub(20);
                    let end = (pos + payload.len() + 20).min(line.len());
                    context = line[start..end].to_string();
                } else {
                    context = context.chars().take(40).collect();
                }
            }
            return Some((line_num + 1, context));
        }
    }
    None
}

fn is_allowed_content_type(ct: &str) -> bool {
    crate::utils::is_htmlish_content_type(ct)
}

#[cfg(test)]
mod tests {
    use super::{extract_context, generate_poc, is_allowed_content_type};
    use crate::scanning::result::Result as ScanResult;

    #[test]
    fn test_allowed_content_types() {
        assert!(is_allowed_content_type("text/html"));
        assert!(is_allowed_content_type("text/html; charset=utf-8"));
        assert!(is_allowed_content_type("application/xml"));
    }

    #[test]
    fn test_denied_content_types() {
        assert!(!is_allowed_content_type("application/json"));
        assert!(!is_allowed_content_type("text/plain"));
        assert!(!is_allowed_content_type("image/png"));
    }

    #[test]
    fn test_edge_cases() {
        assert!(!is_allowed_content_type(""));
        assert!(!is_allowed_content_type("invalid"));
        assert!(!is_allowed_content_type("application/json; charset=utf-8"));
    }

    #[test]
    fn test_extract_context_basic() {
        let resp = "first line\nzzzPAYzzz\nlast line";
        let (line, ctx) = extract_context(resp, "PAY").expect("should find payload");
        assert_eq!(line, 2);
        assert_eq!(ctx, "zzzPAYzzz");
    }

    #[test]
    fn test_extract_context_trims_long_line() {
        let prefix = "a".repeat(30);
        let suffix = "b".repeat(30);
        let line = format!("{}X{}", prefix, suffix);
        let (ln, ctx) = extract_context(&line, "X").expect("should find payload");
        assert_eq!(ln, 1);
        assert!(ctx.starts_with(&"a".repeat(20)));
        assert!(ctx.contains('X'));
        assert!(ctx.ends_with(&"b".repeat(20)));
    }

    #[test]
    fn test_extract_context_none() {
        assert!(extract_context("no match here", "PAY").is_none());
    }

    #[test]
    fn test_generate_poc_plain_query() {
        let r = ScanResult::new(
            "R".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "q".to_string(),
            "<x>".to_string(),
            "evidence".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            0,
            "msg".to_string(),
        );
        let out = generate_poc(&r, "plain");
        assert!(out.contains("[POC][R][GET][inHTML]"));
        assert!(out.contains("?q=%3Cx%3E"));
    }

    #[test]
    fn test_generate_poc_curl() {
        let r = ScanResult::new(
            "R".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "q".to_string(),
            "<x>".to_string(),
            "evidence".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            0,
            "msg".to_string(),
        );
        let out = generate_poc(&r, "curl");
        assert!(out.starts_with("curl -X GET "));
        assert!(out.contains("?q=%3Cx%3E"));
    }

    #[test]
    fn test_generate_poc_http_request_prefers_request_block() {
        let mut r = ScanResult::new(
            "R".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "q".to_string(),
            "<x>".to_string(),
            "evidence".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            0,
            "msg".to_string(),
        );
        r.request = Some("GET / HTTP/1.1\nHost: example.com".to_string());
        let out = generate_poc(&r, "http-request");
        assert!(out.contains("GET / HTTP/1.1"));
    }

    #[test]
    fn test_generate_poc_path_segment_append() {
        let r = ScanResult::new(
            "R".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://ex.com/foo/bar".to_string(),
            "path_segment_1".to_string(),
            "PAY".to_string(),
            "evidence".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            0,
            "msg".to_string(),
        );
        let out = generate_poc(&r, "plain");
        assert!(out.contains("https://ex.com/foo/bar/PAY"));
    }
}

async fn preflight_content_type(
    target: &crate::target_parser::Target,
    args: &ScanArgs,
) -> Option<(String, Option<(String, String)>, Option<String>)> {
    let client = target.build_client().ok()?;

    // Prefer HEAD for fast Content-Type detection; fallback GET with Range elsewhere if needed
    let mut request_builder =
        crate::utils::build_preflight_request(&client, target, true, Some(8192));
    for (k, v) in &target.headers {
        request_builder = request_builder.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        if !ua.is_empty() {
            request_builder = request_builder.header("User-Agent", ua);
        }
    }
    if !target.cookies.is_empty() {
        let mut cookie_header = String::new();
        for (ck, cv) in &target.cookies {
            cookie_header.push_str(&format!("{}={}; ", ck, cv));
        }
        if !cookie_header.is_empty() {
            cookie_header.pop();
            cookie_header.pop();
            request_builder = request_builder.header("Cookie", cookie_header);
        }
    }
    // Request only the first 8KB to reduce transfer while still allowing meta-tag parsing
    request_builder = request_builder.header("Range", "bytes=0-8191");
    if target.delay > 0 {
        tokio::time::sleep(Duration::from_millis(target.delay)).await;
    }
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let resp = request_builder.send().await.ok()?;
    let headers = resp.headers();
    let ct_opt = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut csp_header = if let Some(v) = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
    {
        Some(("Content-Security-Policy".to_string(), v.to_string()))
    } else if let Some(v) = headers
        .get("content-security-policy-report-only")
        .and_then(|v| v.to_str().ok())
    {
        Some((
            "Content-Security-Policy-Report-Only".to_string(),
            v.to_string(),
        ))
    } else {
        None
    };
    // Always fetch a small body for CSP parsing and AST analysis
    let mut response_body: Option<String> = None;
    let get_req = crate::utils::build_preflight_request(&client, target, false, Some(8192));
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(get_resp) = get_req.send().await {
        if let Ok(body) = get_resp.text().await {
            response_body = Some(body.clone());
            // Only parse CSP if not already found
            if csp_header.is_none() {
                let doc = Html::parse_document(&body);
                if let Ok(sel) = Selector::parse("meta[http-equiv][content]") {
                    for el in doc.select(&sel) {
                        let http_equiv = el
                            .value()
                            .attr("http-equiv")
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if http_equiv == "content-security-policy"
                            || http_equiv == "content-security-policy-report-only"
                        {
                            let content = el.value().attr("content").unwrap_or("").to_string();
                            if !content.is_empty() {
                                let name = if http_equiv == "content-security-policy" {
                                    "Content-Security-Policy".to_string()
                                } else {
                                    "Content-Security-Policy-Report-Only".to_string()
                                };
                                csp_header = Some((name, content));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    ct_opt.map(|ct| (ct, csp_header, response_body))
}

#[derive(Clone, Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Output format: json, jsonl, plain
    #[arg(short, long, default_value = "plain")]
    pub format: String,

    #[clap(help_heading = "OUTPUT")]
    /// Write output to a file. Example: -o 'output.txt'
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    #[clap(help_heading = "OUTPUT")]
    /// Include HTTP request information in output
    #[arg(long)]
    pub include_request: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Include HTTP response information in output
    #[arg(long)]
    pub include_response: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Silence all logs except POC output to STDOUT
    #[arg(short = 'S', long)]
    pub silence: bool,

    #[clap(help_heading = "OUTPUT")]
    /// POC output type: plain, curl, httpie, http-request
    #[arg(long, default_value = "plain")]
    pub poc_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Limit the number of results to display. Example: --limit 10
    #[arg(long)]
    pub limit: Option<usize>,

    #[clap(help_heading = "TARGETS")]
    /// Specify parameter names to analyze (e.g., -p sort -p id:query). Types: query, body, json, cookie, header.
    #[arg(short = 'p', long)]
    pub param: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// HTTP request body data
    #[arg(short = 'd', long)]
    pub data: Option<String>,

    #[clap(help_heading = "TARGETS")]
    /// HTTP headers (can be specified multiple times)
    #[arg(short = 'H', long)]
    pub headers: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// Cookies (can be specified multiple times)
    #[arg(long)]
    pub cookies: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// Override the HTTP method. Example: -X 'PUT' (default "GET")
    #[arg(short = 'X', long, default_value = DEFAULT_METHOD)]
    pub method: String,

    #[clap(help_heading = "TARGETS")]
    /// Set a custom User-Agent header. Example: --user-agent 'Mozilla/5.0'
    #[arg(long)]
    pub user_agent: Option<String>,

    #[clap(help_heading = "TARGETS")]
    /// Load cookies from a raw HTTP request file. Example: --cookie-from-raw 'request.txt'
    #[arg(long)]
    pub cookie_from_raw: Option<String>,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip all discovery checks
    #[arg(long)]
    pub skip_discovery: bool,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip header-based reflection checks
    #[arg(long)]
    pub skip_reflection_header: bool,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip cookie-based reflection checks
    #[arg(long)]
    pub skip_reflection_cookie: bool,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip path-based reflection checks
    #[arg(long)]
    pub skip_reflection_path: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Dictionary analysis with wordlist file path
    #[arg(short = 'W', long)]
    pub mining_dict_word: Option<String>,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Fetch remote parameter wordlists from providers (comma-separated). Options: burp, assetnote
    #[arg(long = "remote-wordlists", value_delimiter = ',')]
    pub remote_wordlists: Vec<String>,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip all mining
    #[arg(long)]
    pub skip_mining: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip dictionary-based mining
    #[arg(long)]
    pub skip_mining_dict: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip DOM-based mining
    #[arg(long)]
    pub skip_mining_dom: bool,

    #[clap(help_heading = "NETWORK")]
    /// Timeout in seconds
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,

    #[clap(help_heading = "NETWORK")]
    /// Delay in milliseconds
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_DELAY_MS)]
    pub delay: u64,

    #[clap(help_heading = "NETWORK")]
    /// Proxy URL (e.g., http://localhost:8080)
    #[arg(long)]
    pub proxy: Option<String>,

    #[clap(help_heading = "NETWORK")]
    /// Follow HTTP redirects. Example: -F
    #[arg(short = 'F', long)]
    pub follow_redirects: bool,

    #[clap(help_heading = "ENGINE")]
    /// Number of concurrent workers
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_WORKERS)]
    pub workers: usize,

    #[clap(help_heading = "ENGINE")]
    /// Maximum number of concurrent targets to scan
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS)]
    pub max_concurrent_targets: usize,

    #[clap(help_heading = "ENGINE")]
    /// Maximum number of targets per host
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST)]
    pub max_targets_per_host: usize,

    #[clap(help_heading = "XSS SCANNING")]
    /// Specify payload encoders to use (comma-separated). Options: none, url, 2url, html, base64. Default: url,html
    #[arg(short = 'e', long, value_delimiter = ',', default_values = &["url", "html"])]
    pub encoders: Vec<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Fetch remote XSS payloads from providers (comma-separated). Options: portswigger, payloadbox
    #[arg(long = "remote-payloads", value_delimiter = ',')]
    pub remote_payloads: Vec<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Load custom blind XSS payloads from a file. Example: --custom-blind-xss-payload 'payloads.txt'
    #[arg(long)]
    pub custom_blind_xss_payload: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Blind XSS callback URL. Example: -b 'https://example.com/callback'
    #[arg(short = 'b', long = "blind")]
    pub blind_callback_url: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Load custom payloads from a file. Example: --custom-payload 'payloads.txt'
    #[arg(long)]
    pub custom_payload: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Only test custom payloads. Example: --only-custom-payload --custom-payload=p.txt
    #[arg(long)]
    pub only_custom_payload: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Skip XSS scanning entirely
    #[arg(long)]
    pub skip_xss_scanning: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Perform deep scanning - test all payloads even after finding XSS
    #[arg(long)]
    pub deep_scan: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Enable Stored XSS mode
    #[arg(long)]
    pub sxss: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// URL to check for Stored XSS reflection (required if --sxss is used)
    #[arg(long, required_if_eq("sxss", "true"))]
    pub sxss_url: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// HTTP method for checking Stored XSS (default "GET")
    #[arg(long, default_value = "GET")]
    pub sxss_method: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Skip AST-based DOM XSS detection (analyzes JavaScript in responses)
    #[arg(long)]
    pub skip_ast_analysis: bool,

    #[clap(help_heading = "TARGETS")]
    /// Targets (URLs or file paths)
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
}

pub async fn run_scan(args: &ScanArgs) {
    // Show banner at the start when using plain format and not silenced
    if args.format == "plain" && !args.silence {
        crate::utils::print_banner_once(env!("CARGO_PKG_VERSION"), true);
    }
    let __dalfox_scan_start = std::time::Instant::now();
    crate::REQUEST_COUNT.store(0, Ordering::Relaxed);
    let log_info = |msg: &str| {
        if args.format == "plain" && !args.silence {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            println!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {}", ts, msg);
        }
    };
    let log_warn = |msg: &str| {
        if args.format == "plain" && !args.silence {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            println!("\x1b[90m{}\x1b[0m \x1b[33mWRN\x1b[0m {}", ts, msg);
        }
    };
    let log_dbg = |msg: &str| {
        if crate::DEBUG.load(Ordering::Relaxed) {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            println!("\x1b[90m{}\x1b[0m \x1b[35mDBG\x1b[0m {}", ts, msg);
        }
    };
    // Ephemeral animated spinner for progress (returns (stop_tx, done_rx))
    let start_spinner =
        |enabled: bool, label: String| -> Option<(oneshot::Sender<()>, oneshot::Receiver<()>)> {
            if !enabled {
                return None;
            }
            let (tx, mut rx) = oneshot::channel::<()>();
            let (done_tx, done_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                loop {
                    print!(
                        "\r\x1b[38;5;247m{} {}\x1b[0m",
                        frames[i % frames.len()],
                        label
                    );
                    let _ = io::stdout().flush();
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(80)) => {},
                        _ = &mut rx => {
                            print!("\r\x1b[2K\r");
                            let _ = io::stdout().flush();
                            let _ = done_tx.send(());
                            break;
                        }
                    }
                    i = (i + 1) % frames.len();
                }
            });
            Some((tx, done_rx))
        };
    // Initialize global encoders once for downstream POC/path handling
    if GLOBAL_ENCODERS.get().is_none() {
        let _ = GLOBAL_ENCODERS.set(args.encoders.clone());
    }
    // Initialize remote payloads/wordlists if requested (honor timeout/proxy)
    if !args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::utils::init_remote_resources_with_options(
            &args.remote_payloads,
            &args.remote_wordlists,
            Some(args.timeout),
            args.proxy.clone(),
        )
        .await
        {
            if !args.silence {
                eprintln!("Error initializing remote resources: {}", e);
            }
        }
    }
    let input_type = if args.input_type == "auto" {
        if args.targets.is_empty() {
            // If no positional targets and STDIN is piped, treat as pipe mode
            if !atty::is(atty::Stream::Stdin) {
                "pipe".to_string()
            } else {
                if !args.silence {
                    eprintln!("Error: No targets specified");
                }
                return;
            }
        } else {
            // Check if all targets look like raw HTTP requests or files containing them
            let is_raw_http = args.targets.iter().all(|t| {
                if crate::target_parser::is_raw_http_request(t) {
                    true
                } else if let Ok(content) = fs::read_to_string(t) {
                    crate::target_parser::is_raw_http_request(&content)
                } else {
                    false
                }
            });
            if is_raw_http {
                "raw-http".to_string()
            } else {
                "auto".to_string()
            }
        }
    } else {
        args.input_type.clone()
    };

    let mut target_strings = Vec::new();

    if input_type == "auto" {
        for target in &args.targets {
            if target.contains("://") {
                target_strings.push(target.clone());
            } else {
                // Try as file first
                match fs::read_to_string(target) {
                    Ok(content) => {
                        for line in content.lines() {
                            let line = line.trim();
                            if !line.is_empty() {
                                target_strings.push(line.to_string());
                            }
                        }
                    }
                    Err(_) => {
                        // Not a file, treat as URL
                        target_strings.push(target.clone());
                    }
                }
            }
        }
    } else {
        target_strings = match input_type.as_str() {
            "url" => args.targets.clone(),
            "file" => {
                if args.targets.is_empty() {
                    if !args.silence {
                        eprintln!("Error: No file specified for input-type=file");
                    }
                    return;
                }
                let file_path = &args.targets[0];
                match fs::read_to_string(file_path) {
                    Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        if !args.silence {
                            eprintln!("Error reading file {}: {}", file_path, e);
                        }
                        return;
                    }
                }
            }
            "pipe" => {
                let mut buffer = String::new();
                match io::stdin().read_to_string(&mut buffer) {
                    Ok(_) => buffer
                        .lines()
                        .filter_map(|line| {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        })
                        .collect(),
                    Err(e) => {
                        if !args.silence {
                            eprintln!("Error reading from stdin: {}", e);
                        }
                        return;
                    }
                }
            }
            "raw-http" => {
                // Treat targets as raw HTTP request files or literals; actual parsing happens later
                args.targets.clone()
            }

            _ => {
                if !args.silence {
                    eprintln!(
                        "Error: Invalid input-type '{}'. Use 'auto', 'url', 'file', 'pipe', or 'raw-http'",
                        input_type
                    );
                }
                return;
            }
        };
    }

    if target_strings.is_empty() {
        if !args.silence {
            eprintln!("Error: No targets specified");
        }
        return;
    }

    let mut parsed_targets = Vec::new();
    for s in target_strings {
        if input_type == "raw-http" {
            // Parse raw HTTP from file or literal via target_parser helper
            let content = match fs::read_to_string(&s) {
                Ok(c) => c,
                Err(_) => s.clone(),
            };
            match crate::target_parser::parse_raw_http_request(&content) {
                Ok(mut target) => {
                    // Apply CLI overrides cautiously
                    if args.method != "GET" {
                        target.method = args.method.clone();
                    }
                    if let Some(d) = &args.data {
                        target.data = Some(d.clone());
                    }
                    for h in &args.headers {
                        if let Some((name, value)) = h.split_once(":") {
                            target
                                .headers
                                .push((name.trim().to_string(), value.trim().to_string()));
                        }
                    }
                    if let Some(ua) = &args.user_agent {
                        target.headers.push(("User-Agent".to_string(), ua.clone()));
                        target.user_agent = Some(ua.clone());
                    } else if target.user_agent.is_none() {
                        target.user_agent = Some("".to_string());
                    }
                    for c in &args.cookies {
                        if let Some((k, v)) = c.split_once('=') {
                            target
                                .cookies
                                .push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                    target.timeout = args.timeout;
                    target.delay = args.delay;
                    target.proxy = args.proxy.clone();
                    target.follow_redirects = args.follow_redirects;
                    target.workers = args.workers;
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        eprintln!("Error parsing raw HTTP request '{}': {}", s, e);
                    }
                    return;
                }
            }
        } else {
            match crate::target_parser::parse_target_with_method(&s) {
                Ok(mut target) => {
                    // Only override data if explicitly provided via CLI
                    if let Some(d) = &args.data {
                        target.data = Some(d.clone());
                    }
                    target.headers = args
                        .headers
                        .iter()
                        .filter_map(|h| {
                            let mut parts = h.splitn(2, ':');
                            let name = parts.next()?.trim();
                            let value = parts.next()?.trim();
                            if name.is_empty() {
                                return None;
                            }
                            Some((name.to_string(), value.to_string()))
                        })
                        .collect();
                    // Only override method if explicitly provided via CLI (not the default)
                    if args.method != DEFAULT_METHOD {
                        target.method = args.method.clone();
                    }
                    if let Some(ua) = &args.user_agent {
                        target.headers.push(("User-Agent".to_string(), ua.clone()));
                        target.user_agent = Some(ua.clone());
                    } else {
                        target.user_agent = Some("".to_string());
                    }
                    target.cookies = args
                        .cookies
                        .iter()
                        .filter_map(|c| c.split_once("="))
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    target.timeout = args.timeout;
                    target.delay = args.delay;
                    target.proxy = args.proxy.clone();
                    target.follow_redirects = args.follow_redirects;
                    target.workers = args.workers;
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        eprintln!("Error parsing target '{}': {}", s, e);
                    }
                    return;
                }
            }
        }
    }

    if parsed_targets.is_empty() {
        if !args.silence {
            eprintln!("Error: No targets specified");
        }
        return;
    }

    // Load cookies from raw HTTP request file if specified
    if let Some(path) = &args.cookie_from_raw {
        for target in &mut parsed_targets {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            } else {
                if !args.silence {
                    eprintln!("Error reading cookie file: {}", path);
                }
            }
        }
    }

    let results = Arc::new(Mutex::new(Vec::<Result>::new()));

    let multi_pb: Option<Arc<MultiProgress>> = None;

    // Group targets by host
    let mut host_groups: std::collections::HashMap<String, Vec<Target>> =
        std::collections::HashMap::new();
    for target in parsed_targets {
        let host = target.url.host_str().unwrap_or("unknown").to_string();
        host_groups.entry(host).or_insert(Vec::new()).push(target);
    }

    let total_targets = host_groups.values().map(|g| g.len()).sum::<usize>();
    let preflight_idx = Arc::new(AtomicUsize::new(0));
    let analyze_idx = Arc::new(AtomicUsize::new(0));
    let scan_idx = Arc::new(AtomicUsize::new(0));
    let overall_done = Arc::new(AtomicUsize::new(0));

    // Start global overall progress ticker when multiple targets; runs across preflight, analysis, and scanning
    let overall_ticker = if args.format == "plain" && !args.silence && total_targets > 1 {
        let results_clone = results.clone();
        let overall_done_clone = overall_done.clone();
        let total_targets_copy = total_targets;
        let (tx, mut rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0usize;
            loop {
                let done = overall_done_clone.load(Ordering::Relaxed);
                let percent = (done * 100) / std::cmp::max(1, total_targets_copy);
                let findings = results_clone.lock().await.len();
                print!(
                    "\r\x1b[38;5;247m{} overall: targets={}  done={}  progress={}{}  findings={}\x1b[0m",
                    frames[i % frames.len()],
                    total_targets_copy,
                    done,
                    percent,
                    "%",
                    findings
                );
                let _ = io::stdout().flush();
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(120)) => {},
                    _ = &mut rx => {
                        // clear the line and exit
                        print!("\r\x1b[2K\r");
                        let _ = io::stdout().flush();
                        let _ = done_tx.send(());
                        break;
                    }
                }
                i = (i + 1) % frames.len();
            }
        });
        Some((tx, done_rx))
    } else {
        None
    };
    // Perform blind XSS scanning if callback URL is provided
    if let Some(callback_url) = &args.blind_callback_url {
        if !args.silence && args.format == "plain" {
            println!(
                "Performing blind XSS scanning with callback URL: {}",
                callback_url
            );
        }
        for group in host_groups.values() {
            for target in group {
                crate::scanning::blind_scanning(target, callback_url).await;
            }
        }
    }

    // Analyze parameters for each target concurrently (bounded) instead of sequentially
    for group in host_groups.values_mut() {
        // Limit targets per host
        if group.len() > args.max_targets_per_host {
            group.truncate(args.max_targets_per_host);
        }

        // Bound overall concurrency for preflight + analysis with the same cap as scanning
        let pre_analyze_semaphore =
            Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));

        // Move targets out of the group to own them in spawned tasks
        let mut drained: Vec<Target> = Vec::new();
        drained.append(group);

        let processed: Vec<Target> = {
            let local = LocalSet::new();
            // Clone shared indices and config for this LocalSet to avoid moving them
            let preflight_idx_outer = preflight_idx.clone();
            let analyze_idx_outer = analyze_idx.clone();
            let args_outer = args.clone();
            let pre_analyze_semaphore_outer = pre_analyze_semaphore.clone();
            let total_targets_outer = total_targets;
            let multi_pb_outer = multi_pb.clone();
            let results_outer = results.clone();
            local.run_until(async move {
                let mut handles = vec![];

                for mut target in drained {
            let args_clone = args_outer.clone();
            let sem = pre_analyze_semaphore_outer.clone();
            let preflight_idx_clone = preflight_idx_outer.clone();
            let analyze_idx_clone = analyze_idx_outer.clone();
            let total_targets_copy = total_targets_outer;
            let multi_pb_clone = multi_pb_outer.clone();
            let results_clone = results_outer.clone();

            handles.push(tokio::task::spawn_local(async move {
                // Bound concurrency across targets for preflight + analysis
                let _permit = sem.acquire_owned().await.unwrap();
                let mut __preflight_csp_present = false;
                let mut __preflight_csp_header: Option<(String, String)> = None;
                let mut preflight_response_body: Option<String> = None;

                // Preflight Content-Type check (skip denylisted types unless deep-scan)
                if !args_clone.deep_scan {
                    let current = preflight_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    // Print an ephemeral spinner and auto-clear when finished
                    let label = if total_targets_copy > 1 {
                        format!(
                            "[{}/{}] preflight: {}",
                            current, total_targets_copy, target.url
                        )
                    } else {
                        format!("preflight: {}", target.url)
                    };
                    let __preflight_spinner = if total_targets_copy == 1 { start_spinner(!args_clone.silence, label) } else { None };

                    let __preflight_info = preflight_content_type(&target, &args_clone).await;
                    if let Some((tx, done_rx)) = __preflight_spinner {
                        let _ = tx.send(());
                        let _ = done_rx.await;
                    }
                    
                    if let Some((ct, csp_header, response_body)) = __preflight_info {
                        preflight_response_body = response_body;
                        if let Some((hn, hv)) = csp_header {
                            __preflight_csp_present = true;
                            __preflight_csp_header = Some((hn, hv));
                        }
                        if !is_allowed_content_type(&ct) {
                            // Skip this target early
                            return None;
                        }
                    }
                }

                // Pretty start log per target (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            &target.url.to_string(),
                        ));
                        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                        println!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} start scan to {}",
                            ts, sid, target.url
                        );
                    } else {
                        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                        println!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m start scan to {}",
                            ts, target.url
                        );
                        if __preflight_csp_present {
                            println!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m CSP: enabled", ts);
                            if let Some((hn, hv)) = &__preflight_csp_header {
                                println!("  \x1b[90m└──\x1b[0m \x1b[38;5;247m{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m", hn, hv);
                            }
                        }
                    }
                }

                // Silence parameter analysis logs and progress; show spinner for single-target runs
                let current = analyze_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let __analyze_spinner = if total_targets_copy == 1 {
                    start_spinner(
                        !args_clone.silence,
                        if total_targets_copy > 1 {
                            format!("[{}/{}] analyzing: {}", current, total_targets_copy, target.url)
                        } else {
                            format!("analyzing: {}", target.url)
                        },
                    )
                } else {
                    None
                };
                let mut __analysis_args = args_clone.clone();
                __analysis_args.silence = true;
                analyze_parameters(&mut target, &__analysis_args, multi_pb_clone).await;
                if let Some((tx, done_rx)) = __analyze_spinner {
                    let _ = tx.send(());
                    let _ = done_rx.await;
                }

                // Run AST-based DOM XSS analysis on the initial response (enabled by default)
                if !args_clone.skip_ast_analysis {
                    if let Some(response_text) = preflight_response_body {
                        let js_blocks = crate::scanning::ast_integration::extract_javascript_from_html(&response_text);
                        for js_code in js_blocks {
                            let findings = crate::scanning::ast_integration::analyze_javascript_for_dom_xss(
                                &js_code,
                                target.url.as_str(),
                            );
                            for finding in findings {
                                // Create an AST-based DOM XSS result
                                let ast_result = crate::scanning::result::Result::new(
                                    "A".to_string(), // AST-detected
                                    "DOM-XSS".to_string(),
                                    target.method.clone(),
                                    target.url.to_string(),
                                    "-".to_string(), // No specific parameter
                                    finding.clone(),
                                    "AST-based static DOM XSS analysis".to_string(),
                                    "CWE-79".to_string(),
                                    "High".to_string(),
                                    0,
                                    finding,
                                );
                                // Add to shared results
                                results_clone.lock().await.push(ast_result);
                            }
                        }
                    }
                }

                // Pretty reflection summary (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    let n = target.reflection_params.len();
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            &target.url.to_string(),
                        ));
                        println!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {} found reflected \x1b[33m{}\x1b[0m params",
                            ts, sid, n
                        );
                    } else {
                        println!(
                            "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m found reflected \x1b[33m{}\x1b[0m params",
                            ts, n
                        );
                    }
                    for (i, p) in target.reflection_params.iter().enumerate() {
                        let bullet = if i + 1 == n { "└──" } else { "├──" };
                        let valid = p
                            .valid_specials
                            .as_ref()
                            .map(|v| v.iter().collect::<String>())
                            .unwrap_or_else(|| "-".to_string());
                        let invalid = p
                            .invalid_specials
                            .as_ref()
                            .map(|v| v.iter().collect::<String>())
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "  \x1b[90m{}\x1b[0m \x1b[38;5;247m{}\x1b[0m \x1b[38;5;247mvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\" \x1b[38;5;247minvalid_specials=\x1b[0m\"\x1b[38;5;247m{}\x1b[0m\"",
                            bullet, p.name, valid, invalid
                        );
                    }
                    // Debug: estimate total test cases (requests) to be run during scanning
                    if crate::DEBUG.load(Ordering::Relaxed) && args_clone.format == "plain" && !args_clone.silence {
                        // encoder expansion factor
                        let enc_factor = if args_clone.encoders.iter().any(|e| e == "none") {
                            1
                        } else {
                            let mut f = 1;
                            for e in ["url", "html", "2url", "base64"] {
                                if args_clone.encoders.iter().any(|x| x == e) {
                                    f += 1;
                                }
                            }
                            f
                        };
                        let mut total: usize = 0;
                        for p in &target.reflection_params {
                            let refl_len = if let Some(ctx) = &p.injection_context {
                                crate::scanning::xss_common::get_dynamic_payloads(ctx, &args_clone)
                                    .unwrap_or_else(|_| vec![])
                                    .len()
                            } else {
                                // Fallback estimate: HTML dynamic payloads + JS payloads (with encoders), excluding remote payloads
                                let html_base_len = crate::payload::get_dynamic_xss_html_payloads().len();
                                let html_len = html_base_len * enc_factor;
                                let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
                                html_len + js_len
                            };
                            let dom_len = match &p.injection_context {
                                Some(crate::parameter_analysis::InjectionContext::Javascript(_)) => 0,
                                Some(ctx) => {
                                    // Use locally generated payloads and apply encoder factor; exclude remote payloads
                                    let base = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
                                    base.len() * enc_factor
                                }
                                None => {
                                    // Unknown context: use HTML + Attribute payloads without remote, apply encoder factor
                                    let html = crate::payload::get_dynamic_xss_html_payloads();
                                    let attr = crate::payload::get_dynamic_xss_attribute_payloads();
                                    (html.len() + attr.len()) * enc_factor
                                }
                            };
                            total = total.saturating_add(refl_len.saturating_mul(1 + dom_len));
                        }
                        if args_clone.format == "plain" && !args_clone.silence {
                            log_dbg(&format!("{} test cases (reqs) estimated", total));
                        }
                    }
                }

                Some(target)
            }));
        }

        // Collect processed targets (skipping those filtered by preflight)
                let mut processed: Vec<Target> = Vec::new();
                for handle in handles {
                    if let Ok(res) = handle.await {
                        if let Some(t) = res {
                            processed.push(t);
                        }
                    }
                }
                processed
            }).await
        };

        // Replace group with processed targets
        *group = processed;
    }

    // Semaphore for limiting concurrent targets across all hosts
    let global_semaphore = Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));

    let mut group_handles = vec![];

    for (host, group) in host_groups {
        if let Some(lim) = args.limit {
            if results.lock().await.len() >= lim {
                break;
            }
        }
        let global_semaphore_clone = global_semaphore.clone();
        let multi_pb_clone = multi_pb.clone();
        let args_arc = Arc::new(args.clone());
        let results_clone = results.clone();

        let scan_idx = scan_idx.clone();
        let overall_done_clone = overall_done.clone();
        let group_handle = tokio::spawn(async move {
            // Calculate total overall tasks for this group
            let mut total_overall_tasks = 0u64;
            for target in &group {
                for param in &target.reflection_params {
                    let payloads = if let Some(context) = &param.injection_context {
                        crate::scanning::xss_common::get_dynamic_payloads(context, &args_arc)
                            .unwrap_or_else(|_| vec![])
                    } else {
                        crate::scanning::xss_common::get_dynamic_payloads(
                            &crate::parameter_analysis::InjectionContext::Html(None),
                            &args_arc,
                        )
                        .unwrap_or_else(|_| vec![])
                    };
                    total_overall_tasks += payloads.len() as u64;
                }
            }

            let overall_pb: Option<Arc<Mutex<indicatif::ProgressBar>>> = if let Some(ref mp) =
                multi_pb_clone
            {
                let pb = mp.add(indicatif::ProgressBar::new(total_overall_tasks));
                pb.set_style(
                    indicatif::ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} Overall scanning")
                        .unwrap()
                        .progress_chars("#>-"),
                );
                Some(Arc::new(Mutex::new(pb)))
            } else {
                None
            };

            let mut target_handles = vec![];

            for target in group {
                if let Some(lim) = args_arc.limit {
                    if results_clone.lock().await.len() >= lim {
                        break;
                    }
                }
                let permit = global_semaphore_clone
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                let args_clone = args_arc.clone();
                let results_clone_inner = results_clone.clone();
                let multi_pb_clone_inner = multi_pb_clone.clone();
                let overall_pb_clone = overall_pb.clone();
                let scan_idx_clone = scan_idx.clone();
                let total_targets_copy = total_targets;

                let target_handle = tokio::spawn(async move {
                    if !args_clone.skip_xss_scanning {
                        let __scan_spinner = {
                            let enabled = !args_clone.silence && total_targets_copy == 1;
                            let current = scan_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
                            start_spinner(
                                enabled,
                                if total_targets_copy > 1 {
                                    format!(
                                        "[{}/{}] scanning: {}",
                                        current, total_targets_copy, target.url
                                    )
                                } else {
                                    format!("scanning: {}", target.url)
                                },
                            )
                        };
                        crate::scanning::run_scanning(
                            &target,
                            args_clone.clone(),
                            results_clone_inner,
                            multi_pb_clone_inner,
                            overall_pb_clone,
                        )
                        .await;
                        if let Some((tx, done_rx)) = __scan_spinner {
                            let _ = tx.send(());
                            let _ = done_rx.await;
                        }
                    }
                    drop(permit);
                });
                target_handles.push(target_handle);
            }

            for handle in target_handles {
                handle.await.unwrap();
                // Update global overall progress line when multiple targets
                overall_done_clone.fetch_add(1, Ordering::Relaxed);
                // overall ticker handles rendering globally
            }

            if let Some(pb) = overall_pb {
                pb.lock()
                    .await
                    .finish_with_message(format!("All scanning completed for {}", host));
            }
        });
        group_handles.push(group_handle);
    }

    for handle in group_handles {
        handle.await.unwrap();
        if let Some(lim) = args.limit {
            if results.lock().await.len() >= lim {
                break;
            }
        }
    }

    if args.format == "plain" && !args.silence && total_targets > 1 {
        if let Some((tx, done_rx)) = overall_ticker {
            let _ = tx.send(());
            let _ = done_rx.await;
        }
        println!();
    }
    // Output results
    let final_results = results.lock().await;
    let limit = args.limit.unwrap_or(usize::MAX);
    let display_results_len = std::cmp::min(final_results.len(), limit);
    let display_results = &final_results[..display_results_len];
    let output_content = if args.format == "json" {
        crate::scanning::result::Result::results_to_json(
            display_results,
            args.include_request,
            args.include_response,
            true,
        )
    } else if args.format == "jsonl" {
        crate::scanning::result::Result::results_to_jsonl(
            display_results,
            args.include_request,
            args.include_response,
        )
    } else if args.format == "plain" {
        let mut output = String::new();

        // Plain logger: XSS summary before POC lines
        let v_count = display_results
            .iter()
            .filter(|r| r.result_type == "V")
            .count();
        log_warn(&format!("XSS found \x1b[33m{}\x1b[0m XSS", v_count));

        for result in display_results {
            let mut poc_line = generate_poc(result, &args.poc_type);
            if args.poc_type == "plain" {
                if result.result_type == "R" {
                    let trimmed = poc_line.trim_end();
                    poc_line = format!("\x1b[33m{}\x1b[0m\n", trimmed);
                } else if result.result_type == "V" {
                    let trimmed = poc_line.trim_end();
                    poc_line = format!("\x1b[31m{}\x1b[0m\n", trimmed);
                }
            }
            output.push_str(&poc_line);

            // Determine context (for Line rendering)
            let context_info = if let Some(resp) = &result.response {
                extract_context(resp, &result.payload)
            } else {
                None
            };

            // Build sequence of detail sections to render under POC
            let mut sections: Vec<&str> = vec!["Issue", "Payload"];
            if context_info.is_some() {
                sections.push("Line");
            }
            let want_request = args.include_request && result.request.is_some();
            let want_response = args.include_response && result.response.is_some();
            if want_request {
                sections.push("Request");
            }
            if want_response {
                sections.push("Response");
            }
            let last_idx = sections.len().saturating_sub(1);

            // 1) Issue
            let issue_text = if result.result_type == "R" {
                "XSS payload reflected"
            } else {
                "XSS payload DOM object identified"
            };
            let mut idx = 0usize;
            let bullet = if idx == last_idx {
                "└──"
            } else {
                "├──"
            };
            output.push_str(&format!(
                "  \x1b[90m{}\x1b[0m \x1b[38;5;247mIssue:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
                bullet, issue_text
            ));
            idx += 1;

            // 2) Payload
            let bullet = if idx == last_idx {
                "└──"
            } else {
                "├──"
            };
            output.push_str(&format!(
                "  \x1b[90m{}\x1b[0m \x1b[38;5;247mPayload:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
                bullet, result.payload
            ));
            idx += 1;

            // 3) Line (context), if available
            if let Some((line_num, context)) = context_info {
                let bullet = if idx == last_idx {
                    "└──"
                } else {
                    "├──"
                };
                output.push_str(&format!(
                    "  \x1b[90m{}\x1b[0m \x1b[38;5;247mL{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
                    bullet, line_num, context
                ));
                idx += 1;
            }

            // 4) Request, if included
            if want_request {
                let bullet = if idx == last_idx {
                    "└──"
                } else {
                    "├──"
                };
                output.push_str(&format!(
                    "  \x1b[90m{}\x1b[0m \x1b[38;5;247mRequest:\x1b[0m\n",
                    bullet
                ));
                if let Some(req) = &result.request {
                    for line in req.lines() {
                        output.push_str(&format!("      \x1b[38;5;247m{}\x1b[0m\n", line));
                    }
                }
                idx += 1;
            }

            // 5) Response, if included
            if want_response {
                let bullet = if idx == last_idx {
                    "└──"
                } else {
                    "├──"
                };
                output.push_str(&format!(
                    "  \x1b[90m{}\x1b[0m \x1b[38;5;247mResponse:\x1b[0m\n",
                    bullet
                ));
                if let Some(resp) = &result.response {
                    for line in resp.lines() {
                        output.push_str(&format!("      \x1b[38;5;247m{}\x1b[0m\n", line));
                    }
                }
            }
        }
        output
    } else {
        let mut output = String::new();
        for result in display_results {
            output.push_str(&format!(
                "Found XSS: {} - {}\n",
                result.param, result.payload
            ));
        }
        output
    };

    if let Some(output_path) = &args.output {
        match std::fs::write(output_path, &output_content) {
            Ok(_) => {
                if !args.silence {
                    println!("Results written to {}", output_path);
                }
            }
            Err(e) => {
                if !args.silence {
                    eprintln!("Error writing to file {}: {}", output_path, e);
                }
            }
        }
    } else {
        println!("{}", output_content);
    }

    // Request/Response are displayed inline under each POC in plain mode.
    if args.format == "plain" && !args.silence {
        let __dalfox_elapsed = __dalfox_scan_start.elapsed().as_secs_f64();
        log_info(&format!(
            "scan completed in {:.3} seconds",
            __dalfox_elapsed
        ));
        if crate::DEBUG.load(Ordering::Relaxed) {
            log_dbg(&format!(
                "{} test cases (reqs) sent",
                crate::REQUEST_COUNT.load(Ordering::Relaxed)
            ));
        }
    }
}
