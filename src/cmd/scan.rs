use clap::Args;
use indicatif::MultiProgress;
use reqwest::header::CONTENT_TYPE;

use scraper::Html;
use std::collections::HashMap;
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

use crate::encoding::{
    base64_encode, double_url_encode, html_entity_encode, quadruple_url_encode, triple_url_encode,
    url_encode,
};
use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::{FindingType, Result};
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
// Sanity caps for CLI scan args. The server uses tighter caps in
// crate::cmd::job; CLI users may legitimately want longer timeouts for
// slow targets but values past these almost always indicate a typo or a
// stale config file with stray zeros.
pub const CLI_MAX_TIMEOUT_SECS: u64 = 3600;
pub const CLI_MAX_DELAY_MS: u64 = 60_000;
pub const CLI_MAX_WORKERS: usize = 500;
// Default HTTP method (used by CLI and target parsing)
pub const DEFAULT_METHOD: &str = "GET";

static GLOBAL_ENCODERS: OnceLock<Vec<String>> = OnceLock::new();

use crate::scanning::selectors;

fn build_ast_dom_message(
    description: &str,
    source: &str,
    target_url: &str,
    payload: &str,
) -> String {
    if let Some(hint) =
        crate::scanning::ast_integration::build_dom_xss_manual_poc_hint(target_url, source, payload)
    {
        format!("{description} (검증 필요) [manual POC: {hint}]")
    } else {
        format!("{description} (검증 필요) [경량 확인: 파라미터 없음]")
    }
}

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
    fn apply_path_encoders_if_requested(payload: &str) -> String {
        let Some(encs) = GLOBAL_ENCODERS.get() else {
            return selective_path_encode(payload);
        };
        // Priority order: explicit user order (stop at first transforming encoder that is not 'none')
        for enc in encs {
            match enc.as_str() {
                "none" => continue,
                "url" => return url_encode(payload),
                "2url" => return double_url_encode(payload),
                "3url" => return triple_url_encode(payload),
                "4url" => return quadruple_url_encode(payload),
                "html" => return html_entity_encode(payload),
                "base64" => return base64_encode(payload),
                _ => {}
            }
        }
        // Fallback to selective path encode
        selective_path_encode(payload)
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
        } else if !url.contains(&result.payload) {
            let sep = if url.contains('?') { '&' } else { '?' };
            url = format!(
                "{}{}{}={}",
                url,
                sep,
                result.param,
                urlencoding::encode(&result.payload)
            );
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
        if let Some(pos) = line.find(payload) {
            let context = if line.len() > 40 {
                let start = pos.saturating_sub(20);
                let end = (pos + payload.len() + 20).min(line.len());
                // Use get to avoid panic on multibyte boundaries
                line.get(start..end).unwrap_or(line).to_string()
            } else {
                line.to_string()
            };
            return Some((line_num + 1, context));
        }
    }
    None
}

fn result_priority(result: &Result) -> u8 {
    let type_score = match result.result_type {
        FindingType::Verified => 3,
        FindingType::AstDetected => 2,
        FindingType::Reflected => 1,
    };
    let severity_score = match result.severity.as_str() {
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    };
    type_score * 10 + severity_score
}

// AST findings can be produced in multiple scan stages (preflight/probe/reflection loop).
// Keep one strongest result per equivalent AST fingerprint to reduce duplicate noise.
fn dedupe_ast_results(results: Vec<Result>) -> Vec<Result> {
    let mut out: Vec<Result> = Vec::with_capacity(results.len());
    let mut ast_index_by_key: HashMap<String, usize> = HashMap::new();

    for result in results {
        if result.message_id != 0 {
            out.push(result);
            continue;
        }

        // Use evidence-centric fingerprint so duplicates across stages
        // (preflight/probe/reflection loop) collapse into one.
        let key = format!(
            "{}|{}|{}",
            result.inject_type, result.method, result.evidence
        );

        if let Some(existing_idx) = ast_index_by_key.get(&key).copied() {
            if result_priority(&result) > result_priority(&out[existing_idx]) {
                out[existing_idx] = result;
            }
        } else {
            ast_index_by_key.insert(key, out.len());
            out.push(result);
        }
    }

    out
}

fn is_allowed_content_type(ct: &str) -> bool {
    crate::utils::is_xss_scannable_content_type(ct)
}

/// Preflight result containing content-type, CSP, body, WAF, and tech detection info.
struct PreflightResult {
    content_type: String,
    csp_header: Option<(String, String)>,
    response_body: Option<String>,
    waf_result: crate::waf::WafDetectionResult,
    tech_result: crate::scanning::tech_detect::TechDetectionResult,
}

/// Compact, user-facing summary of a reqwest network failure. Keeps the
/// preflight banner single-line (e.g. "TLS timeout", "connection refused",
/// "DNS error") instead of dumping the full reqwest::Error chain.
fn describe_reqwest_failure(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connection failed"
    } else if err.is_request() {
        "request error"
    } else if err.is_redirect() {
        "redirect loop"
    } else if err.is_status() {
        "bad status"
    } else if err.is_body() {
        "body read failed"
    } else if err.is_decode() {
        "decode error"
    } else if err.is_builder() {
        "request build error"
    } else {
        "network error"
    }
}

async fn preflight_content_type(
    target: &crate::target_parser::Target,
    args: &ScanArgs,
) -> Option<PreflightResult> {
    let client = match target.build_client() {
        Ok(c) => c,
        Err(e) => {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "[DBG] preflight: failed to build HTTP client for {}: {}",
                    target.url, e
                );
            }
            return None;
        }
    };

    // Prefer HEAD for fast Content-Type detection
    // build_preflight_request already applies headers, UA, and cookies consistently
    if target.delay > 0 {
        tokio::time::sleep(Duration::from_millis(target.delay)).await;
    }
    // Retry once on transient connect/timeout errors. At high worker counts
    // ECONNREFUSED can spuriously fire even against healthy servers as the OS
    // throttles new connection establishment; a single short backoff usually
    // recovers without losing the target. Non-connect errors (status / body /
    // decode) fail fast — retry can't help.
    const PREFLIGHT_MAX_ATTEMPTS: u32 = 2;
    const PREFLIGHT_RETRY_BACKOFF_MS: u64 = 200;
    let mut attempt = 0u32;
    let resp = loop {
        attempt += 1;
        let request_builder =
            crate::utils::build_preflight_request(&client, target, true, Some(8192));
        crate::tick_request_count();
        match request_builder.send().await {
            Ok(r) => break r,
            Err(e) => {
                let transient = e.is_connect() || e.is_timeout();
                if transient && attempt < PREFLIGHT_MAX_ATTEMPTS {
                    if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                        eprintln!(
                            "[DBG] preflight transient {} (attempt {}): {} — retrying",
                            describe_reqwest_failure(&e),
                            attempt,
                            target.url
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(PREFLIGHT_RETRY_BACKOFF_MS)).await;
                    continue;
                }
                // Surface a single-line diagnostic for hard reachability failures
                // (TLS timeouts, connection refused, DNS, etc.) so users can
                // distinguish a quiet scan from an unreachable target. Suppressed
                // when --silence is on; the debug channel always carries it.
                let reason = describe_reqwest_failure(&e);
                if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!("[DBG] preflight unreachable: {} ({})", target.url, reason);
                }
                if !args.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    eprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[31mUNREACHABLE\x1b[0m {} ({})",
                        ts, target.url, reason
                    );
                }
                return None;
            }
        }
    };
    let head_status = resp.status().as_u16();
    let head_headers = resp.headers().clone();
    let ct_opt = head_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut csp_header = head_headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|v| ("Content-Security-Policy".to_string(), v.to_string()))
        .or_else(|| {
            head_headers
                .get("content-security-policy-report-only")
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    (
                        "Content-Security-Policy-Report-Only".to_string(),
                        v.to_string(),
                    )
                })
        });

    // Technology detection accumulator
    let mut tech_result = crate::scanning::tech_detect::TechDetectionResult::default();

    // WAF detection from HEAD response headers (zero extra requests)
    let mut waf_result = if args.waf_bypass != "off" {
        crate::waf::fingerprint_from_response(&head_headers, None, head_status)
    } else {
        crate::waf::WafDetectionResult::default()
    };

    // Always fetch a small body for CSP parsing and AST analysis
    let mut response_body: Option<String> = None;
    let get_req = crate::utils::build_preflight_request(&client, target, false, Some(8192));
    crate::tick_request_count();
    if let Ok(get_resp) = get_req.send().await {
        let get_status = get_resp.status().as_u16();
        let get_headers = get_resp.headers().clone();
        if let Ok(body) = get_resp.text().await {
            response_body = Some(body.clone());

            // WAF detection from GET response (headers + body)
            if args.waf_bypass != "off" {
                let body_waf =
                    crate::waf::fingerprint_from_response(&get_headers, Some(&body), get_status);
                crate::waf::merge_results(&mut waf_result, body_waf);
            }

            // Technology/framework detection from GET response
            tech_result =
                crate::scanning::tech_detect::detect_technologies(&get_headers, Some(&body));

            // Only parse CSP if not already found
            if csp_header.is_none() {
                let doc = Html::parse_document(&body);
                {
                    let sel = selectors::meta_csp();
                    for el in doc.select(sel) {
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

    // Provocation probe for stronger WAF detection (costs one extra request)
    if args.waf_bypass != "off" && !args.skip_waf_probe {
        let probe_result = crate::waf::fingerprint_with_probe(target, &client).await;
        crate::waf::merge_results(&mut waf_result, probe_result);
    }

    // Handle --force-waf override
    if let Some(ref forced) = args.force_waf {
        waf_result = crate::waf::WafDetectionResult {
            detected: vec![crate::waf::WafFingerprint {
                waf_type: parse_waf_type(forced),
                confidence: 1.0,
                evidence: "forced via --force-waf".to_string(),
            }],
        };
    }

    // Drop fingerprints below the user-configured minimum confidence.
    // Default 0.0 keeps every match; users tighten this to suppress
    // weak signals (0.3 "Request blocked", 0.5 "Server: Google
    // Frontend", etc.) that often false-positive on benign origins.
    if args.waf_min_confidence > 0.0 {
        waf_result
            .detected
            .retain(|fp| fp.confidence >= args.waf_min_confidence);
    }

    ct_opt.map(|ct| PreflightResult {
        content_type: ct,
        csp_header,
        response_body,
        waf_result,
        tech_result,
    })
}

/// Parse a WAF type string (from --force-waf) into a WafType enum.
fn parse_waf_type(s: &str) -> crate::waf::WafType {
    match s.to_ascii_lowercase().as_str() {
        "cloudflare" | "cf" => crate::waf::WafType::Cloudflare,
        "aws" | "awswaf" | "aws-waf" => crate::waf::WafType::AwsWaf,
        "akamai" => crate::waf::WafType::Akamai,
        "imperva" | "incapsula" => crate::waf::WafType::Imperva,
        "modsecurity" | "modsec" => crate::waf::WafType::ModSecurity,
        "owasp-crs" | "owaspcrs" | "crs" => crate::waf::WafType::OwaspCrs,
        "sucuri" => crate::waf::WafType::Sucuri,
        "f5" | "bigip" | "f5-bigip" => crate::waf::WafType::F5BigIp,
        "barracuda" => crate::waf::WafType::Barracuda,
        "fortiweb" | "forti" => crate::waf::WafType::FortiWeb,
        "azure" | "azurewaf" | "azure-waf" => crate::waf::WafType::AzureWaf,
        "cloudarmor" | "cloud-armor" | "gcp" => crate::waf::WafType::CloudArmor,
        "fastly" => crate::waf::WafType::Fastly,
        "wordfence" => crate::waf::WafType::Wordfence,
        other => crate::waf::WafType::Unknown(other.to_string()),
    }
}

#[derive(Clone, Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Output format: json, jsonl, plain, markdown, sarif, toml
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
    /// Include both HTTP request and response information in output (equivalent to --include-request --include-response)
    #[arg(long)]
    pub include_all: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Disable colored output (also respects NO_COLOR env var)
    #[arg(long)]
    pub no_color: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Silence all logs except POC output to STDOUT
    #[arg(short = 'S', long)]
    pub silence: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Dry-run mode: parse targets, run parameter discovery, and report what would be scanned without sending attack payloads. Outputs target count, discovered parameters, and estimated request count.
    #[arg(long)]
    pub dry_run: bool,

    #[clap(help_heading = "OUTPUT")]
    /// POC output type: plain, curl, httpie, http-request
    #[arg(long, default_value = "plain")]
    pub poc_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Limit the number of results to display. Example: --limit 10
    #[arg(long)]
    pub limit: Option<usize>,

    #[clap(help_heading = "OUTPUT")]
    /// Filter which finding types count toward --limit: all (default), v (verified), r (reflected), a (AST DOM XSS). Example: --limit-result-type v
    #[arg(long, default_value = "all", value_parser = clap::builder::PossibleValuesParser::new(["all", "v", "r", "a", "V", "R", "A"]))]
    pub limit_result_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Filter output to show only specific finding types (comma-separated). Options: v (verified), r (reflected), a (AST DOM XSS). Example: --only-poc "v,r"
    #[arg(long, value_delimiter = ',')]
    pub only_poc: Vec<String>,

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

    #[clap(help_heading = "SCOPE")]
    /// Include only URLs matching these patterns (regex, can be specified multiple times)
    #[arg(long)]
    pub include_url: Vec<String>,

    #[clap(help_heading = "SCOPE")]
    /// Exclude URLs matching these patterns (regex, can be specified multiple times)
    #[arg(long)]
    pub exclude_url: Vec<String>,

    #[clap(help_heading = "SCOPE")]
    /// Ignore specific parameters during scanning (can be specified multiple times)
    #[arg(long)]
    pub ignore_param: Vec<String>,

    #[clap(help_heading = "SCOPE")]
    /// Exclude targets whose domain matches these patterns (supports wildcards, e.g. *.dev.example.com)
    #[arg(long)]
    pub out_of_scope: Vec<String>,

    #[clap(help_heading = "SCOPE")]
    /// Load out-of-scope domains from a file (one per line, supports wildcards)
    #[arg(long)]
    pub out_of_scope_file: Option<String>,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Only perform parameter discovery (skip XSS scanning)
    #[arg(long)]
    pub only_discovery: bool,

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
    /// Proxy URL (e.g., http://localhost:8080, socks5://localhost:9050)
    #[arg(long)]
    pub proxy: Option<String>,

    #[clap(help_heading = "NETWORK")]
    /// Follow HTTP redirects. Example: -F
    #[arg(short = 'F', long)]
    pub follow_redirects: bool,

    #[clap(help_heading = "NETWORK")]
    /// Ignore specific HTTP status codes during scanning (comma-separated). Example: --ignore-return 302,403,404
    #[arg(long, value_delimiter = ',')]
    pub ignore_return: Vec<u16>,

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
    /// Specify payload encoders to use (comma-separated). Options: none, url, 2url, 3url, 4url, html, base64. Default: url,html
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
    /// Custom value for alert/prompt/confirm in payloads. Default: "1". Example: --custom-alert-value 'document.domain'
    #[arg(long, default_value = "1")]
    pub custom_alert_value: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Custom alert function type. Options: none (keep original), str (wrap value in quotes). Default: "none"
    #[arg(long, default_value = "none")]
    pub custom_alert_type: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Custom injection point marker. Replace this string with payloads in URL/headers/body.
    /// Example: --inject-marker 'FUZZ' with URL 'http://example.com/?q=FUZZ'
    #[arg(long)]
    pub inject_marker: Option<String>,

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
    /// URL to check for Stored XSS reflection.
    /// When omitted with --sxss, auto-detects from form discovery context.
    #[arg(long)]
    pub sxss_url: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// HTTP method for checking Stored XSS (default "GET")
    #[arg(long, default_value = "GET")]
    pub sxss_method: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Number of times to re-check the Stored XSS URL to handle slow
    /// session/content propagation. Each retry waits 500ms * attempt_index.
    #[arg(long, default_value_t = 3)]
    pub sxss_retries: u32,

    #[clap(help_heading = "XSS SCANNING")]
    /// Skip AST-based DOM XSS detection (analyzes JavaScript in responses)
    #[arg(long)]
    pub skip_ast_analysis: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Enable HTTP Parameter Pollution (HPP) — duplicate query params to bypass WAF
    #[arg(long)]
    pub hpp: bool,

    #[clap(help_heading = "WAF")]
    /// WAF bypass mode: auto (detect+bypass), force (use --force-waf), off (disable). Default: auto
    #[arg(long, default_value = "auto")]
    pub waf_bypass: String,

    #[clap(help_heading = "WAF")]
    /// Skip WAF fingerprinting probes (header-only detection, no provocation request)
    #[arg(long)]
    pub skip_waf_probe: bool,

    #[clap(help_heading = "WAF")]
    /// Force a specific WAF type for bypass strategies (e.g., cloudflare, akamai, modsecurity)
    #[arg(long)]
    pub force_waf: Option<String>,

    #[clap(help_heading = "WAF")]
    /// Auto-throttle scanning when WAF is detected (workers=1, delay=3000ms)
    #[arg(long)]
    pub waf_evasion: bool,

    #[clap(help_heading = "WAF")]
    /// Discard WAF fingerprints below this confidence (0.0–1.0). Use to
    /// suppress weak detections like "Request blocked" (0.3) or
    /// "Server: Google Frontend" (0.5) that often false-positive.
    /// Default 0.0 keeps every match.
    #[arg(long, default_value_t = 0.0)]
    pub waf_min_confidence: f32,

    #[clap(help_heading = "TARGETS")]
    /// Targets (URLs or file paths)
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
}

/// Options for constructing a preflight ScanArgs.
pub struct PreflightOptions {
    pub target: String,
    pub param: Vec<String>,
    pub method: String,
    pub data: Option<String>,
    pub headers: Vec<String>,
    pub cookies: Vec<String>,
    pub user_agent: Option<String>,
    pub timeout: u64,
    pub proxy: Option<String>,
    pub follow_redirects: bool,
    pub skip_mining: bool,
    pub skip_discovery: bool,
    pub encoders: Vec<String>,
}

impl ScanArgs {
    /// Build a ScanArgs configured for preflight analysis only (no attack payloads).
    /// Used by both MCP preflight_dalfox and REST API /preflight endpoint.
    pub fn for_preflight(opts: PreflightOptions) -> Self {
        let timeout = if opts.timeout > 0 && opts.timeout < 300 {
            opts.timeout
        } else {
            DEFAULT_TIMEOUT_SECS
        };
        ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![opts.target],
            param: opts.param,
            data: opts.data,
            headers: opts.headers,
            cookies: opts.cookies,
            method: opts.method,
            user_agent: opts.user_agent,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: opts.skip_mining,
            skip_mining_dict: opts.skip_mining,
            skip_mining_dom: opts.skip_mining,
            only_discovery: false,
            skip_discovery: opts.skip_discovery,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout,
            delay: 0,
            proxy: opts.proxy,
            follow_redirects: opts.follow_redirects,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            silence: true,
            dry_run: true,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            no_color: true,
            workers: 10,
            max_concurrent_targets: 1,
            max_targets_per_host: 1,
            encoders: opts.encoders,
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: true,
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
}

/// Check if a domain matches an out-of-scope pattern.
/// Supports simple wildcard: `*.example.com` matches `sub.example.com` but not `notexample.com`.
fn domain_matches_pattern(host: &str, pattern: &str) -> bool {
    let host_lower = host.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    if let Some(base) = pattern_lower.strip_prefix("*.") {
        // Match exact subdomain boundary: host must end with ".base" or equal "base"
        host_lower == base || host_lower.ends_with(&format!(".{}", base))
    } else {
        host_lower == pattern_lower
    }
}

/// Outcome of a scan run, used to determine CLI exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Scan completed successfully, no findings.
    Clean,
    /// Scan completed successfully, one or more findings.
    Findings,
    /// Scan failed due to input, configuration, or runtime error.
    Error,
}

/// Range-check numeric scan args before launching any network work.
///
/// The original failure mode was a config file or CLI flag carrying a
/// nonsense value (e.g. `workers: 0`, `max_targets_per_host: 0`,
/// `timeout: 9999999`) that produced cryptic mid-scan failures —
/// truncating the entire target group, deadlocking on a 0-permit
/// semaphore, or hanging on an absurd timeout — long after the user
/// had already invested time in mining/discovery.
///
/// Returns `Err((error_code, message))` when invalid; the caller emits
/// the structured error and exits.
fn validate_numeric_args(args: &ScanArgs) -> std::result::Result<(), (&'static str, String)> {
    if args.workers == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--workers must be at least 1".to_string(),
        ));
    }
    if args.workers > CLI_MAX_WORKERS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--workers must be at most {} (got {})",
                CLI_MAX_WORKERS, args.workers
            ),
        ));
    }
    if args.timeout == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--timeout must be at least 1 second".to_string(),
        ));
    }
    if args.timeout > CLI_MAX_TIMEOUT_SECS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--timeout must be at most {} seconds (got {})",
                CLI_MAX_TIMEOUT_SECS, args.timeout
            ),
        ));
    }
    if args.delay > CLI_MAX_DELAY_MS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--delay must be at most {} ms (got {})",
                CLI_MAX_DELAY_MS, args.delay
            ),
        ));
    }
    if args.max_concurrent_targets == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--max-concurrent-targets must be at least 1".to_string(),
        ));
    }
    if args.max_targets_per_host == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--max-targets-per-host must be at least 1".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&args.waf_min_confidence) || args.waf_min_confidence.is_nan() {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--waf-min-confidence must be in 0.0..=1.0 (got {})",
                args.waf_min_confidence
            ),
        ));
    }
    Ok(())
}

/// Emit a structured error to stderr when format is json/jsonl, otherwise plain eprintln.
fn emit_error(format: &str, code: &str, message: &str) {
    if format == "json" || format == "jsonl" {
        let err = serde_json::json!({
            "error": true,
            "code": code,
            "message": message
        });
        if format == "json" {
            eprintln!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
        } else {
            eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
        }
    } else {
        eprintln!("Error: {}", message);
    }
}

/// Run a scan and return the outcome: `Clean` (no findings), `Findings`, or `Error`.
pub async fn run_scan(args: &ScanArgs) -> ScanOutcome {
    // Compute no-color locally (safe for concurrent server-mode scans)
    let nc = args.no_color || std::env::var("NO_COLOR").is_ok();
    if nc {
        crate::NO_COLOR.store(true, Ordering::Relaxed);
    }

    // Show banner at the start when using plain format and not silenced
    if args.format == "plain" && !args.silence {
        crate::utils::print_banner_once(env!("CARGO_PKG_VERSION"), !nc);
    }
    let __dalfox_scan_start = std::time::Instant::now();
    crate::REQUEST_COUNT.store(0, Ordering::Relaxed);
    let log_info = move |msg: &str| {
        if args.format == "plain" && !args.silence {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            if nc {
                println!("{} INF {}", ts, msg);
            } else {
                println!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {}", ts, msg);
            }
        }
    };
    let log_warn = move |msg: &str| {
        if args.format == "plain" && !args.silence {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            if nc {
                println!("{} WRN {}", ts, msg);
            } else {
                println!("\x1b[90m{}\x1b[0m \x1b[33mWRN\x1b[0m {}", ts, msg);
            }
        }
    };
    let log_dbg = move |msg: &str| {
        if crate::DEBUG.load(Ordering::Relaxed) {
            let ts = chrono::Local::now().format("%-I:%M%p").to_string();
            if nc {
                println!("{} DBG {}", ts, msg);
            } else {
                println!("\x1b[90m{}\x1b[0m \x1b[35mDBG\x1b[0m {}", ts, msg);
            }
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
    // Validate numeric args up front so misconfigurations (workers: 0,
    // max_targets_per_host: 0, absurd timeouts) fail fast with a clear
    // message instead of producing cryptic mid-scan failures.
    if let Err((code, msg)) = validate_numeric_args(args) {
        if !args.silence {
            emit_error(&args.format, code, &msg);
        }
        return ScanOutcome::Error;
    }

    // Validate --custom-payload up front. Without this check, a missing or
    // unreadable file silently produces zero custom payloads mid-scan. With
    // --only-custom-payload that's catastrophic (no payloads at all, scan
    // reports clean), so fail fast. In additive mode it just degrades
    // detection, so warn and continue.
    if let Some(path) = &args.custom_payload {
        match fs::metadata(path) {
            Ok(m) if !m.is_file() => {
                if args.only_custom_payload {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::FILE_READ_ERROR,
                        &format!("--custom-payload is not a regular file: {}", path),
                    );
                    return ScanOutcome::Error;
                }
                log_warn(&format!(
                    "--custom-payload is not a regular file ({}) — built-in payloads only",
                    path
                ));
            }
            Err(e) => {
                if args.only_custom_payload {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::FILE_READ_ERROR,
                        &format!("--custom-payload not readable ({}): {}", path, e),
                    );
                    return ScanOutcome::Error;
                }
                log_warn(&format!(
                    "--custom-payload not readable ({}: {}) — built-in payloads only",
                    path, e
                ));
            }
            Ok(_) => {}
        }
    }

    // Initialize remote payloads/wordlists if requested (honor timeout/proxy)
    if (!args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty())
        && let Err(e) = crate::utils::init_remote_resources_with_options(
            &args.remote_payloads,
            &args.remote_wordlists,
            Some(args.timeout),
            args.proxy.clone(),
        )
        .await
        && !args.silence
    {
        eprintln!("Error initializing remote resources: {}", e);
    }
    let input_type = if args.input_type == "auto" {
        if args.targets.is_empty() {
            // If no positional targets and STDIN is piped, treat as pipe mode
            if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                "pipe".to_string()
            } else {
                if !args.silence {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::NO_TARGETS,
                        "No targets specified",
                    );
                }
                return ScanOutcome::Error;
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
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::NO_FILE,
                            "No file specified for input-type=file",
                        );
                    }
                    return ScanOutcome::Error;
                }
                let file_path = &args.targets[0];
                match fs::read_to_string(file_path) {
                    Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        if !args.silence {
                            emit_error(
                                &args.format,
                                crate::cmd::error_codes::FILE_READ_ERROR,
                                &format!("Error reading file {}: {}", file_path, e),
                            );
                        }
                        return ScanOutcome::Error;
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
                            emit_error(
                                &args.format,
                                crate::cmd::error_codes::STDIN_ERROR,
                                &format!("Error reading from stdin: {}", e),
                            );
                        }
                        return ScanOutcome::Error;
                    }
                }
            }
            "raw-http" => {
                // Treat targets as raw HTTP request files or literals; actual parsing happens later
                args.targets.clone()
            }

            _ => {
                if !args.silence {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::INVALID_INPUT_TYPE,
                        &format!(
                            "Invalid input-type '{}'. Use 'auto', 'url', 'file', 'pipe', or 'raw-http'",
                            input_type
                        ),
                    );
                }
                return ScanOutcome::Error;
            }
        };
    }

    if target_strings.is_empty() {
        if !args.silence {
            emit_error(
                &args.format,
                crate::cmd::error_codes::NO_TARGETS,
                "No targets specified",
            );
        }
        return ScanOutcome::Error;
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
                    target.ignore_return = args.ignore_return.clone();
                    target.workers = args.workers;
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::PARSE_ERROR,
                            &format!("Error parsing raw HTTP request '{}': {}", s, e),
                        );
                    }
                    return ScanOutcome::Error;
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
                    target.ignore_return = args.ignore_return.clone();
                    target.workers = args.workers;
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::PARSE_ERROR,
                            &format!("Error parsing target '{}': {}", s, e),
                        );
                    }
                    return ScanOutcome::Error;
                }
            }
        }
    }

    // Deduplicate targets by URL + method to avoid redundant scans (e.g. pipe input with duplicates)
    {
        let mut seen = std::collections::HashSet::new();
        parsed_targets.retain(|t| {
            let key = format!("{}|{}", t.url, t.method);
            seen.insert(key)
        });
    }

    // Apply URL scope filtering (--include-url / --exclude-url)
    {
        let include_patterns: Vec<regex::Regex> = args
            .include_url
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    if !args.silence {
                        eprintln!("Warning: invalid --include-url pattern '{}': {}", p, e);
                    }
                    None
                }
            })
            .collect();
        let exclude_patterns: Vec<regex::Regex> = args
            .exclude_url
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    if !args.silence {
                        eprintln!("Warning: invalid --exclude-url pattern '{}': {}", p, e);
                    }
                    None
                }
            })
            .collect();

        if !include_patterns.is_empty() || !exclude_patterns.is_empty() {
            let before = parsed_targets.len();
            parsed_targets.retain(|t| {
                let url_str = t.url.as_str();
                // If include patterns are set, URL must match at least one
                if !include_patterns.is_empty()
                    && !include_patterns.iter().any(|r| r.is_match(url_str))
                {
                    return false;
                }
                // If exclude patterns are set, URL must not match any
                if exclude_patterns.iter().any(|r| r.is_match(url_str)) {
                    return false;
                }
                true
            });
            let filtered = before - parsed_targets.len();
            if filtered > 0 {
                log_info(&format!("scope filter: {} target(s) excluded", filtered));
            }
        }
    }

    // Apply out-of-scope domain filtering (--out-of-scope / --out-of-scope-file)
    {
        let mut oos_domains: Vec<String> = args.out_of_scope.clone();
        if let Some(ref path) = args.out_of_scope_file {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    for line in contents.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            oos_domains.push(trimmed.to_string());
                        }
                    }
                }
                Err(e) => {
                    log_warn(&format!(
                        "failed to read --out-of-scope-file '{}': {}",
                        path, e
                    ));
                }
            }
        }
        if !oos_domains.is_empty() {
            let before = parsed_targets.len();
            parsed_targets.retain(|t| {
                let host = match t.url.host_str() {
                    Some(h) => h,
                    None => return true,
                };
                !oos_domains
                    .iter()
                    .any(|pattern| domain_matches_pattern(host, pattern))
            });
            let filtered = before - parsed_targets.len();
            if filtered > 0 {
                log_info(&format!(
                    "out-of-scope filter: {} target(s) excluded",
                    filtered
                ));
            }
        }
    }

    if args.hpp {
        log_info(
            "HPP (HTTP Parameter Pollution) enabled — duplicate query params will be tested for WAF bypass",
        );
    }

    if parsed_targets.is_empty() {
        if !args.silence {
            emit_error(
                &args.format,
                crate::cmd::error_codes::NO_TARGETS,
                "No targets specified",
            );
        }
        return ScanOutcome::Error;
    }

    // Load cookies from raw HTTP request file if specified
    if let Some(path) = &args.cookie_from_raw {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let mut cookies_from_raw: Vec<(String, String)> = Vec::new();
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                cookies_from_raw
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
                if !cookies_from_raw.is_empty() {
                    for target in &mut parsed_targets {
                        target.cookies.extend(cookies_from_raw.iter().cloned());
                    }
                }
            }
            Err(_) if !args.silence => {
                eprintln!("Error reading cookie file: {}", path);
            }
            Err(_) => {}
        }
    }

    let results = Arc::new(Mutex::new(Vec::<Result>::new()));
    let findings_count = Arc::new(AtomicUsize::new(0));

    // Per-target tracking for structured output (target_summary in JSON envelope)
    // Collect all target URLs that will be scanned, then track status per target.
    let all_target_urls: Vec<String> = parsed_targets.iter().map(|t| t.url.to_string()).collect();
    // Track targets that were skipped during preflight (content-type mismatch etc.)
    // Map of skipped target URL -> error code explaining why it was skipped.
    // Used by target_summary to surface skips (content-type mismatch, per-host
    // truncation, etc.) instead of silently marking them clean.
    let skipped_targets: Arc<Mutex<HashMap<String, &'static str>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Per-target preflight metadata serialized once during preflight, read at
    // target_summary build time. Populated from `target.waf_info` and the
    // applied bypass strategy. JSON/JSONL consumers can't otherwise see what
    // WAF was detected — that information only reached the plain-mode log.
    let target_meta: Arc<Mutex<HashMap<String, serde_json::Value>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Side map of WAF-bypass effectiveness counters, alive across the
    // scanning loop and read at target_summary build time. The Arc is
    // shared with `target.mutation_stats`; both increment the same
    // counters via the MutationStats methods.
    let target_mutation_stats: Arc<Mutex<HashMap<String, Arc<crate::waf::bypass::MutationStats>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let multi_pb: Option<Arc<MultiProgress>> = None;

    // Group targets by host
    let mut host_groups: std::collections::HashMap<String, Vec<Target>> =
        std::collections::HashMap::new();
    for target in parsed_targets {
        let host = target.url.host_str().unwrap_or("unknown").to_string();
        host_groups.entry(host).or_default().push(target);
    }

    let total_targets = host_groups.values().map(|g| g.len()).sum::<usize>();
    let preflight_idx = Arc::new(AtomicUsize::new(0));
    let analyze_idx = Arc::new(AtomicUsize::new(0));
    let scan_idx = Arc::new(AtomicUsize::new(0));
    let overall_done = Arc::new(AtomicUsize::new(0));

    // Start global overall progress ticker when multiple targets; runs across preflight, analysis, and scanning
    let overall_ticker = if args.format == "plain" && !args.silence && total_targets > 1 {
        let findings_count_clone = findings_count.clone();
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
                let findings = findings_count_clone.load(Ordering::Relaxed);
                print!(
                    "\r\x1b[38;5;247m{} overall: targets={}  done={}  progress={}%  findings={}\x1b[0m",
                    frames[i % frames.len()],
                    total_targets_copy,
                    done,
                    percent,
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
        // Limit targets per host. Targets above the cap aren't silently dropped
        // — record them in skipped_targets so target_summary surfaces the skip
        // with the TRUNCATED_PER_HOST_CAP error code instead of "clean".
        if group.len() > args.max_targets_per_host {
            let dropped: Vec<String> = group
                .iter()
                .skip(args.max_targets_per_host)
                .map(|t| t.url.to_string())
                .collect();
            if !dropped.is_empty() {
                if !args.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    eprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[33mWARN\x1b[0m max-targets-per-host cap ({}) reached; {} target(s) skipped",
                        ts,
                        args.max_targets_per_host,
                        dropped.len()
                    );
                }
                let mut guard = skipped_targets.lock().await;
                for url in dropped {
                    guard.insert(url, crate::cmd::error_codes::TRUNCATED_PER_HOST_CAP);
                }
            }
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
            let findings_count_outer = findings_count.clone();
            let skipped_targets_outer = skipped_targets.clone();
            let target_meta_outer = target_meta.clone();
            let target_mutation_stats_outer = target_mutation_stats.clone();
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
            let findings_count_clone = findings_count_outer.clone();
            let skipped_targets_clone = skipped_targets_outer.clone();
            let target_meta_clone = target_meta_outer.clone();
            let target_mutation_stats_clone = target_mutation_stats_outer.clone();

            handles.push(tokio::task::spawn_local(async move {
                // Bound concurrency across targets for preflight + analysis
                let Ok(_permit) = sem.acquire_owned().await else {
                    return None;
                };
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

                    if let Some(preflight) = __preflight_info {
                        preflight_response_body = preflight.response_body;
                        if let Some((hn, hv)) = preflight.csp_header {
                            __preflight_csp_present = true;
                            // Analyze CSP and store on target for bypass payload generation
                            target.csp_analysis = Some(crate::payload::xss_csp_bypass::analyze_csp(&hv));
                            __preflight_csp_header = Some((hn, hv));
                        }
                        // Store WAF detection result on target
                        if !preflight.waf_result.is_empty() {
                            target.waf_info = Some(preflight.waf_result);
                            // Allocate per-target effectiveness counters when
                            // bypass is going to run; the scanning loop and
                            // check_reflection both update this Arc, and the
                            // target_mutation_stats side-map keeps it alive
                            // until target_summary is built.
                            if args_clone.waf_bypass != "off" {
                                let stats = std::sync::Arc::new(
                                    crate::waf::bypass::MutationStats::default(),
                                );
                                target.mutation_stats = Some(stats.clone());
                                target_mutation_stats_clone
                                    .lock()
                                    .await
                                    .insert(target.url.to_string(), stats);
                            }

                            // Snapshot WAF + applied bypass for target_summary
                            // (JSON/JSONL output). Plain mode logs the same
                            // info to the console below; JSON consumers
                            // would otherwise have no visibility.
                            if let Some(ref waf_info) = target.waf_info {
                                let detected_json: Vec<serde_json::Value> = waf_info
                                    .detected
                                    .iter()
                                    .map(|fp| {
                                        serde_json::json!({
                                            "type": fp.waf_type.to_string(),
                                            "confidence": fp.confidence,
                                            "evidence": fp.evidence,
                                        })
                                    })
                                    .collect();
                                let mut meta_json = serde_json::json!({
                                    "detected": detected_json,
                                });
                                if args_clone.waf_bypass != "off" {
                                    let waf_types: Vec<&crate::waf::WafType> =
                                        waf_info.waf_types();
                                    let strategy =
                                        crate::waf::bypass::merge_strategies(&waf_types);
                                    meta_json["bypass"] = serde_json::json!({
                                        "encoders": strategy.extra_encoders,
                                        "mutation_count": strategy.mutations.len(),
                                        "extra_delay_hint_ms": strategy.extra_delay_hint_ms,
                                    });
                                }
                                target_meta_clone
                                    .lock()
                                    .await
                                    .insert(target.url.to_string(), meta_json);
                            }

                            // WAF evasion: auto-throttle when WAF detected
                            if args_clone.waf_evasion {
                                target.workers = 1;
                                target.delay = 3000;
                                if !args_clone.silence {
                                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                                    println!(
                                        "\x1b[90m{}\x1b[0m \x1b[33mWAF\x1b[0m evasion activated: workers=1, delay=3000ms",
                                        ts
                                    );
                                }
                            }
                        }
                        // Store technology detection result on target
                        if !preflight.tech_result.is_empty() {
                            target.tech_info = Some(preflight.tech_result);
                        }
                        if !is_allowed_content_type(&preflight.content_type) {
                            // Skip this target early
                            skipped_targets_clone.lock().await.insert(
                                target.url.to_string(),
                                crate::cmd::error_codes::CONTENT_TYPE_MISMATCH,
                            );
                            return None;
                        }
                    }
                }

                // Pretty start log per target (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            target.url.as_ref(),
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
                        // Log WAF detection
                        if let Some(ref waf_info) = target.waf_info {
                            for fp in &waf_info.detected {
                                println!(
                                    "\x1b[90m{}\x1b[0m \x1b[33mWAF\x1b[0m {} detected (confidence: {:.0}%, evidence: {})",
                                    ts, fp.waf_type, fp.confidence * 100.0, fp.evidence
                                );
                            }
                            if args_clone.waf_bypass != "off" {
                                let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
                                let strategy = crate::waf::bypass::merge_strategies(&waf_types);
                                if !strategy.extra_encoders.is_empty() {
                                    println!(
                                        "  \x1b[90m└──\x1b[0m \x1b[38;5;247mbypass encoders: {}\x1b[0m",
                                        strategy.extra_encoders.join(", ")
                                    );
                                }
                                if !strategy.mutations.is_empty() {
                                    println!(
                                        "  \x1b[90m└──\x1b[0m \x1b[38;5;247mbypass mutations: {} types\x1b[0m",
                                        strategy.mutations.len()
                                    );
                                }
                            }
                        }
                        // Log detected technologies
                        if let Some(ref tech_info) = target.tech_info {
                            let tech_names: Vec<String> = tech_info.detected.iter().map(|d| format!("{}", d.tech)).collect();
                            if !tech_names.is_empty() {
                                println!(
                                    "\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m tech: {}",
                                    ts, tech_names.join(", ")
                                );
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
                if let Some(ref marker) = args_clone.inject_marker {
                    // Custom injection marker mode: skip normal discovery/mining
                    // and create params from marker positions in URL/headers/body
                    use crate::parameter_analysis::{Location, Param};
                    let mut marker_params = Vec::new();

                    // Check URL query params
                    for (k, v) in target.url.query_pairs() {
                        if v.contains(marker.as_str()) {
                            marker_params.push(Param {
                                name: k.to_string(),
                                value: v.to_string(),
                                location: Location::Query,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                            });
                        }
                    }

                    // Check body params
                    if let Some(ref data) = target.data {
                        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(data) {
                            if let Some(obj) = json_val.as_object() {
                                for (k, v) in obj {
                                    if let Some(s) = v.as_str()
                                        && s.contains(marker.as_str())
                                    {
                                        marker_params.push(Param {
                                            name: k.clone(),
                                            value: s.to_string(),
                                            location: Location::JsonBody,
                                            injection_context: None,
                                            valid_specials: None,
                                            invalid_specials: None,
                                            pre_encoding: None,
                                            pre_encoding_pipeline: None,
                                            wire_name: None,
                                            form_action_url: None,
                                            form_origin_url: None,
                                        });
                                    }
                                }
                            }
                        } else {
                            for pair in data.split('&') {
                                if let Some((k, v)) = pair.split_once('=')
                                    && v.contains(marker.as_str())
                                {
                                    marker_params.push(Param {
                                        name: k.to_string(),
                                        value: v.to_string(),
                                        location: Location::Body,
                                        injection_context: None,
                                        valid_specials: None,
                                        invalid_specials: None,
                                        pre_encoding: None,
                                        pre_encoding_pipeline: None,
                                        wire_name: None,
                                        form_action_url: None,
                                        form_origin_url: None,
                                    });
                                }
                            }
                        }
                    }

                    // Check headers
                    for (k, v) in &target.headers {
                        if v.contains(marker.as_str()) {
                            marker_params.push(Param {
                                name: k.clone(),
                                value: v.clone(),
                                location: Location::Header,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                            });
                        }
                    }

                    // Check cookies
                    for (k, v) in &target.cookies {
                        if v.contains(marker.as_str()) {
                            marker_params.push(Param {
                                name: k.clone(),
                                value: v.clone(),
                                location: Location::Header,
                                injection_context: None,
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                            });
                        }
                    }

                    target.reflection_params = marker_params;
                } else {
                    analyze_parameters(&mut target, &__analysis_args, multi_pb_clone).await;
                }
                if let Some((tx, done_rx)) = __analyze_spinner {
                    let _ = tx.send(());
                    let _ = done_rx.await;
                }

                // Run AST-based DOM XSS analysis on the initial response (enabled by default)
                if !args_clone.skip_ast_analysis
                    && let Some(response_text) = preflight_response_body {
                        let mut ast_batch: Vec<crate::scanning::result::Result> = Vec::new();
                        let js_blocks = crate::scanning::ast_integration::extract_javascript_from_html(&response_text);
                        for js_code in js_blocks {
                            let findings = crate::scanning::ast_integration::analyze_javascript_for_dom_xss(
                                &js_code,
                                target.url.as_str(),
                            );
                            for (vuln, payload, description) in findings {
                                let self_bootstrap_verified =
                                    crate::scanning::ast_integration::has_self_bootstrap_verification(
                                        &js_code,
                                        &vuln.source,
                                    );
                                let poc_url =
                                    crate::scanning::ast_integration::build_dom_xss_poc_url(
                                        target.url.as_str(),
                                        &vuln.source,
                                        &payload,
                                    );
                                let message = build_ast_dom_message(
                                    &description,
                                    &vuln.source,
                                    target.url.as_str(),
                                    &payload,
                                );
                                // Create an AST-based DOM XSS result with actual executable payload
                                let ast_result = crate::scanning::result::Result::new(
                                    FindingType::AstDetected, // AST-detected
                                    "DOM-XSS".to_string(),
                                    target.method.clone(),
                                    poc_url,
                                    "-".to_string(), // No specific parameter
                                    payload, // Actual XSS payload
                                    format!("{}:{}:{} - {} (Source: {}, Sink: {})",
                                        target.url.as_str(), vuln.line, vuln.column,
                                        description, vuln.source, vuln.sink),
                                    "CWE-79".to_string(),
                                    "Medium".to_string(),
                                    0,
                                    message,
                                );
                                let mut ast_result = ast_result;
                                if self_bootstrap_verified {
                                    ast_result.result_type = FindingType::Verified;
                                    ast_result.severity = "High".to_string();
                                    ast_result.message_str = format!(
                                        "{} [정적 self-bootstrap 확인]",
                                        ast_result.message_str
                                    );
                                }
                                ast_batch.push(ast_result);
                            }
                        }
                        if !ast_batch.is_empty() {
                            let added = ast_batch.len();
                            let mut guard = results_clone.lock().await;
                            guard.extend(ast_batch);
                            findings_count_clone.fetch_add(added, Ordering::Relaxed);
                        }
                    }

                // Pretty reflection summary (plain only)
                if args_clone.format == "plain" && !args_clone.silence && total_targets_copy == 1 {
                    let n = target.reflection_params.len();
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    if total_targets_copy > 1 {
                        let sid = crate::utils::short_scan_id(&crate::utils::make_scan_id(
                            target.url.as_ref(),
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
                            for e in ["url", "html", "2url", "3url", "4url", "base64"] {
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
                    if let Ok(res) = handle.await
                        && let Some(t) = res {
                            processed.push(t);
                        }
                }
                processed
            }).await
        };

        // Replace group with processed targets
        *group = processed;
    }

    // --dry-run: report what would be scanned without sending attack payloads
    if args.dry_run {
        let mut dry_run_targets = Vec::new();
        for group in host_groups.values() {
            for target in group {
                let param_count = target.reflection_params.len();
                // Estimate request count per target using encoder expansion
                let enc_factor = if args.encoders.iter().any(|e| e == "none") {
                    1usize
                } else {
                    let mut f = 1usize;
                    for e in ["url", "html", "2url", "3url", "4url", "base64"] {
                        if args.encoders.iter().any(|x| x == e) {
                            f += 1;
                        }
                    }
                    f
                };
                let mut estimated_requests: usize = 0;
                for p in &target.reflection_params {
                    let payload_count = if let Some(ctx) = &p.injection_context {
                        crate::scanning::xss_common::get_dynamic_payloads(ctx, args)
                            .unwrap_or_else(|_| vec![])
                            .len()
                    } else {
                        let html_len =
                            crate::payload::get_dynamic_xss_html_payloads().len() * enc_factor;
                        let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
                        html_len + js_len
                    };
                    estimated_requests = estimated_requests.saturating_add(payload_count);
                }

                let params: Vec<serde_json::Value> = target
                    .reflection_params
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "location": format!("{:?}", p.location),
                        })
                    })
                    .collect();

                dry_run_targets.push(serde_json::json!({
                    "target": target.url.as_str(),
                    "method": target.method,
                    "params_discovered": param_count,
                    "estimated_requests": estimated_requests,
                    "params": params,
                }));
            }
        }

        let total_estimated: usize = dry_run_targets
            .iter()
            .filter_map(|t| t["estimated_requests"].as_u64())
            .map(|n| n as usize)
            .sum();
        let total_params: usize = dry_run_targets
            .iter()
            .filter_map(|t| t["params_discovered"].as_u64())
            .map(|n| n as usize)
            .sum();
        let skipped = skipped_targets.lock().await;

        if args.format == "json" || args.format == "jsonl" {
            let output = serde_json::json!({
                "dry_run": true,
                "meta": {
                    "dalfox_version": env!("CARGO_PKG_VERSION"),
                    "targets_input": args.targets.len(),
                    "targets_scannable": dry_run_targets.len(),
                    "targets_skipped": skipped.len(),
                    "total_params_discovered": total_params,
                    "total_estimated_requests": total_estimated,
                },
                "targets": dry_run_targets,
            });
            if args.format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            } else {
                println!("{}", serde_json::to_string(&output).unwrap_or_default());
            }
        } else {
            println!("Dry-run summary:");
            println!("  Targets (input):     {}", args.targets.len());
            println!("  Targets (scannable): {}", dry_run_targets.len());
            println!("  Targets (skipped):   {}", skipped.len());
            println!("  Params discovered:   {}", total_params);
            println!("  Estimated requests:  {}", total_estimated);
            println!();
            for t in &dry_run_targets {
                println!(
                    "  {} ({}):",
                    t["target"].as_str().unwrap_or("?"),
                    t["method"].as_str().unwrap_or("?")
                );
                if let Some(params) = t["params"].as_array() {
                    for p in params {
                        println!(
                            "    - {} ({})",
                            p["name"].as_str().unwrap_or("?"),
                            p["location"].as_str().unwrap_or("?")
                        );
                    }
                }
                println!("    estimated_requests: {}", t["estimated_requests"]);
            }
        }
        return ScanOutcome::Clean;
    }

    // --only-discovery: print discovered params and exit early
    if args.only_discovery {
        for group in host_groups.values() {
            for target in group {
                for p in &target.reflection_params {
                    if args.format == "json" || args.format == "jsonl" {
                        let entry = serde_json::json!({
                            "url": target.url.as_str(),
                            "param": p.name,
                            "location": format!("{:?}", p.location),
                        });
                        println!("{}", serde_json::to_string(&entry).unwrap_or_default());
                    } else {
                        println!("[{}] {} ({:?})", target.url, p.name, p.location);
                    }
                }
            }
        }
        return ScanOutcome::Clean;
    }

    // Semaphore for limiting concurrent targets across all hosts
    let global_semaphore = Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));

    let mut group_handles = vec![];

    for (host, group) in host_groups {
        if let Some(lim) = args.limit
            && findings_count.load(Ordering::Relaxed) >= lim
        {
            break;
        }
        let global_semaphore_clone = global_semaphore.clone();
        let multi_pb_clone = multi_pb.clone();
        let args_arc = Arc::new(args.clone());
        let results_clone = results.clone();
        let findings_count_group = findings_count.clone();

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
                        .expect("valid progress bar template")
                        .progress_chars("#>-"),
                );
                Some(Arc::new(Mutex::new(pb)))
            } else {
                None
            };

            let mut target_handles = vec![];

            for target in group {
                if let Some(lim) = args_arc.limit
                    && findings_count_group.load(Ordering::Relaxed) >= lim
                {
                    break;
                }
                let Ok(permit) = global_semaphore_clone.clone().acquire_owned().await else {
                    break;
                };
                let args_clone = args_arc.clone();
                let results_clone_inner = results_clone.clone();
                let multi_pb_clone_inner = multi_pb_clone.clone();
                let overall_pb_clone = overall_pb.clone();
                let scan_idx_clone = scan_idx.clone();
                let total_targets_copy = total_targets;
                let findings_count_target = findings_count_group.clone();

                let target_handle = tokio::spawn(async move {
                    if !args_clone.skip_xss_scanning && !args_clone.only_discovery {
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
                            findings_count_target,
                            None,
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
                let _ = handle.await;
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
        let _ = handle.await;
        if let Some(lim) = args.limit
            && findings_count.load(Ordering::Relaxed) >= lim
        {
            break;
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
    let mut final_results = dedupe_ast_results(results.lock().await.clone());

    // Apply --only-poc filter: keep only results whose type matches the specified filters
    if !args.only_poc.is_empty() {
        let allowed: Vec<String> = args
            .only_poc
            .iter()
            .map(|s| s.trim().to_uppercase())
            .collect();
        final_results.retain(|r| allowed.iter().any(|a| a == r.result_type.short()));
    }

    let limit = args.limit.unwrap_or(usize::MAX);
    let display_results_len = std::cmp::min(final_results.len(), limit);
    let display_results = &final_results[..display_results_len];
    let scan_elapsed = __dalfox_scan_start.elapsed();
    let total_requests = crate::REQUEST_COUNT.load(Ordering::Relaxed);

    // Build per-target summary for structured output.
    //
    // Attribution uses `finding_belongs_to_target`, the same helper that
    // `collapse_redundant_reflected` uses for per-target dedup. The two
    // MUST agree — if they disagree, a finding can be dropped by dedup but
    // attributed to a different target than where it was actually produced.
    //
    // Limitation: targets that share a path-without-query
    // (e.g. `/search?q=a` and `/search?id=b`) or a parent path for
    // path-injection (e.g. `/api/v1/foo` and `/api/v1/bar`) can both match
    // a single finding. This mirrors prior behavior. Single-target scans
    // are unaffected.
    let target_summary: Vec<serde_json::Value> = {
        let skipped = skipped_targets.lock().await;
        let meta = target_meta.lock().await;
        let stats_map = target_mutation_stats.lock().await;
        let mut summary = Vec::with_capacity(all_target_urls.len());
        for url in &all_target_urls {
            let finding_count = display_results
                .iter()
                .filter(|r| crate::utils::finding_belongs_to_target(url, &r.data))
                .count();
            let (status, error_code) = if let Some(code) = skipped.get(url) {
                ("skipped", Some(*code))
            } else if finding_count > 0 {
                ("findings", None)
            } else {
                ("clean", None)
            };
            let mut entry = serde_json::json!({
                "target": url,
                "status": status,
                "findings_count": finding_count,
            });
            if let Some(code) = error_code {
                entry["error_code"] = serde_json::json!(code);
            }
            // Attach preflight metadata (WAF + applied bypass) when present.
            // Omitted entirely for targets where no WAF was detected, to
            // keep the common-case output lean.
            if let Some(m) = meta.get(url) {
                let mut waf_entry = m.clone();
                // Fold per-target effectiveness telemetry into bypass{}.
                // Only present when bypass actually ran (target had stats).
                if let Some(stats) = stats_map.get(url) {
                    let snap = stats.snapshot();
                    let mut applied: Vec<serde_json::Value> = snap
                        .variants
                        .iter()
                        .map(|(m, n)| {
                            serde_json::json!({
                                "type": m.to_string(),
                                "variants_generated": n,
                            })
                        })
                        .collect();
                    // Stable order so re-runs diff cleanly in CI.
                    applied.sort_by(|a, b| {
                        a["type"]
                            .as_str()
                            .unwrap_or("")
                            .cmp(b["type"].as_str().unwrap_or(""))
                    });
                    if let Some(bypass) = waf_entry.get_mut("bypass")
                        && let Some(obj) = bypass.as_object_mut()
                    {
                        obj.insert(
                            "mutations_applied".to_string(),
                            serde_json::Value::Array(applied),
                        );
                        obj.insert(
                            "requests_sent".to_string(),
                            serde_json::json!(snap.bypass_requests),
                        );
                        obj.insert(
                            "requests_blocked".to_string(),
                            serde_json::json!(snap.bypass_blocks),
                        );
                    }
                }
                entry["waf"] = waf_entry;
            }
            summary.push(entry);
        }
        summary
    };

    let output_content = if args.format == "json" {
        let findings_json: Vec<serde_json::Value> = display_results
            .iter()
            .map(|r| r.to_json_value(args.include_request, args.include_response))
            .collect();
        let wrapper = serde_json::json!({
            "meta": {
                "dalfox_version": env!("CARGO_PKG_VERSION"),
                "targets": &args.targets,
                "scan_duration_ms": scan_elapsed.as_millis() as u64,
                "total_requests": total_requests,
                "findings_count": display_results.len(),
                "target_summary": target_summary,
            },
            "findings": findings_json
        });
        serde_json::to_string_pretty(&wrapper).unwrap_or_else(|_| "{}".to_string())
    } else if args.format == "jsonl" {
        // JSONL: first line is meta, then one finding per line
        let meta = serde_json::json!({
            "meta": {
                "dalfox_version": env!("CARGO_PKG_VERSION"),
                "targets": &args.targets,
                "scan_duration_ms": scan_elapsed.as_millis() as u64,
                "total_requests": total_requests,
                "findings_count": display_results.len(),
                "target_summary": target_summary,
            }
        });
        let mut out = serde_json::to_string(&meta).unwrap_or_default();
        out.push('\n');
        for r in display_results {
            let v = r.to_json_value(args.include_request, args.include_response);
            if let Ok(s) = serde_json::to_string(&v) {
                out.push_str(&s);
                out.push('\n');
            }
        }
        out
    } else if args.format == "markdown" {
        crate::scanning::result::Result::results_to_markdown(
            display_results,
            args.include_request,
            args.include_response,
        )
    } else if args.format == "sarif" {
        crate::scanning::result::Result::results_to_sarif(
            display_results,
            args.include_request,
            args.include_response,
        )
    } else if args.format == "toml" {
        crate::scanning::result::Result::results_to_toml(
            display_results,
            args.include_request,
            args.include_response,
        )
    } else if args.format == "plain" {
        let mut output = String::new();

        // Plain logger: XSS summary before POC lines
        let v_count = display_results
            .iter()
            .filter(|r| r.result_type == FindingType::Verified)
            .count();
        log_warn(&format!("XSS found \x1b[33m{}\x1b[0m XSS", v_count));

        for result in display_results {
            let mut poc_line = generate_poc(result, &args.poc_type);
            if args.poc_type == "plain" {
                match result.result_type {
                    FindingType::Reflected => {
                        let trimmed = poc_line.trim_end();
                        poc_line = format!("\x1b[33m{}\x1b[0m\n", trimmed);
                    }
                    FindingType::Verified => {
                        let trimmed = poc_line.trim_end();
                        poc_line = format!("\x1b[31m{}\x1b[0m\n", trimmed);
                    }
                    FindingType::AstDetected => {
                        let trimmed = poc_line.trim_end();
                        poc_line = format!("\x1b[35m{}\x1b[0m\n", trimmed);
                    }
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
            let issue_text = if result.result_type == FindingType::Reflected {
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

    if final_results.is_empty() {
        ScanOutcome::Clean
    } else {
        ScanOutcome::Findings
    }
}

#[cfg(test)]
mod tests;
