//! Scan CLI argument surface: the `ScanArgs` clap struct, its centralized
//! default/cap constants, the `--method` / `--limit` / `--force-waf` value
//! parsers, and the `PreflightOptions` builder used by the server + MCP
//! preflight paths. Kept together so the CLI contract lives in one place.

use clap::Args;

/// Default encoders used when the user does not specify any via CLI or config.
/// Centralizing this allows config.rs to reference the same canonical defaults.
pub const DEFAULT_ENCODERS: &[&str] = &["url", "html"];
// Centralized numeric defaults (used by CLI default_value_t and config precedence logic)
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_DELAY_MS: u64 = 0;
pub const DEFAULT_WORKERS: usize = 50;
pub const DEFAULT_MAX_CONCURRENT_TARGETS: usize = 50;
pub const DEFAULT_MAX_TARGETS_PER_HOST: usize = 100;
/// Default for `--rate-limit`: 0 = unlimited (no token bucket installed),
/// preserving the historical "only `--delay` paces requests" behavior.
pub const DEFAULT_RATE_LIMIT: u32 = 0;
/// Default for `--retries`: 0 = do not retry 5xx / transient transport
/// errors (HTTP 429 is always retried regardless; see `send_with_retry`).
pub const DEFAULT_RETRIES: u32 = 0;
/// Default for `--retry-delay`: base for the exponential retry backoff (ms).
pub const DEFAULT_RETRY_DELAY_MS: u64 = 1000;
/// Floor for WAF fingerprint confidence. Weak signals like
/// `Server: Google Frontend` (0.15 — every Google-hosted property has it) or
/// generic "Request blocked" body markers (0.3) are filtered out by default.
/// Real WAF signatures (Cloudflare's `cf-ray` at 0.9, AWS WAF
/// `x-amzn-waf-action` at 0.95, etc.) sail through. Set
/// `--waf-min-confidence 0.0` to keep every match.
pub const DEFAULT_WAF_MIN_CONFIDENCE: f32 = 0.3;
// Sanity caps for CLI scan args. The server uses tighter caps in
// crate::job; CLI users may legitimately want longer timeouts for
// slow targets but values past these almost always indicate a typo or a
// stale config file with stray zeros.
pub const CLI_MAX_TIMEOUT_SECS: u64 = 3600;
pub const CLI_MAX_DELAY_MS: u64 = 60_000;
pub const CLI_MAX_WORKERS: usize = 500;
/// Sanity cap for `--rate-limit` (req/sec). A value past this almost always
/// means a typo (e.g. a delay in ms typed into the rate field); the limiter
/// is for throttling, not for unbounded fan-out.
pub const CLI_MAX_RATE_LIMIT: u32 = 100_000;
/// Sanity cap for `--retries`. Retrying more than this turns a transient
/// blip into a multi-minute hang per request.
pub const CLI_MAX_RETRIES: u32 = 100;
/// Sanity cap for `--retry-delay` (ms), matching `--delay`'s ceiling.
pub const CLI_MAX_RETRY_DELAY_MS: u64 = 60_000;
// Default HTTP method (used by CLI and target parsing)
pub const DEFAULT_METHOD: &str = "GET";

/// clap value-parser for `--force-waf`. Accepts the same alias set that
/// `parse_waf_type` recognises (case-insensitive) and rejects anything
/// else at parse time so a typo like `--force-waf cloudflair` doesn't
/// silently fall into the `WafType::Unknown(other)` bucket and skip
/// the targeted bypass mutations.
fn parse_force_waf_arg(s: &str) -> std::result::Result<String, String> {
    let lower = s.trim().to_ascii_lowercase();
    let known = [
        "cloudflare",
        "cf",
        "aws",
        "awswaf",
        "aws-waf",
        "akamai",
        "imperva",
        "incapsula",
        "modsecurity",
        "modsec",
        "owasp-crs",
        "owaspcrs",
        "crs",
        "sucuri",
        "f5",
        "bigip",
        "f5-bigip",
        "barracuda",
        "fortiweb",
        "forti",
        "azure",
        "azurewaf",
        "azure-waf",
        "cloudarmor",
        "cloud-armor",
        "gcp",
        "fastly",
        "wordfence",
        "citrix",
        "netscaler",
    ];
    if known.contains(&lower.as_str()) {
        Ok(lower)
    } else {
        Err(format!(
            "unknown WAF '{}' (use one of: cloudflare, aws, akamai, imperva, modsecurity, owasp-crs, sucuri, f5, barracuda, fortiweb, azure, cloudarmor, fastly, wordfence, citrix)",
            s
        ))
    }
}

/// `--limit 0` used to mean "no findings" — counter-intuitive and
/// inconsistent with `--max-payloads-per-param 0` (which means "no
/// cap"). Reject 0 outright so the meaning is unambiguous: either
/// omit `--limit` for unlimited, or supply a positive cap.
fn parse_limit_arg(s: &str) -> std::result::Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("invalid --limit '{}': must be a positive integer", s))?;
    if n == 0 {
        return Err("--limit must be at least 1 (omit the flag entirely for no cap)".to_string());
    }
    Ok(n)
}

/// clap value-parser for `--method` / `-X`. Normalises the input to
/// uppercase so `--method get` and `--method GET` behave identically
/// (case-sensitive comparisons downstream — e.g. `args.method !=
/// "GET"` — used to silently break discovery), and rejects unknown
/// or empty methods at parse time instead of letting them surface as
/// `[POC][V][][body]` / `[POC][V][WAT][body]` garbage later.
fn parse_http_method_arg(s: &str) -> std::result::Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("HTTP method must not be empty".to_string());
    }
    let upper = trimmed.to_ascii_uppercase();
    match upper.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => Ok(upper),
        other => Err(format!(
            "unsupported HTTP method '{}' (expected one of: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)",
            other
        )),
    }
}

#[derive(Clone, Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http, har
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Output format: json, jsonl, plain, markdown, sarif, toml
    #[arg(short, long, default_value = "plain", value_parser = clap::builder::PossibleValuesParser::new(["plain", "json", "jsonl", "markdown", "sarif", "toml"]))]
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

    // `--no-color` and `--silence` (`-S`) are *also* declared on the
    // top-level `Cli` so `dalfox <TARGET> --no-color` (no subcommand)
    // works. clap accepts the same long name at root and subcommand
    // levels without conflict — whichever level the user typed the
    // flag on receives it, and `main.rs` OR-merges `cli.{no_color,
    // silence}` into these fields before invoking `run_scan`.
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
    /// Emit each finding (POC + Issue / Payload / Line) the moment it is verified, instead of waiting for end-of-scan. Useful for long scans where you want immediate feedback; off by default so the default flow shows findings after `WRN XSS found N XSS`.
    #[arg(long = "stream-findings")]
    pub stream_findings: bool,

    #[clap(help_heading = "OUTPUT")]
    /// POC output type: plain, curl, httpie, http-request
    #[arg(long, default_value = "plain", value_parser = clap::builder::PossibleValuesParser::new(["plain", "curl", "httpie", "http-request"]))]
    pub poc_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Limit the number of results to display (must be >=1). Example: --limit 10
    #[arg(long, value_parser = parse_limit_arg)]
    pub limit: Option<usize>,

    #[clap(help_heading = "OUTPUT")]
    /// Filter which finding types count toward --limit: all (default), v (verified), r (reflected), a (AST DOM XSS). Example: --limit-result-type v
    #[arg(long, default_value = "all", value_parser = clap::builder::PossibleValuesParser::new(["all", "v", "r", "a", "V", "R", "A"]))]
    pub limit_result_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Filter output to show only specific finding types (comma-separated). Options: v (verified), r (reflected), a (AST DOM XSS). Example: --only-poc "v,r"
    #[arg(long, value_delimiter = ',', value_parser = clap::builder::PossibleValuesParser::new(["v", "r", "a", "V", "R", "A"]))]
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
    #[arg(short = 'X', long, default_value = DEFAULT_METHOD, value_parser = parse_http_method_arg)]
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
    /// Per-request timeout in seconds (network only; does not bound total scan time)
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,

    #[clap(help_heading = "NETWORK")]
    /// Hard wall-clock cap per target for the scan stage (post-preflight) in
    /// seconds. When set, dalfox stops a target's payload-injection stage
    /// once this budget is exceeded — useful when many sequential phases each
    /// pay the per-request `--timeout` cost against a partially-hung
    /// endpoint. Preflight is bounded separately by per-request `--timeout`.
    /// 0 disables (default).
    #[arg(long, default_value_t = 0)]
    pub scan_timeout: u64,

    #[clap(help_heading = "NETWORK")]
    /// Delay in milliseconds
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_DELAY_MS)]
    pub delay: u64,

    #[clap(help_heading = "NETWORK")]
    /// Cap the global outbound request rate in requests/second, shared across
    /// all workers and targets (0 = unlimited). Unlike --delay (which only
    /// spaces a single worker's requests), this bounds the total in-flight
    /// burst from workers × concurrent targets — friendlier to shared-IP /
    /// edge WAF thresholds. Example: --rate-limit 20
    #[arg(long = "rate-limit", short = 'r', visible_alias = "rl", default_value_t = crate::cmd::scan::DEFAULT_RATE_LIMIT)]
    pub rate_limit: u32,

    #[clap(help_heading = "NETWORK")]
    /// Retry failed requests on HTTP 5xx and transient transport errors
    /// (timeouts, connection resets) up to this many times (0 = off). HTTP
    /// 429 is always retried regardless of this value. Example: --retries 2
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_RETRIES)]
    pub retries: u32,

    #[clap(help_heading = "NETWORK")]
    /// Base delay (ms) for the exponential backoff between retries
    /// (--retries). Doubles each attempt and is capped internally; a server
    /// Retry-After header takes precedence on 429. Example: --retry-delay 500
    #[arg(long = "retry-delay", default_value_t = crate::cmd::scan::DEFAULT_RETRY_DELAY_MS)]
    pub retry_delay: u64,

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
    /// Specify payload encoders to use (comma-separated). Options: none, url, 2url, 3url, 4url, html, htmlpad, base64, unicode, zwsp. Default: url,html
    #[arg(short = 'e', long, value_delimiter = ',', default_values = &["url", "html"], value_parser = clap::builder::PossibleValuesParser::new(["none", "url", "2url", "3url", "4url", "html", "htmlpad", "base64", "unicode", "zwsp"]))]
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
    #[arg(long, default_value = "none", value_parser = clap::builder::PossibleValuesParser::new(["none", "str"]))]
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
    /// Cap the number of payloads tested per parameter (reflection set and DOM-verification
    /// set are each capped independently). 0 = no cap (default). Useful on large attack
    /// surfaces where dynamic payloads + encoders + WAF-bypass mutations would otherwise
    /// generate thousands of requests per parameter.
    #[arg(long, default_value_t = 0)]
    pub max_payloads_per_param: usize,

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
    /// Fetch and AST-analyze same-origin external <script src> bundles for DOM-XSS
    /// (off by default to preserve request budget)
    #[arg(long)]
    pub analyze_external_js: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Enable HTTP Parameter Pollution (HPP) — duplicate query params to bypass WAF
    #[arg(long)]
    pub hpp: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Also report outdated / known-vulnerable JS libraries (informational,
    /// CWE-1104). Off by default: dalfox focuses on verified XSS; this is an
    /// opt-in retire.js-style add-on that inspects <script> tags (0 extra requests).
    #[arg(long)]
    pub detect_outdated_libs: bool,

    #[clap(help_heading = "WAF")]
    /// WAF bypass mode: auto (detect+bypass), force (use --force-waf), off (detect-only; no payload mutations). Default: auto
    #[arg(long, default_value = "auto", value_parser = clap::builder::PossibleValuesParser::new(["auto", "force", "off"]))]
    pub waf_bypass: String,

    #[clap(help_heading = "WAF")]
    /// Skip WAF fingerprinting probes (header-only detection, no provocation request)
    #[arg(long)]
    pub skip_waf_probe: bool,

    #[clap(help_heading = "WAF")]
    /// Force a specific WAF type for bypass strategies (e.g., cloudflare, akamai, modsecurity)
    #[arg(long, value_parser = parse_force_waf_arg)]
    pub force_waf: Option<String>,

    #[clap(help_heading = "WAF")]
    /// Adaptive WAF evasion: when a WAF is detected, randomize inter-request
    /// timing (jitter) and escalate a cooldown pause on clusters of blocked
    /// responses, instead of the old blunt workers=1/delay=3000 preset. Pairs
    /// well with --rate-limit. The per-WAF pacing hint is applied automatically
    /// on detection even without this flag.
    #[arg(long)]
    pub waf_evasion: bool,

    #[clap(help_heading = "WAF")]
    /// Discard WAF fingerprints below this confidence (0.0–1.0). Default
    /// (0.3) filters weak signals like `Server: Google Frontend` (0.15 —
    /// emitted by every Google-hosted property regardless of Cloud Armor)
    /// and generic "Request blocked" body markers. Real WAF signatures
    /// (Cloudflare 0.9+, AWS WAF 0.95) are kept. Pass `--waf-min-confidence 0.0`
    /// to keep every match.
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE)]
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
            detect_outdated_libs: false,
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
            scan_timeout: 0,
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
            stream_findings: false,
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
            max_payloads_per_param: 0,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: true,
            analyze_external_js: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            rate_limit: 0,
            retries: 0,
            retry_delay: 1000,
            waf_min_confidence: DEFAULT_WAF_MIN_CONFIDENCE,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }
}

#[cfg(test)]
mod arg_parser_tests {
    use super::*;
    use crate::cmd::scan::DEFAULT_TIMEOUT_SECS;

    #[test]
    fn encoders_arg_accepts_all_implemented_encoders() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            scan: ScanArgs,
        }

        // Regression for #1069: the clap allowlist must accept every encoder the
        // engine implements, including htmlpad, unicode, and zwsp.
        let cli = TestCli::try_parse_from([
            "dalfox",
            "https://example.com",
            "-e",
            "htmlpad,unicode,zwsp",
        ])
        .expect("encoders htmlpad,unicode,zwsp should be accepted");
        assert_eq!(cli.scan.encoders, vec!["htmlpad", "unicode", "zwsp"]);
    }

    #[test]
    fn force_waf_arg_normalizes_known_alias() {
        assert_eq!(parse_force_waf_arg("  CloudFlare ").unwrap(), "cloudflare");
        assert_eq!(parse_force_waf_arg("MODSEC").unwrap(), "modsec");
        assert_eq!(parse_force_waf_arg("cloud-armor").unwrap(), "cloud-armor");
        assert_eq!(parse_force_waf_arg("NetScaler").unwrap(), "netscaler");
        assert_eq!(parse_force_waf_arg("citrix").unwrap(), "citrix");
    }

    #[test]
    fn force_waf_arg_rejects_unknown() {
        let err = parse_force_waf_arg("notawaf").unwrap_err();
        assert!(err.contains("unknown WAF"), "got: {}", err);
    }

    #[test]
    fn limit_arg_accepts_positive() {
        assert_eq!(parse_limit_arg("5").unwrap(), 5);
        assert_eq!(parse_limit_arg("1").unwrap(), 1);
    }

    #[test]
    fn limit_arg_rejects_zero() {
        let err = parse_limit_arg("0").unwrap_err();
        assert!(err.contains("at least 1"), "got: {}", err);
    }

    #[test]
    fn limit_arg_rejects_non_numeric() {
        let err = parse_limit_arg("abc").unwrap_err();
        assert!(err.contains("positive integer"), "got: {}", err);
    }

    #[test]
    fn http_method_arg_uppercases_and_accepts_known() {
        for (input, expected) in [
            ("get", "GET"),
            ("Post", "POST"),
            ("  put ", "PUT"),
            ("delete", "DELETE"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
            ("patch", "PATCH"),
        ] {
            assert_eq!(parse_http_method_arg(input).unwrap(), expected);
        }
    }

    #[test]
    fn http_method_arg_rejects_empty_and_unknown() {
        assert!(
            parse_http_method_arg("   ")
                .unwrap_err()
                .contains("must not be empty")
        );
        let err = parse_http_method_arg("TRACE").unwrap_err();
        assert!(err.contains("unsupported HTTP method"), "got: {}", err);
    }

    #[test]
    fn for_preflight_sets_discovery_only_shape() {
        let args = ScanArgs::for_preflight(PreflightOptions {
            target: "https://example.com".to_string(),
            param: vec!["q".to_string()],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 15,
            proxy: None,
            follow_redirects: false,
            skip_mining: true,
            skip_discovery: false,
            encoders: vec!["none".to_string()],
        });
        assert_eq!(args.targets, vec!["https://example.com".to_string()]);
        assert_eq!(args.timeout, 15);
        assert!(args.dry_run);
        assert!(args.skip_xss_scanning);
        assert!(args.skip_ast_analysis);
        assert!(args.silence);
        // skip_mining fans out to all three mining toggles.
        assert!(args.skip_mining && args.skip_mining_dict && args.skip_mining_dom);
    }

    #[test]
    fn for_preflight_clamps_out_of_range_timeout_to_default() {
        // 0 and >=300 both fall back to the default timeout.
        let zero = ScanArgs::for_preflight(PreflightOptions {
            target: "https://example.com".to_string(),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 0,
            proxy: None,
            follow_redirects: false,
            skip_mining: false,
            skip_discovery: false,
            encoders: vec![],
        });
        assert_eq!(zero.timeout, DEFAULT_TIMEOUT_SECS);

        let huge = ScanArgs::for_preflight(PreflightOptions {
            target: "https://example.com".to_string(),
            param: vec![],
            method: "GET".to_string(),
            data: None,
            headers: vec![],
            cookies: vec![],
            user_agent: None,
            timeout: 5000,
            proxy: None,
            follow_redirects: false,
            skip_mining: false,
            skip_discovery: false,
            encoders: vec![],
        });
        assert_eq!(huge.timeout, DEFAULT_TIMEOUT_SECS);
    }
}
