//! Request/response data types and server configuration for the HTTP API.

use super::*;

#[derive(Args)]
pub struct ServerArgs {
    /// Port to run the server on
    #[clap(help_heading = "SERVER")]
    #[arg(short, long, default_value = "6664")]
    pub port: u16,

    /// Host to bind the server to
    #[clap(help_heading = "SERVER")]
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// API key required in X-API-KEY header (or set via DALFOX_API_KEY). Leave empty to disable auth.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "api-key")]
    pub api_key: Option<String>,

    /// Path to a log file to also write logs (plain text, no ANSI colors)
    #[clap(help_heading = "SERVER")]
    #[arg(long = "log-file")]
    pub log_file: Option<String>,

    /// Server-wide cap on each scan's outbound request rate (requests/second;
    /// 0 or unset = unlimited). Applied to every submitted scan: a request's
    /// own `rate_limit` may be lower but cannot exceed or disable this cap.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "rate-limit")]
    pub rate_limit: Option<u32>,

    /// Server-wide cap on each scan's total wall-clock runtime, in seconds
    /// (0 or unset = unbounded). Applied to every submitted scan: a request's
    /// own scan_timeout may be shorter but cannot exceed or disable this cap.
    /// Bounds long/deep scans so a single target can't pin a worker indefinitely.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "scan-timeout")]
    pub scan_timeout: Option<u64>,

    /// Maximum number of concurrently active (queued + running) scans. Once the
    /// cap is hit, new submissions get HTTP 503 until a slot frees. 0 disables
    /// the cap (unbounded). Bounds memory + the blocking-pool against a flood
    /// of submissions.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "max-concurrent-scans", default_value_t = 100)]
    pub max_concurrent_scans: usize,

    /// Maximum accepted request-body size (bytes) for POST /scan and /preflight.
    /// Replaces axum's implicit 2 MiB default with an explicit, documented bound.
    #[clap(help_heading = "SERVER")]
    #[arg(long = "max-body-bytes", default_value_t = 1_048_576)]
    pub max_body_bytes: usize,

    /// Comma-separated list of allowed origins for CORS. Supports:
    /// - "*" (match all)
    /// - exact origins (http://localhost:3000)
    /// - "regex:<pattern>" for regex
    #[clap(help_heading = "CORS")]
    #[arg(
        long = "allowed-origins",
        help = "Comma-separated list of allowed origins for CORS.\nSupports:\n  - \"*\" wildcard (match all)\n  - exact origins (http://localhost:3000)\n  - \"regex:<pattern>\" for regex",
        long_help = "Comma-separated list of allowed origins for CORS.\nSupports:\n  - \"*\" wildcard (match all)\n  - exact origins (http://localhost:3000)\n  - \"regex:<pattern>\" for regex"
    )]
    pub allowed_origins: Option<String>,

    /// Allow JSONP responses (wrap JSON in callback())
    #[clap(help_heading = "JSONP")]
    #[arg(long = "jsonp")]
    pub jsonp: bool,

    /// JSONP callback parameter name (default: callback)
    #[clap(help_heading = "JSONP")]
    #[arg(long = "callback-param-name", default_value = "callback")]
    pub callback_param_name: String,

    /// CORS allow methods (comma-separated). Default: GET,POST,OPTIONS,PUT,PATCH,DELETE
    #[clap(help_heading = "CORS")]
    #[arg(long = "cors-allow-methods")]
    pub cors_allow_methods: Option<String>,

    /// CORS allow headers (comma-separated). Default: Content-Type,X-API-KEY,Authorization
    #[clap(help_heading = "CORS")]
    #[arg(long = "cors-allow-headers")]
    pub cors_allow_headers: Option<String>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) api_key: Option<String>,
    pub(crate) jobs: Arc<Mutex<HashMap<String, Job>>>,
    // optional log file path (plain logs only; no ANSI color codes)
    pub(crate) log_file: Option<String>,
    // raw allowed origins as provided (after split)
    pub(crate) allowed_origins: Option<Vec<String>>,
    // compiled regex patterns derived from allowed_origins entries starting with "regex:" or with wildcard '*'
    pub(crate) allowed_origin_regexes: Vec<regex::Regex>,
    // whether '*' was included explicitly
    pub(crate) allow_all_origins: bool,
    // CORS response headers config
    pub(crate) allow_methods: String,
    pub(crate) allow_headers: String,
    // JSONP
    pub(crate) jsonp_enabled: bool,
    pub(crate) callback_param_name: String,
    // Server-wide per-scan request-rate cap (RPS). None/Some(0) leaves scans
    // unbounded unless a request supplies its own rate_limit.
    pub(crate) rate_limit: Option<u32>,
    // Server-wide cap on per-scan wall-clock runtime (seconds). `None`/`Some(0)`
    // leaves scans unbounded unless a request supplies its own scan_timeout.
    pub(crate) scan_timeout: Option<u64>,
    // Max concurrent (queued + running) scans; 0 = unlimited.
    pub(crate) max_concurrent_scans: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ApiResponse<T> {
    pub(crate) code: i32,
    pub(crate) msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<T>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ScanRequest {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) options: Option<ScanOptions>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct ScanOptions {
    pub(crate) cookie: Option<String>,
    pub(crate) worker: Option<usize>,
    pub(crate) delay: Option<u64>,
    pub(crate) timeout: Option<u64>,
    pub(crate) blind: Option<String>,
    pub(crate) header: Option<Vec<String>>,
    pub(crate) method: Option<String>,
    pub(crate) data: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) encoders: Option<Vec<String>>,
    pub(crate) remote_payloads: Option<Vec<String>>,
    pub(crate) remote_wordlists: Option<Vec<String>>,
    pub(crate) include_request: Option<bool>,
    pub(crate) include_response: Option<bool>,
    /// Webhook URL to POST scan results to upon completion.
    pub(crate) callback_url: Option<String>,
    /// Specific parameters to test. Supports location hints via "name:location" syntax.
    pub(crate) param: Option<Vec<String>>,
    /// HTTP/SOCKS proxy URL.
    pub(crate) proxy: Option<String>,
    /// Skip TLS/SSL certificate verification. Absent (None) keeps the scanner
    /// default of `true` (accept self-signed / staging certs); set `false` to
    /// enforce certificate validation.
    pub(crate) insecure: Option<bool>,
    /// Follow HTTP redirects (3xx).
    pub(crate) follow_redirects: Option<bool>,
    /// Skip parameter mining (DOM and dictionary-based discovery).
    pub(crate) skip_mining: Option<bool>,
    /// Skip initial parameter discovery from HTML.
    pub(crate) skip_discovery: Option<bool>,
    /// Enable deep scan mode (test all payloads even after finding XSS).
    pub(crate) deep_scan: Option<bool>,
    /// Skip AST-based JavaScript analysis.
    pub(crate) skip_ast_analysis: Option<bool>,
    /// Fetch and AST-analyze same-origin external <script src> bundles for DOM-XSS.
    pub(crate) analyze_external_js: Option<bool>,
    /// Also report outdated / known-vulnerable JS libraries (informational, CWE-1104).
    pub(crate) detect_outdated_libs: Option<bool>,
    /// Per-scan outbound request rate (requests/second; 0 = unlimited). Capped
    /// by the server's `--rate-limit` when set.
    pub(crate) rate_limit: Option<u32>,
    /// Whole-scan wall-clock budget in seconds (0 = unbounded). When the server
    /// was started with `--scan-timeout`, that value caps this one — a request
    /// may ask for a shorter budget but cannot exceed or disable the cap.
    pub(crate) scan_timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ResultPayload {
    /// The original target URL submitted for scanning.
    pub(crate) target: String,
    pub(crate) status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) results: Option<Vec<SanitizedResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) progress: Option<ProgressPayload>,
    pub(crate) queued_at_ms: i64,
    pub(crate) started_at_ms: Option<i64>,
    pub(crate) finished_at_ms: Option<i64>,
    pub(crate) duration_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProgressPayload {
    pub(crate) params_total: u32,
    pub(crate) params_tested: u32,
    pub(crate) requests_sent: u64,
    pub(crate) findings_so_far: u64,
    pub(crate) estimated_completion_pct: u32,
    /// Recommended delay (ms) before next poll; 0 when done/cancelled.
    pub(crate) suggested_poll_interval_ms: u64,
}
