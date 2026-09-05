//! MCP tool parameter definitions (`*Params` structs + serde defaults).

use super::*;

/* ---------------------------
 * Tool Parameter Definitions
 * ---------------------------
 */

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct ScanWithDalfoxParams {
    /// Target URL to scan for XSS vulnerabilities. Must start with http:// or https://.
    /// Example: "https://example.com/search?q=test"
    pub target: String,

    /// Specific parameters to test. Supports location hints via "name:location" syntax.
    /// Locations: query, body, header, cookie, path, json.
    /// Examples: ["q", "id:query", "user:body", "auth:header"]
    #[serde(default)]
    pub param: Vec<String>,

    /// HTTP method to use for requests (GET, POST, PUT, etc.).
    #[serde(default = "default_method")]
    pub method: String,

    /// Request body data for POST/PUT. Supports form-urlencoded and JSON.
    /// Example: "user=admin&pass=test" or "{\"user\":\"admin\"}"
    #[serde(default)]
    pub data: Option<String>,

    /// Custom HTTP headers. Each entry as "Name: Value".
    /// Example: ["Authorization: Bearer token", "X-Custom: value"]
    #[serde(default)]
    pub headers: Vec<String>,

    /// Cookies to include. Each entry as "name=value".
    /// Example: ["session=abc123", "lang=en"]
    #[serde(default)]
    pub cookies: Vec<String>,

    /// Custom User-Agent header string.
    #[serde(default)]
    pub user_agent: Option<String>,

    // NOTE: `cookie_from_raw` (CLI flag --cookie-from-raw) is intentionally
    // not exposed on the MCP API. It would let any caller drive a host-side
    // file open via std::fs::read_to_string, with the matching `Cookie:`
    // header lines forwarded to the attacker-supplied target URL — the same
    // class of arbitrary file read addressed in v2 by GHSA-35wr-x7v6-9fv2.
    // MCP callers can supply cookies directly via the `cookies` field.
    /// Encoding strategies to apply to payloads. Available: url, html, base64, 2url, 3url, 4url, none.
    /// Default: ["url", "html"]
    #[serde(default = "default_encoders")]
    pub encoders: Vec<String>,

    /// HTTP request timeout in seconds (1-299). Default: 10
    #[serde(default = "default_timeout")]
    #[schemars(range(min = 1, max = 299))]
    pub timeout: u64,

    /// Whole-scan wall-clock budget in seconds (0-86400). When the budget is
    /// reached the scan stops, returns whatever partial results it gathered, and
    /// settles as `cancelled` with an error_message noting the timeout. 0 = no
    /// budget (unbounded). Use this to bound long/deep scans. Default: 0
    #[serde(default)]
    #[schemars(range(max = 86400))]
    pub scan_timeout: u64,

    /// Delay between requests in milliseconds (0-9999). Default: 0
    #[serde(default)]
    #[schemars(range(max = 9999))]
    pub delay: u64,

    /// Follow HTTP redirects (3xx). Default: false
    #[serde(default)]
    pub follow_redirects: bool,

    /// Skip TLS/SSL certificate verification (accept self-signed, expired, or
    /// hostname-mismatched certs). Default: true. Set false to enforce
    /// certificate validation.
    #[serde(default = "default_true")]
    pub insecure: bool,

    /// HTTP/SOCKS proxy URL. Example: "http://127.0.0.1:8080"
    #[serde(default)]
    pub proxy: Option<String>,

    /// Include the raw HTTP request text in each finding for forensic analysis.
    #[serde(default)]
    pub include_request: bool,

    /// Include the raw HTTP response body in each finding for forensic analysis.
    #[serde(default)]
    pub include_response: bool,

    /// Skip parameter mining (DOM and dictionary-based discovery). Default: false
    #[serde(default)]
    pub skip_mining: bool,

    /// Skip initial parameter discovery from HTML. Default: false
    #[serde(default)]
    pub skip_discovery: bool,

    /// Enable deep scan mode for more thorough testing. Default: false
    #[serde(default)]
    pub deep_scan: bool,

    /// Skip AST-based JavaScript analysis. Default: false
    #[serde(default)]
    pub skip_ast_analysis: bool,

    /// Fetch and AST-analyze same-origin external <script src> bundles for DOM-XSS.
    /// Off by default to preserve request budget. Default: false
    #[serde(default)]
    pub analyze_external_js: bool,

    /// Also report outdated / known-vulnerable JS libraries (informational,
    /// CWE-1104, 0 extra requests). Default: false
    #[serde(default)]
    pub detect_outdated_libs: bool,

    /// Blind XSS callback URL (e.g., your Burp Collaborator or interact.sh URL).
    /// Must be an absolute http:// or https:// URL with a host, or omitted /
    /// empty for no blind XSS — setting it writes stored `<script src=...>`
    /// payloads into every parameter of the target, so a value that could never
    /// receive a callback is rejected rather than left behind. Default: none.
    #[serde(default)]
    pub blind_callback_url: Option<String>,

    /// Number of concurrent workers (1-500). Default: 50
    #[serde(default = "default_workers")]
    #[schemars(range(min = 1, max = 500))]
    pub workers: usize,

    /// Cap the scan's outbound request rate (requests/second). 0 = unlimited
    /// (the default). Use this to be gentle on a fragile target or to stay
    /// under a WAF's threshold. Now enforced across all worker tasks.
    #[serde(default)]
    pub rate_limit: u32,

    /// WAF handling mode: "auto" (detect then bypass), "force" (use force_waf),
    /// or "off" (detect only). Default: "auto"
    #[serde(default = "default_waf_bypass")]
    pub waf_bypass: String,

    /// Skip the WAF fingerprinting probe entirely. Default: false
    #[serde(default)]
    pub skip_waf_probe: bool,

    /// Force a specific WAF profile (e.g. "cloudflare", "akamai", "modsec")
    /// instead of detecting one. Default: none.
    #[serde(default)]
    pub force_waf: Option<String>,

    /// Enable adaptive WAF evasion. Default: false
    #[serde(default)]
    pub waf_evasion: bool,

    /// WAF detection confidence floor in [0.0, 1.0]; fingerprints below this are
    /// dropped. Default: 0.3
    //
    // f64 (not the `f32` `ScanArgs` uses internally) so the generated tool
    // schema's `default` renders as a clean `0.3` instead of the f32→f64
    // widening artifact `0.30000001192092896` (schemars/serde_json build the
    // schema's default via `serde_json::Value`, which only has an f64 number
    // variant). Narrowed back to f32 with `as f32` where this flows into
    // `ScanArgs` below.
    #[serde(default = "default_waf_min_confidence")]
    pub waf_min_confidence: f64,

    /// Fetch remote XSS payloads from providers. Available: "portswigger",
    /// "payloadbox". An unregistered name is rejected, because it would fetch
    /// nothing and silently shrink the scan's payload coverage. Default: none.
    #[serde(default)]
    pub remote_payloads: Vec<String>,

    /// Fetch remote parameter wordlists from providers. Available: "burp",
    /// "assetnote". An unregistered name is rejected, because it would fetch
    /// nothing and silently shrink parameter mining. Default: none.
    #[serde(default)]
    pub remote_wordlists: Vec<String>,

    /// Hard cap on payloads tested per parameter (0 = unlimited aside from the
    /// built-in safety cap). Use a small value (e.g. 10–50) for agent smoke
    /// scans. Default: 0
    #[serde(default)]
    pub max_payloads_per_param: usize,

    /// When true, block until the scan reaches a terminal status (done / error
    /// / cancelled) or `wait_timeout_sec` elapses, then return the same shape
    /// as `get_results_dalfox` (includes results when available). When false
    /// (default), return immediately with `{scan_id, status: "queued"}` and
    /// poll via `get_results_dalfox`. Default: false
    #[serde(default)]
    pub wait: bool,

    /// Wall-clock seconds to wait when `wait` is true (1–86400). Default: 300.
    /// Ignored when `wait` is false. On timeout the job is left running and the
    /// response includes `wait_timed_out: true` plus current progress — cancel
    /// with `cancel_scan_dalfox` if you no longer need it.
    #[serde(default = "default_wait_timeout_sec")]
    #[schemars(range(min = 1, max = 86400))]
    pub wait_timeout_sec: u64,
}

/// Default wait budget for `scan_with_dalfox` when `wait=true`.
pub(super) fn default_wait_timeout_sec() -> u64 {
    300
}

/// Hard upper bound for MCP `max_payloads_per_param` (protects against absurd
/// values). Shared with the REST server so both front-ends bound it identically.
pub(super) const MAX_PAYLOADS_PER_PARAM_MCP: usize = crate::job::MAX_PAYLOADS_PER_PARAM;
/// Hard upper bound for MCP wait wall-clock (matches scan_timeout ceiling).
pub(super) const MAX_WAIT_TIMEOUT_SECS: u64 = 86_400;

pub(super) fn default_method() -> String {
    crate::cmd::scan::DEFAULT_METHOD.to_string()
}
pub(super) fn default_waf_bypass() -> String {
    crate::cmd::scan::DEFAULT_WAF_BYPASS.to_string()
}
// Deliberately a literal, not `DEFAULT_WAF_MIN_CONFIDENCE as f64`: widening an
// f32 value preserves *its* rounding error at f64 precision, so the cast
// renders in the generated tool schema as `0.30000001192092896` instead of
// `0.3`. A test below pins this literal to the canonical f32 constant so the
// two can't silently drift if the default ever changes.
pub(super) fn default_waf_min_confidence() -> f64 {
    0.3
}
pub(super) fn default_encoders() -> Vec<String> {
    crate::cmd::scan::DEFAULT_ENCODERS
        .iter()
        .map(ToString::to_string)
        .collect()
}
pub(super) fn default_timeout() -> u64 {
    crate::cmd::scan::DEFAULT_TIMEOUT_SECS
}
pub(super) fn default_workers() -> usize {
    crate::cmd::scan::DEFAULT_WORKERS
}
/// Default for the `insecure` param: TLS verification is skipped by default
/// (scanner posture), matching the CLI `--insecure` default and the REST
/// server. Clients pass `"insecure": false` to enforce certificate validation.
pub(super) fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct GetResultsDalfoxParams {
    /// The scan_id returned by scan_with_dalfox when the scan was started.
    pub scan_id: String,

    /// Zero-based index of the first finding to return. Default: 0.
    /// Use with `limit` to page through large result sets.
    #[serde(default)]
    pub offset: usize,

    /// Maximum number of findings to return in this response. Omit or set
    /// to 0 to return all findings from `offset` onward.
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct ListScansDalfoxParams {
    /// Optional status filter: "queued", "running", "done", "error", or "cancelled". Omit to list all.
    #[serde(default)]
    pub status: Option<String>,

    /// Zero-based index of the first scan to return (scans are ordered
    /// newest-first by queue time). Default: 0.
    #[serde(default)]
    pub offset: usize,

    /// Maximum number of scans to return. Omit or set to 0 to return all from
    /// `offset` onward.
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct CancelScanDalfoxParams {
    /// The scan_id of the scan to cancel.
    pub scan_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct DeleteScanDalfoxParams {
    /// The scan_id of the scan to delete from memory.
    /// The scan must be in a terminal state (done, error, cancelled).
    pub scan_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct PreflightDalfoxParams {
    /// Target URL to analyze. Must start with http:// or https://.
    pub target: String,

    /// Accepted for symmetry with scan_with_dalfox but NOT used by preflight:
    /// preflight always reports the full auto-discovered parameter set (the
    /// impact estimate), matching the REST `/preflight` endpoint. Pass the
    /// filter to scan_with_dalfox when you actually run the scan.
    #[serde(default)]
    pub param: Vec<String>,

    /// HTTP method to use. Default: GET
    #[serde(default = "default_method")]
    pub method: String,

    /// Request body data for POST/PUT.
    #[serde(default)]
    pub data: Option<String>,

    /// Custom HTTP headers. Each entry as "Name: Value".
    #[serde(default)]
    pub headers: Vec<String>,

    /// Cookies to include. Each entry as "name=value".
    #[serde(default)]
    pub cookies: Vec<String>,

    /// Custom User-Agent header string.
    #[serde(default)]
    pub user_agent: Option<String>,

    /// HTTP request timeout in seconds (1-299). Default: 10
    #[serde(default = "default_timeout")]
    #[schemars(range(min = 1, max = 299))]
    pub timeout: u64,

    /// HTTP/SOCKS proxy URL.
    #[serde(default)]
    pub proxy: Option<String>,

    /// Follow HTTP redirects. Default: false
    #[serde(default)]
    pub follow_redirects: bool,

    /// Skip TLS/SSL certificate verification. Default: true. Set false to
    /// enforce certificate validation.
    #[serde(default = "default_true")]
    pub insecure: bool,

    /// Skip parameter mining. Default: false
    #[serde(default)]
    pub skip_mining: bool,

    /// Skip parameter discovery. Default: false
    #[serde(default)]
    pub skip_discovery: bool,

    /// Encoding strategies the subsequent scan will apply to payloads
    /// (url, html, htmlpad, base64, 2url, 3url, 4url, unicode, zwsp, none).
    /// Used only to make the estimated_total_requests reflect that scan's
    /// fan-out; the default matches scan_with_dalfox. Default: ["url", "html"]
    #[serde(default = "default_encoders")]
    pub encoders: Vec<String>,

    /// The `max_payloads_per_param` the subsequent scan will use. Like
    /// `encoders`, this only shapes estimated_total_requests — preflight sends
    /// no payloads. 0 (the default) means the built-in per-parameter safety
    /// cap applies, which is what the estimate then reflects.
    #[serde(default)]
    pub max_payloads_per_param: usize,

    /// Whether the subsequent scan will run with deep_scan. Only shapes
    /// estimated_total_requests: deep_scan lifts the built-in per-parameter
    /// payload safety cap, so the estimate is correspondingly larger.
    /// Default: false
    #[serde(default)]
    pub deep_scan: bool,
}
