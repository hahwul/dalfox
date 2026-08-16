//! Scan CLI argument surface: the `ScanArgs` clap struct, its centralized
//! default/cap constants, the `--method` / `--limit` / `--force-waf` value
//! parsers, and the `PreflightOptions` builder used by the server + MCP
//! preflight paths. Kept together so the CLI contract lives in one place.

use clap::Args;

/// The set of `ScanArgs` fields the operator actually supplied on the command
/// line, as clap's argument ids (the snake_case field names).
///
/// Config precedence needs to answer one question — "did the user ask for
/// this?" — and for most of `ScanArgs` the field itself cannot answer it. A
/// flag like `--workers` always holds *some* value, so the only way to tell an
/// untouched default from a deliberately re-asserted one used to be comparing
/// against the default, which reads a re-assertion as silence: `--workers 50`
/// against a config-file `workers = 200` silently ran 200 workers, and the
/// operator had no way to dial concurrency back down for one fragile target.
/// Two flags (`--baseline-mode`, `--on-session-loss`) were rescued
/// individually by re-typing them as `Option<String>`; this records the answer
/// once, for every flag, from the only place that genuinely knows it —
/// clap's [`clap::parser::ValueSource`].
///
/// Empty for every non-CLI construction (`Default::default()`, the REST and
/// MCP runners, tests). Those paths never consult a config file, so "nothing
/// was explicit" is both true and inert.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExplicitArgs(std::collections::BTreeSet<String>);

impl ExplicitArgs {
    /// Collect every argument id that came from the command line or an
    /// environment variable, i.e. everything except clap's own defaults.
    ///
    /// An env var counts as explicit on purpose: the precedence contract is
    /// CLI > env > config file > built-in default, so `DALFOX_X=…` has to beat
    /// a config value the same way typing the flag does.
    pub fn from_matches(matches: &clap::ArgMatches) -> Self {
        use clap::parser::ValueSource;
        Self(
            matches
                .ids()
                .filter(|id| {
                    matches!(
                        matches.value_source(id.as_str()),
                        Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable)
                    )
                })
                .map(|id| id.as_str().to_string())
                .collect(),
        )
    }

    /// Whether `id` (a `ScanArgs` field name) was supplied by the operator.
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.0.contains(id)
    }

    /// Record `id` as operator-chosen. Used by the `url` / `file` / `pipe`
    /// subcommands, which *derive* `input_type` from which subcommand was
    /// invoked: choosing `dalfox file list.txt` is as deliberate as typing
    /// `-i file`, so a config-file `input_type` must not overwrite it.
    pub(crate) fn insert(&mut self, id: &str) {
        self.0.insert(id.to_string());
    }

    /// True when nothing was recorded — every non-CLI construction path.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Default encoders used when the user does not specify any via CLI or config.
/// Centralizing this allows config.rs to reference the same canonical defaults.
pub const DEFAULT_ENCODERS: &[&str] = &["url", "html"];

// Allowed value sets for the enum-like string flags. Kept as the single source
// of truth so both the clap `PossibleValuesParser` below and the config-file
// validator (`config::ScanConfig::normalize_and_validate`) agree — a config
// file bypasses clap entirely, so without a shared list an invalid config value
// would be copied straight into `ScanArgs` and silently misbehave.
pub const FORMAT_VALUES: &[&str] = &["plain", "json", "jsonl", "markdown", "sarif", "toml"];
pub const POC_TYPE_VALUES: &[&str] = &["plain", "curl", "httpie", "http-request"];
// `i` (informational) is selectable as well as excludable: the letter is a real
// finding type, so omitting it meant `--only-poc v,a,r` could filter it out but
// nothing could ask for it on its own.
pub const LIMIT_RESULT_TYPE_VALUES: &[&str] = &["all", "v", "r", "a", "i", "V", "R", "A", "I"];
pub const ONLY_POC_VALUES: &[&str] = &["v", "r", "a", "i", "V", "R", "A", "I"];
/// `--baseline-mode filter`: drop findings already in the baseline, so the
/// counts, the exit code, and `--limit` all describe only what is new. The
/// CI-gate default.
pub(crate) const BASELINE_MODE_FILTER: &str = "filter";
/// `--baseline-mode annotate`: keep every finding and tag each with
/// `new: true|false`, for dashboards that want the whole set.
pub(crate) const BASELINE_MODE_ANNOTATE: &str = "annotate";
pub const BASELINE_MODE_VALUES: &[&str] = &[BASELINE_MODE_FILTER, BASELINE_MODE_ANNOTATE];
pub const ENCODER_VALUES: &[&str] = &[
    "none", "url", "2url", "3url", "4url", "html", "htmlpad", "base64", "unicode", "zwsp",
];
pub const CUSTOM_ALERT_TYPE_VALUES: &[&str] = &["none", "str"];
pub const WAF_BYPASS_VALUES: &[&str] = &["auto", "force", "off"];
pub const DEDUP_URLS_VALUES: &[&str] = &["exact", "signature", "off"];
/// Default for `--dedup-urls`: collapse only byte-identical `url|method`
/// pairs, i.e. the historical behavior. `signature` additionally collapses
/// URLs that differ solely in parameter *values*, which is not value-safe for
/// every endpoint, so it stays opt-in.
pub const DEFAULT_DEDUP_URLS: &str = "exact";
// Defined in `session`, re-exported through the same door as every other
// enum-like value set so `config.rs` has one place to look.
pub use super::session::{DEFAULT_ON_SESSION_LOSS, ON_SESSION_LOSS_VALUES};
// Centralized numeric defaults (used by CLI default_value_t and config precedence logic)
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_DELAY_MS: u64 = 0;
pub const DEFAULT_WORKERS: usize = 50;
pub const DEFAULT_MAX_CONCURRENT_TARGETS: usize = 50;
pub const DEFAULT_MAX_TARGETS_PER_HOST: usize = 100;
/// Built-in per-parameter payload safety cap, applied when the operator did
/// not pass `--max-payloads-per-param` (its `0`) and is not running
/// `--deep-scan`. A parameter that reflects every payload without ever
/// DOM-verifying — the classic self-/canonical-link echo — would otherwise
/// drive the DOM-verification phase through the full dynamic-payload set
/// (10k+ requests per parameter, the request-amplification behind the
/// "scan hangs for many minutes" reports). Capping the long encoder/mutation
/// tail keeps the high-signal head (structural + common-context payloads run
/// first) while bounding the fan-out. `--deep-scan` or an explicit
/// `--max-payloads-per-param` opts out.
pub const DEFAULT_PAYLOAD_SAFETY_CAP: usize = 3000;
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
/// Sanity cap for `--sxss-retries`. Much tighter than [`CLI_MAX_RETRIES`]
/// because the stored-XSS re-check backoff is `500ms * attempt`, i.e. the total
/// wait grows *quadratically*: 20 retries is ~1.6 minutes per check URL, while
/// the un-capped 3000 someone could type is ~26 days. Applied per check URL and
/// per verified payload, so it multiplies.
pub const CLI_MAX_SXSS_RETRIES: u32 = 20;
/// Ceiling on a single stored-XSS re-check backoff sleep. Bounds the tail of
/// the `500ms * attempt` ramp so the last attempts stay responsive.
pub const MAX_SXSS_BACKOFF_MS: u64 = 5_000;
/// Sanity cap for `--retry-delay` (ms), matching `--delay`'s ceiling.
pub const CLI_MAX_RETRY_DELAY_MS: u64 = 60_000;
/// Sanity cap for `--scan-timeout` (seconds). Kept in lockstep with the async
/// front-ends' `crate::job::MAX_SCAN_TIMEOUT_SECS` (24h) so the whole-scan
/// budget bound is identical across CLI / server / MCP. Beyond a ceiling, the
/// per-target `Instant::now() + Duration::from_secs(scan_timeout)` in
/// `scan_loop::run_target_capped` can overflow and panic, so — like every other
/// duration arg — this must be range-checked before it reaches the scan loop.
pub(crate) const CLI_MAX_SCAN_TIMEOUT_SECS: u64 = 86_400;
// Enforce the "identical bound across CLI / server / MCP" claim at compile time
// so a future edit to one constant can't silently diverge from the other.
const _: () = assert!(CLI_MAX_SCAN_TIMEOUT_SECS == crate::job::MAX_SCAN_TIMEOUT_SECS);
// Default HTTP method (used by CLI and target parsing)
pub const DEFAULT_METHOD: &str = "GET";

/// True when `format` makes stdout a *document* rather than human-facing
/// output, so the banner — and anything else decorative — must be suppressed
/// or it corrupts the document.
///
/// Deliberately derived from `plain` being the only human renderer instead of
/// listing the machine ones. The machine list was spelled out literally in two
/// places in `main.rs` and drifted: `markdown` was missing from both, so
/// `dalfox scan URL -f markdown > report.md` produced a file whose first
/// seventeen lines were the ASCII banner, while the same run written with `-o`
/// was clean. Phrasing it as "not plain" makes a newly added format
/// document-safe by default, which is the safe direction to fail in.
pub fn format_is_machine(format: &str) -> bool {
    format != "plain"
}

/// clap value-parser for `--force-waf`. Accepts the same alias set that
/// `parse_waf_type` recognises (case-insensitive) and rejects anything
/// else at parse time so a typo like `--force-waf cloudflair` doesn't
/// silently fall into the `WafType::Unknown(other)` bucket and skip
/// the targeted bypass mutations.
pub(crate) fn parse_force_waf_arg(s: &str) -> std::result::Result<String, String> {
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
pub(crate) fn parse_http_method_arg(s: &str) -> std::result::Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("HTTP method must not be empty".to_string());
    }
    let upper = trimmed.to_ascii_uppercase();
    match upper.as_str() {
        // QUERY is RFC 10008 (safe/idempotent body-bearing method).
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "QUERY" => Ok(upper),
        other => Err(format!(
            "unsupported HTTP method '{}' (expected one of: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, QUERY)",
            other
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http, har
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "INPUT")]
    /// Target deduplication [default: exact]: exact (drop byte-identical
    /// URL+method), signature (also collapse URLs that differ only in
    /// parameter values — keys on method+host+path+parameter names), off (scan
    /// every input line).
    //
    // Non-doc on purpose: clap renders `///` into `--help`, and the rest of
    // this is implementation rationale, not operator guidance.
    //
    // `None` (not `Some("exact")`) — absence is meaningful: it lets a config
    // file supply the mode, while `Some(_)` is an explicit CLI choice that
    // always wins. Without that distinction `--dedup-urls exact` could not
    // override a config-file `signature`, i.e. the operator could not turn
    // off a mode that discards targets. Read it through
    // `ScanArgs::dedup_urls_mode`.
    #[arg(long, value_name = "MODE", value_parser = clap::builder::PossibleValuesParser::new(DEDUP_URLS_VALUES.iter().copied()))]
    pub dedup_urls: Option<String>,

    #[clap(help_heading = "OUTPUT")]
    /// Output format: json, jsonl, plain, markdown, sarif, toml
    #[arg(short, long, default_value = "plain", value_parser = clap::builder::PossibleValuesParser::new(FORMAT_VALUES.iter().copied()))]
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
    #[arg(long, default_value = "plain", value_parser = clap::builder::PossibleValuesParser::new(POC_TYPE_VALUES.iter().copied()))]
    pub poc_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Limit the number of results to display (must be >=1). Example: --limit 10
    #[arg(long, value_parser = parse_limit_arg)]
    pub limit: Option<usize>,

    #[clap(help_heading = "OUTPUT")]
    /// Filter which finding types count toward --limit: all (default), v (vulnerable), r (reflected), a (AST DOM XSS), i (informational). Example: --limit-result-type v
    #[arg(long, default_value = "all", value_parser = clap::builder::PossibleValuesParser::new(LIMIT_RESULT_TYPE_VALUES.iter().copied()))]
    pub limit_result_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Filter output to show only specific finding types (comma-separated). Options: v (vulnerable), r (reflected), a (AST DOM XSS), i (informational). Example: --only-poc "v,r"
    #[arg(long, value_delimiter = ',', value_parser = clap::builder::PossibleValuesParser::new(ONLY_POC_VALUES.iter().copied()))]
    pub only_poc: Vec<String>,

    #[clap(help_heading = "INPUT")]
    /// Record which targets finished to PATH and skip them when the same scan
    /// is re-run, so an interrupted mass scan resumes instead of restarting.
    /// Only fully completed targets are skipped; ones cut short by Ctrl-C or
    /// --scan-timeout are retried. Example: --state-file scan.state
    #[arg(long, value_name = "PATH")]
    pub state_file: Option<String>,

    #[clap(help_heading = "OUTPUT")]
    /// Diff against a previous dalfox JSON/JSONL report and report only findings new since it. The baseline is an ordinary `--format json --output` report. Example: --baseline baseline.json
    #[arg(long)]
    pub baseline: Option<String>,

    #[clap(help_heading = "OUTPUT")]
    /// What --baseline does with already-known findings [default: filter]:
    /// filter (drop them, so the exit code gates on new findings only) or
    /// annotate (keep them and mark each `new`). Example: --baseline-mode annotate
    //
    // `None` (not `Some("filter")`) — absence is meaningful: it lets a config
    // file supply the mode, while `Some(_)` is an explicit CLI choice that
    // always wins. Read it through `ScanArgs::baseline_mode`.
    #[arg(long = "baseline-mode", value_name = "MODE", value_parser = clap::builder::PossibleValuesParser::new(BASELINE_MODE_VALUES.iter().copied()))]
    pub baseline_mode_arg: Option<String>,

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

    #[clap(help_heading = "SESSION")]
    /// Regex that must keep matching the response body for the session to be
    /// considered alive (e.g. --session-check 'Sign out'). Authoritative: when
    /// set, the built-in heuristics (401/403, login redirect, appearing login
    /// form) are not consulted. Without it, session monitoring still runs
    /// automatically whenever credentials are supplied via --cookies,
    /// --cookie-from-raw, or a Cookie/Authorization header.
    #[arg(long, value_name = "REGEX")]
    pub session_check: Option<String>,

    #[clap(help_heading = "SESSION")]
    /// Probe this URL instead of the scan target when re-validating the
    /// session. Useful when the target itself is public but the app exposes a
    /// cheap authenticated endpoint. Example: --session-check-url 'https://app/me'
    #[arg(long, value_name = "URL")]
    pub session_check_url: Option<String>,

    #[clap(help_heading = "SESSION")]
    /// What to do when the session is detected as lost [default: abort]: abort
    /// stops the affected target and skips the rest of that host; continue keeps
    /// scanning. Either way the target is reported as `incomplete` /
    /// SESSION_LOST instead of a misleading "clean".
    //
    // `None` (not `Some("abort")`) — absence is meaningful: it lets a config
    // file supply the policy, while `Some(_)` is an explicit CLI choice that
    // always wins. Without that distinction `--on-session-loss abort` could not
    // override a config-file `continue`, i.e. the operator could not turn the
    // safe default back on. Read it through `ScanArgs::on_session_loss_mode`.
    #[arg(long = "on-session-loss", value_name = "POLICY", value_parser = clap::builder::PossibleValuesParser::new(ON_SESSION_LOSS_VALUES.iter().copied()))]
    pub on_session_loss_arg: Option<String>,

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
    /// Skip mining parameter names from HTML input id/name attributes. Does NOT disable DOM-XSS static analysis of inline scripts (the `[A]` findings) — use --skip-ast-analysis for that.
    #[arg(long)]
    pub skip_mining_dom: bool,

    #[clap(help_heading = "NETWORK")]
    /// Per-request timeout in seconds (network only; does not bound total scan time)
    #[arg(long, default_value_t = crate::cmd::scan::DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,

    #[clap(help_heading = "NETWORK")]
    /// Hard wall-clock cap per target for the payload-injection (scan) stage in
    /// seconds. When set, dalfox stops a target's payload-injection stage
    /// once this budget is exceeded — useful when many sequential phases each
    /// pay the per-request `--timeout` cost against a partially-hung
    /// endpoint. Scope note: this caps ONLY the injection stage. The earlier
    /// preflight and parameter-analysis (discovery + mining) phases are bounded
    /// separately by `--timeout` × request-count, NOT by this wall-clock cap, so
    /// a slow target can overshoot this budget during analysis. 0 disables (default).
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
    /// Skip TLS/SSL certificate verification, accepting self-signed, expired,
    /// or hostname-mismatched certs. Enabled by default for scanner use; pass
    /// `--insecure=false` to enforce certificate validation. Example: --insecure=false
    ///
    /// Stored as Option so presence is distinguishable from the default:
    /// `None` means the user didn't pass the flag (config may set it; the
    /// effective value is `unwrap_or(true)`), while `Some(_)` is an explicit
    /// CLI choice that always wins over config — in either direction.
    #[arg(
        long,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub insecure: Option<bool>,

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
    #[arg(short = 'e', long, value_delimiter = ',', default_values = &["url", "html"], value_parser = clap::builder::PossibleValuesParser::new(ENCODER_VALUES.iter().copied()))]
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

    /// OOB/OAST (interactsh) blind-XSS options: --blind-oob[=servers],
    /// --blind-oob-secret, --blind-oob-wait. Flattened so they appear as
    /// top-level flags while staying a single field on `ScanArgs`.
    #[command(flatten)]
    pub oob: BlindOobArgs,

    #[clap(help_heading = "XSS SCANNING")]
    /// Load custom payloads from a file. Example: --custom-payload 'payloads.txt'
    #[arg(long)]
    pub custom_payload: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Only test custom payloads. Example: --only-custom-payload --custom-payload=p.txt
    //
    // Deliberately NOT `requires = "custom_payload"`. The pairing is real — on
    // its own this flag yields an empty payload set and a scan that reports
    // clean without sending anything — but clap validates argument
    // relationships *before* the config file is overlaid, so `requires` would
    // reject the legitimate `--only-custom-payload` + `custom_payload = "…"`
    // in a config file. The check therefore lives in `run_scan`, which runs
    // after `finalize_scan_args` has merged the config, plus in
    // `Config::normalize_and_validate` for the all-config form.
    #[arg(long)]
    pub only_custom_payload: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Custom value for alert/prompt/confirm in payloads. Default: "1". Example: --custom-alert-value 'document.domain'
    #[arg(long, default_value = "1")]
    pub custom_alert_value: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Custom alert function type. Options: none (keep original), str (wrap value in quotes). Default: "none"
    #[arg(long, default_value = "none", value_parser = clap::builder::PossibleValuesParser::new(CUSTOM_ALERT_TYPE_VALUES.iter().copied()))]
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
    /// Cap the number of base payloads tested per parameter (reflection set and DOM-verification
    /// set are each capped independently). 0 (default) applies a built-in safety cap of 3000
    /// per set unless --deep-scan is set; pass an explicit value to override, or --deep-scan
    /// for a truly unlimited run. Bounds the request fan-out on large attack surfaces and on
    /// endpoints that reflect every payload (self-/canonical-link echoes) without verifying.
    /// Note: the cap applies to the base catalog; WAF-bypass mutation/encoder expansion and a
    /// small set of shared CSP-bypass / tech-specific payloads are added afterwards (and never
    /// trimmed), so the actual per-parameter total can exceed this value — substantially so when
    /// a WAF bypass strategy is active. Use --deep-scan only to lift the built-in default cap.
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
    // Same parser as `--method`. Without it `--sxss-method post` went on the
    // wire as the literal extension verb `post` (`reqwest::Method` is
    // case-sensitive) and `--sxss-method "GET junk"` failed to parse and
    // silently degraded to GET.
    #[arg(long, default_value = "GET", value_parser = parse_http_method_arg)]
    pub sxss_method: String,

    #[clap(help_heading = "XSS SCANNING")]
    /// Number of times to re-check the Stored XSS URL to handle slow
    /// session/content propagation. Each retry waits 500ms * attempt_index.
    #[arg(long, default_value_t = 3)]
    pub sxss_retries: u32,

    #[clap(help_heading = "XSS SCANNING")]
    /// Skip AST-based DOM XSS detection — the source→sink analysis of
    /// JavaScript in responses that emits [A] findings. This is the flag
    /// that silences them; --skip-mining-dom does not
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
    #[arg(long, default_value = "auto", value_parser = clap::builder::PossibleValuesParser::new(WAF_BYPASS_VALUES.iter().copied()))]
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

    /// Which of the fields above the operator actually typed. Not a flag —
    /// `#[arg(skip)]` keeps it out of the CLI surface entirely; it is filled in
    /// from clap's `ArgMatches` in `main.rs` and read only by
    /// [`crate::config::Config::apply_to_scan_args_if_default`]. See
    /// [`ExplicitArgs`].
    #[arg(skip)]
    pub explicit: ExplicitArgs,
}

impl ScanArgs {
    /// Whether the operator supplied `id` (a field name) on the command line,
    /// as opposed to it holding a built-in default. Config precedence hangs off
    /// this: a config value may fill a field the operator left alone, never one
    /// they chose — including when their choice equals the default.
    pub(crate) fn was_explicit(&self, id: &str) -> bool {
        self.explicit.contains(id)
    }
}

/// Every field carries exactly the value clap's `default_value` /
/// `default_value_t` would produce for a bare `dalfox scan <TARGET>` run, so
/// `ScanArgs { .. , ..Default::default() }` is behaviourally identical to
/// spelling out the full struct.
///
/// This exists so that adding a field to `ScanArgs` touches *this* impl and
/// nothing else. Before it, every construction site listed all ~60 fields
/// exhaustively, which meant a one-line flag addition rippled through 30+
/// call sites across `src/` — pure merge-conflict surface for anything
/// developed in parallel.
///
/// `scanargs_default_matches_clap_defaults` in `arg_parser_tests` pins the two
/// together: if a new field's `default_value` and its entry here disagree, that
/// test fails rather than the divergence reaching a release.
impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            input_type: "auto".to_string(),
            dedup_urls: None,
            format: "plain".to_string(),
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            stream_findings: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            state_file: None,
            baseline: None,
            baseline_mode_arg: None,
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: DEFAULT_METHOD.to_string(),
            user_agent: None,
            cookie_from_raw: None,
            session_check: None,
            session_check_url: None,
            on_session_loss_arg: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            mining_dict_word: None,
            remote_wordlists: vec![],
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            timeout: crate::cmd::scan::DEFAULT_TIMEOUT_SECS,
            scan_timeout: 0,
            delay: crate::cmd::scan::DEFAULT_DELAY_MS,
            rate_limit: crate::cmd::scan::DEFAULT_RATE_LIMIT,
            retries: crate::cmd::scan::DEFAULT_RETRIES,
            retry_delay: crate::cmd::scan::DEFAULT_RETRY_DELAY_MS,
            proxy: None,
            // `None` (not `Some(false)`) — absence is meaningful here: it lets
            // config supply the value, while `Some(_)` is an explicit CLI
            // choice that always wins. See the field's doc comment.
            insecure: None,
            follow_redirects: false,
            ignore_return: vec![],
            workers: crate::cmd::scan::DEFAULT_WORKERS,
            max_concurrent_targets: crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
            max_targets_per_host: crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
            encoders: DEFAULT_ENCODERS.iter().map(|s| s.to_string()).collect(),
            remote_payloads: vec![],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            oob: BlindOobArgs::default(),
            custom_payload: None,
            only_custom_payload: false,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            inject_marker: None,
            skip_xss_scanning: false,
            max_payloads_per_param: 0,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            sxss_retries: 3,
            skip_ast_analysis: false,
            analyze_external_js: false,
            hpp: false,
            detect_outdated_libs: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
            targets: vec![],
            explicit: ExplicitArgs::default(),
        }
    }
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
    /// Skip TLS certificate verification for the preflight reachability probe
    /// and discovery requests. Defaults to the scanner posture (`true`) at the
    /// call sites; threaded through so server/MCP preflight honor the caller's
    /// `--insecure` choice instead of silently forcing it on.
    pub insecure: bool,
    pub follow_redirects: bool,
    pub skip_mining: bool,
    pub skip_discovery: bool,
    pub encoders: Vec<String>,
}

/// OOB/OAST (interactsh) blind-XSS flags, flattened into [`ScanArgs`]. Grouped
/// into one sub-struct so adding OOB support touches a single `ScanArgs` field
/// instead of three. `Default` (all-unset) means OOB is disabled.
#[derive(Args, Clone, Debug, Default, PartialEq)]
pub struct BlindOobArgs {
    #[clap(help_heading = "XSS SCANNING")]
    /// Enable OOB blind XSS via interactsh. Optional comma-separated server
    /// domains (default: public servers). Example: --blind-oob=oast.fun,oast.me
    //
    // `require_equals` is deliberate (kept out of `--help`): with a bare
    // `num_args = 0..` this option would greedily swallow the following
    // positional target (`dalfox --blind-oob https://t` would treat `https://t`
    // as a server name and leave no scan target). Forcing the `=` form keeps
    // bare `--blind-oob` (default mesh) working while never consuming the URL.
    #[arg(long = "blind-oob", value_delimiter = ',', num_args = 0.., require_equals = true)]
    pub blind_oob: Option<Vec<String>>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Auth token (secret) for a self-hosted interactsh server; sent as the
    /// Authorization header on register/poll/deregister.
    #[arg(long = "blind-oob-secret")]
    pub blind_oob_secret: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Seconds to keep polling for OOB callbacks after all payloads are sent
    /// (default 30; 0 = no extra end-of-scan wait).
    #[arg(long = "blind-oob-wait")]
    pub blind_oob_wait: Option<u64>,
}

/// Default end-of-scan OOB drain window when `--blind-oob-wait` is unset.
pub(crate) const DEFAULT_BLIND_OOB_WAIT_SECS: u64 = 30;

impl ScanArgs {
    /// Effective `--dedup-urls` mode: the operator's choice, else the built-in
    /// [`DEFAULT_DEDUP_URLS`]. The field is an `Option` so config precedence can
    /// tell "unset" from an explicit `exact`; every reader should go through
    /// this instead of unwrapping the field.
    pub(crate) fn dedup_urls_mode(&self) -> &str {
        self.dedup_urls.as_deref().unwrap_or(DEFAULT_DEDUP_URLS)
    }

    /// Effective `--baseline-mode`: the operator's choice, else
    /// [`BASELINE_MODE_FILTER`]. `Option` for the same reason as
    /// [`ScanArgs::dedup_urls_mode`] — an explicit `--baseline-mode filter` has
    /// to beat a config-file `annotate`, which a "field equals the default"
    /// test cannot express.
    pub(crate) fn baseline_mode(&self) -> &str {
        self.baseline_mode_arg
            .as_deref()
            .unwrap_or(BASELINE_MODE_FILTER)
    }

    /// Effective `--on-session-loss` policy: the operator's choice, else
    /// `abort`. `Option` so an explicit `--on-session-loss abort` beats a
    /// config-file `continue`; see [`ScanArgs::dedup_urls_mode`].
    pub(crate) fn on_session_loss_mode(&self) -> &str {
        self.on_session_loss_arg
            .as_deref()
            .unwrap_or(DEFAULT_ON_SESSION_LOSS)
    }

    /// True when `--blind-oob` was supplied (with or without a server list).
    pub(crate) fn blind_oob_enabled(&self) -> bool {
        self.oob.blind_oob.is_some()
    }

    /// Candidate OOB server domains: the user's list, or the public mesh.
    ///
    /// Entries are trimmed and blanks dropped, so `--blind-oob=`,
    /// `--blind-oob=,,`, or stray whitespace (`--blind-oob=" oast.fun , "`)
    /// degrade to a clean list (or the public mesh) instead of attempting a
    /// doomed registration against an empty host.
    pub(crate) fn blind_oob_servers(&self) -> Vec<String> {
        let cleaned: Vec<String> = self
            .oob
            .blind_oob
            .iter()
            .flatten()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() {
            crate::oob::DEFAULT_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            cleaned
        }
    }

    /// Self-hosted interactsh auth token, if any.
    pub(crate) fn blind_oob_secret(&self) -> Option<&str> {
        self.oob.blind_oob_secret.as_deref()
    }

    /// End-of-scan OOB drain window in seconds.
    pub(crate) fn blind_oob_wait(&self) -> u64 {
        self.oob
            .blind_oob_wait
            .unwrap_or(DEFAULT_BLIND_OOB_WAIT_SECS)
    }

    /// Build [`crate::oob::OobConfig`] from the parsed args + scan HTTP knobs.
    pub(crate) fn oob_config(&self) -> crate::oob::OobConfig {
        crate::oob::OobConfig {
            servers: self.blind_oob_servers(),
            secret: self.blind_oob_secret().map(str::to_string),
            wait_secs: self.blind_oob_wait(),
            timeout: self.timeout,
            proxy: self.proxy.clone(),
            // Mirror the scanner-wide insecure-by-default TLS posture: every
            // other consumer of `insecure` resolves `None` -> true (see
            // input.rs / mod.rs). Enforcing validation only on the OOB client
            // silently disabled blind-OOB against self-hosted interactsh
            // servers presenting self-signed/mismatched certs.
            insecure: self.insecure.unwrap_or(true),
        }
    }

    /// Build a ScanArgs configured for preflight analysis only (no attack payloads).
    /// Used by both MCP preflight_dalfox and REST API /preflight endpoint.
    pub(crate) fn for_preflight(opts: PreflightOptions) -> Self {
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
            skip_mining: opts.skip_mining,
            skip_mining_dict: opts.skip_mining,
            skip_mining_dom: opts.skip_mining,
            skip_discovery: opts.skip_discovery,
            timeout,
            proxy: opts.proxy,
            // Preflight only inspects content-type/parameters; it defaults to
            // trusting self-signed / staging certs (callers pass `true`) so
            // discovery isn't blocked by an internal TLS posture, but the value
            // is now caller-controlled rather than hardcoded. The caller always
            // has a concrete bool here, so record it as an explicit choice.
            insecure: Some(opts.insecure),
            follow_redirects: opts.follow_redirects,
            silence: true,
            dry_run: true,
            no_color: true,
            workers: 10,
            max_concurrent_targets: 1,
            max_targets_per_host: 1,
            encoders: opts.encoders,
            skip_xss_scanning: true,
            skip_ast_analysis: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod arg_parser_tests;

#[cfg(test)]
mod format_tests;
