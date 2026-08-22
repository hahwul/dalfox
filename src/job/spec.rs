//! The one place a scan request from an agent-facing surface becomes `ScanArgs`.
//!
//! The REST server and the MCP runtime accept the same scan, described in two
//! request shapes: REST fields are `Option<T>` with the default applied at use,
//! MCP fields are concrete with a serde `default`. Both then had their own
//! ~50-line `ScanArgs` literal that applied an identical policy — single
//! target, `input_type: "url"`, JSON output, silenced and stripped of ANSI, the
//! `skip_mining` fan-out into `skip_mining_dict`/`skip_mining_dom`, everything
//! else at its CLI default. The two literals were kept in step by comments
//! telling each side to mirror the other, and drifted anyway: `proxy` and
//! `callback_url` were silently discarded on one side (#1388), and the REST
//! copy still spelled its defaults as literals (`50`, `"GET"`,
//! `["url", "html"]`) while MCP read them from the CLI constants, so a change
//! to a `DEFAULT_*` would have moved only one front-end.
//!
//! [`ScanRequestSpec`] is that policy's single input: a scan request with every
//! value already resolved and validated. Each surface owns only the mapping
//! from its own request type into this one; [`ScanRequestSpec::into_scan_args`]
//! owns everything after that.

use crate::cmd::scan::ScanArgs;

/// A fully resolved single-target scan request.
///
/// "Resolved" means defaults are already applied, values are already validated
/// and normalized (WAF names lowercased, bounds checked), and any server-wide
/// ceiling — `--scan-timeout`, `--rate-limit` — is already folded in. Nothing
/// downstream of this struct second-guesses a field.
#[derive(Debug, Clone)]
pub(crate) struct ScanRequestSpec {
    /// The single URL to scan.
    pub(crate) target: String,
    pub(crate) param: Vec<String>,
    pub(crate) data: Option<String>,
    pub(crate) headers: Vec<String>,
    pub(crate) cookies: Vec<String>,
    pub(crate) method: String,
    pub(crate) user_agent: Option<String>,
    pub(crate) encoders: Vec<String>,
    pub(crate) timeout: u64,
    /// Whole-scan wall-clock budget; 0 = unbounded. Already capped by the
    /// server-wide ceiling where one is configured.
    pub(crate) scan_timeout: u64,
    pub(crate) delay: u64,
    pub(crate) follow_redirects: bool,
    /// Tri-state on purpose: `None` means the request said nothing, and the
    /// effective value is decided when the `Target`'s client is built (insecure
    /// by default, matching the CLI). A surface whose schema always produces a
    /// concrete bool passes `Some(..)`.
    pub(crate) insecure: Option<bool>,
    pub(crate) proxy: Option<String>,
    pub(crate) include_request: bool,
    pub(crate) include_response: bool,
    pub(crate) skip_mining: bool,
    pub(crate) skip_discovery: bool,
    pub(crate) deep_scan: bool,
    pub(crate) skip_ast_analysis: bool,
    pub(crate) analyze_external_js: bool,
    pub(crate) detect_outdated_libs: bool,
    pub(crate) blind_callback_url: Option<String>,
    pub(crate) workers: usize,
    /// Outbound request rate (RPS); 0 = unlimited. Already capped by the
    /// server-wide ceiling where one is configured.
    pub(crate) rate_limit: u32,
    pub(crate) waf_bypass: String,
    pub(crate) skip_waf_probe: bool,
    /// Canonical (lowercased) WAF name, already validated by the surface.
    pub(crate) force_waf: Option<String>,
    pub(crate) waf_evasion: bool,
    pub(crate) waf_min_confidence: f32,
    pub(crate) remote_payloads: Vec<String>,
    pub(crate) remote_wordlists: Vec<String>,
    pub(crate) max_payloads_per_param: usize,
}

impl Default for ScanRequestSpec {
    /// The values a request gets when it names nothing. Sourced from the CLI
    /// constants so the three front-ends cannot drift apart: MCP's serde
    /// `default = "..."` functions read the same constants, and
    /// [`ScanRequestSpec::from_rest_options`] fills its `Option` fields from
    /// here.
    fn default() -> Self {
        Self {
            target: String::new(),
            param: Vec::new(),
            data: None,
            headers: Vec::new(),
            cookies: Vec::new(),
            method: crate::cmd::scan::DEFAULT_METHOD.to_string(),
            user_agent: None,
            encoders: crate::cmd::scan::DEFAULT_ENCODERS
                .iter()
                .map(ToString::to_string)
                .collect(),
            timeout: crate::cmd::scan::DEFAULT_TIMEOUT_SECS,
            scan_timeout: 0,
            delay: 0,
            follow_redirects: false,
            insecure: None,
            proxy: None,
            include_request: false,
            include_response: false,
            skip_mining: false,
            skip_discovery: false,
            deep_scan: false,
            skip_ast_analysis: false,
            analyze_external_js: false,
            detect_outdated_libs: false,
            blind_callback_url: None,
            workers: crate::cmd::scan::DEFAULT_WORKERS,
            rate_limit: 0,
            waf_bypass: crate::cmd::scan::DEFAULT_WAF_BYPASS.to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            waf_min_confidence: crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
            remote_payloads: Vec::new(),
            remote_wordlists: Vec::new(),
            max_payloads_per_param: 0,
        }
    }
}

impl ScanRequestSpec {
    /// Turn the request into the `ScanArgs` the scan core runs on.
    ///
    /// Everything this sets beyond the request's own values is fixed policy for
    /// the agent-facing surfaces, and applies identically to REST and MCP.
    pub(crate) fn into_scan_args(self) -> ScanArgs {
        ScanArgs {
            // One REST job / one MCP call scans exactly one caller-supplied
            // URL, with method, headers, cookies, and body given as explicit
            // request fields — the same per-request fidelity a single HAR entry
            // carries. The fan-out input shapes (`file`, `pipe`, `raw-http`,
            // `har`) stay CLI-only because they expand one input into many
            // targets, which the one-request-one-URL model here doesn't
            // express; a caller replays a HAR by submitting one scan per entry.
            input_type: "url".to_string(),
            targets: vec![self.target],
            format: "json".to_string(),
            // Scan output is silenced and serialized as JSON, so strip ANSI
            // from any diagnostic the pipeline emits along the way.
            silence: true,
            no_color: true,

            param: self.param,
            data: self.data,
            headers: self.headers,
            cookies: self.cookies,
            method: self.method,
            user_agent: self.user_agent,
            encoders: self.encoders,
            include_request: self.include_request,
            include_response: self.include_response,

            skip_discovery: self.skip_discovery,
            // One request-level switch drives all three mining stages; the CLI
            // splits them because an operator may want to keep one.
            skip_mining: self.skip_mining,
            skip_mining_dict: self.skip_mining,
            skip_mining_dom: self.skip_mining,

            timeout: self.timeout,
            // Whole-scan wall-clock budget; 0 = unbounded. `run_scanning` does
            // not honor this field — the job runner wraps the scan future with
            // it, the same way the CLI applies the budget in its scan loop.
            scan_timeout: self.scan_timeout,
            delay: self.delay,
            proxy: self.proxy,
            insecure: self.insecure,
            follow_redirects: self.follow_redirects,
            workers: self.workers,
            // Per-scan outbound request rate, honored across all worker tasks
            // (see `crate::with_job_scopes`). 0 = unlimited.
            rate_limit: self.rate_limit,

            blind_callback_url: self.blind_callback_url,
            max_payloads_per_param: self.max_payloads_per_param,
            deep_scan: self.deep_scan,
            skip_ast_analysis: self.skip_ast_analysis,
            analyze_external_js: self.analyze_external_js,
            detect_outdated_libs: self.detect_outdated_libs,

            waf_bypass: self.waf_bypass,
            skip_waf_probe: self.skip_waf_probe,
            force_waf: self.force_waf,
            waf_evasion: self.waf_evasion,
            waf_min_confidence: self.waf_min_confidence,

            remote_payloads: self.remote_payloads,
            remote_wordlists: self.remote_wordlists,

            // Everything else stays at its CLI default. Notably `oob`: OOB/OAST
            // blind XSS is CLI-only for now, because these surfaces run their
            // own job loop and would need the poller lifecycle wired
            // separately.
            ..Default::default()
        }
    }
}

impl ScanRequestSpec {
    /// Build a spec from a REST `/scan` request body.
    ///
    /// Every `ScanOptions` field is optional, so this is where the API defaults
    /// are applied — from [`ScanRequestSpec::default`], not from literals, so
    /// the REST surface tracks a change to a `DEFAULT_*` constant the way the
    /// CLI and the MCP tool schema do.
    ///
    /// `scan_timeout` and `rate_limit` arrive already capped by the server-wide
    /// ceilings, and `force_waf` already normalized, because those need state
    /// this function does not have.
    pub(crate) fn from_rest_options(
        target: String,
        opts: &crate::server::types::ScanOptions,
        include_request: bool,
        include_response: bool,
        scan_timeout: u64,
        rate_limit: u32,
        force_waf: Option<String>,
    ) -> Self {
        let d = Self::default();
        Self {
            target,
            param: opts.param.clone().unwrap_or(d.param),
            data: opts.data.clone(),
            headers: opts.header.clone().unwrap_or(d.headers),
            // The REST body carries cookies as one `Cookie:`-style string
            // (`string_or_seq_cookie` already joined a list form); an empty or
            // whitespace-only value means "no cookies", not one blank cookie.
            cookies: opts
                .cookie
                .as_deref()
                .filter(|c| !c.trim().is_empty())
                .map(|c| vec![c.to_string()])
                .unwrap_or(d.cookies),
            method: opts.method.clone().unwrap_or(d.method),
            user_agent: opts.user_agent.clone(),
            encoders: opts.encoders.clone().unwrap_or(d.encoders),
            timeout: opts.timeout.unwrap_or(d.timeout),
            scan_timeout,
            delay: opts.delay.unwrap_or(d.delay),
            follow_redirects: opts.follow_redirects.unwrap_or(d.follow_redirects),
            // Passed through verbatim; `None` stays "unspecified".
            insecure: opts.insecure,
            proxy: opts.proxy.clone(),
            include_request,
            include_response,
            skip_mining: opts.skip_mining.unwrap_or(d.skip_mining),
            skip_discovery: opts.skip_discovery.unwrap_or(d.skip_discovery),
            deep_scan: opts.deep_scan.unwrap_or(d.deep_scan),
            skip_ast_analysis: opts.skip_ast_analysis.unwrap_or(d.skip_ast_analysis),
            analyze_external_js: opts.analyze_external_js.unwrap_or(d.analyze_external_js),
            detect_outdated_libs: opts.detect_outdated_libs.unwrap_or(d.detect_outdated_libs),
            blind_callback_url: opts.blind.clone(),
            workers: opts.worker.unwrap_or(d.workers),
            rate_limit,
            waf_bypass: opts.waf_bypass.clone().unwrap_or(d.waf_bypass),
            skip_waf_probe: opts.skip_waf_probe.unwrap_or(d.skip_waf_probe),
            force_waf,
            waf_evasion: opts.waf_evasion.unwrap_or(d.waf_evasion),
            waf_min_confidence: opts.waf_min_confidence.unwrap_or(d.waf_min_confidence),
            remote_payloads: opts.remote_payloads.clone().unwrap_or(d.remote_payloads),
            remote_wordlists: opts.remote_wordlists.clone().unwrap_or(d.remote_wordlists),
            max_payloads_per_param: opts
                .max_payloads_per_param
                .unwrap_or(d.max_payloads_per_param),
        }
    }
}
