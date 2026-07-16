/*!
Configuration module for Dalfox.

Responsibilities:
- Resolve config directory using XDG Base Directory spec or HOME fallback
- Load configuration from TOML or JSON with precedence: TOML > JSON
- If the directory or file does not exist, create it (default to TOML), then load
- Expose a structure that maps to most Dalfox flags so users can predefine them
- Provide helpers to overlay config onto ScanArgs (caller controls precedence)

Notes:
- Search order for config base dir:
  1) $XDG_CONFIG_HOME/dalfox
  2) $HOME/.config/dalfox
- File preference in a base dir: config.toml first, then config.json
- Auto-create directory and a TOML template if no config exists.
*/

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Json,
}

#[derive(Debug, Clone)]
pub struct LoadResult {
    pub config: Config,
    pub path: PathBuf,
    pub format: ConfigFormat,
    // Whether a new config file was created on this load
    pub created: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    // Expand with more top-level settings if needed (e.g., logging)
    pub scan: Option<ScanConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanConfig {
    // INPUT
    pub input_type: Option<String>,
    // OUTPUT
    pub format: Option<String>,
    pub output: Option<String>,
    pub include_request: Option<bool>,
    pub include_response: Option<bool>,
    pub include_all: Option<bool>,
    pub silence: Option<bool>,
    pub dry_run: Option<bool>,
    pub stream_findings: Option<bool>,
    pub poc_type: Option<String>,
    pub limit: Option<usize>,
    pub limit_result_type: Option<String>,
    pub only_poc: Option<Vec<String>>,
    pub no_color: Option<bool>,
    // TARGETS
    pub param: Option<Vec<String>>,
    pub data: Option<String>,
    pub headers: Option<Vec<String>>,
    pub cookies: Option<Vec<String>>,
    pub method: Option<String>,
    pub user_agent: Option<String>,
    pub cookie_from_raw: Option<String>,
    // SCOPE
    pub include_url: Option<Vec<String>>,
    pub exclude_url: Option<Vec<String>>,
    pub ignore_param: Option<Vec<String>>,
    pub out_of_scope: Option<Vec<String>>,
    pub out_of_scope_file: Option<String>,
    // PARAMETER DISCOVERY
    pub only_discovery: Option<bool>,
    pub skip_discovery: Option<bool>,
    pub skip_reflection_header: Option<bool>,
    pub skip_reflection_cookie: Option<bool>,
    pub skip_reflection_path: Option<bool>,
    // PARAMETER MINING
    pub mining_dict_word: Option<String>,
    pub remote_wordlists: Option<Vec<String>>,
    pub skip_mining: Option<bool>,
    pub skip_mining_dict: Option<bool>,
    pub skip_mining_dom: Option<bool>,
    // NETWORK
    pub timeout: Option<u64>,
    pub scan_timeout: Option<u64>,
    pub delay: Option<u64>,
    pub rate_limit: Option<u32>,
    pub retries: Option<u32>,
    pub retry_delay: Option<u64>,
    pub proxy: Option<String>,
    /// Skip TLS/SSL certificate verification. Omitted (None) keeps the
    /// scanner default of `true` (insecure); set `false` to enforce
    /// certificate validation.
    pub insecure: Option<bool>,
    pub follow_redirects: Option<bool>,
    pub ignore_return: Option<Vec<u16>>,
    // ENGINE
    pub workers: Option<usize>,
    pub max_concurrent_targets: Option<usize>,
    pub max_targets_per_host: Option<usize>,
    // XSS SCANNING
    pub encoders: Option<Vec<String>>,
    pub remote_payloads: Option<Vec<String>>,
    pub custom_blind_xss_payload: Option<String>,
    pub blind_callback_url: Option<String>,
    /// OOB/OAST (interactsh) blind XSS. `blind_oob` mirrors `--blind-oob`:
    /// `Some([])` enables with default public servers, `Some([..])` names them.
    pub blind_oob: Option<Vec<String>>,
    pub blind_oob_secret: Option<String>,
    pub blind_oob_wait: Option<u64>,
    pub custom_payload: Option<String>,
    pub only_custom_payload: Option<bool>,
    pub inject_marker: Option<String>,
    pub custom_alert_value: Option<String>,
    pub custom_alert_type: Option<String>,
    pub skip_xss_scanning: Option<bool>,
    pub max_payloads_per_param: Option<usize>,
    pub deep_scan: Option<bool>,
    pub sxss: Option<bool>,
    pub sxss_url: Option<String>,
    pub sxss_method: Option<String>,
    pub sxss_retries: Option<u32>,
    pub skip_ast_analysis: Option<bool>,
    pub analyze_external_js: Option<bool>,
    pub detect_outdated_libs: Option<bool>,
    // HPP
    pub hpp: Option<bool>,
    // WAF
    pub waf_bypass: Option<String>,
    pub skip_waf_probe: Option<bool>,
    pub force_waf: Option<String>,
    pub waf_evasion: Option<bool>,
    pub waf_min_confidence: Option<f32>,
    // LOGGING/DEBUG
    pub debug: Option<bool>,
}

impl Config {
    // Apply this configuration to ScanArgs. This unconditionally overwrites the fields present
    // in the config (Option::Some). Callers should control precedence by calling this either
    // before or after applying CLI args.
    pub fn apply_to_scan_args(&self, args: &mut crate::cmd::scan::ScanArgs) {
        if let Some(scan) = &self.scan {
            // INPUT
            if let Some(v) = &scan.input_type {
                args.input_type = v.clone();
            }
            // OUTPUT
            if let Some(v) = &scan.format {
                args.format = v.clone();
            }
            if let Some(v) = &scan.output {
                args.output = Some(v.clone());
            }
            if let Some(v) = scan.include_request {
                args.include_request = v;
            }
            if let Some(v) = scan.include_response {
                args.include_response = v;
            }
            if let Some(v) = scan.include_all {
                args.include_all = v;
            }
            if let Some(v) = scan.silence {
                args.silence = v;
            }
            if let Some(v) = scan.dry_run {
                args.dry_run = v;
            }
            if let Some(v) = scan.stream_findings {
                args.stream_findings = v;
            }
            if let Some(v) = &scan.poc_type {
                args.poc_type = v.clone();
            }
            if let Some(v) = scan.limit {
                args.limit = Some(v);
            }
            if let Some(v) = &scan.limit_result_type {
                args.limit_result_type = v.clone();
            }
            if let Some(v) = &scan.only_poc {
                args.only_poc = v.clone();
            }
            if let Some(v) = scan.no_color {
                args.no_color = v;
            }
            // TARGETS
            if let Some(v) = &scan.param {
                args.param = v.clone();
            }
            if let Some(v) = &scan.data {
                args.data = Some(v.clone());
            }
            if let Some(v) = &scan.headers {
                args.headers = v.clone();
            }
            if let Some(v) = &scan.cookies {
                args.cookies = v.clone();
            }
            if let Some(v) = &scan.method {
                args.method = v.clone();
            }
            if let Some(v) = &scan.user_agent {
                args.user_agent = Some(v.clone());
            }
            if let Some(v) = &scan.cookie_from_raw {
                args.cookie_from_raw = Some(v.clone());
            }
            // SCOPE
            if let Some(v) = &scan.include_url {
                args.include_url = v.clone();
            }
            if let Some(v) = &scan.exclude_url {
                args.exclude_url = v.clone();
            }
            if let Some(v) = &scan.ignore_param {
                args.ignore_param = v.clone();
            }
            if let Some(v) = &scan.out_of_scope {
                args.out_of_scope = v.clone();
            }
            if let Some(v) = &scan.out_of_scope_file {
                args.out_of_scope_file = Some(v.clone());
            }
            // PARAMETER DISCOVERY
            if let Some(v) = scan.only_discovery {
                args.only_discovery = v;
            }
            if let Some(v) = scan.skip_discovery {
                args.skip_discovery = v;
            }
            if let Some(v) = scan.skip_reflection_header {
                args.skip_reflection_header = v;
            }
            if let Some(v) = scan.skip_reflection_cookie {
                args.skip_reflection_cookie = v;
            }
            if let Some(v) = scan.skip_reflection_path {
                args.skip_reflection_path = v;
            }
            // PARAMETER MINING
            if let Some(v) = &scan.mining_dict_word {
                args.mining_dict_word = Some(v.clone());
            }
            if let Some(v) = &scan.remote_wordlists {
                args.remote_wordlists = v.clone();
            }
            if let Some(v) = scan.skip_mining {
                args.skip_mining = v;
            }
            if let Some(v) = scan.skip_mining_dict {
                args.skip_mining_dict = v;
            }
            if let Some(v) = scan.skip_mining_dom {
                args.skip_mining_dom = v;
            }
            // NETWORK
            if let Some(v) = scan.timeout {
                args.timeout = v;
            }
            if let Some(v) = scan.scan_timeout {
                args.scan_timeout = v;
            }
            if let Some(v) = scan.delay {
                args.delay = v;
            }
            if let Some(v) = scan.rate_limit {
                args.rate_limit = v;
            }
            if let Some(v) = scan.retries {
                args.retries = v;
            }
            if let Some(v) = scan.retry_delay {
                args.retry_delay = v;
            }
            if let Some(v) = &scan.proxy {
                args.proxy = Some(v.clone());
            }
            if let Some(v) = scan.insecure {
                args.insecure = Some(v);
            }
            if let Some(v) = scan.follow_redirects {
                args.follow_redirects = v;
            }
            if let Some(v) = &scan.ignore_return {
                args.ignore_return = v.clone();
            }
            // ENGINE
            if let Some(v) = scan.workers {
                args.workers = v;
            }
            if let Some(v) = scan.max_concurrent_targets {
                args.max_concurrent_targets = v;
            }
            if let Some(v) = scan.max_targets_per_host {
                args.max_targets_per_host = v;
            }
            // XSS SCANNING
            if let Some(v) = &scan.encoders {
                args.encoders = v.clone();
            }
            if let Some(v) = &scan.remote_payloads {
                args.remote_payloads = v.clone();
            }
            if let Some(v) = &scan.custom_blind_xss_payload {
                args.custom_blind_xss_payload = Some(v.clone());
            }
            if let Some(v) = &scan.blind_callback_url {
                args.blind_callback_url = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob {
                args.oob.blind_oob = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob_secret {
                args.oob.blind_oob_secret = Some(v.clone());
            }
            if let Some(v) = scan.blind_oob_wait {
                args.oob.blind_oob_wait = Some(v);
            }
            if let Some(v) = &scan.custom_payload {
                args.custom_payload = Some(v.clone());
            }
            if let Some(v) = scan.only_custom_payload {
                args.only_custom_payload = v;
            }
            if let Some(v) = &scan.inject_marker {
                args.inject_marker = Some(v.clone());
            }
            if let Some(v) = &scan.custom_alert_value {
                args.custom_alert_value = v.clone();
            }
            if let Some(v) = &scan.custom_alert_type {
                args.custom_alert_type = v.clone();
            }
            if let Some(v) = scan.skip_xss_scanning {
                args.skip_xss_scanning = v;
            }
            if let Some(v) = scan.max_payloads_per_param {
                args.max_payloads_per_param = v;
            }
            if let Some(v) = scan.deep_scan {
                args.deep_scan = v;
            }
            if let Some(v) = scan.sxss {
                args.sxss = v;
            }
            if let Some(v) = &scan.sxss_url {
                args.sxss_url = Some(v.clone());
            }
            if let Some(v) = &scan.sxss_method {
                args.sxss_method = v.clone();
            }
            if let Some(v) = scan.sxss_retries {
                args.sxss_retries = v;
            }
            if let Some(v) = scan.skip_ast_analysis {
                args.skip_ast_analysis = v;
            }
            if let Some(v) = scan.analyze_external_js {
                args.analyze_external_js = v;
            }
            if let Some(v) = scan.detect_outdated_libs {
                args.detect_outdated_libs = v;
            }
            // HPP
            if let Some(v) = scan.hpp {
                args.hpp = v;
            }
            // WAF
            if let Some(v) = &scan.waf_bypass {
                args.waf_bypass = v.clone();
            }
            if let Some(v) = scan.skip_waf_probe {
                args.skip_waf_probe = v;
            }
            if let Some(v) = &scan.force_waf {
                args.force_waf = Some(v.clone());
            }
            if let Some(v) = scan.waf_evasion {
                args.waf_evasion = v;
            }
            if let Some(v) = scan.waf_min_confidence {
                args.waf_min_confidence = v;
            }
            // NOTE: `debug` is intentionally not applied here. It is a process-
            // global toggle (`crate::DEBUG`), not a `ScanArgs` field, so it is
            // handled only in `apply_to_scan_args_if_default` (the overlay the
            // CLI actually uses). Mirroring it here would mutate global state
            // from a method whose contract is "write ScanArgs fields".
        }
    }

    // Conservative application: only fill Option fields when unset in args.
    // Useful when you want config to fill "holes" but never override already-set fields.
    pub fn apply_to_scan_args_conservative(&self, args: &mut crate::cmd::scan::ScanArgs) {
        if let Some(scan) = &self.scan {
            // OUTPUT
            if let Some(v) = &scan.output
                && args.output.is_none()
            {
                args.output = Some(v.clone());
            }
            if let Some(v) = scan.limit
                && args.limit.is_none()
            {
                args.limit = Some(v);
            }
            if let Some(v) = &scan.limit_result_type
                && args.limit_result_type == "all"
            {
                args.limit_result_type = v.clone();
            }
            if let Some(v) = &scan.only_poc
                && args.only_poc.is_empty()
            {
                args.only_poc = v.clone();
            }
            // TARGETS
            if let Some(v) = &scan.data
                && args.data.is_none()
            {
                args.data = Some(v.clone());
            }
            if let Some(v) = &scan.user_agent
                && args.user_agent.is_none()
            {
                args.user_agent = Some(v.clone());
            }
            if let Some(v) = &scan.cookie_from_raw
                && args.cookie_from_raw.is_none()
            {
                args.cookie_from_raw = Some(v.clone());
            }
            // SCOPE
            if let Some(v) = &scan.include_url
                && args.include_url.is_empty()
            {
                args.include_url = v.clone();
            }
            if let Some(v) = &scan.exclude_url
                && args.exclude_url.is_empty()
            {
                args.exclude_url = v.clone();
            }
            // PARAMETER MINING
            if let Some(v) = &scan.mining_dict_word
                && args.mining_dict_word.is_none()
            {
                args.mining_dict_word = Some(v.clone());
            }
            if let Some(v) = &scan.remote_wordlists
                && args.remote_wordlists.is_empty()
            {
                args.remote_wordlists = v.clone();
            }
            // NETWORK
            if let Some(v) = &scan.proxy
                && args.proxy.is_none()
            {
                args.proxy = Some(v.clone());
            }
            // `insecure` is None unless the user passed --insecure; only fill
            // it from config when the CLI left it unspecified, so an explicit
            // CLI choice (either direction) always wins (mirrors apply_if_default).
            if let Some(v) = scan.insecure
                && args.insecure.is_none()
            {
                args.insecure = Some(v);
            }
            if let Some(v) = scan.scan_timeout
                && args.scan_timeout == 0
            {
                args.scan_timeout = v;
            }
            if let Some(v) = &scan.ignore_return
                && args.ignore_return.is_empty()
            {
                args.ignore_return = v.clone();
            }
            // XSS SCANNING
            if let Some(v) = &scan.custom_blind_xss_payload
                && args.custom_blind_xss_payload.is_none()
            {
                args.custom_blind_xss_payload = Some(v.clone());
            }
            if let Some(v) = &scan.blind_callback_url
                && args.blind_callback_url.is_none()
            {
                args.blind_callback_url = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob
                && args.oob.blind_oob.is_none()
            {
                args.oob.blind_oob = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob_secret
                && args.oob.blind_oob_secret.is_none()
            {
                args.oob.blind_oob_secret = Some(v.clone());
            }
            if let Some(v) = scan.blind_oob_wait
                && args.oob.blind_oob_wait.is_none()
            {
                args.oob.blind_oob_wait = Some(v);
            }
            if let Some(v) = &scan.custom_payload
                && args.custom_payload.is_none()
            {
                args.custom_payload = Some(v.clone());
            }
            if let Some(v) = &scan.remote_payloads
                && args.remote_payloads.is_empty()
            {
                args.remote_payloads = v.clone();
            }
            if let Some(v) = &scan.sxss_url
                && args.sxss_url.is_none()
            {
                args.sxss_url = Some(v.clone());
            }
            if let Some(v) = scan.sxss_retries
                && args.sxss_retries == 3
            {
                args.sxss_retries = v;
            }
            // PARAMETER DISCOVERY (conservative mapping)
            if let Some(v) = scan.skip_reflection_path
                && !args.skip_reflection_path
            {
                args.skip_reflection_path = v;
            }
        }
    }

    // Apply config only when current args fields equal clap default values (from clap on ScanArgs).
    // This lets CLI-specified values win while config populates defaults.
    pub fn apply_to_scan_args_if_default(&self, args: &mut crate::cmd::scan::ScanArgs) {
        if let Some(scan) = &self.scan {
            // INPUT
            if let Some(v) = &scan.input_type
                && args.input_type == "auto"
            {
                args.input_type = v.clone();
            }

            // OUTPUT
            if let Some(v) = &scan.format
                && args.format == "plain"
            {
                args.format = v.clone();
            }
            if let Some(v) = &scan.output
                && args.output.is_none()
            {
                args.output = Some(v.clone());
            }
            if let Some(v) = scan.include_request
                && !args.include_request
            {
                args.include_request = v;
            }
            if let Some(v) = scan.include_response
                && !args.include_response
            {
                args.include_response = v;
            }
            if let Some(v) = scan.include_all
                && !args.include_all
            {
                args.include_all = v;
            }
            if let Some(v) = scan.silence
                && !args.silence
            {
                args.silence = v;
            }
            if let Some(v) = scan.dry_run
                && !args.dry_run
            {
                args.dry_run = v;
            }
            if let Some(v) = scan.stream_findings
                && !args.stream_findings
            {
                args.stream_findings = v;
            }
            if let Some(v) = &scan.poc_type
                && args.poc_type == "plain"
            {
                args.poc_type = v.clone();
            }
            if let Some(v) = scan.limit
                && args.limit.is_none()
            {
                args.limit = Some(v);
            }
            if let Some(v) = &scan.limit_result_type
                && args.limit_result_type == "all"
            {
                args.limit_result_type = v.clone();
            }
            if let Some(v) = &scan.only_poc
                && args.only_poc.is_empty()
            {
                args.only_poc = v.clone();
            }
            if let Some(v) = scan.no_color
                && !args.no_color
            {
                args.no_color = v;
            }
            // Map debug conservatively: only set when CLI didn't enable it (global false)
            if let Some(v) = scan.debug
                && !crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed)
            {
                crate::DEBUG.store(v, std::sync::atomic::Ordering::Relaxed);
            }

            // TARGETS
            if let Some(v) = &scan.param
                && args.param.is_empty()
            {
                args.param = v.clone();
            }
            if let Some(v) = &scan.data
                && args.data.is_none()
            {
                args.data = Some(v.clone());
            }
            if let Some(v) = &scan.headers
                && args.headers.is_empty()
            {
                args.headers = v.clone();
            }
            if let Some(v) = &scan.cookies
                && args.cookies.is_empty()
            {
                args.cookies = v.clone();
            }
            if let Some(v) = &scan.method
                && args.method == "GET"
            {
                args.method = v.clone();
            }
            if let Some(v) = &scan.user_agent
                && args.user_agent.is_none()
            {
                args.user_agent = Some(v.clone());
            }
            // PARAMETER DISCOVERY (default mapping)
            if let Some(v) = scan.skip_reflection_path
                && !args.skip_reflection_path
            {
                args.skip_reflection_path = v;
            }
            if let Some(v) = &scan.cookie_from_raw
                && args.cookie_from_raw.is_none()
            {
                args.cookie_from_raw = Some(v.clone());
            }

            // SCOPE (if_default)
            if let Some(v) = &scan.include_url
                && args.include_url.is_empty()
            {
                args.include_url = v.clone();
            }
            if let Some(v) = &scan.exclude_url
                && args.exclude_url.is_empty()
            {
                args.exclude_url = v.clone();
            }
            if let Some(v) = &scan.ignore_param
                && args.ignore_param.is_empty()
            {
                args.ignore_param = v.clone();
            }
            if let Some(v) = &scan.out_of_scope
                && args.out_of_scope.is_empty()
            {
                args.out_of_scope = v.clone();
            }
            if let Some(v) = &scan.out_of_scope_file
                && args.out_of_scope_file.is_none()
            {
                args.out_of_scope_file = Some(v.clone());
            }

            // PARAMETER DISCOVERY
            if let Some(v) = scan.only_discovery
                && !args.only_discovery
            {
                args.only_discovery = v;
            }
            if let Some(v) = scan.skip_discovery
                && !args.skip_discovery
            {
                args.skip_discovery = v;
            }
            if let Some(v) = scan.skip_reflection_header
                && !args.skip_reflection_header
            {
                args.skip_reflection_header = v;
            }
            if let Some(v) = scan.skip_reflection_cookie
                && !args.skip_reflection_cookie
            {
                args.skip_reflection_cookie = v;
            }

            // PARAMETER MINING
            if let Some(v) = &scan.mining_dict_word
                && args.mining_dict_word.is_none()
            {
                args.mining_dict_word = Some(v.clone());
            }
            if let Some(v) = &scan.remote_wordlists
                && args.remote_wordlists.is_empty()
            {
                args.remote_wordlists = v.clone();
            }
            if let Some(v) = scan.skip_mining
                && !args.skip_mining
            {
                args.skip_mining = v;
            }
            if let Some(v) = scan.skip_mining_dict
                && !args.skip_mining_dict
            {
                args.skip_mining_dict = v;
            }
            if let Some(v) = scan.skip_mining_dom
                && !args.skip_mining_dom
            {
                args.skip_mining_dom = v;
            }

            // NETWORK
            if let Some(v) = scan.timeout
                && args.timeout == crate::cmd::scan::DEFAULT_TIMEOUT_SECS
            {
                args.timeout = v;
            }
            if let Some(v) = scan.scan_timeout
                && args.scan_timeout == 0
            {
                args.scan_timeout = v;
            }
            if let Some(v) = scan.delay
                && args.delay == crate::cmd::scan::DEFAULT_DELAY_MS
            {
                args.delay = v;
            }
            if let Some(v) = scan.rate_limit
                && args.rate_limit == crate::cmd::scan::DEFAULT_RATE_LIMIT
            {
                args.rate_limit = v;
            }
            if let Some(v) = scan.retries
                && args.retries == crate::cmd::scan::DEFAULT_RETRIES
            {
                args.retries = v;
            }
            if let Some(v) = scan.retry_delay
                && args.retry_delay == crate::cmd::scan::DEFAULT_RETRY_DELAY_MS
            {
                args.retry_delay = v;
            }
            if let Some(v) = &scan.proxy
                && args.proxy.is_none()
            {
                args.proxy = Some(v.clone());
            }
            // `insecure` is `None` unless the user passed `--insecure[=…]`, so
            // config only applies when the flag was left off. An explicit CLI
            // value — `--insecure=true` *or* `--insecure=false` — is `Some(_)`
            // and therefore always wins over the config file, in either
            // direction. (A plain `bool` couldn't express this: it can't tell
            // an explicit `--insecure=true` apart from the default.)
            if let Some(v) = scan.insecure
                && args.insecure.is_none()
            {
                args.insecure = Some(v);
            }
            if let Some(v) = scan.follow_redirects
                && !args.follow_redirects
            {
                args.follow_redirects = v;
            }
            if let Some(v) = &scan.ignore_return
                && args.ignore_return.is_empty()
            {
                args.ignore_return = v.clone();
            }

            // ENGINE
            if let Some(v) = scan.workers
                && args.workers == crate::cmd::scan::DEFAULT_WORKERS
            {
                args.workers = v;
            }
            if let Some(v) = scan.max_concurrent_targets
                && args.max_concurrent_targets == crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS
            {
                args.max_concurrent_targets = v;
            }
            if let Some(v) = scan.max_targets_per_host
                && args.max_targets_per_host == crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST
            {
                args.max_targets_per_host = v;
            }

            // XSS SCANNING
            if let Some(v) = &scan.encoders {
                // Override only if current encoders equal the canonical defaults (user did not supply CLI override).
                // Canonical defaults are defined in cmd::scan::DEFAULT_ENCODERS (["url","html"]).
                if args.encoders.iter().map(String::as_str).collect::<Vec<_>>()
                    == crate::cmd::scan::DEFAULT_ENCODERS
                {
                    args.encoders = v.clone();
                }
            }
            if let Some(v) = &scan.remote_payloads
                && args.remote_payloads.is_empty()
            {
                args.remote_payloads = v.clone();
            }
            if let Some(v) = &scan.custom_blind_xss_payload
                && args.custom_blind_xss_payload.is_none()
            {
                args.custom_blind_xss_payload = Some(v.clone());
            }
            if let Some(v) = &scan.blind_callback_url
                && args.blind_callback_url.is_none()
            {
                args.blind_callback_url = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob
                && args.oob.blind_oob.is_none()
            {
                args.oob.blind_oob = Some(v.clone());
            }
            if let Some(v) = &scan.blind_oob_secret
                && args.oob.blind_oob_secret.is_none()
            {
                args.oob.blind_oob_secret = Some(v.clone());
            }
            if let Some(v) = scan.blind_oob_wait
                && args.oob.blind_oob_wait.is_none()
            {
                args.oob.blind_oob_wait = Some(v);
            }
            if let Some(v) = &scan.custom_payload
                && args.custom_payload.is_none()
            {
                args.custom_payload = Some(v.clone());
            }
            if let Some(v) = scan.only_custom_payload
                && !args.only_custom_payload
            {
                args.only_custom_payload = v;
            }
            if let Some(v) = &scan.inject_marker
                && args.inject_marker.is_none()
            {
                args.inject_marker = Some(v.clone());
            }
            if let Some(v) = &scan.custom_alert_value
                && args.custom_alert_value == "1"
            {
                args.custom_alert_value = v.clone();
            }
            if let Some(v) = &scan.custom_alert_type
                && args.custom_alert_type == "none"
            {
                args.custom_alert_type = v.clone();
            }
            if let Some(v) = scan.skip_xss_scanning
                && !args.skip_xss_scanning
            {
                args.skip_xss_scanning = v;
            }
            if let Some(v) = scan.max_payloads_per_param
                && args.max_payloads_per_param == 0
            {
                args.max_payloads_per_param = v;
            }
            if let Some(v) = scan.deep_scan
                && !args.deep_scan
            {
                args.deep_scan = v;
            }
            if let Some(v) = scan.sxss
                && !args.sxss
            {
                args.sxss = v;
            }
            if let Some(v) = &scan.sxss_url
                && args.sxss_url.is_none()
            {
                args.sxss_url = Some(v.clone());
            }
            if let Some(v) = &scan.sxss_method
                && args.sxss_method == "GET"
            {
                args.sxss_method = v.clone();
            }
            if let Some(v) = scan.sxss_retries
                && args.sxss_retries == 3
            {
                args.sxss_retries = v;
            }
            if let Some(v) = scan.skip_ast_analysis
                && !args.skip_ast_analysis
            {
                args.skip_ast_analysis = v;
            }
            if let Some(v) = scan.analyze_external_js
                && !args.analyze_external_js
            {
                args.analyze_external_js = v;
            }
            if let Some(v) = scan.detect_outdated_libs
                && !args.detect_outdated_libs
            {
                args.detect_outdated_libs = v;
            }
            if let Some(v) = scan.hpp
                && !args.hpp
            {
                args.hpp = v;
            }
            // WAF
            if let Some(v) = &scan.waf_bypass
                && args.waf_bypass == "auto"
            {
                args.waf_bypass = v.clone();
            }
            if let Some(v) = scan.skip_waf_probe
                && !args.skip_waf_probe
            {
                args.skip_waf_probe = v;
            }
            if let Some(v) = &scan.force_waf
                && args.force_waf.is_none()
            {
                args.force_waf = Some(v.clone());
            }
            if let Some(v) = scan.waf_evasion
                && !args.waf_evasion
            {
                args.waf_evasion = v;
            }
            // Only override when the CLI was left at the default (0.3)
            // — same precedence pattern as the other numeric overrides
            // so users who pass --waf-min-confidence on the command
            // line keep authority over what the config file says.
            if let Some(v) = scan.waf_min_confidence
                && (args.waf_min_confidence - crate::cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE).abs()
                    < f32::EPSILON
            {
                args.waf_min_confidence = v;
            }
        }
    }

    /// Normalize and validate config values that the CLI would otherwise
    /// normalize or reject through clap value-parsers. See
    /// [`ScanConfig::normalize_and_validate`]; returns human-readable warnings
    /// for the caller to surface (empty when the config is clean).
    pub fn normalize_and_validate(&mut self) -> Vec<String> {
        match self.scan.as_mut() {
            Some(scan) => scan.normalize_and_validate(),
            None => Vec::new(),
        }
    }
}

/// Reset `field` to `None` (falling back to the built-in default) and record a
/// warning when its value is not one of `allowed`. Mirrors clap's
/// `PossibleValuesParser` for the config-file path, which bypasses clap.
fn reject_unless_allowed(
    field: &mut Option<String>,
    allowed: &[&str],
    name: &str,
    warnings: &mut Vec<String>,
) {
    if let Some(v) = field
        && !allowed.contains(&v.as_str())
    {
        warnings.push(format!(
            "config {name}: '{v}' is not a valid value (expected one of: {}); ignoring",
            allowed.join(", ")
        ));
        *field = None;
    }
}

/// List variant of [`reject_unless_allowed`]: if any element is invalid, drop
/// the whole list back to `None` (a partially-applied list would be surprising)
/// and warn, naming the offending values.
fn reject_list_unless_allowed(
    field: &mut Option<Vec<String>>,
    allowed: &[&str],
    name: &str,
    warnings: &mut Vec<String>,
) {
    if let Some(list) = field {
        let invalid: Vec<String> = list
            .iter()
            .filter(|v| !allowed.contains(&v.as_str()))
            .cloned()
            .collect();
        if !invalid.is_empty() {
            warnings.push(format!(
                "config {name}: invalid value(s) [{}] (expected each of: {}); ignoring",
                invalid.join(", "),
                allowed.join(", ")
            ));
            *field = None;
        }
    }
}

impl ScanConfig {
    /// Normalize and validate the free-form string / numeric fields that the
    /// CLI would otherwise route through clap value-parsers (`--format`,
    /// `--method`, `--limit`, …). A config file is deserialized straight into
    /// this struct and never sees clap, so without this pass an invalid value
    /// is copied verbatim into [`crate::cmd::scan::ScanArgs`] and silently
    /// misbehaves — a lowercase `method = "post"` breaks the `== "POST"`
    /// comparisons that drive discovery, `format = "xml"` falls through to a
    /// degraded output writer, and `limit = 0` resurrects the old "show no
    /// findings" behavior clap now rejects outright.
    ///
    /// Each invalid field is reset to `None` so it falls back to the built-in
    /// default instead of corrupting the scan, and a human-readable warning is
    /// returned for the caller to surface (empty vec == clean). `method` and
    /// `force_waf` are additionally normalized in place (upper / lower-cased)
    /// exactly as their CLI parsers do, so a valid-but-differently-cased value
    /// is accepted rather than dropped.
    pub fn normalize_and_validate(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();

        // `method` — uppercase + validate, mirroring `--method`'s parser so a
        // config `method = "post"` becomes "POST" instead of silently breaking
        // the case-sensitive method comparisons downstream.
        if let Some(m) = &self.method {
            match crate::cmd::scan::parse_http_method_arg(m) {
                Ok(upper) => self.method = Some(upper),
                Err(e) => {
                    warnings.push(format!("config scan.method: {e}; ignoring"));
                    self.method = None;
                }
            }
        }

        // `force_waf` — lowercase + validate against the known WAF aliases,
        // mirroring `--force-waf`'s parser so a typo doesn't fall into the
        // silent `WafType::Unknown` bucket that skips targeted bypasses.
        if let Some(w) = &self.force_waf {
            match crate::cmd::scan::parse_force_waf_arg(w) {
                Ok(lower) => self.force_waf = Some(lower),
                Err(e) => {
                    warnings.push(format!("config scan.force_waf: {e}; ignoring"));
                    self.force_waf = None;
                }
            }
        }

        // Single-value enum fields validated against clap's possible values.
        reject_unless_allowed(
            &mut self.format,
            crate::cmd::scan::FORMAT_VALUES,
            "scan.format",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.poc_type,
            crate::cmd::scan::POC_TYPE_VALUES,
            "scan.poc_type",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.limit_result_type,
            crate::cmd::scan::LIMIT_RESULT_TYPE_VALUES,
            "scan.limit_result_type",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.custom_alert_type,
            crate::cmd::scan::CUSTOM_ALERT_TYPE_VALUES,
            "scan.custom_alert_type",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.waf_bypass,
            crate::cmd::scan::WAF_BYPASS_VALUES,
            "scan.waf_bypass",
            &mut warnings,
        );

        // Comma-delimited enum list fields.
        reject_list_unless_allowed(
            &mut self.only_poc,
            crate::cmd::scan::ONLY_POC_VALUES,
            "scan.only_poc",
            &mut warnings,
        );
        reject_list_unless_allowed(
            &mut self.encoders,
            crate::cmd::scan::ENCODER_VALUES,
            "scan.encoders",
            &mut warnings,
        );

        // `limit` — clap rejects `--limit 0` ("omit the flag entirely for no
        // cap"); a config `limit = 0` used to mean "show no findings". Treat it
        // as unset (no cap) with a warning so the meaning stays unambiguous.
        if self.limit == Some(0) {
            warnings.push(
                "config scan.limit: 0 is not a valid cap (omit it for no cap); ignoring"
                    .to_string(),
            );
            self.limit = None;
        }

        warnings
    }
}

// Load configuration with the following behavior:
// - If $XDG_CONFIG_HOME is set and non-empty, use "$XDG_CONFIG_HOME/dalfox"
// - Otherwise, use "$HOME/.config/dalfox"
// - Within the selected base directory, prefer "config.toml" over "config.json"
// - If neither file exists, create "config.toml" with a commented template and return it as created
/// Upper bound on the size of a config file we will read into memory. Config
/// files are tiny in practice; the cap exists so a config path that resolves to
/// a huge / unbounded file (e.g. a symlink to `/dev/zero`) fails fast instead of
/// slurping unboundedly, keeping config loading consistent with every other
/// input surface. Shared with the `--config` CLI path in `main`.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20; // 1 MiB

pub fn load_or_init() -> Result<LoadResult, Box<dyn std::error::Error>> {
    let base_dir = resolve_config_dir()?;
    fs::create_dir_all(&base_dir)?;

    let toml_path = base_dir.join("config.toml");
    let json_path = base_dir.join("config.json");

    if toml_path.exists() {
        let s = crate::utils::fs::read_bounded(&toml_path, MAX_CONFIG_BYTES, "config file")?;
        let cfg: Config = toml::from_str(&s)?;
        return Ok(LoadResult {
            config: cfg,
            path: toml_path,
            format: ConfigFormat::Toml,
            created: false,
        });
    }

    if json_path.exists() {
        let s = crate::utils::fs::read_bounded(&json_path, MAX_CONFIG_BYTES, "config file")?;
        let cfg: Config = serde_json::from_str(&s)?;
        return Ok(LoadResult {
            config: cfg,
            path: json_path,
            format: ConfigFormat::Json,
            created: false,
        });
    }

    // Neither exists: create TOML by default
    let template = default_toml_template();
    {
        let mut f = fs::File::create(&toml_path)?;
        f.write_all(template.as_bytes())?;
        f.sync_all()?;
    }
    // Load the template back as Config (will parse to defaults)
    let cfg: Config = toml::from_str(&template)?;
    Ok(LoadResult {
        config: cfg,
        path: toml_path,
        format: ConfigFormat::Toml,
        created: true,
    })
}

// Resolve the configuration directory:
// - $XDG_CONFIG_HOME/dalfox if XDG_CONFIG_HOME is set
// - else $HOME/.config/dalfox
pub fn resolve_config_dir() -> Result<PathBuf, io::Error> {
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME")
        && !xdg.trim().is_empty()
    {
        return Ok(Path::new(&xdg).join("dalfox"));
    }
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("HOME/USERPROFILE not set: {e}"),
            )
        })?;
    Ok(Path::new(&home).join(".config").join("dalfox"))
}

// Save a config back to disk in the detected format.
pub fn save(
    config: &Config,
    path: &Path,
    format: ConfigFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        ConfigFormat::Toml => {
            let s = toml::to_string_pretty(config)?;
            fs::write(path, s)?;
        }
        ConfigFormat::Json => {
            let s = serde_json::to_string_pretty(config)?;
            fs::write(path, s)?;
        }
    }
    Ok(())
}

// Generate a commented TOML template with most flags represented for pre-configuration.
pub fn default_toml_template() -> String {
    let tpl = r#"# Dalfox configuration (TOML)
# Docs: https://github.com/hahwul/dalfox
# Predefine most flags here. CLI flags can override these at runtime.

[scan]
# INPUT
# input_type = "auto"        # auto, url, file, pipe, raw-http (parses raw HTTP request file or literal), har (HAR / proxy export)

# OUTPUT
# format = "plain"           # plain, json, jsonl, markdown, sarif, toml
# output = "output.txt"
# include_request = false
# include_response = false
# include_all = false          # shorthand for include_request + include_response
# silence = false
# debug = false              # enable debug logging (DBG lines)
# stream_findings = false    # emit findings mid-scan instead of after `WRN XSS found N XSS` (plain format only)
# poc_type = "plain"         # plain, curl, httpie, http-request
# limit = 100

# TARGETS
# param = ["id", "q:query", "auth:header"]
# data = "param=value"
# headers = ["X-Header: value", "Authorization: Bearer ..."]
# cookies = ["a=1", "b=2"]
# method = "GET"
# user_agent = "Dalfox/3"
# cookie_from_raw = "request.txt"

# SCOPE
# include_url = []
# exclude_url = []

# PARAMETER DISCOVERY
# skip_discovery = false
# skip_reflection_header = false
# skip_reflection_cookie = false

# PARAMETER MINING
# mining_dict_word = "wordlist.txt"
# remote_wordlists = ["burp", "assetnote"]
# skip_mining = false
# skip_mining_dict = false
# skip_mining_dom = false

# NETWORK
# timeout = 10               # seconds (applies to HTTP requests and remote provider fetches)
# scan_timeout = 0           # hard wall-clock cap per target for the scan stage in seconds
# delay = 0                  # milliseconds
# proxy = "http://127.0.0.1:8080"  # also used for remote provider fetches
# insecure = true            # skip TLS certificate verification (default true); set false to enforce validation
# follow_redirects = false

# ENGINE
# workers = 50
# max_concurrent_targets = 50
# max_targets_per_host = 100

# XSS SCANNING
# encoders = ["url", "html"]  # none, url, 2url, 3url, 4url, html, base64
# remote_payloads = ["payloadbox", "portswigger"]
# custom_blind_xss_payload = "blind.txt"
# blind_callback_url = "https://your-bxss-callback.com"
# blind_oob = ["oast.fun", "oast.me"]   # OOB/OAST via interactsh; [] = default public servers
# blind_oob_secret = "token"            # auth token for a self-hosted interactsh server
# blind_oob_wait = 30                   # seconds to keep polling for callbacks after the scan
# custom_payload = "payloads.txt"
# only_custom_payload = false
# skip_xss_scanning = false
# max_payloads_per_param = 0  # cap payloads per param (0 = unlimited)
# deep_scan = false
# sxss = false
# sxss_url = "https://target/echo"
# sxss_method = "GET"
# sxss_retries = 3
# skip_ast_analysis = false
# analyze_external_js = false
# detect_outdated_libs = false

# HPP
# hpp = false                 # test HTTP Parameter Pollution

# WAF
# waf_bypass = "auto"         # auto, force, off
# skip_waf_probe = false
# force_waf = "cloudflare"    # skip detection and target a specific WAF's bypasses
# waf_evasion = false
# waf_min_confidence = 0.3    # 0.0..=1.0 floor for WAF fingerprint confidence
"#;
    tpl.to_string()
}

// Optional helpers for JSON (rarely used because TOML is preferred)
pub fn default_json_template() -> String {
    let obj = serde_json::json!({
        "scan": serde_json::Value::Object(serde_json::Map::new())
    });
    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{\n  \"scan\": {}\n}".to_string())
}

#[cfg(test)]
mod tests;
