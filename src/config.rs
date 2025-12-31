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
    pub silence: Option<bool>,
    pub poc_type: Option<String>,
    pub limit: Option<usize>,
    // TARGETS
    pub param: Option<Vec<String>>,
    pub data: Option<String>,
    pub headers: Option<Vec<String>>,
    pub cookies: Option<Vec<String>>,
    pub method: Option<String>,
    pub user_agent: Option<String>,
    pub cookie_from_raw: Option<String>,
    // PARAMETER DISCOVERY
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
    pub delay: Option<u64>,
    pub proxy: Option<String>,
    pub follow_redirects: Option<bool>,
    // ENGINE
    pub workers: Option<usize>,
    pub max_concurrent_targets: Option<usize>,
    pub max_targets_per_host: Option<usize>,
    // XSS SCANNING
    pub encoders: Option<Vec<String>>,
    pub remote_payloads: Option<Vec<String>>,
    pub custom_blind_xss_payload: Option<String>,
    pub blind_callback_url: Option<String>,
    pub custom_payload: Option<String>,
    pub only_custom_payload: Option<bool>,
    pub skip_xss_scanning: Option<bool>,
    pub deep_scan: Option<bool>,
    pub sxss: Option<bool>,
    pub sxss_url: Option<String>,
    pub sxss_method: Option<String>,
    pub skip_ast_analysis: Option<bool>,
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
            if let Some(v) = scan.silence {
                args.silence = v;
            }
            if let Some(v) = &scan.poc_type {
                args.poc_type = v.clone();
            }
            if let Some(v) = scan.limit {
                args.limit = Some(v);
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
            // PARAMETER DISCOVERY
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
            if let Some(v) = scan.delay {
                args.delay = v;
            }
            if let Some(v) = &scan.proxy {
                args.proxy = Some(v.clone());
            }
            if let Some(v) = scan.follow_redirects {
                args.follow_redirects = v;
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
            if let Some(v) = &scan.custom_payload {
                args.custom_payload = Some(v.clone());
            }
            if let Some(v) = scan.only_custom_payload {
                args.only_custom_payload = v;
            }
            if let Some(v) = scan.skip_xss_scanning {
                args.skip_xss_scanning = v;
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
        }
    }

    // Conservative application: only fill Option fields when unset in args.
    // Useful when you want config to fill "holes" but never override already-set fields.
    pub fn apply_to_scan_args_conservative(&self, args: &mut crate::cmd::scan::ScanArgs) {
        if let Some(scan) = &self.scan {
            // OUTPUT
            if let Some(v) = &scan.output
                && args.output.is_none() {
                    args.output = Some(v.clone());
                }
            if let Some(v) = scan.limit
                && args.limit.is_none() {
                    args.limit = Some(v);
                }
            // TARGETS
            if let Some(v) = &scan.data
                && args.data.is_none() {
                    args.data = Some(v.clone());
                }
            if let Some(v) = &scan.user_agent
                && args.user_agent.is_none() {
                    args.user_agent = Some(v.clone());
                }
            if let Some(v) = &scan.cookie_from_raw
                && args.cookie_from_raw.is_none() {
                    args.cookie_from_raw = Some(v.clone());
                }
            // PARAMETER MINING
            if let Some(v) = &scan.mining_dict_word
                && args.mining_dict_word.is_none() {
                    args.mining_dict_word = Some(v.clone());
                }
            if let Some(v) = &scan.remote_wordlists
                && args.remote_wordlists.is_empty() {
                    args.remote_wordlists = v.clone();
                }
            // NETWORK
            if let Some(v) = &scan.proxy
                && args.proxy.is_none() {
                    args.proxy = Some(v.clone());
                }
            // XSS SCANNING
            if let Some(v) = &scan.custom_blind_xss_payload
                && args.custom_blind_xss_payload.is_none() {
                    args.custom_blind_xss_payload = Some(v.clone());
                }
            if let Some(v) = &scan.blind_callback_url
                && args.blind_callback_url.is_none() {
                    args.blind_callback_url = Some(v.clone());
                }
            if let Some(v) = &scan.custom_payload
                && args.custom_payload.is_none() {
                    args.custom_payload = Some(v.clone());
                }
            if let Some(v) = &scan.remote_payloads
                && args.remote_payloads.is_empty() {
                    args.remote_payloads = v.clone();
                }
            if let Some(v) = &scan.sxss_url
                && args.sxss_url.is_none() {
                    args.sxss_url = Some(v.clone());
                }
            // PARAMETER DISCOVERY (conservative mapping)
            if let Some(v) = scan.skip_reflection_path
                && !args.skip_reflection_path {
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
                && args.input_type == "auto" {
                    args.input_type = v.clone();
                }

            // OUTPUT
            if let Some(v) = &scan.format
                && args.format == "plain" {
                    args.format = v.clone();
                }
            if let Some(v) = &scan.output
                && args.output.is_none() {
                    args.output = Some(v.clone());
                }
            if let Some(v) = scan.include_request
                && !args.include_request {
                    args.include_request = v;
                }
            if let Some(v) = scan.include_response
                && !args.include_response {
                    args.include_response = v;
                }
            if let Some(v) = scan.silence
                && !args.silence {
                    args.silence = v;
                }
            if let Some(v) = &scan.poc_type
                && args.poc_type == "plain" {
                    args.poc_type = v.clone();
                }
            if let Some(v) = scan.limit
                && args.limit.is_none() {
                    args.limit = Some(v);
                }
            // Map debug conservatively: only set when CLI didn't enable it (global false)
            if let Some(v) = scan.debug
                && !crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    crate::DEBUG.store(v, std::sync::atomic::Ordering::Relaxed);
                }

            // TARGETS
            if let Some(v) = &scan.param
                && args.param.is_empty() {
                    args.param = v.clone();
                }
            if let Some(v) = &scan.data
                && args.data.is_none() {
                    args.data = Some(v.clone());
                }
            if let Some(v) = &scan.headers
                && args.headers.is_empty() {
                    args.headers = v.clone();
                }
            if let Some(v) = &scan.cookies
                && args.cookies.is_empty() {
                    args.cookies = v.clone();
                }
            if let Some(v) = &scan.method
                && args.method == "GET" {
                    args.method = v.clone();
                }
            if let Some(v) = &scan.user_agent
                && args.user_agent.is_none() {
                    args.user_agent = Some(v.clone());
                }
            // PARAMETER DISCOVERY (default mapping)
            if let Some(v) = scan.skip_reflection_path
                && !args.skip_reflection_path {
                    args.skip_reflection_path = v;
                }
            if let Some(v) = &scan.cookie_from_raw
                && args.cookie_from_raw.is_none() {
                    args.cookie_from_raw = Some(v.clone());
                }

            // PARAMETER DISCOVERY
            if let Some(v) = scan.skip_discovery
                && !args.skip_discovery {
                    args.skip_discovery = v;
                }
            if let Some(v) = scan.skip_reflection_header
                && !args.skip_reflection_header {
                    args.skip_reflection_header = v;
                }
            if let Some(v) = scan.skip_reflection_cookie
                && !args.skip_reflection_cookie {
                    args.skip_reflection_cookie = v;
                }

            // PARAMETER MINING
            if let Some(v) = &scan.mining_dict_word
                && args.mining_dict_word.is_none() {
                    args.mining_dict_word = Some(v.clone());
                }
            if let Some(v) = &scan.remote_wordlists
                && args.remote_wordlists.is_empty() {
                    args.remote_wordlists = v.clone();
                }
            if let Some(v) = scan.skip_mining
                && !args.skip_mining {
                    args.skip_mining = v;
                }
            if let Some(v) = scan.skip_mining_dict
                && !args.skip_mining_dict {
                    args.skip_mining_dict = v;
                }
            if let Some(v) = scan.skip_mining_dom
                && !args.skip_mining_dom {
                    args.skip_mining_dom = v;
                }

            // NETWORK
            if let Some(v) = scan.timeout
                && args.timeout == crate::cmd::scan::DEFAULT_TIMEOUT_SECS {
                    args.timeout = v;
                }
            if let Some(v) = scan.delay
                && args.delay == crate::cmd::scan::DEFAULT_DELAY_MS {
                    args.delay = v;
                }
            if let Some(v) = &scan.proxy
                && args.proxy.is_none() {
                    args.proxy = Some(v.clone());
                }
            if let Some(v) = scan.follow_redirects
                && !args.follow_redirects {
                    args.follow_redirects = v;
                }

            // ENGINE
            if let Some(v) = scan.workers
                && args.workers == crate::cmd::scan::DEFAULT_WORKERS {
                    args.workers = v;
                }
            if let Some(v) = scan.max_concurrent_targets
                && args.max_concurrent_targets == crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS {
                    args.max_concurrent_targets = v;
                }
            if let Some(v) = scan.max_targets_per_host
                && args.max_targets_per_host == crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST {
                    args.max_targets_per_host = v;
                }

            // XSS SCANNING
            if let Some(v) = &scan.encoders {
                // Override only if current encoders equal the canonical defaults (user did not supply CLI override).
                // Canonical defaults are defined in cmd::scan::DEFAULT_ENCODERS (["url","html"]).
                if args.encoders.iter().map(|s| s.as_str()).collect::<Vec<_>>()
                    == crate::cmd::scan::DEFAULT_ENCODERS
                {
                    args.encoders = v.clone();
                }
            }
            if let Some(v) = &scan.remote_payloads
                && args.remote_payloads.is_empty() {
                    args.remote_payloads = v.clone();
                }
            if let Some(v) = &scan.custom_blind_xss_payload
                && args.custom_blind_xss_payload.is_none() {
                    args.custom_blind_xss_payload = Some(v.clone());
                }
            if let Some(v) = &scan.blind_callback_url
                && args.blind_callback_url.is_none() {
                    args.blind_callback_url = Some(v.clone());
                }
            if let Some(v) = &scan.custom_payload
                && args.custom_payload.is_none() {
                    args.custom_payload = Some(v.clone());
                }
            if let Some(v) = scan.only_custom_payload
                && !args.only_custom_payload {
                    args.only_custom_payload = v;
                }
            if let Some(v) = scan.skip_xss_scanning
                && !args.skip_xss_scanning {
                    args.skip_xss_scanning = v;
                }
            if let Some(v) = scan.deep_scan
                && !args.deep_scan {
                    args.deep_scan = v;
                }
            if let Some(v) = scan.sxss
                && !args.sxss {
                    args.sxss = v;
                }
            if let Some(v) = &scan.sxss_url
                && args.sxss_url.is_none() {
                    args.sxss_url = Some(v.clone());
                }
            if let Some(v) = &scan.sxss_method
                && args.sxss_method == "GET" {
                    args.sxss_method = v.clone();
                }
            if let Some(v) = scan.skip_ast_analysis
                && !args.skip_ast_analysis {
                    args.skip_ast_analysis = v;
                }
        }
    }
}

// Load configuration with the following behavior:
// - If $XDG_CONFIG_HOME is set and non-empty, use "$XDG_CONFIG_HOME/dalfox"
// - Otherwise, use "$HOME/.config/dalfox"
// - Within the selected base directory, prefer "config.toml" over "config.json"
// - If neither file exists, create "config.toml" with a commented template and return it as created
pub fn load_or_init() -> Result<LoadResult, Box<dyn std::error::Error>> {
    let base_dir = resolve_config_dir()?;
    fs::create_dir_all(&base_dir)?;

    let toml_path = base_dir.join("config.toml");
    let json_path = base_dir.join("config.json");

    if toml_path.exists() {
        let s = fs::read_to_string(&toml_path)?;
        let cfg: Config = toml::from_str(&s)?;
        return Ok(LoadResult {
            config: cfg,
            path: toml_path,
            format: ConfigFormat::Toml,
            created: false,
        });
    }

    if json_path.exists() {
        let s = fs::read_to_string(&json_path)?;
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
        && !xdg.trim().is_empty() {
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
# input_type = "auto"        # auto, url, file, pipe, raw-http (parses raw HTTP request file or literal)

# OUTPUT
# format = "plain"           # json, jsonl, plain
# output = "output.txt"
# include_request = false
# include_response = false
# silence = false
# debug = false              # enable debug logging (DBG lines)
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
# delay = 0                  # milliseconds
# proxy = "http://127.0.0.1:8080"  # also used for remote provider fetches
# follow_redirects = false

# ENGINE
# workers = 50
# max_concurrent_targets = 50
# max_targets_per_host = 100

# XSS SCANNING
# encoders = ["url", "html"]  # none, url, 2url, html, base64
# remote_payloads = ["payloadbox", "portswigger"]
# custom_blind_xss_payload = "blind.txt"
# blind_callback_url = "https://your-bxss-callback.com"
# custom_payload = "payloads.txt"
# only_custom_payload = false
# skip_xss_scanning = false
# deep_scan = false
# sxss = false
# sxss_url = "https://target/echo"
# sxss_method = "GET"
"#;
    tpl.to_string()
}

// Optional helpers for JSON (rarely used because TOML is preferred)
pub fn default_json_template() -> String {
    // Represents the same defaults but as commented JSON is not standard, we include minimal fields.
    let obj = serde_json::json!({
        "scan": serde_json::Value::Object(serde_json::Map::new())
    });
    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{\n  \"scan\": {}\n}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_config_dir_returns_dalfox_path() {
        let dir = resolve_config_dir().expect("should resolve config dir");
        assert!(dir.ends_with("dalfox"));
    }

    #[test]
    fn test_default_toml_parses() {
        let s = default_toml_template();
        let cfg: Config = toml::from_str(&s).expect("template must parse");
        // Empty or partial config is fine; ensure not panicking
        let _ = cfg.scan.as_ref().and_then(|s| s.format.clone());
    }

    #[test]
    fn test_default_json_parses() {
        let s = default_json_template();
        let cfg: Config = serde_json::from_str(&s).expect("json template must parse");
        // Touch a field to avoid unused variable warning
        let _ = cfg.scan.as_ref().and_then(|scan| scan.format.clone());
    }

    #[test]
    fn test_default_numeric_constants_alignment() {
        assert_eq!(crate::cmd::scan::DEFAULT_TIMEOUT_SECS, 10);
        assert_eq!(crate::cmd::scan::DEFAULT_DELAY_MS, 0);
        assert_eq!(crate::cmd::scan::DEFAULT_WORKERS, 50);
        assert_eq!(crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS, 50);
        assert_eq!(crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST, 100);
        // DEFAULT_ENCODERS canonical defaults
        assert_eq!(crate::cmd::scan::DEFAULT_ENCODERS, &["url", "html"]);
    }

    #[test]
    fn test_encoders_override_when_default() {
        // Prepare config with custom encoders
        let cfg = Config {
            scan: Some(ScanConfig {
                encoders: Some(vec![
                    "url".to_string(),
                    "2url".to_string(),
                    "html".to_string(),
                    "base64".to_string(),
                ]),
                ..Default::default()
            }),
        };

        // Prepare ScanArgs with canonical defaults (["url","html"])
        let mut args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "plain".to_string(),
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
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
            delay: crate::cmd::scan::DEFAULT_DELAY_MS,
            proxy: None,
            follow_redirects: false,
            workers: crate::cmd::scan::DEFAULT_WORKERS,
            max_concurrent_targets: crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
            max_targets_per_host: crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
            encoders: crate::cmd::scan::DEFAULT_ENCODERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            remote_payloads: vec![],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            targets: vec![],
        };

        // Apply config only-if-default logic
        cfg.apply_to_scan_args_if_default(&mut args);
        // Expect override to occur
        assert_eq!(
            args.encoders,
            vec!["url", "2url", "html", "base64"],
            "Encoders should be overridden when starting from canonical defaults"
        );
    }

    #[test]
    fn test_encoders_not_override_when_custom_cli() {
        // Config wants to set encoders, but CLI already customized
        let cfg = Config {
            scan: Some(ScanConfig {
                encoders: Some(vec![
                    "url".to_string(),
                    "html".to_string(),
                    "base64".to_string(),
                ]),
                ..Default::default()
            }),
        };

        // CLI provided non-default encoders (e.g., includes 'none')
        let mut args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "plain".to_string(),
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
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
            delay: crate::cmd::scan::DEFAULT_DELAY_MS,
            proxy: None,
            follow_redirects: false,
            workers: crate::cmd::scan::DEFAULT_WORKERS,
            max_concurrent_targets: crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
            max_targets_per_host: crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
            encoders: vec!["none".to_string(), "url".to_string()], // Custom CLI setting
            remote_payloads: vec![],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            targets: vec![],
        };

        cfg.apply_to_scan_args_if_default(&mut args);
        // Should NOT override because starting encoders != canonical defaults
        assert_eq!(
            args.encoders,
            vec!["none", "url"],
            "Encoders should remain as custom CLI-provided set"
        );
    }
}
