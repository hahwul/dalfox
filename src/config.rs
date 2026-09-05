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
    pub dedup_urls: Option<String>,
    /// `--state-file`: path of the resume state file. CLI only — the server /
    /// MCP job model has its own per-job lifecycle and never resumes a
    /// previous process's scan.
    pub state_file: Option<String>,
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
    pub baseline: Option<String>,
    pub baseline_mode: Option<String>,
    pub no_color: Option<bool>,
    // TARGETS
    pub param: Option<Vec<String>>,
    pub data: Option<String>,
    pub headers: Option<Vec<String>>,
    pub cookies: Option<Vec<String>>,
    pub method: Option<String>,
    pub user_agent: Option<String>,
    pub cookie_from_raw: Option<String>,
    // SESSION
    pub session_check: Option<String>,
    pub session_check_url: Option<String>,
    pub on_session_loss: Option<String>,
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

/// Apply one config-file value to a `ScanArgs` field unless the operator
/// already settled it on the command line.
///
/// Each arm names the sentinel that means "the operator said nothing" for that
/// field's shape. Only [`apply_cfg!(explicit …)`](apply_cfg) needs
/// [`ExplicitArgs`](crate::cmd::scan::ExplicitArgs); the others read a value the
/// command line cannot forge — `Option::None`, an empty `Vec`, a `false` flag
/// whose default is `false`.
///
/// Both `explicit` arms derive the `was_explicit` id from the *assigned* field
/// with `stringify!`, so a guard can no longer name a different flag than the
/// one it protects (`!args.was_explicit("poc_type")` in front of
/// `args.format = …` was a real hazard, previously caught only by a test that
/// re-parsed this function's source text).
macro_rules! apply_cfg {
    // A `--flag` whose default is `false`: still `false` means untouched.
    (flag $($cfg:ident).+ => $($arg:ident).+) => {
        if let Some(v) = $($cfg).+
            && !$($arg).+
        {
            $($arg).+ = v;
        }
    };
    // An `Option` field: `None` means untouched. `Copy` value.
    (opt $($cfg:ident).+ => $($arg:ident).+) => {
        if let Some(v) = $($cfg).+
            && $($arg).+.is_none()
        {
            $($arg).+ = Some(v);
        }
    };
    // An `Option` field holding a value that must be cloned.
    (opt_clone $($cfg:ident).+ => $($arg:ident).+) => {
        if let Some(v) = &$($cfg).+
            && $($arg).+.is_none()
        {
            $($arg).+ = Some(v.clone());
        }
    };
    // A `Vec` field: empty means untouched.
    (vec $($cfg:ident).+ => $($arg:ident).+) => {
        if let Some(v) = &$($cfg).+
            && $($arg).+.is_empty()
        {
            $($arg).+ = v.clone();
        }
    };
    // A field whose value cannot carry its own "untouched" sentinel, so the
    // answer comes from clap's `ValueSource`. `Copy` value.
    (explicit $($cfg:ident).+ => $args:ident.$field:ident) => {
        if let Some(v) = $($cfg).+
            && !$args.was_explicit(stringify!($field))
        {
            $args.$field = v;
        }
    };
    // Same, for a value that must be cloned.
    (explicit_clone $($cfg:ident).+ => $args:ident.$field:ident) => {
        if let Some(v) = &$($cfg).+
            && !$args.was_explicit(stringify!($field))
        {
            $args.$field = v.clone();
        }
    };
}

impl Config {
    /// Overlay config-file values onto `args`, filling only what the operator
    /// left alone. Implements `CLI flag > config file > built-in default`.
    ///
    /// **Guard on `!args.was_explicit("<field>")`, never on the field's value.**
    /// A value-comparison guard (`args.workers == DEFAULT_WORKERS`) cannot tell
    /// "untouched" from "typed with the value that happens to be the default",
    /// so it silently lets the config win over `--workers 50` / `--method GET`.
    /// That was the bug across 22 flags; `ExplicitArgs` records the answer from
    /// clap's `ValueSource` instead. `was_explicit` takes the clap argument id,
    /// which is the `ScanArgs` field name.
    ///
    /// The only guards that may key on the value are the ones a command line
    /// cannot forge: `Option::is_none()`, `Vec::is_empty()`, and `!bool` for a
    /// flag whose default is `false` — in each case the sentinel *is*
    /// "the operator said nothing".
    ///
    /// `every_was_explicit_id_is_a_real_clap_argument` in `config::tests` reads
    /// this function's body and fails if an id here does not name a real clap
    /// argument, or does not match the field the same block assigns.
    pub(crate) fn apply_to_scan_args_if_default(&self, args: &mut crate::cmd::scan::ScanArgs) {
        if let Some(scan) = &self.scan {
            // INPUT
            apply_cfg!(explicit_clone scan.input_type => args.input_type);
            apply_cfg!(opt_clone scan.state_file => args.state_file);
            apply_cfg!(opt_clone scan.dedup_urls => args.dedup_urls);

            // OUTPUT
            apply_cfg!(explicit_clone scan.format => args.format);
            apply_cfg!(opt_clone scan.output => args.output);
            apply_cfg!(flag scan.include_request => args.include_request);
            apply_cfg!(flag scan.include_response => args.include_response);
            apply_cfg!(flag scan.include_all => args.include_all);
            apply_cfg!(flag scan.silence => args.silence);
            apply_cfg!(flag scan.dry_run => args.dry_run);
            apply_cfg!(flag scan.stream_findings => args.stream_findings);
            apply_cfg!(explicit_clone scan.poc_type => args.poc_type);
            apply_cfg!(opt scan.limit => args.limit);
            apply_cfg!(explicit_clone scan.limit_result_type => args.limit_result_type);
            apply_cfg!(vec scan.only_poc => args.only_poc);
            apply_cfg!(opt_clone scan.baseline => args.baseline);
            apply_cfg!(opt_clone scan.baseline_mode => args.baseline_mode_arg);
            apply_cfg!(flag scan.no_color => args.no_color);
            // Map debug conservatively: only set when CLI didn't enable it (global false)
            if let Some(v) = scan.debug
                && !crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed)
            {
                crate::DEBUG.store(v, std::sync::atomic::Ordering::Relaxed);
            }

            // TARGETS
            apply_cfg!(vec scan.param => args.param);
            apply_cfg!(opt_clone scan.data => args.data);
            apply_cfg!(vec scan.headers => args.headers);
            apply_cfg!(vec scan.cookies => args.cookies);
            apply_cfg!(explicit_clone scan.method => args.method);
            apply_cfg!(opt_clone scan.user_agent => args.user_agent);
            // PARAMETER DISCOVERY (default mapping)
            apply_cfg!(flag scan.skip_reflection_path => args.skip_reflection_path);
            apply_cfg!(opt_clone scan.cookie_from_raw => args.cookie_from_raw);

            // SESSION (if_default)
            apply_cfg!(opt_clone scan.session_check => args.session_check);
            apply_cfg!(opt_clone scan.session_check_url => args.session_check_url);
            apply_cfg!(opt_clone scan.on_session_loss => args.on_session_loss_arg);

            // SCOPE (if_default)
            apply_cfg!(vec scan.include_url => args.include_url);
            apply_cfg!(vec scan.exclude_url => args.exclude_url);
            apply_cfg!(vec scan.ignore_param => args.ignore_param);
            apply_cfg!(vec scan.out_of_scope => args.out_of_scope);
            apply_cfg!(opt_clone scan.out_of_scope_file => args.out_of_scope_file);

            // PARAMETER DISCOVERY
            apply_cfg!(flag scan.only_discovery => args.only_discovery);
            apply_cfg!(flag scan.skip_discovery => args.skip_discovery);
            apply_cfg!(flag scan.skip_reflection_header => args.skip_reflection_header);
            apply_cfg!(flag scan.skip_reflection_cookie => args.skip_reflection_cookie);

            // PARAMETER MINING
            apply_cfg!(opt_clone scan.mining_dict_word => args.mining_dict_word);
            apply_cfg!(vec scan.remote_wordlists => args.remote_wordlists);
            apply_cfg!(flag scan.skip_mining => args.skip_mining);
            apply_cfg!(flag scan.skip_mining_dict => args.skip_mining_dict);
            apply_cfg!(flag scan.skip_mining_dom => args.skip_mining_dom);

            // NETWORK
            apply_cfg!(explicit scan.timeout => args.timeout);
            apply_cfg!(explicit scan.scan_timeout => args.scan_timeout);
            apply_cfg!(explicit scan.delay => args.delay);
            apply_cfg!(explicit scan.rate_limit => args.rate_limit);
            apply_cfg!(explicit scan.retries => args.retries);
            apply_cfg!(explicit scan.retry_delay => args.retry_delay);
            apply_cfg!(opt_clone scan.proxy => args.proxy);
            // `insecure` is `None` unless the user passed `--insecure[=…]`, so
            // config only applies when the flag was left off. An explicit CLI
            // value — `--insecure=true` *or* `--insecure=false` — is `Some(_)`
            // and therefore always wins over the config file, in either
            // direction. (A plain `bool` couldn't express this: it can't tell
            // an explicit `--insecure=true` apart from the default.)
            apply_cfg!(opt scan.insecure => args.insecure);
            apply_cfg!(flag scan.follow_redirects => args.follow_redirects);
            apply_cfg!(vec scan.ignore_return => args.ignore_return);

            // ENGINE
            apply_cfg!(explicit scan.workers => args.workers);
            apply_cfg!(explicit scan.max_concurrent_targets => args.max_concurrent_targets);
            apply_cfg!(explicit scan.max_targets_per_host => args.max_targets_per_host);

            // XSS SCANNING
            apply_cfg!(explicit_clone scan.encoders => args.encoders);
            apply_cfg!(vec scan.remote_payloads => args.remote_payloads);
            apply_cfg!(opt_clone scan.custom_blind_xss_payload => args.custom_blind_xss_payload);
            apply_cfg!(opt_clone scan.blind_callback_url => args.blind_callback_url);
            apply_cfg!(opt_clone scan.blind_oob => args.oob.blind_oob);
            apply_cfg!(opt_clone scan.blind_oob_secret => args.oob.blind_oob_secret);
            apply_cfg!(opt scan.blind_oob_wait => args.oob.blind_oob_wait);
            apply_cfg!(opt_clone scan.custom_payload => args.custom_payload);
            apply_cfg!(flag scan.only_custom_payload => args.only_custom_payload);
            apply_cfg!(opt_clone scan.inject_marker => args.inject_marker);
            apply_cfg!(explicit_clone scan.custom_alert_value => args.custom_alert_value);
            apply_cfg!(explicit_clone scan.custom_alert_type => args.custom_alert_type);
            apply_cfg!(flag scan.skip_xss_scanning => args.skip_xss_scanning);
            apply_cfg!(explicit scan.max_payloads_per_param => args.max_payloads_per_param);
            apply_cfg!(flag scan.deep_scan => args.deep_scan);
            apply_cfg!(flag scan.sxss => args.sxss);
            apply_cfg!(opt_clone scan.sxss_url => args.sxss_url);
            apply_cfg!(explicit_clone scan.sxss_method => args.sxss_method);
            apply_cfg!(explicit scan.sxss_retries => args.sxss_retries);
            apply_cfg!(flag scan.skip_ast_analysis => args.skip_ast_analysis);
            apply_cfg!(flag scan.analyze_external_js => args.analyze_external_js);
            apply_cfg!(flag scan.detect_outdated_libs => args.detect_outdated_libs);
            apply_cfg!(flag scan.hpp => args.hpp);
            // WAF
            apply_cfg!(explicit_clone scan.waf_bypass => args.waf_bypass);
            apply_cfg!(flag scan.skip_waf_probe => args.skip_waf_probe);
            apply_cfg!(opt_clone scan.force_waf => args.force_waf);
            apply_cfg!(flag scan.waf_evasion => args.waf_evasion);
            apply_cfg!(explicit scan.waf_min_confidence => args.waf_min_confidence);
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

        // `sxss_method` — same normalization as `method` above. `--sxss-method`
        // now carries clap's parser, but a config value never passes through
        // clap, so `sxss_method = "post"` would still reach
        // `reqwest::Method::from_str` as the literal extension verb `post`.
        if let Some(m) = &self.sxss_method {
            match crate::cmd::scan::parse_http_method_arg(m) {
                Ok(upper) => self.sxss_method = Some(upper),
                Err(e) => {
                    warnings.push(format!("config scan.sxss_method: {e}; ignoring"));
                    self.sxss_method = None;
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
            &mut self.baseline_mode,
            crate::cmd::scan::BASELINE_MODE_VALUES,
            "scan.baseline_mode",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.custom_alert_type,
            crate::cmd::scan::CUSTOM_ALERT_TYPE_VALUES,
            "scan.custom_alert_type",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.dedup_urls,
            crate::cmd::scan::DEDUP_URLS_VALUES,
            "scan.dedup_urls",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.waf_bypass,
            crate::cmd::scan::WAF_BYPASS_VALUES,
            "scan.waf_bypass",
            &mut warnings,
        );
        reject_unless_allowed(
            &mut self.on_session_loss,
            crate::cmd::scan::ON_SESSION_LOSS_VALUES,
            "scan.on_session_loss",
            &mut warnings,
        );

        // `session_check` — compiled on every probe, potentially an hour into
        // the scan. A config file skips clap entirely, so validate the pattern
        // here rather than letting a typo silently report every probe as a
        // dead session (which, under the default `abort`, kills the run).
        if let Some(p) = &self.session_check
            && let Err(e) = regex::Regex::new(p)
        {
            warnings.push(format!(
                "config scan.session_check: invalid regex ({e}); ignoring"
            ));
            self.session_check = None;
        }

        // `session_check_url` — must be absolute; a relative value would fail
        // to parse at probe time and silently disable the check.
        if let Some(u) = &self.session_check_url
            && url::Url::parse(u).is_err()
        {
            warnings.push(format!(
                "config scan.session_check_url: '{u}' is not a valid absolute URL; ignoring"
            ));
            self.session_check_url = None;
        }

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

        // NOTE: the `only_custom_payload` / `custom_payload` pairing is
        // deliberately NOT checked here. This validator runs on the config file
        // alone, before CLI args are merged, so rejecting a config
        // `only_custom_payload = true` whose file comes from `--custom-payload`
        // on the command line would silently drop a flag the operator did set.
        // `run_scan` enforces the rule post-merge, where it can see both
        // sources, and errors out rather than running a payload-less scan.

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
pub(crate) fn resolve_config_dir() -> Result<PathBuf, io::Error> {
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
#[cfg(test)]
pub(crate) fn save(
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
# dedup_urls = "exact"       # exact (drop identical URL+method), signature (also collapse URLs differing only in param values), off
# state_file = "scan.state"  # CLI only (not applied by `dalfox server` / MCP); record completed targets and skip them when the scan is re-run

# OUTPUT
# format = "plain"           # plain, json, jsonl, markdown, sarif, toml
# output = "output.txt"
# include_request = false
# include_response = false
# include_all = false          # shorthand for include_request + include_response
# silence = false
# no_color = false           # disable colored output (also honors the NO_COLOR env var)
# dry_run = false            # parse targets + run discovery, report what would be scanned, send no payloads
# debug = false              # enable debug logging (DBG lines)
# stream_findings = false    # emit findings mid-scan instead of after `WRN XSS found N XSS` (plain format only)
# poc_type = "plain"         # plain, curl, httpie, http-request
# limit = 100
# limit_result_type = "all"  # which finding types count toward `limit`: all, v (vulnerable), r (reflected), a (AST DOM XSS), i (informational)
# only_poc = ["v", "r"]      # show only these finding types: v (vulnerable), r (reflected), a (AST DOM XSS), i (informational)
# baseline = "baseline.json"  # CLI only (not applied by `dalfox server` / MCP); prior JSON/JSONL report, report only findings new since it
# baseline_mode = "filter"    # filter (drop known findings) or annotate (keep them, mark each `new`)

# TARGETS
# param = ["id", "q:query", "auth:header"]
# data = "param=value"
# headers = ["X-Header: value", "Authorization: Bearer ..."]
# cookies = ["a=1", "b=2"]
# method = "GET"
# user_agent = "Dalfox/3"
# cookie_from_raw = "request.txt"

# SESSION (mid-scan session-loss detection; auto-enabled when credentials are supplied)
# session_check = "Sign out"          # regex that must keep matching an authenticated response
# session_check_url = "https://app.example.com/api/me"
# on_session_loss = "abort"           # abort, continue

# SCOPE
# include_url = []
# exclude_url = []
# ignore_param = ["utm_source", "csrf_token"]  # skip these parameters during scanning
# out_of_scope = ["*.cdn.example.com"]         # exclude targets whose domain matches these patterns (supports wildcards)
# out_of_scope_file = "out-of-scope.txt"       # load out-of-scope domain patterns from a file (one per line)

# PARAMETER DISCOVERY
# only_discovery = false          # only run parameter discovery, then stop (skip XSS scanning)
# skip_discovery = false
# skip_reflection_header = false
# skip_reflection_cookie = false
# skip_reflection_path = false

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
# rate_limit = 0             # cap outbound requests/sec (0 = unlimited); also eases off under WAF thresholds
# retries = 0                # retry failed requests on HTTP 5xx / transient transport errors (0 = off; 429 always retried)
# retry_delay = 1000         # base delay (ms) for the exponential backoff between retries
# proxy = "http://127.0.0.1:8080"  # also used for remote provider fetches
# insecure = true            # skip TLS certificate verification (default true); set false to enforce validation
# follow_redirects = false
# ignore_return = [302, 403, 404]  # ignore responses carrying these HTTP status codes

# ENGINE
# workers = 50
# max_concurrent_targets = 50
# max_targets_per_host = 100

# XSS SCANNING
# encoders = ["url", "html"]  # none, url, 2url, 3url, 4url, html, htmlpad, base64, unicode, zwsp
# remote_payloads = ["payloadbox", "portswigger"]
# custom_blind_xss_payload = "blind.txt"
# blind_callback_url = "https://your-bxss-callback.com"
# blind_oob = ["oast.fun", "oast.me"]   # OOB/OAST via interactsh; [] = default public servers
# blind_oob_secret = "token"            # auth token for a self-hosted interactsh server
# blind_oob_wait = 30                   # seconds to keep polling for callbacks after the scan
# custom_payload = "payloads.txt"
# only_custom_payload = false
# custom_alert_value = "1"    # value used inside alert()/prompt()/confirm() in generated payloads
# custom_alert_type = "none"  # alert value handling: none (keep original), str (wrap value in quotes)
# inject_marker = "FUZZ"      # replace this marker in URL/headers/body with payloads instead of auto-injecting
# skip_xss_scanning = false
# max_payloads_per_param = 0  # cap payloads per param (0 = built-in safety cap of 3000 per set, unless deep_scan)
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
