//! The options the scan engine runs with.
//!
//! [`ScanArgs`] is the command line: 89 clap fields, half of which are about
//! input, output and reporting. The engine (`scanning`, `parameter_analysis`)
//! used to take that struct whole, so anything that wanted to run a scan had to
//! build a CLI invocation first, and nothing said which flags the engine reads.
//!
//! [`EngineOptions`] is that subset, already resolved: it is built from the
//! finalized `ScanArgs` ([`EngineOptions::from`]) where a caller enters the
//! engine (once per run in the scan loop and in the job runner) and is the
//! only options type the engine sees. Field names and types match `ScanArgs`, so moving a
//! reader from one to the other changes its signature and nothing else.
//!
//! Adding an engine option: add the field here and to the `From` impl below.
//! The `From` impl names every field, so forgetting it is a compile error.

use crate::cmd::scan::ScanArgs;
use crate::scanning::result::Result as Finding;

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub sxss: bool,
    pub data: Option<String>,
    pub max_payloads_per_param: usize,
    pub deep_scan: bool,
    pub sxss_url: Vec<String>,
    pub encoders: Vec<String>,
    pub only_custom_payload: bool,
    pub skip_mining: bool,
    pub param: Vec<String>,
    pub custom_payload: Option<String>,
    pub sxss_retries: u32,
    pub silence: bool,
    pub ignore_return: Vec<u16>,
    pub skip_xss_scanning: bool,
    pub waf_evasion: bool,
    pub method: String,
    pub hpp: bool,
    pub waf_bypass: String,
    pub tier_model: Option<String>,
    pub skip_mining_dom: bool,
    pub retry_delay: u64,
    pub retries: u32,
    pub mining_dict_word: Option<String>,
    pub limit: Option<usize>,
    pub ignore_param: Vec<String>,
    pub custom_alert_value: String,
    pub sxss_method: String,
    pub skip_mining_dict: bool,
    pub remote_wordlists: Vec<String>,
    pub proxy: Option<String>,
    pub workers: usize,
    pub skip_reflection_header: bool,
    pub skip_discovery: bool,
    pub skip_ast_analysis: bool,
    pub skip_reflection_path: bool,
    pub skip_reflection_cookie: bool,
    pub remote_payloads: Vec<String>,
    pub only_poc: Vec<String>,
    pub custom_blind_xss_payload: Option<String>,
    pub custom_alert_type: String,
    pub cookie_from_raw: Option<String>,
    pub analyze_external_js: bool,
    pub timeout: u64,
    pub max_concurrent_targets: usize,
    pub limit_result_type: String,
    pub include_url: Vec<String>,
    pub exclude_url: Vec<String>,
    pub min_confidence: Option<String>,
    pub discard_below_min_confidence: bool,
}

impl From<&ScanArgs> for EngineOptions {
    fn from(args: &ScanArgs) -> Self {
        Self {
            sxss: args.sxss,
            data: args.data.clone(),
            max_payloads_per_param: args.max_payloads_per_param,
            deep_scan: args.deep_scan,
            sxss_url: args.sxss_url.clone(),
            encoders: args.encoders.clone(),
            only_custom_payload: args.only_custom_payload,
            skip_mining: args.skip_mining,
            param: args.param.clone(),
            custom_payload: args.custom_payload.clone(),
            sxss_retries: args.sxss_retries,
            silence: args.silence,
            ignore_return: args.ignore_return.clone(),
            skip_xss_scanning: args.skip_xss_scanning,
            waf_evasion: args.waf_evasion,
            method: args.method.clone(),
            hpp: args.hpp,
            waf_bypass: args.waf_bypass.clone(),
            tier_model: args.tier_model.clone(),
            skip_mining_dom: args.skip_mining_dom,
            retry_delay: args.retry_delay,
            retries: args.retries,
            mining_dict_word: args.mining_dict_word.clone(),
            limit: args.limit,
            ignore_param: args.ignore_param.clone(),
            custom_alert_value: args.custom_alert_value.clone(),
            sxss_method: args.sxss_method.clone(),
            skip_mining_dict: args.skip_mining_dict,
            remote_wordlists: args.remote_wordlists.clone(),
            proxy: args.proxy.clone(),
            workers: args.workers,
            skip_reflection_header: args.skip_reflection_header,
            skip_discovery: args.skip_discovery,
            skip_ast_analysis: args.skip_ast_analysis,
            skip_reflection_path: args.skip_reflection_path,
            skip_reflection_cookie: args.skip_reflection_cookie,
            remote_payloads: args.remote_payloads.clone(),
            only_poc: args.only_poc.clone(),
            custom_blind_xss_payload: args.custom_blind_xss_payload.clone(),
            custom_alert_type: args.custom_alert_type.clone(),
            cookie_from_raw: args.cookie_from_raw.clone(),
            analyze_external_js: args.analyze_external_js,
            timeout: args.timeout,
            max_concurrent_targets: args.max_concurrent_targets,
            limit_result_type: args.limit_result_type.clone(),
            include_url: args.include_url.clone(),
            exclude_url: args.exclude_url.clone(),
            min_confidence: args.min_confidence.clone(),
            discard_below_min_confidence: args.discard_below_min_confidence,
        }
    }
}

impl Default for EngineOptions {
    /// The engine options of a scan run with no flags.
    fn default() -> Self {
        Self::from(&ScanArgs::default())
    }
}

impl EngineOptions {
    /// Whether `r` counts toward `--limit`: it survives `--min-confidence`,
    /// passes `--only-poc`, and is of the type `--limit-result-type` names.
    pub(crate) fn counts_toward_limit(&self, r: &Finding) -> bool {
        counts_toward_limit(
            &self.only_poc,
            &self.limit_result_type,
            self.tier_model.as_deref(),
            self.min_confidence.as_deref(),
            r,
        )
    }

    /// Whether `--min-confidence` drops `r`.
    pub(crate) fn below_min_confidence(&self, r: &Finding) -> bool {
        r.below_min_confidence(self.min_confidence.as_deref())
    }

    /// Whether `url` passes `--include-url` / `--exclude-url`.
    pub(crate) fn url_in_scope(&self, url: &str) -> bool {
        crate::cmd::scan::url_in_scope(&self.include_url, &self.exclude_url, url)
    }
}

/// `--only-poc`: no filter, or one of the listed types matches.
pub(crate) fn matches_only_poc(only_poc: &[String], tier_model: Option<&str>, r: &Finding) -> bool {
    only_poc.is_empty()
        || only_poc
            .iter()
            .any(|f| r.matches_type(&f.trim().to_uppercase(), tier_model))
}

/// The rule behind [`EngineOptions::counts_toward_limit`], on its inputs.
pub(crate) fn counts_toward_limit(
    only_poc: &[String],
    limit_result_type: &str,
    tier_model: Option<&str>,
    min_confidence: Option<&str>,
    r: &Finding,
) -> bool {
    !r.below_min_confidence(min_confidence)
        && matches_only_poc(only_poc, tier_model, r)
        && r.matches_type(&limit_result_type.to_uppercase(), tier_model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::result::{FindingType, Result as Finding};

    fn finding(kind: FindingType) -> Finding {
        Finding::builder(kind).build()
    }

    #[test]
    fn conversion_carries_what_the_operator_set() {
        let args = ScanArgs {
            sxss: true,
            data: Some("a=1".to_string()),
            encoders: vec!["none".to_string()],
            limit: Some(3),
            workers: 7,
            only_poc: vec!["v".to_string()],
            limit_result_type: "v".to_string(),
            min_confidence: Some("high".to_string()),
            include_url: vec!["/api/".to_string()],
            exclude_url: vec!["/api/admin".to_string()],
            ..Default::default()
        };
        let opts = EngineOptions::from(&args);
        assert!(opts.sxss);
        assert_eq!(opts.data.as_deref(), Some("a=1"));
        assert_eq!(opts.encoders, ["none"]);
        assert_eq!(opts.limit, Some(3));
        assert_eq!(opts.workers, 7);
        assert_eq!(opts.only_poc, ["v"]);
        assert_eq!(opts.limit_result_type, "v");
        assert_eq!(opts.min_confidence.as_deref(), Some("high"));
        assert!(opts.url_in_scope("https://a.test/api/x"));
        assert!(!opts.url_in_scope("https://a.test/api/admin"));
        assert!(!opts.url_in_scope("https://a.test/other"));
    }

    #[test]
    fn default_options_are_the_defaults_of_the_command_line() {
        let args = ScanArgs::default();
        let opts = EngineOptions::default();
        assert_eq!(opts.method, args.method);
        assert_eq!(opts.encoders, args.encoders);
        assert_eq!(opts.workers, args.workers);
        assert_eq!(opts.timeout, args.timeout);
        assert_eq!(opts.max_payloads_per_param, args.max_payloads_per_param);
        assert_eq!(opts.limit_result_type, args.limit_result_type);
        assert!(opts.url_in_scope("https://anything.test/"));
    }

    #[test]
    fn limit_counts_only_what_the_report_keeps() {
        let verified = finding(FindingType::Verified);
        let reflected = finding(FindingType::Reflected);
        let mut opts = EngineOptions::default();
        assert!(opts.counts_toward_limit(&verified));
        assert!(opts.counts_toward_limit(&reflected));
        opts.only_poc = vec!["v".to_string()];
        assert!(opts.counts_toward_limit(&verified));
        assert!(!opts.counts_toward_limit(&reflected));
        opts.only_poc.clear();
        opts.limit_result_type = "r".to_string();
        assert!(!opts.counts_toward_limit(&verified));
        assert!(opts.counts_toward_limit(&reflected));
        // The command line answers the same question the same way.
        let args = ScanArgs {
            only_poc: vec!["v".to_string()],
            ..Default::default()
        };
        assert!(args.matches_only_poc(&verified));
        assert!(!args.matches_only_poc(&reflected));
    }
}
