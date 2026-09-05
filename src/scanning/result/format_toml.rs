//! `format_toml` output serialization for [`Result`].
//!
//! One `impl Result` block per output format keeps format-specific work
//! isolated; the shared model and helpers live in the parent module.

use super::*;

impl Result {
    /// Serialize a slice of Result into TOML string.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope (equivalent to `meta=None`).
    /// Use the `_with_meta` variant to carry `ScanMetadata` (targets, duration, WAF in
    /// `target_summary`, etc.) for parity with the JSON/JSONL render path.
    #[allow(dead_code)]
    pub(crate) fn results_to_toml(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_toml_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_toml`).
    pub(crate) fn results_to_toml_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        #[derive(Serialize)]
        struct TomlWrapper {
            #[serde(skip_serializing_if = "Option::is_none")]
            meta: Option<serde_json::Value>,
            results: Vec<SanitizedResult>,
        }

        let sanitized: Vec<SanitizedResult> = results
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect();

        let meta_val = meta.map(Self::make_scan_meta_value);
        let wrapper = TomlWrapper {
            meta: meta_val,
            results: sanitized,
        };
        toml::to_string(&wrapper).unwrap_or_else(|_| "".to_string())
    }
}
