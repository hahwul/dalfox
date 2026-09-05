//! `format_json` output serialization for [`Result`].
//!
//! One `impl Result` block per output format keeps format-specific work
//! isolated; the shared model and helpers live in the parent module.

use super::*;

impl Result {
    /// Serialize a slice of Result into JSON array string. Set pretty=true for pretty-printed JSON.
    // The plain (meta-less) arms of the format matrix. `output.rs` routes every
    // scan through the `*_with_meta` variants, so these are kept as the
    // complete set rather than because a caller reaches them today.
    #[allow(dead_code)]
    pub(crate) fn results_to_json(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        pretty: bool,
    ) -> String {
        let vals: Vec<serde_json::Value> = results
            .iter()
            .map(|r| r.to_json_value(include_request, include_response))
            .collect();
        if pretty {
            serde_json::to_string_pretty(&vals).unwrap_or_else(|_| "[]".to_string())
        } else {
            serde_json::to_string(&vals).unwrap_or_else(|_| "[]".to_string())
        }
    }

    /// Serialize a slice of Result into JSON Lines (JSONL) string.
    #[allow(dead_code)]
    pub(crate) fn results_to_jsonl(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        let mut out = String::new();
        for r in results {
            let v = r.to_json_value(include_request, include_response);
            if let Ok(s) = serde_json::to_string(&v) {
                out.push_str(&s);
                out.push('\n');
            }
        }
        out
    }
}
