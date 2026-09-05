//! `format_sarif` output serialization for [`Result`].
//!
//! One `impl Result` block per output format keeps format-specific work
//! isolated; the shared model and helpers live in the parent module.

use super::*;

impl Result {
    /// Serialize a slice of Result into SARIF v2.1.0 format string.
    /// SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tools.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope. Use the `_with_meta` variant
    /// to populate `run.properties` + `tool.driver.properties` (recommended for CI/code-scanning).
    pub fn results_to_sarif(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_sarif_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_sarif`).
    pub(crate) fn results_to_sarif_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        use serde_json::json;

        // Convert severity to SARIF level
        let severity_to_level = |severity: &str| -> &str {
            match severity.to_lowercase().as_str() {
                "high" | "critical" => "error",
                "medium" => "warning",
                "low" | "info" => "note",
                _ => "warning",
            }
        };

        // SARIF requires that a result's `ruleId` reference a rule defined in
        // `driver.rules`, and that a present `ruleIndex` point at THAT rule.
        // Findings carry different CWEs (XSS is CWE-79; outdated-library
        // findings are CWE-1104), so a single hardcoded rule + `ruleIndex: 0`
        // emitted an id with no matching rule and an inconsistent index, which
        // GitHub code scanning rejects. Build the rule table from the distinct
        // CWEs actually present, in first-seen order, and index each result
        // into it.
        let mut rule_ids: Vec<String> = Vec::new();
        for r in results {
            let id = sarif_rule_id(&r.cwe);
            if !rule_ids.contains(&id) {
                rule_ids.push(id);
            }
        }
        // Never emit an empty `rules` array — keep the XSS rule as the default
        // so an empty result set still describes the tool's primary rule.
        if rule_ids.is_empty() {
            rule_ids.push(sarif_rule_id("CWE-79"));
        }
        let rules: Vec<serde_json::Value> =
            rule_ids.iter().map(|id| sarif_rule_for_id(id)).collect();

        // Convert results to SARIF result objects
        let sarif_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                // Build message with additional context
                let mut message_parts = vec![r.message_str.clone()];
                if !r.evidence.is_empty() {
                    message_parts.push(format!("Evidence: {}", r.evidence));
                }
                if include_request && r.request.is_some() {
                    message_parts.push("HTTP request included in properties".to_string());
                }
                if include_response && r.response.is_some() {
                    message_parts.push("HTTP response included in properties".to_string());
                }
                let full_message = message_parts.join(". ");

                // Build properties bag
                let mut properties = json!({
                    "type": r.result_type,
                    "inject_type": r.inject_type,
                    "method": r.method,
                    "param": r.param,
                    "payload": r.payload,
                    "severity": r.severity,
                    "detection_method": r.detection_method.as_str(),
                });
                if let Some(grade) = r.confidence {
                    properties["confidence"] = json!(grade.as_str());
                    if !r.confidence_reason.is_empty() {
                        properties["confidence_reason"] = json!(r.confidence_reason);
                    }
                }

                if let Some(is_new) = r.new_since_baseline {
                    properties["new"] = json!(is_new);
                }

                if include_request && let Some(req) = &r.request {
                    properties["request"] = json!(req);
                }
                if include_response && let Some(resp) = &r.response {
                    properties["response"] = json!(resp);
                }

                // Stable, vulnerability-identity fingerprint so SARIF
                // consumers (e.g. GitHub code scanning) can dedupe the
                // same finding across rescans. Previously this was the
                // catalog `message_id`, which is hardcoded per finding
                // type (e.g. 606 for every reflected XSS) and therefore
                // useless for dedup.
                let stable_fp = crate::utils::stable_finding_fingerprint(
                    &r.data,
                    &r.param,
                    &r.inject_type,
                    &r.cwe,
                );
                let rule_id = sarif_rule_id(&r.cwe);
                let rule_index = rule_ids.iter().position(|id| *id == rule_id).unwrap_or(0);
                json!({
                    "ruleId": rule_id,
                    "ruleIndex": rule_index,
                    "level": severity_to_level(&r.severity),
                    "message": {
                        "text": full_message
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.data.clone()
                            },
                            "region": {
                                "snippet": {
                                    "text": r.payload.clone()
                                }
                            }
                        }
                    }],
                    "partialFingerprints": {
                        // SARIF spec: keys are arbitrary identifiers, values
                        // are stable hashes. v1 versions the scheme so we can
                        // evolve the input tuple later without re-mapping
                        // historical findings.
                        "vulnIdentity/v1": stable_fp,
                        // Preserve the catalog id under a clearly non-
                        // fingerprint name — useful for human triage but
                        // not used by consumers for dedup.
                        "dalfoxMessageId": r.message_id.to_string(),
                    },
                    "properties": properties
                })
            })
            .collect();

        // Build driver, optionally with scan meta under its properties (per issue #1093)
        let mut driver = json!({
            "name": "Dalfox",
            "informationUri": "https://github.com/hahwul/dalfox",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules,
        });
        if let Some(m) = meta {
            driver["properties"] = Self::make_scan_meta_value(m);
        }

        // Build run object, optionally with scan meta under run.properties
        let mut run = json!({
            "tool": {
                "driver": driver
            },
            "results": sarif_results
        });
        if let Some(m) = meta {
            run["properties"] = Self::make_scan_meta_value(m);
        }

        // Build SARIF document
        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [run]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }
}

/// SARIF `ruleId` / `driver.rules[].id` for a finding's CWE. Empty or unknown
/// CWEs fall back to the XSS rule so the id is always a well-formed
/// `dalfox/cwe-<n>` rather than a bare `dalfox/`.
fn sarif_rule_id(cwe: &str) -> String {
    let trimmed = cwe.trim();
    if trimmed.is_empty() {
        return "dalfox/cwe-79".to_string();
    }
    format!("dalfox/{}", trimmed.to_ascii_lowercase())
}

/// Build a `driver.rules[]` entry for a `dalfox/cwe-<n>` rule id. CWE-79 (the
/// scanner's primary finding class) keeps its rich description; other CWEs get
/// a minimal-but-valid rule so every emitted `ruleId` resolves to a defined
/// rule (SARIF requirement for GitHub code scanning ingestion).
fn sarif_rule_for_id(id: &str) -> serde_json::Value {
    use serde_json::json;
    match id {
        "dalfox/cwe-1104" => json!({
            "id": id,
            "name": "UseOfUnmaintainedThirdPartyComponents",
            "shortDescription": {
                "text": "Use of a component with known vulnerabilities (CWE-1104)"
            },
            "fullDescription": {
                "text": "The application loads a third-party JavaScript component whose version is known to be outdated or vulnerable."
            },
            "help": {
                "text": "Upgrade the flagged component to a maintained, non-vulnerable release and track dependency advisories."
            },
            "defaultConfiguration": { "level": "warning" },
            "properties": { "tags": ["security", "dependencies"], "precision": "high" }
        }),
        "dalfox/cwe-79" => json!({
            "id": id,
            "name": "CrossSiteScripting",
            "shortDescription": {
                "text": "Cross-site Scripting (XSS)"
            },
            "fullDescription": {
                "text": "The application reflects user input in HTML responses without proper encoding, allowing attackers to inject malicious scripts."
            },
            "help": {
                "text": "Ensure all user input is properly encoded before being rendered in HTML context. Use context-aware output encoding based on where the data is placed (HTML body, attributes, JavaScript, CSS, or URL)."
            },
            "defaultConfiguration": {
                "level": "error"
            },
            "properties": {
                "tags": ["security", "xss", "injection"],
                "precision": "high"
            }
        }),
        // Any other CWE: emit a valid, generic rule so the id resolves.
        other => json!({
            "id": other,
            "name": "SecurityFinding",
            "shortDescription": { "text": format!("Security finding ({})", other) },
            "defaultConfiguration": { "level": "warning" },
            "properties": { "tags": ["security"] }
        }),
    }
}
