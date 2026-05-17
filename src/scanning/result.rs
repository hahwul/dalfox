use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification of an XSS finding.
///
/// Internal code uses descriptive variant names; serialization produces the
/// single-letter abbreviation for compact user-facing output and backward-
/// compatible JSON (`"V"`, `"A"`, `"R"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    /// DOM-verified XSS — payload confirmed in parsed DOM structure.
    #[serde(rename = "V")]
    Verified,
    /// AST-detected DOM XSS — identified via static JavaScript analysis,
    /// not yet confirmed at runtime.
    #[serde(rename = "A")]
    AstDetected,
    /// Reflected XSS — payload appears in HTTP response but DOM evidence
    /// was not confirmed.
    #[serde(rename = "R")]
    Reflected,
}

impl FindingType {
    /// Short single-letter label used in compact output (POC lines, etc.).
    pub fn short(&self) -> &'static str {
        match self {
            FindingType::Verified => "V",
            FindingType::AstDetected => "A",
            FindingType::Reflected => "R",
        }
    }

    /// Human-readable descriptive name for logs and verbose output.
    pub fn description(&self) -> &'static str {
        match self {
            FindingType::Verified => "Verified",
            FindingType::AstDetected => "AST-Detected",
            FindingType::Reflected => "Reflected",
        }
    }

    /// Detailed description suitable for agents and structured output.
    pub fn long_description(&self) -> &'static str {
        match self {
            FindingType::Verified => "Verified XSS - payload confirmed executed in parsed DOM",
            FindingType::AstDetected => {
                "AST-detected DOM XSS - identified via static JavaScript analysis, needs runtime confirmation"
            }
            FindingType::Reflected => {
                "Reflected XSS - payload appears in HTTP response but DOM execution not confirmed"
            }
        }
    }
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    #[serde(rename = "type")]
    pub result_type: FindingType,
    pub inject_type: String,
    pub method: String,
    pub data: String,
    pub param: String,
    pub payload: String,
    pub evidence: String,
    pub cwe: String,
    pub severity: String,
    pub message_id: u32,
    pub message_str: String,
    /// Where the parameter lives on the wire: `"Query"`, `"Header"`,
    /// `"Body"`, `"JsonBody"`, `"MultipartBody"`, `"Path"`, or `"Fragment"`.
    /// Empty when the producer didn't set it (older call sites). Consumed
    /// by `generate_poc` to avoid synthesizing a misleading `?name=payload`
    /// query for header/cookie/body findings, and to tag the plain POC
    /// line with a short location hint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

impl Result {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_type: FindingType,
        inject_type: String,
        method: String,
        data: String,
        param: String,
        payload: String,
        evidence: String,
        cwe: String,
        severity: String,
        message_id: u32,
        message_str: String,
    ) -> Self {
        Self {
            result_type,
            inject_type,
            method,
            data,
            param,
            payload,
            evidence,
            cwe,
            severity,
            message_id,
            message_str,
            location: String::new(),
            request: None,
            response: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedResult {
    #[serde(rename = "type")]
    pub result_type: FindingType,
    pub type_description: String,
    pub inject_type: String,
    pub method: String,
    pub data: String,
    pub param: String,
    pub payload: String,
    pub evidence: String,
    pub cwe: String,
    pub severity: String,
    pub message_id: u32,
    pub message_str: String,
    /// Wire location of the parameter (Query / Header / Body / …). See
    /// [`Result::location`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

impl Result {
    pub fn to_sanitized(&self, include_request: bool, include_response: bool) -> SanitizedResult {
        SanitizedResult {
            type_description: self.result_type.long_description().to_string(),
            result_type: self.result_type.clone(),
            inject_type: self.inject_type.clone(),
            method: self.method.clone(),
            data: self.data.clone(),
            param: self.param.clone(),
            payload: self.payload.clone(),
            evidence: self.evidence.clone(),
            cwe: self.cwe.clone(),
            severity: self.severity.clone(),
            message_id: self.message_id,
            message_str: self.message_str.clone(),
            location: self.location.clone(),
            request: if include_request {
                self.request.clone()
            } else {
                None
            },
            response: if include_response {
                self.response.clone()
            } else {
                None
            },
        }
    }

    /// Convert this Result into a serde_json::Value honoring include_request/include_response flags.
    pub fn to_json_value(
        &self,
        include_request: bool,
        include_response: bool,
    ) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.result_type,
            "type_description": self.result_type.long_description(),
            "inject_type": self.inject_type,
            "method": self.method,
            "data": self.data,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "severity": self.severity,
            "message_id": self.message_id,
            "message_str": self.message_str
        });
        if !self.location.is_empty()
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "location".to_string(),
                serde_json::Value::String(self.location.clone()),
            );
        }
        if include_request
            && let Some(req) = &self.request
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "request".to_string(),
                serde_json::Value::String(req.clone()),
            );
        }
        if include_response
            && let Some(resp) = &self.response
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "response".to_string(),
                serde_json::Value::String(resp.clone()),
            );
        }
        obj
    }

    /// Serialize a slice of Result into JSON array string. Set pretty=true for pretty-printed JSON.
    pub fn results_to_json(
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
    pub fn results_to_jsonl(
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

    /// Serialize a slice of Result into Markdown string.
    pub fn results_to_toml(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        #[derive(Serialize)]
        struct TomlWrapper {
            results: Vec<SanitizedResult>,
        }

        let sanitized: Vec<SanitizedResult> = results
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect();

        let wrapper = TomlWrapper { results: sanitized };
        toml::to_string(&wrapper).unwrap_or_else(|_| "".to_string())
    }

    pub fn results_to_markdown(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(results.len() * 512 + 256);

        // Add header
        out.push_str("# Dalfox Scan Results\n\n");

        // Add summary
        let v_count = results
            .iter()
            .filter(|r| r.result_type == FindingType::Verified)
            .count();
        let r_count = results
            .iter()
            .filter(|r| r.result_type == FindingType::Reflected)
            .count();
        out.push_str("## Summary\n\n");
        let _ = writeln!(out, "- **Total Findings**: {}", results.len());
        let _ = writeln!(out, "- **Vulnerabilities (V)**: {}", v_count);
        let _ = write!(out, "- **Reflections (R)**: {}\n\n", r_count); // double newline intentional

        // Add findings table
        if !results.is_empty() {
            out.push_str("## Findings\n\n");

            for (idx, result) in results.iter().enumerate() {
                let _ = write!(
                    out,
                    "### {}. {} - {} ({})\n\n", // double newline intentional
                    idx + 1,
                    if result.result_type == FindingType::Verified {
                        "Vulnerability"
                    } else {
                        "Reflection"
                    },
                    result.param,
                    result.inject_type
                );

                out.push_str("| Field | Value |\n");
                out.push_str("|-------|-------|\n");
                let _ = writeln!(out, "| **Type** | {} |", result.result_type);
                let _ = writeln!(out, "| **Parameter** | `{}` |", result.param);
                let _ = writeln!(out, "| **Method** | {} |", result.method);
                let _ = writeln!(out, "| **Injection Type** | {} |", result.inject_type);
                let _ = writeln!(out, "| **Severity** | {} |", result.severity);
                let _ = writeln!(out, "| **CWE** | {} |", result.cwe);
                let _ = writeln!(out, "| **URL** | {} |", result.data);
                let _ = writeln!(
                    out,
                    "| **Payload** | `{}` |",
                    result.payload.replace('|', "\\|")
                );

                if !result.evidence.is_empty() {
                    let _ = writeln!(
                        out,
                        "| **Evidence** | {} |",
                        result.evidence.replace('|', "\\|")
                    );
                }

                out.push('\n');

                // Include request if requested
                if include_request && let Some(req) = &result.request {
                    out.push_str("**Request:**\n\n```http\n");
                    out.push_str(req);
                    out.push_str("\n```\n\n");
                }

                // Include response if requested
                if include_response && let Some(resp) = &result.response {
                    out.push_str("**Response:**\n\n```http\n");
                    out.push_str(resp);
                    out.push_str("\n```\n\n");
                }

                out.push_str("---\n\n");
            }
        }

        out
    }

    /// Serialize a slice of Result into SARIF v2.1.0 format string.
    /// SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tools.
    pub fn results_to_sarif(
        results: &[Result],
        include_request: bool,
        include_response: bool,
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
                });

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
                json!({
                    "ruleId": format!("dalfox/{}", r.cwe.to_lowercase()),
                    "ruleIndex": 0,
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

        // Build SARIF document
        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Dalfox",
                        "informationUri": "https://github.com/hahwul/dalfox",
                        "version": env!("CARGO_PKG_VERSION"),
                        "rules": [{
                            "id": "dalfox/cwe-79",
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
                        }]
                    }
                },
                "results": sarif_results
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests;
