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
    /// Informational — a non-exploitable observation, e.g. an outdated or
    /// known-vulnerable JavaScript library (CWE-1104). Not an XSS finding;
    /// excluded from XSS-only dedup/collapse logic.
    #[serde(rename = "I")]
    Informational,
}

impl FindingType {
    /// Short single-letter label used in compact output (POC lines, etc.).
    pub fn short(&self) -> &'static str {
        match self {
            FindingType::Verified => "V",
            FindingType::AstDetected => "A",
            FindingType::Reflected => "R",
            FindingType::Informational => "I",
        }
    }

    /// Human-readable descriptive name for logs and verbose output.
    pub fn description(&self) -> &'static str {
        match self {
            FindingType::Verified => "Verified",
            FindingType::AstDetected => "AST-Detected",
            FindingType::Reflected => "Reflected",
            FindingType::Informational => "Informational",
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
            FindingType::Informational => {
                "Informational - outdated or known-vulnerable component, not an exploitable XSS"
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
    /// Start building a finding. `result_type` is the only required field;
    /// every other field starts empty (`""` / `0` / `None`) and is filled in
    /// with the chained setters on [`ResultBuilder`], finishing with
    /// [`ResultBuilder::build`].
    ///
    /// Replaces the former 11-argument `Result::new`, which tripped
    /// `clippy::too_many_arguments`. The `location` / `request` / `response`
    /// fields remain public and are set directly on the built value when a
    /// caller needs them (often conditionally).
    pub fn builder(result_type: FindingType) -> ResultBuilder {
        ResultBuilder {
            inner: Result {
                result_type,
                inject_type: String::new(),
                method: String::new(),
                data: String::new(),
                param: String::new(),
                payload: String::new(),
                evidence: String::new(),
                cwe: String::new(),
                severity: String::new(),
                message_id: 0,
                message_str: String::new(),
                location: String::new(),
                request: None,
                response: None,
            },
        }
    }
}

/// Fluent builder for [`Result`]. Each setter consumes and returns `self` so
/// calls chain; setters take `impl Into<String>` so both `&str` and `String`
/// work at the call site.
#[derive(Debug, Clone)]
pub struct ResultBuilder {
    inner: Result,
}

impl ResultBuilder {
    /// Injection technique label (e.g. `"inHTML-URL"`, `"DOM-XSS"`).
    pub fn inject_type(mut self, v: impl Into<String>) -> Self {
        self.inner.inject_type = v.into();
        self
    }

    /// HTTP method used for the request that produced the finding.
    pub fn method(mut self, v: impl Into<String>) -> Self {
        self.inner.method = v.into();
        self
    }

    /// Request data / URL associated with the finding.
    pub fn data(mut self, v: impl Into<String>) -> Self {
        self.inner.data = v.into();
        self
    }

    /// Name of the affected parameter.
    pub fn param(mut self, v: impl Into<String>) -> Self {
        self.inner.param = v.into();
        self
    }

    /// The payload that triggered the finding.
    pub fn payload(mut self, v: impl Into<String>) -> Self {
        self.inner.payload = v.into();
        self
    }

    /// Human-readable evidence string.
    pub fn evidence(mut self, v: impl Into<String>) -> Self {
        self.inner.evidence = v.into();
        self
    }

    /// CWE identifier (e.g. `"CWE-79"`).
    pub fn cwe(mut self, v: impl Into<String>) -> Self {
        self.inner.cwe = v.into();
        self
    }

    /// Severity label (e.g. `"High"`, `"Medium"`).
    pub fn severity(mut self, v: impl Into<String>) -> Self {
        self.inner.severity = v.into();
        self
    }

    /// Numeric message identifier.
    pub fn message_id(mut self, v: u32) -> Self {
        self.inner.message_id = v;
        self
    }

    /// Message string shown to the user.
    pub fn message_str(mut self, v: impl Into<String>) -> Self {
        self.inner.message_str = v.into();
        self
    }

    /// Finalize the builder into a [`Result`].
    pub fn build(self) -> Result {
        self.inner
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

/// Scan-level metadata envelope, previously only surfaced for JSON/JSONL.
/// Now also threaded into SARIF (run.properties + driver.properties),
/// Markdown (as additional summary tables), and TOML (as `[meta]` table).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanMetadata {
    pub dalfox_version: String,
    pub targets: Vec<String>,
    pub scan_duration_ms: u64,
    pub total_requests: u64,
    pub findings_count: usize,
    pub target_summary: Vec<serde_json::Value>,
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

    fn make_scan_meta_value(meta: &ScanMetadata) -> serde_json::Value {
        serde_json::json!({
            "dalfox_version": &meta.dalfox_version,
            "targets": &meta.targets,
            "scan_duration_ms": meta.scan_duration_ms,
            "total_requests": meta.total_requests,
            "findings_count": meta.findings_count,
            "target_summary": &meta.target_summary,
        })
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

    /// Serialize a slice of Result into TOML string.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope (equivalent to `meta=None`).
    /// Use the `_with_meta` variant to carry `ScanMetadata` (targets, duration, WAF in
    /// `target_summary`, etc.) for parity with the JSON/JSONL render path.
    pub fn results_to_toml(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_toml_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_toml`).
    pub fn results_to_toml_with_meta(
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

    /// Serialize a slice of Result into Markdown string.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope (equivalent to `meta=None`).
    /// Use the `_with_meta` variant to include `## Scan Metadata` + target summary tables.
    pub fn results_to_markdown(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_markdown_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_markdown`).
    pub fn results_to_markdown_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(results.len() * 512 + 256);

        // Add header
        out.push_str("# Dalfox Scan Results\n\n");

        // Inject scan metadata envelope when provided (for parity with JSON/JSONL)
        if let Some(m) = meta {
            out.push_str("## Scan Metadata\n\n");
            out.push_str("| Field | Value |\n");
            out.push_str("|-------|-------|\n");
            let _ = writeln!(out, "| **Dalfox Version** | {} |", m.dalfox_version);
            let _ = writeln!(
                out,
                "| **Targets** | {} |",
                m.targets.join(", ").replace('|', "\\|")
            );
            let _ = writeln!(out, "| **Scan Duration** | {} ms |", m.scan_duration_ms);
            let _ = writeln!(out, "| **Total Requests** | {} |", m.total_requests);
            let _ = writeln!(out, "| **Findings Count** | {} |", m.findings_count);
            out.push('\n');

            // Per-target summary table (includes status, findings_count, WAF when present)
            if !m.target_summary.is_empty() {
                out.push_str("### Target Summary\n\n");
                out.push_str("| Target | Status | Findings | WAF |\n");
                out.push_str("|--------|--------|----------|-----|\n");
                for t in &m.target_summary {
                    let tgt = t.get("target").and_then(|v| v.as_str()).unwrap_or("?");
                    let st = t.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    let fc = t
                        .get("findings_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let status_cell = if let Some(ec) = t.get("error_code").and_then(|e| e.as_str())
                    {
                        format!("{} ({})", st, ec)
                    } else {
                        st.to_string()
                    };
                    let waf_str = if let Some(w) = t.get("waf") {
                        // Real shape (from analysis.rs + render_results): "detected": [{ "type": "..", "confidence": N, ...}, ...]
                        // plus optional "bypass". Support legacy test mock shape {detected: bool, name} too.
                        if let Some(dets) = w.get("detected").and_then(|d| d.as_array()) {
                            if !dets.is_empty() {
                                dets[0]
                                    .get("type")
                                    .and_then(|ty| ty.as_str())
                                    .unwrap_or("detected")
                                    .to_string()
                            } else {
                                "none".to_string()
                            }
                        } else if w.get("detected").and_then(|d| d.as_bool()).unwrap_or(false) {
                            w.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("detected")
                                .to_string()
                        } else {
                            "none".to_string()
                        }
                    } else {
                        "none".to_string()
                    };
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {} |",
                        tgt.replace('|', "\\|"),
                        status_cell.replace('|', "\\|"),
                        fc,
                        waf_str.replace('|', "\\|")
                    );
                }
                out.push('\n');
            }
        }

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
    pub fn results_to_sarif_with_meta(
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

        // Build driver, optionally with scan meta under its properties (per issue #1093)
        let mut driver = json!({
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

#[cfg(test)]
mod tests;
