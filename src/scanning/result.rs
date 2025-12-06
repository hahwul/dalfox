use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    #[serde(rename = "type")]
    pub result_type: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

impl Result {
    pub fn new(
        result_type: String,
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
            request: None,
            response: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedResult {
    #[serde(rename = "type")]
    pub result_type: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

impl Result {
    pub fn to_sanitized(&self, include_request: bool, include_response: bool) -> SanitizedResult {
        SanitizedResult {
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
    pub fn results_to_markdown(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        let mut out = String::new();

        // Add header
        out.push_str("# Dalfox Scan Results\n\n");

        // Add summary
        let v_count = results.iter().filter(|r| r.result_type == "V").count();
        let r_count = results.iter().filter(|r| r.result_type == "R").count();
        out.push_str(&format!("## Summary\n\n"));
        out.push_str(&format!("- **Total Findings**: {}\n", results.len()));
        out.push_str(&format!("- **Vulnerabilities (V)**: {}\n", v_count));
        out.push_str(&format!("- **Reflections (R)**: {}\n\n", r_count));

        // Add findings table
        if !results.is_empty() {
            out.push_str("## Findings\n\n");

            for (idx, result) in results.iter().enumerate() {
                out.push_str(&format!(
                    "### {}. {} - {} ({})\n\n",
                    idx + 1,
                    if result.result_type == "V" {
                        "Vulnerability"
                    } else {
                        "Reflection"
                    },
                    result.param,
                    result.inject_type
                ));

                out.push_str("| Field | Value |\n");
                out.push_str("|-------|-------|\n");
                out.push_str(&format!("| **Type** | {} |\n", result.result_type));
                out.push_str(&format!("| **Parameter** | `{}` |\n", result.param));
                out.push_str(&format!("| **Method** | {} |\n", result.method));
                out.push_str(&format!(
                    "| **Injection Type** | {} |\n",
                    result.inject_type
                ));
                out.push_str(&format!("| **Severity** | {} |\n", result.severity));
                out.push_str(&format!("| **CWE** | {} |\n", result.cwe));
                out.push_str(&format!("| **URL** | {} |\n", result.data));
                out.push_str(&format!(
                    "| **Payload** | `{}` |\n",
                    result.payload.replace('|', "\\|")
                ));

                if !result.evidence.is_empty() {
                    out.push_str(&format!(
                        "| **Evidence** | {} |\n",
                        result.evidence.replace('|', "\\|")
                    ));
                }

                out.push_str("\n");

                // Include request if requested
                if include_request
                    && let Some(req) = &result.request
                {
                    out.push_str("**Request:**\n\n");
                    out.push_str("```http\n");
                    out.push_str(req);
                    out.push_str("\n```\n\n");
                }

                // Include response if requested
                if include_response
                    && let Some(resp) = &result.response
                {
                    out.push_str("**Response:**\n\n");
                    out.push_str("```http\n");
                    out.push_str(resp);
                    out.push_str("\n```\n\n");
                }

                out.push_str("---\n\n");
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_result_creation() {
        let result = Result::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com?q=test".to_string(),
            "q".to_string(),
            "<script>alert(1)</script>".to_string(),
            "Found script tag".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            606,
            "XSS detected".to_string(),
        );

        assert_eq!(result.result_type, "V");
        assert_eq!(result.inject_type, "inHTML");
        assert_eq!(result.method, "GET");
        assert_eq!(result.data, "https://example.com?q=test");
        assert_eq!(result.param, "q");
        assert_eq!(result.payload, "<script>alert(1)</script>");
        assert_eq!(result.evidence, "Found script tag");
        assert_eq!(result.cwe, "CWE-79");
        assert_eq!(result.severity, "High");
        assert_eq!(result.message_id, 606);
        assert_eq!(result.message_str, "XSS detected");
        assert!(result.request.is_none());
        assert!(result.response.is_none());
    }

    #[test]
    fn test_result_creation_with_request_response() {
        let mut result = Result::new(
            "V".to_string(),
            "inJS".to_string(),
            "POST".to_string(),
            "https://example.com".to_string(),
            "data".to_string(),
            "alert(1)".to_string(),
            "JavaScript execution".to_string(),
            "CWE-79".to_string(),
            "Medium".to_string(),
            200,
            "Potential XSS".to_string(),
        );

        result.request = Some("POST / HTTP/1.1\nHost: example.com\n\nkey=value".to_string());
        result.response = Some("HTTP/1.1 200 OK\n\n<html>alert(1)</html>".to_string());

        assert_eq!(result.result_type, "V");
        assert_eq!(result.severity, "Medium");
        assert!(result.request.is_some());
        assert!(result.response.is_some());
        assert!(result.request.as_ref().unwrap().contains("POST"));
        assert!(result.response.as_ref().unwrap().contains("200 OK"));
    }

    #[test]
    fn test_result_serialization() {
        let result = Result::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "query".to_string(),
            "payload".to_string(),
            "evidence".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            606,
            "message".to_string(),
        );

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"type\":\"V\""));
        assert!(json.contains("\"inject_type\":\"inHTML\""));
        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"data\":\"https://example.com\""));
        assert!(json.contains("\"param\":\"query\""));
        assert!(json.contains("\"payload\":\"payload\""));
        assert!(json.contains("\"evidence\":\"evidence\""));
        assert!(json.contains("\"cwe\":\"CWE-79\""));
        assert!(json.contains("\"severity\":\"High\""));
        assert!(json.contains("\"message_id\":606"));
        assert!(json.contains("\"message_str\":\"message\""));
        assert!(!json.contains("\"request\":null"));
        assert!(!json.contains("\"response\":null"));
    }

    #[test]
    fn test_result_deserialization() {
        let json = r#"{
            "type": "V",
            "inject_type": "inHTML",
            "method": "GET",
            "data": "https://example.com",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Found script",
            "cwe": "CWE-79",
            "severity": "High",
            "message_id": 200,
            "message_str": "XSS found",
            "request": null,
            "response": null
        }"#;

        let result: Result = serde_json::from_str(json).unwrap();
        assert_eq!(result.result_type, "V");
        assert_eq!(result.param, "q");
        assert_eq!(result.severity, "High");
        assert_eq!(result.message_id, 200);
    }

    #[test]
    fn test_result_different_types() {
        let reflected = Result::new(
            "R".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "param".to_string(),
            "test".to_string(),
            "Reflected".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            200,
            "Parameter reflected".to_string(),
        );

        let vulnerable = Result::new(
            "V".to_string(),
            "inJS".to_string(),
            "POST".to_string(),
            "https://example.com".to_string(),
            "data".to_string(),
            "alert(1)".to_string(),
            "Executed".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            200,
            "XSS confirmed".to_string(),
        );

        assert_eq!(reflected.result_type, "R");
        assert_eq!(reflected.severity, "Info");
        assert_eq!(vulnerable.result_type, "V");
        assert_eq!(vulnerable.severity, "High");
        assert_ne!(reflected.result_type, vulnerable.result_type);
    }

    #[test]
    fn test_result_edge_cases() {
        // Empty strings
        let result = Result::new(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            0,
            "".to_string(),
        );

        assert_eq!(result.result_type, "");
        assert_eq!(result.message_id, 0);

        // Special characters
        let result = Result::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "param".to_string(),
            "<>\"'&".to_string(),
            "Special chars".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            200,
            "Test".to_string(),
        );

        assert_eq!(result.payload, "<>\"'&");
        let json = serde_json::to_string(&result).unwrap();
        // Ensure special chars are properly handled in JSON
        assert!(json.contains("\"payload\":\"<>\\\""));
    }

    #[test]
    fn test_results_to_markdown() {
        let result1 = Result::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com?q=test".to_string(),
            "q".to_string(),
            "<script>alert(1)</script>".to_string(),
            "Found script tag".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            606,
            "XSS detected".to_string(),
        );

        let result2 = Result::new(
            "R".to_string(),
            "inJS".to_string(),
            "POST".to_string(),
            "https://example.com/api".to_string(),
            "data".to_string(),
            "alert(2)".to_string(),
            "Reflected in JS".to_string(),
            "CWE-79".to_string(),
            "Medium".to_string(),
            200,
            "Reflection found".to_string(),
        );

        let results = vec![result1, result2];
        let markdown = Result::results_to_markdown(&results, false, false);

        // Check header
        assert!(markdown.contains("# Dalfox Scan Results"));

        // Check summary
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("**Total Findings**: 2"));
        assert!(markdown.contains("**Vulnerabilities (V)**: 1"));
        assert!(markdown.contains("**Reflections (R)**: 1"));

        // Check findings section
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("### 1. Vulnerability - q (inHTML)"));
        assert!(markdown.contains("### 2. Reflection - data (inJS)"));

        // Check table content
        assert!(markdown.contains("| **Type** | V |"));
        assert!(markdown.contains("| **Type** | R |"));
        assert!(markdown.contains("| **Parameter** | `q` |"));
        assert!(markdown.contains("| **Parameter** | `data` |"));
        assert!(markdown.contains("| **Severity** | High |"));
        assert!(markdown.contains("| **Severity** | Medium |"));
        assert!(markdown.contains("| **CWE** | CWE-79 |"));
        assert!(markdown.contains("| **Payload** | `<script>alert(1)</script>` |"));
    }

    #[test]
    fn test_results_to_markdown_with_request_response() {
        let mut result = Result::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "test".to_string(),
            "<x>".to_string(),
            "test evidence".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            606,
            "XSS".to_string(),
        );

        result.request = Some("GET /?test=%3Cx%3E HTTP/1.1\nHost: example.com".to_string());
        result.response =
            Some("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><x></html>".to_string());

        let results = vec![result];
        let markdown = Result::results_to_markdown(&results, true, true);

        // Check request and response sections
        assert!(markdown.contains("**Request:**"));
        assert!(markdown.contains("```http"));
        assert!(markdown.contains("GET /?test=%3Cx%3E HTTP/1.1"));
        assert!(markdown.contains("**Response:**"));
        assert!(markdown.contains("<html><x></html>"));
    }

    #[test]
    fn test_results_to_markdown_empty() {
        let results: Vec<Result> = vec![];
        let markdown = Result::results_to_markdown(&results, false, false);

        assert!(markdown.contains("# Dalfox Scan Results"));
        assert!(markdown.contains("**Total Findings**: 0"));
        assert!(markdown.contains("**Vulnerabilities (V)**: 0"));
        assert!(markdown.contains("**Reflections (R)**: 0"));
    }
}
