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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(result.param, "q");
        assert_eq!(result.severity, "High");
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
        assert!(json.contains("\"param\":\"query\""));
    }
}
