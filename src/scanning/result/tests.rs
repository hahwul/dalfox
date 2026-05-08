use super::*;
use serde_json;

#[test]
fn test_result_creation() {
    let result = Result::new(
        FindingType::Verified,
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

    assert_eq!(result.result_type, FindingType::Verified);
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
        FindingType::Verified,
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

    assert_eq!(result.result_type, FindingType::Verified);
    assert_eq!(result.severity, "Medium");
    assert!(result.request.is_some());
    assert!(result.response.is_some());
    assert!(result.request.as_ref().unwrap().contains("POST"));
    assert!(result.response.as_ref().unwrap().contains("200 OK"));
}

#[test]
fn test_result_serialization() {
    let result = Result::new(
        FindingType::Verified,
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
    assert_eq!(result.result_type, FindingType::Verified);
    assert_eq!(result.param, "q");
    assert_eq!(result.severity, "High");
    assert_eq!(result.message_id, 200);
}

#[test]
fn test_result_deserialization_reflected() {
    let json = r#"{
        "type": "R",
        "inject_type": "inHTML",
        "method": "GET",
        "data": "https://example.com",
        "param": "q",
        "payload": "test",
        "evidence": "Reflected",
        "cwe": "CWE-79",
        "severity": "Info",
        "message_id": 100,
        "message_str": "Reflection found"
    }"#;

    let result: Result = serde_json::from_str(json).unwrap();
    assert_eq!(result.result_type, FindingType::Reflected);
}

#[test]
fn test_result_deserialization_ast_detected() {
    let json = r#"{
        "type": "A",
        "inject_type": "DOM-XSS",
        "method": "GET",
        "data": "https://example.com",
        "param": "-",
        "payload": "alert(1)",
        "evidence": "AST finding",
        "cwe": "CWE-79",
        "severity": "Medium",
        "message_id": 0,
        "message_str": "AST DOM XSS"
    }"#;

    let result: Result = serde_json::from_str(json).unwrap();
    assert_eq!(result.result_type, FindingType::AstDetected);
}

#[test]
fn test_result_different_types() {
    let reflected = Result::new(
        FindingType::Reflected,
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
        FindingType::Verified,
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

    assert_eq!(reflected.result_type, FindingType::Reflected);
    assert_eq!(reflected.severity, "Info");
    assert_eq!(vulnerable.result_type, FindingType::Verified);
    assert_eq!(vulnerable.severity, "High");
    assert_ne!(reflected.result_type, vulnerable.result_type);
}

#[test]
fn test_result_edge_cases() {
    // Empty strings (except result_type which is now an enum)
    let result = Result::new(
        FindingType::Reflected,
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

    assert_eq!(result.result_type, FindingType::Reflected);
    assert_eq!(result.message_id, 0);

    // Special characters
    let result = Result::new(
        FindingType::Verified,
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
        FindingType::Verified,
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
        FindingType::Reflected,
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
        FindingType::Verified,
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

#[test]
fn test_results_to_sarif_basic() {
    let result = Result::new(
        FindingType::Verified,
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

    let results = vec![result];
    let sarif = Result::results_to_sarif(&results, false, false);

    // Verify SARIF structure
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("\"$schema\""));
    assert!(sarif.contains("sarif-schema-2.1.0.json"));
    assert!(sarif.contains("\"runs\""));
    assert!(sarif.contains("\"tool\""));
    assert!(sarif.contains("\"driver\""));
    assert!(sarif.contains("\"name\": \"Dalfox\""));
    assert!(sarif.contains("\"results\""));

    // Verify result content
    assert!(sarif.contains("\"ruleId\": \"dalfox/cwe-79\""));
    assert!(sarif.contains("\"level\": \"error\""));
    assert!(sarif.contains("XSS detected"));
    assert!(sarif.contains("https://example.com?q=test"));
    assert!(sarif.contains("<script>alert(1)</script>"));

    // Verify properties
    assert!(sarif.contains("\"type\": \"V\""));
    assert!(sarif.contains("\"inject_type\": \"inHTML\""));
    assert!(sarif.contains("\"method\": \"GET\""));
    assert!(sarif.contains("\"param\": \"q\""));
    assert!(sarif.contains("\"severity\": \"High\""));
    // Stable fingerprint key present and a 16-char hex value, not the
    // catalog message_id.
    assert!(sarif.contains("\"vulnIdentity/v1\""));
    assert!(!sarif.contains("\"messageId\": \"606\""));
}

/// SARIF consumers (e.g. GitHub code scanning) dedupe re-runs by matching
/// `partialFingerprints`. Two findings produced by different payload
/// variants for the same vulnerability identity (target + param +
/// inject_type + cwe) must therefore share a fingerprint.
#[test]
fn test_results_to_sarif_fingerprint_stable_across_payload_variants() {
    let mk = |payload: &str, data: &str| {
        Result::new(
            FindingType::Reflected,
            "inHTML".to_string(),
            "GET".to_string(),
            data.to_string(),
            "q".to_string(),
            payload.to_string(),
            "".to_string(),
            "CWE-79".to_string(),
            "Info".to_string(),
            606,
            "X".to_string(),
        )
    };
    let a = mk("<svg/onload=alert(1)>", "https://h/s?q=%3Csvg%3E");
    let b = mk("<img src=x onerror=alert(1)>", "https://h/s?q=%3Cimg%3E");
    let sarif_a = Result::results_to_sarif(&[a], false, false);
    let sarif_b = Result::results_to_sarif(&[b], false, false);
    let extract_fp = |s: &str| -> String {
        let key = "\"vulnIdentity/v1\": \"";
        let i = s.find(key).expect("fingerprint key present");
        let rest = &s[i + key.len()..];
        let end = rest.find('"').expect("closing quote");
        rest[..end].to_string()
    };
    assert_eq!(extract_fp(&sarif_a), extract_fp(&sarif_b));
}

/// Distinct vulnerabilities must have distinct fingerprints — otherwise
/// SARIF consumers would collapse independent findings.
#[test]
fn test_results_to_sarif_fingerprint_distinct_for_different_targets() {
    let mk = |data: &str, param: &str| {
        Result::new(
            FindingType::Verified,
            "inHTML".to_string(),
            "GET".to_string(),
            data.to_string(),
            param.to_string(),
            "p".to_string(),
            "".to_string(),
            "CWE-79".to_string(),
            "High".to_string(),
            606,
            "X".to_string(),
        )
    };
    let a = Result::results_to_sarif(&[mk("https://h/a?q=x", "q")], false, false);
    let b = Result::results_to_sarif(&[mk("https://h/b?q=x", "q")], false, false);
    let extract_fp = |s: &str| -> String {
        let key = "\"vulnIdentity/v1\": \"";
        let i = s.find(key).expect("fingerprint key present");
        let rest = &s[i + key.len()..];
        let end = rest.find('"').expect("closing quote");
        rest[..end].to_string()
    };
    assert_ne!(extract_fp(&a), extract_fp(&b));
}

#[test]
fn test_results_to_sarif_with_request_response() {
    let mut result = Result::new(
        FindingType::Verified,
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
    let sarif = Result::results_to_sarif(&results, true, true);

    // Verify request and response are included in properties
    assert!(sarif.contains("\"request\""));
    assert!(sarif.contains("GET /?test=%3Cx%3E HTTP/1.1"));
    assert!(sarif.contains("\"response\""));
    assert!(sarif.contains("<html><x></html>"));
}

#[test]
fn test_results_to_sarif_severity_levels() {
    let high = Result::new(
        FindingType::Verified,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "p1".to_string(),
        "payload".to_string(),
        "".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        1,
        "High severity".to_string(),
    );

    let medium = Result::new(
        FindingType::Verified,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "p2".to_string(),
        "payload".to_string(),
        "".to_string(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        2,
        "Medium severity".to_string(),
    );

    let low = Result::new(
        FindingType::Reflected,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "p3".to_string(),
        "payload".to_string(),
        "".to_string(),
        "CWE-79".to_string(),
        "Low".to_string(),
        3,
        "Low severity".to_string(),
    );

    // Test each severity level mapping
    let sarif_high = Result::results_to_sarif(&[high], false, false);
    assert!(sarif_high.contains("\"level\": \"error\""));

    let sarif_medium = Result::results_to_sarif(&[medium], false, false);
    assert!(sarif_medium.contains("\"level\": \"warning\""));

    let sarif_low = Result::results_to_sarif(&[low], false, false);
    assert!(sarif_low.contains("\"level\": \"note\""));
}

#[test]
fn test_results_to_sarif_empty() {
    let results: Vec<Result> = vec![];
    let sarif = Result::results_to_sarif(&results, false, false);

    // Should still be valid SARIF with empty results array
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("\"results\": []"));
}

#[test]
fn test_results_to_toml() {
    let result = Result::new(
        FindingType::Verified,
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

    let results = vec![result];
    let toml_output = Result::results_to_toml(&results, false, false);

    assert!(toml_output.contains("type = \"V\""));
    assert!(toml_output.contains("inject_type = \"inHTML\""));
    assert!(toml_output.contains("method = \"GET\""));
    assert!(toml_output.contains("param = \"q\""));
    assert!(toml_output.contains("payload = \"<script>alert(1)</script>\""));
    assert!(toml_output.contains("severity = \"High\""));
    assert!(toml_output.contains("message_id = 606"));
}

#[test]
fn test_results_to_sarif_valid_json() {
    let result = Result::new(
        FindingType::Verified,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "payload".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "message".to_string(),
    );

    let results = vec![result];
    let sarif = Result::results_to_sarif(&results, false, false);

    // Should be valid JSON
    let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&sarif);
    assert!(parsed.is_ok(), "SARIF output should be valid JSON");

    if let Ok(json) = parsed {
        // Verify required SARIF fields
        assert_eq!(json["version"], "2.1.0");
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"].as_array().unwrap().len(), 1);

        let run = &json["runs"][0];
        assert!(run["tool"].is_object());
        assert!(run["results"].is_array());
    }
}

#[test]
fn test_to_json_value_respects_include_flags() {
    let mut result = Result::new(
        FindingType::Verified,
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "payload".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        1,
        "message".to_string(),
    );
    result.request = Some("GET / HTTP/1.1".to_string());
    result.response = Some("HTTP/1.1 200 OK".to_string());

    let with_all = result.to_json_value(true, true);
    assert_eq!(with_all["request"], "GET / HTTP/1.1");
    assert_eq!(with_all["response"], "HTTP/1.1 200 OK");
    assert_eq!(
        with_all["type_description"],
        "Verified XSS - payload confirmed executed in parsed DOM"
    );

    let without_optional = result.to_json_value(false, false);
    assert!(without_optional.get("request").is_none());
    assert!(without_optional.get("response").is_none());
    // type_description always present
    assert!(without_optional.get("type_description").is_some());
}

#[test]
fn test_results_to_json_compact_and_jsonl() {
    let mut result = Result::new(
        FindingType::Reflected,
        "inJS".to_string(),
        "POST".to_string(),
        "https://example.com/api".to_string(),
        "data".to_string(),
        "alert(1)".to_string(),
        "reflected".to_string(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        2,
        "reflection".to_string(),
    );
    result.request = Some("POST /api HTTP/1.1".to_string());

    let results = vec![result];
    let compact = Result::results_to_json(&results, true, false, false);
    assert!(compact.starts_with("["));
    assert!(compact.contains("\"request\":\"POST /api HTTP/1.1\""));

    let jsonl = Result::results_to_jsonl(&results, true, false);
    assert!(jsonl.contains("\"type\":\"R\""));
    assert!(jsonl.ends_with('\n'));
}
