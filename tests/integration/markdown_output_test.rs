/// Integration test for markdown output format
use dalfox::scanning::result::Result as ScanResult;

#[test]
fn test_markdown_output_single_result() {
    let result = ScanResult::builder(dalfox::scanning::result::FindingType::Verified)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com?q=test")
        .param("q")
        .payload("<script>alert(1)</script>")
        .evidence("XSS script tag found")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("XSS vulnerability detected")
        .build();

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false, None);

    // Verify main sections exist
    assert!(markdown.contains("# Dalfox Scan Results"));
    assert!(markdown.contains("## Summary"));
    assert!(markdown.contains("## Findings"));

    // Verify summary counts
    assert!(markdown.contains("**Total Findings**: 1"));
    assert!(markdown.contains("**Vulnerabilities (V)**: 1"));
    assert!(markdown.contains("**Reflections (R)**: 0"));

    // Verify finding details
    assert!(markdown.contains("### 1. Vulnerability - q (inHTML)"));
    assert!(markdown.contains("| **Type** | V |"));
    assert!(markdown.contains("| **Parameter** | `q` |"));
    assert!(markdown.contains("| **Method** | GET |"));
    assert!(markdown.contains("| **Severity** | High |"));
    assert!(markdown.contains("| **CWE** | CWE-79 |"));
    assert!(markdown.contains("<script>alert(1)</script>"));
}

#[test]
fn test_markdown_output_multiple_results() {
    let result1 = ScanResult::builder(dalfox::scanning::result::FindingType::Verified)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com?q=test1")
        .param("q")
        .payload("<img src=x onerror=alert(1)>")
        .evidence("XSS in image tag")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("XSS detected")
        .build();

    let result2 = ScanResult::builder(dalfox::scanning::result::FindingType::Reflected)
        .inject_type("inJS")
        .method("POST")
        .data("https://example.com/api")
        .param("callback")
        .payload("alert(2)")
        .evidence("Reflection in JavaScript")
        .cwe("CWE-79")
        .severity("Medium")
        .message_id(200)
        .message_str("Reflection found")
        .build();

    let results = vec![result1, result2];
    let markdown = ScanResult::results_to_markdown(&results, false, false, None);

    // Verify summary counts
    assert!(markdown.contains("**Total Findings**: 2"));
    assert!(markdown.contains("**Vulnerabilities (V)**: 1"));
    assert!(markdown.contains("**Reflections (R)**: 1"));

    // Verify both findings are present
    assert!(markdown.contains("### 1. Vulnerability - q (inHTML)"));
    assert!(markdown.contains("### 2. Reflection - callback (inJS)"));

    // Verify separators
    assert!(markdown.matches("---").count() >= 2);
}

#[test]
fn test_markdown_output_with_request_response() {
    let mut result = ScanResult::builder(dalfox::scanning::result::FindingType::Verified)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com?test=xss")
        .param("test")
        .payload("<x>")
        .evidence("test evidence")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("XSS")
        .build();

    result.request =
        Some("GET /?test=%3Cx%3E HTTP/1.1\nHost: example.com\nUser-Agent: Dalfox".to_string());
    result.response = Some(
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><x></body></html>".to_string(),
    );

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, true, true, None);

    // Verify request section is included
    assert!(markdown.contains("**Request:**"));
    assert!(markdown.contains("```http"));
    assert!(markdown.contains("GET /?test=%3Cx%3E HTTP/1.1"));
    assert!(markdown.contains("Host: example.com"));

    // Verify response section is included
    assert!(markdown.contains("**Response:**"));
    assert!(markdown.contains("<html><body><x></body></html>"));
}

#[test]
fn test_markdown_output_without_request_response() {
    let mut result = ScanResult::builder(dalfox::scanning::result::FindingType::Verified)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("test")
        .payload("<x>")
        .evidence("evidence")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("XSS")
        .build();

    result.request = Some("GET / HTTP/1.1".to_string());
    result.response = Some("HTTP/1.1 200 OK".to_string());

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false, None);

    // Verify request/response are NOT included when flags are false
    assert!(!markdown.contains("**Request:**"));
    assert!(!markdown.contains("**Response:**"));
    assert!(!markdown.contains("GET / HTTP/1.1"));
    assert!(!markdown.contains("HTTP/1.1 200 OK"));
}

#[test]
fn test_markdown_output_special_characters() {
    let result = ScanResult::builder(dalfox::scanning::result::FindingType::Verified)
        .inject_type("inHTML")
        .method("GET")
        .data("https://example.com")
        .param("param|with|pipes")
        .payload("payload|with|pipes")
        .evidence("evidence|test")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("XSS")
        .build();

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false, None);

    // Verify pipe characters are properly escaped in payload and evidence
    assert!(markdown.contains("payload\\|with\\|pipes"));
    assert!(markdown.contains("evidence\\|test"));
    // Parameter is in code block so doesn't need escaping
    assert!(markdown.contains("`param|with|pipes`"));
}

#[test]
fn test_markdown_output_empty_results() {
    let results: Vec<ScanResult> = vec![];
    let markdown = ScanResult::results_to_markdown(&results, false, false, None);

    // Verify empty results still produce valid markdown
    assert!(markdown.contains("# Dalfox Scan Results"));
    assert!(markdown.contains("## Summary"));
    assert!(markdown.contains("**Total Findings**: 0"));
    assert!(markdown.contains("**Vulnerabilities (V)**: 0"));
    assert!(markdown.contains("**Reflections (R)**: 0"));
}
