/// Integration test for markdown output format
use dalfox::scanning::result::Result as ScanResult;

#[test]
fn test_markdown_output_single_result() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com?q=test".to_string(),
        "q".to_string(),
        "<script>alert(1)</script>".to_string(),
        "XSS script tag found".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS vulnerability detected".to_string(),
    );

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false);

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
    let result1 = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com?q=test1".to_string(),
        "q".to_string(),
        "<img src=x onerror=alert(1)>".to_string(),
        "XSS in image tag".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS detected".to_string(),
    );

    let result2 = ScanResult::new(
        "R".to_string(),
        "inJS".to_string(),
        "POST".to_string(),
        "https://example.com/api".to_string(),
        "callback".to_string(),
        "alert(2)".to_string(),
        "Reflection in JavaScript".to_string(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        200,
        "Reflection found".to_string(),
    );

    let results = vec![result1, result2];
    let markdown = ScanResult::results_to_markdown(&results, false, false);

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
    let mut result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com?test=xss".to_string(),
        "test".to_string(),
        "<x>".to_string(),
        "test evidence".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS".to_string(),
    );

    result.request = Some("GET /?test=%3Cx%3E HTTP/1.1\nHost: example.com\nUser-Agent: Dalfox".to_string());
    result.response = Some("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><x></body></html>".to_string());

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, true, true);

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
    let mut result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "test".to_string(),
        "<x>".to_string(),
        "evidence".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS".to_string(),
    );

    result.request = Some("GET / HTTP/1.1".to_string());
    result.response = Some("HTTP/1.1 200 OK".to_string());

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false);

    // Verify request/response are NOT included when flags are false
    assert!(!markdown.contains("**Request:**"));
    assert!(!markdown.contains("**Response:**"));
    assert!(!markdown.contains("GET / HTTP/1.1"));
    assert!(!markdown.contains("HTTP/1.1 200 OK"));
}

#[test]
fn test_markdown_output_special_characters() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "param|with|pipes".to_string(),
        "payload|with|pipes".to_string(),
        "evidence|test".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS".to_string(),
    );

    let results = vec![result];
    let markdown = ScanResult::results_to_markdown(&results, false, false);

    // Verify pipe characters are properly escaped in payload and evidence
    assert!(markdown.contains("payload\\|with\\|pipes"));
    assert!(markdown.contains("evidence\\|test"));
    // Parameter is in code block so doesn't need escaping
    assert!(markdown.contains("`param|with|pipes`"));
}

#[test]
fn test_markdown_output_empty_results() {
    let results: Vec<ScanResult> = vec![];
    let markdown = ScanResult::results_to_markdown(&results, false, false);

    // Verify empty results still produce valid markdown
    assert!(markdown.contains("# Dalfox Scan Results"));
    assert!(markdown.contains("## Summary"));
    assert!(markdown.contains("**Total Findings**: 0"));
    assert!(markdown.contains("**Vulnerabilities (V)**: 0"));
    assert!(markdown.contains("**Reflections (R)**: 0"));
}
