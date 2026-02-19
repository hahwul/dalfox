/// Integration test for SARIF output format
use dalfox::scanning::result::Result as ScanResult;

#[test]
fn test_sarif_output_basic_structure() {
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
    let sarif = ScanResult::results_to_sarif(&results, false, false);

    // Parse as JSON to verify structure
    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    // Verify SARIF version and schema
    assert_eq!(json["version"], "2.1.0");
    assert!(
        json["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0.json")
    );

    // Verify runs array
    assert!(json["runs"].is_array());
    let runs = json["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);

    // Verify tool information
    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"], "Dalfox");
    assert!(
        run["tool"]["driver"]["informationUri"]
            .as_str()
            .unwrap()
            .contains("github.com/hahwul/dalfox")
    );

    // Verify rules
    assert!(run["tool"]["driver"]["rules"].is_array());
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
    assert_eq!(rules[0]["id"], "dalfox/cwe-79");
    assert_eq!(rules[0]["name"], "CrossSiteScripting");

    // Verify results
    assert!(run["results"].is_array());
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert_eq!(result["ruleId"], "dalfox/cwe-79");
    assert_eq!(result["level"], "error"); // High severity maps to error
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .contains("XSS vulnerability detected")
    );
}

#[test]
fn test_sarif_output_multiple_results() {
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
    let sarif = ScanResult::results_to_sarif(&results, false, false);

    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    // Verify we have 2 results
    let run_results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(run_results.len(), 2);

    // Verify first result
    assert_eq!(run_results[0]["level"], "error"); // High
    assert!(
        run_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("q=test1")
    );

    // Verify second result
    assert_eq!(run_results[1]["level"], "warning"); // Medium
    assert!(
        run_results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("/api")
    );
}

#[test]
fn test_sarif_output_with_request_response() {
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

    result.request =
        Some("GET /?test=%3Cx%3E HTTP/1.1\nHost: example.com\nUser-Agent: Dalfox".to_string());
    result.response = Some(
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><x></body></html>".to_string(),
    );

    let results = vec![result];
    let sarif = ScanResult::results_to_sarif(&results, true, true);

    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    // Verify request and response are in properties
    let result = &json["runs"][0]["results"][0];
    assert!(
        result["properties"]["request"]
            .as_str()
            .unwrap()
            .contains("GET /?test=%3Cx%3E HTTP/1.1")
    );
    assert!(
        result["properties"]["response"]
            .as_str()
            .unwrap()
            .contains("<html><body><x></body></html>")
    );

    // Message should indicate that request/response are included
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .contains("HTTP request included")
    );
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .contains("HTTP response included")
    );
}

#[test]
fn test_sarif_output_locations() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com/path?param=value".to_string(),
        "param".to_string(),
        "<script>alert(1)</script>".to_string(),
        "Evidence text".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS found".to_string(),
    );

    let results = vec![result];
    let sarif = ScanResult::results_to_sarif(&results, false, false);

    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    let result = &json["runs"][0]["results"][0];

    // Verify locations array
    assert!(result["locations"].is_array());
    let locations = result["locations"].as_array().unwrap();
    assert_eq!(locations.len(), 1);

    // Verify physical location
    let location = &locations[0]["physicalLocation"];
    assert_eq!(
        location["artifactLocation"]["uri"],
        "https://example.com/path?param=value"
    );

    // Verify snippet contains the payload
    assert_eq!(
        location["region"]["snippet"]["text"],
        "<script>alert(1)</script>"
    );
}

#[test]
fn test_sarif_output_properties() {
    let result = ScanResult::new(
        "V".to_string(),
        "inJS".to_string(),
        "POST".to_string(),
        "https://example.com".to_string(),
        "data".to_string(),
        "alert(1)".to_string(),
        "Test evidence".to_string(),
        "CWE-79".to_string(),
        "Medium".to_string(),
        200,
        "Test message".to_string(),
    );

    let results = vec![result];
    let sarif = ScanResult::results_to_sarif(&results, false, false);

    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    let result = &json["runs"][0]["results"][0];
    let props = &result["properties"];

    // Verify all custom properties are present
    assert_eq!(props["type"], "V");
    assert_eq!(props["inject_type"], "inJS");
    assert_eq!(props["method"], "POST");
    assert_eq!(props["param"], "data");
    assert_eq!(props["payload"], "alert(1)");
    assert_eq!(props["severity"], "Medium");
}

#[test]
fn test_sarif_empty_results() {
    let results: Vec<ScanResult> = vec![];
    let sarif = ScanResult::results_to_sarif(&results, false, false);

    let json: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

    // Should still have valid SARIF structure
    assert_eq!(json["version"], "2.1.0");
    assert!(json["runs"].is_array());

    // Results should be empty array
    let run_results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(run_results.len(), 0);
}

#[test]
fn test_sarif_severity_mappings() {
    // Test all severity levels map correctly to SARIF levels
    let test_cases = vec![
        ("High", "error"),
        ("Critical", "error"),
        ("Medium", "warning"),
        ("Low", "note"),
        ("Info", "note"),
    ];

    for (severity, expected_level) in test_cases {
        let result = ScanResult::new(
            "V".to_string(),
            "inHTML".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
            "param".to_string(),
            "payload".to_string(),
            "".to_string(),
            "CWE-79".to_string(),
            severity.to_string(),
            1,
            format!("{} severity test", severity),
        );

        let results = vec![result];
        let sarif = ScanResult::results_to_sarif(&results, false, false);

        let json: serde_json::Value =
            serde_json::from_str(&sarif).expect("SARIF should be valid JSON");

        let result_level = json["runs"][0]["results"][0]["level"]
            .as_str()
            .expect("Level should be a string");

        assert_eq!(
            result_level, expected_level,
            "Severity {} should map to level {}",
            severity, expected_level
        );
    }
}
