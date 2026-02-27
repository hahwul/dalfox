/// Validation test to ensure SARIF output conforms to the specification
use dalfox::scanning::result::Result as ScanResult;
use serde_json::Value;

#[test]
fn test_sarif_schema_compliance() {
    // Create a comprehensive result with all possible fields
    let mut result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com/test?param=value".to_string(),
        "param".to_string(),
        "<script>alert('XSS')</script>".to_string(),
        "Script tag found in HTML response".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "Cross-site scripting vulnerability detected".to_string(),
    );

    result.request = Some("GET /test?param=value HTTP/1.1\nHost: example.com".to_string());
    result.response = Some("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html></html>".to_string());

    let results = vec![result];
    let sarif = ScanResult::results_to_sarif(&results, true, true);

    // Parse the SARIF output
    let json: Value = serde_json::from_str(&sarif).expect("SARIF output should be valid JSON");

    // Validate required top-level properties according to SARIF 2.1.0 spec
    assert_eq!(json["version"], "2.1.0", "Version must be 2.1.0");
    assert!(json["$schema"].is_string(), "$schema must be present");
    assert!(json["runs"].is_array(), "runs must be an array");

    // Validate runs array
    let runs = json["runs"].as_array().unwrap();
    assert!(!runs.is_empty(), "runs array must not be empty");

    // Validate run object
    let run = &runs[0];
    assert!(run["tool"].is_object(), "tool must be an object");
    assert!(run["results"].is_array(), "results must be an array");

    // Validate tool.driver
    let driver = &run["tool"]["driver"];
    assert!(driver["name"].is_string(), "driver.name must be a string");
    assert_eq!(driver["name"], "Dalfox", "driver.name should be Dalfox");
    assert!(
        driver["informationUri"].is_string(),
        "driver.informationUri must be present"
    );
    assert!(
        driver["version"].is_string(),
        "driver.version must be present"
    );
    assert!(driver["rules"].is_array(), "driver.rules must be an array");

    // Validate rules
    let rules = driver["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "rules array must not be empty");

    let rule = &rules[0];
    assert!(rule["id"].is_string(), "rule.id must be a string");
    assert!(rule["name"].is_string(), "rule.name must be a string");
    assert!(
        rule["shortDescription"].is_object(),
        "rule.shortDescription must be an object"
    );
    assert!(
        rule["shortDescription"]["text"].is_string(),
        "rule.shortDescription.text must be a string"
    );
    assert!(
        rule["fullDescription"].is_object(),
        "rule.fullDescription must be an object"
    );
    assert!(rule["help"].is_object(), "rule.help must be an object");

    // Validate results
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "Should have exactly 1 result");

    let result = &results[0];
    assert!(
        result["ruleId"].is_string(),
        "result.ruleId must be a string"
    );
    assert!(result["level"].is_string(), "result.level must be a string");
    assert!(
        result["message"].is_object(),
        "result.message must be an object"
    );
    assert!(
        result["message"]["text"].is_string(),
        "result.message.text must be a string"
    );
    assert!(
        result["locations"].is_array(),
        "result.locations must be an array"
    );

    // Validate level is one of the allowed values
    let level = result["level"].as_str().unwrap();
    assert!(
        matches!(level, "error" | "warning" | "note" | "none"),
        "level must be one of: error, warning, note, none. Got: {}",
        level
    );

    // Validate locations
    let locations = result["locations"].as_array().unwrap();
    assert!(!locations.is_empty(), "locations array must not be empty");

    let location = &locations[0];
    assert!(
        location["physicalLocation"].is_object(),
        "location.physicalLocation must be an object"
    );

    let physical_location = &location["physicalLocation"];
    assert!(
        physical_location["artifactLocation"].is_object(),
        "artifactLocation must be an object"
    );
    assert!(
        physical_location["artifactLocation"]["uri"].is_string(),
        "uri must be a string"
    );

    // Validate properties
    assert!(
        result["properties"].is_object(),
        "result.properties must be an object"
    );
    let props = result["properties"].as_object().unwrap();

    // Verify custom properties are present
    assert!(
        props.contains_key("type"),
        "properties should contain 'type'"
    );
    assert!(
        props.contains_key("inject_type"),
        "properties should contain 'inject_type'"
    );
    assert!(
        props.contains_key("method"),
        "properties should contain 'method'"
    );
    assert!(
        props.contains_key("param"),
        "properties should contain 'param'"
    );
    assert!(
        props.contains_key("payload"),
        "properties should contain 'payload'"
    );
    assert!(
        props.contains_key("severity"),
        "properties should contain 'severity'"
    );

    // When include_request and include_response are true
    assert!(
        props.contains_key("request"),
        "properties should contain 'request'"
    );
    assert!(
        props.contains_key("response"),
        "properties should contain 'response'"
    );
}

#[test]
fn test_sarif_severity_to_level_mapping() {
    let test_cases = vec![
        ("High", "error"),
        ("Critical", "error"),
        ("CRITICAL", "error"),
        ("Medium", "warning"),
        ("MEDIUM", "warning"),
        ("Low", "note"),
        ("Info", "note"),
        ("low", "note"),
        ("unknown", "warning"), // Default case
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
            "test".to_string(),
        );

        let sarif = ScanResult::results_to_sarif(&[result], false, false);
        let json: Value = serde_json::from_str(&sarif).unwrap();

        let actual_level = json["runs"][0]["results"][0]["level"].as_str().unwrap();
        assert_eq!(
            actual_level, expected_level,
            "Severity '{}' should map to level '{}'",
            severity, expected_level
        );
    }
}

#[test]
fn test_sarif_message_with_evidence() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "payload".to_string(),
        "Found unescaped output".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        606,
        "XSS detected".to_string(),
    );

    let sarif = ScanResult::results_to_sarif(&[result], false, false);
    let json: Value = serde_json::from_str(&sarif).unwrap();

    let message = json["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .unwrap();

    // Message should contain both the main message and evidence
    assert!(
        message.contains("XSS detected"),
        "Message should contain main text"
    );
    assert!(
        message.contains("Evidence: Found unescaped output"),
        "Message should contain evidence"
    );
}

#[test]
fn test_sarif_partial_fingerprints() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "payload".to_string(),
        "".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        12345,
        "test".to_string(),
    );

    let sarif = ScanResult::results_to_sarif(&[result], false, false);
    let json: Value = serde_json::from_str(&sarif).unwrap();

    let fingerprints = &json["runs"][0]["results"][0]["partialFingerprints"];
    assert!(
        fingerprints.is_object(),
        "partialFingerprints should be an object"
    );
    assert_eq!(
        fingerprints["messageId"], "12345",
        "messageId should be included"
    );
}

#[test]
fn test_sarif_rule_metadata() {
    let result = ScanResult::new(
        "V".to_string(),
        "inHTML".to_string(),
        "GET".to_string(),
        "https://example.com".to_string(),
        "q".to_string(),
        "payload".to_string(),
        "".to_string(),
        "CWE-79".to_string(),
        "High".to_string(),
        1,
        "test".to_string(),
    );

    let sarif = ScanResult::results_to_sarif(&[result], false, false);
    let json: Value = serde_json::from_str(&sarif).unwrap();

    let rule = &json["runs"][0]["tool"]["driver"]["rules"][0];

    // Verify rule has all required metadata
    assert_eq!(rule["id"], "dalfox/cwe-79");
    assert_eq!(rule["name"], "CrossSiteScripting");
    assert!(
        rule["shortDescription"]["text"]
            .as_str()
            .unwrap()
            .contains("XSS")
    );
    assert!(!rule["fullDescription"]["text"].as_str().unwrap().is_empty());
    assert!(!rule["help"]["text"].as_str().unwrap().is_empty());
    assert_eq!(rule["defaultConfiguration"]["level"], "error");

    // Verify tags
    let tags = rule["properties"]["tags"].as_array().unwrap();
    assert!(tags.contains(&Value::String("security".to_string())));
    assert!(tags.contains(&Value::String("xss".to_string())));
    assert!(tags.contains(&Value::String("injection".to_string())));
}
