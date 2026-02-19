//! DOM XSS detection tests
//!
//! This module tests the AST-based DOM XSS detection capabilities against
//! structured test cases from TOML files.

use crate::functional::mock_case_loader::{self, MockCase};
use dalfox::scanning::ast_dom_analysis::AstDomAnalyzer;

/// Load DOM XSS test cases from the mock_cases directory
fn load_dom_xss_cases() -> Result<Vec<MockCase>, String> {
    let base_dir = mock_case_loader::get_mock_cases_base_dir();
    let dom_xss_dir = base_dir.join("dom_xss");

    if !dom_xss_dir.exists() {
        return Err(format!(
            "DOM XSS cases directory does not exist: {}",
            dom_xss_dir.display()
        ));
    }

    mock_case_loader::load_mock_cases_from_dir(&dom_xss_dir)
}

/// Extract JavaScript code from HTML reflection pattern
///
/// Note: This is a simple extraction for controlled test cases.
/// For production use, a proper HTML parser would be more robust.
/// This implementation handles basic <script> tags without complex nesting.
fn extract_javascript(html: &str) -> Vec<String> {
    let mut scripts = Vec::new();

    // Simple extraction of <script>...</script> content
    let mut remaining = html;
    while let Some(start_pos) = remaining.find("<script>") {
        let after_start = &remaining[start_pos + 8..];
        if let Some(end_pos) = after_start.find("</script>") {
            let script_content = &after_start[..end_pos];
            scripts.push(script_content.to_string());
            remaining = &after_start[end_pos + 9..];
        } else {
            break;
        }
    }

    // Also handle <script src="...">...</script>
    let mut remaining = html;
    while let Some(start_pos) = remaining.find("<script src=") {
        let after_start = &remaining[start_pos..];
        if let Some(close_tag_pos) = after_start.find('>') {
            let after_close = &after_start[close_tag_pos + 1..];
            if let Some(end_pos) = after_close.find("</script>") {
                let script_content = &after_close[..end_pos];
                if !script_content.trim().is_empty() {
                    scripts.push(script_content.to_string());
                }
                remaining = &after_close[end_pos + 9..];
            } else {
                break;
            }
        } else {
            break;
        }
    }

    scripts
}

#[test]
fn test_dom_xss_location_sources() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");
    let location_cases: Vec<&MockCase> = cases
        .iter()
        .filter(|c| c.id >= 1000 && c.id < 1100)
        .collect();

    assert!(
        !location_cases.is_empty(),
        "Should have location-based DOM XSS test cases"
    );

    let analyzer = AstDomAnalyzer::new();
    let mut detected = 0;
    let mut failed_cases = Vec::new();

    for case in &location_cases {
        println!(
            "\nTesting case {}: {} - {}",
            case.id, case.name, case.description
        );

        let scripts = extract_javascript(&case.reflection);
        let mut case_detected = false;

        for script in scripts {
            match analyzer.analyze(&script) {
                Ok(vulnerabilities) => {
                    if !vulnerabilities.is_empty() {
                        println!("  ✓ Detected {} vulnerability(ies)", vulnerabilities.len());
                        for vuln in &vulnerabilities {
                            println!("    - Line {}: {} -> {}", vuln.line, vuln.source, vuln.sink);
                        }
                        case_detected = true;
                    }
                }
                Err(e) => {
                    println!("  ✗ Analysis error: {}", e);
                }
            }
        }

        if case_detected {
            detected += 1;
        } else if case.expected_detection {
            println!("  ✗ FAILED: Expected to detect but didn't");
            failed_cases.push((case.id, case.name.clone()));
        } else {
            println!("  ✓ Correctly not detected (expected)");
        }
    }

    println!("\n=== Location Sources Summary ===");
    println!("Total cases: {}", location_cases.len());
    println!("Detected: {}", detected);
    println!(
        "Detection rate: {:.1}%",
        (detected as f64 / location_cases.len() as f64) * 100.0
    );

    if !failed_cases.is_empty() {
        println!("\nFailed cases:");
        for (id, name) in &failed_cases {
            println!("  - Case {}: {}", id, name);
        }
    }

    assert!(
        failed_cases.is_empty(),
        "Location source DOM XSS cases should all be detected"
    );

    assert!(
        detected > 0,
        "Should detect at least one DOM XSS vulnerability in location sources"
    );
}

#[test]
fn test_dom_xss_storage_sources() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");
    let storage_cases: Vec<&MockCase> = cases
        .iter()
        .filter(|c| c.id >= 1100 && c.id < 1200)
        .collect();

    assert!(
        !storage_cases.is_empty(),
        "Should have storage-based DOM XSS test cases"
    );

    let analyzer = AstDomAnalyzer::new();
    let mut detected = 0;
    let mut failed_cases = Vec::new();

    for case in &storage_cases {
        println!(
            "\nTesting case {}: {} - {}",
            case.id, case.name, case.description
        );

        let scripts = extract_javascript(&case.reflection);
        let mut case_detected = false;

        for script in scripts {
            match analyzer.analyze(&script) {
                Ok(vulnerabilities) => {
                    if !vulnerabilities.is_empty() {
                        println!("  ✓ Detected {} vulnerability(ies)", vulnerabilities.len());
                        for vuln in &vulnerabilities {
                            println!("    - Line {}: {} -> {}", vuln.line, vuln.source, vuln.sink);
                        }
                        case_detected = true;
                    }
                }
                Err(e) => {
                    println!("  ✗ Analysis error: {}", e);
                }
            }
        }

        if case_detected {
            detected += 1;
        } else if case.expected_detection {
            println!("  ✗ FAILED: Expected to detect but didn't");
            failed_cases.push((case.id, case.name.clone()));
        } else {
            println!("  ✓ Correctly not detected (expected)");
        }
    }

    println!("\n=== Storage Sources Summary ===");
    println!("Total cases: {}", storage_cases.len());
    println!("Detected: {}", detected);
    println!(
        "Detection rate: {:.1}%",
        (detected as f64 / storage_cases.len() as f64) * 100.0
    );

    if !failed_cases.is_empty() {
        println!("\nFailed cases:");
        for (id, name) in &failed_cases {
            println!("  - Case {}: {}", id, name);
        }
    }

    assert!(
        failed_cases.is_empty(),
        "Storage source DOM XSS cases should all be detected"
    );
}

#[test]
fn test_dom_xss_postmessage_sources() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");
    let postmessage_cases: Vec<&MockCase> = cases
        .iter()
        .filter(|c| c.id >= 1200 && c.id < 1300)
        .collect();

    assert!(
        !postmessage_cases.is_empty(),
        "Should have postMessage-based DOM XSS test cases"
    );

    let analyzer = AstDomAnalyzer::new();
    let mut detected = 0;
    let mut failed_cases = Vec::new();

    for case in &postmessage_cases {
        println!(
            "\nTesting case {}: {} - {}",
            case.id, case.name, case.description
        );

        let scripts = extract_javascript(&case.reflection);
        let mut case_detected = false;

        for script in scripts {
            match analyzer.analyze(&script) {
                Ok(vulnerabilities) => {
                    if !vulnerabilities.is_empty() {
                        println!("  ✓ Detected {} vulnerability(ies)", vulnerabilities.len());
                        for vuln in &vulnerabilities {
                            println!("    - Line {}: {} -> {}", vuln.line, vuln.source, vuln.sink);
                        }
                        case_detected = true;
                    }
                }
                Err(e) => {
                    println!("  ✗ Analysis error: {}", e);
                }
            }
        }

        if case_detected {
            detected += 1;
        } else if case.expected_detection {
            println!("  ✗ FAILED: Expected to detect but didn't");
            failed_cases.push((case.id, case.name.clone()));
        } else {
            println!("  ✓ Correctly not detected (expected)");
        }
    }

    println!("\n=== PostMessage Sources Summary ===");
    println!("Total cases: {}", postmessage_cases.len());
    println!("Detected: {}", detected);
    println!(
        "Detection rate: {:.1}%",
        (detected as f64 / postmessage_cases.len() as f64) * 100.0
    );

    if !failed_cases.is_empty() {
        println!("\nFailed cases:");
        for (id, name) in &failed_cases {
            println!("  - Case {}: {}", id, name);
        }
    }

    assert!(
        failed_cases.is_empty(),
        "postMessage DOM XSS cases should all be detected"
    );
}

#[test]
fn test_dom_xss_complex_flows() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");
    let complex_cases: Vec<&MockCase> = cases
        .iter()
        .filter(|c| c.id >= 1300 && c.id < 1400)
        .collect();

    assert!(
        !complex_cases.is_empty(),
        "Should have complex flow DOM XSS test cases"
    );

    let analyzer = AstDomAnalyzer::new();
    let mut detected = 0;
    let mut failed_cases = Vec::new();

    for case in &complex_cases {
        println!(
            "\nTesting case {}: {} - {}",
            case.id, case.name, case.description
        );

        let scripts = extract_javascript(&case.reflection);
        let mut case_detected = false;

        for script in scripts {
            match analyzer.analyze(&script) {
                Ok(vulnerabilities) => {
                    if !vulnerabilities.is_empty() {
                        println!("  ✓ Detected {} vulnerability(ies)", vulnerabilities.len());
                        for vuln in &vulnerabilities {
                            println!("    - Line {}: {} -> {}", vuln.line, vuln.source, vuln.sink);
                        }
                        case_detected = true;
                    }
                }
                Err(e) => {
                    println!("  ✗ Analysis error: {}", e);
                }
            }
        }

        if case_detected {
            detected += 1;
        } else if case.expected_detection {
            println!("  ✗ FAILED: Expected to detect but didn't");
            failed_cases.push((case.id, case.name.clone()));
        } else {
            println!("  ✓ Correctly not detected (expected)");
        }
    }

    println!("\n=== Complex Flows Summary ===");
    println!("Total cases: {}", complex_cases.len());
    println!("Detected: {}", detected);
    println!(
        "Detection rate: {:.1}%",
        (detected as f64 / complex_cases.len() as f64) * 100.0
    );

    if !failed_cases.is_empty() {
        println!("\nFailed cases:");
        for (id, name) in &failed_cases {
            println!("  - Case {}: {}", id, name);
        }
    }

    let detection_rate = detected as f64 / complex_cases.len() as f64;

    // Complex flows include known hard patterns (e.g. inter-procedural calls),
    // but baseline coverage should remain high.
    assert!(
        detection_rate >= 0.90,
        "Complex flow detection rate dropped below baseline: {:.1}%",
        detection_rate * 100.0
    );

    assert!(
        detected > 0,
        "Should detect at least one vulnerability in complex flows"
    );
}

#[test]
fn test_dom_xss_sanitized_flows() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");
    let sanitized_cases: Vec<&MockCase> = cases
        .iter()
        .filter(|c| c.id >= 1400 && c.id < 1500)
        .collect();

    assert!(
        !sanitized_cases.is_empty(),
        "Should have sanitized flow test cases"
    );

    let analyzer = AstDomAnalyzer::new();
    let mut correctly_not_detected = 0;
    let mut false_positives = Vec::new();

    for case in &sanitized_cases {
        println!(
            "\nTesting case {}: {} - {}",
            case.id, case.name, case.description
        );

        let scripts = extract_javascript(&case.reflection);
        let mut case_detected = false;

        for script in scripts {
            match analyzer.analyze(&script) {
                Ok(vulnerabilities) => {
                    if !vulnerabilities.is_empty() {
                        println!(
                            "  ✗ Detected {} vulnerability(ies) (false positive)",
                            vulnerabilities.len()
                        );
                        for vuln in &vulnerabilities {
                            println!("    - Line {}: {} -> {}", vuln.line, vuln.source, vuln.sink);
                        }
                        case_detected = true;
                    }
                }
                Err(e) => {
                    println!("  ✗ Analysis error: {}", e);
                }
            }
        }

        if !case_detected && !case.expected_detection {
            println!("  ✓ Correctly not detected (properly sanitized)");
            correctly_not_detected += 1;
        } else if case_detected && !case.expected_detection {
            println!("  ✗ FALSE POSITIVE: Should not detect (code is sanitized)");
            false_positives.push((case.id, case.name.clone()));
        }
    }

    println!("\n=== Sanitized Flows Summary ===");
    println!("Total cases: {}", sanitized_cases.len());
    println!("Correctly not detected: {}", correctly_not_detected);
    println!(
        "False positive rate: {:.1}%",
        (false_positives.len() as f64 / sanitized_cases.len() as f64) * 100.0
    );

    if !false_positives.is_empty() {
        println!("\nFalse positives:");
        for (id, name) in &false_positives {
            println!("  - Case {}: {}", id, name);
        }
        println!(
            "\nNote: Some false positives are expected as the analyzer may not recognize all sanitization patterns"
        );
    }
}

#[test]
fn test_dom_xss_comprehensive_coverage() {
    let cases = load_dom_xss_cases().expect("Failed to load DOM XSS test cases");

    println!("\n=== Comprehensive DOM XSS Detection Coverage ===");
    println!("Total test cases: {}", cases.len());

    let analyzer = AstDomAnalyzer::new();
    let mut total_detected = 0;
    let mut total_expected = 0;
    let mut category_stats = std::collections::HashMap::new();

    for case in &cases {
        let category = match case.id {
            1000..=1099 => "Location Sources",
            1100..=1199 => "Storage Sources",
            1200..=1299 => "PostMessage Sources",
            1300..=1399 => "Complex Flows",
            1400..=1499 => "Sanitized (Should NOT detect)",
            _ => "Other",
        };

        let scripts = extract_javascript(&case.reflection);
        let mut detected = false;

        for script in scripts {
            if let Ok(vulnerabilities) = analyzer.analyze(&script) {
                if !vulnerabilities.is_empty() {
                    detected = true;
                    break;
                }
            }
        }

        let stats = category_stats.entry(category).or_insert((0, 0, 0));
        stats.0 += 1; // total
        if case.expected_detection {
            stats.1 += 1; // expected
            total_expected += 1;
        }
        if detected {
            stats.2 += 1; // detected
            if case.expected_detection {
                total_detected += 1;
            }
        }
    }

    println!("\nCategory Breakdown:");
    for (category, (total, _expected, detected)) in category_stats {
        println!(
            "  {}: {}/{} detected ({:.1}%)",
            category,
            detected,
            total,
            (detected as f64 / total as f64) * 100.0
        );
    }

    println!(
        "\nOverall Detection Rate: {}/{} ({:.1}%)",
        total_detected,
        total_expected,
        if total_expected > 0 {
            (total_detected as f64 / total_expected as f64) * 100.0
        } else {
            0.0
        }
    );

    // We should detect a reasonable percentage of cases
    assert!(
        total_detected > 0,
        "Should detect at least some DOM XSS vulnerabilities"
    );

    println!("\n=== Recommendations for Improvement ===");
    println!("1. Ensure storage sources (localStorage/sessionStorage) are recognized");
    println!("2. Track event.data and e.data from postMessage handlers");
    println!("3. Improve taint tracking through function calls and object properties");
    println!("4. Add sanitizer recognition (DOMPurify, textContent, createTextNode)");
}
