//! Mock case loader for XSS testing
//!
//! This module loads test case definitions from TOML files in subdirectories
//! and provides a structured way to manage and execute test cases.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Represents a single mock test case
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MockCase {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub handler_type: String,
    pub reflection: String,
    pub expected_detection: bool,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub cookie_name: Option<String>,
    #[serde(default)]
    pub param_name: Option<String>,
    /// Server-side filter chain (pipe-separated: "strip_script|encode_angles")
    #[serde(default)]
    pub filter: Option<String>,
    /// Page template key (search_page, error_page, login_form, etc.)
    #[serde(default)]
    pub page_template: Option<String>,
    /// Content-Type header override
    #[serde(default)]
    pub content_type: Option<String>,
    /// HTTP status code override
    #[serde(default)]
    pub status_code: Option<u16>,
    /// Additional response headers
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// CVE or reference identifier
    #[serde(default)]
    pub reference: Option<String>,
    /// Classification tag (cve, hackerone, waf_bypass, real_world, etc.)
    #[serde(default)]
    pub category: Option<String>,
}

/// Container for multiple test cases from a TOML file
#[derive(Debug, Deserialize)]
struct MockCaseFile {
    #[serde(rename = "case")]
    cases: Vec<MockCase>,
}

/// Loads all mock cases from a given directory
pub fn load_mock_cases_from_dir(dir_path: &Path) -> Result<Vec<MockCase>, String> {
    let mut all_cases = Vec::new();

    if !dir_path.exists() {
        return Err(format!("Directory does not exist: {}", dir_path.display()));
    }

    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", dir_path.display()));
    }

    // Read all .toml files in the directory
    let entries = fs::read_dir(dir_path)
        .map_err(|e| format!("Failed to read directory {}: {}", dir_path.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            let cases = load_mock_cases_from_file(&path)?;
            all_cases.extend(cases);
        }
    }

    Ok(all_cases)
}

/// Loads mock cases from a single TOML file
pub fn load_mock_cases_from_file(file_path: &Path) -> Result<Vec<MockCase>, String> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read file {}: {}", file_path.display(), e))?;

    let case_file: MockCaseFile = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse TOML from {}: {}", file_path.display(), e))?;

    Ok(case_file.cases)
}

/// Loads all mock cases organized by handler type
pub fn load_all_mock_cases(base_dir: &Path) -> Result<HashMap<String, Vec<MockCase>>, String> {
    let mut cases_by_type: HashMap<String, Vec<MockCase>> = HashMap::new();

    // Define the handler types we support
    let handler_types = vec!["query", "header", "cookie", "path", "body", "dom_xss", "realworld"];

    for handler_type in handler_types {
        let type_dir = base_dir.join(handler_type);
        if type_dir.exists() {
            let cases = load_mock_cases_from_dir(&type_dir)?;
            cases_by_type.insert(handler_type.to_string(), cases);
        }
    }

    Ok(cases_by_type)
}

/// Gets the base directory for mock cases
pub fn get_mock_cases_base_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("functional")
        .join("mock_cases")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_load_mock_cases_structure() {
        let base_dir = get_mock_cases_base_dir();

        // Just verify the structure exists - don't fail if files don't exist yet
        if base_dir.exists() {
            let result = load_all_mock_cases(&base_dir);
            if let Ok(cases) = result {
                // Verify we got some cases
                assert!(!cases.is_empty(), "Should load at least one handler type");

                // Verify structure
                for (handler_type, cases_list) in cases.iter() {
                    println!(
                        "Handler type: {}, cases: {}",
                        handler_type,
                        cases_list.len()
                    );
                    assert!(
                        !cases_list.is_empty(),
                        "Handler type {} should have cases",
                        handler_type
                    );
                }
            }
        }
    }

    #[test]
    fn test_mock_case_deserialization() {
        let toml_content = r#"
[[case]]
id = 1
name = "test_case"
description = "Test description"
handler_type = "query"
reflection = "<div>{input}</div>"
expected_detection = true
"#;

        let case_file: MockCaseFile = toml::from_str(toml_content).unwrap();
        assert_eq!(case_file.cases.len(), 1);
        assert_eq!(case_file.cases[0].id, 1);
        assert_eq!(case_file.cases[0].name, "test_case");
        assert_eq!(case_file.cases[0].handler_type, "query");
    }

    #[test]
    fn test_mock_case_ids_unique_per_handler_type() {
        let base_dir = get_mock_cases_base_dir();
        if !base_dir.exists() {
            return;
        }

        let all = load_all_mock_cases(&base_dir).expect("mock cases should load");
        for (handler_type, cases) in all {
            let mut ids = HashSet::new();
            for case in &cases {
                assert!(
                    ids.insert(case.id),
                    "Duplicate case id {} in handler type {}",
                    case.id,
                    handler_type
                );
            }
            assert!(
                !cases.is_empty(),
                "Handler type {} should include at least one case",
                handler_type
            );
        }
    }

    #[test]
    fn test_dom_xss_has_positive_and_negative_expectations() {
        let base_dir = get_mock_cases_base_dir();
        if !base_dir.exists() {
            return;
        }

        let all = load_all_mock_cases(&base_dir).expect("mock cases should load");
        let dom_cases = all.get("dom_xss").expect("dom_xss cases should exist");
        let positives = dom_cases.iter().filter(|c| c.expected_detection).count();
        let negatives = dom_cases.iter().filter(|c| !c.expected_detection).count();

        assert!(
            positives > 0,
            "dom_xss should include positive detection cases"
        );
        assert!(
            negatives > 0,
            "dom_xss should include negative/sanitized cases"
        );
    }
}
