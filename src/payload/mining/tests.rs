use super::*;

#[test]
fn test_gf_patterns_not_empty() {
    assert!(!GF_PATTERNS_PARAMS.is_empty());
}

#[test]
fn test_gf_patterns_no_empty_entries() {
    for p in GF_PATTERNS_PARAMS {
        assert!(!p.is_empty(), "parameter name must not be empty");
    }
}

#[test]
fn test_gf_patterns_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for p in GF_PATTERNS_PARAMS {
        assert!(seen.insert(p), "duplicate parameter: {}", p);
    }
}

#[test]
fn test_gf_patterns_no_whitespace() {
    for p in GF_PATTERNS_PARAMS {
        assert_eq!(
            p.trim(),
            *p,
            "parameter '{}' should not have leading/trailing whitespace",
            p
        );
    }
}

#[test]
fn test_gf_patterns_contains_common_params() {
    let expected = ["q", "search", "url", "callback", "id"];
    for e in expected {
        assert!(
            GF_PATTERNS_PARAMS.contains(&e),
            "common parameter '{}' should be in GF_PATTERNS_PARAMS",
            e
        );
    }
}

#[test]
fn test_built_in_mining_params_extend_and_deduplicate_the_seed() {
    let params = built_in_mining_params();
    let unique: std::collections::HashSet<_> = params.iter().collect();

    assert_eq!(params.len(), unique.len());
    assert!(params.len() > GF_PATTERNS_PARAMS.len());
    for expected in [
        "authorization",
        "api_version",
        "page_size",
        "feature",
        "webhook",
    ] {
        assert!(
            params.iter().any(|param| param == expected),
            "missing {expected}"
        );
    }
}

#[test]
fn test_gori_mining_seed_has_no_blank_or_comment_entries() {
    let params = built_in_mining_params();
    assert!(
        params
            .iter()
            .all(|param| { !param.is_empty() && param.trim() == param && !param.starts_with('#') })
    );
}
