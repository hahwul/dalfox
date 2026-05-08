use super::{
    finding_belongs_to_target, init_remote_resources, init_remote_resources_with_options,
    stable_finding_fingerprint,
};

#[test]
fn fingerprint_is_deterministic() {
    let a = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    assert_eq!(a, b);
    assert_eq!(a.len(), 16, "fingerprint must be 16 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn fingerprint_invariant_to_query_value() {
    // Same target identity (path stable, query value differs across payload
    // variants) must hash to the same fingerprint — this is the property
    // that makes SARIF consumers dedupe re-runs.
    let a = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/s?q=%3Csvg%3E", "q", "inHTML", "CWE-79");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_invariant_to_path_segment_payload() {
    // Path-injection variants must collapse to the same identity.
    let a = stable_finding_fingerprint("http://h/p/level1/seed", "p", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/p/level1/%3Cimg%3E", "p", "inHTML", "CWE-79");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_separates_distinct_targets() {
    let q = stable_finding_fingerprint("http://h/a?q=x", "q", "inHTML", "CWE-79");
    let other_path = stable_finding_fingerprint("http://h/b?q=x", "q", "inHTML", "CWE-79");
    let other_param = stable_finding_fingerprint("http://h/a?q=x", "id", "inHTML", "CWE-79");
    let other_inject = stable_finding_fingerprint("http://h/a?q=x", "q", "inJS", "CWE-79");
    assert_ne!(q, other_path);
    assert_ne!(q, other_param);
    assert_ne!(q, other_inject);
}

#[test]
fn finding_belongs_query_target_same_path() {
    // Query target: payload mutates query string only.
    let target = "http://h/search?q=a";
    assert!(finding_belongs_to_target(
        target,
        "http://h/search?q=%3Csvg%3E"
    ));
    assert!(finding_belongs_to_target(target, "http://h/search?id=1"));
}

#[test]
fn finding_belongs_query_target_rejects_other_path() {
    let target = "http://h/search?q=a";
    assert!(!finding_belongs_to_target(target, "http://h/other?q=a"));
    assert!(!finding_belongs_to_target(target, "http://h/searches?q=a"));
}

#[test]
fn finding_belongs_path_injection_uses_parent() {
    // Path target: payload replaces last segment.
    let target = "http://h/path/level1/a";
    assert!(finding_belongs_to_target(
        target,
        "http://h/path/level1/%3Cimg%3E"
    ));
    assert!(finding_belongs_to_target(target, "http://h/path/level1/b"));
}

#[test]
fn finding_belongs_header_inject_no_query_exact_match() {
    // Header/cookie/body target with no query: finding URL is identical.
    let target = "http://h/page";
    assert!(finding_belongs_to_target(target, "http://h/page"));
}

#[test]
fn finding_belongs_path_injection_rejects_sibling_path() {
    let target = "http://h/path/level1/a";
    // Different parent path — must not match.
    assert!(!finding_belongs_to_target(
        target,
        "http://h/path/level2/a"
    ));
    assert!(!finding_belongs_to_target(target, "http://h/other/x"));
}

#[test]
fn finding_belongs_query_target_does_not_borrow_path_parent_fallback() {
    // A target with a query string must NOT use the parent-path fallback,
    // because path is stable across query payload variants.
    let target = "http://h/a/b?q=x";
    assert!(!finding_belongs_to_target(target, "http://h/a/c?q=x"));
}


#[tokio::test]
async fn test_init_remote_resources_noop_when_no_providers() {
    let payloads: Vec<String> = vec![];
    let wordlists: Vec<String> = vec![];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_with_options_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources_with_options(&payloads, &wordlists, Some(1), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}
