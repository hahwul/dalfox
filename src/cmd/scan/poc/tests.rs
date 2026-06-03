use super::*;
use crate::scanning::result::{FindingType, Result};

fn informational(inject_type: &str) -> Result {
    Result::builder(FindingType::Informational)
        .inject_type(inject_type)
        .data("https://example.com")
        .message_str("Outdated JavaScript library: jQuery 1.7.2")
        .evidence("jQuery 1.7.2 is known-vulnerable (CVE-2020-11023); upgrade to >= 3.5.0")
        .cwe("CWE-1104")
        .build()
}

#[test]
fn informational_block_plain_is_compact_and_colored() {
    let r = informational("OutdatedComponent");
    let out = render_finding_block(&r, "plain", false, false);
    // Tagged, payload-free summary line + evidence sub-line.
    assert!(out.contains("[INF][OutdatedComponent]"), "{out}");
    assert!(out.contains("https://example.com"));
    assert!(out.contains("jQuery 1.7.2"));
    assert!(out.contains("CVE-2020-11023"));
    // plain output is colorized (cyan).
    assert!(out.contains("\x1b[36m"));
    // No payload-oriented "[POC]" / "Payload:" tree for informational findings.
    assert!(!out.contains("[POC]"));
    assert!(!out.contains("Payload:"));
}

#[test]
fn informational_block_non_plain_summary_not_cyan() {
    let r = informational("OutdatedComponent");
    let out = render_finding_block(&r, "curl", false, false);
    assert!(out.contains("[INF][OutdatedComponent]"));
    // The summary line must not be cyan-wrapped for non-plain output (the tree
    // sub-lines follow the existing always-colored convention).
    assert!(
        !out.contains("\x1b[36m"),
        "non-plain summary must not be cyan-colored: {out:?}"
    );
}

#[test]
fn informational_block_defaults_tag_when_inject_type_empty() {
    let r = informational("");
    let out = render_finding_block(&r, "plain", false, false);
    assert!(out.contains("[INF][Informational]"), "{out}");
}
