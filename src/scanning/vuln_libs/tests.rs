use super::*;

#[test]
fn version_ordering() {
    assert!(version_lt("1.7.2", "3.5.0"));
    assert!(version_lt("3.4.1", "3.5.0"));
    assert!(!version_lt("3.5.0", "3.5.0"));
    assert!(!version_lt("3.6.0", "3.5.0"));
    // Missing components treated as 0.
    assert!(version_lt("1.9", "1.9.1"));
    assert!(!version_lt("2", "1.9.9"));
    // Pre-release suffix truncated to numeric prefix.
    assert!(version_lt("1.7.2-rc1", "1.8.0"));
    assert!(version_ge("4.0.0", "4.0.0"));
}

fn libs(body: &str) -> Vec<VulnLib> {
    detect_vulnerable_libraries(body)
}

#[test]
fn detects_old_jquery_from_script_src() {
    let body = r#"<html><head>
        <script src="/assets/js/jquery-1.7.2.min.js"></script>
        </head><body>x</body></html>"#;
    let found = libs(body);
    let jq = found
        .iter()
        .find(|v| v.library == "jQuery")
        .expect("jQuery should be detected");
    assert_eq!(jq.version, "1.7.2");
    // 1.7.2 is below every jQuery fixed range, so all advisories aggregate.
    assert!(jq.advisories.iter().any(|a| a == "CVE-2020-11023"));
    assert!(jq.advisories.iter().any(|a| a == "CVE-2012-6708"));
    assert_eq!(jq.fixed_in, "3.5.0");
}

#[test]
fn detects_jquery_from_cdn_path() {
    let body = r#"<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>"#;
    let found = libs(body);
    assert!(
        found
            .iter()
            .any(|v| v.library == "jQuery" && v.version == "1.11.0"),
        "expected jQuery 1.11.0 from CDN path, got {:?}",
        found
    );
}

#[test]
fn detects_jquery_from_inline_banner() {
    let body = "<script>/*! jQuery JavaScript Library v1.8.3\n ... */ \n var a=1;</script>";
    let found = libs(body);
    assert!(
        found
            .iter()
            .any(|v| v.library == "jQuery" && v.version == "1.8.3"),
        "expected jQuery 1.8.3 from inline banner, got {:?}",
        found
    );
}

#[test]
fn current_jquery_is_not_flagged() {
    let body = r#"<script src="/js/jquery-3.7.1.min.js"></script>"#;
    let found = libs(body);
    assert!(
        !found.iter().any(|v| v.library == "jQuery"),
        "current jQuery must not be flagged, got {:?}",
        found
    );
}

#[test]
fn boundary_version_at_fix_is_safe() {
    // Exactly the fixed release is not vulnerable (range is `< fixed`).
    let body = r#"<script src="/js/jquery-3.5.0.min.js"></script>"#;
    let found = libs(body);
    assert!(found.iter().all(|v| v.library != "jQuery"));
}

#[test]
fn partially_old_jquery_aggregates_only_matching_ranges() {
    // 3.4.1: below 3.5.0 only → just the htmlPrefilter advisories.
    let body = r#"<script src="/js/jquery-3.4.1.min.js"></script>"#;
    let jq = libs(body)
        .into_iter()
        .find(|v| v.library == "jQuery")
        .expect("3.4.1 is vulnerable to CVE-2020-11022/11023");
    assert!(jq.advisories.iter().any(|a| a == "CVE-2020-11022"));
    assert!(
        !jq.advisories.iter().any(|a| a == "CVE-2012-6708"),
        "must not attribute pre-1.9 advisory to 3.4.1"
    );
}

#[test]
fn detects_lodash_high_severity() {
    let body = r#"<script src="/vendor/lodash-4.17.10.min.js"></script>"#;
    let lo = libs(body)
        .into_iter()
        .find(|v| v.library == "Lodash")
        .expect("old Lodash should be flagged");
    assert_eq!(lo.severity, "High");
    assert!(lo.advisories.iter().any(|a| a == "CVE-2021-23337"));
}

#[test]
fn detects_angularjs_and_bootstrap() {
    let body = r#"
        <script src="/js/angular-1.5.8.min.js"></script>
        <script src="/js/bootstrap-3.3.7.min.js"></script>
    "#;
    let found = libs(body);
    assert!(
        found
            .iter()
            .any(|v| v.library == "AngularJS" && v.version == "1.5.8")
    );
    assert!(
        found
            .iter()
            .any(|v| v.library == "Bootstrap" && v.version == "3.3.7")
    );
}

#[test]
fn bootstrap_4_introduced_bound_respected() {
    // Bootstrap 4.2.0 is in the [4.0.0, 4.3.1) range → flagged.
    assert!(
        libs(r#"<script src="/bootstrap-4.2.0.min.js">"#)
            .iter()
            .any(|v| v.library == "Bootstrap")
    );
    // Bootstrap 4.5.0 is past 4.3.1 and not in the <3.4.1 range → safe.
    assert!(
        libs(r#"<script src="/bootstrap-4.5.0.min.js">"#)
            .iter()
            .all(|v| v.library != "Bootstrap")
    );
}

#[test]
fn no_libraries_in_plain_page() {
    let found = libs("<html><body><h1>hello</h1></body></html>");
    assert!(found.is_empty(), "got {:?}", found);
}

#[test]
fn dedups_repeated_same_version() {
    let body = r#"
        <script src="/a/jquery-1.7.2.min.js"></script>
        <script src="/b/jquery-1.7.2.min.js"></script>
    "#;
    let count = libs(body).iter().filter(|v| v.library == "jQuery").count();
    assert_eq!(count, 1, "same (lib, version) must be reported once");
}

#[test]
fn library_findings_builds_informational_results() {
    use crate::scanning::result::FindingType;
    let vulns = detect_vulnerable_libraries(r#"<script src="/jquery-1.7.2.min.js"></script>"#);
    assert!(!vulns.is_empty());
    let findings = library_findings(vulns, "https://t.example/page", "GET");
    let f = findings.first().expect("one finding");
    assert_eq!(f.result_type, FindingType::Informational);
    assert_eq!(f.inject_type, "OutdatedComponent");
    assert_eq!(f.cwe, "CWE-1104");
    assert_eq!(f.method, "GET");
    assert_eq!(f.data, "https://t.example/page");
    assert_eq!(f.severity, "Medium");
    assert_ne!(
        f.message_id, 0,
        "must avoid the message_id==0 AST-dedup path"
    );
    assert!(f.message_str.contains("jQuery 1.7.2"));
    assert!(f.evidence.contains("CVE-") && f.evidence.contains("upgrade to >= 3.5.0"));
    // Payload/param-free (so POC synthesis is bypassed).
    assert!(f.payload.is_empty() && f.param.is_empty());
}

#[test]
fn library_findings_empty_for_no_vulns() {
    assert!(library_findings(vec![], "https://t.example", "GET").is_empty());
}

#[test]
fn detects_jquery_ui_from_src() {
    let body = r#"<script src="/js/jquery-ui-1.11.4.min.js"></script>"#;
    let ui = libs(body)
        .into_iter()
        .find(|v| v.library == "jQuery UI")
        .expect("old jQuery UI should be flagged");
    assert_eq!(ui.version, "1.11.4");
    assert!(ui.advisories.iter().any(|a| a == "CVE-2022-31160"));
}

#[test]
fn detects_handlebars_from_src_and_inline() {
    let from_src = libs(r#"<script src="/vendor/handlebars-4.0.5.min.js"></script>"#);
    assert!(
        from_src
            .iter()
            .any(|v| v.library == "Handlebars" && v.version == "4.0.5" && v.severity == "High"),
        "got {from_src:?}"
    );
    let from_inline = libs("<script>/* Handlebars.js v4.0.5 */</script>");
    assert!(
        from_inline
            .iter()
            .any(|v| v.library == "Handlebars" && v.version == "4.0.5"),
        "inline Handlebars banner should be detected, got {from_inline:?}"
    );
}

#[test]
fn detects_moment_from_src_and_inline() {
    let from_src = libs(r#"<script src="/js/moment-2.20.1.min.js"></script>"#);
    assert!(
        from_src
            .iter()
            .any(|v| v.library == "Moment.js" && v.version == "2.20.1"),
        "got {from_src:?}"
    );
    let from_inline = libs("//! moment.js\n//! version : 2.20.1\n//! authors");
    assert!(
        from_inline
            .iter()
            .any(|v| v.library == "Moment.js" && v.version == "2.20.1"),
        "inline Moment banner should be detected, got {from_inline:?}"
    );
}

#[test]
fn detects_angularjs_from_inline_version() {
    let body = r#"<script>angular.module('a'); angular.version = {full: "1.5.8"};</script>"#;
    assert!(
        libs(body)
            .iter()
            .any(|v| v.library == "AngularJS" && v.version == "1.5.8"),
        "inline AngularJS version should be detected"
    );
}

#[test]
fn detects_bootstrap_from_inline_banner() {
    let body = "<script>/*! Bootstrap v3.3.7 (https://getbootstrap.com) */</script>";
    assert!(
        libs(body)
            .iter()
            .any(|v| v.library == "Bootstrap" && v.version == "3.3.7"),
        "inline Bootstrap banner should be detected"
    );
}

#[test]
fn current_libraries_across_dataset_are_safe() {
    // A modern stack must produce zero findings (guards against over-broad ranges).
    let body = r#"
        <script src="/jquery-ui-1.13.2.min.js"></script>
        <script src="/handlebars-4.7.8.min.js"></script>
        <script src="/moment-2.29.4.min.js"></script>
        <script src="/lodash-4.17.21.min.js"></script>
        <script src="/bootstrap-5.3.0.min.js"></script>
    "#;
    assert!(
        libs(body).is_empty(),
        "modern stack flagged: {:?}",
        libs(body)
    );
}
