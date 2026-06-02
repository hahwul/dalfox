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
