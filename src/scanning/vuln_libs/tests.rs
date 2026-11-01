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
fn detects_inline_banner_when_script_closes_with_whitespace() {
    // Regression: SCRIPT_INLINE_RE must accept `</script >` (trailing space),
    // matching the AST module's `</script\s*>`. A space-padded closing tag
    // previously dropped the inline banner and its CWE-1104 finding.
    let body = "<script>/*! jQuery JavaScript Library v1.8.3\n ... */ \n var a=1;</script >";
    let found = libs(body);
    assert!(
        found
            .iter()
            .any(|v| v.library == "jQuery" && v.version == "1.8.3"),
        "inline banner closed by `</script >` should still be detected, got {found:?}"
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
fn prose_mention_is_not_flagged() {
    // A library + version named in body text (not a loaded script) must NOT be
    // reported — it isn't a loaded dependency.
    let body = "<html><body><p>We migrated our UI from Bootstrap 3.3.7 \
                and jQuery 1.7.2 to a modern stack last year.</p></body></html>";
    assert!(
        libs(body).is_empty(),
        "prose mention flagged: {:?}",
        libs(body)
    );
}

#[test]
fn download_href_is_not_flagged() {
    // A version in a download link / anchor href is not a loaded script.
    let body = r#"<a href="/downloads/jquery-1.7.2.min.js">Download jQuery 1.7.2</a>"#;
    assert!(
        libs(body).is_empty(),
        "href mention flagged: {:?}",
        libs(body)
    );
}

#[test]
fn html_comment_mention_is_not_flagged() {
    let body = "<!-- TODO: upgrade from angular 1.5.8, see changelog --><div>x</div>";
    assert!(
        libs(body).is_empty(),
        "comment mention flagged: {:?}",
        libs(body)
    );
}

#[test]
fn inline_script_banner_is_still_flagged() {
    // The version inside an inline <script> (a real loaded banner) must still fire.
    let body = "<script>/*! Bootstrap v3.3.7 (https://getbootstrap.com) */ var a=1;</script>";
    assert!(
        libs(body)
            .iter()
            .any(|v| v.library == "Bootstrap" && v.version == "3.3.7"),
        "inline banner should still be flagged, got {:?}",
        libs(body)
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
fn detects_jquery_validation_from_src_and_inline() {
    let from_src = libs(r#"<script src="/js/jquery.validate-1.19.0.min.js"></script>"#);
    let jv = from_src
        .iter()
        .find(|v| v.library == "jQuery Validation" && v.version == "1.19.0")
        .unwrap_or_else(|| panic!("old jQuery Validation should be flagged, got {from_src:?}"));
    assert_eq!(jv.severity, "High");
    assert_eq!(jv.fixed_in, "1.20.0");
    for cve in [
        "CVE-2021-21252",
        "CVE-2021-43306",
        "CVE-2022-31147",
        "CVE-2025-3573",
    ] {
        assert!(jv.advisories.iter().any(|a| a == cve), "missing {cve}");
    }

    for banner in [
        "<script>/*!\n * jQuery Validation Plugin v1.19.0\n *\n * https://jqueryvalidation.org/ */</script>",
        "<script>/*! jQuery Validation Plugin - v1.19.0 - 11/28/2018\n * https://jqueryvalidation.org/ */</script>",
    ] {
        let found = libs(banner);
        assert!(
            found
                .iter()
                .any(|v| v.library == "jQuery Validation" && v.version == "1.19.0"),
            "inline jQuery Validation banner should be detected, got {found:?}"
        );
    }
}

#[test]
fn jquery_validation_from_cdn_paths() {
    for url in [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.0/jquery.validate.min.js",
        "https://ajax.aspnetcdn.com/ajax/jquery.validate/1.19.0/jquery.validate.min.js",
        "https://cdn.jsdelivr.net/npm/jquery-validation@1.19.0/dist/jquery.validate.min.js",
        "https://unpkg.com/jquery-validation@1.19.0/dist/jquery.validate.js",
    ] {
        let body = format!(r#"<script src="{url}"></script>"#);
        let found = libs(&body);
        assert!(
            found
                .iter()
                .any(|v| v.library == "jQuery Validation" && v.version == "1.19.0"),
            "expected jQuery Validation 1.19.0 from {url}, got {found:?}"
        );
    }
    for url in [
        "https://cdn.jsdelivr.net/npm/jquery-validation-unobtrusive@3.2.12/dist/jquery.validate.unobtrusive.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery-validation-unobtrusive/3.2.12/jquery.validate.unobtrusive.min.js",
    ] {
        let body = format!(r#"<script src="{url}"></script>"#);
        assert!(libs(&body).is_empty(), "{url} flagged: {:?}", libs(&body));
    }
}

/// 1.19.5 fixes the three ReDoS advisories but not CVE-2025-3573 (< 1.20.0).
#[test]
fn jquery_validation_fix_boundaries() {
    let found = libs(r#"<script src="/js/jquery.validate-1.19.5.min.js"></script>"#);
    let jv = found
        .iter()
        .find(|v| v.library == "jQuery Validation")
        .unwrap_or_else(|| panic!("1.19.5 should still be flagged, got {found:?}"));
    assert_eq!(jv.advisories, vec!["CVE-2025-3573".to_string()]);
    assert_eq!(jv.severity, "Medium");

    let fixed = libs(r#"<script src="/js/jquery.validate-1.20.0.min.js"></script>"#);
    assert!(fixed.is_empty(), "1.20.0 flagged: {fixed:?}");
}

/// The jQuery patterns must not read the plugin's version, from its URL or
/// its banner.
#[test]
fn jquery_validation_is_not_read_as_jquery() {
    let body = r#"
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
        <script src="/js/jquery.validate.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/jquery-validation@1.19.0/dist/jquery.validate.min.js"></script>
        <script src="/js/jquery.validate-1.19.0.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.0/jquery.validate.min.js"></script>
        <script>/*! jQuery Validation Plugin - v1.19.0 - 11/28/2018 */</script>
        <script>/*!\n * jQuery Validation Plugin v1.19.0\n */</script>
    "#;
    let found = libs(body);
    assert!(
        found.iter().all(|v| v.library != "jQuery"),
        "jQuery read from the plugin: {found:?}"
    );
    assert!(
        found.iter().any(|v| v.library == "jQuery Validation"),
        "got {found:?}"
    );
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
    let from_inline = libs("<script>//! moment.js\n//! version : 2.20.1\n//! authors</script>");
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
        <script src="/jquery.validate-1.22.1.min.js"></script>
        <script src="/handlebars-4.7.8.min.js"></script>
        <script src="/moment-2.29.4.min.js"></script>
        <script src="/lodash-4.17.21.min.js"></script>
        <script src="/bootstrap-5.3.0.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/dompurify@3.4.17/dist/purify.min.js"></script>
        <script src="/underscore-1.13.8.min.js"></script>
        <script src="/knockout-3.5.3.js"></script>
    "#;
    assert!(
        libs(body).is_empty(),
        "modern stack flagged: {:?}",
        libs(body)
    );
}

/// A `>` inside a quoted attribute before `src` must not hide the script URL.
#[test]
fn detects_script_src_after_quoted_gt_attribute() {
    let body = r#"<script data-x="a>b" src="/assets/js/jquery-1.7.2.min.js"></script>"#;
    assert!(libs(body).iter().any(|v| v.library == "jQuery"));
}

#[test]
fn detects_dompurify_from_src_and_inline() {
    let from_src = libs(
        r#"<script src="https://cdn.jsdelivr.net/npm/dompurify@2.3.3/dist/purify.min.js"></script>"#,
    );
    let dp = from_src
        .iter()
        .find(|v| v.library == "DOMPurify" && v.version == "2.3.3")
        .unwrap_or_else(|| panic!("old DOMPurify should be flagged, got {from_src:?}"));
    assert_eq!(dp.severity, "High");
    assert!(dp.advisories.iter().any(|a| a == "CVE-2024-45801"));

    let from_inline = libs(
        "<script>/*! @license DOMPurify 3.0.6 | (c) Cure53 and other contributors */</script>",
    );
    assert!(
        from_inline
            .iter()
            .any(|v| v.library == "DOMPurify" && v.version == "3.0.6"),
        "inline DOMPurify banner should be detected, got {from_inline:?}"
    );
}

#[test]
fn detects_dompurify_from_cdnjs_path() {
    let found = libs(
        r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>"#,
    );
    assert!(
        found
            .iter()
            .any(|v| v.library == "DOMPurify" && v.version == "3.0.6"),
        "got {found:?}"
    );
}

#[test]
fn dompurify_major_line_introduced_bounds_respected() {
    // 3.2.0 is past the 3.x fix (3.1.3) for CVE-2024-45801, but still before
    // the CVE-2025-26791 fix (3.2.4).
    let found = libs(r#"<script src="/ajax/libs/dompurify/3.2.0/purify.min.js"></script>"#);
    let dp = found
        .iter()
        .find(|v| v.library == "DOMPurify")
        .unwrap_or_else(|| panic!("DOMPurify 3.2.0 should be flagged, got {found:?}"));
    assert!(dp.advisories.iter().any(|a| a == "CVE-2025-26791"));
    assert!(!dp.advisories.iter().any(|a| a == "CVE-2024-45801"));
}

#[test]
fn detects_underscore_from_src_and_inline() {
    let from_src = libs(r#"<script src="/vendor/underscore-1.9.1.min.js"></script>"#);
    assert!(
        from_src
            .iter()
            .any(|v| v.library == "Underscore" && v.version == "1.9.1" && v.severity == "High"),
        "got {from_src:?}"
    );
    let from_inline =
        libs("<script>//     Underscore.js 1.9.1\n//     https://underscorejs.org</script>");
    assert!(
        from_inline
            .iter()
            .any(|v| v.library == "Underscore" && v.version == "1.9.1"),
        "inline Underscore banner should be detected, got {from_inline:?}"
    );
}

#[test]
fn detects_knockout_from_src_and_inline() {
    let from_src = libs(r#"<script src="/ajax/libs/knockout/3.4.2/knockout-min.js"></script>"#);
    assert!(
        from_src
            .iter()
            .any(|v| v.library == "Knockout" && v.version == "3.4.2"),
        "got {from_src:?}"
    );
    let from_inline = libs(
        "<script>/*!\n * Knockout JavaScript library v3.4.2\n * (c) The Knockout.js team */</script>",
    );
    assert!(
        from_inline
            .iter()
            .any(|v| v.library == "Knockout" && v.version == "3.4.2"),
        "inline Knockout banner should be detected, got {from_inline:?}"
    );
}

/// Lo-Dash 2.x banners credit Underscore ("Based on Underscore.js 1.5.2");
/// that is not a loaded Underscore.
#[test]
fn lodash_banner_crediting_underscore_is_not_underscore() {
    let body = "<script>/**\n * @license\n * Lo-Dash 2.4.1 (Custom Build) <http://lodash.com/>\n * Based on Underscore.js 1.5.2 <http://underscorejs.org/LICENSE>\n */</script>";
    assert!(
        libs(body).iter().all(|v| v.library != "Underscore"),
        "got {:?}",
        libs(body)
    );
}

/// npm-style (`name@<ver>`, jsDelivr / unpkg) and path-style
/// (`/name(.js)?/<ver>/`, cdnjs / Google / StackPath) CDN URLs, including the
/// cdnjs aliases that differ from the npm name.
#[test]
fn detects_libraries_from_cdn_url_shapes() {
    for (url, library, version) in [
        (
            "https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js",
            "jQuery",
            "3.3.1",
        ),
        (
            "https://unpkg.com/lodash@4.17.15/lodash.min.js",
            "Lodash",
            "4.17.15",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js",
            "Lodash",
            "4.17.15",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.8/angular.min.js",
            "AngularJS",
            "1.5.8",
        ),
        (
            "https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js",
            "AngularJS",
            "1.5.8",
        ),
        (
            "https://cdn.jsdelivr.net/npm/angular@1.5.8/angular.min.js",
            "AngularJS",
            "1.5.8",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js",
            "Bootstrap",
            "3.3.7",
        ),
        (
            "https://stackpath.bootstrapcdn.com/bootstrap/4.3.0/js/bootstrap.min.js",
            "Bootstrap",
            "4.3.0",
        ),
        (
            "https://cdn.jsdelivr.net/npm/bootstrap@4.3.0/dist/js/bootstrap.min.js",
            "Bootstrap",
            "4.3.0",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js",
            "jQuery UI",
            "1.12.1",
        ),
        (
            "https://cdn.jsdelivr.net/npm/jquery-ui@1.12.1/ui/widget.js",
            "jQuery UI",
            "1.12.1",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/handlebars.js/4.0.5/handlebars.min.js",
            "Handlebars",
            "4.0.5",
        ),
        (
            "https://unpkg.com/handlebars@4.0.5/dist/handlebars.min.js",
            "Handlebars",
            "4.0.5",
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js",
            "Moment.js",
            "2.18.1",
        ),
        ("https://unpkg.com/moment@2.18.1", "Moment.js", "2.18.1"),
        (
            "https://cdn.jsdelivr.net/npm/underscore@1.9.1/underscore-min.js",
            "Underscore",
            "1.9.1",
        ),
        (
            "https://unpkg.com/knockout@3.4.2/build/output/knockout-latest.js",
            "Knockout",
            "3.4.2",
        ),
    ] {
        let body = format!(r#"<script src="{url}"></script>"#);
        let found = libs(&body);
        assert!(
            found
                .iter()
                .any(|v| v.library == library && v.version == version),
            "expected {library} {version} from {url}, got {found:?}"
        );
    }
}

/// The CDN patterns are anchored on `/`, so a package whose name merely
/// contains a library name is not read as that library.
#[test]
fn cdn_patterns_ignore_packages_that_contain_a_library_name() {
    for url in [
        "https://cdn.jsdelivr.net/npm/my-lodash-fork@1.0.0/index.js",
        "https://unpkg.com/lodash-es@4.17.15/lodash.js",
        "https://cdn.jsdelivr.net/npm/moment-timezone@0.5.0/index.js",
        "https://cdn.jsdelivr.net/npm/bootstrap-select@1.13.0/dist/js/bootstrap-select.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.9.0/js/bootstrap-datepicker.min.js",
        "https://cdn.jsdelivr.net/npm/underscore.string@3.3.4/dist/underscore.string.min.js",
        "https://unpkg.com/knockout-mapping@2.6.0/dist/knockout.mapping.min.js",
    ] {
        let body = format!(r#"<script src="{url}"></script>"#);
        assert!(libs(&body).is_empty(), "{url} flagged: {:?}", libs(&body));
    }
}
