use super::*;
use crate::cmd::scan::args::BASELINE_MODE_FILTER;
use crate::cmd::scan::output::apply_baseline;
use crate::scanning::result::{FindingMethod, FindingType, Result};

fn tmp(name: &str, body: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dalfox-baseline-{}-{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write temp baseline");
    p
}

fn finding(tier: FindingType, url: &str, param: &str) -> Result {
    Result::builder(tier)
        .inject_type("inHTML-none(1)")
        .method("GET")
        .data(url.to_string())
        .param(param.to_string())
        .payload("<svg onload=alert(1)>")
        .evidence("reflected in body")
        .cwe("CWE-79")
        .severity("High")
        .message_id(606)
        .message_str("msg")
        .build()
}

/// Serialize findings the way `--format json --output` does, so the tests
/// diff against the exact bytes an operator would hand back as a baseline.
fn report(findings: &[Result]) -> String {
    let values: Vec<serde_json::Value> = findings
        .iter()
        .map(|r| r.to_json_value(false, false))
        .collect();
    serde_json::json!({
        "meta": { "dalfox_version": env!("CARGO_PKG_VERSION") },
        "findings": values,
    })
    .to_string()
}

// ---------------------------------------------------------------- key identity

#[test]
fn key_ignores_the_payload_in_the_url() {
    // Two runs of the same scan embed different payloads in `data`. That is
    // the single most common source of scan-to-scan variation, and it must
    // not read as a new finding.
    let a = finding(FindingType::Verified, "https://h/s?q=%3Csvg%3E", "q");
    let b = finding(FindingType::Verified, "https://h/s?q=%22onload%3D1", "q");
    assert_eq!(key_for_result(&a), key_for_result(&b));
}

#[test]
fn key_ignores_request_response_and_payload_fields() {
    let a = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let mut b = finding(FindingType::Verified, "https://h/s?q=1", "q");
    b.payload = "<img src=x onerror=alert(1)>".to_string();
    b.request = Some("GET /s?q=1 HTTP/1.1".to_string());
    b.response = Some("<html>…</html>".to_string());
    b.severity = "Medium".to_string();
    assert_eq!(key_for_result(&a), key_for_result(&b));
}

#[test]
fn key_separates_path_param_location_and_tier() {
    let base = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let base_key = key_for_result(&base);

    let other_path = finding(FindingType::Verified, "https://h/other?q=1", "q");
    let other_param = finding(FindingType::Verified, "https://h/s?q=1", "id");
    // Same tier promotion is the point: an R that becomes a V is new.
    let other_tier = finding(FindingType::Reflected, "https://h/s?q=1", "q");
    let mut other_location = finding(FindingType::Verified, "https://h/s?q=1", "q");
    other_location.location = "Header".to_string();

    for other in [other_path, other_param, other_tier, other_location] {
        assert_ne!(base_key, key_for_result(&other));
    }
}

#[test]
fn ast_key_uses_source_sink_not_line_numbers() {
    // AST evidence carries `url:line:col`, which moves whenever the page's
    // JavaScript is re-bundled. The source→sink pair is the real identity.
    let mut a = finding(FindingType::AstDetected, "https://h/app", "location.search");
    a.inject_type = "DOM-XSS".to_string();
    a.detection_method = FindingMethod::Ast;
    a.evidence = "https://h/app.js:12:4 - flow (Source: location.search, Sink: innerHTML)".into();

    let mut moved = a.clone();
    moved.evidence =
        "https://h/app.b91f.js:998:31 - flow (Source: location.search, Sink: innerHTML)".into();
    assert_eq!(key_for_result(&a), key_for_result(&moved));

    let mut other_sink = a.clone();
    other_sink.evidence =
        "https://h/app.js:12:4 - flow (Source: location.search, Sink: document.write)".into();
    assert_ne!(key_for_result(&a), key_for_result(&other_sink));
}

#[test]
fn evidence_family_keeps_a_parenthesized_sink_intact() {
    let family = evidence_family(
        "u.js:1:1 - f (Source: location.hash, Sink: document.write())",
        "ast",
    );
    assert_eq!(family, "src=location.hash;sink=document.write()");
}

// ------------------------------------------------------------------- loading

#[test]
fn loads_a_json_report_and_matches_its_own_findings() {
    let known = finding(FindingType::Verified, "https://h/s?q=%3Csvg%3E", "q");
    let path = tmp("json-roundtrip.json", &report(std::slice::from_ref(&known)));
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert_eq!(bl.keys.len(), 1);
    // Same finding, different payload in the URL — still known.
    assert!(!bl.is_new(&finding(
        FindingType::Verified,
        "https://h/s?q=%22%3E%3Cimg%3E",
        "q"
    )));
    assert!(bl.is_new(&finding(FindingType::Verified, "https://h/s?q=1", "id")));
}

#[test]
fn loads_a_jsonl_report() {
    let known = finding(FindingType::Reflected, "https://h/s?q=1", "q");
    let body = format!(
        "{{\"meta\":{{\"dalfox_version\":\"{}\"}}}}\n{}\n",
        env!("CARGO_PKG_VERSION"),
        serde_json::to_string(&known.to_json_value(false, false)).unwrap()
    );
    let path = tmp("roundtrip.jsonl", &body);
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert!(!bl.is_new(&known));
}

#[test]
fn loads_a_bare_findings_array() {
    let known = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let body = serde_json::to_string(&vec![known.to_json_value(false, false)]).unwrap();
    let path = tmp("bare-array.json", &body);
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert!(!bl.is_new(&known));
}

#[test]
fn an_empty_findings_array_is_a_valid_zero_finding_baseline() {
    let path = tmp("empty.json", &report(&[]));
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert_eq!(bl.keys.len(), 0);
    assert!(bl.is_new(&finding(FindingType::Verified, "https://h/s?q=1", "q")));
}

#[test]
fn a_missing_file_disables_the_diff_instead_of_failing() {
    let bl = load("/nonexistent/dalfox-baseline.json", BASELINE_MODE_FILTER);
    assert!(!bl.is_active());
    assert!(bl.warning.as_deref().unwrap().contains("could not be read"));
    assert!(bl.keys.is_empty());
}

#[test]
fn a_malformed_report_disables_the_diff() {
    for (name, body) in [
        ("garbage.json", "not json at all {{{"),
        ("empty-file.json", "   \n  "),
        ("no-findings.json", "{\"scanned\":true,\"targets\":[]}"),
        // A --dry-run envelope carries a `meta` but describes a plan, not
        // findings; reading it as an empty backlog would be wrong.
        (
            "dry-run.json",
            "{\"dry_run\":true,\"meta\":{},\"targets\":[]}",
        ),
        ("wrong-shape.json", "[{\"unrelated\":1},{\"also\":2}]"),
    ] {
        let path = tmp(name, body);
        let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
        let _ = std::fs::remove_file(&path);
        assert!(!bl.is_active(), "{} should have been rejected", name);
        assert!(bl.keys.is_empty());
    }
}

#[test]
fn a_foreign_major_version_disables_the_diff() {
    let body = serde_json::json!({
        "meta": { "dalfox_version": "2.9.1" },
        "findings": [finding(FindingType::Verified, "https://h/s?q=1", "q")
            .to_json_value(false, false)],
    })
    .to_string();
    let path = tmp("v2.json", &body);
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(!bl.is_active());
    assert!(bl.warning.as_deref().unwrap().contains("2.9.1"));
}

#[test]
fn a_newer_patch_or_minor_version_still_diffs() {
    let known = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let major = env!("CARGO_PKG_VERSION").split('.').next().unwrap();
    let body = serde_json::json!({
        "meta": { "dalfox_version": format!("{}.0.0", major) },
        "findings": [known.to_json_value(false, false)],
    })
    .to_string();
    let path = tmp("older-patch.json", &body);
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert!(!bl.is_new(&known));
}

// --------------------------------------------------------------- apply modes

fn active_baseline(keys: &[&Result], mode: &str) -> Baseline {
    Baseline {
        path: "baseline.json".to_string(),
        mode: mode.to_string(),
        keys: keys.iter().map(|r| key_for_result(r)).collect(),
        entries: keys.len(),
        warning: None,
    }
}

#[test]
fn filter_mode_drops_known_findings_and_reports_counts() {
    let known = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let fresh = finding(FindingType::Verified, "https://h/s?q=1", "id");
    let bl = active_baseline(&[&known], BASELINE_MODE_FILTER);

    let mut results = vec![known.clone(), fresh.clone()];
    let meta = apply_baseline(&mut results, Some(&bl)).expect("baseline block");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].param, "id");
    // Nothing is annotated under filter — every reported finding is new by
    // construction, so a `new: true` on each would be noise.
    assert_eq!(results[0].new_since_baseline, None);
    assert_eq!(meta["enabled"], serde_json::json!(true));
    assert_eq!(meta["new"], serde_json::json!(1));
    assert_eq!(meta["known"], serde_json::json!(1));
    assert_eq!(meta["baseline_findings"], serde_json::json!(1));
}

#[test]
fn filter_mode_keeps_findings_aligned_when_dropping_from_the_middle() {
    // The retain pass walks a precomputed flag list; an off-by-one here would
    // silently drop the wrong findings.
    let a = finding(FindingType::Verified, "https://h/a?q=1", "q");
    let b = finding(FindingType::Verified, "https://h/b?q=1", "q");
    let c = finding(FindingType::Verified, "https://h/c?q=1", "q");
    let bl = active_baseline(&[&b], BASELINE_MODE_FILTER);

    let mut results = vec![a.clone(), b.clone(), c.clone()];
    apply_baseline(&mut results, Some(&bl));

    assert_eq!(results.len(), 2);
    assert!(results[0].data.contains("/a"));
    assert!(results[1].data.contains("/c"));
}

#[test]
fn annotate_mode_keeps_everything_and_tags_each_finding() {
    let known = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let fresh = finding(FindingType::Verified, "https://h/s?q=1", "id");
    let bl = active_baseline(&[&known], BASELINE_MODE_ANNOTATE);

    let mut results = vec![known.clone(), fresh.clone()];
    let meta = apply_baseline(&mut results, Some(&bl)).expect("baseline block");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].new_since_baseline, Some(false));
    assert_eq!(results[1].new_since_baseline, Some(true));
    assert_eq!(meta["new"], serde_json::json!(1));
    assert_eq!(meta["known"], serde_json::json!(1));

    // The tag reaches structured output as `new`.
    let json = results[1].to_json_value(false, false);
    assert_eq!(json["new"], serde_json::json!(true));
    assert_eq!(
        results[0].to_json_value(false, false)["new"],
        serde_json::json!(false)
    );
}

#[test]
fn a_finding_carries_no_new_field_without_a_baseline() {
    let mut results = vec![finding(FindingType::Verified, "https://h/s?q=1", "q")];
    assert!(apply_baseline(&mut results, None).is_none());
    assert_eq!(results.len(), 1);
    assert!(results[0].to_json_value(false, false).get("new").is_none());
}

#[test]
fn a_disabled_baseline_changes_nothing_but_still_reports_itself() {
    // "Nothing new" and "the diff never ran" must be distinguishable by a
    // pipeline reading the envelope.
    let bl = Baseline {
        path: "gone.json".to_string(),
        mode: BASELINE_MODE_FILTER.to_string(),
        keys: Default::default(),
        entries: 0,
        warning: Some("could not be read".to_string()),
    };
    let mut results = vec![finding(FindingType::Verified, "https://h/s?q=1", "q")];
    let meta = apply_baseline(&mut results, Some(&bl)).expect("baseline block");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].new_since_baseline, None);
    assert_eq!(meta["enabled"], serde_json::json!(false));
    assert!(
        meta["warning"]
            .as_str()
            .unwrap()
            .contains("could not be read")
    );
}

// ------------------------------------------------------- review regressions

#[test]
fn sibling_endpoints_without_a_query_stay_distinct() {
    // The SARIF fingerprint helper drops the whole last path segment for any
    // query-less URL, which collapses `/api/v1/users` into `/api/v1/`. Reused
    // as a baseline identity it would suppress a genuinely new finding on a
    // sibling endpoint — a silent false-clean, the one failure a gate must not
    // have. Every non-query wire location is affected.
    for location in ["Header", "Cookie", "Body", "JsonBody", "Fragment", ""] {
        let mut a = finding(FindingType::Verified, "https://h/api/v1/users", "X-Fwd");
        a.location = location.to_string();
        let mut b = finding(FindingType::Verified, "https://h/api/v1/orders", "X-Fwd");
        b.location = location.to_string();
        assert_ne!(
            key_for_result(&a),
            key_for_result(&b),
            "sibling endpoints collapsed at location={:?}",
            location
        );
    }
}

#[test]
fn path_injection_findings_still_ignore_the_injected_segment() {
    // The flip side: a path parameter puts the payload IN the last segment, so
    // that segment must not participate or every run reports it as new.
    let mut a = finding(FindingType::Verified, "https://h/p/level1/%3Cimg%3E", "seg");
    a.location = "Path".to_string();
    let mut b = finding(FindingType::Verified, "https://h/p/level1/%3Csvg%3E", "seg");
    b.location = "Path".to_string();
    assert_eq!(key_for_result(&a), key_for_result(&b));

    // …but a different parent path is still a different finding.
    let mut other = finding(FindingType::Verified, "https://h/q/level1/%3Cimg%3E", "seg");
    other.location = "Path".to_string();
    assert_ne!(key_for_result(&a), key_for_result(&other));
}

#[test]
fn dom_poc_url_carrying_the_payload_on_the_path_ignores_that_segment() {
    // `build_dom_xss_poc_url` pushes the payload onto the path for a
    // `location.pathname` source, percent-encoded and with no `location` set.
    // Recognising it by content keeps those findings stable across runs.
    let payload = "<img src=x onerror=alert(1) class=dlx1>";
    let encoded = urlencoding::encode(payload).into_owned();
    let mut a = finding(
        FindingType::AstDetected,
        "https://h/app/",
        "location.pathname",
    );
    a.data = format!("https://h/app/{}", encoded);
    a.payload = payload.to_string();

    let mut b = a.clone();
    let other_payload = "<svg onload=alert(1) class=dlx2>";
    b.data = format!("https://h/app/{}", urlencoding::encode(other_payload));
    b.payload = other_payload.to_string();

    assert_eq!(key_for_result(&a), key_for_result(&b));
}

#[test]
fn a_meta_only_jsonl_baseline_is_a_valid_empty_baseline() {
    // A clean first `--format jsonl` run writes exactly one line — the meta
    // envelope. Whole-file JSON parsing accepts it as an object with no
    // `findings`, and rejecting that broke "record once, diff every run after"
    // for any repo whose first scan is clean.
    let body = format!(
        "{{\"meta\":{{\"dalfox_version\":\"{}\",\"findings_count\":0}}}}\n",
        env!("CARGO_PKG_VERSION")
    );
    let path = tmp("meta-only.jsonl", &body);
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert_eq!(bl.keys.len(), 0);
    assert_eq!(bl.entries, 0);
    assert!(bl.is_new(&finding(FindingType::Verified, "https://h/s?q=1", "q")));
}

#[test]
fn baseline_entries_counts_report_rows_not_deduplicated_keys() {
    // Two findings, one shared identity (an `R` that a `V` supersedes would
    // look like this). `entries` must still say 2 so it lines up with the
    // baseline file's own `findings_count`.
    let a = finding(FindingType::Verified, "https://h/s?q=1", "q");
    let b = finding(FindingType::Verified, "https://h/s?q=2", "q");
    let path = tmp("dup-identity.json", &report(&[a.clone(), b]));
    let bl = load(path.to_str().unwrap(), BASELINE_MODE_FILTER);
    let _ = std::fs::remove_file(&path);

    assert!(bl.is_active(), "warning: {:?}", bl.warning);
    assert_eq!(bl.keys.len(), 1, "both rows share one identity");
    assert_eq!(bl.entries, 2, "but the report held two rows");
}
