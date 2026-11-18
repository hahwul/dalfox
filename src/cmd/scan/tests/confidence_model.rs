use super::*;
use crate::scanning::result::{Confidence, FindingMethod, Result};

fn findings() -> Vec<Result> {
    let build = |tier, grade, evidence: &str| {
        Result::builder(tier)
            .confidence(grade, "test grade")
            .detection_method(FindingMethod::Ast)
            .data("https://example.com")
            .evidence(evidence)
            .inject_type("DOM-XSS")
            .severity("High")
            .build()
    };
    vec![
        // Same AST key: map confidence before deduplication.
        build(FindingType::Verified, Confidence::Low, "same sink"),
        build(FindingType::AstDetected, Confidence::High, "same sink"),
        build(FindingType::AstDetected, Confidence::Low, "other sink"),
        Result::builder(FindingType::Informational)
            .severity("Critical")
            .message_id(1)
            .build(),
    ]
}

#[tokio::test]
async fn maps_before_filters_and_dedup() {
    let make_state = || make_scan_state(findings());
    let ok = super::super::output::RequestTally { sent: 5, failed: 0 };
    let (default, _) = render_and_exit(default_scan_args(), make_state(), ok, "tier_default").await;
    let (legacy, _) = render_and_exit(
        ScanArgs {
            tier_model: Some("legacy".into()),
            ..default_scan_args()
        },
        make_state(),
        ok,
        "tier_legacy",
    )
    .await;
    assert_eq!(default, legacy, "explicit legacy must be byte-identical");
    let (mapped, _) = render_and_exit(
        ScanArgs {
            tier_model: Some("confidence".into()),
            only_poc: vec!["a".into()],
            ..default_scan_args()
        },
        make_state(),
        ok,
        "tier_confidence",
    )
    .await;
    let mapped: serde_json::Value = serde_json::from_str(&mapped).unwrap();
    let rows = mapped["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "AST selection retains both mapped tiers");
    assert_eq!(rows[0]["type"], "V");
    assert_eq!(
        rows[0]["confidence"], "high",
        "high A must beat a low legacy V"
    );
    assert_eq!(rows[0]["severity"], "High");
    assert_eq!(rows[1]["type"], "R");
    assert_eq!(rows[1]["severity"], "Info");
    assert!(rows.iter().all(|r| r["detection_method"] == "ast"));
}

#[test]
fn limit_selection_uses_mapped_tiers_and_ast_method() {
    let rows = findings();
    let mut args = ScanArgs {
        tier_model: Some("confidence".into()),
        only_poc: vec!["a".into()],
        limit_result_type: "v".into(),
        ..Default::default()
    };
    assert_eq!(crate::scanning::count_matching_results(&rows, &args), 1);
    args.limit_result_type = "r".into();
    assert_eq!(crate::scanning::count_matching_results(&rows, &args), 1);
    args.limit_result_type = "a".into();
    assert_eq!(crate::scanning::count_matching_results(&rows, &args), 2);
    args.min_confidence = Some("high".into());
    assert_eq!(crate::scanning::count_matching_results(&rows, &args), 1);
}

#[test]
fn severity_drives_sarif_and_preserves_info() {
    let mut rows = findings();
    for r in &mut rows {
        r.apply_tier_model(Some("confidence"));
    }
    assert_eq!(rows[3].severity, "Critical");
    assert_eq!(rows[3].result_type, FindingType::Informational);
    let sarif: serde_json::Value =
        serde_json::from_str(&Result::results_to_sarif(&rows, false, false)).unwrap();
    let rows = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(rows[0]["level"], "note");
    assert_eq!(rows[1]["level"], "error");
    assert_eq!(rows[2]["level"], "note");
}
