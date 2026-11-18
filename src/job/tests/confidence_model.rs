use super::*;
use crate::scanning::result::{Confidence, FindingType, Result};

#[test]
fn live_and_settled_views_map_and_rank_the_same_way_as_cli() {
    let low_ast = Result::builder(FindingType::AstDetected)
        .confidence(Confidence::Low, "needs confirmation")
        .severity("Medium")
        .payload("first")
        .evidence("same sink")
        .build();
    let mut promoted = low_ast.clone();
    promoted.result_type = FindingType::Verified;
    promoted.severity = "High".into();
    promoted.payload = "second".into();
    let info = Result::builder(FindingType::Informational)
        .severity("Critical")
        .message_id(1)
        .build();
    let args = crate::cmd::scan::ScanArgs {
        tier_model: Some("confidence".into()),
        ..Default::default()
    };
    let view = ResultView::of(&args);
    let results = runner::sanitize_results(&[low_ast, promoted, info], &view);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].result_type, FindingType::Reflected);
    assert_eq!(results[0].severity, "Info");
    assert_eq!(
        results[0].payload, "first",
        "both low claims have equal mapped severity"
    );
    assert!(results[0].type_description.starts_with("Reflected"));
    assert_eq!(
        results[0].detection_method,
        crate::scanning::result::FindingMethod::Ast
    );
    assert!(results[0].request.is_none() && results[0].response.is_none());
    assert_eq!(results[1].result_type, FindingType::Informational);
    assert_eq!(results[1].severity, "Critical");
}

#[test]
fn tier_model_is_validated_and_mapped_at_both_request_boundaries() {
    for model in ["legacy", "confidence"] {
        assert!(
            ScanOptionChecks::<f32> {
                tier_model: Some(model),
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
        let options: crate::server::types::ScanOptions =
            serde_json::from_value(serde_json::json!({"tier_model":model})).unwrap();
        let args =
            ScanRequestSpec::from_rest_options("http://example.com/".into(), &options, 0, 0, None)
                .into_scan_args();
        assert_eq!(args.tier_model.as_deref(), Some(model));
        let params: crate::mcp::ScanWithDalfoxParams = serde_json::from_value(
            serde_json::json!({"target":"http://example.com/", "tier_model":model}),
        )
        .unwrap();
        assert_eq!(params.tier_model.as_deref(), Some(model));
    }
    assert!(
        ScanOptionChecks::<f32> {
            tier_model: Some("unknown"),
            ..Default::default()
        }
        .validate()
        .unwrap_err()
        .contains("tier_model")
    );
}
