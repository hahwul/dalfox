use super::*;
use crate::scanning::result::{Confidence, FindingType, Result};

#[tokio::test]
async fn confidence_limit_follows_winners_within_and_across_batches() {
    let make = |grade| {
        Result::builder(FindingType::AstDetected)
            .confidence(grade, "test")
            .evidence("same sink")
            .build()
    };
    let args = ScanArgs {
        tier_model: Some("confidence".into()),
        only_poc: vec!["r".into()],
        ..Default::default()
    };
    let low = make(Confidence::Low);
    let high = make(Confidence::High);
    let results = tokio::sync::Mutex::new(Vec::new());
    let count = std::sync::atomic::AtomicUsize::new(0);
    accumulate_findings(&results, &count, vec![low.clone(), high.clone()], &args).await;
    assert_eq!(
        count.load(Ordering::Relaxed),
        0,
        "winning V is not reported by only-poc r"
    );
    let results = tokio::sync::Mutex::new(Vec::new());
    accumulate_findings(&results, &count, vec![low], &args).await;
    assert_eq!(count.load(Ordering::Relaxed), 1);
    accumulate_findings(&results, &count, vec![high], &args).await;
    assert_eq!(
        count.load(Ordering::Relaxed),
        0,
        "replacement must subtract a stale counted R"
    );
    assert_eq!(count_matching_results(&results.lock().await, &args), 0);
}
