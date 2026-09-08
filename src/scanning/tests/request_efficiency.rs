use super::*;
use axum::{Router, extract::Query, response::Html, routing::get};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

const VERIFIED: &str = "<svg onload=alert(1)>";

// Exercise the actual HTTP/verification pipeline with a fixed catalog so
// payload-generator changes cannot silently weaken the request-count checks.
async fn worker(
    redirects: bool,
) -> (
    ScanWorkerCtx,
    Param,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                let q = params.get("q").map(String::as_str).unwrap_or_default();
                if redirects && q.starts_with("miss") {
                    return (axum::http::StatusCode::FOUND, Html(String::new()));
                }
                let body = if q == VERIFIED || q == "echo" || q == markers::bracketed_marker() {
                    format!("<html><body>{q}</body></html>")
                } else {
                    "<html><body>filtered</body></html>".to_owned()
                };
                (axum::http::StatusCode::OK, Html(body))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut target = parse_target(&format!("http://{addr}/?q=a")).unwrap();
    target.workers = crate::cmd::scan::DEFAULT_WORKERS;
    let param = Param::new("q".to_owned(), "a".to_owned(), Location::Query);
    let ctx = ScanWorkerCtx {
        args: Arc::new(integration_scan_args(false)),
        client: Arc::new(target.build_client_or_default()),
        target: Arc::new(target),
        results: Arc::new(Mutex::new(Vec::new())),
        found_params: Arc::new(RwLock::new(FoundParams {
            reflection: HashSet::new(),
            dom: HashSet::new(),
        })),
        findings_count: Arc::new(AtomicUsize::new(0)),
        pb: None,
        overall_pb: None,
        limit_result_type: Arc::from("ALL"),
        cancel: None,
        finding_tx: None,
        semaphore: Arc::new(Semaphore::new(1)),
        req_budget: Arc::new(Semaphore::new(crate::utils::semaphore_permits(
            crate::cmd::scan::DEFAULT_WORKERS,
        ))),
        params_done: None,
    };
    (ctx, param, requests, server)
}

fn catalog() -> Vec<String> {
    (0..150).map(|i| format!("miss{i}")).collect()
}

#[tokio::test]
async fn early_reflection_hit_uses_four_requests_including_probe() {
    let (ctx, param, requests, server) = worker(false).await;
    let mut payloads = catalog();
    payloads[1] = VERIFIED.to_owned();
    ctx.scan_param(param, payloads, vec![]).await;
    server.abort();
    let results = ctx.results.lock().await;
    assert!(
        results
            .iter()
            .any(|r| r.result_type == FindingType::Verified)
    );
    assert_eq!(requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn early_dom_hit_uses_four_requests_including_probe() {
    let (ctx, param, requests, server) = worker(false).await;
    let mut payloads = catalog();
    payloads[1] = VERIFIED.to_owned();
    ctx.scan_param(param, vec![], payloads).await;
    server.abort();
    let results = ctx.results.lock().await;
    assert!(
        results
            .iter()
            .any(|r| r.result_type == FindingType::Verified)
    );
    assert_eq!(requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn prefetched_verification_survives_an_earlier_reflection() {
    let (ctx, param, requests, server) = worker(false).await;
    let mut payloads = catalog();
    payloads[1] = "echo".to_owned();
    payloads[2] = VERIFIED.to_owned();
    // No DOM catalog: the V must come from the already-fetched reflection
    // response. Retrying that payload in a later phase cannot rescue it.
    ctx.scan_param(param, payloads, vec![]).await;
    server.abort();
    let results = ctx.results.lock().await;
    assert!(
        results
            .iter()
            .any(|r| r.result_type == FindingType::Verified)
    );
    assert_eq!(requests.load(Ordering::Relaxed), 4);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.result_type == FindingType::Verified)
            .count(),
        1
    );
}

#[tokio::test]
async fn prefetched_reflections_still_deduplicate() {
    let (ctx, param, requests, server) = worker(false).await;
    let mut payloads = catalog();
    payloads[1] = "echo".to_owned();
    payloads[2] = "echo".to_owned();
    ctx.scan_param(param, payloads, vec![]).await;
    server.abort();
    let results = ctx.results.lock().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].result_type, FindingType::Reflected);
    assert_eq!(requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn dom_budget_preserves_prefetched_verification() {
    let (ctx, param, requests, server) = worker(true).await;
    let mut payloads = catalog();
    payloads[REDIRECT_STREAK_LIMIT as usize] = VERIFIED.to_owned();
    ctx.scan_param(param, vec![], payloads).await;
    server.abort();
    let results = ctx.results.lock().await;
    assert!(
        results
            .iter()
            .any(|r| r.result_type == FindingType::Verified)
    );
    // 1 probe + batches of 1, 2, 4, 8, 16, 20; no further batch is needed.
    assert_eq!(requests.load(Ordering::Relaxed), 52);
}

#[tokio::test]
async fn dom_budget_still_stops_when_prefetched_responses_do_not_verify() {
    let (ctx, param, requests, server) = worker(true).await;
    ctx.scan_param(param, vec![], catalog()).await;
    server.abort();
    assert!(ctx.results.lock().await.is_empty());
    assert_eq!(requests.load(Ordering::Relaxed), 52);
}

#[tokio::test]
async fn deep_scan_keeps_the_full_unsuccessful_catalog() {
    let (mut ctx, param, requests, server) = worker(true).await;
    Arc::make_mut(&mut ctx.args).deep_scan = true;
    ctx.scan_param(param, vec![], catalog()).await;
    server.abort();
    assert!(ctx.results.lock().await.is_empty());
    assert_eq!(requests.load(Ordering::Relaxed), 151);
}

#[test]
fn growing_batches_never_exceed_previous_request_cost_at_any_stop_position() {
    for concurrency in 1..=crate::cmd::scan::MAX_PER_PARAM_CONCURRENCY {
        let mut completed = 0;
        for stop_after in 1usize..=512 {
            if completed < stop_after {
                let chunk = payload_chunk_size(completed, concurrency);
                assert!((1..=concurrency).contains(&chunk));
                completed += chunk;
            }
            let previous_cost = 1 + (stop_after - 1).div_ceil(concurrency) * concurrency;
            assert!(completed <= previous_cost);
        }
    }
}
