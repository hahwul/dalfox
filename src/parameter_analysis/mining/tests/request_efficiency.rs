use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn mining_server() -> (Target, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                // Keep request accounting deterministic while the bucket
                // engine processes each candidate group.
                sleep(Duration::from_millis(2)).await;
                let mut body = String::from("<html><body>");
                if params.is_empty() {
                    for i in 0..500 {
                        body.push_str(&format!("<input name=candidate_{i}>"));
                    }
                }
                for (name, value) in params {
                    // Real candidates reflect, sentinel names do not. This
                    // exercises post-bucket EWMA handling rather than the
                    // arbitrary-name pre-probe.
                    if name.starts_with("candidate_") || name == "selected" || name == "hidden" {
                        body.push_str(&value);
                    }
                }
                body.push_str("</body></html>");
                Html(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut target = parse_target(&format!("http://{addr}/")).unwrap();
    target.workers = 1;
    (target, requests, server)
}

async fn metric_only_server() -> (Target, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                let mut body = String::from("<html><body>stable");
                if params.contains_key("hidden") {
                    // This parameter changes the response but never echoes its
                    // canary, exercising control-request bisection.
                    body.push_str(" feature-enabled");
                }
                body.push_str("</body></html>");
                Html(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut target = parse_target(&format!("http://{addr}/")).unwrap();
    target.workers = 1;
    (target, requests, server)
}

fn candidate_wordlist() -> TempWordlist {
    let words = (0..500)
        .map(|i| format!("candidate_{i}\n"))
        .collect::<String>();
    TempWordlist::new("mining-efficiency", &words)
}

#[tokio::test]
async fn duplicate_words_do_not_hide_a_later_real_parameter() {
    let (target, requests, server) = mining_server().await;
    let wordlist = TempWordlist::new("duplicate-mining", &("selected\n".repeat(500) + "hidden\n"));
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    let params = params.lock().await;
    let names: Vec<_> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["selected", "hidden"]);
    // One sentinel pre-probe, one clean baseline sample, and one bucket
    // carrying both unique candidates.
    // Eligibility is measured on the loaded wordlist, not on what survives
    // dedup, so shrinking the list cannot silently drop that check.
    assert_eq!(requests.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn dictionary_bucketing_keeps_mined_params_without_detached_requests() {
    let (target, requests, server) = mining_server().await;
    let wordlist = candidate_wordlist();
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(vec![Param::new(
        "saved",
        "value",
        Location::Body,
    )]));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    let count = requests.load(Ordering::Relaxed);
    sleep(Duration::from_millis(20)).await;
    server.abort();
    assert_eq!(
        requests.load(Ordering::Relaxed),
        count,
        "no detached probes after return"
    );
    assert_eq!(
        count,
        1 + 1 + 500usize.div_ceil(crate::cmd::scan::DEFAULT_MINING_BUCKET_SIZE),
        "one sentinel + one baseline + eight candidate buckets"
    );
    let params = params.lock().await;
    assert!(
        params
            .iter()
            .any(|p| p.name == "saved" && p.location == Location::Body)
    );
    // The sentinels did not reflect, so "this target echoes arbitrary names" is
    // disproved: every reflected candidate stays as a real injection point
    // instead of being replaced by an `any` the target answers nothing for.
    assert!(
        !params.iter().any(|p| p.name == "any"),
        "unconfirmed collapse must not fold real params into a stand-in"
    );
    let mined: Vec<_> = params
        .iter()
        .filter(|p| p.location == Location::Query)
        .collect();
    assert_eq!(mined.len(), 500);
    assert!(mined.iter().all(|p| p.name.starts_with("candidate_")));
    assert!(
        mined.iter().all(|p| p.valid_specials.is_some()),
        "the drained samples must seed metadata"
    );
}

#[tokio::test]
async fn dom_bucketing_keeps_the_full_reflected_candidate_set() {
    let (target, requests, server) = mining_server().await;
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_response_id_params(
        &target,
        &default_scan_args(),
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    assert_eq!(
        requests.load(Ordering::Relaxed),
        1 + 1 + 500usize.div_ceil(crate::cmd::scan::DEFAULT_MINING_BUCKET_SIZE),
        "HTML fetch + sentinel + eight candidate buckets"
    );
    let params = params.lock().await;
    // The DOM candidate set comes from a HashSet, so only the shape is
    // asserted. The bucket engine keeps every reflected candidate.
    assert_eq!(params.len(), 500);
    assert!(params.iter().all(|p| p.name.starts_with("candidate_")));
    assert!(!params.iter().any(|p| p.name == "any"));
}

#[tokio::test]
async fn known_query_candidates_are_probed_once_at_most() {
    let (target, requests, server) = mining_server().await;
    let wordlist = candidate_wordlist();
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(
        (0..500)
            .map(|i| Param::new(format!("candidate_{i}"), "a", Location::Query))
            .collect(),
    ));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    // Every wordlist entry is an already-discovered Query slot, so no candidate
    // probe is sent — only the arbitrary-name pre-probe, whose first sentinel
    // does not reflect here.
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    probe_response_id_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    assert_eq!(
        requests.load(Ordering::Relaxed),
        3,
        "DOM needs its HTML fetch and one sentinel"
    );
    assert_eq!(params.lock().await.len(), 500);
}

#[tokio::test]
async fn existing_body_slot_does_not_suppress_a_query_candidate() {
    let (target, requests, server) = mining_server().await;
    let wordlist = TempWordlist::new("location-mining", "hidden\nhidden\n");
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(vec![Param::new("hidden", "a", Location::Body)]));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    let params = params.lock().await;
    assert_eq!(params.len(), 2);
    assert!(
        params
            .iter()
            .any(|p| p.name == "hidden" && p.location == Location::Query)
    );
    assert_eq!(requests.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn mining_pipeline_preserves_dictionary_findings_through_dom_bucketing() {
    let (mut target, requests, server) = mining_server().await;
    let wordlist = TempWordlist::new("pipeline-mining", &("selected\n".repeat(500) + "hidden\n"));
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    mine_parameters(
        &mut target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    let params = params.lock().await;
    let names: Vec<_> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(&names[..2], ["selected", "hidden"], "{names:?}");
    // The two dictionary findings are never folded away, and the DOM bucket
    // pass keeps all 500 reflected fields after its negative sentinel.
    assert_eq!(names.len(), 502, "{names:?}");
    assert!(names[2..].iter().all(|n| n.starts_with("candidate_")));
    // Dictionary: one sentinel + one baseline + one bucket. DOM: one HTML
    // fetch + one sentinel + eight candidate buckets.
    assert_eq!(
        requests.load(Ordering::Relaxed),
        1 + 1 + 1 + 1 + 1 + 500usize.div_ceil(crate::cmd::scan::DEFAULT_MINING_BUCKET_SIZE)
    );
}

#[tokio::test]
async fn nonreflecting_prefix_does_not_skip_a_late_hidden_parameter() {
    let (target, requests, server) = mining_server().await;
    let words = (0..30).map(|i| format!("miss_{i}\n")).collect::<String>() + "hidden\n";
    let wordlist = TempWordlist::new("late-mining", &words);
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(4)),
        None,
    )
    .await;
    server.abort();
    let params = params.lock().await;
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "hidden");
    // One failed sentinel, one clean baseline, one mixed bucket, one control,
    // and four child buckets each paired with a same-width control.
    assert_eq!(requests.load(Ordering::Relaxed), 12);
}

#[tokio::test]
async fn metric_only_parameter_is_found_by_four_way_bisection() {
    let (target, requests, server) = metric_only_server().await;
    let words = (0..63).map(|i| format!("miss_{i}\n")).collect::<String>() + "hidden\n";
    let wordlist = TempWordlist::new("metric-only-mining", &words);
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_dictionary_params(
        &target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();

    let params = params.lock().await;
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "hidden");
    assert!(
        requests.load(Ordering::Relaxed) < 64,
        "bucket bisection should beat one request per candidate"
    );
}

#[tokio::test]
async fn concurrent_mining_bounds_overshoot_to_active_workers() {
    let (mut target, requests, server) = mining_server().await;
    target.workers = crate::cmd::scan::DEFAULT_WORKERS;
    let semaphore = Arc::new(Semaphore::new(crate::utils::semaphore_permits(
        target.workers,
    )));
    let wordlist = candidate_wordlist();
    let args = ScanArgs {
        workers: target.workers,
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_dictionary_params(&target, &args, params, semaphore.clone(), None).await;
    let dictionary_requests = requests.swap(0, Ordering::Relaxed);
    // Eight initial buckets cover the 500-name list. There is no per-candidate
    // overshoot because bucket results are joined before child buckets queue.
    assert_eq!(
        dictionary_requests,
        1 + 1 + 500usize.div_ceil(crate::cmd::scan::DEFAULT_MINING_BUCKET_SIZE)
    );
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_response_id_params(&target, &args, params, semaphore, None).await;
    server.abort();
    let dom_requests = requests.load(Ordering::Relaxed);
    assert_eq!(
        dom_requests,
        1 + 1 + 500usize.div_ceil(crate::cmd::scan::DEFAULT_MINING_BUCKET_SIZE)
    );
}
