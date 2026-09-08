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
                // Let tasks queue behind the semaphore before reflection
                // statistics decide to stop the mining stage.
                sleep(Duration::from_millis(2)).await;
                let mut body = String::from("<html><body>");
                if params.is_empty() {
                    for i in 0..500 {
                        body.push_str(&format!("<input name=candidate_{i}>"));
                    }
                }
                for (name, value) in params {
                    // Real candidates reflect, sentinel names do not. This
                    // exercises the adaptive stop rather than the pre-probe.
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
    // Two candidate probes, plus the first sentinel of the arbitrary-name
    // pre-probe (it does not reflect here, so the probe stops after one).
    // Eligibility is measured on the loaded wordlist, not on what survives
    // dedup, so shrinking the list cannot silently drop that check.
    assert_eq!(requests.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn dictionary_collapse_stops_queued_requests_and_keeps_mined_params() {
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
    assert_eq!(count, 16, "one sentinel + fifteen reflection samples");
    let params = params.lock().await;
    assert!(
        params
            .iter()
            .any(|p| p.name == "saved" && p.location == Location::Body)
    );
    // The sentinels did not reflect, so "this target echoes arbitrary names" is
    // disproved: the stop still bounds the fan-out, but the fifteen candidates
    // it did confirm stay as real injection points instead of being replaced by
    // an `any` the target answers nothing for.
    assert!(
        !params.iter().any(|p| p.name == "any"),
        "unconfirmed collapse must not fold real params into a stand-in"
    );
    let mined: Vec<_> = params
        .iter()
        .filter(|p| p.location == Location::Query)
        .collect();
    assert_eq!(mined.len(), 15);
    assert!(mined.iter().all(|p| p.name.starts_with("candidate_")));
    assert!(
        mined.iter().all(|p| p.valid_specials.is_some()),
        "the drained samples must seed metadata"
    );
}

#[tokio::test]
async fn dom_collapse_stops_queued_requests() {
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
        17,
        "HTML fetch + sentinel + fifteen samples"
    );
    let params = params.lock().await;
    // Same as the dictionary stage: stop early, keep what was confirmed. The
    // DOM candidate set comes from a HashSet, so only the shape is asserted.
    assert_eq!(params.len(), 15);
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
    assert_eq!(requests.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn mining_pipeline_preserves_dictionary_findings_through_dom_collapse() {
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
    // DOM mining stops on its EWMA sample and keeps those fifteen candidates;
    // the two dictionary findings are never folded away.
    assert_eq!(names.len(), 17, "{names:?}");
    assert!(names[2..].iter().all(|n| n.starts_with("candidate_")));
    // 1 dictionary sentinel + 2 candidates, then 1 HTML fetch + 1 DOM sentinel
    // + 15 DOM samples.
    assert_eq!(requests.load(Ordering::Relaxed), 20);
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
    assert_eq!(requests.load(Ordering::Relaxed), 32);
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
    // Fifteen samples trigger the stop; up to workers-1 other requests may
    // already be active. Include the failed sentinel (and DOM's HTML fetch).
    assert!((16..=15 + target.workers).contains(&dictionary_requests));
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_response_id_params(&target, &args, params, semaphore, None).await;
    server.abort();
    let dom_requests = requests.load(Ordering::Relaxed);
    assert!((17..=16 + target.workers).contains(&dom_requests));
}
