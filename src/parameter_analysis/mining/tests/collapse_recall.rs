//! Collapse-vs-recall guards: the request-saving filters in Query/DOM mining
//! must not cost an injection point the previous revision would have found.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Echo-everything page: any query param name is reflected raw, sentinels
/// included.
async fn echo_all_server() -> (Target, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                let mut body = String::from("<html><body>");
                if params.is_empty() {
                    for i in 0..SENTINEL_PROBE_COUNT * 5 {
                        body.push_str(&format!("<input name=field_{i}>"));
                    }
                }
                for (_name, value) in params {
                    body.push_str(&value);
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

/// Only `cand_*` names reflect — the target has many real reflecting params but
/// does *not* echo names it has never heard of.
async fn selective_server() -> (Target, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                let mut body = String::from("<html><body>");
                for (name, value) in params {
                    if name.starts_with("cand_") {
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

/// A wordlist whose entries are all already-discovered Query slots still has to
/// run the arbitrary-name pre-probe: `any` is the only injection point that
/// covers "this target echoes names it does not have", and nothing else in the
/// stage can find it. Pre-probe eligibility therefore comes from the loaded
/// wordlist, not from what survives filtering.
#[tokio::test]
async fn known_slots_keep_arbitrary_name_coverage() {
    let (target, _requests, server) = echo_all_server().await;
    let words = (0..20).map(|i| format!("known_{i}\n")).collect::<String>();
    let wordlist = TempWordlist::new("collapse-recall-known", &words);
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(
        (0..20)
            .map(|i| Param::new(format!("known_{i}"), "a", Location::Query))
            .collect::<Vec<_>>(),
    ));
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
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert!(params.iter().any(|p| p.name == "any"), "{names:?}");
    assert_eq!(params.len(), 21, "the known slots survive too: {names:?}");
}

/// The reflection EWMA cannot tell "echoes any name" from "these fields all
/// reflect". Its stop stays (an endpoint reflecting most of a wordlist would
/// otherwise hand Stage 3-6 hundreds of near-identical injection points), but
/// replacing the confirmed params with the synthetic `any` needs the sentinels
/// to agree. They do not here, so the mined params must stay.
#[tokio::test]
async fn unconfirmed_ewma_stop_keeps_the_real_params() {
    let (target, _requests, server) = selective_server().await;
    let words = (0..20).map(|i| format!("cand_{i}\n")).collect::<String>();
    let wordlist = TempWordlist::new("collapse-recall-ewma", &words);
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
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !params.iter().any(|p| p.name == "any"),
        "the sentinels never reflected, so `any` is a stand-in for nothing: {names:?}"
    );
    // Serial (`workers = 1`) probing, so the stop lands on the fifteenth
    // attempt — the minimum the EWMA collapse requires.
    assert_eq!(params.len(), 15, "{names:?}");
    assert!(params.iter().all(|p| p.name.starts_with("cand_")));
}

/// A wordlist at or under the pre-probe threshold never ran the arbitrary-name
/// check, so a collapse there has no evidence yet: confirm before folding. When
/// the sentinels do reflect, the fold happens exactly as before — and the
/// sentinel body, not a mined param, seeds `any`'s metadata.
#[tokio::test]
async fn unprobed_wordlist_confirms_before_folding() {
    let (target, requests, server) = echo_all_server().await;
    let words = (0..SENTINEL_PROBE_COUNT * 5)
        .map(|i| format!("cand_{i}\n"))
        .collect::<String>();
    let wordlist = TempWordlist::new("collapse-recall-confirm", &words);
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
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["any"], "{names:?}");
    assert!(
        params[0].valid_specials.is_some(),
        "sentinel body seeds `any`"
    );
    assert_eq!(
        requests.load(Ordering::Relaxed),
        SENTINEL_PROBE_COUNT * 5 + SENTINEL_PROBE_COUNT,
        "fifteen candidates, then the three confirming sentinels"
    );
}

/// The DOM stage carries the same fold-time confirmation. Exactly
/// `SENTINEL_PROBE_COUNT * 5` candidate fields keep it under the pre-probe
/// threshold, so the collapse it reaches has to ask the sentinels itself.
#[tokio::test]
async fn unprobed_dom_candidates_confirm_before_folding() {
    let (target, requests, server) = echo_all_server().await;
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
    let params = params.lock().await;
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["any"], "{names:?}");
    assert_eq!(
        requests.load(Ordering::Relaxed),
        1 + SENTINEL_PROBE_COUNT * 5 + SENTINEL_PROBE_COUNT,
        "HTML fetch, fifteen fields, then the three confirming sentinels"
    );
}
