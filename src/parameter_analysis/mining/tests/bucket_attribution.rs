//! A bucket's response has to be attributed to the right names: a failure or
//! a refusal must not discard every name in it, and a response difference
//! (or a redirect echo) must not credit names that did nothing.

use super::*;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn serve(
    handler: impl Fn(HashMap<String, String>, usize) -> Response + Clone + Send + Sync + 'static,
) -> (Target, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().route(
        "/",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let count = count.clone();
            let handler = handler.clone();
            async move {
                let n = count.fetch_add(1, Ordering::Relaxed);
                handler(params, n)
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

async fn mine(target: &Target, words: &str) -> Vec<Param> {
    let wordlist = TempWordlist::new("bucket-attribution", words);
    let args = ScanArgs {
        mining_dict_word: Some(wordlist.as_str()),
        ..default_scan_args()
    };
    let params = Arc::new(Mutex::new(Vec::new()));
    probe_dictionary_params(
        target,
        &args,
        params.clone(),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    params.lock().await.clone()
}

fn names(params: &[Param]) -> Vec<&str> {
    let mut n: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    n.sort_unstable();
    n
}

/// `int(request.GET['page'])` answers 500 for a non-numeric value. The bucket
/// carrying `page` failed as a whole and every other name in it — here the
/// reflecting `q` — was dropped untested.
#[tokio::test]
async fn a_name_that_errors_does_not_discard_its_bucket() {
    let (target, _, server) = serve(|params, _| {
        if params.contains_key("page") {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let echo = params.get("q").cloned().unwrap_or_default();
        Html(format!("<html><body>{echo}</body></html>")).into_response()
    })
    .await;
    let words =
        "page\nq\n".to_string() + &(0..20).map(|i| format!("miss_{i}\n")).collect::<String>();
    let params = mine(&target, &words).await;
    server.abort();
    assert_eq!(names(&params), ["q"]);
}

/// A server with a 2 KB query-string limit (IIS / ASP.NET defaults, AWS WAF's
/// size rule) refuses a full bucket and its same-width control alike. That
/// read as "nothing changed" and resolved the whole bucket as empty.
#[tokio::test]
async fn a_bucket_refused_for_its_size_is_split_not_dropped() {
    let (target, _, server) = serve(|params, _| {
        let query_len: usize = params.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
        if query_len > 400 {
            return (StatusCode::NOT_FOUND, "query string too long").into_response();
        }
        let echo = params.get("q").cloned().unwrap_or_default();
        Html(format!("<html><body>{echo}</body></html>")).into_response()
    })
    .await;
    let words = (0..30).map(|i| format!("miss_{i}\n")).collect::<String>() + "q\n";
    let params = mine(&target, &words).await;
    server.abort();
    assert_eq!(names(&params), ["q"]);
}

/// A name that changes nothing shares a bucket with one that echoes. The
/// control never echoes, so the bucket always "differs" from it, and the one
/// name left over was accepted without ever being tested on its own.
#[tokio::test]
async fn a_name_sharing_a_bucket_with_an_echo_is_not_accepted_untested() {
    let (target, _, server) = serve(|params, _| {
        let echo = params.get("q").cloned().unwrap_or_default();
        Html(format!("<html><body>stable {echo}</body></html>")).into_response()
    })
    .await;
    let params = mine(&target, "q\nzzz\n").await;
    server.abort();
    assert_eq!(names(&params), ["q"]);
}

/// A page whose length changes between identical requests (a rotating
/// widget, a render-time footer). Every comparison differed, so every bucket
/// bisected down to single names and each was accepted as a parameter.
#[tokio::test]
async fn an_unstable_page_does_not_turn_the_wordlist_into_parameters() {
    let (target, requests, server) = serve(|params, n| {
        let echo = params.get("q").cloned().unwrap_or_default();
        let noise = "x".repeat(n % 7);
        Html(format!("<html><body>{noise} {echo}</body></html>")).into_response()
    })
    .await;
    let words = (0..40).map(|i| format!("miss_{i}\n")).collect::<String>() + "q\n";
    let params = mine(&target, &words).await;
    let sent = requests.load(Ordering::Relaxed);
    server.abort();
    assert_eq!(names(&params), ["q"]);
    assert!(sent < 12, "no bisection on noise; sent {sent} requests");
}

/// On an unstable page a status change is still attributable: the body
/// varies between identical requests, the status does not.
#[tokio::test]
async fn an_unstable_page_still_finds_a_name_that_changes_the_status() {
    let (target, _, server) = serve(|params, n| {
        if params.contains_key("debug") {
            return (StatusCode::BAD_REQUEST, "debug disabled").into_response();
        }
        Html(format!("<html><body>{}</body></html>", "x".repeat(n % 7))).into_response()
    })
    .await;
    let words = (0..20).map(|i| format!("miss_{i}\n")).collect::<String>() + "debug\n";
    let params = mine(&target, &words).await;
    server.abort();
    assert_eq!(names(&params), ["debug"]);
}

/// `lang` redirects to the same URL minus itself, carrying the rest of the
/// query. Every other canary in the bucket then sits in `Location`, and all of
/// those names were reported as redirect sinks — none of which reflect when
/// sent alone.
#[tokio::test]
async fn a_redirect_carrying_the_query_does_not_credit_every_name() {
    let (target, _, server) = serve(|params, _| {
        if params.contains_key("lang") {
            let rest: String = params
                .iter()
                .filter(|(k, _)| k.as_str() != "lang")
                .map(|(k, v)| format!("{k}={v}&"))
                .collect();
            let mut h = HeaderMap::new();
            h.insert("location", format!("/?{rest}").parse().unwrap());
            return (StatusCode::FOUND, h, "").into_response();
        }
        let next = params.get("next").cloned().unwrap_or_default();
        if !next.is_empty() {
            let mut h = HeaderMap::new();
            h.insert("location", next.parse().unwrap());
            return (StatusCode::FOUND, h, "").into_response();
        }
        Html("<html><body>home</body></html>").into_response()
    })
    .await;
    let words =
        "lang\nnext\n".to_string() + &(0..10).map(|i| format!("miss_{i}\n")).collect::<String>();
    let params = mine(&target, &words).await;
    server.abort();
    // `next` is a genuine redirect sink; `lang` changes the response (a 302)
    // and is kept as a metric-only name; the `miss_*` names that only rode
    // along in `lang`'s redirect are not parameters.
    assert_eq!(names(&params), ["lang", "next"]);
    let next = params.iter().find(|p| p.name == "next").unwrap();
    assert!(matches!(
        next.injection_context,
        Some(InjectionContext::AttributeUrl(_))
    ));
}
