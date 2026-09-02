//! The remote payload / wordlist caches must be keyed by provider set.
//!
//! They used to be bare `OnceLock`s — "fetch once per process", which is right
//! for the one-scan-per-process CLI and wrong for the `dalfox server` / MCP
//! daemon, where every job carries its own `remote_payloads` /
//! `remote_wordlists` list. The first job to fetch anything won the cell for
//! the life of the process, so a later job asking for a different provider
//! silently scanned with the first job's list and still reported `done`.
//!
//! This lives in its own integration binary because the caches are process
//! globals: a separate process is what makes "the first init wins" observable
//! without depending on the order of the whole `--lib` suite.

use std::time::Duration;

use dalfox::payload::{
    RemoteFetchOptions, get_remote_payloads_for, get_remote_words_for, init_remote_payloads_with,
    init_remote_wordlists_with, register_payload_provider, register_wordlist_provider,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve `body` as `text/plain` for up to `max_requests` connections.
async fn spawn_text_server(
    body: &'static str,
    max_requests: usize,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test server");
    let addr = listener.local_addr().expect("get local addr");

    let handle = tokio::spawn(async move {
        for _ in 0..max_requests {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    (format!("http://{addr}/list.txt"), handle)
}

fn fetch_opts() -> RemoteFetchOptions {
    RemoteFetchOptions {
        timeout_secs: Some(3),
        proxy: None,
    }
}

/// Two jobs, two different providers: each must get back its own list.
#[tokio::test]
async fn test_remote_payload_cache_is_keyed_by_provider_set() {
    let (url_a, handle_a) = spawn_text_server("alpha-payload\n", 1).await;
    let (url_b, handle_b) = spawn_text_server("beta-payload\n", 1).await;
    register_payload_provider("cache-key-a", vec![url_a]);
    register_payload_provider("cache-key-b", vec![url_b]);

    let a = vec!["cache-key-a".to_string()];
    let b = vec!["cache-key-b".to_string()];

    init_remote_payloads_with(&a, fetch_opts())
        .await
        .expect("provider A fetch");
    // Second job, different provider set. Before the fix this short-circuited
    // on the already-set OnceLock and never fetched provider B at all.
    init_remote_payloads_with(&b, fetch_opts())
        .await
        .expect("provider B fetch");

    assert_eq!(
        get_remote_payloads_for(&a).expect("provider A cached").as_ref(),
        &vec!["alpha-payload".to_string()],
    );
    assert_eq!(
        get_remote_payloads_for(&b).expect("provider B cached").as_ref(),
        &vec!["beta-payload".to_string()],
        "a job asking for provider B must not be served provider A's payloads"
    );

    // The key is order- and case-insensitive and dedupes, so the same set
    // spelled differently hits the same entry rather than refetching.
    let b_spelled_differently = vec![
        " CACHE-KEY-B ".to_string(),
        "cache-key-b".to_string(),
        String::new(),
    ];
    assert_eq!(
        get_remote_payloads_for(&b_spelled_differently)
            .expect("normalized key hits the same entry")
            .as_ref(),
        &vec!["beta-payload".to_string()],
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), handle_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), handle_b).await;
}

/// A job naming only unrecognized providers takes the "no URLs" path and caches
/// an empty list. That must not poison a later job that names a real provider —
/// the poisoned daemon scanned with an empty wordlist and reported `done`.
#[tokio::test]
async fn test_unknown_provider_set_does_not_poison_a_real_one() {
    let (url, handle) = spawn_text_server("id\nq\n", 1).await;
    register_wordlist_provider("cache-key-real", vec![url]);

    let bogus = vec!["definitely-not-a-registered-provider".to_string()];
    let real = vec!["cache-key-real".to_string()];

    init_remote_wordlists_with(&bogus, fetch_opts())
        .await
        .expect("unknown provider set caches an empty list");
    assert!(
        get_remote_words_for(&bogus)
            .expect("unknown set is cached")
            .is_empty()
    );

    init_remote_wordlists_with(&real, fetch_opts())
        .await
        .expect("real provider fetch");
    assert_eq!(
        get_remote_words_for(&real)
            .expect("real provider cached")
            .as_ref(),
        &vec!["id".to_string(), "q".to_string()],
        "an earlier unknown-provider job must not leave later jobs with an empty list"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
