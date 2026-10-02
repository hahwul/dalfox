use std::time::Duration;

use dalfox::payload::{
    RemoteFetchOptions, get_remote_payloads_for, get_remote_words_for, init_remote_payloads_with,
    init_remote_wordlists_with, list_payload_providers, list_wordlist_providers,
    register_wordlist_provider,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
    });

    (format!("http://{addr}/words.txt"), handle)
}

#[tokio::test]
async fn test_wordlist_fetch_path_and_payload_unknown_path() {
    let (good_url, server_handle) =
        spawn_text_server("# c\nid\nq\nid\n// skip\n; skip\n  token  \n", 1).await;
    let bad_url = "http://127.0.0.1:0/unreachable.txt".to_string();

    register_wordlist_provider(
        "LOCAL-WORDLIST-PROVIDER",
        vec![good_url.clone(), bad_url.clone()],
    );

    let wordlist_providers = list_wordlist_providers();
    assert!(
        wordlist_providers
            .iter()
            .any(|p| p == "local-wordlist-provider")
    );

    let providers = vec!["local-wordlist-provider".to_string()];
    init_remote_wordlists_with(
        &providers,
        RemoteFetchOptions {
            timeout_secs: Some(2),
            proxy: Some("://invalid-proxy".to_string()),
        },
    )
    .await
    .expect("initialize remote wordlists");

    let words = get_remote_words_for(&providers).expect("wordlist cache should exist");
    assert_eq!(
        words.as_ref(),
        &vec!["id".to_string(), "q".to_string(), "token".to_string()]
    );

    // idempotent path (already initialized)
    init_remote_wordlists_with(&providers, RemoteFetchOptions::default())
        .await
        .expect("idempotent wordlist init");

    // unknown-provider path for payloads in a fresh payload cache
    let unknown_payload = vec!["definitely-unknown-payload-provider".to_string()];
    init_remote_payloads_with(&unknown_payload, RemoteFetchOptions::default())
        .await
        .expect("unknown payload provider should yield empty cache");
    assert!(
        get_remote_payloads_for(&unknown_payload)
            .expect("payload cache should exist")
            .is_empty()
    );

    let payload_providers = list_payload_providers();
    assert!(payload_providers.iter().any(|p| p == "payloadbox"));

    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}
