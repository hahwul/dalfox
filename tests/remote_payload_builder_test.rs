use std::time::Duration;

use dalfox::payload::{
    RemoteFetchOptions, get_remote_payloads, get_remote_words, has_remote_payloads,
    has_remote_wordlists, init_remote_payloads, init_remote_payloads_with, init_remote_wordlists,
    list_payload_providers, list_wordlist_providers, register_payload_provider,
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

    (format!("http://{addr}/list.txt"), handle)
}

#[tokio::test]
async fn test_payload_fetch_path_and_wordlist_unknown_path() {
    let (good_url, server_handle) =
        spawn_text_server("# c\nfoo\nbar\nfoo\n// skip\n; skip\n  baz  \n", 1).await;
    let bad_url = "http://127.0.0.1:0/unreachable.txt".to_string();

    register_payload_provider(
        "LOCAL-PAYLOAD-PROVIDER",
        vec![good_url.clone(), bad_url.clone()],
    );

    let payload_providers = list_payload_providers();
    assert!(
        payload_providers
            .iter()
            .any(|p| p == "local-payload-provider")
    );

    let providers = vec!["local-payload-provider".to_string()];
    init_remote_payloads_with(
        &providers,
        RemoteFetchOptions {
            timeout_secs: Some(2),
            proxy: Some("://invalid-proxy".to_string()),
        },
    )
    .await
    .expect("initialize remote payloads");

    assert!(has_remote_payloads());
    let payloads = get_remote_payloads().expect("payload cache should exist");
    assert_eq!(
        payloads.as_ref(),
        &vec!["bar".to_string(), "baz".to_string(), "foo".to_string()]
    );

    // idempotent path (already initialized)
    init_remote_payloads(&providers)
        .await
        .expect("idempotent payload init");

    // unknown-provider path for wordlists in a fresh wordlist cache
    let unknown_wordlist = vec!["definitely-unknown-wordlist-provider".to_string()];
    init_remote_wordlists(&unknown_wordlist)
        .await
        .expect("unknown wordlist provider should yield empty cache");
    assert!(has_remote_wordlists());
    assert!(
        get_remote_words()
            .expect("wordlist cache should exist")
            .is_empty()
    );

    let wordlist_providers = list_wordlist_providers();
    assert!(wordlist_providers.iter().any(|p| p == "burp"));

    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}
