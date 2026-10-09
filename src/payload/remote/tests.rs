use super::*;

#[test]
fn test_sanitize_lines_strips_comments_and_blanks() {
    let input = "payload1\n  \n# comment\n// comment\n; comment\n  payload2  \n";
    let result = sanitize_lines(input);
    assert_eq!(result, vec!["payload1", "payload2"]);
}

#[test]
fn test_sanitize_lines_trims_whitespace() {
    let input = "  <script>alert(1)</script>  \n\t<img src=x>\t";
    let result = sanitize_lines(input);
    assert_eq!(result, vec!["<script>alert(1)</script>", "<img src=x>"]);
}

#[test]
fn test_sanitize_lines_empty_input() {
    assert!(sanitize_lines("").is_empty());
    assert!(sanitize_lines("   \n  \n").is_empty());
    assert!(sanitize_lines("# only comments\n// more\n").is_empty());
}

#[test]
fn test_dedup_and_sort_removes_duplicates() {
    let input = vec![
        "b".to_string(),
        "a".to_string(),
        "b".to_string(),
        "c".to_string(),
        "a".to_string(),
    ];
    let result = dedup_and_sort(input);
    assert_eq!(result, vec!["a", "b", "c"]);
}

#[test]
fn test_dedup_and_sort_preserves_case() {
    let input = vec!["Alert".to_string(), "alert".to_string()];
    let result = dedup_and_sort(input);
    assert_eq!(result.len(), 2, "case-sensitive dedup");
}

#[test]
fn test_dedup_and_sort_empty() {
    assert!(dedup_and_sort(vec![]).is_empty());
}

#[test]
fn test_default_registry_seeds_providers() {
    let providers = list_payload_providers();
    assert!(providers.contains(&"payloadbox".to_string()));
    assert!(providers.contains(&"portswigger".to_string()));
}

#[test]
fn test_default_registry_seeds_wordlists() {
    let providers = list_wordlist_providers();
    assert!(providers.contains(&"assetnote".to_string()));
    assert!(providers.contains(&"burp".to_string()));
}

#[test]
fn test_register_custom_payload_provider() {
    register_payload_provider(
        "custom",
        vec!["https://example.com/payloads.txt".to_string()],
    );
    let providers = list_payload_providers();
    assert!(providers.contains(&"custom".to_string()));
}

#[test]
fn test_register_payload_provider_case_insensitive() {
    register_payload_provider("MyProvider", vec!["https://example.com/p.txt".to_string()]);
    let providers = list_payload_providers();
    assert!(providers.contains(&"myprovider".to_string()));
}

#[test]
fn test_collect_payload_urls_unknown_provider_returns_empty() {
    let urls = PAYLOADS.collect_urls(&["nonexistent".to_string()]);
    assert!(urls.is_empty());
}

#[test]
fn test_collect_payload_urls_known_provider() {
    let urls = PAYLOADS.collect_urls(&["payloadbox".to_string()]);
    assert!(!urls.is_empty());
    assert!(urls[0].contains("payloadbox"));
}

#[test]
fn test_collect_payload_urls_dedups_repeated_provider_names() {
    // A caller repeating the same provider name must NOT expand into N copies
    // of its URLs (that would fan out into N concurrent fetches per URL — a
    // single-request amplification). The result is the distinct URL set.
    register_payload_provider(
        "dedup_probe",
        vec![
            "https://example.com/a.txt".to_string(),
            "https://example.com/b.txt".to_string(),
        ],
    );
    let repeated = vec!["dedup_probe".to_string(); 50];
    let urls = PAYLOADS.collect_urls(&repeated);
    assert_eq!(
        urls.len(),
        2,
        "repeated provider names must collapse to the distinct URL set"
    );
}

#[test]
fn test_register_custom_wordlist_provider() {
    register_wordlist_provider(
        "customwords",
        vec!["https://example.com/words.txt".to_string()],
    );
    let providers = list_wordlist_providers();
    assert!(providers.contains(&"customwords".to_string()));
}

#[test]
fn test_register_wordlist_provider_case_insensitive() {
    register_wordlist_provider("MyWordlist", vec!["https://example.com/w.txt".to_string()]);
    let providers = list_wordlist_providers();
    assert!(providers.contains(&"mywordlist".to_string()));
    // The lowercased key resolves back to the registered URL.
    let urls = WORDLISTS.collect_urls(&["MYWORDLIST".to_string()]);
    assert_eq!(urls, vec!["https://example.com/w.txt".to_string()]);
}

#[test]
fn test_register_wordlist_provider_overwrites_existing_urls() {
    register_wordlist_provider("dupword", vec!["https://example.com/v1.txt".to_string()]);
    register_wordlist_provider("dupword", vec!["https://example.com/v2.txt".to_string()]);
    let urls = WORDLISTS.collect_urls(&["dupword".to_string()]);
    assert_eq!(urls, vec!["https://example.com/v2.txt".to_string()]);
}

#[test]
fn test_collect_wordlist_urls_unknown_provider_returns_empty() {
    let urls = WORDLISTS.collect_urls(&["definitely_not_registered".to_string()]);
    assert!(urls.is_empty());
}

#[test]
fn test_collect_wordlist_urls_known_provider() {
    let urls = WORDLISTS.collect_urls(&["burp".to_string()]);
    assert!(!urls.is_empty());
    assert!(urls[0].contains("wl-params"));
}

#[test]
fn test_collect_payload_urls_multiple_providers_concatenated() {
    let urls = PAYLOADS.collect_urls(&["payloadbox".to_string(), "portswigger".to_string()]);
    // Both known providers contribute one URL each, in request order.
    assert_eq!(urls.len(), 2);
    assert!(urls.iter().any(|u| u.contains("payloadbox")));
    assert!(urls.iter().any(|u| u.contains("portswigger")));
}

#[test]
fn test_build_remote_client_default_opts() {
    let client = build_remote_client(&RemoteFetchOptions::default());
    assert!(client.is_ok());
}

#[test]
fn test_build_remote_client_with_timeout_and_proxy() {
    let opts = RemoteFetchOptions {
        timeout_secs: Some(3),
        proxy: Some("http://127.0.0.1:8080".to_string()),
    };
    let client = build_remote_client(&opts);
    assert!(client.is_ok());
}

#[test]
fn test_build_remote_client_invalid_proxy_is_tolerated() {
    // A malformed proxy string makes `reqwest::Proxy::all` return Err, which
    // is swallowed (the proxy is simply not applied), so the client still
    // builds successfully rather than failing the whole fetch.
    let opts = RemoteFetchOptions {
        timeout_secs: None,
        proxy: Some("::not a url::".to_string()),
    };
    let client = build_remote_client(&opts);
    assert!(client.is_ok());
}

#[test]
fn test_sanitize_lines_keeps_inline_hash_and_slashes() {
    // Only *leading* '#', '//', ';' mark a comment; the same characters
    // mid-line are part of a real payload and must survive.
    let input = "a#b\nhttp://example.com/x\n<a href=//evil>\nval;ue\n";
    let result = sanitize_lines(input);
    assert_eq!(
        result,
        vec!["a#b", "http://example.com/x", "<a href=//evil>", "val;ue"]
    );
}

/// Only a successful response is a list. A provider that moved answers with a
/// 404 page whose lines were ingested as payloads / wordlist names.
#[tokio::test]
async fn fetch_multiple_text_lists_ignores_non_success_responses() {
    use axum::{Router, http::StatusCode, routing::get};

    let app = Router::new()
        .route("/ok", get(|| async { "alpha\nbeta\n" }))
        .route(
            "/gone",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    "<html>\n<h1>404 Not Found</h1>\n</html>\n",
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = build_remote_client(&RemoteFetchOptions::default()).expect("client");
    let (text, failed) = fetch_multiple_text_lists(
        &client,
        &[format!("http://{addr}/ok"), format!("http://{addr}/gone")],
    )
    .await;
    server.abort();

    assert_eq!(failed, 1);
    let lines = sanitize_lines(&text);
    assert!(lines.contains(&"alpha".to_string()));
    assert!(
        !lines.iter().any(|l| l.contains("404")),
        "an error page must not become list entries: {lines:?}"
    );
}

/// One provider URL failing must not pin the surviving half as the complete
/// list: once the retry backoff passes, the next init for the same provider
/// set fetches again and picks up the recovered URL.
#[tokio::test]
async fn partial_fetch_is_retried_not_pinned() {
    use axum::{Router, http::StatusCode, routing::get};
    use std::sync::atomic::{AtomicBool, Ordering};

    let healthy = Arc::new(AtomicBool::new(false));
    let flag = healthy.clone();
    let app = Router::new()
        .route("/a", get(|| async { "alpha\n" }))
        .route(
            "/b",
            get(move || {
                let ok = flag.load(Ordering::SeqCst);
                async move {
                    if ok {
                        (StatusCode::OK, "beta\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "down\n")
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let name = "partial-retry-test-provider";
    register_payload_provider(
        name,
        vec![format!("http://{addr}/a"), format!("http://{addr}/b")],
    );
    let providers = vec![name.to_string()];

    init_remote_payloads_with(&providers, RemoteFetchOptions::default())
        .await
        .expect("partial fetch still serves the survivors");
    let first = get_remote_payloads_for(&providers).expect("cached");
    assert_eq!(*first, vec!["alpha".to_string()]);

    // Within the backoff a dead URL is not re-fetched on every job.
    healthy.store(true, Ordering::SeqCst);
    init_remote_payloads_with(&providers, RemoteFetchOptions::default())
        .await
        .expect("backoff serves the cached survivors");
    assert_eq!(*get_remote_payloads_for(&providers).unwrap(), *first);

    PAYLOADS
        .cache
        .expire_partial(&provider_cache_key(&providers));
    init_remote_payloads_with(&providers, RemoteFetchOptions::default())
        .await
        .expect("retry succeeds");
    let second = get_remote_payloads_for(&providers).expect("cached");
    assert_eq!(*second, vec!["alpha".to_string(), "beta".to_string()]);

    // Now complete: a further init is a no-op even though the server is gone.
    server.abort();
    init_remote_payloads_with(&providers, RemoteFetchOptions::default())
        .await
        .expect("complete entry is not refetched");
    assert_eq!(get_remote_payloads_for(&providers).unwrap().len(), 2);
}
