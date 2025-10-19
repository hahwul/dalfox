use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use reqwest::Client;
use tokio::task::JoinSet;

/// Cache for remote XSS payloads (deduplicated, sorted).
static REMOTE_PAYLOADS: OnceLock<Arc<Vec<String>>> = OnceLock::new();

/// Cache for remote parameter wordlists (deduplicated, sorted).
static REMOTE_WORDS: OnceLock<Arc<Vec<String>>> = OnceLock::new();

/// Default timeout for remote fetch operations.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

#[derive(Clone, Debug, Default)]
pub struct RemoteFetchOptions {
    pub timeout_secs: Option<u64>,
    pub proxy: Option<String>,
}

/// Initialize and cache remote XSS payloads with explicit options (timeout/proxy).
/// This is idempotent: subsequent calls are no-ops once initialized.
pub async fn init_remote_payloads_with(
    providers: &[String],
    opts: RemoteFetchOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if REMOTE_PAYLOADS.get().is_some() {
        return Ok(());
    }

    let urls = collect_payload_provider_urls(providers);
    if urls.is_empty() {
        let _ = REMOTE_PAYLOADS.set(Arc::new(Vec::new()));
        return Ok(());
    }

    let mut client_builder = Client::builder().timeout(Duration::from_secs(
        opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
    ));
    if let Some(pxy) = opts.proxy.as_ref() {
        if let Ok(proxy) = reqwest::Proxy::all(pxy) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    let _ = REMOTE_PAYLOADS.set(Arc::new(dedup_sorted));
    Ok(())
}

/// Initialize and cache remote parameter wordlists with explicit options (timeout/proxy).
/// This is idempotent: subsequent calls are no-ops once initialized.
pub async fn init_remote_wordlists_with(
    providers: &[String],
    opts: RemoteFetchOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if REMOTE_WORDS.get().is_some() {
        return Ok(());
    }

    let urls = collect_wordlist_provider_urls(providers);
    if urls.is_empty() {
        let _ = REMOTE_WORDS.set(Arc::new(Vec::new()));
        return Ok(());
    }

    let mut client_builder = Client::builder().timeout(Duration::from_secs(
        opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
    ));
    if let Some(pxy) = opts.proxy.as_ref() {
        if let Ok(proxy) = reqwest::Proxy::all(pxy) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    let _ = REMOTE_WORDS.set(Arc::new(dedup_sorted));
    Ok(())
}

/// Public API: Initialize and cache remote XSS payloads for the given providers.
/// - providers: case-insensitive tokens such as "portswigger", "payloadbox"
/// - Returns Ok(()) when initialized or already initialized. Never panics.
pub async fn init_remote_payloads(providers: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if REMOTE_PAYLOADS.get().is_some() {
        // Already initialized – idempotent
        return Ok(());
    }

    let urls = collect_payload_provider_urls(providers);
    if urls.is_empty() {
        // No recognized providers – set empty cache
        let _ = REMOTE_PAYLOADS.set(Arc::new(Vec::new()));
        return Ok(());
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    let _ = REMOTE_PAYLOADS.set(Arc::new(dedup_sorted));
    Ok(())
}

/// Public API: Get a clone of the cached remote XSS payloads (if initialized).
/// Returns None if `init_remote_payloads` has not been called yet.
pub fn get_remote_payloads() -> Option<Arc<Vec<String>>> {
    REMOTE_PAYLOADS.get().cloned()
}

/// Public API: Initialize and cache remote parameter wordlists for the given providers.
/// - providers: case-insensitive tokens such as "burp", "assetnote"
/// - Returns Ok(()) when initialized or already initialized. Never panics.
pub async fn init_remote_wordlists(providers: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if REMOTE_WORDS.get().is_some() {
        // Already initialized – idempotent
        return Ok(());
    }

    let urls = collect_wordlist_provider_urls(providers);
    if urls.is_empty() {
        // No recognized providers – set empty cache
        let _ = REMOTE_WORDS.set(Arc::new(Vec::new()));
        return Ok(());
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    let _ = REMOTE_WORDS.set(Arc::new(dedup_sorted));
    Ok(())
}

/// Public API: Get a clone of the cached remote parameter words (if initialized).
/// Returns None if `init_remote_wordlists` has not been called yet.
pub fn get_remote_words() -> Option<Arc<Vec<String>>> {
    REMOTE_WORDS.get().cloned()
}

/// Helper: Return true if remote payloads have been initialized.
pub fn has_remote_payloads() -> bool {
    REMOTE_PAYLOADS.get().is_some()
}

/// Helper: Return true if remote wordlists have been initialized.
pub fn has_remote_wordlists() -> bool {
    REMOTE_WORDS.get().is_some()
}

/// Build the list of remote URLs for the given payload providers.
fn collect_payload_provider_urls(providers: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        match p.to_ascii_lowercase().as_str() {
            // PayloadBox XSS payloads
            // Reference: payloadbox/xss-payload-list
            "payloadbox" => {
                urls.push("https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt".to_string());
                // Alternative (extra) lists can be appended here if desired in the future
            }
            // PortSwigger XSS cheat sheet data (best-effort; repository structure may change)
            // If the URL is unavailable, it will be skipped gracefully.
            "portswigger" => {
                // Note: This is a best-effort endpoint. If the upstream path changes, fetching will simply fail silently.
                urls.push("https://raw.githubusercontent.com/PortSwigger/xss-cheatsheet-data/master/output/payloads.txt".to_string());
            }
            // Unknown provider – ignore
            _ => {}
        }
    }
    urls
}

/// Build the list of remote URLs for the given wordlist providers.
fn collect_wordlist_provider_urls(providers: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        match p.to_ascii_lowercase().as_str() {
            // Assetnote parameter wordlist
            "assetnote" => {
                urls.push(
                    "https://raw.githubusercontent.com/assetnote/wordlists/master/data/parameters.txt"
                        .to_string(),
                );
            }
            // Burp parameter names (via SecLists)
            "burp" => {
                urls.push("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt".to_string());
            }
            // Unknown provider – ignore
            _ => {}
        }
    }
    urls
}

/// Concurrently fetch multiple text endpoints and concatenate their contents.
/// Any individual fetch failure will be logged to stderr and skipped.
async fn fetch_multiple_text_lists(client: &Client, urls: &[String]) -> String {
    let mut set = JoinSet::new();
    for url in urls.iter().cloned() {
        let client = client.clone();
        set.spawn(async move {
            match client.get(&url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(text) => Some(text),
                    Err(e) => {
                        eprintln!("[remote] failed to read body from {}: {}", url, e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("[remote] failed to fetch {}: {}", url, e);
                    None
                }
            }
        });
    }

    let mut out = String::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(text)) = res {
            out.push('\n');
            out.push_str(&text);
        }
    }
    out
}

/// Sanitize a blob of text into lines:
/// - split on newlines
/// - trim whitespace
/// - drop empty lines
/// - drop comment lines starting with '#', '//', or ';'
fn sanitize_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with('#'))
        .filter(|l| !l.starts_with("//"))
        .filter(|l| !l.starts_with(';'))
        .map(|l| l.to_string())
        .collect()
}

/// Deduplicate and sort lines (case-sensitive, stable).
fn dedup_and_sort(mut lines: Vec<String>) -> Vec<String> {
    // Use a HashSet for O(1) deduplication, then sort to have deterministic ordering.
    let mut set: HashSet<String> = HashSet::with_capacity(lines.len());
    lines.retain(|s| set.insert(s.clone()));
    lines.sort();
    lines
}
