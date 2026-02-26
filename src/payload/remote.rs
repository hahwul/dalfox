use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use reqwest::Client;
use tokio::task::JoinSet;

/// Cache for remote XSS payloads (deduplicated, sorted).
static REMOTE_PAYLOADS: OnceLock<Arc<Vec<String>>> = OnceLock::new();

/// Cache for remote parameter wordlists (deduplicated, sorted).
static REMOTE_WORDS: OnceLock<Arc<Vec<String>>> = OnceLock::new();

/// Default timeout for remote fetch operations.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// Provider registries with default seeds and registration APIs
static PAYLOAD_PROVIDER_REGISTRY: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
static WORDLIST_PROVIDER_REGISTRY: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();

fn ensure_default_registries() {
    // Seed payload providers if empty
    {
        let reg = PAYLOAD_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut m = reg.lock().unwrap();
        if m.is_empty() {
            m.insert(
                "payloadbox".to_string(),
                vec!["https://assets.hahwul.com/xss-payloadbox.txt".to_string()],
            );
            m.insert(
                "portswigger".to_string(),
                vec!["https://assets.hahwul.com/xss-portswigger.txt".to_string()],
            );
        }
    }
    // Seed wordlist providers if empty
    {
        let reg = WORDLIST_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut m = reg.lock().unwrap();
        if m.is_empty() {
            m.insert(
                "assetnote".to_string(),
                vec!["https://assets.hahwul.com/wl-assetnote-params.txt".to_string()],
            );
            m.insert(
                "burp".to_string(),
                vec!["https://assets.hahwul.com/wl-params.txt".to_string()],
            );
        }
    }
}

// Public registration APIs
pub fn register_payload_provider<N: AsRef<str>>(name: N, urls: Vec<String>) {
    let reg = PAYLOAD_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let key = name.as_ref().to_ascii_lowercase();
    let mut m = reg.lock().unwrap();
    m.insert(key, urls);
}

pub fn register_wordlist_provider<N: AsRef<str>>(name: N, urls: Vec<String>) {
    let reg = WORDLIST_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let key = name.as_ref().to_ascii_lowercase();
    let mut m = reg.lock().unwrap();
    m.insert(key, urls);
}

// Optional helpers to enumerate providers
pub fn list_payload_providers() -> Vec<String> {
    ensure_default_registries();
    let reg = PAYLOAD_PROVIDER_REGISTRY.get().unwrap();
    let m = reg.lock().unwrap();
    m.keys().cloned().collect()
}

pub fn list_wordlist_providers() -> Vec<String> {
    ensure_default_registries();
    let reg = WORDLIST_PROVIDER_REGISTRY.get().unwrap();
    let m = reg.lock().unwrap();
    m.keys().cloned().collect()
}

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

    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(
            opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
        ))
        .danger_accept_invalid_certs(true);
    if let Some(pxy) = opts.proxy.as_ref()
        && let Ok(proxy) = reqwest::Proxy::all(pxy)
    {
        client_builder = client_builder.proxy(proxy);
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

    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(
            opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
        ))
        .danger_accept_invalid_certs(true);
    if let Some(pxy) = opts.proxy.as_ref()
        && let Ok(proxy) = reqwest::Proxy::all(pxy)
    {
        client_builder = client_builder.proxy(proxy);
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
        .danger_accept_invalid_certs(true)
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
        .danger_accept_invalid_certs(true)
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
    ensure_default_registries();
    let reg = PAYLOAD_PROVIDER_REGISTRY.get().unwrap();
    let m = reg.lock().unwrap();
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        if let Some(lst) = m.get(&p.to_ascii_lowercase()) {
            urls.extend(lst.clone());
        }
    }
    urls
}

/// Build the list of remote URLs for the given wordlist providers.
fn collect_wordlist_provider_urls(providers: &[String]) -> Vec<String> {
    ensure_default_registries();
    let reg = WORDLIST_PROVIDER_REGISTRY.get().unwrap();
    let m = reg.lock().unwrap();
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        if let Some(lst) = m.get(&p.to_ascii_lowercase()) {
            urls.extend(lst.clone());
        }
    }
    urls
}

/// Concurrently fetch multiple text endpoints and concatenate their contents.
/// Any individual fetch failure will be logged to stderr and skipped.
async fn fetch_multiple_text_lists(client: &Client, urls: &[String]) -> String {
    let mut set = JoinSet::new();
    for url in urls.iter() {
        let url = url.clone();
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

#[cfg(test)]
mod tests {
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
        assert_eq!(
            result,
            vec!["<script>alert(1)</script>", "<img src=x>"]
        );
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
    fn test_ensure_default_registries_seeds_providers() {
        ensure_default_registries();
        let providers = list_payload_providers();
        assert!(providers.contains(&"payloadbox".to_string()));
        assert!(providers.contains(&"portswigger".to_string()));
    }

    #[test]
    fn test_ensure_default_registries_seeds_wordlists() {
        ensure_default_registries();
        let providers = list_wordlist_providers();
        assert!(providers.contains(&"assetnote".to_string()));
        assert!(providers.contains(&"burp".to_string()));
    }

    #[test]
    fn test_register_custom_payload_provider() {
        register_payload_provider("custom", vec!["https://example.com/payloads.txt".to_string()]);
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
        let urls = collect_payload_provider_urls(&["nonexistent".to_string()]);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_collect_payload_urls_known_provider() {
        ensure_default_registries();
        let urls = collect_payload_provider_urls(&["payloadbox".to_string()]);
        assert!(!urls.is_empty());
        assert!(urls[0].contains("payloadbox"));
    }

    #[test]
    fn test_has_remote_payloads_initially_depends_on_test_order() {
        // This just checks that the function doesn't panic
        let _ = has_remote_payloads();
    }

    #[test]
    fn test_has_remote_wordlists_does_not_panic() {
        let _ = has_remote_wordlists();
    }
}
