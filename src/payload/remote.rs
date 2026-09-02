use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use reqwest::Client;
use tokio::task::JoinSet;

/// Cache for remote XSS payloads (deduplicated, sorted), keyed by the
/// normalized provider set that produced them. See [`ProviderCache`].
static REMOTE_PAYLOADS: ProviderCache = ProviderCache::new();

/// Cache for remote parameter wordlists (deduplicated, sorted), keyed by the
/// normalized provider set that produced them. See [`ProviderCache`].
static REMOTE_WORDS: ProviderCache = ProviderCache::new();

/// Default timeout for remote fetch operations.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

/// Ceiling on distinct provider sets held in one cache.
///
/// Provider names are caller-supplied (a REST/MCP scan request carries
/// `remote_payloads` / `remote_wordlists` verbatim), so the number of distinct
/// *sets* a long-lived daemon can be asked to remember is unbounded — including
/// sets naming providers that do not exist, which cache an empty list without
/// ever touching the network. Past this many entries new sets simply are not
/// cached: they refetch each time, which is slower but never wrong.
const MAX_CACHED_PROVIDER_SETS: usize = 64;

/// A process-wide cache of fetched remote lists, keyed by provider set.
///
/// This used to be a bare `OnceLock<Arc<Vec<String>>>` — "fetch once per
/// process", which is right for the one-scan-per-process CLI and wrong for the
/// `dalfox server` / MCP daemon, where every job brings its own provider list:
///
/// * The first job to ask for *any* remote list won the cell for the life of
///   the process. A later job asking for a different provider silently scanned
///   with the first job's payloads and still reported `done`.
/// * A job naming only unrecognized providers took the `urls.is_empty()` path
///   and cached an **empty** list, poisoning every later job in the same way —
///   they short-circuited on the already-set cell and scanned with nothing.
///
/// Keying by the provider set fixes both: an entry can only ever be read back
/// by a job that asked for exactly the same providers.
struct ProviderCache(OnceLock<Mutex<HashMap<Vec<String>, Arc<Vec<String>>>>>);

impl ProviderCache {
    const fn new() -> Self {
        Self(OnceLock::new())
    }

    fn map(&self) -> &Mutex<HashMap<Vec<String>, Arc<Vec<String>>>> {
        self.0.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn get(&self, key: &[String]) -> Option<Arc<Vec<String>>> {
        let m = self.map().lock().unwrap_or_else(PoisonError::into_inner);
        m.get(key).cloned()
    }

    fn store(&self, key: Vec<String>, lines: Vec<String>) {
        let mut m = self.map().lock().unwrap_or_else(PoisonError::into_inner);
        // Never evict a live entry to make room — a job mid-scan may still read
        // it. Refusing the new one degrades to "refetch next time" instead.
        if m.len() >= MAX_CACHED_PROVIDER_SETS && !m.contains_key(&key) {
            return;
        }
        m.insert(key, Arc::new(lines));
    }

    fn is_empty(&self) -> bool {
        let m = self.map().lock().unwrap_or_else(PoisonError::into_inner);
        m.is_empty()
    }

    /// The single cached entry, or `None` when the cache holds zero or more
    /// than one provider set. Backs the legacy provider-less getters, which
    /// have no way to say *which* list they mean; see [`get_remote_payloads`].
    fn sole_entry(&self) -> Option<Arc<Vec<String>>> {
        let m = self.map().lock().unwrap_or_else(PoisonError::into_inner);
        if m.len() == 1 {
            m.values().next().cloned()
        } else {
            None
        }
    }
}

/// Normalize a caller-supplied provider list into a cache key: each name
/// trimmed and lowercased (matching how [`collect_payload_provider_urls`] looks
/// them up), blanks dropped, then deduplicated and sorted so `["Burp","assetnote"]`
/// and `["assetnote"," burp ","burp"]` name the same entry. A `Vec<String>` key
/// rather than a joined string, so a provider name containing the separator
/// cannot collide with a two-provider set.
fn provider_cache_key(providers: &[String]) -> Vec<String> {
    let mut names: Vec<String> = providers
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

// Provider registries with default seeds and registration APIs
static PAYLOAD_PROVIDER_REGISTRY: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
static WORDLIST_PROVIDER_REGISTRY: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();

fn ensure_default_registries() {
    // Seed any built-in providers that aren't already registered. Seeding each
    // default key independently (rather than gating on an empty registry) keeps
    // the defaults available even after a caller has registered a custom
    // provider first — registering "custom" must never suppress "payloadbox".
    {
        let reg = PAYLOAD_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut m = reg.lock().unwrap_or_else(PoisonError::into_inner);
        m.entry("payloadbox".to_string())
            .or_insert_with(|| vec!["https://assets.hahwul.com/xss-payloadbox.txt".to_string()]);
        m.entry("portswigger".to_string())
            .or_insert_with(|| vec!["https://assets.hahwul.com/xss-portswigger.txt".to_string()]);
    }
    {
        let reg = WORDLIST_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut m = reg.lock().unwrap_or_else(PoisonError::into_inner);
        m.entry("assetnote".to_string()).or_insert_with(|| {
            vec!["https://assets.hahwul.com/wl-assetnote-params.txt".to_string()]
        });
        m.entry("burp".to_string())
            .or_insert_with(|| vec!["https://assets.hahwul.com/wl-params.txt".to_string()]);
    }
}

// Public registration APIs
pub fn register_payload_provider<N: AsRef<str>>(name: N, urls: Vec<String>) {
    let reg = PAYLOAD_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let key = name.as_ref().to_ascii_lowercase();
    let mut m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    m.insert(key, urls);
}

pub fn register_wordlist_provider<N: AsRef<str>>(name: N, urls: Vec<String>) {
    let reg = WORDLIST_PROVIDER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let key = name.as_ref().to_ascii_lowercase();
    let mut m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    m.insert(key, urls);
}

// Optional helpers to enumerate providers
pub fn list_payload_providers() -> Vec<String> {
    ensure_default_registries();
    let Some(reg) = PAYLOAD_PROVIDER_REGISTRY.get() else {
        return Vec::new();
    };
    let m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    m.keys().cloned().collect()
}

pub fn list_wordlist_providers() -> Vec<String> {
    ensure_default_registries();
    let Some(reg) = WORDLIST_PROVIDER_REGISTRY.get() else {
        return Vec::new();
    };
    let m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    m.keys().cloned().collect()
}

#[derive(Clone, Debug, Default)]
pub struct RemoteFetchOptions {
    pub timeout_secs: Option<u64>,
    pub proxy: Option<String>,
}

/// Build a reqwest Client with the given remote fetch options (timeout, proxy).
fn build_remote_client(opts: &RemoteFetchOptions) -> Result<Client, Box<dyn std::error::Error>> {
    crate::ensure_crypto_provider();
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(
            opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
        ))
        .danger_accept_invalid_certs(true);
    if let Some(pxy) = opts.proxy.as_ref()
        && let Ok(proxy) = reqwest::Proxy::all(pxy)
    {
        builder = builder.proxy(proxy);
    }
    Ok(builder.build()?)
}

/// Initialize and cache remote XSS payloads with explicit options (timeout/proxy).
/// This is idempotent: subsequent calls are no-ops once initialized.
pub async fn init_remote_payloads_with(
    providers: &[String],
    opts: RemoteFetchOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = provider_cache_key(providers);
    if REMOTE_PAYLOADS.get(&key).is_some() {
        return Ok(());
    }

    let urls = collect_payload_provider_urls(providers);
    if urls.is_empty() {
        REMOTE_PAYLOADS.store(key, Vec::new());
        return Ok(());
    }

    let client = build_remote_client(&opts)?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    // Never cache "we got nothing" for a provider set that named real URLs: a
    // transient egress blip would otherwise pin an empty list to this provider
    // set for the daemon's lifetime, and every later job asking for the same
    // providers would scan with nothing while still reporting `done`. Leaving
    // the entry unset costs one retry and keeps the failure transient.
    if dedup_sorted.is_empty() {
        return Err("remote payload fetch returned no usable entries".into());
    }

    REMOTE_PAYLOADS.store(key, dedup_sorted);
    Ok(())
}

/// Initialize and cache remote parameter wordlists with explicit options (timeout/proxy).
/// This is idempotent: subsequent calls are no-ops once initialized.
pub async fn init_remote_wordlists_with(
    providers: &[String],
    opts: RemoteFetchOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = provider_cache_key(providers);
    if REMOTE_WORDS.get(&key).is_some() {
        return Ok(());
    }

    let urls = collect_wordlist_provider_urls(providers);
    if urls.is_empty() {
        REMOTE_WORDS.store(key, Vec::new());
        return Ok(());
    }

    let client = build_remote_client(&opts)?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    // Never cache "we got nothing" for a provider set that named real URLs: a
    // transient egress blip would otherwise pin an empty list to this provider
    // set for the daemon's lifetime, and every later job asking for the same
    // providers would scan with nothing while still reporting `done`. Leaving
    // the entry unset costs one retry and keeps the failure transient.
    if dedup_sorted.is_empty() {
        return Err("remote wordlist fetch returned no usable entries".into());
    }

    REMOTE_WORDS.store(key, dedup_sorted);
    Ok(())
}

/// Public API: Initialize and cache remote XSS payloads for the given providers.
/// - providers: case-insensitive tokens such as "portswigger", "payloadbox"
/// - Returns Ok(()) when initialized or already initialized. Never panics.
pub async fn init_remote_payloads(providers: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let key = provider_cache_key(providers);
    if REMOTE_PAYLOADS.get(&key).is_some() {
        // This provider set is already fetched – idempotent
        return Ok(());
    }

    let urls = collect_payload_provider_urls(providers);
    if urls.is_empty() {
        // No recognized providers – cache an empty list for *this* set only
        REMOTE_PAYLOADS.store(key, Vec::new());
        return Ok(());
    }

    crate::ensure_crypto_provider();
    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .danger_accept_invalid_certs(true)
        .build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    // Never cache "we got nothing" for a provider set that named real URLs: a
    // transient egress blip would otherwise pin an empty list to this provider
    // set for the daemon's lifetime, and every later job asking for the same
    // providers would scan with nothing while still reporting `done`. Leaving
    // the entry unset costs one retry and keeps the failure transient.
    if dedup_sorted.is_empty() {
        return Err("remote payload fetch returned no usable entries".into());
    }

    REMOTE_PAYLOADS.store(key, dedup_sorted);
    Ok(())
}

/// Public API: the cached remote XSS payloads fetched for `providers`.
///
/// Returns `None` when this provider set has not been initialized. Prefer this
/// over [`get_remote_payloads`] anywhere more than one scan can run in the same
/// process (the server and MCP daemons): the cache holds one entry per provider
/// set, and only the caller knows which one it asked for.
pub fn get_remote_payloads_for(providers: &[String]) -> Option<Arc<Vec<String>>> {
    REMOTE_PAYLOADS.get(&provider_cache_key(providers))
}

/// Public API: Get a clone of the cached remote XSS payloads (if initialized).
///
/// Legacy provider-less accessor for single-scan processes (the CLI). It names
/// no provider set, so it can only answer when exactly one has been fetched;
/// with zero or several cached it returns `None` rather than guessing. Callers
/// that know their provider list should use [`get_remote_payloads_for`].
pub fn get_remote_payloads() -> Option<Arc<Vec<String>>> {
    REMOTE_PAYLOADS.sole_entry()
}

/// Public API: Initialize and cache remote parameter wordlists for the given providers.
/// - providers: case-insensitive tokens such as "burp", "assetnote"
/// - Returns Ok(()) when initialized or already initialized. Never panics.
pub async fn init_remote_wordlists(providers: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let key = provider_cache_key(providers);
    if REMOTE_WORDS.get(&key).is_some() {
        // This provider set is already fetched – idempotent
        return Ok(());
    }

    let urls = collect_wordlist_provider_urls(providers);
    if urls.is_empty() {
        // No recognized providers – cache an empty list for *this* set only
        REMOTE_WORDS.store(key, Vec::new());
        return Ok(());
    }

    crate::ensure_crypto_provider();
    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .danger_accept_invalid_certs(true)
        .build()?;

    let lines = fetch_multiple_text_lists(&client, &urls).await;
    let sanitized = sanitize_lines(&lines);
    let dedup_sorted = dedup_and_sort(sanitized);

    // Never cache "we got nothing" for a provider set that named real URLs: a
    // transient egress blip would otherwise pin an empty list to this provider
    // set for the daemon's lifetime, and every later job asking for the same
    // providers would scan with nothing while still reporting `done`. Leaving
    // the entry unset costs one retry and keeps the failure transient.
    if dedup_sorted.is_empty() {
        return Err("remote wordlist fetch returned no usable entries".into());
    }

    REMOTE_WORDS.store(key, dedup_sorted);
    Ok(())
}

/// Public API: the cached remote parameter words fetched for `providers`.
///
/// Returns `None` when this provider set has not been initialized. Prefer this
/// over [`get_remote_words`] for the same reason as [`get_remote_payloads_for`].
pub fn get_remote_words_for(providers: &[String]) -> Option<Arc<Vec<String>>> {
    REMOTE_WORDS.get(&provider_cache_key(providers))
}

/// Public API: Get a clone of the cached remote parameter words (if initialized).
///
/// Legacy provider-less accessor; see [`get_remote_payloads`] for the caveat.
pub fn get_remote_words() -> Option<Arc<Vec<String>>> {
    REMOTE_WORDS.sole_entry()
}

/// Helper: Return true if any remote payload provider set has been initialized.
pub fn has_remote_payloads() -> bool {
    !REMOTE_PAYLOADS.is_empty()
}

/// Helper: Return true if any remote wordlist provider set has been initialized.
pub fn has_remote_wordlists() -> bool {
    !REMOTE_WORDS.is_empty()
}

/// Collapse a provider->URL expansion to the set of distinct URLs, preserving
/// first-seen order. Without this, a caller (e.g. an authenticated server/MCP
/// scan request) that repeats the same provider name N times — `remote_payloads:
/// ["payloadbox","payloadbox",...]` — expands 1:1 into N copies of each URL,
/// every one of which `fetch_multiple_text_lists` fetches concurrently and
/// concatenates: a deterministic memory / file-descriptor amplification from a
/// single request. Deduping makes name-spam inert (distinct providers are
/// unaffected, since their URLs differ).
fn dedup_urls(mut urls: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(urls.len());
    urls.retain(|u| seen.insert(u.clone()));
    urls
}

/// Build the list of remote URLs for the given payload providers.
fn collect_payload_provider_urls(providers: &[String]) -> Vec<String> {
    ensure_default_registries();
    let Some(reg) = PAYLOAD_PROVIDER_REGISTRY.get() else {
        return Vec::new();
    };
    let m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        if let Some(lst) = m.get(&p.to_ascii_lowercase()) {
            urls.extend(lst.clone());
        }
    }
    dedup_urls(urls)
}

/// Build the list of remote URLs for the given wordlist providers.
fn collect_wordlist_provider_urls(providers: &[String]) -> Vec<String> {
    ensure_default_registries();
    let Some(reg) = WORDLIST_PROVIDER_REGISTRY.get() else {
        return Vec::new();
    };
    let m = reg.lock().unwrap_or_else(PoisonError::into_inner);
    let mut urls: Vec<String> = Vec::new();
    for p in providers {
        if let Some(lst) = m.get(&p.to_ascii_lowercase()) {
            urls.extend(lst.clone());
        }
    }
    dedup_urls(urls)
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
                Ok(resp) => match crate::utils::http::read_body(resp).await {
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
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with('#'))
        .filter(|l| !l.starts_with("//"))
        .filter(|l| !l.starts_with(';'))
        .map(std::string::ToString::to_string)
        .collect()
}

/// Deduplicate and sort lines (case-sensitive).
fn dedup_and_sort(mut lines: Vec<String>) -> Vec<String> {
    lines.sort();
    lines.dedup();
    lines
}

#[cfg(test)]
mod tests;
