/*!
Utility helpers for Dalfox.

This module re-exports commonly used helpers so other modules can simply
`use crate::utils::*;` or import the specific functions directly.
*/

pub mod banner;
pub mod fs;
pub mod html;
pub mod http;
pub mod log;
pub mod rate_limit;
pub mod scan_id;
pub mod shimmer;
pub mod term;

/// Largest permit count `tokio::sync::Semaphore::new` accepts; it asserts
/// above this. Taken from tokio's own public constant rather than hand-copying
/// its `usize::MAX >> 3` definition, which is a private detail tokio is free to
/// change — a stale local copy would make this clamp itself the panic.
pub const MAX_SEMAPHORE_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// Clamp a configured concurrency into the range `Semaphore::new` accepts.
///
/// Concurrency knobs (`--workers`, `--max-concurrent-targets`) reach a
/// semaphore from four surfaces: the CLI, a config file, the REST
/// `ScanOptions`, and MCP. Only the CLI path runs `validate_numeric_args`, and
/// even there `max_concurrent_targets` is checked for zero but has no upper
/// bound — so an absurd value used to reach `Semaphore::new` and panic the
/// scanner on user input.
///
/// Both ends matter, and the lower one is the more damaging: `Semaphore::new(0)`
/// is not a slow scan, it is a permanent deadlock — every worker blocks on
/// `acquire()` forever and the scan hangs with no output. A helper whose whole
/// point is holding regardless of which validator ran must therefore floor at 1
/// as well as cap. Anything near the ceiling is already "effectively
/// unlimited", so no realistic scan changes.
pub fn semaphore_permits(requested: usize) -> usize {
    requested.clamp(1, MAX_SEMAPHORE_PERMITS)
}

// Re-export banner helpers at `crate::utils::*`
pub use banner::print_banner_once;
// Re-export scan_id helpers at `crate::utils::*`
pub use scan_id::{make_scan_id, make_unique_scan_id, short_scan_id};
// Re-export http helpers at `crate::utils::*`
pub use http::{
    apply_header_overrides, apply_headers_ua_cookies, build_preflight_request, build_request,
    build_request_with_cookie, compose_cookie_header_excluding, content_type_is_inert_data,
    content_type_is_inert_data_with_nosniff, content_type_primary, headers_declare_nosniff,
    is_htmlish_content_type, is_javascript_content_type, is_xss_scannable_content_type,
    send_with_retry,
};

// Re-export remote payload/wordlist getters at `crate::utils::*`
pub use crate::payload::get_remote_payloads;

/// Stable per-finding identity fingerprint for SARIF `partialFingerprints`
/// and any other dedup consumer that compares results across scan runs.
///
/// Built from the *vulnerability* identity, not the *payload variant*: two
/// payloads that surface the same logical issue (e.g. an `R` and a `V` for
/// the same parameter and injection context) hash to the same fingerprint.
/// Re-running the scan against an unchanged target yields the same value
/// — that's the property SARIF consumers rely on to dedupe re-scans.
///
/// Inputs are joined into a single string before hashing so a future
/// reordering of fields can't silently change the output for existing
/// findings.
///
/// Returns a 16-char lowercase hex string (truncated SHA-256). 64 bits
/// is plenty of collision resistance for finding identity within a run,
/// and it keeps SARIF output compact.
pub fn stable_finding_fingerprint(
    target_url: &str,
    param: &str,
    inject_type: &str,
    cwe: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "v1|{}|{}|{}|{}",
        target_identity_key_owned(target_url),
        param,
        inject_type,
        cwe
    ));
    let digest = hasher.finalize();
    let hex_full = hex::encode(digest);
    hex_full[..16].to_string()
}

/// Owned version of the identity key used by `finding_belongs_to_target`,
/// suitable for hashing. Mirrors that helper's logic: strip query if
/// present, else key by parent path. Lives next to the matching helper
/// so the two stay in sync.
fn target_identity_key_owned(url: &str) -> String {
    let no_query = url.split('?').next().unwrap_or(url);
    if url.contains('?') {
        return no_query.to_string();
    }
    match no_query.rfind('/') {
        Some(i) => no_query[..=i].to_string(),
        None => no_query.to_string(),
    }
}

/// Decide whether a finding URL was produced by scanning a given target URL.
///
/// Used both by `collapse_redundant_reflected` (dedup) and the
/// `target_summary` attribution in CLI output, so the two stay in sync.
/// A naive `starts_with(target_url)` fails because payload variants can
/// shape the finding URL in three different ways:
///
///   - **Query/cookie/header/body injection**: payload mutates the query
///     string only — finding URL has the same path as the target, possibly
///     a different query.
///   - **Path injection**: payload replaces a path segment — finding URL
///     has the same parent path as the target but a different last segment.
///   - **No-mutation injection** (header/cookie/body without query in the
///     target): finding URL is byte-identical to the target.
///
/// We try each strategy in order. Trade-off: two targets that share the
/// same path-without-query (e.g. `/search?q=a` vs `/search?id=b`) or the
/// same parent path for path injection (e.g. `/api/v1/foo` vs
/// `/api/v1/bar`) will both match a single finding. This mirrors the
/// pre-existing prefix-match behavior; single-target scans are unaffected.
pub fn finding_belongs_to_target(target_url: &str, finding_url: &str) -> bool {
    if target_url == finding_url {
        return true;
    }
    let t_path = target_url.split('?').next().unwrap_or(target_url);
    let f_path = finding_url.split('?').next().unwrap_or(finding_url);
    if t_path == f_path {
        return true;
    }
    // Path-injection fallback: only when the target has no query string,
    // since query targets keep their path stable.
    if !target_url.contains('?')
        && let Some(i) = t_path.rfind('/')
    {
        let parent = &t_path[..=i];
        if f_path.starts_with(parent) {
            return true;
        }
    }
    false
}

/// Initialize remote resources based on CLI flags. Safe to call multiple times.
/// This default variant uses no proxy and default timeout. To customize, use
/// `init_remote_resources_with_options`.
pub async fn init_remote_resources(
    payload_providers: &[String],
    wordlist_providers: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    // Default options: no proxy, default timeout handled by fetcher
    let opts = crate::payload::RemoteFetchOptions {
        timeout_secs: None,
        proxy: None,
    };
    fetch_both(payload_providers, wordlist_providers, opts).await
}

/// Fetch both remote lists, **not** short-circuiting on the first failure, and
/// report every failure together.
///
/// The `?`-chained version stopped at the first error, which mattered once an
/// all-failed fetch started returning `Err` instead of caching an empty list: a
/// payload-provider outage silently skipped the wordlist fetch too, so a scan
/// that asked for both lost the one that was actually reachable.
async fn fetch_both(
    payload_providers: &[String],
    wordlist_providers: &[String],
    opts: crate::payload::RemoteFetchOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors: Vec<String> = Vec::new();
    if !payload_providers.is_empty()
        && let Err(e) =
            crate::payload::init_remote_payloads_with(payload_providers, opts.clone()).await
    {
        errors.push(format!("payloads: {e}"));
    }
    if !wordlist_providers.is_empty()
        && let Err(e) = crate::payload::init_remote_wordlists_with(wordlist_providers, opts).await
    {
        errors.push(format!("wordlists: {e}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; ").into())
    }
}

/// Initialize remote resources with explicit options (timeout/proxy).
/// Use this in contexts (like server jobs) where you want to honor user/network options.
pub async fn init_remote_resources_with_options(
    payload_providers: &[String],
    wordlist_providers: &[String],
    timeout_secs: Option<u64>,
    proxy: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let opts = crate::payload::RemoteFetchOptions {
        timeout_secs,
        proxy,
    };
    fetch_both(payload_providers, wordlist_providers, opts).await
}

#[cfg(test)]
mod tests;
