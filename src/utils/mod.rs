/*!
Utility helpers for Dalfox.

This module re-exports commonly used helpers so other modules can simply
`use crate::utils::*;` or import the specific functions directly.
*/

pub mod banner;
pub mod fs;
pub mod http;
pub mod rate_limit;
pub mod scan_id;
pub mod shimmer;
pub mod term;

// Re-export banner helpers at `crate::utils::*`
pub use banner::print_banner_once;
// Re-export scan_id helpers at `crate::utils::*`
pub use scan_id::{make_scan_id, make_unique_scan_id, short_scan_id};
// Re-export http helpers at `crate::utils::*`
pub use http::{
    apply_header_overrides, apply_headers_ua_cookies, build_preflight_request, build_request,
    build_request_with_cookie, compose_cookie_header_excluding, content_type_primary,
    is_htmlish_content_type, is_xss_scannable_content_type, send_with_retry,
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
    if !payload_providers.is_empty() {
        crate::payload::init_remote_payloads_with(payload_providers, opts.clone()).await?;
    }
    if !wordlist_providers.is_empty() {
        crate::payload::init_remote_wordlists_with(wordlist_providers, opts).await?;
    }
    Ok(())
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
    if !payload_providers.is_empty() {
        crate::payload::init_remote_payloads_with(payload_providers, opts.clone()).await?;
    }
    if !wordlist_providers.is_empty() {
        crate::payload::init_remote_wordlists_with(wordlist_providers, opts).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
