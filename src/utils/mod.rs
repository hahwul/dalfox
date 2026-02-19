/*!
Utility helpers for Dalfox.

This module re-exports commonly used helpers so other modules can simply
`use crate::utils::*;` or import the specific functions directly.
*/

pub mod banner;
pub mod http;
pub mod scan_id;

// Re-export banner helpers at `crate::utils::*`
pub use banner::print_banner_once;
// Re-export scan_id helpers at `crate::utils::*`
pub use scan_id::{make_scan_id, short_scan_id};
// Re-export http helpers at `crate::utils::*`
pub use http::{
    apply_header_overrides, build_preflight_request, build_request, build_request_with_cookie,
    compose_cookie_header_excluding, is_htmlish_content_type,
};

// Re-export remote payload/wordlist getters at `crate::utils::*`
pub use crate::payload::get_remote_payloads;

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
mod tests {
    use super::{init_remote_resources, init_remote_resources_with_options};

    #[tokio::test]
    async fn test_init_remote_resources_noop_when_no_providers() {
        let payloads: Vec<String> = vec![];
        let wordlists: Vec<String> = vec![];
        let result = init_remote_resources(&payloads, &wordlists).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_remote_resources_with_options_accepts_unknown_provider_tokens() {
        let payloads = vec!["__unknown_payload_provider__".to_string()];
        let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
        let result = init_remote_resources_with_options(&payloads, &wordlists, Some(1), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_remote_resources_accepts_unknown_provider_tokens() {
        let payloads = vec!["__unknown_payload_provider__".to_string()];
        let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
        let result = init_remote_resources(&payloads, &wordlists).await;
        assert!(result.is_ok());
    }
}
