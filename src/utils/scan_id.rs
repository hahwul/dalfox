/*!
Shared scan_id utilities.

This module provides a consistent way to generate a scan identifier that is:
- Unique per invocation (seed + current time in nanoseconds)
- Hex-encoded (SHA-256 → 64 chars)
- Easily shortenable for compact log prefixes (7 chars)

Server and CLI paths should use these helpers to ensure the same shape and behavior.
*/

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a unique scan id using the given seed (e.g., target URL)
/// combined with a high-resolution timestamp (nanoseconds).
///
/// Output is a 64-character, lowercase hex string (SHA-256).
pub fn make_scan_id(seed: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    make_scan_id_with_nonce(seed, now)
}

/// Deterministic variant for generating a scan id using a provided nonce.
/// Useful for tests or when the caller wants to control uniqueness explicitly.
///
/// Output is a 64-character, lowercase hex string (SHA-256).
pub fn make_scan_id_with_nonce(seed: &str, nonce: u128) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", seed, nonce));
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Return a compact, 7-character prefix of a scan id for log display.
///
/// If the input is shorter than 7 chars, returns it as-is.
/// Intended for use like:
///   log: "6bf733a start scan to https://example.com"
pub fn short_scan_id(id: &str) -> String {
    if id.len() <= 7 {
        id.to_string()
    } else {
        id[..7].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_scan_id_shape() {
        let id = make_scan_id_with_nonce("https://example.com", 42);
        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_make_scan_id_uniqueness_with_different_nonces() {
        let a = make_scan_id_with_nonce("seed", 1);
        let b = make_scan_id_with_nonce("seed", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_short_scan_id() {
        assert_eq!(short_scan_id("abcdef1234"), "abcdef1");
        assert_eq!(short_scan_id("abc"), "abc");
        let id = make_scan_id_with_nonce("seed", 999);
        assert_eq!(short_scan_id(&id).len(), 7);
    }
}
