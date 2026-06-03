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
        .map_or(0, |d| d.as_nanos());

    make_scan_id_with_nonce(seed, now)
}

/// Generate a scan id that is unique with respect to an existing-id predicate.
///
/// `make_scan_id` already mixes in a nanosecond nonce, so a clash is
/// vanishingly rare — but two same-seed submissions landing in the same
/// nanosecond would otherwise collide. This regenerates (varying the seed with
/// an attempt suffix, which also re-draws the nonce) until `exists` returns
/// false. Callers hold whatever lock guards their id store and pass a closure
/// that checks membership, so the check-and-reserve stays atomic at the call
/// site. Shared by the REST server's `/scan` handlers and the MCP scan tool.
pub fn make_unique_scan_id(seed: &str, exists: impl Fn(&str) -> bool) -> String {
    let mut id = make_scan_id(seed);
    let mut attempt: u32 = 0;
    while exists(&id) {
        attempt += 1;
        id = make_scan_id(&format!("{}#{}", seed, attempt));
    }
    id
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
mod tests;
