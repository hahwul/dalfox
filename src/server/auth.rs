//! API-key authentication for the HTTP API.

use super::*;

/// Constant-time byte comparison. Returns false for differing lengths
/// without iterating, which leaks length only — never the contents. Used
/// for the API-key check so an attacker can't recover the key byte-by-byte
/// from response-time differences.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn check_api_key(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.api_key {
        Some(required) if !required.is_empty() => {
            if let Some(h) = headers.get("X-API-KEY")
                && let Ok(v) = h.to_str()
            {
                return constant_time_eq(v.as_bytes(), required.as_bytes());
            }
            false
        }
        _ => true, // no API key set -> allow all
    }
}
