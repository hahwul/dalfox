//! Shared helpers for constructing injected URLs for reflection / DOM XSS testing.
//!
//! This consolidates logic that previously appeared in multiple modules (reflection checks,
//! scanning orchestration, etc.). Centralizing the transformation avoids subtle divergence
//! (e.g., inconsistent path segment encoding or query param insertion).
//!
//! Notes:
//! - Query parameter injection: replaces existing parameter value or appends when absent.
//! - Path segment injection: parameter name pattern "path_segment_{idx}" where idx is the
//!   zero-based index of the segment in the URL path. Only simple visible encoding is
//!   applied (space, '#', '?', '%') to keep the payload recognizable in PoCs without
//!   breaking path semantics. Additional encoding strategies (full percent-encoding,
//!   unicode escaping) can be layered in higher-level modules if needed.

use crate::parameter_analysis::{Location, Param};

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Percent-encode a query component directly into `out`, preserving existing `%XX` sequences.
fn encode_query_component_preserving_pct_into(raw: &str, out: &mut String) {
    let bytes = raw.as_bytes();
    let mut idx = 0;

    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && is_hex(bytes[idx + 1])
            && is_hex(bytes[idx + 2])
        {
            out.push('%');
            out.push(bytes[idx + 1] as char);
            out.push(bytes[idx + 2] as char);
            idx += 3;
            continue;
        }

        let ch = raw[idx..].chars().next().expect("valid utf-8 char");
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).as_bytes() {
                out.push('%');
                out.push(HEX[(*byte >> 4) as usize] as char);
                out.push(HEX[(*byte & 0xF) as usize] as char);
            }
        }
        idx += ch.len_utf8();
    }
}

/// Selectively encode a path segment for readability while preserving most characters
/// for exploit clarity. This mirrors prior inline logic (space, '#', '?', '%').
/// If more rigorous encoding is desired, enhance or replace this function centrally.
fn selective_path_segment_encode(raw: &str) -> String {
    // Fast path: if no special chars, return as-is
    if !raw.bytes().any(|b| matches!(b, b' ' | b'#' | b'?' | b'%' | b'\n' | b'\t' | b'\r')) {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        match ch {
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\t' => out.push_str("%09"),
            '\r' => out.push_str("%0D"),
            _ => out.push(ch),
        }
    }
    out
}

/// Build a URL string with the given parameter injected/replaced by `injected`.
/// For Location::Query it rewrites or appends the query pair.
/// For Location::Path it replaces the indexed segment derived from param name pattern
/// "path_segment_{idx}". Other locations return the original URL unchanged.
///
/// Returns the new URL as a String. (We return String instead of Url to avoid
/// repeated parse/serialize overhead in hot loops; caller already holds original Url.)
pub fn build_injected_url(base: &url::Url, param: &Param, injected: &str) -> String {
    match param.location {
        Location::Query => {
            // Build the URL string directly without cloning Url or allocating Vec
            let base_str = base.as_str();
            // Find prefix before query (scheme + authority + path)
            let prefix = if let Some(q_pos) = base_str.find('?') {
                &base_str[..q_pos]
            } else {
                base_str
            };
            // Preserve fragment
            let fragment = base.fragment();

            let mut result = String::with_capacity(base_str.len() + injected.len() + 16);
            result.push_str(prefix);
            result.push('?');

            let mut found = false;
            let mut first = true;
            for (k, v) in base.query_pairs() {
                if !first {
                    result.push('&');
                }
                first = false;
                encode_query_component_preserving_pct_into(&k, &mut result);
                result.push('=');
                if k == param.name && !found {
                    encode_query_component_preserving_pct_into(injected, &mut result);
                    found = true;
                } else {
                    encode_query_component_preserving_pct_into(&v, &mut result);
                }
            }
            if !found {
                if !first {
                    result.push('&');
                }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
            }
            if let Some(frag) = fragment {
                result.push('#');
                result.push_str(frag);
            }
            result
        }
        Location::Path => {
            let mut url = base.clone();
            if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                let original_path = url.path().to_string();
                if original_path != "/" {
                    let encoded = selective_path_segment_encode(injected);
                    let mut new_path =
                        String::with_capacity(original_path.len() + encoded.len());
                    let segments = original_path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty());
                    let mut count = 0;
                    for (i, segment) in segments.enumerate() {
                        new_path.push('/');
                        if i == idx {
                            new_path.push_str(&encoded);
                        } else {
                            new_path.push_str(segment);
                        }
                        count = i + 1;
                    }
                    if idx < count {
                        url.set_path(&new_path);
                    }
                }
            }
            url.to_string()
        }
        Location::Body | Location::JsonBody | Location::MultipartBody => {
            // For body params, the URL itself does not change.
            // Return the base URL as-is; actual payload injection happens in the
            // request body (handled by the caller when building the request).
            base.to_string()
        }
        Location::Header => {
            // Header injection does not alter the URL.
            base.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn make_url(u: &str) -> Url {
        Url::parse(u).expect("valid url")
    }

    #[test]
    fn test_query_injection_replace() {
        let base = make_url("https://example.com/path?a=1&b=2");
        let param = Param {
            name: "a".into(),
            value: "1".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "PAY");
        assert!(out.contains("a=PAY"));
        assert!(out.contains("b=2"));
    }

    #[test]
    fn test_query_injection_append() {
        let base = make_url("https://example.com/path");
        let param = Param {
            name: "q".into(),
            value: "".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "X");
        assert!(out.contains("q=X"));
    }

    #[test]
    fn test_query_injection_preserves_existing_percent_encoding() {
        let base = make_url("https://example.com/path?q=seed");
        let param = Param {
            name: "q".into(),
            value: "seed".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "%3Cimg%20src=x%3E");
        assert!(out.contains("q=%3Cimg%20src%3Dx%3E"));
        assert!(!out.contains("%253Cimg"));
    }

    #[test]
    fn test_query_injection_encodes_raw_spaces_without_plus() {
        let base = make_url("https://example.com/path?q=seed");
        let param = Param {
            name: "q".into(),
            value: "seed".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "PAY LOAD");
        assert!(out.contains("q=PAY%20LOAD"));
    }

    #[test]
    fn test_path_injection_basic() {
        let base = make_url("https://example.com/a/b/c");
        let param = Param {
            name: "path_segment_1".into(),
            value: "b".into(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "PAY LOAD");
        // space should be %20
        assert!(out.contains("/a/PAY%20LOAD/c"));
    }

    #[test]
    fn test_path_injection_index_out_of_bounds() {
        let base = make_url("https://example.com/a");
        let param = Param {
            name: "path_segment_5".into(),
            value: "".into(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "X");
        assert_eq!(out, "https://example.com/a");
    }

    #[test]
    fn test_non_target_location_passthrough() {
        let base = make_url("https://example.com/x?y=1");
        let param = Param {
            name: "headerX".into(),
            value: "".into(),
            location: Location::Header,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "IGNORED");
        assert_eq!(out, base.as_str());
    }
}
