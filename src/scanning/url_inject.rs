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
        Location::Fragment => {
            // Fragment injection: replace the target param value inside the URL fragment.
            // Supports SPA-style routing fragments like `#/redir?url=value` and simple
            // `#key=value` fragments.
            let base_str = base.as_str();
            let frag = base.fragment().unwrap_or("");

            // Split fragment into route prefix and query part
            let (route_prefix, query_part) = if let Some(q_pos) = frag.find('?') {
                (&frag[..q_pos], &frag[q_pos + 1..])
            } else {
                // No '?' — treat the whole fragment as key=value pairs
                ("", frag)
            };

            // Parse key=value pairs from the query part
            let pairs: Vec<(&str, &str)> = query_part
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|pair| {
                    if let Some((k, v)) = pair.split_once('=') {
                        (k, v)
                    } else {
                        (pair, "")
                    }
                })
                .collect();

            // Rebuild the fragment with injected value
            let mut new_frag = String::with_capacity(frag.len() + injected.len() + 16);
            new_frag.push_str(route_prefix);
            if !route_prefix.is_empty() || !pairs.is_empty() {
                if !route_prefix.is_empty() {
                    new_frag.push('?');
                }
            }

            let mut found = false;
            let mut first = true;
            for (k, v) in &pairs {
                if !first {
                    new_frag.push('&');
                }
                first = false;
                new_frag.push_str(k);
                new_frag.push('=');
                if *k == param.name && !found {
                    new_frag.push_str(injected);
                    found = true;
                } else {
                    new_frag.push_str(v);
                }
            }
            if !found {
                if !first {
                    new_frag.push('&');
                }
                new_frag.push_str(&param.name);
                new_frag.push('=');
                new_frag.push_str(injected);
            }

            // Build result: everything before '#' + new fragment
            let prefix = if let Some(hash_pos) = base_str.find('#') {
                &base_str[..hash_pos]
            } else {
                base_str
            };
            let mut result = String::with_capacity(prefix.len() + 1 + new_frag.len());
            result.push_str(prefix);
            result.push('#');
            result.push_str(&new_frag);
            result
        }
    }
}

/// HPP (HTTP Parameter Pollution) strategy variants.
/// Different server stacks handle duplicate query parameters differently,
/// so we generate multiple HPP variants to increase bypass probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HppPosition {
    /// Payload appears as the last duplicate: `?p=safe&p=<payload>`
    /// Effective against: PHP/Apache (uses last), Ruby/Rack (uses last)
    Last,
    /// Payload appears as the first duplicate: `?p=<payload>&p=safe`
    /// Effective against: JSP/Tomcat (uses first), Python/Flask (uses first)
    First,
    /// Payload only, no safe decoy: `?p=<payload>&p=<payload>`
    /// Useful when server concatenates (ASP.NET/IIS joins with comma)
    Both,
}

/// Build an HPP URL variant for a query parameter.
/// Returns the URL with the parameter duplicated according to the given `position`.
/// For non-Query locations, returns `None` (HPP only applies to query params).
pub fn build_hpp_url(
    base: &url::Url,
    param: &Param,
    injected: &str,
    position: HppPosition,
) -> Option<String> {
    if param.location != Location::Query {
        return None;
    }

    let base_str = base.as_str();
    let prefix = if let Some(q_pos) = base_str.find('?') {
        &base_str[..q_pos]
    } else {
        base_str
    };
    let fragment = base.fragment();

    let safe_value = &param.value;

    let mut result = String::with_capacity(base_str.len() + injected.len() + param.name.len() + 32);
    result.push_str(prefix);
    result.push('?');

    let mut first = true;
    let mut replaced = false;

    // Rebuild existing query pairs, replacing the target param's value
    for (k, v) in base.query_pairs() {
        if k == param.name && !replaced {
            replaced = true;
            match position {
                HppPosition::Last => {
                    // safe value first, payload second
                    if !first { result.push('&'); }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(safe_value, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                }
                HppPosition::First => {
                    // payload first, safe value second
                    if !first { result.push('&'); }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(safe_value, &mut result);
                }
                HppPosition::Both => {
                    // payload in both positions
                    if !first { result.push('&'); }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                }
            }
        } else {
            if !first { result.push('&'); }
            first = false;
            encode_query_component_preserving_pct_into(&k, &mut result);
            result.push('=');
            encode_query_component_preserving_pct_into(&v, &mut result);
        }
    }

    // If param wasn't in the original query, append the HPP pair
    if !replaced {
        match position {
            HppPosition::Last => {
                if !first { result.push('&'); }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(safe_value, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
            }
            HppPosition::First => {
                if !first { result.push('&'); }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(safe_value, &mut result);
            }
            HppPosition::Both => {
                if !first { result.push('&'); }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
            }
        }
    }

    if let Some(frag) = fragment {
        result.push('#');
        result.push_str(frag);
    }

    Some(result)
}

/// Generate all HPP URL variants for a given payload.
/// Returns up to 3 variants (Last, First, Both) for query params, empty vec for others.
pub fn build_hpp_urls(
    base: &url::Url,
    param: &Param,
    injected: &str,
) -> Vec<(String, HppPosition)> {
    [HppPosition::Last, HppPosition::First, HppPosition::Both]
        .iter()
        .filter_map(|&pos| {
            build_hpp_url(base, param, injected, pos).map(|url| (url, pos))
        })
        .collect()
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

    #[test]
    fn test_fragment_injection_spa_route() {
        let base = make_url("http://example.com/#/redir?url=foo");
        let param = Param {
            name: "url".into(),
            value: "foo".into(),
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "javascript:alert()");
        assert_eq!(out, "http://example.com/#/redir?url=javascript:alert()");
    }

    #[test]
    fn test_fragment_injection_simple_kv() {
        let base = make_url("http://example.com/#key=val&other=123");
        let param = Param {
            name: "key".into(),
            value: "val".into(),
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "PAYLOAD");
        assert_eq!(out, "http://example.com/#key=PAYLOAD&other=123");
    }

    #[test]
    fn test_fragment_injection_append_when_absent() {
        let base = make_url("http://example.com/#/path?existing=1");
        let param = Param {
            name: "newparam".into(),
            value: "".into(),
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "INJECTED");
        assert_eq!(
            out,
            "http://example.com/#/path?existing=1&newparam=INJECTED"
        );
    }

    #[test]
    fn test_fragment_injection_no_existing_fragment() {
        let base = make_url("http://example.com/page");
        let param = Param {
            name: "url".into(),
            value: "".into(),
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "PAY");
        assert_eq!(out, "http://example.com/page#url=PAY");
    }

    #[test]
    fn test_fragment_injection_multiple_params() {
        let base = make_url("http://example.com/#/app?a=1&b=2&c=3");
        let param = Param {
            name: "b".into(),
            value: "2".into(),
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_injected_url(&base, &param, "XSS");
        assert_eq!(out, "http://example.com/#/app?a=1&b=XSS&c=3");
    }

    // --- HPP tests ---

    #[test]
    fn test_hpp_last_position() {
        let base = make_url("https://example.com/path?q=safe&b=2");
        let param = Param {
            name: "q".into(),
            value: "safe".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_hpp_url(&base, &param, "<script>", HppPosition::Last).unwrap();
        assert!(out.contains("q=safe&q=%3Cscript%3E"));
        assert!(out.contains("b=2"));
    }

    #[test]
    fn test_hpp_first_position() {
        let base = make_url("https://example.com/path?q=safe&b=2");
        let param = Param {
            name: "q".into(),
            value: "safe".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_hpp_url(&base, &param, "<script>", HppPosition::First).unwrap();
        assert!(out.contains("q=%3Cscript%3E&q=safe"));
        assert!(out.contains("b=2"));
    }

    #[test]
    fn test_hpp_both_position() {
        let base = make_url("https://example.com/path?q=safe");
        let param = Param {
            name: "q".into(),
            value: "safe".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_hpp_url(&base, &param, "PAYLOAD", HppPosition::Both).unwrap();
        assert!(out.contains("q=PAYLOAD&q=PAYLOAD"));
    }

    #[test]
    fn test_hpp_non_query_returns_none() {
        let base = make_url("https://example.com/path");
        let param = Param {
            name: "path_segment_0".into(),
            value: "path".into(),
            location: Location::Path,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        assert!(build_hpp_url(&base, &param, "PAYLOAD", HppPosition::Last).is_none());
    }

    #[test]
    fn test_hpp_absent_param_appended() {
        let base = make_url("https://example.com/path?other=1");
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
        let out = build_hpp_url(&base, &param, "XSS", HppPosition::Last).unwrap();
        assert!(out.contains("other=1"));
        assert!(out.contains("q=&q=XSS"));
    }

    #[test]
    fn test_hpp_preserves_fragment() {
        let base = make_url("https://example.com/path?q=safe#frag");
        let param = Param {
            name: "q".into(),
            value: "safe".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let out = build_hpp_url(&base, &param, "PAY", HppPosition::Last).unwrap();
        assert!(out.ends_with("#frag"));
    }

    #[test]
    fn test_build_hpp_urls_returns_3_variants() {
        let base = make_url("https://example.com/?q=safe");
        let param = Param {
            name: "q".into(),
            value: "safe".into(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            form_action_url: None,
            form_origin_url: None,
        };
        let variants = build_hpp_urls(&base, &param, "XSS");
        assert_eq!(variants.len(), 3);
        assert_eq!(variants[0].1, HppPosition::Last);
        assert_eq!(variants[1].1, HppPosition::First);
        assert_eq!(variants[2].1, HppPosition::Both);
    }
}
