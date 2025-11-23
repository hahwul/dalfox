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

use url::form_urlencoded;

use crate::parameter_analysis::{Location, Param};

/// Selectively encode a path segment for readability while preserving most characters
/// for exploit clarity. This mirrors prior inline logic (space, '#', '?', '%').
/// If more rigorous encoding is desired, enhance or replace this function centrally.
fn selective_path_segment_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for ch in raw.chars() {
        match ch {
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '%' => out.push_str("%25"),
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
            let mut pairs: Vec<(String, String)> = base
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param.name {
                    pair.1 = injected.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param.name.clone(), injected.to_string()));
            }
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = base.clone();
            url.set_query(Some(&query));
            url.to_string()
        }
        Location::Path => {
            let mut url = base.clone();
            if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                let original_path = url.path();
                let mut segments: Vec<String> = if original_path == "/" {
                    Vec::new()
                } else {
                    original_path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                };
                if idx < segments.len() {
                    segments[idx] = selective_path_segment_encode(injected);
                    let new_path = if segments.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", segments.join("/"))
                    };
                    url.set_path(&new_path);
                }
            }
            url.to_string()
        }
        _ => base.to_string(),
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
        };
        let out = build_injected_url(&base, &param, "X");
        assert!(out.contains("q=X"));
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
        };
        let out = build_injected_url(&base, &param, "IGNORED");
        assert_eq!(out, base.as_str());
    }
}
