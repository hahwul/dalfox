use base64::{Engine, engine::general_purpose::STANDARD};

/// Apply encoder policy to a list of base payloads and return expanded, de-duplicated variants.
/// Policy:
/// - If encoders contains "none", return only the original payloads (deduplicated), no variants.
/// - Otherwise, include original payload and, for each encoder present, append its variant(s).
/// - Encoder application order is fixed to: url, html, 2url, base64
/// - Results are de-duplicated while preserving the first occurrence order.
pub fn apply_encoders_to_payloads(base_payloads: &[String], encoders: &[String]) -> Vec<String> {
    // Dedup base first while preserving order
    let mut seen = std::collections::HashSet::new();
    let mut bases: Vec<String> = Vec::new();
    for p in base_payloads {
        if seen.insert(p.clone()) {
            bases.push(p.clone());
        }
    }

    // If "none" is selected, only originals should be used
    if encoders.iter().any(|e| e == "none") {
        return bases;
    }

    let mut out: Vec<String> = Vec::new();
    let mut out_seen = std::collections::HashSet::new();

    // Expansion order
    let prio = ["url", "html", "2url", "base64"];

    for p in bases {
        // Always include original first
        if out_seen.insert(p.clone()) {
            out.push(p.clone());
        }
        // Then encoder variants in fixed order gated by encoders set
        for e in prio {
            if encoders.iter().any(|x| x == e) {
                let v = match e {
                    "url" => url_encode(&p),
                    "html" => html_entity_encode(&p),
                    "2url" => double_url_encode(&p),
                    "base64" => base64_encode(&p),
                    _ => continue,
                };
                if out_seen.insert(v.clone()) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Convenience helper to expand a single payload with encoders using the same policy.
pub fn expand_payload_with_encoders(payload: &str, encoders: &[String]) -> Vec<String> {
    apply_encoders_to_payloads(&[payload.to_string()], encoders)
}

#[cfg(test)]
mod encoder_policy_tests {
    use super::*;

    #[test]
    fn test_apply_encoders_none_only() {
        let bases = vec!["<x>".to_string(), "<x>".to_string()];
        let encs = vec!["none".to_string()];
        let out = apply_encoders_to_payloads(&bases, &encs);
        // Only unique originals
        assert_eq!(out, vec!["<x>".to_string()]);
    }

    #[test]
    fn test_apply_encoders_order_and_dedup() {
        let bases = vec!["<x>".to_string()];
        let encs = vec!["url".to_string(), "html".to_string()];
        let out = apply_encoders_to_payloads(&bases, &encs);
        assert!(out.contains(&"<x>".to_string()));
        assert!(out.contains(&url_encode("<x>")));
        assert!(out.contains(&html_entity_encode("<x>")));
        // No duplicates
        let mut set = std::collections::HashSet::new();
        assert!(out.iter().all(|p| set.insert(p)));
    }

    #[test]
    fn test_expand_single_payload() {
        let out =
            expand_payload_with_encoders("<", &vec!["2url".to_string(), "base64".to_string()]);
        assert!(out.contains(&"<".to_string()));
        assert!(out.contains(&double_url_encode("<")));
        assert!(out.contains(&base64_encode("<")));
    }
}
use urlencoding;

/// URL-encodes the given payload string.
/// Example: "<" becomes "%3C"
pub fn url_encode(payload: &str) -> String {
    urlencoding::encode(payload).to_string()
}

/// Base64-encodes the given payload string.
/// Example: "<" becomes "PA=="
pub fn base64_encode(payload: &str) -> String {
    STANDARD.encode(payload)
}

/// HTML entity-encodes the given payload string using hex entities.
/// Example: "<" becomes "&#x003c;"
pub fn html_entity_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|c| format!("&#x{:04x};", c as u32))
        .collect()
}

/// Double URL-encodes the given payload string.
/// First encodes, then encodes the result again.
/// Example: "<" becomes "%253C"
pub fn double_url_encode(payload: &str) -> String {
    url_encode(&url_encode(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("<"), "%3C");
        assert_eq!(url_encode(">"), "%3E");
        assert_eq!(url_encode("&"), "%26");
        assert_eq!(url_encode("\""), "%22");
        assert_eq!(url_encode("'"), "%27");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(
            url_encode("<script>alert(1)</script>"),
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
        );
    }

    #[test]
    fn test_html_entity_encode() {
        assert_eq!(html_entity_encode("<"), "&#x003c;");
        assert_eq!(html_entity_encode(">"), "&#x003e;");
        assert_eq!(html_entity_encode("&"), "&#x0026;");
        assert_eq!(html_entity_encode("\""), "&#x0022;");
        assert_eq!(html_entity_encode("'"), "&#x0027;");
        assert_eq!(
            html_entity_encode("hello world"),
            "&#x0068;&#x0065;&#x006c;&#x006c;&#x006f;&#x0020;&#x0077;&#x006f;&#x0072;&#x006c;&#x0064;"
        );
        assert_eq!(
            html_entity_encode("<script>alert(1)</script>"),
            "&#x003c;&#x0073;&#x0063;&#x0072;&#x0069;&#x0070;&#x0074;&#x003e;&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x0028;&#x0031;&#x0029;&#x003c;&#x002f;&#x0073;&#x0063;&#x0072;&#x0069;&#x0070;&#x0074;&#x003e;"
        );
    }

    #[test]
    fn test_double_url_encode() {
        assert_eq!(double_url_encode("<"), "%253C");
        assert_eq!(double_url_encode(">"), "%253E");
        assert_eq!(double_url_encode("&"), "%2526");
        assert_eq!(double_url_encode("\""), "%2522");
        assert_eq!(double_url_encode("'"), "%2527");
        assert_eq!(double_url_encode("hello world"), "hello%2520world");
        assert_eq!(double_url_encode("a<b"), "a%253Cb");
        assert_eq!(
            double_url_encode("<script>alert(1)</script>"),
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
        );
    }

    #[test]
    fn test_encoding_round_trip() {
        let payload = "<script>alert('XSS')</script>";
        let url_encoded = url_encode(payload);
        let double_encoded = double_url_encode(payload);
        let html_encoded = html_entity_encode(payload);

        // Ensure they are different
        assert_ne!(payload, url_encoded);
        assert_ne!(payload, double_encoded);
        assert_ne!(payload, html_encoded);
        assert_ne!(url_encoded, double_encoded);

        // Ensure double encode is encode of encode
        assert_eq!(double_encoded, url_encode(&url_encoded));
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(url_encode(""), "");
        assert_eq!(html_entity_encode(""), "");
        assert_eq!(double_url_encode(""), "");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("<"), "PA==");
        assert_eq!(base64_encode(">"), "Pg==");
        assert_eq!(base64_encode("&"), "Jg==");
        assert_eq!(base64_encode("\""), "Ig==");
        assert_eq!(base64_encode("'"), "Jw==");
        assert_eq!(base64_encode("hello world"), "aGVsbG8gd29ybGQ=");
        assert_eq!(
            base64_encode("<script>alert(1)</script>"),
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        );
    }

    #[test]
    fn test_special_characters() {
        let payload = "!@#$%^&*()_+{}|:<>?[]\\;',./";
        let url_encoded = url_encode(payload);
        let html_encoded = html_entity_encode(payload);
        let double_encoded = double_url_encode(payload);

        // Check that special chars are encoded
        assert!(url_encoded.contains("%"));
        assert!(html_encoded.contains("&#x"));
        assert!(double_encoded.contains("%25"));
    }
}
