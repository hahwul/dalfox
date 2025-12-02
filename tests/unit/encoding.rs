//! Unit tests for the encoding module
//!
//! Tests URL encoding, HTML entity encoding, Base64 encoding, double URL encoding,
//! and the encoder policy application.

use dalfox::encoding::{
    apply_encoders_to_payloads, base64_encode, double_url_encode, expand_payload_with_encoders,
    html_entity_encode, url_encode,
};

mod url_encoding {
    use super::*;

    #[test]
    fn test_url_encode_special_chars() {
        assert_eq!(url_encode("<"), "%3C");
        assert_eq!(url_encode(">"), "%3E");
        assert_eq!(url_encode("&"), "%26");
        assert_eq!(url_encode("\""), "%22");
        assert_eq!(url_encode("'"), "%27");
    }

    #[test]
    fn test_url_encode_space() {
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn test_url_encode_script_tag() {
        assert_eq!(
            url_encode("<script>alert(1)</script>"),
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
        );
    }

    #[test]
    fn test_url_encode_empty_string() {
        assert_eq!(url_encode(""), "");
    }
}

mod html_entity_encoding {
    use super::*;

    #[test]
    fn test_html_entity_encode_special_chars() {
        assert_eq!(html_entity_encode("<"), "&#x003c;");
        assert_eq!(html_entity_encode(">"), "&#x003e;");
        assert_eq!(html_entity_encode("&"), "&#x0026;");
        assert_eq!(html_entity_encode("\""), "&#x0022;");
        assert_eq!(html_entity_encode("'"), "&#x0027;");
    }

    #[test]
    fn test_html_entity_encode_hello_world() {
        assert_eq!(
            html_entity_encode("hello world"),
            "&#x0068;&#x0065;&#x006c;&#x006c;&#x006f;&#x0020;&#x0077;&#x006f;&#x0072;&#x006c;&#x0064;"
        );
    }

    #[test]
    fn test_html_entity_encode_script_tag() {
        assert_eq!(
            html_entity_encode("<script>alert(1)</script>"),
            "&#x003c;&#x0073;&#x0063;&#x0072;&#x0069;&#x0070;&#x0074;&#x003e;&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x0028;&#x0031;&#x0029;&#x003c;&#x002f;&#x0073;&#x0063;&#x0072;&#x0069;&#x0070;&#x0074;&#x003e;"
        );
    }

    #[test]
    fn test_html_entity_encode_empty_string() {
        assert_eq!(html_entity_encode(""), "");
    }
}

mod double_url_encoding {
    use super::*;

    #[test]
    fn test_double_url_encode_special_chars() {
        assert_eq!(double_url_encode("<"), "%253C");
        assert_eq!(double_url_encode(">"), "%253E");
        assert_eq!(double_url_encode("&"), "%2526");
        assert_eq!(double_url_encode("\""), "%2522");
        assert_eq!(double_url_encode("'"), "%2527");
    }

    #[test]
    fn test_double_url_encode_space() {
        assert_eq!(double_url_encode("hello world"), "hello%2520world");
    }

    #[test]
    fn test_double_url_encode_mixed() {
        assert_eq!(double_url_encode("a<b"), "a%253Cb");
    }

    #[test]
    fn test_double_url_encode_script_tag() {
        assert_eq!(
            double_url_encode("<script>alert(1)</script>"),
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
        );
    }

    #[test]
    fn test_double_url_encode_empty_string() {
        assert_eq!(double_url_encode(""), "");
    }
}

mod base64_encoding {
    use super::*;

    #[test]
    fn test_base64_encode_special_chars() {
        assert_eq!(base64_encode("<"), "PA==");
        assert_eq!(base64_encode(">"), "Pg==");
        assert_eq!(base64_encode("&"), "Jg==");
        assert_eq!(base64_encode("\""), "Ig==");
        assert_eq!(base64_encode("'"), "Jw==");
    }

    #[test]
    fn test_base64_encode_hello_world() {
        assert_eq!(base64_encode("hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn test_base64_encode_script_tag() {
        assert_eq!(
            base64_encode("<script>alert(1)</script>"),
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        );
    }
}

mod encoding_round_trip {
    use super::*;

    #[test]
    fn test_encoding_round_trip_produces_different_outputs() {
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
    fn test_special_characters_are_encoded() {
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

mod encoder_policy {
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

    #[test]
    fn test_apply_encoders_empty_input() {
        let bases: Vec<String> = vec![];
        let encs = vec!["url".to_string()];
        let out = apply_encoders_to_payloads(&bases, &encs);
        assert!(out.is_empty());
    }

    #[test]
    fn test_apply_encoders_empty_encoders() {
        let bases = vec!["<x>".to_string()];
        let encs: Vec<String> = vec![];
        let out = apply_encoders_to_payloads(&bases, &encs);
        // With no encoders, only originals should be returned
        assert_eq!(out, vec!["<x>".to_string()]);
    }
}
