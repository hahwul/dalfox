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
fn test_deep_url_encode() {
    assert_eq!(triple_url_encode("<"), "%25253C");
    assert_eq!(quadruple_url_encode("<"), "%2525253C");
    assert_eq!(triple_url_encode("<"), url_encode(&double_url_encode("<")));
    assert_eq!(
        quadruple_url_encode("<"),
        url_encode(&triple_url_encode("<"))
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

#[test]
fn test_unicode_fullwidth_encode() {
    assert_eq!(unicode_fullwidth_encode("<"), "\u{FF1C}");
    assert_eq!(unicode_fullwidth_encode(">"), "\u{FF1E}");
    assert_eq!(unicode_fullwidth_encode("a"), "\u{FF41}");
    // Space (0x20) is outside printable range for fullwidth mapping, stays as-is
    assert_eq!(unicode_fullwidth_encode(" "), " ");
    // Full payload
    let encoded = unicode_fullwidth_encode("<script>");
    assert!(!encoded.contains('<'));
    assert!(!encoded.contains('>'));
}

#[test]
fn test_zero_width_encode() {
    let encoded = zero_width_encode("<img>");
    assert!(encoded.contains('\u{200B}'));
    // < should be followed by ZWS, > should be followed by ZWS
    assert_eq!(encoded, "<\u{200B}img>\u{200B}");
}

#[test]
fn test_zero_width_encode_preserves_non_special() {
    let encoded = zero_width_encode("abc");
    assert_eq!(encoded, "abc");
}

#[test]
fn test_html_entity_zero_padded_encode() {
    let result = html_entity_zero_padded_encode("<");
    assert!(result.contains("&#x000003c;"));
    assert!(!result.contains('<'));

    let result2 = html_entity_zero_padded_encode("<script>");
    assert!(result2.contains("&#x000003c;"));
    assert!(result2.contains("script"));
    assert!(result2.contains("&#x000003e;"));
}

#[test]
fn test_htmlpad_in_apply_encoders() {
    let bases = vec!["<x>".to_string()];
    let encs = vec!["htmlpad".to_string()];
    let out = apply_encoders_to_payloads(&bases, &encs);
    assert!(out.len() >= 2);
    assert!(out.iter().any(|p| p.contains("&#x")));
}

#[test]
fn test_generate_adaptive_encodings_angle_blocked() {
    let encoders = generate_adaptive_encodings(&['<', '>'], &['"', '\'']);
    assert!(encoders.contains(&"html".to_string()));
    assert!(encoders.contains(&"url".to_string()));
    assert!(encoders.contains(&"2url".to_string()));
    assert!(encoders.contains(&"3url".to_string()));
    assert!(encoders.contains(&"4url".to_string()));
    assert!(encoders.contains(&"unicode".to_string()));
}

#[test]
fn test_generate_adaptive_encodings_quote_blocked() {
    let encoders = generate_adaptive_encodings(&['"'], &['<', '>']);
    assert!(encoders.contains(&"html".to_string()));
    assert!(encoders.contains(&"url".to_string()));
}

#[test]
fn test_generate_adaptive_encodings_nothing_blocked() {
    let encoders = generate_adaptive_encodings(&[], &['<', '>', '"']);
    // Should at least have url as baseline
    assert!(encoders.contains(&"url".to_string()));
}

#[test]
fn test_apply_adaptive_encoding_angle_blocked() {
    let variants = apply_adaptive_encoding("<img src=x>", &['<', '>']);
    assert!(variants.len() > 1, "should produce multiple variants");
    // Original should be first
    assert_eq!(variants[0], "<img src=x>");
    // Should contain a variant with encoded angles
    assert!(variants.iter().any(|v| !v.contains('<')));
    assert!(
        variants
            .iter()
            .any(|v| v == &triple_url_encode("<img src=x>"))
    );
    assert!(
        variants
            .iter()
            .any(|v| v == &quadruple_url_encode("<img src=x>"))
    );
}

#[test]
fn test_apply_adaptive_encoding_no_block() {
    let variants = apply_adaptive_encoding("<img>", &[]);
    assert_eq!(variants.len(), 1, "no blocked chars = no extra variants");
    assert_eq!(variants[0], "<img>");
}

#[test]
fn test_selective_html_encode() {
    let result = selective_html_encode("<img src='x'>", &['<', '>']);
    assert!(!result.contains('<'));
    assert!(!result.contains('>'));
    assert!(result.contains("src='x'"));
}
