use urlencoding;

/// URL-encodes the given payload string.
/// Example: "<" becomes "%3C"
pub fn url_encode(payload: &str) -> String {
    urlencoding::encode(payload).to_string()
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
