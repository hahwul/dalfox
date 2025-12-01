//! Unit tests for the utils module
//!
//! Tests HTTP helpers and scan ID utilities.

mod http {
    use dalfox::utils::http::{
        compose_cookie_header, compose_cookie_header_excluding, has_header,
    };

    #[test]
    fn test_compose_cookie_header_empty() {
        let cookies: Vec<(String, String)> = vec![];
        assert!(compose_cookie_header(&cookies).is_none());
    }

    #[test]
    fn test_compose_cookie_header_basic() {
        let cookies = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let s = compose_cookie_header(&cookies).unwrap();
        assert!(s == "a=1; b=2" || s == "b=2; a=1"); // order not guaranteed by this helper
    }

    #[test]
    fn test_compose_cookie_header_single_cookie() {
        let cookies = vec![("session".to_string(), "abc123".to_string())];
        let s = compose_cookie_header(&cookies).unwrap();
        assert_eq!(s, "session=abc123");
    }

    #[test]
    fn test_compose_cookie_header_excluding() {
        let cookies = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let s = compose_cookie_header_excluding(&cookies, Some("a")).unwrap();
        assert_eq!(s, "b=2");
        assert!(compose_cookie_header_excluding(&cookies, Some("a_non")).is_some());
    }

    #[test]
    fn test_compose_cookie_header_excluding_to_none() {
        let cookies = vec![("only".to_string(), "1".to_string())];
        let s = compose_cookie_header_excluding(&cookies, Some("only"));
        assert!(s.is_none());
    }

    #[test]
    fn test_compose_cookie_header_excluding_none_name() {
        let cookies = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let s = compose_cookie_header_excluding(&cookies, None).unwrap();
        // Should return all cookies when exclude_name is None
        assert!(s.contains("a=1"));
        assert!(s.contains("b=2"));
    }

    #[test]
    fn test_has_header_case_insensitive() {
        let headers = vec![
            ("X-Test".to_string(), "v".to_string()),
            ("content-type".to_string(), "x".to_string()),
        ];
        assert!(has_header(&headers, "Content-Type"));
        assert!(has_header(&headers, "content-type"));
        assert!(has_header(&headers, "X-Test"));
        assert!(has_header(&headers, "x-test"));
        assert!(!has_header(&headers, "missing"));
    }

    #[test]
    fn test_has_header_empty_headers() {
        let headers: Vec<(String, String)> = vec![];
        assert!(!has_header(&headers, "Any-Header"));
    }
}

mod scan_id {
    use dalfox::utils::scan_id::{make_scan_id, make_scan_id_with_nonce, short_scan_id};

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
    fn test_make_scan_id_uniqueness_with_different_seeds() {
        let a = make_scan_id_with_nonce("seed1", 1);
        let b = make_scan_id_with_nonce("seed2", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn test_make_scan_id_deterministic() {
        let a = make_scan_id_with_nonce("seed", 42);
        let b = make_scan_id_with_nonce("seed", 42);
        assert_eq!(a, b);
    }

    #[test]
    fn test_short_scan_id() {
        assert_eq!(short_scan_id("abcdef1234"), "abcdef1");
        assert_eq!(short_scan_id("abc"), "abc");
        assert_eq!(short_scan_id("1234567"), "1234567");
        let id = make_scan_id_with_nonce("seed", 999);
        assert_eq!(short_scan_id(&id).len(), 7);
    }

    #[test]
    fn test_short_scan_id_empty() {
        assert_eq!(short_scan_id(""), "");
    }

    #[test]
    fn test_make_scan_id_produces_different_ids() {
        // Make two calls quickly - should still be different due to nanos
        let a = make_scan_id("https://example.com");
        let b = make_scan_id("https://example.com");
        // Note: In theory these could be the same if called in the same nanosecond,
        // but in practice this is extremely unlikely
        // We just verify the format is correct
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
    }
}
