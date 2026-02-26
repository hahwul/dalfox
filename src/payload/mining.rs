// https://github.com/1ndianl33t/Gf-Patterns/blob/master/xss.json
pub const GF_PATTERNS_PARAMS: &[&str] = &[
    "q",
    "s",
    "search",
    "lang",
    "keyword",
    "query",
    "page",
    "keywords",
    "year",
    "view",
    "email",
    "type",
    "name",
    "p",
    "callback",
    "jsonp",
    "api_key",
    "api",
    "password",
    "emailto",
    "token",
    "username",
    "csrf_token",
    "unsubscribe_token",
    "id",
    "item",
    "page_id",
    "month",
    "immagine",
    "list_type",
    "url",
    "terms",
    "categoryid",
    "key",
    "l",
    "begindate",
    "enddate",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_patterns_not_empty() {
        assert!(!GF_PATTERNS_PARAMS.is_empty());
    }

    #[test]
    fn test_gf_patterns_no_empty_entries() {
        for p in GF_PATTERNS_PARAMS {
            assert!(!p.is_empty(), "parameter name must not be empty");
        }
    }

    #[test]
    fn test_gf_patterns_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in GF_PATTERNS_PARAMS {
            assert!(seen.insert(p), "duplicate parameter: {}", p);
        }
    }

    #[test]
    fn test_gf_patterns_no_whitespace() {
        for p in GF_PATTERNS_PARAMS {
            assert_eq!(
                p.trim(),
                *p,
                "parameter '{}' should not have leading/trailing whitespace",
                p
            );
        }
    }

    #[test]
    fn test_gf_patterns_contains_common_params() {
        let expected = ["q", "search", "url", "callback", "id"];
        for e in expected {
            assert!(
                GF_PATTERNS_PARAMS.contains(&e),
                "common parameter '{}' should be in GF_PATTERNS_PARAMS",
                e
            );
        }
    }
}
