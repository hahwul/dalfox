use crate::parameter_analysis::Param;
use url::Url;

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    pub method: String,
    pub data: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub user_agent: Option<String>,
    pub reflection_params: Vec<Param>,
    pub timeout: u64,
    pub delay: u64,
    pub proxy: Option<String>,
    pub workers: usize,
    pub follow_redirects: bool,
}

pub fn parse_target(s: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let url_str = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{}", s)
    };
    let url = Url::parse(&url_str)?;
    Ok(Target {
        url,
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        reflection_params: vec![],
        timeout: 10,
        delay: 0,
        proxy: None,
        workers: 10,
        follow_redirects: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_with_scheme() {
        let target = parse_target("https://example.com").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/");
        assert_eq!(target.method, "GET");
        assert!(target.data.is_none());
        assert!(target.headers.is_empty());
        assert!(target.cookies.is_empty());
        assert!(target.user_agent.is_none());
        assert!(target.reflection_params.is_empty());
        assert_eq!(target.timeout, 10);
        assert_eq!(target.delay, 0);
        assert!(target.proxy.is_none());
        assert_eq!(target.workers, 10);
        assert_eq!(target.follow_redirects, false);
    }

    #[test]
    fn test_parse_target_without_scheme() {
        let target = parse_target("example.com").unwrap();
        assert_eq!(target.url.as_str(), "http://example.com/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_invalid_url() {
        assert!(parse_target("invalid url").is_err());
    }

    #[test]
    fn test_parse_target_with_path() {
        let target = parse_target("https://example.com/path/to/resource").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/path/to/resource");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_query() {
        let target = parse_target("https://example.com?param=value").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/?param=value");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_fragment() {
        let target = parse_target("https://example.com#section").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com/#section");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_with_port() {
        let target = parse_target("https://example.com:8080").unwrap();
        assert_eq!(target.url.as_str(), "https://example.com:8080/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_ip_address() {
        let target = parse_target("http://192.168.1.1").unwrap();
        assert_eq!(target.url.as_str(), "http://192.168.1.1/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_localhost() {
        let target = parse_target("localhost:3000").unwrap();
        assert_eq!(target.url.as_str(), "http://localhost:3000/");
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_unicode_domain() {
        // URL parsing converts unicode domains to punycode
        let target = parse_target("https://例え.テスト").unwrap();
        assert!(target.url.as_str().contains("xn--r8jz45g.xn--zckzah"));
        assert_eq!(target.method, "GET");
    }

    #[test]
    fn test_parse_target_empty_string() {
        assert!(parse_target("").is_err());
    }

    #[test]
    fn test_parse_target_only_spaces() {
        assert!(parse_target("   ").is_err());
    }

    #[test]
    fn test_parse_target_invalid_scheme() {
        assert!(parse_target("://example.com").is_err());
    }
}
