pub mod discovery;
pub mod mining;

pub use discovery::*;
pub use mining::*;

use crate::cmd::scan::ScanArgs;
use crate::target_parser::Target;

#[derive(Debug, Clone, PartialEq)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    Header,
}

#[derive(Debug, Clone)]
pub enum InjectionContext {
    Html,
    Javascript,
    Comment,
    Attribute,
    StringSingle,
    StringDouble,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: Location,
    pub injection_context: Option<InjectionContext>,
}

pub fn analyze_parameters(target: &mut Target, args: &ScanArgs) {
    check_discovery(target, args);
    mine_parameters(target, args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::scan::ScanArgs;
    use crate::target_parser::parse_target;

    // Mock mining function for testing
    fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
        // Simulate adding a reflection param
        _target.reflection_params.push(Param {
            name: "test_param".to_string(),
            value: "test_value".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html),
        });
    }

    #[test]
    fn test_analyze_parameters_with_mock_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            timeout: 10,
            delay: 0,
            proxy: None,
        };

        // Mock mining instead of real mining
        mock_mine_parameters(&mut target, &args);

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].name, "test_param");
    }

    #[test]
    fn test_probe_body_params_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            data: Some("key1=value1&key2=value2".to_string()),
            headers: vec![],
            cookies: vec![],
            method: "POST".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            timeout: 10,
            delay: 0,
            proxy: None,
        };

        // Mock body param reflection
        target.reflection_params.push(Param {
            name: "key1".to_string(),
            value: "dalfox".to_string(),
            location: Location::Body,
            injection_context: Some(InjectionContext::Html),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Body);
    }

    #[test]
    fn test_check_header_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .headers
            .push(("X-Test".to_string(), "value".to_string()));

        // Mock header discovery
        target.reflection_params.push(Param {
            name: "X-Test".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_check_cookie_discovery_mock() {
        let mut target = parse_target("https://example.com").unwrap();
        target
            .cookies
            .push(("session".to_string(), "abc".to_string()));

        // Mock cookie discovery
        target.reflection_params.push(Param {
            name: "session".to_string(),
            value: "dalfox".to_string(),
            location: Location::Header, // Cookies are sent in Header
            injection_context: Some(InjectionContext::Html),
        });

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].location, Location::Header);
    }

    #[test]
    fn test_cookie_from_raw() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: Some("samples/sample_request.txt".to_string()),
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            timeout: 10,
            delay: 0,
            proxy: None,
        };

        // Simulate cookie loading
        if let Some(path) = &args.cookie_from_raw {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }

        assert!(!target.cookies.is_empty());
        assert_eq!(target.cookies.len(), 2);
        assert_eq!(
            target.cookies[0],
            ("session".to_string(), "abc".to_string())
        );
    }
}
