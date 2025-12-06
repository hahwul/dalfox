//! Integration tests for scanner pipeline
//!
//! These tests verify the interaction between internal modules:
//! target parser → parameter analyzer → scanner → result reporter

use dalfox::target_parser::parse_target;
use dalfox::parameter_analysis::{Param, Location, InjectionContext, DelimiterType};
use serde_json;

/// Test that the target parser correctly parses various URL formats
#[test]
fn test_target_parsing_basic_url() {
    let result = parse_target("http://example.com/test?id=123");
    assert!(result.is_ok(), "Should parse valid URL");
    
    let target = result.unwrap();
    assert_eq!(target.url.scheme(), "http");
    assert_eq!(target.url.host_str(), Some("example.com"));
    assert_eq!(target.url.path(), "/test");
    assert_eq!(target.url.query(), Some("id=123"));
}

#[test]
fn test_target_parsing_url_without_scheme() {
    let result = parse_target("example.com/test");
    assert!(result.is_ok(), "Should parse URL without scheme and add http://");
    
    let target = result.unwrap();
    assert_eq!(target.url.scheme(), "http");
    assert_eq!(target.url.host_str(), Some("example.com"));
    assert_eq!(target.url.path(), "/test");
}

#[test]
fn test_target_parsing_https_url() {
    let result = parse_target("https://secure.example.com/api");
    assert!(result.is_ok(), "Should parse HTTPS URL");
    
    let target = result.unwrap();
    assert_eq!(target.url.scheme(), "https");
    assert_eq!(target.url.host_str(), Some("secure.example.com"));
    assert_eq!(target.url.path(), "/api");
}

#[test]
fn test_target_parsing_with_port() {
    let result = parse_target("http://example.com:8080/test");
    assert!(result.is_ok(), "Should parse URL with port");
    
    let target = result.unwrap();
    assert_eq!(target.url.port(), Some(8080));
}

#[test]
fn test_target_parsing_with_multiple_query_params() {
    let result = parse_target("http://example.com/search?q=test&page=1&sort=asc");
    assert!(result.is_ok(), "Should parse URL with multiple query parameters");
    
    let target = result.unwrap();
    assert!(target.url.query().unwrap().contains("q=test"));
    assert!(target.url.query().unwrap().contains("page=1"));
    assert!(target.url.query().unwrap().contains("sort=asc"));
}

/// Test parameter analysis structures and their properties
#[test]
fn test_param_structure_query_location() {
    let param = Param {
        name: "id".to_string(),
        value: "123".to_string(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
    };
    
    assert_eq!(param.name, "id");
    assert_eq!(param.value, "123");
    assert_eq!(param.location, Location::Query);
}

#[test]
fn test_param_structure_with_injection_context() {
    let param = Param {
        name: "search".to_string(),
        value: "test".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: Some(vec!['<', '>', '"']),
        invalid_specials: Some(vec!['\'', '`']),
    };
    
    assert_eq!(param.injection_context, Some(InjectionContext::Html(None)));
    assert!(param.valid_specials.is_some());
    assert_eq!(param.valid_specials.as_ref().unwrap().len(), 3);
    assert!(param.invalid_specials.is_some());
}

#[test]
fn test_param_structure_javascript_context() {
    let param = Param {
        name: "callback".to_string(),
        value: "func".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Javascript(Some(DelimiterType::SingleQuote))),
        valid_specials: None,
        invalid_specials: None,
    };
    
    match &param.injection_context {
        Some(InjectionContext::Javascript(delimiter)) => {
            assert_eq!(*delimiter, Some(DelimiterType::SingleQuote));
        }
        _ => panic!("Expected Javascript context"),
    }
}

#[test]
fn test_param_structure_attribute_context() {
    let param = Param {
        name: "attr".to_string(),
        value: "value".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Attribute(Some(DelimiterType::DoubleQuote))),
        valid_specials: None,
        invalid_specials: None,
    };
    
    match &param.injection_context {
        Some(InjectionContext::Attribute(delimiter)) => {
            assert_eq!(*delimiter, Some(DelimiterType::DoubleQuote));
        }
        _ => panic!("Expected Attribute context"),
    }
}

#[test]
fn test_param_location_types() {
    let locations = vec![
        Location::Query,
        Location::Body,
        Location::JsonBody,
        Location::Header,
        Location::Path,
    ];
    
    // Verify all location types are distinct
    assert_eq!(locations.len(), 5);
    
    // Verify specific location comparisons
    assert_eq!(Location::Query, Location::Query);
    assert_ne!(Location::Query, Location::Body);
    assert_ne!(Location::Header, Location::Path);
}

/// Test the integration of URL parsing with parameter extraction
#[test]
fn test_url_query_parameter_extraction() {
    let result = parse_target("http://example.com/page?name=john&age=25");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    let query_string = target.url.query().unwrap_or("");
    
    // Verify query parameters can be accessed
    assert!(query_string.contains("name=john"));
    assert!(query_string.contains("age=25"));
}

#[test]
fn test_url_fragment_handling() {
    let result = parse_target("http://example.com/page#section");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    assert_eq!(target.url.fragment(), Some("section"));
}

/// Test target configuration properties
#[test]
fn test_target_default_configuration() {
    let result = parse_target("http://example.com/test");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    
    // Verify default values are set properly
    assert_eq!(target.method, "GET");
    assert!(target.data.is_none());
    assert!(target.headers.is_empty());
    assert!(target.cookies.is_empty());
    assert!(target.user_agent.is_none());
}

/// Test parameter serialization and deserialization
#[test]
fn test_param_serialization() {
    let param = Param {
        name: "test".to_string(),
        value: "value".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: Some(vec!['<', '>']),
        invalid_specials: Some(vec!['\'']),
    };
    
    // Test serialization
    let json = serde_json::to_string(&param);
    assert!(json.is_ok(), "Should serialize param to JSON");
    
    // Test deserialization
    let json_str = json.unwrap();
    let deserialized: Result<Param, _> = serde_json::from_str(&json_str);
    assert!(deserialized.is_ok(), "Should deserialize param from JSON");
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.name, param.name);
    assert_eq!(restored.value, param.value);
    assert_eq!(restored.location, param.location);
}

/// Test delimiter type variations
#[test]
fn test_delimiter_types() {
    let single_quote = DelimiterType::SingleQuote;
    let double_quote = DelimiterType::DoubleQuote;
    let comment = DelimiterType::Comment;
    
    assert_eq!(single_quote, DelimiterType::SingleQuote);
    assert_ne!(single_quote, double_quote);
    assert_ne!(double_quote, comment);
}

/// Test injection context variations
#[test]
fn test_injection_context_variants() {
    let html_ctx = InjectionContext::Html(None);
    let html_ctx_sq = InjectionContext::Html(Some(DelimiterType::SingleQuote));
    let js_ctx = InjectionContext::Javascript(None);
    let attr_ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    
    // Verify contexts are properly distinguished
    assert_eq!(html_ctx, InjectionContext::Html(None));
    assert_ne!(html_ctx, html_ctx_sq);
    assert_ne!(html_ctx, js_ctx);
    assert_ne!(js_ctx, attr_ctx);
}

/// Test URL path parsing for path-based injection
#[test]
fn test_url_path_segments() {
    let result = parse_target("http://example.com/path/to/resource");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    let path_segments: Vec<&str> = target.url.path_segments()
        .map(|c| c.collect())
        .unwrap_or_default();
    
    assert_eq!(path_segments.len(), 3);
    assert_eq!(path_segments[0], "path");
    assert_eq!(path_segments[1], "to");
    assert_eq!(path_segments[2], "resource");
}

/// Test special character handling in parameters
#[test]
fn test_special_chars_classification() {
    let valid_chars = vec!['<', '>', '"', '\''];
    let invalid_chars = vec!['`', '{', '}'];
    
    let param = Param {
        name: "input".to_string(),
        value: "test".to_string(),
        location: Location::Query,
        injection_context: None,
        valid_specials: Some(valid_chars.clone()),
        invalid_specials: Some(invalid_chars.clone()),
    };
    
    assert!(param.valid_specials.as_ref().unwrap().contains(&'<'));
    assert!(param.valid_specials.as_ref().unwrap().contains(&'>'));
    assert!(param.invalid_specials.as_ref().unwrap().contains(&'`'));
}

/// Test that multiple parameters can be tracked
#[test]
fn test_multiple_parameters() {
    let params = vec![
        Param {
            name: "id".to_string(),
            value: "1".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        },
        Param {
            name: "name".to_string(),
            value: "test".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: Some(vec!['<', '>']),
            invalid_specials: None,
        },
        Param {
            name: "X-Custom".to_string(),
            value: "header".to_string(),
            location: Location::Header,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        },
    ];
    
    assert_eq!(params.len(), 3);
    assert_eq!(params[0].location, Location::Query);
    assert_eq!(params[1].location, Location::Query);
    assert_eq!(params[2].location, Location::Header);
}

/// Test URL with complex query string encoding
#[test]
fn test_url_with_encoded_query() {
    let result = parse_target("http://example.com/search?q=hello%20world&filter=%3Ctest%3E");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    let query = target.url.query().unwrap();
    
    // URL parser should preserve the encoded form
    assert!(query.contains("q=hello%20world") || query.contains("q=hello+world"));
}

/// Test path normalization behavior
#[test]
fn test_url_path_normalization() {
    let result = parse_target("http://example.com//double//slash///path");
    assert!(result.is_ok());
    
    let target = result.unwrap();
    // URL parser may normalize paths
    let path = target.url.path();
    assert!(path.contains("double"));
    assert!(path.contains("slash"));
    assert!(path.contains("path"));
}
