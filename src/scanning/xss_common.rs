use crate::cmd::scan::ScanArgs;
use crate::encoding::{base64_encode, double_url_encode, html_entity_encode, url_encode};
use crate::parameter_analysis::{DelimiterType, InjectionContext};

// Context-specific payload lists

/// Generate dynamic payloads based on the injection context
pub fn generate_dynamic_payloads(context: &InjectionContext) -> Vec<String> {
    let mut payloads = Vec::new();

    match context {
        InjectionContext::Attribute(delimiter_type) => {
            let html_payloads = crate::payload::get_dynamic_xss_html_payloads();
            let attr_payloads = crate::payload::get_dynamic_xss_attribute_payloads();
            match delimiter_type {
                Some(DelimiterType::SingleQuote) => {
                    for payload in html_payloads.iter() {
                        payloads.push(format!("'>{}'", payload));
                    }
                    for payload in attr_payloads.iter() {
                        payloads.push(format!("' {} a='", payload));
                    }
                }
                Some(DelimiterType::DoubleQuote) => {
                    for payload in html_payloads.iter() {
                        payloads.push(format!("\">{}\"", payload));
                    }
                    for payload in attr_payloads.iter() {
                        payloads.push(format!("\" {} \"", payload));
                    }
                }
                _ => {
                    payloads.extend(html_payloads.into_iter());
                    payloads.extend(attr_payloads.into_iter());
                }
            }
        }
        InjectionContext::Javascript(delimiter_type) => match delimiter_type {
            Some(DelimiterType::SingleQuote) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("'-{}-'", payload));
                    payloads.push(format!("'+{}+'", payload));
                }
            }
            Some(DelimiterType::DoubleQuote) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("\"-{}-\"", payload));
                    payloads.push(format!("\"+{}+\"", payload));
                }
            }
            Some(DelimiterType::Comment) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("*/{}/*", payload));
                    payloads.push(format!("\n{}", payload));
                }
            }
            _ => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    // Base payload
                    payloads.push(payload.to_string());
                    // Augmented wrappers for broader execution contexts
                    payloads.push(format!("</script><script>{}</script>", payload));
                }
            }
        },
        InjectionContext::Html(delimiter_type) => {
            let html_payloads = crate::payload::get_dynamic_xss_html_payloads();
            match delimiter_type {
                Some(DelimiterType::Comment) => {
                    for payload in html_payloads.iter() {
                        payloads.push(format!("-->{}<!--", payload));
                    }
                }
                _ => {
                    payloads.extend(html_payloads.into_iter());
                }
            }
        }
    }

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dynamic_payloads_comment() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains("<svg onload=alert(1) class=dalfox>")
        }));
    }

    #[test]
    fn test_generate_dynamic_payloads_string_double() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
        assert!(
            payloads
                .iter()
                .any(|p| p.starts_with("\"") && p.ends_with("\""))
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains("<img src=x onerror=alert(1) class=dalfox>")
        }));
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute_single_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::SingleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("'")));
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute_double_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p == "alert(1)"));
        assert!(
            payloads
                .iter()
                .any(|p| p == "</script><script>alert(1)</script>")
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_single_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::SingleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("'")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_double_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_comment() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Javascript(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("*/")));
        assert!(payloads.iter().any(|p| p.starts_with("\n")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_single_quote() {
        // With the new representation, comment context is represented via Html(Some(Comment))
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_double_quote() {
        // With the new representation, comment context is represented via Html(Some(Comment))
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_html() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Html(None));
        assert!(!payloads.is_empty());
        assert!(
            payloads
                .iter()
                .any(|p| p.to_lowercase() == "<img src=x onerror=alert(1) class=dalfox>")
        );
    }

    #[test]
    fn test_get_dynamic_payloads_basic() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
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
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        assert!(!payloads.is_empty());
        // Check that original payloads are included
        assert!(
            payloads
                .iter()
                .any(|p| p.to_lowercase() == "<img src=x onerror=alert(1) class=dalfox>")
        );
        // Check encoded versions
        assert!(payloads.iter().any(|p| p.contains("%3C")));
        assert!(payloads.iter().any(|p| p.contains("&#x")));
    }

    #[test]
    fn test_get_dynamic_payloads_only_custom() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
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
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: Some("test_payloads.txt".to_string()),
            only_custom_payload: true,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // This will fail if file doesn't exist, but for test structure it's fine
        let result = get_dynamic_payloads(&context, &args);
        // In real test, we'd create a temp file
        assert!(result.is_err()); // Since file doesn't exist
    }

    #[test]
    fn test_get_dynamic_payloads_no_encoders() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
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
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        assert!(!payloads.is_empty());
        // Should only have original payloads, no encoded ones
        assert!(
            payloads
                .iter()
                .all(|p| !p.contains("%3C") && !p.contains("&#x"))
        );
    }
}

pub fn load_custom_payloads(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().map(|s| s.to_string()).collect())
}

pub fn get_dynamic_payloads(
    context: &InjectionContext,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(load_custom_payloads(path)?);
        }
    } else {
        base_payloads.extend(generate_dynamic_payloads(context));
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(load_custom_payloads(path)?);
        }
    }

    // Include remote payloads if available (initialized via --remote-payloads at runtime)
    if let Some(remotes) = crate::payload::get_remote_payloads() {
        if !remotes.is_empty() {
            base_payloads.extend(remotes.as_ref().clone());
        }
    }

    // Deduplicate base_payloads to prevent sending identical payloads multiple times
    let mut unique_base_payloads = std::collections::HashSet::new();
    base_payloads.retain(|p| unique_base_payloads.insert(p.clone()));

    let mut payloads = vec![];
    for payload in base_payloads {
        if args.encoders.contains(&"none".to_string()) {
            payloads.push(payload.clone()); // No encoding
        } else {
            payloads.push(payload.clone()); // Original
            if args.encoders.contains(&"url".to_string()) {
                payloads.push(url_encode(&payload)); // URL encoded
            }
            if args.encoders.contains(&"html".to_string()) {
                payloads.push(html_entity_encode(&payload)); // HTML entity encoded
            }
            if args.encoders.contains(&"2url".to_string()) {
                payloads.push(double_url_encode(&payload)); // Double URL encoded
            }
            if args.encoders.contains(&"base64".to_string()) {
                payloads.push(base64_encode(&payload)); // Base64 encoded
            }
        }
    }

    Ok(payloads)
}
