use crate::cmd::scan::ScanArgs;

use crate::parameter_analysis::{DelimiterType, InjectionContext};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Context-specific payload lists

static CUSTOM_PAYLOAD_CACHE: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();

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
                    payloads.extend(html_payloads);
                    payloads.extend(attr_payloads);
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
            let mxss_payloads = crate::payload::get_mxss_payloads();
            let clobbering_payloads = crate::payload::get_dom_clobbering_payloads();
            match delimiter_type {
                Some(DelimiterType::Comment) => {
                    for payload in html_payloads
                        .iter()
                        .chain(mxss_payloads.iter())
                        .chain(clobbering_payloads.iter())
                    {
                        payloads.push(format!("-->{}<!--", payload));
                    }
                }
                _ => {
                    payloads.extend(html_payloads);
                    payloads.extend(mxss_payloads);
                    payloads.extend(clobbering_payloads);
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
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains(&format!("<svg onload=alert(1) class={}>", cls))
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
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains(&format!("<img src=x onerror=alert(1) class={}>", cls))
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
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls)
        }));
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
            skip_reflection_path: false,
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
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        assert!(!payloads.is_empty());
        // Check that original payloads are included
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls)
        }));
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
            skip_reflection_path: false,
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
            skip_ast_analysis: false,
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
            skip_reflection_path: false,
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
            skip_ast_analysis: false,
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

/// Generate adaptive payloads using per-parameter analysis data (valid/invalid specials).
/// When a parameter has analysis data, this applies targeted encoding to bypass filters.
pub fn generate_adaptive_payloads(
    context: &InjectionContext,
    invalid_specials: &[char],
    valid_specials: &[char],
) -> Vec<String> {
    let base_payloads = generate_dynamic_payloads(context);

    // Use adaptive encoders from the encoding module
    let adaptive_encoders =
        crate::encoding::generate_adaptive_encodings(invalid_specials, valid_specials);

    // Apply adaptive encoders
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in &base_payloads {
        // Original
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
        // Adaptive variants based on what's blocked
        let adaptive_variants = crate::encoding::apply_adaptive_encoding(p, invalid_specials);
        for v in adaptive_variants {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
        // Standard encoder variants
        for enc in &adaptive_encoders {
            let v = match enc.as_str() {
                "url" => crate::encoding::url_encode(p),
                "html" => crate::encoding::html_entity_encode(p),
                "2url" => crate::encoding::double_url_encode(p),
                "unicode" => crate::encoding::unicode_fullwidth_encode(p),
                "zwsp" => crate::encoding::zero_width_encode(p),
                _ => continue,
            };
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

pub fn load_custom_payloads(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cache = CUSTOM_PAYLOAD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(cached) = guard.get(path)
    {
        return Ok(cached.clone());
    }

    let content = std::fs::read_to_string(path)?;
    let payloads: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    if let Ok(mut guard) = cache.lock() {
        guard.insert(path.to_string(), payloads.clone());
    }

    Ok(payloads)
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
    if let Some(remotes) = crate::payload::get_remote_payloads()
        && !remotes.is_empty()
    {
        base_payloads.extend(remotes.as_ref().clone());
    }

    // Expand with shared encoder policy helper; handles "none" and deduplication
    let payloads = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);

    Ok(payloads)
}
