use scraper::{Html, Selector};

/// Extract JavaScript code from HTML response
/// Looks for <script> tags and inline event handlers
pub fn extract_javascript_from_html(html: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut js_code = Vec::new();
    let mut seen = HashSet::new();

    let document = Html::parse_document(html);

    // Extract from <script> tags
    if let Ok(selector) = Selector::parse("script") {
        for element in document.select(&selector) {
            let text = element.text().collect::<Vec<_>>().join("");
            if !text.trim().is_empty() && seen.insert(text.trim().to_string()) {
                js_code.push(text);
            }
        }
    }

    // Extract inline event handler attributes (on*) and javascript: URLs
    if let Ok(all) = Selector::parse("*") {
        for node in document.select(&all) {
            let attrs = node.value().attrs();
            for (name, value) in attrs {
                let lname = name.to_ascii_lowercase();
                let v = value;
                if v.trim().is_empty() {
                    continue;
                }
                if lname.starts_with("on") {
                    // Inline handler body as JS snippet
                    let snippet = v.trim().to_string();
                    if seen.insert(snippet.clone()) {
                        js_code.push(snippet);
                    }
                } else if lname == "href" {
                    let vv = v.trim();
                    if vv.len() >= 11 && vv[..11].eq_ignore_ascii_case("javascript:") {
                        let js = vv[11..].trim();
                        if !js.is_empty() {
                            let snippet = js.to_string();
                            if seen.insert(snippet.clone()) {
                                js_code.push(snippet);
                            }
                        }
                    }
                }
            }
        }
    }

    js_code
}

/// Generate an executable POC payload based on the source and sink
/// Returns (payload, description)
pub fn generate_dom_xss_poc(source: &str, sink: &str) -> (String, String) {
    // Generate payload based on the source type
    let payload = if source.contains("location.hash") {
        // Hash-based XSS - use fragment identifier
        "#<img src=x onerror=alert(1)>".to_string()
    } else if source.contains("location.search") {
        // Query-based XSS
        "xss=<img src=x onerror=alert(1)>".to_string()
    } else if source.contains("location.href") || source.contains("document.URL") {
        // URL-based - could be anywhere
        "#<img src=x onerror=alert(1)>".to_string()
    } else {
        // Generic payload for other sources
        "<img src=x onerror=alert(1)>".to_string()
    };

    let description = format!("DOM-based XSS via {} to {}", source, sink);

    (payload, description)
}

/// Analyze JavaScript code for DOM XSS vulnerabilities using AST analysis
/// Returns a list of (vulnerability, payload, description) tuples
pub fn analyze_javascript_for_dom_xss(
    js_code: &str,
    _url: &str,
) -> Vec<(
    crate::scanning::ast_dom_analysis::DomXssVulnerability,
    String,
    String,
)> {
    let analyzer = crate::scanning::ast_dom_analysis::AstDomAnalyzer::new();

    match analyzer.analyze(js_code) {
        Ok(vulnerabilities) => {
            let mut findings = Vec::new();
            for vuln in vulnerabilities {
                let (payload, description) = generate_dom_xss_poc(&vuln.source, &vuln.sink);
                findings.push((vuln, payload, description));
            }
            findings
        }
        Err(_) => {
            // Parse error - JavaScript might be too complex or malformed
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_javascript_from_html() {
        let html = r#"
<html>
<head>
    <script>
        var x = 1;
    </script>
</head>
<body>
    <script>
        let y = location.search;
        document.getElementById('foo').innerHTML = y;
    </script>
</body>
</html>
"#;
        let js_code = extract_javascript_from_html(html);
        assert_eq!(js_code.len(), 2);
        assert!(js_code[1].contains("location.search"));
    }

    #[test]
    fn test_analyze_javascript_for_dom_xss() {
        let js = r#"
let param = location.search;
document.getElementById('x').innerHTML = param;
"#;
        let findings = analyze_javascript_for_dom_xss(js, "https://example.com");
        assert!(!findings.is_empty());
        let (vuln, payload, description) = &findings[0];
        assert!(description.contains("DOM-based XSS"));
        assert!(description.contains("innerHTML"));
        assert!(payload.contains("alert"));
    }
}
