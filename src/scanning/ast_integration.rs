use scraper::{Html, Selector};

/// Extract JavaScript code from HTML response
/// Looks for <script> tags and inline event handlers
pub fn extract_javascript_from_html(html: &str) -> Vec<String> {
    let mut js_code = Vec::new();
    
    let document = Html::parse_document(html);
    
    // Extract from <script> tags
    if let Ok(selector) = Selector::parse("script") {
        for element in document.select(&selector) {
            let text = element.text().collect::<Vec<_>>().join("");
            if !text.trim().is_empty() {
                js_code.push(text);
            }
        }
    }
    
    js_code
}

/// Analyze JavaScript code for DOM XSS vulnerabilities using AST analysis
/// Returns a list of vulnerability descriptions
pub fn analyze_javascript_for_dom_xss(
    js_code: &str,
    url: &str,
) -> Vec<String> {
    let analyzer = crate::scanning::ast_dom_analysis::AstDomAnalyzer::new();
    
    match analyzer.analyze(js_code) {
        Ok(vulnerabilities) => {
            let mut findings = Vec::new();
            for vuln in vulnerabilities {
                findings.push(format!(
                    "DOM XSS at {}:{}:{} - {} (Source: {}, Sink: {})",
                    url, vuln.line, vuln.column, vuln.description, vuln.source, vuln.sink
                ));
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
        assert!(findings[0].contains("DOM XSS"));
        assert!(findings[0].contains("innerHTML"));
    }
}
