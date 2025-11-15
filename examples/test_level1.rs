use dalfox::scanning::ast_integration;

fn main() {
    // Test case from the issue
    let html = r#"<script>document.write(location.hash.slice(1))</script>"#;
    
    println!("Testing HTML: {}", html);
    println!();
    
    let js_blocks = ast_integration::extract_javascript_from_html(html);
    println!("Extracted {} JavaScript block(s)", js_blocks.len());
    
    for (i, js) in js_blocks.iter().enumerate() {
        println!("\nBlock {}: {}", i + 1, js.trim());
        let findings = ast_integration::analyze_javascript_for_dom_xss(
            js,
            "http://localhost:3000/dom/level1/"
        );
        
        if findings.is_empty() {
            println!("  ❌ No vulnerabilities detected");
        } else {
            println!("  ✓ Found {} vulnerability/vulnerabilities:", findings.len());
            for finding in findings {
                println!("    - {}", finding);
            }
        }
    }
}
