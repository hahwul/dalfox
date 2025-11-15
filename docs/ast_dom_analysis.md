# AST-based DOM XSS Detection

This module provides JavaScript Abstract Syntax Tree (AST) analysis to detect potential DOM-based XSS vulnerabilities through taint tracking.

## Overview

The AST-based analyzer parses JavaScript source code and tracks the flow of untrusted data from sources to sinks, identifying potential DOM XSS vulnerabilities.

### Features

- **Source Detection**: Identifies untrusted input sources like:
  - `location.search`, `location.hash`, `location.href`
  - `document.URL`, `document.cookie`, `document.referrer`
  - `window.name`

- **Sink Detection**: Identifies dangerous DOM operations:
  - `innerHTML`, `outerHTML`, `insertAdjacentHTML`
  - `document.write`, `document.writeln`
  - `eval`, `setTimeout`, `setInterval`, `Function`
  - `location.href`, `location.assign`, `location.replace`

- **Taint Tracking**: Propagates taint through:
  - Variable assignments
  - Template literals
  - Binary and logical expressions
  - Conditional expressions

- **Sanitizer Recognition**: Recognizes common sanitization functions:
  - `DOMPurify.sanitize`
  - `encodeURIComponent`, `encodeURI`

## Usage

### As a Library Module

```rust
use dalfox::scanning::ast_dom_analysis::AstDomAnalyzer;

let js_code = r#"
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;
"#;

let analyzer = AstDomAnalyzer::new();
match analyzer.analyze(js_code) {
    Ok(vulnerabilities) => {
        for vuln in vulnerabilities {
            println!("Vulnerability at line {}: {}", vuln.line, vuln.description);
            println!("  Source: {}", vuln.source);
            println!("  Sink: {}", vuln.sink);
        }
    }
    Err(err) => eprintln!("Parse error: {}", err),
}
```

### Running the Example

```bash
cargo run --example ast_dom_xss_demo
```

## Architecture

### Components

1. **AstDomAnalyzer**: Main public interface for analyzing JavaScript code
2. **DomXssVisitor**: Internal AST visitor that walks the syntax tree
3. **DomXssVulnerability**: Result structure containing vulnerability details

### Taint Tracking Algorithm

1. Parse JavaScript code into an AST using `oxc_parser`
2. Walk through the AST statements
3. For each variable declaration:
   - Check if initializer is a known source → mark variable as tainted
   - Check if initializer uses tainted data → mark variable as tainted
4. For each assignment:
   - Check if target is a sink and right side is tainted → report vulnerability
5. For each function call:
   - Check if function is a sink and any argument is tainted → report vulnerability
   - Check if function is a sanitizer → don't propagate taint

## Dependencies

- `oxc_parser` (0.97.0): JavaScript/TypeScript parser
- `oxc_ast` (0.97.0): AST definitions
- `oxc_allocator` (0.97.0): Memory allocator for AST
- `oxc_span` (0.97.0): Source location tracking

## Testing

Run the tests:
```bash
cargo test ast_dom_analysis
```

All tests should pass:
- Basic DOM XSS detection
- Eval with location.hash
- Document.write with cookie
- Direct source to sink
- Safe code (no false positives)
- Multiple vulnerabilities
- Parse error handling
- Template literals with tainted data

## Limitations

- **Scope**: Currently tracks global scope only (no function-level scoping)
- **Flow sensitivity**: Simple forward data flow (no backwards analysis)
- **Aliases**: Limited alias tracking (one level)
- **Sanitizers**: Simple pattern matching (no semantic analysis)
- **Context**: Doesn't analyze execution context or reachability

## Future Enhancements

- Multi-scope support with symbol tables
- Inter-procedural analysis for function calls
- More sophisticated sanitizer detection
- Control flow analysis
- Support for async/await patterns
- Integration with browser DOM verification

## Example Vulnerabilities Detected

```javascript
// Example 1: Variable assignment
let param = location.search;
document.getElementById('x').innerHTML = param;  // ✗ Vulnerable

// Example 2: Direct usage
eval(location.hash);  // ✗ Vulnerable

// Example 3: Template literal
let search = location.search;
let html = `<div>${search}</div>`;
element.innerHTML = html;  // ✗ Vulnerable

// Example 4: Safe (no vulnerability)
let safe = "Hello";
element.innerHTML = safe;  // ✓ Safe
```

## References

- [DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [oxc_parser Documentation](https://docs.rs/oxc_parser/)
