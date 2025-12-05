# DOM XSS Test Cases

This directory contains comprehensive test cases for DOM-based XSS vulnerabilities. These test cases are used to validate the AST-based DOM XSS detection capabilities of Dalfox.

## Structure

Test cases are organized by the type of taint source:

- **location_sources.toml** - Tests using `location.*` properties as taint sources
- **storage_sources.toml** - Tests using `localStorage` and `sessionStorage` APIs
- **postmessage_sources.toml** - Tests using `postMessage` event handlers
- **complex_flows.toml** - Tests with multi-step taint propagation
- **sanitized_flows.toml** - Tests with proper sanitization (should NOT detect)

## Test Case Format

Each test case is defined in TOML format with the following fields:

```toml
[[case]]
id = 1001                                    # Unique identifier (1000-1099 for location, etc.)
name = "location_search_to_innerhtml"        # Short descriptive name
description = "Location search parameter to innerHTML sink"
handler_type = "dom_xss"                     # Type of handler
reflection = """                              # HTML/JavaScript code to analyze
<html>
<body>
<div id="output"></div>
<script>
var search = location.search.substring(1);
document.getElementById('output').innerHTML = search;
</script>
</body>
</html>
"""
expected_detection = true                    # Whether this should be detected as vulnerable
```

## ID Ranges

- **1000-1099**: Location-based sources (location.search, location.hash, etc.)
- **1100-1199**: Storage-based sources (localStorage, sessionStorage)
- **1200-1299**: PostMessage sources (event.data)
- **1300-1399**: Complex taint flows (multi-step propagation)
- **1400-1499**: Sanitized flows (safe patterns that should NOT be flagged)

## Test Results

Current detection rates (as of last test):

| Category | Detection Rate | Notes |
|----------|---------------|-------|
| Location Sources | 100.0% (8/8) | ✓ Full coverage |
| Storage Sources | 75.0% (3/4) | Good coverage |
| PostMessage Sources | 75.0% (3/4) | Good coverage |
| Complex Flows | 42.9% (3/7) | Needs improvement |
| Sanitized Flows | 0.0% FP (4/4) | ✓ No false positives |
| **Overall** | **73.9% (17/23)** | Strong detection |

## Adding New Test Cases

To add a new test case:

1. Choose the appropriate category file
2. Assign a unique ID in the correct range
3. Write realistic JavaScript code that demonstrates the vulnerability
4. Set `expected_detection` appropriately
5. Run the tests to validate

Example command to run tests:
```bash
cargo test test_dom_xss_location_sources -- --nocapture
cargo test test_dom_xss_comprehensive_coverage -- --nocapture
```

## Test Coverage Areas

### Sources (Taint Origins)
- [x] location.search, location.hash, location.href, location.pathname
- [x] document.URL, document.referrer, document.cookie
- [x] window.name
- [x] localStorage.getItem(), sessionStorage.getItem()
- [x] event.data (from postMessage)

### Sinks (Vulnerable Operations)
- [x] innerHTML, outerHTML
- [x] document.write(), document.writeln()
- [x] eval(), setTimeout(), setInterval()
- [x] Function constructor
- [x] location.href, location.assign(), location.replace()
- [x] script.src, insertAdjacentHTML()

### Safe Patterns (Should NOT Detect)
- [x] textContent (doesn't parse HTML)
- [x] createTextNode() (creates text nodes, not HTML)
- [x] DOMPurify.sanitize() (sanitization library)
- [x] Custom HTML encoding functions

## Known Limitations

The following patterns are not yet fully supported:

1. **Function parameter tracking** - Taint flow through function parameters needs interprocedural analysis
2. **Array element tracking** - Complex array operations may not be fully tracked
3. **Conditional flows** - Taint tracking through if/else branches needs improvement
4. **Loop iterations** - Taint propagation in loops is partially supported

## References

- [DOM-based XSS - OWASP](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [DOM XSS Sources & Sinks - PortSwigger](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [Oxc Parser Documentation](https://github.com/oxc-project/oxc)
