# New Test Cases Summary

This document summarizes the 116 new XSS test cases added to expand the mock_cases test suite.

## Overview

**Total new cases**: 116
**Previous total**: 309 cases
**New total**: 425 cases
**Increase**: +37.5%

## New Files Created

### Query Parameters (76 new cases)
1. **encoding_bypass.toml** (15 cases)
   - HTML entity encoding variations (named, hex, decimal)
   - URL encoding
   - Base64 encoding
   - Double encoding
   - Unicode/hex/octal escapes
   - Mixed encoding techniques
   - JSON/CSS Unicode escapes
   - Data URI with Base64

2. **character_filtering.toml** (20 cases)
   - Blocked angle brackets
   - Blocked quotes (single, double, both)
   - Blocked parentheses
   - Blocked script tag keyword
   - Blocked event handlers
   - Blocked special characters (/, =, space, ;, \)
   - Keyword blocking (alert, javascript)
   - Whitelist scenarios
   - Tag stripping

3. **complex_multilayer.toml** (21 cases)
   - Nested HTML/JS contexts
   - Triple nested quoting
   - JSON in script in HTML
   - SVG foreignObject
   - Template literals
   - Regex patterns
   - mXSS (mutation XSS) vectors
   - CDATA sections
   - CSS expressions
   - Meta refresh injection
   - Base/form/iframe/object/embed injection
   - HTML imports
   - XML external entities
   - MathML injection
   - SVG xlink:href

4. **edge_cases.toml** (20 cases)
   - Null byte injection
   - BOM markers
   - RTLO (Right-to-Left Override)
   - Zero-width characters
   - Newline normalization
   - Carriage return bypass
   - Unicode line/paragraph separators
   - Homoglyph attacks
   - Combining characters
   - Surrogate pairs
   - Emoji characters
   - Fullwidth/halfwidth characters
   - Ideographic space
   - Vertical tab/form feed
   - Various Unicode space characters

### Headers (10 new cases)
**encoding_filtering.toml** (10 cases)
- HTML entity encoding
- URL encoding
- Base64 encoding
- CRLF injection
- JSON context reflection
- JavaScript string context
- Meta tag reflection
- HTML comment context
- Style attribute context
- Data attribute reflection

### Cookies (10 new cases)
**encoding_filtering.toml** (10 cases)
- HTML entity encoding
- URL encoding
- Base64 encoding
- JSON context reflection
- JavaScript string context
- HTML attribute context
- SVG context
- Meta refresh
- Style tag
- Nested quotes

### Path Parameters (10 new cases)
**encoding_filtering.toml** (10 cases)
- HTML entity encoding
- URL encoding
- Base64 encoding
- JSON context reflection
- JavaScript string context
- SVG context
- href attribute context
- src attribute context
- Meta tag
- Double reflection

### Body Parameters (10 new cases)
**encoding_filtering.toml** (10 cases)
- HTML entity encoding
- URL encoding
- Base64 encoding
- JSON context reflection
- JavaScript string context
- Textarea context
- Input value
- Title attribute
- Placeholder attribute
- Nested JSON

## Test Coverage Areas

### Encoding Techniques Tested
- HTML named entities (&lt;, &gt;, etc.)
- HTML numeric hex (&#x3c;, &#X3E;)
- HTML numeric decimal (&#60;)
- URL percent encoding
- Base64 encoding
- Double encoding
- Unicode escapes (\u003c)
- Hex escapes (\x3c)
- Octal escapes (\74)

### Filtering Bypass Scenarios
- Character blocking (quotes, brackets, slashes, etc.)
- Keyword blocking (script, alert, javascript, on*)
- Whitelist/blacklist scenarios
- Tag stripping
- Special character filtering

### Complex Attack Vectors
- Multi-layer context switching
- Mutation XSS (mXSS)
- Nested contexts (HTML → JS → JSON)
- Template injection
- SVG/XML/MathML contexts
- Data URIs
- Protocol handlers
- Meta/base/form injections

### Edge Cases and Unicode
- Control characters (null, CRLF, tabs)
- Unicode normalization
- Right-to-left override
- Zero-width characters
- Homoglyphs
- Surrogate pairs
- Various Unicode spaces
- Fullwidth/halfwidth characters

## Testing Philosophy

Each test case follows these principles:

1. **Specificity**: Tests one specific scenario or bypass technique
2. **Real-world**: Based on actual XSS patterns seen in the wild
3. **Documentation**: Clear descriptions of what is being tested
4. **Incrementality**: IDs continue from existing cases without gaps
5. **Organization**: Grouped by technique/context for maintainability

## ID Ranges (After Addition)

- **Query**: 1-266 (previous highest: 190, added 76 cases)
- **Header**: 1-50 (previous highest: 40, added 10 cases)
- **Cookie**: 1-40 (previous highest: 30, added 10 cases)
- **Path**: 1-33 (previous highest: 23, added 10 cases)
- **Body**: 1-36 (previous highest: 26, added 10 cases)

## How to Use These Tests

### Run All Mock Server Tests
```bash
cargo test xss_mock_server_v2 -- --ignored --nocapture
```

### Run Specific Type
```bash
cargo test test_query_reflection_v2 -- --ignored --nocapture
cargo test test_header_reflection_v2 -- --ignored --nocapture
```

### Verify Case Loading
```bash
cargo test mock_case_loader -- --nocapture
```

## Future Expansion Ideas

Areas that could be further expanded:
1. WAF bypass techniques
2. Browser-specific quirks
3. Content-Security-Policy bypasses
4. More mXSS patterns
5. Framework-specific bypasses (React, Angular, Vue)
6. WebAssembly contexts
7. Service Worker contexts
8. Module script contexts
9. More protocol handlers (data:, blob:, etc.)
10. Shadow DOM contexts

## References

These test cases were inspired by:
- OWASP XSS Filter Evasion Cheat Sheet
- PortSwigger XSS research
- Real-world vulnerability reports
- Browser quirks and edge cases
- Unicode specification edge cases
- HTML5/CSS3/SVG specifications

## Validation

All new test cases have been validated to:
- Parse correctly as TOML
- Load into the mock case loader
- Have unique IDs within their injection type
- Follow the established schema
- Include proper metadata (name, description, expected_detection)
