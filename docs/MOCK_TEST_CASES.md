# XSS Mock Server Test Case Management

This document describes the structured approach to managing XSS test cases for Dalfox.

## Overview

The XSS mock server testing framework has been refactored to support a more maintainable, structured approach to defining test cases. Instead of hardcoding test cases in Rust, test cases are now defined in TOML files organized by injection type.

## Directory Structure

```
tests/functional/
├── mock_cases/           # Root directory for all mock test cases
│   ├── query/           # Query parameter injection cases
│   │   ├── html_contexts.toml
│   │   ├── js_contexts.toml
│   │   ├── attribute_contexts.toml
│   │   ├── event_handlers.toml
│   │   ├── css_contexts.toml
│   │   ├── svg_xml_contexts.toml
│   │   └── special_contexts.toml
│   ├── header/          # HTTP header injection cases
│   │   └── header_contexts.toml
│   ├── cookie/          # Cookie injection cases
│   │   └── cookie_contexts.toml
│   ├── path/            # Path parameter injection cases
│   │   └── path_contexts.toml
│   └── body/            # POST body parameter injection cases
│       └── body_contexts.toml
├── mock_case_loader.rs  # Case loader implementation
├── xss_mock_server.rs   # Original mock server (legacy)
└── xss_mock_server_v2.rs # New structured mock server
```

## Test Case Definition Format

Test cases are defined in TOML files with the following structure:

```toml
[[case]]
id = 1                              # Unique ID within this injection type
name = "test_case_name"             # Short identifier for the test
description = "What this tests"     # Human-readable description
handler_type = "query"              # Type: query, header, cookie, path, or body
reflection = "<div>{input}</div>"   # How the input is reflected
expected_detection = true           # Whether Dalfox should detect XSS

# Optional fields depending on handler type:
header_name = "X-Custom-Header"     # For header injection (default: "X-Test")
cookie_name = "session"             # For cookie injection (default: "test")
param_name = "data"                 # For body injection (default: "query")
```

### Reflection Patterns

The `reflection` field supports two types of values:

1. **Template strings**: Use `{input}` as a placeholder
   ```toml
   reflection = "<div>{input}</div>"
   ```

2. **Encoding keywords**: Special keywords for common encoding patterns
   - `encoded_html_named` - HTML entity encoding (named entities)
   - `encoded_html_hex_lower` - HTML hex encoding (lowercase)
   - `encoded_html_hex_upper` - HTML hex encoding (uppercase)
   - `percent_to_entity` - Percent sign to HTML entity
   - `encoded_base64` - Base64 encoding
   - `encoded_url` - URL encoding

## Test Case Categories

### Query Parameter Injection (50 cases)

Located in `tests/functional/mock_cases/query/`:

- **html_contexts.toml**: Basic HTML injection contexts
  - Raw reflection, HTML encoding variants
  - HTML elements (div, meta, form, input)
  
- **js_contexts.toml**: JavaScript injection contexts
  - Script blocks, string contexts (single/double quotes)
  - Alert calls, variable assignments
  
- **attribute_contexts.toml**: HTML attribute injection
  - Various attributes (src, href, alt, title, etc.)
  - Different tag types (img, a, iframe, object, embed, etc.)
  
- **event_handlers.toml**: Event handler attributes
  - onerror, onload, onclick, onfocus, etc.
  - Various elements (img, svg, body, button, etc.)
  
- **css_contexts.toml**: CSS injection contexts
  - Style tags, inline styles
  - CSS expressions, URL functions
  
- **svg_xml_contexts.toml**: SVG and XML contexts
  - SVG script blocks, animate, use elements
  - MathML, foreignObject
  
- **special_contexts.toml**: Special contexts
  - HTML comments
  - JSON values
  - JavaScript URLs, data URLs
  - CSS imports

### Header Injection (12 cases)

Located in `tests/functional/mock_cases/header/`:

- Various encoding strategies
- Different reflection contexts
- Custom headers (User-Agent, Referer)

### Cookie Injection (12 cases)

Located in `tests/functional/mock_cases/cookie/`:

- Cookie value reflections
- Different encoding and contexts
- Session and tracking cookies

### Path Parameter Injection (12 cases)

Located in `tests/functional/mock_cases/path/`:

- Path segment reflections
- Encoding variants
- Breadcrumb links, canonical URLs

### Body Parameter Injection (12 cases)

Located in `tests/functional/mock_cases/body/`:

- POST parameter reflections
- JSON responses
- Confirmation messages

## Adding New Test Cases

### Step 1: Choose the appropriate directory

Select the directory based on the injection type:
- Query parameters → `query/`
- HTTP headers → `header/`
- Cookies → `cookie/`
- Path parameters → `path/`
- POST body → `body/`

### Step 2: Choose or create a TOML file

Either add to an existing TOML file or create a new one based on the context category.

### Step 3: Define the test case

```toml
[[case]]
id = 51  # Use the next available ID
name = "descriptive_name"
description = "Clear description of what vulnerability this tests"
handler_type = "query"
reflection = "<your_reflection_pattern>"
expected_detection = true
```

### Step 4: Test your changes

The test cases are automatically loaded when tests run:

```bash
# Run all v2 tests
cargo test test_query_reflection_v2 -- --nocapture --ignored

# Run specific injection type
cargo test test_header_reflection_v2 -- --nocapture --ignored
```

## Implementation Details

### Mock Case Loader

The `mock_case_loader.rs` module provides:

- `MockCase` struct: Represents a single test case
- `load_mock_cases_from_dir()`: Loads all cases from a directory
- `load_all_mock_cases()`: Loads all cases organized by type
- `get_mock_cases_base_dir()`: Returns the base directory path

### Mock Server v2

The `xss_mock_server_v2.rs` implements:

- Dynamic case loading on server startup
- Handler functions that look up cases by ID
- Automatic reflection pattern application
- Test runner for all loaded cases

## Benefits of This Approach

1. **Easy to maintain**: Test cases are defined in simple TOML files
2. **Organized**: Cases are grouped by type and context
3. **Scalable**: Adding new cases is straightforward
4. **Documented**: Each case has a name and description
5. **Flexible**: Supports various encoding and reflection patterns
6. **Comprehensive**: Currently 98 test cases covering many XSS vectors

## Migration Path

The original `xss_mock_server.rs` is retained for compatibility. The new `xss_mock_server_v2.rs` uses the structured approach. Tests can gradually migrate to the v2 system.

## Future Enhancements

Potential improvements:

1. Add expected payload patterns for each case
2. Support custom encoders per case
3. Add negative test cases (expected to NOT detect)
4. Support multi-step reflection scenarios
5. Add DOM-based XSS test cases with client-side JavaScript
6. Support for testing different WAF bypass techniques
