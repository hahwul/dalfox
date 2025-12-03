# Contributing XSS Test Cases

This guide explains how to add new XSS test cases to Dalfox's structured mock server testing framework.

## Quick Start

1. **Choose the injection type** you want to test:
   - Query parameters: `tests/functional/mock_cases/query/`
   - HTTP headers: `tests/functional/mock_cases/header/`
   - Cookies: `tests/functional/mock_cases/cookie/`
   - Path parameters: `tests/functional/mock_cases/path/`
   - POST body: `tests/functional/mock_cases/body/`

2. **Pick an existing TOML file** or create a new one in that directory

3. **Add your test case** following the format below

4. **Run the tests** to verify

## Test Case Format

```toml
[[case]]
id = 91                             # Must be unique within this injection type
name = "my_test_case"               # Short, descriptive identifier
description = "What vulnerability this tests"
handler_type = "query"              # Type: query, header, cookie, path, body
reflection = "<div>{input}</div>"   # How the input is reflected
expected_detection = true           # Whether Dalfox should detect it

# Optional fields:
header_name = "X-Custom"            # For header injection (default: "X-Test")
cookie_name = "session"             # For cookie injection (default: "test")
param_name = "data"                 # For body injection (default: "query")
```

## Reflection Patterns

### Template Strings
Use `{input}` as a placeholder for where user input is reflected:

```toml
reflection = "<script>alert('{input}');</script>"
reflection = "<div class='{input}'>content</div>"
reflection = "var x = {input};"
```

### Encoding Keywords
Use special keywords for common encoding patterns:

```toml
reflection = "encoded_html_named"      # &lt;&gt;&amp;&quot;&apos;
reflection = "encoded_html_hex_lower"  # &#x3c;&#x3e; (lowercase)
reflection = "encoded_html_hex_upper"  # &#X3C;&#X3E; (uppercase)
reflection = "percent_to_entity"       # % becomes &#37;
reflection = "encoded_base64"          # Base64 encoding
reflection = "encoded_url"             # URL percent encoding
```

## Example: Adding a New Query Parameter Test

Let's add a test for textarea value injection:

1. Open `tests/functional/mock_cases/query/attribute_contexts.toml`

2. Find the highest `id` number (currently 27)

3. Add your case:

```toml
[[case]]
id = 28
name = "textarea_value"
description = "XSS via textarea content"
handler_type = "query"
reflection = "<textarea>{input}</textarea>"
expected_detection = true
```

4. Save the file

## Example: Adding a New Header Test

Let's add a test for a custom API header:

1. Open or create `tests/functional/mock_cases/header/api_headers.toml`

2. Add your case:

```toml
[[case]]
id = 23
name = "x_api_key_reflection"
description = "API key reflected in debug output"
handler_type = "header"
header_name = "X-API-Key"
reflection = "<div>Debug: API Key = {input}</div>"
expected_detection = true
```

## Test Categories and Files

### Query Parameters (`query/`)

Organize by context type:

- **html_contexts.toml**: Basic HTML elements
- **js_contexts.toml**: JavaScript contexts
- **attribute_contexts.toml**: HTML attributes
- **event_handlers.toml**: Event handler attributes
- **css_contexts.toml**: CSS injection
- **svg_xml_contexts.toml**: SVG and XML
- **special_contexts.toml**: Comments, JSON, URLs
- **bypass_techniques.toml**: Filter bypass methods
- **template_contexts.toml**: Template engines
- **dom_contexts.toml**: DOM manipulation
- **protocol_contexts.toml**: URL protocols

### Headers (`header/`)

- **header_contexts.toml**: Common headers
- **extended_headers.toml**: Additional headers

### Cookies (`cookie/`)

- **cookie_contexts.toml**: Basic cookie reflections
- **extended_cookies.toml**: Additional cookie types

### Path (`path/`)

- **path_contexts.toml**: Path parameter reflections

### Body (`body/`)

- **body_contexts.toml**: POST parameter reflections

## Running Tests

### Run all mock server tests:
```bash
cargo test xss_mock_server_v2 -- --ignored --nocapture
```

### Run specific injection type:
```bash
cargo test test_query_reflection_v2 -- --ignored --nocapture
cargo test test_header_reflection_v2 -- --ignored --nocapture
cargo test test_cookie_reflection_v2 -- --ignored --nocapture
```

### Verify case loading:
```bash
cargo test mock_case_loader -- --nocapture
```

## Naming Conventions

### File Names
- Use lowercase with underscores: `event_handlers.toml`
- Group related tests: `bypass_techniques.toml`
- Descriptive but concise: `svg_xml_contexts.toml`

### Case Names
- Use lowercase with underscores: `img_onerror`
- Be specific: `js_string_double_quote` not just `js_string`
- Reflect the context: `template_angular`, `dom_innerhtml`

### Descriptions
- Start with a verb or "Test": "Test XSS via..."
- Be specific about the vulnerability
- Include context: "AngularJS template injection"

## ID Management

Each injection type has its own ID namespace:

- **Query**: Currently 1-190 (can go higher)
- **Header**: Currently 1-40
- **Cookie**: Currently 1-30
- **Path**: Currently 1-23
- **Body**: Currently 1-26

When adding a new case:
1. Find the highest ID in that directory
2. Use the next sequential number
3. IDs must be unique within that injection type

## Complex Scenarios

### Multiple Injection Points

If testing multiple injection points, create separate cases:

```toml
[[case]]
id = 91
name = "double_reflection_1"
description = "First reflection point"
handler_type = "query"
reflection = "<div>{input}</div><span>static</span>"
expected_detection = true

[[case]]
id = 92
name = "double_reflection_2"
description = "Second reflection point"
handler_type = "query"
reflection = "<div>static</div><span>{input}</span>"
expected_detection = true
```

### Context-Specific Escaping

Document special escaping in the description:

```toml
[[case]]
id = 93
name = "backslash_escape"
description = "Test XSS with backslash escaping in JS string"
handler_type = "query"
reflection = "<script>var x='\\{input}\\';</script>"
expected_detection = true
```

## Testing Best Practices

1. **Start simple**: Test basic injection before complex bypasses
2. **One thing at a time**: Each case should test one specific scenario
3. **Document well**: Use clear descriptions
4. **Test both positive and negative**: Some cases may set `expected_detection = false`
5. **Verify manually**: Run dalfox manually against the case to verify

## Debugging Failed Tests

If a test fails:

1. Check the server logs for the case
2. Verify the reflection pattern is correct
3. Test the URL manually:
   ```bash
   # For query parameter case 91:
   curl "http://localhost:PORT/query/91?query=test"
   ```
4. Check if Dalfox generates appropriate payloads for that context

## Current Test Coverage

As of the latest commit:

- **Query parameters**: 190 cases
- **Headers**: 40 cases  
- **Cookies**: 30 cases
- **Path parameters**: 23 cases
- **Body parameters**: 26 cases

**Total**: 309 test cases

## Adding New Categories

To add a completely new category:

1. Create a new TOML file in the appropriate directory
2. Follow the naming conventions
3. Add at least 5-10 related test cases
4. Update this README with the new category

## Questions?

- Check `docs/MOCK_TEST_CASES.md` for architecture details
- Look at existing test cases for examples
- The mock server code is in `tests/functional/xss_mock_server_v2.rs`
- The loader code is in `tests/functional/mock_case_loader.rs`

Happy testing! 🎯
