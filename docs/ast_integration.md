# AST-based DOM XSS Integration

## Overview

The AST-based DOM XSS detection has been integrated into the Dalfox scan command. When enabled, it automatically analyzes JavaScript code found in HTTP responses to detect potential DOM-based XSS vulnerabilities.

## Usage

### Enable AST Analysis

```bash
dalfox scan <target> --ast-analysis
```

### Example

```bash
# Scan a single URL with AST analysis
dalfox scan https://example.com --ast-analysis

# Scan from file with AST analysis
dalfox scan -i file urls.txt --ast-analysis

# Combine with other options
dalfox scan https://example.com --ast-analysis --deep-scan
```

### Configuration File

You can also enable AST analysis in your config file (`~/.config/dalfox/config.toml`):

```toml
[scan]
ast_analysis = true
```

## How It Works

1. **HTTP Response Analysis**: When enabled, Dalfox analyzes HTTP responses from target URLs
2. **JavaScript Extraction**: Extracts JavaScript code from `<script>` tags in HTML responses
3. **AST Parsing**: Parses the JavaScript using oxc_parser into an Abstract Syntax Tree
4. **Taint Tracking**: Tracks data flow from sources (e.g., location.search) to sinks (e.g., innerHTML)
5. **Vulnerability Reporting**: Reports potential DOM XSS vulnerabilities with line numbers and descriptions

## Output

When AST analysis detects vulnerabilities, they are reported with type "A" (AST-detected):

```
[POC][A][GET][DOM-XSS]
DOM XSS at https://example.com/page.html:5:1 - Assignment to sink property (Source: location.search, Sink: innerHTML)
```

## Integration Points

The AST analysis is integrated at the scanning level:

- **After Reflection Check**: AST analysis runs after each reflection check when responses are available
- **JavaScript Extraction**: Automatically extracts and analyzes all `<script>` blocks
- **Result Reporting**: Findings are added to the standard result set with type "A" for AST-detected

## Performance

- **Minimal Overhead**: AST parsing is fast (sub-millisecond for typical scripts)
- **Opt-in**: Only runs when `--ast-analysis` flag is provided
- **No Extra Requests**: Analyzes existing response data without additional HTTP requests

## Limitations

- Only analyzes inline JavaScript in `<script>` tags
- Does not analyze external JavaScript files
- Simple taint tracking (global scope only)
- May not detect all complex data flows

## See Also

- [AST DOM Analysis Documentation](./ast_dom_analysis.md)
- [Implementation Summary](./IMPLEMENTATION_SUMMARY.md)
