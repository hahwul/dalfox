# AST-based DOM XSS Integration

## Overview

The AST-based DOM XSS detection is integrated into the Dalfox scan command and **enabled by default**. It automatically analyzes JavaScript code found in HTTP responses to detect potential DOM-based XSS vulnerabilities.

## Usage

### AST Analysis (Enabled by Default)

AST analysis runs automatically during scans. No additional flags are required.

```bash
# AST analysis runs by default
dalfox scan <target>
```

### Disable AST Analysis

If you want to skip AST analysis for faster scanning:

```bash
dalfox scan <target> --skip-ast-analysis
```

### Example

```bash
# Scan with AST analysis (default)
dalfox scan https://example.com

# Scan from file with AST analysis (default)
dalfox scan -i file urls.txt

# Scan without AST analysis
dalfox scan https://example.com --skip-ast-analysis

# Combine with other options
dalfox scan https://example.com --deep-scan
```

### Configuration File

You can disable AST analysis in your config file (`~/.config/dalfox/config.toml`):

```toml
[scan]
skip_ast_analysis = true  # Disable AST analysis
```

## How It Works

1. **HTTP Response Analysis**: Dalfox analyzes HTTP responses from target URLs automatically
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

The AST analysis is integrated at the scanning level and **runs by default**:

- **After Reflection Check**: AST analysis runs after each reflection check when responses are available
- **JavaScript Extraction**: Automatically extracts and analyzes all `<script>` blocks
- **Result Reporting**: Findings are added to the standard result set with type "A" for AST-detected
- **Default Behavior**: Enabled by default for all scans (use `--skip-ast-analysis` to disable)

## Performance

- **Minimal Overhead**: AST parsing is fast (sub-millisecond for typical scripts)
- **Enabled by Default**: Provides enhanced security scanning without manual activation
- **No Extra Requests**: Analyzes existing response data without additional HTTP requests
- **Skip Option**: Can be disabled with `--skip-ast-analysis` flag for faster scanning

## Limitations

- Only analyzes inline JavaScript in `<script>` tags
- Does not analyze external JavaScript files
- Simple taint tracking (global scope only)
- May not detect all complex data flows

## See Also

- [AST DOM Analysis Documentation](./ast_dom_analysis.md)
- [Implementation Summary](./IMPLEMENTATION_SUMMARY.md)
