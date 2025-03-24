---
title: Basic Another Vulnerability (BAV)
redirect_from: /docs/bav/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Basic Another Vulnerability (BAV)

## What is BAV?

BAV (Basic Another Vulnerability) is a powerful feature in Dalfox that automatically tests for additional vulnerabilities beyond XSS during scanning. While Dalfox is primarily designed for finding XSS vulnerabilities, the BAV module extends its capabilities to detect other common web security issues with minimal additional overhead.

By default, BAV is enabled in all scanning modes, providing a more comprehensive security assessment without requiring additional tools.

## Vulnerabilities Detected by BAV

The BAV module can detect several types of common web vulnerabilities:

| Vulnerability Type | Description | Detection Method |
|-------------------|-------------|------------------|
| **SQL Injection** | Detects potential SQL injection vulnerabilities by looking for database error messages in responses | Pattern matching for MySQL, PostgreSQL, MSSQL, SQLite error strings |
| **Server-Side Template Injection (SSTI)** | Identifies template injection vulnerabilities in web frameworks | Testing special template syntax and analyzing responses |
| **Open Redirect** | Discovers endpoints vulnerable to URL redirection attacks | Testing redirection parameters with malicious URLs |
| **CRLF Injection** | Finds header injection vulnerabilities | Inserting CRLF sequences and analyzing response headers |

## How BAV Works

The BAV module operates through two main mechanisms:

1. **Active Testing**: Dalfox injects special test payloads designed to trigger specific vulnerability patterns
2. **Pattern Matching**: Responses are analyzed for characteristic error messages, behavior changes, or other indicators

This integration into the main scanning process is efficient, as it:
- Reuses established connections and parameter discovery
- Minimizes additional requests
- Provides unified reporting for all discovered vulnerabilities

## Controlling BAV Behavior

### Disabling BAV

If you prefer to focus solely on XSS testing or want to reduce scanning time, you can disable BAV using the `--skip-bav` flag:

```bash
dalfox url https://example.com --skip-bav
```

### Explicitly Enabling BAV

Although BAV is enabled by default, you can explicitly enable it using the `--use-bav` flag:

```bash
dalfox url https://example.com --use-bav
```

This is useful when combined with other configuration options or when you want to be explicit about which features are active.

## Example Output

Here's an example of what you might see in the output when BAV detects vulnerabilities:

```
[*] 🦊 Starting scan of http://vulnerable-website.com/page.php?id=1
[*] Parameter analysis in progress... 🔍
[G] Found SQL Injection via built-in grepping (MySQL error)
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://vulnerable-website.com/page.php?id=1'

[G] Found CRLF Injection vulnerability
[POC][G][CRLF/GET] http://vulnerable-website.com/page.php?id=%0D%0ASet-Cookie:+crlf=injection

[G] Found Open Redirect vulnerability
[POC][G][OPREDIRECT/GET] http://vulnerable-website.com/page.php?url=https://evil.com

[I] Found reflected parameter: id
[V] Triggered XSS Payload (found dialog in headless browser)
[POC][V][GET] http://vulnerable-website.com/page.php?id=<script>alert(1)</script>
```

Notice how Dalfox integrates BAV findings with XSS results, providing a unified view of discovered vulnerabilities.

## BAV Detection Patterns

Dalfox uses sophisticated pattern matching to identify vulnerability indicators. Some examples include:

### SQL Injection Patterns
- `SQL syntax; check the manual that corresponds to your MySQL`
- `Warning.*?mysqli?`
- `Unclosed quotation mark after the character string`
- `PostgreSQL.*ERROR`

### SSTI Patterns
- `undefined:(0x)?[a-f0-9]+`
- `jinja2\.exceptions`
- `Twig_Error_Syntax`
- `Error: Problem parsing template`

### Open Redirect Indicators
- Unexpected 3xx responses
- URL redirection to test domains

## Benefits of Using BAV

1. **Efficiency**: Get broader coverage without running multiple tools
2. **Integrated Results**: All findings appear in the same report
3. **Low Overhead**: Minimal impact on scanning speed
4. **Comprehensive Security**: Find non-XSS issues that might be missed

## Limitations

While BAV provides valuable additional security testing, it's important to understand its limitations:

- It focuses on basic pattern detection, not deep exploitation
- False positives may occur with certain error messages
- It's not a replacement for dedicated SQL injection or SSTI scanners
- Advanced vulnerabilities requiring complex exploitation are not covered

For critical applications, consider supplementing Dalfox with specialized tools for each vulnerability type.

## Adding Custom BAV Patterns

Advanced users can contribute to the BAV module by adding new detection patterns. To learn how, see the [CONTRIBUTING.md](https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md) file in the Dalfox repository.
