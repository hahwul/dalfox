+++
title = "Basic XSS Scanning"
description = "Learn how to perform basic XSS scans with Dalfox"
weight = 1
sort_by = "weight"

[extra]
+++

## Quick Start

```bash
dalfox scan https://example.com
```

Test with parameters:
```bash
dalfox scan "https://example.com/search?q=test"
```

Test specific parameters:
```bash
dalfox scan "https://example.com?id=1&q=test" -p id -p q
```

## Output Formats

**Plain** (default):
```bash
dalfox scan https://example.com
```

**JSON**:
```bash
dalfox scan https://example.com -f json -o results.json
```

**Markdown**:
```bash
dalfox scan https://example.com -f markdown -o report.md
```

**SARIF** (for CI/CD, GitHub Code Scanning):
```bash
dalfox scan https://example.com -f sarif -o results.sarif
```

## Input Types

**File**:
```bash
dalfox scan -i file urls.txt
```

**Pipe**:
```bash
cat urls.txt | dalfox scan -i pipe
subfinder -d example.com | httpx | dalfox scan -i pipe
```

## POST Requests

```bash
dalfox scan https://example.com/api -X POST -d "username=admin&password=test"
```

JSON:
```bash
dalfox scan https://example.com/api -X POST -H "Content-Type: application/json" -d '{"user":"admin"}'
```

## Headers & Cookies

```bash
dalfox scan https://example.com -H "Authorization: Bearer token123"
dalfox scan https://example.com --cookies "sessionid=abc123"
```

## Options

**Timeout & Delay**:
```bash
dalfox scan https://example.com --timeout 30 --delay 1000
```

**Follow Redirects**:
```bash
dalfox scan https://example.com -F
```

**Proxy** (Burp Suite):
```bash
dalfox scan https://example.com --proxy http://localhost:8080
```

**Encoders**:
```bash
dalfox scan https://example.com -e url,html,base64
dalfox scan https://example.com -e none  # No encoding
```

**Remote Payloads**:
```bash
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
```

**Custom Payloads**:
```bash
dalfox scan https://example.com --custom-payload payloads.txt
dalfox scan https://example.com --custom-payload payloads.txt --only-custom-payload
```

## Examples

**Authenticated API**:
```bash
dalfox scan https://api.example.com/users -X POST -H "Authorization: Bearer token" -d '{"name":"test"}'
```

**Multiple URLs**:
```bash
dalfox scan -i file targets.txt -f json -o results.json --workers 50
```

**Burp Suite Integration**:
```bash
dalfox scan https://example.com --proxy http://localhost:8080 --cookies "session=abc123" -F
```

**CI/CD (Quiet Mode)**:
```bash
dalfox scan https://example.com -S -f json -o results.json
```

## Quick Reference

```bash
dalfox scan https://example.com                           # Basic scan
dalfox scan https://example.com -p id -p search          # Specific params
dalfox scan https://example.com -X POST -d "user=admin"  # POST request
dalfox scan https://example.com -H "Authorization: Bearer token"  # Auth
dalfox scan https://example.com --cookies "session=abc123"  # Cookies
dalfox scan https://example.com -f json -o results.json  # JSON output
dalfox scan https://example.com --proxy http://localhost:8080  # Proxy
dalfox scan -i file urls.txt                             # File input
cat urls.txt | dalfox scan -i pipe                       # Pipe input
dalfox scan https://example.com --custom-payload p.txt   # Custom payloads
dalfox scan https://example.com -S -f json -o out.json   # Quiet mode
```

## See Also

- [Scan Command Reference](/sub-commands/scan)
- [Blind XSS Testing](/usage_guides/blind_xss_testing)
- [Stored XSS Testing](/usage_guides/stored_xss_testing)
