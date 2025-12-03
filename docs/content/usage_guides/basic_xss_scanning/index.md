+++
title = "Basic XSS Scanning"
description = "Learn how to perform basic XSS scans with Dalfox"
weight = 1
sort_by = "weight"

[extra]
+++

This guide covers the fundamentals of scanning for XSS vulnerabilities using Dalfox.

## Prerequisites

Make sure you have Dalfox installed. See the [Installation Guide](/get_started/installation) if you haven't installed it yet.

## Your First Scan

The simplest way to scan for XSS is to provide a target URL:

```bash
dalfox scan https://example.com
```

This will:
1. Analyze the URL for parameters
2. Discover additional parameters
3. Test each parameter for XSS vulnerabilities
4. Display results in your terminal

## Scanning URLs with Parameters

### Single Parameter

```bash
dalfox scan "https://example.com/search?q=test"
```

Dalfox will automatically detect the `q` parameter and test it for XSS.

### Multiple Parameters

```bash
dalfox scan "https://example.com/page?id=1&category=news&search=test"
```

All three parameters (`id`, `category`, `search`) will be tested.

{% alert_info() %}
**Tip**: Always quote URLs with special characters to avoid shell interpretation issues.
{% end %}

## Specifying Target Parameters

If you only want to test specific parameters:

```bash
dalfox scan "https://example.com/page?id=1&category=news" -p id
```

This tests only the `id` parameter, ignoring `category`.

**Test multiple specific parameters:**
```bash
dalfox scan "https://example.com/page?id=1&category=news&q=test" -p id -p q
```

## Understanding the Output

### Plain Output Format

By default, Dalfox outputs results in a human-readable format:

```
[POC] Reflected XSS
[Parameter] q
[Payload] <script>alert(1)</script>
[Evidence] ...response excerpt...
[Severity] High
[CWE] CWE-79
```

### JSON Output Format

For programmatic analysis, use JSON format:

```bash
dalfox scan https://example.com -f json -o results.json
```

**Output structure:**
```json
[
  {
    "type": "reflected-xss",
    "inject_type": "inHTML",
    "method": "GET",
    "param": "q",
    "payload": "<script>alert(1)</script>",
    "evidence": "...",
    "cwe": "CWE-79",
    "severity": "High",
    "message_id": "...",
    "message_str": "..."
  }
]
```

## Scanning Different Input Types

### URL Mode (Default)

Directly test a URL:
```bash
dalfox scan https://example.com
```

### File Mode

Test multiple URLs from a file:

**urls.txt:**
```
https://example.com/page1?q=test
https://example.com/page2?id=1
https://example.com/search?keyword=xss
```

**Scan:**
```bash
dalfox scan -i file urls.txt
```

### Pipe Mode

Integrate with other tools:
```bash
cat urls.txt | dalfox scan -i pipe
```

**Example with subfinder:**
```bash
subfinder -d example.com | httpx | dalfox scan -i pipe
```

## Working with POST Requests

### Simple POST Data

```bash
dalfox scan https://example.com/api -X POST -d "username=admin&password=test"
```

### JSON POST Data

```bash
dalfox scan https://example.com/api \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'
```

## Adding Custom Headers

### Authorization Headers

```bash
dalfox scan https://example.com \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Multiple Headers

```bash
dalfox scan https://example.com \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value" \
  -H "Accept: application/json"
```

## Using Cookies

### Simple Cookie

```bash
dalfox scan https://example.com --cookies "sessionid=abc123"
```

### Multiple Cookies

```bash
dalfox scan https://example.com \
  --cookies "sessionid=abc123" \
  --cookies "token=xyz789"
```

### Cookies from Raw HTTP File

If you have a raw HTTP request file with cookies:

```bash
dalfox scan https://example.com --cookie-from-raw request.txt
```

## Controlling Scan Behavior

### Timeout

Set request timeout (default: 10 seconds):
```bash
dalfox scan https://example.com --timeout 30
```

### Delay Between Requests

Add delay to avoid rate limiting:
```bash
dalfox scan https://example.com --delay 1000
```

### Follow Redirects

Follow HTTP redirects:
```bash
dalfox scan https://example.com -F
```

### Using a Proxy

Route requests through a proxy (useful for Burp Suite integration):
```bash
dalfox scan https://example.com --proxy http://localhost:8080
```

## Customizing Payload Encoders

By default, Dalfox uses URL and HTML encoding. You can customize this:

### Standard Encoders

```bash
# Use URL and double-URL encoding
dalfox scan https://example.com -e url,2url

# Use HTML entity encoding
dalfox scan https://example.com -e html

# Use base64 encoding
dalfox scan https://example.com -e base64

# Use multiple encoders
dalfox scan https://example.com -e url,html,base64
```

### No Encoding

Test only original payloads without encoding:
```bash
dalfox scan https://example.com -e none
```

## Remote Payloads

Use professionally-curated payload lists:

```bash
# PortSwigger payloads
dalfox scan https://example.com --remote-payloads portswigger

# PayloadBox payloads
dalfox scan https://example.com --remote-payloads payloadbox

# Both
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
```

## Custom Payloads

### Using a Custom Payload File

**payloads.txt:**
```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**Scan:**
```bash
dalfox scan https://example.com --custom-payload payloads.txt
```

### Only Custom Payloads

Skip built-in payloads and use only your custom ones:
```bash
dalfox scan https://example.com \
  --custom-payload payloads.txt \
  --only-custom-payload
```

## Practical Examples

### Example 1: Basic Search Page

```bash
dalfox scan "https://example.com/search?q=test&lang=en" \
  -p q \
  -f json \
  -o search-results.json
```

### Example 2: Authenticated API Endpoint

```bash
dalfox scan https://api.example.com/users \
  -X POST \
  -H "Authorization: Bearer token123" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@example.com"}' \
  --timeout 30
```

### Example 3: Testing Multiple URLs

```bash
# Create URL list
cat > targets.txt << EOF
https://example.com/page1?id=1
https://example.com/page2?search=test
https://example.com/page3?category=news
EOF

# Scan all URLs
dalfox scan -i file targets.txt \
  -f json \
  -o batch-results.json \
  --workers 50
```

### Example 4: Through Burp Suite Proxy

```bash
dalfox scan https://example.com \
  --proxy http://localhost:8080 \
  -H "Authorization: Bearer token123" \
  --cookies "session=abc123" \
  -F
```

### Example 5: Quiet Mode for CI/CD

```bash
dalfox scan https://example.com \
  -S \
  -f json \
  -o results.json \
  --limit 10
```

The `-S` (silence) flag suppresses logs, showing only POC output.

## Tips and Best Practices

{% collapse(title="1. Use Specific Parameters") %}
When testing large applications, use `-p` to focus on specific parameters:
```bash
dalfox scan https://example.com -p id -p search
```
This is faster and reduces noise.
{% end %}

{% collapse(title="2. Respect Rate Limits") %}
Add delay between requests to avoid being blocked:
```bash
dalfox scan https://example.com --delay 500 --workers 10
```
{% end %}

{% collapse(title="3. Save Results") %}
Always save results to a file for later analysis:
```bash
dalfox scan https://example.com -f json -o results.json
```
{% end %}

{% collapse(title="4. Use Proxy for Manual Verification") %}
Route through Burp Suite to manually verify findings:
```bash
dalfox scan https://example.com --proxy http://localhost:8080
```
{% end %}

{% collapse(title="5. Test Different Methods") %}
Don't forget to test POST, PUT, and other methods:
```bash
dalfox scan https://example.com -X POST -d "param=value"
```
{% end %}

## Common Issues and Solutions

{% collapse(title="No vulnerabilities found") %}
**Possible reasons:**
1. Target is not vulnerable
2. Parameters are properly sanitized
3. WAF/IDS is blocking requests
4. Need custom payloads for bypass

**Try:**
- Use `--deep-scan` to test all payloads
- Add custom payloads with `--custom-payload`
- Increase timeout with `--timeout 30`
- Use remote payloads with `--remote-payloads portswigger,payloadbox`
{% end %}

{% collapse(title="Too many requests / Rate limiting") %}
**Solution:**
```bash
dalfox scan https://example.com \
  --delay 1000 \
  --workers 10 \
  --max-concurrent-targets 5
```
{% end %}

{% collapse(title="SSL/TLS errors") %}
**For testing environments with self-signed certificates:**

Note: Dalfox respects system SSL settings. Use a proxy if needed:
```bash
dalfox scan https://example.com --proxy http://localhost:8080
```
Then configure your proxy to handle SSL.
{% end %}

## Next Steps

Now that you understand basic scanning, explore:

- [Scan Command Reference](/sub-commands/scan) - Complete command documentation
- [Scanning via REST API](/usage_guides/scanning_via_rest_api) - Remote scanning
- [Payload Command](/sub-commands/payload) - Custom payload development

## Quick Reference

```bash
# Basic scan
dalfox scan https://example.com

# Specific parameters
dalfox scan https://example.com -p id -p search

# POST request
dalfox scan https://example.com -X POST -d "user=admin"

# With authentication
dalfox scan https://example.com -H "Authorization: Bearer token"

# With cookies
dalfox scan https://example.com --cookies "session=abc123"

# JSON output
dalfox scan https://example.com -f json -o results.json

# Through proxy
dalfox scan https://example.com --proxy http://localhost:8080

# File input
dalfox scan -i file urls.txt

# Pipe input
cat urls.txt | dalfox scan -i pipe

# Custom payloads
dalfox scan https://example.com --custom-payload payloads.txt

# Remote payloads
dalfox scan https://example.com --remote-payloads portswigger

# Silence mode
dalfox scan https://example.com -S -f json -o results.json
```
