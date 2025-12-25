+++
title = "Quick Start"
description = "Get started with Dalfox in minutes"
weight = 3
sort_by = "weight"

[extra]
+++

## Your First Scan

Once installed, perform a basic scan:

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

## Common Use Cases

### Scan Multiple URLs

**From File**:
```bash
dalfox scan -i file urls.txt
```

**From Pipe**:
```bash
cat urls.txt | dalfox scan -i pipe
subfinder -d example.com | httpx | dalfox scan -i pipe
```

### POST Requests

```bash
dalfox scan https://example.com/api -X POST -d "username=admin&password=test"
```

JSON:
```bash
dalfox scan https://example.com/api -X POST -H "Content-Type: application/json" -d '{"user":"admin"}'
```

### With Authentication

```bash
dalfox scan https://example.com -H "Authorization: Bearer token123"
dalfox scan https://example.com --cookies "sessionid=abc123"
```

### Save Results

**JSON Output**:
```bash
dalfox scan https://example.com -f json -o results.json
```

**Markdown Report**:
```bash
dalfox scan https://example.com -f markdown -o report.md
```

**SARIF** (for CI/CD, GitHub Code Scanning):
```bash
dalfox scan https://example.com -f sarif -o results.sarif
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

## Next Steps

- Learn more about [Commands](/usage/commands) and their options
- Explore detailed [Examples](/usage/examples) for advanced scenarios
- Configure Dalfox with [Configuration](/usage/configuration) files
- Set up [Pipelining](/advanced/pipelining) with other security tools
