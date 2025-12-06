+++
title = "Scan"
description = "Scan targets for XSS vulnerabilities"
weight = 1
sort_by = "weight"

[extra]
+++

The `scan` command is the primary tool for detecting XSS vulnerabilities in web applications. It supports multiple input modes, parameter discovery, and comprehensive XSS testing.

## Basic Usage

```bash
dalfox scan [OPTIONS] [TARGET]...
```

### Quick Examples

**Scan a single URL:**
```bash
dalfox scan https://example.com
```

**Scan with specific parameters:**
```bash
dalfox scan https://example.com?id=1 -p id
```

**Scan from a file:**
```bash
dalfox scan -i file urls.txt
```

**Scan with JSON output:**
```bash
dalfox scan https://example.com -f json -o results.json
```

## Input Options

### Input Type (`-i, --input-type`)

Specify how Dalfox should interpret the input.

{% badge_info() %}auto{% end %} (default)
{% badge_primary() %}url{% end %}
{% badge_primary() %}file{% end %}
{% badge_primary() %}pipe{% end %}
{% badge_primary() %}raw-http{% end %}

**Auto Mode** (default):
```bash
# Automatically detects whether input is URL or file
dalfox scan https://example.com
dalfox scan urls.txt
```

**URL Mode**:
```bash
dalfox scan -i url https://example.com
```

**File Mode**:
```bash
dalfox scan -i file urls.txt
```

**Pipe Mode**:
```bash
cat urls.txt | dalfox scan -i pipe
```

**Raw HTTP Mode**:
```bash
dalfox scan -i raw-http request.txt
```

## Output Options

### Format (`-f, --format`)

Control the output format.

{% badge_primary() %}plain{% end %} (default)
{% badge_primary() %}json{% end %}
{% badge_primary() %}jsonl{% end %}
{% badge_primary() %}markdown{% end %}
{% badge_primary() %}sarif{% end %}

**Plain Format**:
```bash
dalfox scan https://example.com -f plain
```

**JSON Format**:
```bash
dalfox scan https://example.com -f json -o results.json
```

**JSONL Format** (JSON Lines - one JSON object per line):
```bash
dalfox scan https://example.com -f jsonl -o results.jsonl
```

**Markdown Format**:
```bash
dalfox scan https://example.com -f markdown -o report.md
```

**SARIF Format** (Static Analysis Results Interchange Format):
```bash
dalfox scan https://example.com -f sarif -o results.sarif
```

### Output to File (`-o, --output`)

```bash
dalfox scan https://example.com -o output.txt
```

### Include Request/Response

Include full HTTP request and response data in the output:

```bash
# Include request only
dalfox scan https://example.com --include-request

# Include response only
dalfox scan https://example.com --include-response

# Include both
dalfox scan https://example.com --include-request --include-response
```

### Silence Mode (`-S, --silence`)

Suppress all logs except POC output:

```bash
dalfox scan https://example.com -S
```

### POC Type (`--poc-type`)

Choose the format for proof-of-concept output.

{% badge_primary() %}plain{% end %} (default)
{% badge_primary() %}curl{% end %}
{% badge_primary() %}httpie{% end %}
{% badge_primary() %}http-request{% end %}

```bash
# Output as curl command
dalfox scan https://example.com --poc-type curl

# Output as httpie command
dalfox scan https://example.com --poc-type httpie

# Output as raw HTTP request
dalfox scan https://example.com --poc-type http-request
```

### Limit Results (`--limit`)

Limit the number of results to display:

```bash
dalfox scan https://example.com --limit 10
```

## Target Configuration

### Parameters (`-p, --param`)

Specify which parameters to analyze. You can filter by name or type.

```bash
# Test specific parameters
dalfox scan https://example.com?id=1&search=test -p id -p search

# Filter by type
dalfox scan https://example.com -p id:query
dalfox scan https://example.com -p token:header
```

**Parameter Types:**
- `query`: URL query parameters
- `body`: POST body parameters
- `json`: JSON body fields
- `cookie`: Cookie values
- `header`: HTTP headers

### HTTP Method (`-X, --method`)

Override the HTTP method:

```bash
dalfox scan https://example.com -X POST
dalfox scan https://example.com -X PUT
```

### Request Data (`-d, --data`)

Send HTTP request body data:

```bash
dalfox scan https://example.com -X POST -d "username=admin&password=test"
```

### Headers (`-H, --headers`)

Add custom HTTP headers:

```bash
dalfox scan https://example.com -H "Authorization: Bearer token123"
dalfox scan https://example.com -H "X-Custom: value" -H "X-Another: value2"
```

### Cookies (`--cookies`)

Set cookies for the request:

```bash
dalfox scan https://example.com --cookies "sessionid=abc123"
dalfox scan https://example.com --cookies "token=xyz" --cookies "user=admin"
```

### Cookie from Raw (`--cookie-from-raw`)

Load cookies from a raw HTTP request file:

```bash
dalfox scan https://example.com --cookie-from-raw request.txt
```

### User Agent (`--user-agent`)

Set a custom User-Agent header:

```bash
dalfox scan https://example.com --user-agent "Mozilla/5.0 Custom Bot"
```

## Parameter Discovery

Control how Dalfox discovers parameters for testing.

### Skip Discovery (`--skip-discovery`)

Skip all parameter discovery checks:

```bash
dalfox scan https://example.com --skip-discovery
```

### Skip Specific Discovery Types

```bash
# Skip header reflection checks
dalfox scan https://example.com --skip-reflection-header

# Skip cookie reflection checks
dalfox scan https://example.com --skip-reflection-cookie

# Skip path reflection checks
dalfox scan https://example.com --skip-reflection-path
```

## Parameter Mining

Discover additional parameters using various techniques.

### Dictionary Mining (`-W, --mining-dict-word`)

Use a wordlist for parameter name discovery:

```bash
dalfox scan https://example.com -W wordlist.txt
```

### Remote Wordlists (`--remote-wordlists`)

Fetch parameter wordlists from remote providers:

```bash
# Use Burp Suite wordlist
dalfox scan https://example.com --remote-wordlists burp

# Use AssertNote wordlist
dalfox scan https://example.com --remote-wordlists assetnote

# Use multiple providers
dalfox scan https://example.com --remote-wordlists burp,assetnote
```

### Skip Mining Options

```bash
# Skip all mining
dalfox scan https://example.com --skip-mining

# Skip dictionary mining only
dalfox scan https://example.com --skip-mining-dict

# Skip DOM-based mining only
dalfox scan https://example.com --skip-mining-dom
```

## Network Options

### Timeout (`--timeout`)

Set request timeout in seconds:

```bash
dalfox scan https://example.com --timeout 30
```

### Delay (`--delay`)

Add delay between requests in milliseconds:

```bash
dalfox scan https://example.com --delay 1000
```

### Proxy (`--proxy`)

Route requests through a proxy:

```bash
dalfox scan https://example.com --proxy http://localhost:8080
```

### Follow Redirects (`-F, --follow-redirects`)

Follow HTTP redirects:

```bash
dalfox scan https://example.com -F
```

## Engine Configuration

### Workers (`--workers`)

Number of concurrent workers for parameter analysis:

```bash
dalfox scan https://example.com --workers 100
```

### Max Concurrent Targets (`--max-concurrent-targets`)

Global limit for concurrent target scanning:

```bash
dalfox scan -i file urls.txt --max-concurrent-targets 20
```

### Max Targets Per Host (`--max-targets-per-host`)

Limit targets per hostname:

```bash
dalfox scan -i file urls.txt --max-targets-per-host 50
```

## XSS Scanning Options

### Encoders (`-e, --encoders`)

Specify payload encoding methods:

{% badge_primary() %}none{% end %}
{% badge_primary() %}url{% end %}
{% badge_primary() %}2url{% end %}
{% badge_primary() %}html{% end %}
{% badge_primary() %}base64{% end %}

```bash
# Default: url and html encoding
dalfox scan https://example.com

# Custom encoders
dalfox scan https://example.com -e url,2url,html

# No encoding (only original payloads)
dalfox scan https://example.com -e none
```

{% alert_info() %}
If the encoder list contains "none", only original payloads will be used without any encoding variants.
{% end %}

### Remote Payloads (`--remote-payloads`)

Fetch XSS payloads from remote providers:

```bash
# PortSwigger payloads
dalfox scan https://example.com --remote-payloads portswigger

# PayloadBox payloads
dalfox scan https://example.com --remote-payloads payloadbox

# Multiple providers
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
```

### Custom Payloads

**Custom Payload File** (`--custom-payload`):
```bash
dalfox scan https://example.com --custom-payload payloads.txt
```

**Only Custom Payloads** (`--only-custom-payload`):
```bash
dalfox scan https://example.com --custom-payload payloads.txt --only-custom-payload
```

### Blind XSS (`-b, --blind`)

Enable blind XSS testing with a callback URL:

```bash
dalfox scan https://example.com -b https://your-callback.com/xss
```

**Custom Blind Payload Templates** (`--custom-blind-xss-payload`):
```bash
dalfox scan https://example.com -b https://callback.com --custom-blind-xss-payload blind-templates.txt
```

### Stored XSS (SXSS)

Test for stored XSS vulnerabilities:

```bash
# Enable SXSS mode with verification URL
dalfox scan https://example.com/submit --sxss --sxss-url https://example.com/view

# Specify method for verification request
dalfox scan https://example.com/submit --sxss --sxss-url https://example.com/view --sxss-method GET
```

### Skip XSS Scanning (`--skip-xss-scanning`)

Perform discovery and mining but skip XSS payload testing:

```bash
dalfox scan https://example.com --skip-xss-scanning
```

### Deep Scan (`--deep-scan`)

Disable Content-Type preflight filtering and test all payloads:

```bash
dalfox scan https://example.com --deep-scan
```

{% alert_warning() %}
Deep scan mode will test all payloads even on non-HTML content types, which may increase false positives.
{% end %}

## Complete Examples

### Basic Security Test
```bash
dalfox scan https://example.com \
  -p id -p search \
  -f json \
  -o results.json
```

### Comprehensive Scan with Mining
```bash
dalfox scan https://example.com \
  -W params.txt \
  --remote-wordlists burp,assetnote \
  --remote-payloads portswigger,payloadbox \
  -e url,html,base64 \
  --timeout 30 \
  --workers 100 \
  -f json \
  --include-request \
  --include-response \
  -o comprehensive-results.json
```

### Blind XSS Testing
```bash
dalfox scan https://example.com \
  -b https://your-callback.com/xss \
  --custom-blind-xss-payload blind.txt \
  -W params.txt
```

### Stored XSS Testing
```bash
dalfox scan https://example.com/comment/submit \
  -X POST \
  -d "comment=test&author=user" \
  --sxss \
  --sxss-url https://example.com/comment/view?id=1 \
  --sxss-method GET
```

### Authenticated Scan through Proxy
```bash
dalfox scan https://example.com \
  -H "Authorization: Bearer token123" \
  --cookies "sessionid=abc123" \
  --proxy http://localhost:8080 \
  --delay 500 \
  -F
```

### Generate Markdown Report
```bash
dalfox scan https://example.com \
  -p id -p search \
  -W params.txt \
  --remote-payloads portswigger \
  -f markdown \
  -o security-report.md
```

### SARIF Output for CI/CD
```bash
dalfox scan https://example.com \
  -f sarif \
  -o results.sarif \
  --timeout 30 \
  --workers 100
```

This SARIF format is compatible with:
- GitHub Code Scanning
- Azure DevOps
- GitLab SAST
- Various security analysis tools

## See Also

- [Basic XSS Scanning Guide](/usage_guides/basic_xss_scanning)
- [Payload Command](/sub-commands/payload)
- [Server Mode](/sub-commands/server)
