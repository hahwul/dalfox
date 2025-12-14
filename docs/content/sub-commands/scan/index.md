+++
title = "Scan"
description = "Scan targets for XSS vulnerabilities"
weight = 1
sort_by = "weight"

[extra]
+++

Primary command for XSS detection. Supports multiple input modes, parameter discovery, and comprehensive testing.

```bash
dalfox scan [OPTIONS] [TARGET]...
```

**Quick Examples**:
```bash
dalfox scan https://example.com
dalfox scan https://example.com?id=1 -p id
dalfox scan -i file urls.txt
dalfox scan https://example.com -f json -o results.json
```

## Input Type (`-i, --input-type`)

{% badge_info() %}auto{% end %} {% badge_primary() %}url{% end %} {% badge_primary() %}file{% end %} {% badge_primary() %}pipe{% end %} {% badge_primary() %}raw-http{% end %}

```bash
dalfox scan https://example.com              # auto (default)
dalfox scan -i file urls.txt                 # file
cat urls.txt | dalfox scan -i pipe           # pipe
dalfox scan -i raw-http request.txt          # raw-http
```

## Output Options

**Format** (`-f, --format`): {% badge_primary() %}plain{% end %} {% badge_primary() %}json{% end %} {% badge_primary() %}jsonl{% end %} {% badge_primary() %}markdown{% end %} {% badge_primary() %}sarif{% end %}

```bash
dalfox scan https://example.com -f json -o results.json
dalfox scan https://example.com -f markdown -o report.md
dalfox scan https://example.com -f sarif -o results.sarif
```

**Include Request/Response**:
```bash
dalfox scan https://example.com --include-request --include-response
```

**Silence Mode** (`-S`): Suppress logs, show only POCs  
**POC Type** (`--poc-type`): plain | curl | httpie | http-request  
**Limit** (`--limit`): Cap number of results

## Target Options

**Parameters** (`-p`): Test specific params, with optional type filters (query, body, json, cookie, header)
```bash
dalfox scan https://example.com?id=1&search=test -p id -p search
dalfox scan https://example.com -p id:query -p token:header
```

**Method** (`-X`): POST, PUT, etc.  
**Data** (`-d`): Request body  
**Headers** (`-H`): Custom headers  
**Cookies** (`--cookies`): Set cookies  
**Cookie from Raw** (`--cookie-from-raw`): Load from raw HTTP file  
**User Agent** (`--user-agent`): Custom UA

## Discovery & Mining

**Skip Discovery**: `--skip-discovery`, `--skip-reflection-header`, `--skip-reflection-cookie`, `--skip-reflection-path`

**Dictionary Mining** (`-W`): Use wordlist
```bash
dalfox scan https://example.com -W wordlist.txt
```

**Remote Wordlists** (`--remote-wordlists`): burp, assetnote
```bash
dalfox scan https://example.com --remote-wordlists burp,assetnote
```

**Skip Mining**: `--skip-mining`, `--skip-mining-dict`, `--skip-mining-dom`

## Network & Engine

**Timeout** (`--timeout`): Request timeout (seconds)  
**Delay** (`--delay`): Delay between requests (ms)  
**Proxy** (`--proxy`): Route through proxy  
**Follow Redirects** (`-F`): Follow HTTP redirects

**Workers** (`--workers`): Concurrent workers (default: 50)  
**Max Concurrent Targets** (`--max-concurrent-targets`): Global limit (default: 50)  
**Max Targets Per Host** (`--max-targets-per-host`): Per-host cap (default: 100)

## XSS Options

**Encoders** (`-e`): {% badge_primary() %}none{% end %} {% badge_primary() %}url{% end %} {% badge_primary() %}2url{% end %} {% badge_primary() %}html{% end %} {% badge_primary() %}base64{% end %} (default: url,html)
```bash
dalfox scan https://example.com -e url,2url,html
dalfox scan https://example.com -e none  # No encoding
```

**Remote Payloads** (`--remote-payloads`): portswigger, payloadbox
```bash
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
```

**Custom Payloads**:
```bash
dalfox scan https://example.com --custom-payload payloads.txt
dalfox scan https://example.com --custom-payload payloads.txt --only-custom-payload
```

**Blind XSS** (`-b`):
```bash
dalfox scan https://example.com -b https://callback.com
dalfox scan https://example.com -b https://callback.com --custom-blind-xss-payload blind.txt
```

**Stored XSS** (`--sxss`):
```bash
dalfox scan https://example.com/submit --sxss --sxss-url https://example.com/view
```

**Other**: `--skip-xss-scanning`, `--deep-scan`, `--skip-ast-analysis`

## Examples

**Basic**:
```bash
dalfox scan https://example.com -p id -p search -f json -o results.json
```

**Comprehensive**:
```bash
dalfox scan https://example.com -W params.txt --remote-wordlists burp,assetnote --remote-payloads portswigger,payloadbox -e url,html,base64 -f json --include-request --include-response -o results.json
```

**Blind XSS**:
```bash
dalfox scan https://example.com -b https://callback.com --custom-blind-xss-payload blind.txt -W params.txt
```

**Stored XSS**:
```bash
dalfox scan https://example.com/submit -X POST -d "comment=test" --sxss --sxss-url https://example.com/view
```

**Authenticated + Proxy**:
```bash
dalfox scan https://example.com -H "Authorization: Bearer token" --cookies "sessionid=abc" --proxy http://localhost:8080 -F
```

**CI/CD (SARIF)**:
```bash
dalfox scan https://example.com -f sarif -o results.sarif
```

## See Also

- [Basic XSS Scanning Guide](/usage_guides/basic_xss_scanning)
- [Payload Command](/sub-commands/payload)
- [Server Mode](/sub-commands/server)
