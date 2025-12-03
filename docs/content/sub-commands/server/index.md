+++
title = "Server"
description = "Run Dalfox as a REST API server"
weight = 2
sort_by = "weight"

[extra]
+++

# Server Command

The `server` command runs Dalfox as a REST API server, allowing remote orchestration and integration with other tools, CI/CD pipelines, or web interfaces.

## Basic Usage

```bash
dalfox server [OPTIONS]
```

### Quick Start

**Start server on default port (6664):**
```bash
dalfox server
```

**Start with custom host and port:**
```bash
dalfox server --host 0.0.0.0 --port 8080
```

**Start with API key authentication:**
```bash
dalfox server --api-key mysecretkey
```

## Server Options

### Host (`-H, --host`)

Specify the host address to bind the server to.

```bash
# Bind to localhost (default)
dalfox server --host 127.0.0.1

# Bind to all interfaces (accessible from network)
dalfox server --host 0.0.0.0
```

{% alert_warning() %}
Be careful when binding to `0.0.0.0` as it exposes the server to your network. Always use API key authentication in production.
{% end %}

### Port (`-p, --port`)

Set the port number for the server.

```bash
dalfox server --port 8080
```

**Default**: 6664

### API Key (`--api-key`)

Require authentication via API key in the `X-API-KEY` header.

```bash
dalfox server --api-key your-secret-key
```

You can also set the API key via environment variable:
```bash
export DALFOX_API_KEY=your-secret-key
dalfox server
```

### Log File (`--log-file`)

Write logs to a file in addition to stdout:

```bash
dalfox server --log-file /var/log/dalfox.log
```

## CORS Configuration

Configure Cross-Origin Resource Sharing (CORS) settings.

### Allowed Origins (`--allowed-origins`)

Specify which origins can access the API:

```bash
# Allow all origins (not recommended for production)
dalfox server --allowed-origins "*"

# Allow specific origin
dalfox server --allowed-origins "http://localhost:3000"

# Allow multiple origins
dalfox server --allowed-origins "http://localhost:3000,https://app.example.com"

# Use regex pattern
dalfox server --allowed-origins "regex:^https?://localhost:\\d+$"
```

**Supported formats:**
- `*` - Wildcard (match all origins)
- Exact URLs - `http://localhost:3000`
- Regex patterns - `regex:<pattern>`

### Allow Methods (`--cors-allow-methods`)

Specify allowed HTTP methods for CORS:

```bash
dalfox server --cors-allow-methods "GET,POST,OPTIONS"
```

**Default**: `GET,POST,OPTIONS,PUT,PATCH,DELETE`

### Allow Headers (`--cors-allow-headers`)

Specify allowed headers for CORS:

```bash
dalfox server --cors-allow-headers "Content-Type,X-API-KEY,Authorization,X-Custom"
```

**Default**: `Content-Type,X-API-KEY,Authorization`

## JSONP Support

Enable JSONP (JSON with Padding) for legacy browser support.

### Enable JSONP (`--jsonp`)

```bash
dalfox server --jsonp
```

### Callback Parameter (`--callback-param-name`)

Customize the callback parameter name:

```bash
dalfox server --jsonp --callback-param-name cb
```

**Default**: `callback`

## API Endpoints

### POST /scan

Submit a scan request.

**Request Body:**
```json
{
  "url": "https://example.com",
  "options": {
    "worker": 100,
    "delay": 500,
    "blind": "https://callback.com",
    "header": ["Authorization: Bearer token"],
    "method": "POST",
    "data": "param=value",
    "user_agent": "Custom Bot",
    "encoders": ["url", "html"],
    "remote_payloads": ["portswigger"],
    "remote_wordlists": ["burp"],
    "include_request": true,
    "include_response": true
  }
}
```

**Response:**
```json
{
  "code": 200,
  "msg": "scan_abc123def456"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://example.com",
    "options": {
      "worker": 50
    }
  }'
```

### GET /scan

Submit a scan via query parameters (useful for JSONP).

**Query Parameters:**
- `url` - Target URL (required)
- `worker` - Number of workers
- `delay` - Delay between requests
- `blind` - Blind XSS callback URL
- ... (most scan options can be passed as query params)

**Example:**
```bash
curl "http://localhost:6664/scan?url=https://example.com&worker=50" \
  -H "X-API-KEY: your-secret-key"
```

**JSONP Example:**
```bash
curl "http://localhost:6664/scan?url=https://example.com&callback=handleScan"
```

### GET /result/:id

Retrieve scan results by scan ID.

**Response:**
```json
{
  "code": 200,
  "msg": "success",
  "data": {
    "status": "done",
    "results": [
      {
        "type": "reflected-xss",
        "inject_type": "inHTML",
        "method": "GET",
        "param": "id",
        "payload": "<script>alert(1)</script>",
        "evidence": "...",
        "cwe": "CWE-79",
        "severity": "High"
      }
    ]
  }
}
```

**Possible status values:**
- `queued` - Scan is queued
- `running` - Scan is in progress
- `done` - Scan completed
- `error` - Scan failed

**Example:**
```bash
curl http://localhost:6664/result/scan_abc123def456 \
  -H "X-API-KEY: your-secret-key"
```

### GET /scan/:id

Alias for `/result/:id`.

```bash
curl http://localhost:6664/scan/scan_abc123def456 \
  -H "X-API-KEY: your-secret-key"
```

## Complete Examples

### Basic Server Setup

```bash
dalfox server \
  --host 0.0.0.0 \
  --port 8080 \
  --api-key secret123
```

### Production Server with CORS

```bash
dalfox server \
  --host 0.0.0.0 \
  --port 443 \
  --api-key "$(cat /etc/dalfox/api-key.txt)" \
  --allowed-origins "https://security-dashboard.example.com" \
  --log-file /var/log/dalfox/server.log
```

### Development Server with JSONP

```bash
dalfox server \
  --host 127.0.0.1 \
  --port 6664 \
  --jsonp \
  --allowed-origins "http://localhost:3000,http://localhost:8080"
```

## Integration Examples

### Python Client

```python
import requests
import json

# Server configuration
BASE_URL = "http://localhost:6664"
API_KEY = "your-secret-key"

headers = {
    "Content-Type": "application/json",
    "X-API-KEY": API_KEY
}

# Submit scan
scan_data = {
    "url": "https://example.com",
    "options": {
        "worker": 100,
        "encoders": ["url", "html"],
        "include_request": True
    }
}

response = requests.post(
    f"{BASE_URL}/scan",
    headers=headers,
    json=scan_data
)

scan_result = response.json()
scan_id = scan_result["msg"]
print(f"Scan ID: {scan_id}")

# Check results
import time
while True:
    result = requests.get(
        f"{BASE_URL}/result/{scan_id}",
        headers=headers
    ).json()
    
    status = result["data"]["status"]
    print(f"Status: {status}")
    
    if status == "done":
        print(json.dumps(result["data"]["results"], indent=2))
        break
    elif status == "error":
        print("Scan failed!")
        break
    
    time.sleep(2)
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:6664';
const API_KEY = 'your-secret-key';

async function scanUrl(url) {
  // Submit scan
  const scanResponse = await axios.post(`${BASE_URL}/scan`, {
    url: url,
    options: {
      worker: 50,
      encoders: ['url', 'html']
    }
  }, {
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': API_KEY
    }
  });

  const scanId = scanResponse.data.msg;
  console.log(`Scan ID: ${scanId}`);

  // Poll for results
  while (true) {
    const result = await axios.get(`${BASE_URL}/result/${scanId}`, {
      headers: { 'X-API-KEY': API_KEY }
    });

    const status = result.data.data.status;
    console.log(`Status: ${status}`);

    if (status === 'done') {
      console.log(JSON.stringify(result.data.data.results, null, 2));
      break;
    } else if (status === 'error') {
      console.log('Scan failed!');
      break;
    }

    await new Promise(resolve => setTimeout(resolve, 2000));
  }
}

scanUrl('https://example.com');
```

### cURL Workflow

```bash
#!/bin/bash

API_KEY="your-secret-key"
BASE_URL="http://localhost:6664"

# Submit scan
SCAN_ID=$(curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: $API_KEY" \
  -d '{"url":"https://example.com","options":{"worker":50}}' \
  | jq -r '.msg')

echo "Scan ID: $SCAN_ID"

# Poll for results
while true; do
  RESULT=$(curl -s "$BASE_URL/result/$SCAN_ID" \
    -H "X-API-KEY: $API_KEY")
  
  STATUS=$(echo "$RESULT" | jq -r '.data.status')
  echo "Status: $STATUS"
  
  if [ "$STATUS" = "done" ]; then
    echo "$RESULT" | jq '.data.results'
    break
  elif [ "$STATUS" = "error" ]; then
    echo "Scan failed!"
    break
  fi
  
  sleep 2
done
```

## Security Considerations

{% alert_warning() %}
**Important Security Notes:**
- Always use `--api-key` in production environments
- Avoid binding to `0.0.0.0` unless necessary
- Use HTTPS reverse proxy (nginx, Apache) in production
- Implement rate limiting at the reverse proxy level
- Restrict CORS origins to trusted domains only
- Monitor logs for suspicious activity
{% end %}

### Recommended Production Setup

1. **Run behind a reverse proxy** (nginx, Apache, Caddy)
2. **Use HTTPS** with valid SSL certificates
3. **Enable API key authentication**
4. **Restrict CORS origins** to specific domains
5. **Implement rate limiting**
6. **Use a process manager** (systemd, supervisord)
7. **Set up logging** and monitoring

### Example nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name dalfox-api.example.com;

    ssl_certificate /etc/letsencrypt/live/dalfox-api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dalfox-api.example.com/privkey.pem;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=dalfox:10m rate=10r/s;
    limit_req zone=dalfox burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:6664;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## See Also

- [Scan Command](/sub-commands/scan)
- [Scanning via REST API Guide](/usage_guides/scanning_via_rest_api)
- [MCP Command](/sub-commands/mcp)
