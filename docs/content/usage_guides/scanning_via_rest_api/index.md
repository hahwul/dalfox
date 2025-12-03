+++
title = "Scanning via REST API"
description = "Learn how to use Dalfox REST API for remote scanning"
weight = 2
sort_by = "weight"

[extra]
+++

# Scanning via REST API

Learn how to use Dalfox in server mode to perform XSS scans via REST API. This is ideal for remote orchestration, CI/CD integration, and building custom security tools.

## Prerequisites

- Dalfox installed (see [Installation Guide](/get_started/installation))
- Basic understanding of REST APIs
- (Optional) `curl`, `jq`, or HTTP client library

## Starting the Server

### Basic Server

Start the server on default port (6664):

```bash
dalfox server
```

The server will start on `http://127.0.0.1:6664`.

### Production Server

For production use, bind to all interfaces and use API key authentication:

```bash
dalfox server \
  --host 0.0.0.0 \
  --port 8080 \
  --api-key your-secret-key
```

{% alert_warning() %}
Always use `--api-key` when exposing the server to a network!
{% end %}

### Server with Environment Variable

```bash
export DALFOX_API_KEY=your-secret-key
dalfox server --host 0.0.0.0 --port 8080
```

## API Endpoints

### POST /scan - Submit a Scan

Submit a scan request with full options.

**Endpoint:** `POST /scan`

**Headers:**
- `Content-Type: application/json`
- `X-API-KEY: your-secret-key` (if authentication is enabled)

**Request Body:**
```json
{
  "url": "https://example.com",
  "options": {
    "worker": 100,
    "delay": 500,
    "blind": "https://callback.example.com",
    "header": ["Authorization: Bearer token123"],
    "method": "POST",
    "data": "username=admin&password=test",
    "user_agent": "Custom Scanner",
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

The `msg` field contains the scan ID for retrieving results.

**cURL Example:**
```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://example.com",
    "options": {
      "worker": 50,
      "encoders": ["url", "html"]
    }
  }'
```

### GET /scan - Submit via Query Parameters

Alternative method using query parameters (useful for JSONP).

**Endpoint:** `GET /scan?url=...&worker=...`

**Query Parameters:**
- `url` (required) - Target URL
- `worker` - Number of workers
- `delay` - Delay in milliseconds
- `blind` - Blind XSS callback URL
- ... (most scan options)

**Example:**
```bash
curl "http://localhost:6664/scan?url=https://example.com&worker=50" \
  -H "X-API-KEY: your-secret-key"
```

**Response:** Same as POST /scan

### GET /result/:id - Get Scan Results

Retrieve scan results by scan ID.

**Endpoint:** `GET /result/{scan_id}`

**Headers:**
- `X-API-KEY: your-secret-key` (if authentication is enabled)

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
        "param": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "...",
        "cwe": "CWE-79",
        "severity": "High",
        "message_id": "...",
        "message_str": "..."
      }
    ]
  }
}
```

**Status Values:**
- `queued` - Scan is waiting to start
- `running` - Scan is in progress
- `done` - Scan completed successfully
- `error` - Scan failed

**Example:**
```bash
curl http://localhost:6664/result/scan_abc123def456 \
  -H "X-API-KEY: your-secret-key"
```

### GET /scan/:id - Alias for /result/:id

Alternative endpoint for getting results:

```bash
curl http://localhost:6664/scan/scan_abc123def456 \
  -H "X-API-KEY: your-secret-key"
```

## Complete Workflow Examples

### Basic Scan Workflow

```bash
#!/bin/bash

API_KEY="your-secret-key"
BASE_URL="http://localhost:6664"

# 1. Submit scan
echo "Submitting scan..."
RESPONSE=$(curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: $API_KEY" \
  -d '{
    "url": "https://example.com",
    "options": {
      "worker": 50
    }
  }')

SCAN_ID=$(echo "$RESPONSE" | jq -r '.msg')
echo "Scan ID: $SCAN_ID"

# 2. Wait and check results
echo "Waiting for results..."
while true; do
  RESULT=$(curl -s "$BASE_URL/result/$SCAN_ID" \
    -H "X-API-KEY: $API_KEY")
  
  STATUS=$(echo "$RESULT" | jq -r '.data.status')
  echo "Status: $STATUS"
  
  if [ "$STATUS" = "done" ]; then
    echo "Scan complete!"
    echo "$RESULT" | jq '.data.results'
    break
  elif [ "$STATUS" = "error" ]; then
    echo "Scan failed!"
    break
  fi
  
  sleep 2
done
```

### Python Client Example

```python
#!/usr/bin/env python3
import requests
import time
import json

class DalfoxClient:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json"
        }
        if api_key:
            self.headers["X-API-KEY"] = api_key
    
    def scan(self, url, options=None):
        """Submit a scan request"""
        data = {"url": url}
        if options:
            data["options"] = options
        
        response = requests.post(
            f"{self.base_url}/scan",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()["msg"]
    
    def get_results(self, scan_id):
        """Get scan results"""
        response = requests.get(
            f"{self.base_url}/result/{scan_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()["data"]
    
    def wait_for_results(self, scan_id, poll_interval=2):
        """Wait for scan to complete and return results"""
        while True:
            data = self.get_results(scan_id)
            status = data["status"]
            
            print(f"Status: {status}")
            
            if status == "done":
                return data["results"]
            elif status == "error":
                raise Exception("Scan failed")
            
            time.sleep(poll_interval)

# Usage
if __name__ == "__main__":
    client = DalfoxClient(
        base_url="http://localhost:6664",
        api_key="your-secret-key"
    )
    
    # Submit scan
    scan_id = client.scan(
        url="https://example.com",
        options={
            "worker": 50,
            "encoders": ["url", "html"],
            "include_request": True
        }
    )
    print(f"Scan ID: {scan_id}")
    
    # Wait for results
    results = client.wait_for_results(scan_id)
    
    # Display results
    print(json.dumps(results, indent=2))
```

### Node.js Client Example

```javascript
const axios = require('axios');

class DalfoxClient {
  constructor(baseUrl, apiKey = null) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Content-Type': 'application/json'
    };
    if (apiKey) {
      this.headers['X-API-KEY'] = apiKey;
    }
  }

  async scan(url, options = {}) {
    const response = await axios.post(`${this.baseUrl}/scan`, {
      url: url,
      options: options
    }, {
      headers: this.headers
    });
    return response.data.msg;
  }

  async getResults(scanId) {
    const response = await axios.get(`${this.baseUrl}/result/${scanId}`, {
      headers: this.headers
    });
    return response.data.data;
  }

  async waitForResults(scanId, pollInterval = 2000) {
    while (true) {
      const data = await this.getResults(scanId);
      const status = data.status;
      
      console.log(`Status: ${status}`);
      
      if (status === 'done') {
        return data.results;
      } else if (status === 'error') {
        throw new Error('Scan failed');
      }
      
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
  }
}

// Usage
(async () => {
  const client = new DalfoxClient(
    'http://localhost:6664',
    'your-secret-key'
  );
  
  // Submit scan
  const scanId = await client.scan('https://example.com', {
    worker: 50,
    encoders: ['url', 'html'],
    include_request: true
  });
  console.log(`Scan ID: ${scanId}`);
  
  // Wait for results
  const results = await client.waitForResults(scanId);
  
  // Display results
  console.log(JSON.stringify(results, null, 2));
})();
```

## Advanced Usage

### Authenticated Scanning

```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://api.example.com/users",
    "options": {
      "method": "POST",
      "header": [
        "Authorization: Bearer eyJhbGciOiJIUzI1...",
        "Content-Type: application/json"
      ],
      "data": "{\"name\":\"test\",\"email\":\"test@example.com\"}",
      "worker": 50
    }
  }'
```

### Blind XSS Testing

```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://example.com",
    "options": {
      "blind": "https://your-callback.burpcollaborator.net",
      "worker": 100
    }
  }'
```

### Custom Payloads

First, upload your payloads to the server filesystem, then reference them:

```bash
curl -X POST http://localhost:6664/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://example.com",
    "options": {
      "custom_payload": "/path/to/payloads.txt",
      "only_custom_payload": true
    }
  }'
```

{% alert_info() %}
Custom payload files must be accessible on the server's filesystem.
{% end %}

### Batch Scanning

```python
#!/usr/bin/env python3
import requests
import time
import json

BASE_URL = "http://localhost:6664"
API_KEY = "your-secret-key"

urls = [
    "https://example.com/page1",
    "https://example.com/page2",
    "https://example.com/page3"
]

# Submit all scans
scan_ids = []
for url in urls:
    response = requests.post(
        f"{BASE_URL}/scan",
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": API_KEY
        },
        json={"url": url, "options": {"worker": 50}}
    )
    scan_id = response.json()["msg"]
    scan_ids.append((url, scan_id))
    print(f"Submitted: {url} -> {scan_id}")

# Wait for all to complete
results = {}
while scan_ids:
    for url, scan_id in scan_ids[:]:
        response = requests.get(
            f"{BASE_URL}/result/{scan_id}",
            headers={"X-API-KEY": API_KEY}
        )
        data = response.json()["data"]
        status = data["status"]
        
        if status == "done":
            results[url] = data["results"]
            scan_ids.remove((url, scan_id))
            print(f"Completed: {url}")
        elif status == "error":
            results[url] = []
            scan_ids.remove((url, scan_id))
            print(f"Failed: {url}")
    
    if scan_ids:
        time.sleep(2)

# Display summary
print("\n=== Results Summary ===")
for url, findings in results.items():
    print(f"{url}: {len(findings)} vulnerabilities found")
```

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  xss-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Install Dalfox
        run: |
          cargo install dalfox
      
      - name: Start Dalfox Server
        run: |
          dalfox server --host 127.0.0.1 --port 6664 &
          sleep 5
      
      - name: Run Scan
        run: |
          SCAN_ID=$(curl -s -X POST http://localhost:6664/scan \
            -H "Content-Type: application/json" \
            -d '{"url":"https://staging.example.com"}' \
            | jq -r '.msg')
          
          # Wait for results
          while true; do
            STATUS=$(curl -s http://localhost:6664/result/$SCAN_ID \
              | jq -r '.data.status')
            
            if [ "$STATUS" = "done" ]; then
              curl -s http://localhost:6664/result/$SCAN_ID \
                | jq '.data.results' > results.json
              break
            fi
            sleep 2
          done
      
      - name: Check for Vulnerabilities
        run: |
          COUNT=$(jq 'length' results.json)
          if [ "$COUNT" -gt 0 ]; then
            echo "Found $COUNT XSS vulnerabilities!"
            jq '.' results.json
            exit 1
          fi
```

### Docker Compose Setup

```yaml
version: '3.8'

services:
  dalfox:
    image: hahwul/dalfox:latest
    command: server --host 0.0.0.0 --port 6664 --api-key ${DALFOX_API_KEY}
    ports:
      - "6664:6664"
    environment:
      - DALFOX_API_KEY=${DALFOX_API_KEY}
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - dalfox
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dalfox-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dalfox
  template:
    metadata:
      labels:
        app: dalfox
    spec:
      containers:
      - name: dalfox
        image: hahwul/dalfox:latest
        command: ["dalfox", "server", "--host", "0.0.0.0", "--port", "6664"]
        env:
        - name: DALFOX_API_KEY
          valueFrom:
            secretKeyRef:
              name: dalfox-secret
              key: api-key
        ports:
        - containerPort: 6664
---
apiVersion: v1
kind: Service
metadata:
  name: dalfox-service
spec:
  selector:
    app: dalfox
  ports:
  - port: 80
    targetPort: 6664
  type: LoadBalancer
```

## CORS Configuration

For web applications that need to access the API from different origins:

```bash
dalfox server \
  --host 0.0.0.0 \
  --port 6664 \
  --api-key secret123 \
  --allowed-origins "https://dashboard.example.com,https://app.example.com" \
  --cors-allow-methods "GET,POST,OPTIONS" \
  --cors-allow-headers "Content-Type,X-API-KEY,Authorization"
```

### JSONP Support

For legacy browser support:

```bash
dalfox server \
  --jsonp \
  --callback-param-name callback
```

**Request with JSONP:**
```bash
curl "http://localhost:6664/scan?url=https://example.com&callback=handleResults"
```

**Response:**
```javascript
handleResults({"code":200,"msg":"scan_abc123"})
```

## Security Best Practices

{% alert_warning() %}
**Production Security Checklist:**
{% end %}

1. **Always use API key authentication**
   ```bash
   dalfox server --api-key "$(openssl rand -hex 32)"
   ```

2. **Use HTTPS with reverse proxy**
   - Never expose HTTP in production
   - Use nginx, Apache, or Caddy as reverse proxy

3. **Implement rate limiting**
   - At reverse proxy level
   - Or using API gateway

4. **Restrict CORS origins**
   ```bash
   --allowed-origins "https://trusted-domain.com"
   ```

5. **Monitor and log**
   ```bash
   --log-file /var/log/dalfox/server.log
   ```

6. **Use systemd or supervisor**
   - Automatic restart on failure
   - Proper process management

7. **Network isolation**
   - Bind to `127.0.0.1` when possible
   - Use firewall rules

## Troubleshooting

{% collapse(title="Connection refused") %}
**Check server is running:**
```bash
curl http://localhost:6664/scan?url=test
```

**Check port binding:**
```bash
netstat -tlnp | grep 6664
```
{% end %}

{% collapse(title="Authentication failed") %}
**Verify API key:**
```bash
curl http://localhost:6664/scan?url=test \
  -H "X-API-KEY: your-secret-key" -v
```

Check for 401 vs 200 status code.
{% end %}

{% collapse(title="Scan stuck in 'queued' status") %}
**Possible causes:**
- Server overloaded
- Network issues reaching target
- Target timeout

**Check server logs** or restart server.
{% end %}

## See Also

- [Server Command Reference](/sub-commands/server) - Complete server documentation
- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - CLI scanning
- [MCP Command](/sub-commands/mcp) - AI integration alternative
