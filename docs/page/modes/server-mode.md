---
title: Server Mode
redirect_from: /docs/modes/server-mode/
has_children: false
parent: Usage
nav_order: 4
toc: true
layout: page
---

# Server Mode

## Overview

Server mode transforms Dalfox into a service that can be used in different ways. By default, Dalfox runs as a REST API service, but it can also operate as an MCP (Model Context Protocol) server using the `--type` flag.

### Server Types

1. **REST API Mode (Default)**: Enables integration with other security tools, automation workflows, and continuous security pipelines through HTTP endpoints.

2. **MCP Mode**: Allows Dalfox to operate as a Model Context Protocol server, making it compatible with advanced AI assistants and development environments like Visual Studio Code.

These modes are particularly valuable for:
- Security operations centers (SOCs) looking to build centralized scanning infrastructure
- DevSecOps teams integrating security scanning into CI/CD pipelines
- Bug bounty hunters automating large-scale testing
- Creating custom security dashboards with XSS scanning capabilities
- AI-assisted security testing workflows (MCP mode)

## Starting the Server

To start Dalfox in server mode, use the `server` command:

```bash
# Start with default settings (listening on 0.0.0.0:6664 in REST API mode)
dalfox server

# Specify custom host and port
dalfox server --host 127.0.0.1 --port 8090

# Start REST API server with API key authentication
dalfox server --api-key "your-secret-key"

# Start REST API server with CORS and JSONP enabled
dalfox server --allowed-origins "http://localhost:3000,https://example.com" --jsonp

# Start as an MCP server
dalfox server --type mcp
```

### Server Mode Flags

| Flag                | Description                                                                  | Default        |
|---------------------|------------------------------------------------------------------------------|----------------|
| `--host`            | Specify the address to bind the server to                                    | `0.0.0.0`      |
| `--port`            | Specify the port to bind the server to                                       | `6664`         |
| `--type`            | Specify the server type (`rest` or `mcp`)                                    | `rest`         |
| `--api-key`         | Specify the API key for server authentication (REST API mode only)           | `""` (empty)   |
| `--allowed-origins` | Comma-separated list of allowed origins for CORS (REST API mode only)        | `[]` (empty)   |
| `--jsonp`           | Enable JSONP responses by checking for a `callback` param (REST API mode only) | `false`        |

### Example Output

```bash
dalfox server --host 0.0.0.0 --port 8090
    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''
Parameter Analysis and XSS Scanning tool based on golang
Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul
 🎯  Target                 REST API Mode
 🧲  Listen Address         0.0.0.0:8090
 🏁  Method                 GET
 🖥  Worker                 100
 🔦  BAV                    true
 ⛏  Mining                 true (Gf-Patterns)
 🔬  Mining-DOM             true (mining from DOM)
 ⏱  Timeout                10
 📤  FollowRedirect         false
 🕰  Started at             2021-07-08 18:10:15.214339875 +0900 KST m=+0.027712246
```

## API Documentation

The Dalfox server provides a Swagger UI for easy API exploration and testing. Access it at:

```
http://your-server-address:port/swagger/index.html
```

For example: `http://localhost:8090/swagger/index.html`

![Swagger UI Screenshot](https://user-images.githubusercontent.com/13212227/89736705-5002ab80-daa6-11ea-9ee8-d2def396c25a.png)

## API Endpoints

Dalfox's server mode provides several RESTful endpoints for scan management:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan`  | POST   | Submit a new scan request |
| `/result/:id` | GET | Retrieve scan results by scan ID |
| `/status/:id` | GET | Check the status of a scan by ID |
| `/stop/:id`   | GET | Stop a running scan by ID |

## Basic Scanning Example

### Initiating a Basic Scan

To start a scan with default settings:

```bash
# Request
curl -X POST "http://localhost:8090/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{"url": "https://example.com"}'

# Response
{"code":200,"msg":"28846e5b355577ecd60766f45735c4c687e8c1c200db65700e3f458b73234984","data":null}
```
**Note:** If API key authentication is enabled via the `--api-key` flag when starting the server, you must include the `X-API-KEY` header in all your API requests.

The response contains a scan ID (`msg` field) that you'll use to retrieve results.

### Retrieving Scan Results

```bash
curl -X GET "http://localhost:8090/result/28846e5b355577ecd60766f45735c4c687e8c1c200db65700e3f458b73234984" \
  -H "X-API-KEY: your-secret-key"
```

## Advanced Scanning with Options

You can customize scans by providing options in the request body:

```bash
# Request with custom options
curl -X POST "http://localhost:8090/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{
    "url": "https://example.com", 
    "options": {
      "cookie": "session=abc123",
      "worker": 20,
      "delay": 100,
      "blind": "your-blind-xss.com",
      "header": ["Authorization: Bearer token", "Custom-Header: value"]
    }
  }'
```

### Available Options

The server mode accepts the same options available in CLI mode. Below are some commonly used options:

```json
{
  "url": "https://example.com",
  "options": {
    // Target specification
    "param": ["search", "q"],       // Target specific parameters
    "header": ["Authorization: Bearer token"],  // Custom headers
    "cookie": "sessionid=123456",   // Cookies
    "data": "username=test",        // POST data
    "method": "POST",               // HTTP method

    // Scanning behavior
    "worker": 30,                   // Number of concurrent workers
    "timeout": 10,                  // Timeout in seconds
    "delay": 100,                   // Delay between requests (ms)
    "blind": "your-callback.xss.ht", // Blind XSS callback URL
    "follow-redirects": true,       // Follow HTTP redirects

    // Feature control
    "mining-dom": true,             // Enable DOM-based parameter mining
    "mining-dict": true,            // Enable dictionary-based parameter mining
    "only-discovery": false,        // Only perform parameter analysis
    "skip-bav": false,              // Skip BAV analysis

    // Output control
    "format": "json",               // Output format
    "silence": true,                // Minimal output mode
    "found-action": "webhook.sh",   // Action on finding vulnerability
    "debug": false                  // Enable debug mode
  }
}
```

For a complete list of options, refer to the [options model](https://github.com/hahwul/dalfox/blob/master/pkg/model/options.go).

## Integration Examples

### Python Client Example

```python
import requests
import json
import time

DALFOX_SERVER = "http://localhost:8090"

def start_scan(url, options=None):
    payload = {"url": url}
    if options:
        payload["options"] = options
    
    response = requests.post(f"{DALFOX_SERVER}/scan", json=payload)
    return response.json()["msg"]  # Return the scan ID

def get_scan_results(scan_id):
    response = requests.get(f"{DALFOX_SERVER}/result/{scan_id}")
    return response.json()

def main():
    # Start scan with custom options
    scan_id = start_scan("https://example.com/search?q=test", {
        "worker": 10,
        "timeout": 5,
        "blind": "your-callback.xss.ht"
    })
    
    print(f"Scan started with ID: {scan_id}")
    
    # Poll for results
    while True:
        result = get_scan_results(scan_id)
        if result["status"] == "done":
            print("Scan completed!")
            print(json.dumps(result["data"], indent=2))
            break
        
        print("Scan in progress...")
        time.sleep(5)

if __name__ == "__main__":
    main()
```

### CI/CD Integration (GitHub Actions)

```yaml
name: Dalfox Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Run Dalfox Server
        run: |
          docker run -d -p 6664:6664 hahwul/dalfox:latest server
          sleep 5  # Wait for server to start
      
      - name: Run Scan
        run: |
          # Extract URLs from your application
          URLS=$(grep -r "https://" ./src --include="*.js" | grep -o 'https://[^"]*' | sort | uniq)
          
          # Scan each URL
          for url in $URLS; do
            SCAN_ID=$(curl -s -X POST "http://localhost:6664/scan" \
              -H "Content-Type: application/json" \
              -d "{\"url\": \"$url\"}" | jq -r .msg)
            
            echo "Started scan for $url with ID: $SCAN_ID"
          done
```

## Security Considerations

When deploying Dalfox in server mode, consider the following security practices:

1. **Access Control**: Restrict access to the API server using a reverse proxy, firewall rules, or API keys
2. **Resource Limits**: Set appropriate worker and timeout values to avoid resource exhaustion
3. **Monitoring**: Implement monitoring for the Dalfox server to track resource usage and scan activity
4. **Isolation**: Run the server in an isolated environment (Docker container or separate VM)

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Server unresponsive | Check resource usage; reduce worker count or increase server capacity |
| Slow scan results | Increase worker count or adjust timeout settings |
| Connection errors | Verify network connectivity and firewall settings |
| Memory issues | Reduce concurrent scans or increase server memory |

## Best Practices

- Start with a low number of workers and increase gradually based on your server's capacity
- For production deployments, set up logging and monitoring
- Use a proper API key mechanism for authenticating clients
- Consider implementing rate limiting for public-facing instances
- Regularly update your Dalfox installation to get the latest security checks and bug fixes

## MCP Server Mode
{: .d-inline-block }

New (v2.11.0) 
{: .label .label-blue }

Dalfox can function as a Model Context Protocol (MCP) server, enabling direct integration with AI-powered development environments like Visual Studio Code and compatible AI assistants.

### What is MCP?

Model Context Protocol (MCP) is a protocol designed to enable AI assistants to execute specialized tools in a controlled environment. By running Dalfox as an MCP server, AI coding assistants can directly leverage Dalfox's XSS scanning capabilities within your development workflow.

### Setting Up MCP Integration with VS Code

To use Dalfox as an MCP server with Visual Studio Code:

1. Start Dalfox in MCP server mode:
   ```bash
   dalfox server --type mcp
   ```

2. Configure VS Code to use Dalfox as an MCP server by adding the following to your `settings.json`:
   ```json
   {
     "mcp": {
       "servers": {
         "dalfox": {
           "type": "stdio",
           "command": "dalfox",
           "args": [
             "server",
             "--type=mcp"
           ]
         }
       }
     }
   }
   ```

3. With this configuration, compatible AI coding assistants can now use Dalfox to perform XSS vulnerability scanning directly within your IDE.

### Benefits of MCP Mode

- **AI-Driven Security Testing**: AI assistants can suggest and execute security tests directly within your development environment
- **Interactive Scanning**: Have conversations with AI about possible XSS vulnerabilities in your code
- **Seamless Workflow Integration**: Eliminates the need to switch between your development environment and security tools
- **Guided Remediation**: AI can not only find vulnerabilities but help explain and fix them in context
