+++
title = "MCP"
description = "Model Context Protocol server for AI integration"
weight = 4
sort_by = "weight"

[extra]
+++

The `mcp` command runs Dalfox as a Model Context Protocol (MCP) stdio server, enabling AI models and assistants to use Dalfox's XSS scanning capabilities.

## What is MCP?

Model Context Protocol (MCP) is a standardized protocol that allows AI models to interact with external tools and services. By running Dalfox in MCP mode, you can:

- Enable AI assistants (like Claude, GPT, etc.) to perform XSS scans
- Integrate Dalfox into AI-powered security workflows
- Automate security testing with natural language instructions
- Build intelligent security analysis pipelines

## Basic Usage

```bash
dalfox mcp [OPTIONS]
```

### Quick Start

**Start MCP server:**
```bash
dalfox mcp
```

The MCP server runs in stdio mode, communicating via standard input and output. This makes it compatible with various MCP clients and AI platforms.

## Available Tools

The MCP server exposes two main tools:

### 1. scan_with_dalfox

Submit a scan request and get a scan ID.

**Tool Signature:**
```json
{
  "name": "scan_with_dalfox",
  "description": "Scan a target URL for XSS vulnerabilities",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target URL to scan"
      },
      "include_request": {
        "type": "boolean",
        "description": "Include HTTP request in results"
      },
      "include_response": {
        "type": "boolean",
        "description": "Include HTTP response in results"
      },
      "param": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Parameter names to test"
      },
      "data": {
        "type": "string",
        "description": "HTTP request body data"
      },
      "headers": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Custom HTTP headers"
      },
      "cookies": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Cookies to send"
      },
      "method": {
        "type": "string",
        "description": "HTTP method (GET, POST, etc.)"
      },
      "user_agent": {
        "type": "string",
        "description": "Custom User-Agent"
      },
      "encoders": {
        "description": "Payload encoders (string or array)",
        "oneOf": [
          { "type": "string" },
          { "type": "array", "items": { "type": "string" } }
        ]
      },
      "timeout": {
        "type": "integer",
        "description": "Request timeout in seconds"
      },
      "delay": {
        "type": "integer",
        "description": "Delay between requests in milliseconds"
      },
      "follow_redirects": {
        "type": "boolean",
        "description": "Follow HTTP redirects"
      },
      "proxy": {
        "type": "string",
        "description": "Proxy URL"
      }
    },
    "required": ["target"]
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "queued"
}
```

### 2. get_results_dalfox

Retrieve scan results by scan ID.

**Tool Signature:**
```json
{
  "name": "get_results_dalfox",
  "description": "Get XSS scan results by scan ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "scan_id": {
        "type": "string",
        "description": "Scan ID from scan_with_dalfox"
      }
    },
    "required": ["scan_id"]
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "done",
  "results": [
    {
      "type": "reflected-xss",
      "param": "id",
      "payload": "<script>alert(1)</script>",
      "evidence": "...",
      "severity": "High"
    }
  ]
}
```

**Possible status values:**
- `queued` - Scan is queued
- `running` - Scan is in progress  
- `done` - Scan completed
- `error` - Scan failed

## Integration with AI Assistants

### Claude Desktop

Add Dalfox to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "dalfox": {
      "command": "dalfox",
      "args": ["mcp"]
    }
  }
}
```

After restarting Claude Desktop, you can ask:
- "Scan https://example.com for XSS vulnerabilities"
- "Check if this URL is vulnerable to XSS: https://test.com?q=search"
- "Scan https://app.example.com with custom headers"

### Custom MCP Client

```python
#!/usr/bin/env python3
import subprocess
import json

class DalfoxMCP:
    def __init__(self):
        self.process = subprocess.Popen(
            ['dalfox', 'mcp'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    def scan(self, target, **options):
        """Submit a scan request"""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_with_dalfox",
                "arguments": {
                    "target": target,
                    **options
                }
            },
            "id": 1
        }
        
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        
        response = self.process.stdout.readline()
        return json.loads(response)
    
    def get_results(self, scan_id):
        """Get scan results"""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_results_dalfox",
                "arguments": {
                    "scan_id": scan_id
                }
            },
            "id": 2
        }
        
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        
        response = self.process.stdout.readline()
        return json.loads(response)
    
    def close(self):
        self.process.terminate()

# Usage
mcp = DalfoxMCP()

# Start scan
scan_result = mcp.scan("https://example.com", include_request=True)
scan_id = scan_result["result"]["scan_id"]
print(f"Scan ID: {scan_id}")

# Get results
import time
while True:
    results = mcp.get_results(scan_id)
    status = results["result"]["status"]
    print(f"Status: {status}")
    
    if status == "done":
        print(json.dumps(results["result"]["results"], indent=2))
        break
    elif status == "error":
        print("Scan failed")
        break
    
    time.sleep(2)

mcp.close()
```

## Use Cases

### AI-Powered Security Testing

**Natural language security testing:**
```
User: "Scan my login page at https://app.example.com/login for XSS"
AI: [Uses scan_with_dalfox tool]
AI: "I found 2 XSS vulnerabilities in the login page..."
```

**Automated analysis:**
```
User: "Test all parameters on https://api.example.com/users?id=1&name=test"
AI: [Uses scan_with_dalfox with param analysis]
AI: "Scanning parameters: id, name. Found vulnerability in 'name' parameter..."
```

### Security Workflow Automation

```
User: "Check these 5 URLs for XSS and summarize the findings"
AI: [Submits multiple scans via scan_with_dalfox]
AI: [Retrieves results via get_results_dalfox]
AI: "Summary: 3 URLs vulnerable, 2 safe. Critical finding in..."
```

### Integration with Security Pipelines

Use MCP to enable AI assistants to:
- Review pull requests for XSS vulnerabilities
- Automated security testing in CI/CD
- Interactive security consultations
- Intelligent vulnerability triage

## Advanced Configuration

### Custom Configuration File

```bash
dalfox mcp --config /path/to/config.toml
```

### Debug Mode

Enable debug logging:
```bash
dalfox mcp --debug
```

## Job Management

The MCP server manages scan jobs in-memory with the following characteristics:

- **Non-blocking**: Scans run asynchronously
- **Concurrent**: Multiple scans can run simultaneously
- **Ephemeral**: Jobs are lost when server stops
- **Isolated**: Each scan runs in its own spawned thread

{% alert_warning() %}
**Important**: Scan jobs are stored in memory only. If the MCP server is stopped, all job data is lost.
{% end %}

## Protocol Details

The MCP server implements the [Model Context Protocol specification](https://modelcontextprotocol.io/):

- **Transport**: stdio (standard input/output)
- **Format**: JSON-RPC 2.0
- **Tools**: 2 (scan_with_dalfox, get_results_dalfox)
- **Schemas**: JSON Schema for tool parameters

### Example JSON-RPC Request

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_with_dalfox",
    "arguments": {
      "target": "https://example.com",
      "include_request": true,
      "encoders": ["url", "html"],
      "timeout": 30
    }
  },
  "id": 1
}
```

### Example JSON-RPC Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "scan_id": "scan_abc123def456",
    "status": "queued"
  },
  "id": 1
}
```

## Troubleshooting

{% collapse(title="MCP client can't connect") %}
1. Verify Dalfox is installed and in PATH
2. Check the command in MCP client config: `dalfox mcp`
3. Test manually: `echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | dalfox mcp`
{% end %}

{% collapse(title="Scans not completing") %}
1. Check if target is accessible
2. Verify network settings (proxy, timeout)
3. Enable debug mode: `dalfox mcp --debug`
4. Check for errors in stderr
{% end %}

{% collapse(title="Results not returning") %}
1. Scans are asynchronous; allow time to complete
2. Check scan status before expecting results
3. Status "done" indicates completion
4. Status "error" indicates failure
{% end %}

## Security Considerations

{% alert_warning() %}
**Security Notes:**
- MCP server runs with same privileges as the user
- No authentication built into stdio protocol
- Restrict access to MCP server process
- Use in trusted environments only
- Monitor resource usage for concurrent scans
{% end %}

## Performance Considerations

- Each scan spawns a new thread
- Concurrent scans share system resources
- Memory usage scales with number of active scans
- Consider resource limits for production use

## See Also

- [Server Command](/sub-commands/server) - REST API alternative
- [Scan Command](/sub-commands/scan) - Direct scanning
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
