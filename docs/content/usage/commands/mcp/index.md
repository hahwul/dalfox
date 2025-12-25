+++
title = "MCP"
description = "Model Context Protocol server for AI integration"
weight = 4
sort_by = "weight"

[extra]
+++

Run Dalfox as a Model Context Protocol (MCP) stdio server, enabling AI assistants to perform XSS scans.

```bash
dalfox mcp [OPTIONS]
```

MCP allows AI models (Claude, GPT, etc.) to use Dalfox for security testing with natural language instructions.

## Tools

**scan_with_dalfox**: Submit scan, returns scan_id and status
- Required: `target` (URL)
- Optional: `param`, `data`, `headers`, `cookies`, `method`, `user_agent`, `encoders`, `timeout`, `delay`, `follow_redirects`, `proxy`, `include_request`, `include_response`

**get_results_dalfox**: Get scan results by scan_id
- Required: `scan_id`
- Returns: `status` (queued | running | done | error) and `results` array

## Claude Desktop Integration

**Config**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

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

Restart Claude Desktop and ask: "Scan https://example.com for XSS vulnerabilities"

## Notes

- Jobs are in-memory (lost on restart)
- Scans run asynchronously and concurrently
- Transport: stdio, Format: JSON-RPC 2.0
- See [MCP specification](https://modelcontextprotocol.io/)

## See Also

- [Server Command](/usage/commands/server) - REST API alternative
- [Scan Command](/usage/commands/scan) - Direct scanning
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
