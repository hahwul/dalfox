+++
title = "MCP Server"
description = "Expose Dalfox to Claude and other MCP clients as a set of scanner tools."
weight = 2
+++

The **Model Context Protocol** (MCP) is an open standard for letting AI clients talk to external tools. `dalfox mcp` runs a stdio-based MCP server so Claude Desktop, Claude Code, Cursor, and any other MCP-compatible client can drive Dalfox scans directly.

## Starting the server

```bash
dalfox mcp
```

The server speaks MCP over `stdin`/`stdout`. Launch it from the client — you don't run it manually in a terminal.

## Claude Desktop config

Add Dalfox to your Claude Desktop MCP config (`claude_desktop_config.json`):

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

Restart Claude Desktop. Dalfox appears as a tool-provider named `dalfox`.

## Claude Code (and other CLIs)

```bash
claude mcp add dalfox -- dalfox mcp
```

## Available tools

Five tools are exposed. All are async and non-blocking — submit a scan, poll for results, then move on.

### `scan_with_dalfox`

Submit a scan. Returns immediately.

```json
{
  "target": "https://example.com/search?q=test",
  "method": "GET",
  "param": ["q"],
  "headers": ["Authorization: Bearer token"],
  "encoders": ["url", "html"],
  "timeout": 10,
  "workers": 50,
  "blind_callback_url": "https://callback.example",
  "deep_scan": false,
  "skip_ast_analysis": false
}
```

Response:

```json
{ "scan_id": "9f2c…", "target": "https://example.com/search?q=test", "status": "queued" }
```

### `get_results_dalfox`

Poll a scan. Returns status, progress, and results when ready.

```json
{ "scan_id": "9f2c…" }
```

Response (in progress):

```json
{
  "scan_id": "9f2c…",
  "target": "…",
  "status": "running",
  "progress": {
    "params_total": 10,
    "params_tested": 4,
    "requests_sent": 215,
    "findings_so_far": 1,
    "estimated_completion_pct": 40,
    "suggested_poll_interval_ms": 3000
  }
}
```

Response (done):

```json
{
  "scan_id": "9f2c…",
  "status": "done",
  "results": [
    {
      "type": "V",
      "type_description": "Verified",
      "inject_type": "inHTML",
      "method": "GET",
      "param": "q",
      "payload": "<svg/onload=alert(1)>",
      "evidence": "payload reflected and DOM element verified",
      "cwe": "CWE-79",
      "severity": "High"
    }
  ]
}
```

### `list_scans_dalfox`

List every tracked scan. Optional filter:

```json
{ "status": "running" }
```

Returns `total`, `scans: [{scan_id, target, status, result_count}]`.

### `cancel_scan_dalfox`

Abort a queued or running scan:

```json
{ "scan_id": "9f2c…" }
```

### `preflight_dalfox`

Analyse a target **without** sending payloads. Useful for scoping before committing to a scan.

```json
{
  "target": "https://example.com",
  "method": "GET",
  "skip_discovery": false,
  "skip_mining": false
}
```

Returns reachability, discovered parameters, and an estimated request count.

## Typical agent flow

1. Agent calls `preflight_dalfox` to confirm the target and count parameters.
2. Agent calls `scan_with_dalfox`, receives a `scan_id`.
3. Agent polls `get_results_dalfox` using `suggested_poll_interval_ms` from the progress object.
4. Once `status == "done"`, the agent summarises findings and reports back to the user.

Because every tool is async, the agent stays responsive — no long-running tool call blocks the conversation.

## Authorization & safety

The MCP server enforces the same rules as the CLI: **only scan targets you're authorised to test.** Consider gating Dalfox MCP calls behind an explicit user confirmation step in your agent's system prompt — e.g., "Confirm the scope before every scan."

## Troubleshooting

- **Tool not showing up?** Make sure the `dalfox` binary is on the PATH the MCP client uses. For Claude Desktop on macOS, that's often just `/usr/local/bin` or `/opt/homebrew/bin`.
- **Empty results?** Poll again — scans are async. Use `suggested_poll_interval_ms` as your cadence.
- **Want logs?** Run `dalfox mcp --debug` while you're setting things up. The debug lines go to stderr so they don't pollute the MCP channel.
