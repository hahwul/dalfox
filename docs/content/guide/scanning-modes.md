+++
title = "Scanning Modes"
description = "Single URL, file batch, pipeline, stored XSS, server, and MCP — pick the mode that fits your workflow."
weight = 1
+++

Dalfox accepts targets in several shapes. Every mode shares the same discovery, payload, and verification engine — they differ only in how you feed URLs in and where results go.

## Auto (default)

Just give Dalfox a URL. It figures out the rest.

```bash
dalfox https://target.app/search?q=test
```

Under the hood, Dalfox uses the `scan` subcommand with `--input-type auto`. It auto-detects whether the argument is a URL, a file path, or a stream on `stdin`.

## URL mode

Force URL parsing (rarely needed, useful in scripts):

```bash
dalfox scan --input-type url https://target.app
```

## File mode

Scan a list of URLs, one per line:

```bash
# urls.txt
# https://target.app/search?q=1
# https://target.app/profile?id=2
dalfox file urls.txt
```

Comments (`#`) and blank lines are ignored. Each URL runs through the full pipeline.

## Pipe mode

Read from `stdin` — the common case when chaining recon tools:

```bash
cat urls.txt | dalfox
waybackurls example.com | gf xss | dalfox
hakrawler -url https://target.app | dalfox
```

Dalfox buffers the input, deduplicates, and scans every line as a target.

## Raw HTTP mode

Captured a request in Burp, Caido, or ZAP? Save it to a file and hand it to Dalfox:

```bash
dalfox scan --input-type raw-http request.txt
```

The file is a standard raw HTTP request (method + path + headers + blank line + body). Dalfox preserves every header, cookie, and body parameter.

## Stored XSS mode (SXSS)

Test the classic "inject on form A, payload appears on page B" pattern:

```bash
dalfox https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox injects into the first URL, then fetches the second to check whether the payload landed. See the [Stored XSS guide](../stored-xss/) for the full flow.

## Server mode

Run Dalfox as a long-lived HTTP service. Submit scans via REST, poll for results, cancel running jobs:

```bash
dalfox server --port 6664 --api-key "$DALFOX_API_KEY"
```

See [REST API Server](../../integrations/server/) for endpoints and request shapes.

## MCP mode

Expose Dalfox as a [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents and IDEs (like Claude) can drive scans:

```bash
dalfox mcp
```

The tools (`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `preflight_dalfox`) are described in [MCP Server](../../integrations/mcp/).

## Payload mode (utility)

Not a scanning mode, but useful alongside: print or fetch payloads without running a scan.

```bash
dalfox payload event-handlers    # list DOM event handlers
dalfox payload useful-tags       # list useful HTML tags
dalfox payload portswigger       # fetch PortSwigger XSS cheatsheet
dalfox payload payloadbox        # fetch PayloadBox XSS list
dalfox payload uri-scheme        # print javascript:/data: payloads
```

## Choosing a mode

| You want to… | Use |
|--------------|-----|
| Test one URL | Auto / URL |
| Scan a list from your crawler | File or Pipe |
| Replay a specific request | Raw HTTP |
| Test a form that writes to another page | SXSS |
| Run many scans from a dashboard or CI | Server |
| Let an AI agent drive scans | MCP |
| Just see what payloads Dalfox would send | Payload utility or `--dry-run` |
