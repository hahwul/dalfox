+++
title = "Scanning Modes"
description = "Single URL, file batch, pipeline, stored XSS, server, and MCP. Pick the mode that fits your workflow."
weight = 1
toc = true
+++

Dalfox accepts targets in several shapes. Every mode shares the same discovery, payload, and verification engine; they differ only in how you feed URLs in and where results go.

Under the hood there are four subcommands: `scan` (the scanner), `server` (long-lived REST API), `payload` (payload utilities), and `mcp` (Model Context Protocol stdio server). Everything below labelled "URL / File / Pipe / Raw HTTP / HAR / SXSS" is a *shape of input* that the `scan` subcommand handles via `--input-type`; they are not independent subcommands.

> The fan-out input shapes (`file`, `pipe`, `raw-http`, `har`) are `scan`-only: each expands one input into many targets. The `server` and `mcp` interfaces are single-target per call — they take one URL plus explicit method/headers/cookies/body (the same fidelity one HAR entry carries), so you replay a captured session by issuing one call per request.

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
dalfox scan urls.txt
# or, explicit:
dalfox scan --input-type file urls.txt
```

Comments (`#`) and blank lines are ignored. Each URL runs through the full pipeline.

## Pipe mode

Read from `stdin`, the common case when chaining recon tools:

```bash
cat urls.txt | dalfox scan
waybackurls example.com | gf xss | dalfox scan
hakrawler -url https://target.app | dalfox scan
```

Dalfox buffers the input, deduplicates, and scans every line as a target.

## Raw HTTP mode

Save a request you captured in Burp, Caido, or ZAP to a file and hand it to Dalfox:

```bash
dalfox scan --input-type raw-http request.txt
```

The file is a standard raw HTTP request (method + path + headers + blank line + body). Dalfox preserves every header, cookie, and body parameter.

For live proxy workflows (especially Caido Active Workflows) see the dedicated **[Caido integration guide](../integrations/caido/)**. It covers the exact shell pattern, the Caido boolean gotcha in If/Else nodes, and how to turn results into Findings automatically.

## HAR mode

Hand Dalfox a whole [HAR](http://www.softwareishard.com/blog/har-12-spec/) (HTTP Archive) export — the JSON capture that browser DevTools and intercepting proxies (Burp, Caido, ZAP, Charles, mitmproxy) produce — and it scans every request in it, preserving each one's URL, method, headers, cookies, and body:

```bash
# Auto-detected from the file content:
dalfox scan capture.har
# or explicit:
dalfox scan --input-type har capture.har
# or piped from another tool:
mitmdump -nr flows -w /dev/stdout --set hardump=- | dalfox scan -i har
```

Unlike flattening a HAR to a plain list of URLs (which throws away method, headers, cookies, and body), HAR mode keeps the full shape of each captured request, so a POST with a JSON body or an authenticated session is replayed faithfully. Each `log.entries[].request` becomes one target; requests are deduplicated by URL + method and run through the same scope filters as every other mode. Non-`http(s)` entries (`data:`, `blob:`, WebSocket, browser-extension URLs) are skipped automatically.

This restores a capability the Go v2.x line had that the v3 rewrite initially dropped. CLI request flags still apply on top — e.g. `-H "Authorization: Bearer …"` is appended to every entry, and `--include-url` / `--out-of-scope` narrow the set.

## Stored XSS mode (SXSS)

Test the classic "inject on form A, payload appears on page B" pattern:

```bash
dalfox scan https://target.app/post-comment \
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

The tools (`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`) are described in [MCP Server](../../integrations/mcp/).

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
| Replay a whole captured session (proxy/DevTools export) | HAR |
| Test a form that writes to another page | SXSS |
| Run many scans from a dashboard or CI | Server |
| Let an AI agent drive scans | MCP |
| Just see what payloads Dalfox would send | Payload utility or `--dry-run` |
