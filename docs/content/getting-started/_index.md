+++
title = "Getting Started"
description = "Install Dalfox, run your first scan, and learn the basics."
weight = 1
+++

This section takes you from zero to a verified XSS finding in about ten minutes.

## What is Dalfox?

Dalfox is a powerful open-source **XSS scanner and automation utility**. Give it a URL, a file of URLs, or a piped crawl, and it will:

1. **Discover parameters** across the query string, body, headers, cookies, and DOM.
2. **Probe contexts** to learn where each parameter lands (HTML, JavaScript, attribute, CSS).
3. **Inject payloads** tuned to each context, with optional WAF-evasion encoders.
4. **Verify findings** at the DOM level using an AST-backed parser, not just a text match.
5. **Report results** in the format your workflow speaks (plain, JSON, JSONL, Markdown, SARIF, TOML).

## Who is Dalfox for?

- **Pentesters & bug hunters:** fast CLI reconnaissance that fits any recon stack.
- **Security teams:** SARIF output drops into GitHub Advanced Security or any SAST dashboard.
- **Developers:** a REST API and MCP server let CI/CD pipelines and AI agents drive scans without leaving their tools.

## Where to start

Start with **[Installation](./installation/)**, then work through the **[Quick Start](./quick-start/)**. After that, the [Guide](../guide/) covers deeper topics like WAF bypass and Stored XSS.
