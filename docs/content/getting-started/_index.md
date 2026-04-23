+++
title = "Getting Started"
description = "Install Dalfox, run your first scan, and learn the basics."
weight = 1
+++

Welcome! This section gets you from zero to a verified XSS finding in about ten minutes.

## What is Dalfox?

Dalfox is a powerful open-source **XSS scanner and automation utility**. Give it a URL, a file of URLs, or a piped crawl — it will:

1. **Discover parameters** across the query string, body, headers, cookies, and DOM.
2. **Probe contexts** to learn where each parameter lands (HTML, JavaScript, attribute, CSS).
3. **Inject payloads** tuned to each context, with optional WAF-evasion encoders.
4. **Verify findings** at the DOM level using an AST-backed parser — not just a text match.
5. **Report results** in the format your workflow speaks (plain, JSON, JSONL, Markdown, SARIF, TOML).

## Who is Dalfox for?

- **Pentesters & bug hunters** — fast CLI reconnaissance that fits any recon stack.
- **Security teams** — SARIF output drops into GitHub Advanced Security or any SAST dashboard.
- **Developers** — a REST API and MCP server let CI/CD pipelines and AI agents drive scans without leaving their tools.

## Ready to go?

Start with **[Installation](./installation/)**, then take the **[Quick Start](./quick-start/)** tour. Once you're comfortable, hop into the [Guide](../guide/) for deeper topics like WAF bypass and Stored XSS.
