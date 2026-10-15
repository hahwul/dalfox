+++
title = "Getting Started"
description = "Install Dalfox, run your first XSS scan, and learn the core workflow from URL to verified finding."
weight = 1
+++

This section takes you from zero to a verified XSS finding in about five minutes.

## What is Dalfox?

Dalfox is an open-source **XSS scanner and automation utility**. Give it a URL, a file of URLs, or a piped crawl, and it will:

1. **Discover parameters** in the query string, body, headers, cookies, path, and the input fields on the page.
2. **Probe contexts** to learn where each parameter lands (HTML, JavaScript, attribute, CSS).
3. **Inject payloads** chosen for each context, encoded and mutated to get past filters and WAFs.
4. **Verify findings** in the parsed response instead of matching text: an HTML parser for markup and a JavaScript AST for script contexts.
5. **Report results** in the format your workflow speaks (plain, JSON, JSONL, Markdown, SARIF, TOML).

## Who is Dalfox for?

- **Pentesters and bug hunters:** a fast CLI that slots into any recon pipeline.
- **Security teams:** SARIF output loads into GitHub code scanning or any other tool that reads SARIF.
- **Developers:** a REST API and an MCP server let CI/CD pipelines and AI agents run scans from their own tools.

## Where to start

Start with [Installation](./installation/), then work through the [Quick Start](./quick-start/). [Configuration](./configuration/) shows how to keep your usual flags in a config file. After that, the [Guide](../guide/) covers deeper topics like WAF bypass and Stored XSS.

Coming from Dalfox v2 (Go)? Read [Migrating from v2](./migration/) first. The scan subcommands were merged into one, and several flags were renamed or removed.
