+++
title = "Guide"
description = "Deep dives into how Dalfox works and how to drive it for real targets."
weight = 2
+++

The guide covers the concepts that make Dalfox effective — how parameters are discovered, which payloads run where, how Stored XSS detection works, and how to handle WAFs.

Each page is self-contained. Read them in order the first time, then come back as reference.

## Topics

- **[Scanning Modes](./scanning-modes/)** — Single URL, file batch, pipe, stored-XSS, server, and MCP.
- **[Parameters &amp; Discovery](./parameters/)** — How Dalfox finds inputs, prunes false-positives, and mines wordlists.
- **[Payloads &amp; Encoding](./payloads/)** — Built-in payload families, encoders, and custom wordlists.
- **[WAF Bypass](./waf-bypass/)** — Fingerprinting WAFs and applying evasive mutations.
- **[Stored XSS](./stored-xss/)** — Inject on one URL, verify on another.
- **[Output &amp; Reports](./output/)** — Plain, JSON, JSONL, Markdown, SARIF, TOML.
