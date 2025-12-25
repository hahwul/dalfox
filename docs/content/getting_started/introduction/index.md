+++
title = "Introduction"
description = "Introduction to Dalfox - a powerful open-source XSS scanner"
weight = 1
sort_by = "weight"

[extra]
+++

Dalfox is a fast, automated XSS scanner built with Rust. It discovers parameters, tests for XSS vulnerabilities, and provides comprehensive analysis.

{% alert_info() %}
**Name Origin**: Dal([달](https://en.wiktionary.org/wiki/달)) is Korean for "moon" + "Fox" (Finder Of XSS) 🦊
{% end %}

## Key Features

### Scanning Modes
- **URL**: Test single or multiple URLs
- **File**: Batch scan from file
- **Pipe**: Integrate with other tools
- **Raw HTTP**: Use raw request files
- **Server**: REST API mode

### Parameter Analysis
Automatically discovers and tests parameters in:
- Query strings, POST data, JSON
- HTTP headers and cookies
- URL path segments

Mining techniques: dictionary, DOM-based, response heuristics, remote wordlists (Burp, AssertNote)

### XSS Detection
- **Reflected**: Immediate response reflection
- **Stored**: Persistent XSS with verification
- **DOM-based**: AST-powered JavaScript analysis
- **Blind**: Out-of-band testing with callbacks

Context-aware payloads, multiple encoders (URL, HTML, Base64), DOM verification

### Performance
Rust-powered concurrent scanning with configurable workers, host grouping, smart preflight checks

### Extensibility
REST API, custom payloads, remote providers (PortSwigger, PayloadBox), MCP for AI integration, multiple output formats (Plain, JSON, JSONL, Markdown, SARIF)

## Next Steps

Ready to start using Dalfox? Check out the [Installation Guide](/getting_started/installation) to set up Dalfox on your system, then follow the [Quick Start Guide](/getting_started/quick_start) to perform your first scan.
