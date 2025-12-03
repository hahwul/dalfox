+++
title = "Overview"
description = "Introduction to Dalfox - a powerful open-source XSS scanner"
weight = 1
sort_by = "weight"

[extra]
+++

# What is Dalfox?

Dalfox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS (Cross-Site Scripting) flaws and analyzing parameters. Its advanced testing engine and niche features are designed to streamline the process of detecting and verifying vulnerabilities.

{% alert_info() %}
**Name Origin**: Dal([달](https://en.wiktionary.org/wiki/달)) is the Korean word for "moon," while "Fox" stands for "Finder Of XSS" 🦊
{% end %}

## Key Features

### Multiple Scanning Modes

Dalfox supports various input modes to fit your testing workflow:

- **URL Mode**: Direct testing of single or multiple URLs
- **File Mode**: Batch testing from a file containing URLs
- **Pipe Mode**: Integration with other tools via stdin/stdout
- **Raw HTTP Mode**: Test using raw HTTP request files
- **Server Mode**: REST API for remote orchestration

### Parameter Discovery & Mining

Dalfox can automatically discover and analyze parameters across different injection points:

- **Query parameters**: URL query strings
- **Body parameters**: POST data (form-encoded, JSON)
- **Headers**: Custom HTTP headers
- **Cookies**: Cookie values
- **Path segments**: URL path components

Advanced mining techniques include:
- Dictionary-based parameter discovery
- DOM-based parameter extraction
- Response analysis with heuristics
- Remote wordlist support (Burp, AssertNote)

### XSS Detection

Dalfox employs multiple detection strategies:

- **Reflected XSS**: Immediate reflection in the response
- **Stored XSS**: Persistent XSS testing with verification URL
- **DOM-based XSS**: AST-based JavaScript analysis for DOM XSS

Features:
- Context-aware payload generation (HTML, JavaScript, Attribute contexts)
- Multiple encoding options (URL, double URL, HTML entity, Base64)
- DOM verification using `.dalfox` element detection
- AST-based taint analysis for JavaScript sources and sinks

### Blind XSS Support

Test for out-of-band XSS vulnerabilities with:
- Callback URL support
- Custom blind payload templates
- Automated injection across all parameter types

### Performance & Optimization

Built with Rust for maximum performance:
- Concurrent scanning with configurable workers
- Host grouping with per-host rate limiting
- Smart preflight checks (Content-Type filtering, CSP detection)
- Global concurrency limits

### Extensibility

- REST API server mode
- Custom payload support
- Remote payload providers (PortSwigger, PayloadBox)
- MCP (Model Context Protocol) for AI integration
- Multiple output formats (Plain, JSON, JSONL)

## Use Cases

### Security Testing
- Web application security assessments
- Bug bounty hunting
- Penetration testing
- Continuous security testing in CI/CD

### Integration
- Integration with proxy tools (Burp Suite, OWASP ZAP)
- Pipeline automation with other security tools
- AI-powered testing via MCP protocol

### Research & Development
- XSS payload research
- Parameter analysis research
- Custom payload development and testing

## Getting Started

Ready to start using Dalfox? Check out the [Installation Guide](/get_started/installation) to set up Dalfox on your system.
