+++
title = "Changelog"
description = "Release history and version changes"
weight = 3
sort_by = "weight"

[extra]
+++

This page summarizes major releases and changes. For detailed release notes, see [GitHub Releases](https://github.com/hahwul/dalfox/releases).

## v3.0.0 (In Development)

Major rewrite in Rust for improved performance and reliability.

**Major Changes**:
- Complete rewrite from Go to Rust
- Enhanced concurrency model with tokio async runtime
- AST-based DOM XSS detection using oxc_parser
- Improved parameter discovery and mining
- New output formats: Markdown and SARIF
- MCP (Model Context Protocol) support for AI integration
- Enhanced server mode with better API design

**New Features**:
- `dalfox mcp` - MCP stdio server for AI assistants
- AST-powered JavaScript analysis for DOM XSS
- SARIF output format for CI/CD integration
- Markdown report generation
- Enhanced configuration file support (TOML/JSON)
- Host grouping for optimized concurrent scanning
- Remote wordlist providers (Burp, AssertNote)
- Cookie extraction from raw HTTP files

**Improvements**:
- 10x faster scanning with Rust performance
- Better memory efficiency
- Improved error handling and logging
- Enhanced payload generation system
- More accurate reflection detection
- Better CSP detection and handling

**Breaking Changes**:
- Command-line interface changes
- Configuration file format changes
- API endpoints restructured
- Some flags renamed or removed

## v2.x (Go Version)

Previous stable version written in Go.

**Key Features**:
- URL, File, Pipe, SXSS modes
- Parameter discovery and mining
- Reflected and Stored XSS detection
- Blind XSS testing
- Custom payload support
- JSON/Plain output formats
- REST API server mode
- Proxy support

For v2.x release notes, see [GitHub Releases](https://github.com/hahwul/dalfox/releases?q=v2).

## Previous Releases

For complete release history including:
- Bug fixes
- Minor improvements
- Security patches
- Dependency updates

Visit the [GitHub Releases Page](https://github.com/hahwul/dalfox/releases).

## Version Numbering

Dalfox follows Semantic Versioning:
- **Major** (v3.0.0): Breaking changes, major rewrites
- **Minor** (v3.1.0): New features, backwards compatible
- **Patch** (v3.0.1): Bug fixes, security patches

## Upgrade Guides

### Upgrading from v2 to v3

v3 is a complete rewrite with significant changes:

**Installation**:
```bash
# Remove v2 (if installed via Homebrew)
brew uninstall dalfox

# Install v3
cargo install dalfox
```

**Command Changes**:
```bash
# v2
dalfox url https://example.com

# v3
dalfox scan https://example.com
```

**Configuration**:
- Configuration file format changed to TOML/JSON
- Location changed to `~/.config/dalfox/config.*`
- Many option names updated

**API**:
- Server API endpoints restructured
- New response format
- Authentication via X-API-KEY header

**Output**:
- New formats: Markdown, SARIF
- JSON structure updated
- Enhanced POC generation

For detailed migration guide, see [GitHub Migration Guide](https://github.com/hahwul/dalfox/blob/main/docs/MIGRATION.md) (if available).

## Stay Updated

- **GitHub Releases**: Watch the [repository](https://github.com/hahwul/dalfox) for new releases
- **Twitter**: Follow [@hahwul](https://twitter.com/hahwul) for announcements
- **Crates.io**: Check [dalfox on Crates.io](https://crates.io/crates/dalfox)

## See Also

- [GitHub Releases](https://github.com/hahwul/dalfox/releases)
- [Contributing](/support/contributing)
- [Installation Guide](/getting_started/installation)
