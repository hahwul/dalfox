# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## 3.0.0

Dalfox v3 is a complete rewrite in Rust, replacing the legacy Go implementation (now on the `v2` branch) with an asynchronous architecture and a modern CLI structure.

### Added

* **AST-Based JS Analysis**: Replaced heavy headless browsers with fast and accurate static analysis powered by `oxc` for DOM-XSS detection.
* **Model Context Protocol (MCP)**: Added an MCP stdio server (`dalfox mcp`) to expose Dalfox tools directly to AI coding assistants.
* **Async REST API Server**: Rebuilt the API server using `axum` with async job queueing, real-time cancellation, and webhook notifications.
* **Extended Formats & Configurations**: Added TOML/JSON configuration files along with `markdown`, `sarif` (GitHub Code Scanning), and `toml` output formats.
* **Safety & Control**: Introduced `--dry-run` preflight mode, `--stream-findings` for immediate feedback, and limit-capping flags (`--max-payloads-per-param`, `--scan-timeout`).

### Changed

* **Unified CLI Interface**: Consolidated all target scan paths under a single `scan` subcommand, preserving legacy aliases (`url`, `file`, `pipe`) for backward compatibility.
* **Exit Code Standardization**: Aligned standard exits (`0` for clean, `1` for findings, `2` for errors) for seamless CI pipeline integration.
* **Intelligent Output**: Replaced command-line spinners with per-target progress bars, automatically suppressing banners for silence or machine-readable modes.

### Removed

* **Headless Browser Engine**: Removed Chromium/`chromedp` engine and all headless-related CLI flags.
* **Legacy Vulnerability Checkers (BAV)**: Deprecated non-XSS checks to strictly focus on specialized XSS scanning.
* **Outmoded CLI Options**: Removed `--found-action`, `--grep`, `--report`, and `--max-cpu` flags in favor of unified pipelines, formats, and async runtimes.

### Security & Reliability

* Hardened the REST server with constant-time API key comparisons and strict JSONP callback validation.
* Sandbox improvements to exclude local cookie file loaders (`--cookie-from-raw`) from the MCP tool interface.
* Implemented panic isolation (`catch_unwind`) to prevent scanner and MCP thread crashes.
