# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## 3.0.0

Dalfox v3 is rewritten in Rust. It replaces the legacy Go implementation (now on the `v2` branch) with an async architecture and updated CLI structure.

### Added

* Model Context Protocol (MCP) server (`dalfox mcp`) with `scan_with_dalfox`, `get_results_dalfox`, and related tools.
* Async REST API server (`dalfox server`) using axum, with job management, cancellation, and webhook support.
* AST + DOM verification using oxc (verified findings now include execution evidence).
* Composable encoder pipelines and tag/JavaScript keyword bypass mutations.
* Configuration file support (TOML, JSON) under `$XDG_CONFIG_HOME/dalfox/`.
* Output formats: `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`.
* `--dry-run` mode for preflight summary.
* Per-target progress bars and `--stream-findings` option.
* Cached remote payload/wordlist providers.

### Changed

* CLI unified under `scan` subcommand (legacy `url`/`file`/`pipe` aliases preserved for compatibility).
* Exit codes standardized: `0` (clean), `1` (findings), `2` (error).
* Banner automatically suppressed for machine-readable outputs, MCP, and `--silence` mode.
* `payload` subcommand limited to enumeration only.

### Fixed

* Improved template literal and free attribute context detection.
* Accurate POST form method and action reporting.
* Panic isolation in scan tasks and MCP worker using `catch_unwind`.
* Server graceful shutdown handling.
* False-positive WAF detection on standard rate limiting.
* URL scheme double-prefixing issue.
* Preflight error classification and response decompression (gzip, deflate, brotli).
* SIGPIPE handling on stdout.

### Removed

* Legacy Go runtime and v2-specific flags.
* BAV
* `--found-action` flag

### Security

* Constant-time API key comparison in REST server.
* JSONP callback validation to prevent script injection.
* File-based cookie loading excluded from MCP interface.

### Documentation & Packaging

* Documentation site updated for v3.
* Nix flakes, AUR, snap, and Dockerfile updated with automated checks.
