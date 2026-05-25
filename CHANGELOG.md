# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## 3.0.0

Dalfox v3 is a complete, ground-up rewrite in Rust, transitioning from the legacy Go implementation. This release brings massive performance gains, memory safety, structural AST/DOM verification, and a unified CLI interface designed for both human operators and LLM-driven environments.

### 🚀 Key Highlights

* **Complete Rust Rewrite**: Built entirely in Rust (Edition 2024) using a modern async architecture (`tokio`, `reqwest`, `axum`, `oxc_*`, `rmcp`). The legacy Go implementation is retired to the `v2` branch.
* **Unified Subcommand Layout (`scan`)**: The separate legacy commands/inputs (`url`, `file`, `pipe`) have been unified into a single, cohesive `scan` subcommand. Subcommands are now cleanly categorized into:
  * `scan`: Target scanning (URL, file, pipe, stdin)
  * `server`: High-performance async REST API server
  * `payload`: Payloads and event-handlers enumeration
  * `mcp`: First-class Model Context Protocol (MCP) server for agentic AI tools
  *(Note: Hidden legacy aliases for `url`, `file`, and `pipe` are preserved for backward compatibility).*
---

### ➕ Added

* **Model Context Protocol (MCP)**: First-class integration (`dalfox mcp`) exposing `scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, and `preflight_dalfox` over stdio JSON-RPC for LLM-driven workflows.
* **Async REST API Server**: Rebuilt under `dalfox server` using `axum` with support for optional API key verification, CORS, JSONP, and webhook callbacks. Includes an in-memory job store with real cancellation via `AtomicBool` flags and live progress stats.
* **Smart Detection & Verification**:
  * AST + DOM verification powered by `oxc_*`. Verified (`V`) findings now carry the exact execution evidence path, and structural verification can accept marker-less payloads when DOM proves execution.
  * Composable encoder pipelines (`url`, `2url`, `3url`, `4url`, `html`, `base64`, `none`) with automatic JWT, base64url, and URL-encoded JSON inference.
  * Tag and JavaScript keyword bypass mutations using bracketed sandwich probes for partial-strip detection.
* **Modern CLI & Config Experience**:
  * Configuration files support (TOML, JSON) under `$XDG_CONFIG_HOME/dalfox/config.*` with a strict `CLI > config` precedence mapping.
  * Multiple output formats: `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` (JSON/JSONL output includes `meta.target_summary` with per-target status).
  * `--dry-run`: Generates a quick preflight summary (target count, discovered parameters, and estimated request count) without executing any attack payloads.
  * Rich PoC formats via `--poc-type`: `plain`, `curl`, `httpie`, `http-request`.
  * Opt-in controls: `--include-request` and `--include-response` (or `--include-all` for convenience), and `--stream-findings` for mid-scan PoC emissions.
  * Per-target progress bars showing live request count, scan rate, and ETA.
  * Process-cached remote payload/wordlist providers (`payloadbox`, `portswigger`, `burp`, `assetnote`) utilizing thread-safe `OnceLock` fetches.

### 🔄 Changed

* **CLI Reorganization**: Scan options are now cleanly organized under descriptive help headers (`OUTPUT`, `TARGETS`, `SCOPE`, `NETWORK`, `WAF`, etc.). Legacy Go flags without Rust equivalents have been removed.
* **Exit Code Standardization**: Standardized CLI exit codes to `0` (Clean - no findings), `1` (Findings found), and `2` (Runtime / configuration / input error).
* **Automatic Banner Suppression**: The startup banner is now suppressed automatically for machine-readable output formats (`json`, `jsonl`, `sarif`, `toml`), the `mcp` subcommand, and when running in `--silence` mode.
* **Refined `payload` Subcommand**: Re-scoped solely to enumeration (`event-handlers`, `useful-tags`, `payloadbox`, `portswigger`, `uri-scheme`); legacy v2 `enum-*` flags have been removed.

### 🛠️ Fixed

* **Improved Scanning Accuracy**:
  * Enhanced template-literal reflection context (`` `…${marker}…` ``) detection to emit appropriate `${…}` expression breakouts.
  * Classified free attribute-name slots within existing tags (`<div id='x' MARKER>`) as `Attribute(None)`, generating self-triggering event handlers to achieve V (Verified) status.
  * Precise DOM-XSS source reporting (e.g., `new Function(URLSearchParams.get('q'))` properly traces back to `URLSearchParams.get`).
* **Metadata & Reporting Corrections**:
  * Fixed POST form findings to render with `method = POST` and the form's action URL rather than inheriting the parent page's GET details.
* **Scan & Server Reliability**:
  * Skip fragment-only parameters in parameter discovery.
  * Isolated scan-task panics using `catch_unwind`, preventing in-memory jobs from getting stuck in `Queued`/`Running` states.
  * Server graceful shutdown via SIGINT/SIGTERM, ensuring in-flight scans write out properly.
  * Fixed false-positive WAF detection where standard HTTP `429 + Retry-After` rate-limiting was treated as a WAF block.
  * Prevented double-prefixing of URL schemes on case-insensitive matches (e.g., `HTTP://` no longer resolves to `http://HTTP://`).
  * Classify unreachable preflight diagnostic failures into distinct types (`DNS_RESOLUTION_FAILED`, `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`, `CONNECTION_FAILED`).
  * Global panic hook for SIGPIPE on stdout, resolving crashes on downstream CLI pipeline truncation (e.g., `dalfox payload event-handlers | head -10`).
  * decompresses `gzip`, `deflate`, and `brotli` HTTP responses during active inspection.

### ❌ Removed

* Legacy Go runtime entry points, dependencies, and v2-specific flags.

### 🔒 Security

* **API Server Protection**:
  * Mitigated timing attacks on the REST API server via constant-time comparison of `X-API-KEY`.
  * Implemented strict validation regex (`[A-Za-z_$][A-Za-z0-9_$.]{0,63}`) for JSONP callbacks to prevent client-side script injection.
  * Ensured webhook notifications are consistently triggered on all terminal states, including preflight parser errors and panic recoveries.
* **Safe MCP Execution**:
  * Handled task panics inside the MCP worker thread safely with `catch_unwind` to avoid hung jobs.
  * Intentionally excluded file-based raw cookie reading (`cookie_from_raw`) from the MCP interface to prevent arbitrary host-side file reads.

### 📝 Documentation & Packaging

* **Hugo Documentation Site**: Rebuilt documentation with complete v3 references for configuration, CLI arguments, scanning modes, and deployment.
* **Modern Package Configurations**: Updated Nix flakes, AUR PKGBUILD, snap, and Dockerfile configurations with automated checks via `just`.
