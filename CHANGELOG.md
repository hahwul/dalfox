# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## Unreleased

### Added

* **HAR input (`--input-type har`)**: `dalfox scan` now accepts a HAR / proxy export (Burp, Caido, ZAP, browser DevTools, mitmproxy) as a scan source. Every `log.entries[].request` becomes a target with its URL, method, headers, cookies, and body preserved — replacing the lossy workaround of flattening a capture to per-line URLs. HAR is auto-detected from file content (and from a stdin pipe), selectable explicitly with `-i har`, deduplicated by URL+method, and run through the same scope filters as every other input. Restores a capability the Go v2.x line had. Fixes [#1095](https://github.com/hahwul/dalfox/issues/1095).
* **Global rate limiting (`--rate-limit` / `-r` / `--rl`)**: A true requests-per-second token-bucket limiter, shared across every worker and target, caps the aggregate outbound rate (`0` = unlimited). Unlike `--delay` (which only spaces a single worker), this bounds the total in-flight burst from `workers × concurrent targets` — friendlier to shared-IP and edge-WAF thresholds. Installed process-wide from the CLI and bound per-job for concurrent MCP / REST scans. Also configurable via `rate_limit` in the config file. Fixes [#1096](https://github.com/hahwul/dalfox/issues/1096).
* **Transient retry policy (`--retries` / `--retry-delay`)**: `send_with_retry` now optionally retries HTTP 5xx and transient transport errors (timeouts, connection resets) with exponential backoff, in addition to the always-on HTTP 429 handling (which honors `Retry-After`). Off by default (`--retries 0`) so the default scan is unchanged; also configurable via `retries` / `retry_delay` in the config file.
* **Structured outputs (SARIF / Markdown / TOML)**: The scan metadata envelope (`meta` with `dalfox_version`, `targets`, `scan_duration_ms`, `total_requests`, `findings_count`, `target_summary` including per-target WAF/bypass info) is now included for parity with JSON/JSONL. SARIF surfaces it under `runs[].properties` and `tool.driver.properties`; Markdown renders summary tables; TOML adds a `[meta]` table. Fixes [#1093](https://github.com/hahwul/dalfox/issues/1093).

### Changed

* **Adaptive WAF evasion (`--waf-evasion`)**: Replaced the blunt `workers=1` / `delay=3000ms` preset with adaptive timing — randomized inter-request jitter (so the cadence can't be fingerprinted) plus an escalating cooldown on clusters of blocked responses. The per-WAF `extra_delay_hint_ms` is now consumed to pace injection requests on detection (previously it only appeared in JSON metadata) instead of being dead weight. Pairs with `--rate-limit`. Part of [#1096](https://github.com/hahwul/dalfox/issues/1096).

## 3.0.2

A packaging and source-build release: installing from source — AUR, `cargo install`, and musl — now links cleanly, and the broken v3.0.1 release pipeline is repaired so every platform artifact ships.

### Fixed

* **Source Builds (AUR / `cargo install` / musl)**: Switched the rustls TLS backend from `aws-lc-rs` to the portable `ring` provider, so source builds no longer fail to link against `aws-lc-sys`'s bundled C/assembly. Dalfox installs ring's `CryptoProvider` at startup via `ensure_crypto_provider()`, since `reqwest` now relies on `rustls-no-provider`.
* **Release Packaging**: Repaired `.deb`/`.rpm` generation — dropped the invalid `description`/`homepage` keys from `[package.metadata.deb]` that aborted the v3.0.1 pipeline, and moved `homepage`/`repository` to `[package]` where `cargo-deb` reads them.
* **Release Matrix**: Hardened the release workflow so one failing target no longer drops the rest — added `fail-fast: false`, upload the binary archive before `.deb`/`.rpm` packaging, collect packages from their real output paths, fix the duplicated `linux-` in package names, and pin `tag_name` so `workflow_dispatch` runs target the intended version. (v3.0.1 shipped only the musl and macOS binaries; Windows `.zip`, both glibc `.tar.gz`, and all `.deb`/`.rpm` were missing.)

### Changed

* **Documentation Site**: Hardened the docs site to the Website Specification — self-hosted Inter/JetBrains Mono fonts and highlight.js, added `robots.txt`, `security.txt`, and a `.well-known/agent-skills` manifest, and tightened the CSP and page templates.

## 3.0.1

A maintenance release focused on scan-accuracy fixes, lighter WAF handling, and broader packaging.

### Added

* **DOM-XSS Coverage**: AST analysis now recognizes jQuery `$()`/`jQuery()` selector-to-HTML sinks, dynamic `import()` execution sinks, and `fetch()`/`XMLHttpRequest` response sources.
* **WAF Fingerprints**: Added NetScaler and cookie-based signatures and generalized the bypass mutations shared across vendors.
* **Packaging**: Added native `.deb`/`.rpm` packages (`cargo-deb` + `cargo-generate-rpm`), musl binaries (`x86_64-musl`, `aarch64-musl`), and Snapcraft and AUR distribution.

### Changed

* **WAF Bypass Performance**: Made WAF bypass payload expansion orthogonal to avoid combinatorial blow-up during scanning.
* **Progress UI**: Animated the scan spinner and progress bars with a metallic shimmer.

### Fixed

* Explicit `-p` targets are now always tested, regardless of `--skip-*` flags.
* Explicit `-p` header/cookie/multipart injection points are honored.
* Explicit `-d` body params are tested under `--skip-mining`/`--skip-mining-dict` (XSSMaze detection 92.7% → 98.2%).
* Workers shut down gracefully instead of panicking on a closed semaphore.
* `--custom-payload` content is validated up front rather than only checking that the file exists.
* Release tooling no longer truncates `aur/PKGBUILD` during version bumps.

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
