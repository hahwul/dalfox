# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

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
