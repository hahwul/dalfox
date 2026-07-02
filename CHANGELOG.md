# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## Unreleased

Stability hardening and bug fixes across the `scan` and `mcp` subcommands.

### Fixed

* **`--deep-scan` no longer skips the preflight probe.** The whole preflight was gated behind `if !deep_scan`, so `--deep-scan` — nominally the *more* thorough mode — silently disabled WAF fingerprinting/bypass, CSP-bypass, technology detection, outdated-library detection, and the initial-response AST DOM-XSS analysis. The probe now runs for every scan; `--deep-scan` still lifts the per-parameter payload cap and scans all content types (its documented behavior).
* **`--limit` with `--limit-result-type` no longer hides the findings it limited on.** A run like `--limit 2 --limit-result-type v` (stop after 2 verified findings) truncated the display to the first 2 findings of *any* type, which could hide the verified findings behind earlier reflected ones. The display now truncates on the same per-type count the stop condition uses.
* **`--scan-timeout` is range-checked** (max 24h, matching the server/MCP bound) like every other duration arg, so an out-of-range value fails fast with a clear message instead of risking an `Instant + Duration` overflow panic in the per-target cap.
* **`-i file` reads every file argument** instead of silently scanning only the first, matching the `raw-http` and `har` input shapes.
* **MCP: a parse-error on an already-cancelled scan no longer clobbers it back to `error`**, which lost the user's cancel and rewrote its finish timestamp; the parse-error path now goes through the same `!is_terminal()`-guarded transition as every other error path.
* **MCP: `preflight_dalfox` reports the real target on its internal panic path** instead of a blank `target` field a client can't correlate.

## 3.1.2

A maintenance release: reflected-XSS false-positive fixes, stricter URL-scheme handling, async server / MCP resource-safety, and documentation accuracy fixes.

### Fixed

* Reject non-`http(s)` URL schemes outright instead of mangling them into malformed targets.
* Suppressed a false `[R]` for `javascript:` WAF strip-mutations reflected in inert contexts, and a false `[V]` for `on*` handlers on `<input type="hidden">`. Fixes [#1183](https://github.com/hahwul/dalfox/issues/1183).
* Resource-safety, REST / MCP parity, and hot-path performance fixes across the async scan front-ends — bounded worker leaks, reclaimed job slots, and aligned server / MCP options. Fixes [#1190](https://github.com/hahwul/dalfox/pull/1190).

### Performance & Reliability

* Bounded query-discovery memory with a chunked spawn-and-drain, capping live-task memory during parameter mining.

### Documentation

* Clarified that `--scan-timeout` caps only the injection stage, and corrected the MCP encoder list ([#1182](https://github.com/hahwul/dalfox/pull/1182)), the `server` flag table ([#1175](https://github.com/hahwul/dalfox/pull/1175)), the Google Frontend WAF confidence value ([#1181](https://github.com/hahwul/dalfox/pull/1181)), and the URI-scheme payload example ([#1174](https://github.com/hahwul/dalfox/pull/1174)).
* Version-bump tooling now keeps the installation guide's `dalfox <version>` example in lockstep, fixing the stale sample ([#1180](https://github.com/hahwul/dalfox/pull/1180)).

## 3.1.1

A maintenance release: reflected-XSS recall and false-positive fixes, `url`/`file`/`pipe` subcommand parity, request-fan-out bounding, and unified logging.

### Changed

* **Unified scan target parameter**: Server and MCP now take `target`; REST keeps `url` as a backward-compatible alias. Fixes [#1152](https://github.com/hahwul/dalfox/pull/1152).
* **Unified debug logging**: Routed all debug output through a single stderr `dbg_log!` macro and structured server/MCP loggers, and aligned OOB / blind output with the standard log format ([#1145](https://github.com/hahwul/dalfox/pull/1145), [#1147](https://github.com/hahwul/dalfox/pull/1147), [#1144](https://github.com/hahwul/dalfox/pull/1144)).

### Fixed

* Restored reflected-XSS recall in raw-JS-expression and regex-literal contexts. Fixes [#1161](https://github.com/hahwul/dalfox/pull/1161).
* Demoted inert URL-scheme and `javascript:` self-link reflections, clearing the residual false positive from [#1153](https://github.com/hahwul/dalfox/issues/1153) ([#1154](https://github.com/hahwul/dalfox/pull/1154), [#1160](https://github.com/hahwul/dalfox/pull/1160)).
* Front-loaded the protocol-scheme payload family so the per-param cap can no longer evict it. Fixes [#1159](https://github.com/hahwul/dalfox/pull/1159).
* `url` / `file` / `pipe` subcommands now apply config files, global flags, and `--include-all` ([#1151](https://github.com/hahwul/dalfox/pull/1151)) and respect an explicit `-i` / `--input-type` ([#1149](https://github.com/hahwul/dalfox/pull/1149)).
* `--output` write failures are now reported via stderr and a non-zero exit code. Fixes [#1150](https://github.com/hahwul/dalfox/pull/1150).
* Scoped `--scan-timeout` cancellation to the timed-out target so it no longer aborts other targets, plus assorted OOB and retry edge-case fixes.
* Fixed the Nix build by dropping removed `darwin.apple_sdk` framework inputs. Fixes [#1158](https://github.com/hahwul/dalfox/pull/1158).

### Performance & Reliability

* Per-parameter payload safety cap and recall-preserving DOM-phase early-exit to bound request fan-out ([#1155](https://github.com/hahwul/dalfox/pull/1155), [#1156](https://github.com/hahwul/dalfox/pull/1156)).
* Bounded unbounded task spawning in parameter mining and cut server / hot-path lock-hold and allocations.
* Capped the HPP reflection body read to bound scanner memory. Fixes [#1148](https://github.com/hahwul/dalfox/pull/1148).

## 3.1.0

A feature release: out-of-band (blind) XSS detection, external- and modern-DOM-sink analysis, CSP / Trusted Types awareness, filter-aware payload synthesis, HAR input, a global rate limiter, and broad WAF-bypass and server/MCP hardening.

### Added

* **Blind / out-of-band XSS (`--blind-oob`)**: OAST detection via an [interactsh](https://github.com/projectdiscovery/interactsh) server, catching execution in stored, async, and other non-reflecting sinks. CLI-only for now.
* **External JavaScript analysis (`--analyze-external-js`)**: Fetches a target's same-origin `<script src>` bundles (16 files / 512 KiB cap) and runs them through AST DOM-XSS analysis. Fixes [#1094](https://github.com/hahwul/dalfox/issues/1094).
* **Wider DOM-XSS coverage**: Models `Document.parseHTMLUnsafe()` and `window.open()` as sinks ([#1127](https://github.com/hahwul/dalfox/pull/1127)) and extends the recognized JS sink-name set ([#1139](https://github.com/hahwul/dalfox/pull/1139)).
* **Outdated JS library detection (`--detect-outdated-libs`)**: Flags known-vulnerable front-end library versions as informational findings. Opt-in. Fixes [#1074](https://github.com/hahwul/dalfox/issues/1074).
* **CSP & Trusted Types awareness**: Emits `strict-dynamic` / nonce gadget payloads and adapts to Trusted Types when a policy is present. Fixes [#1097](https://github.com/hahwul/dalfox/issues/1097).
* **Filter-aware payload synthesis**: Computes exact JS breakout sequences from the observed script prefix, including escaped-quote and nested-context cases. Fixes [#1075](https://github.com/hahwul/dalfox/issues/1075), [#1072](https://github.com/hahwul/dalfox/issues/1072), [#1073](https://github.com/hahwul/dalfox/issues/1073).
* **Attribute-decode WAF-bypass mutations**: Four mutations (`KeywordEntityEncode`, `SchemeBreak`, `EntityScheme`, `MultiSlash`) that exploit the HTML tokenizer's attribute-value entity decoding — a layer literal-string WAF regexes don't model.
* **Size-limited WAF inspection-window bypass**: Detects WAFs that inspect only the first N bytes of a request and positions payloads past the window. Part of [#1106](https://github.com/hahwul/dalfox/pull/1106).
* **HAR input (`--input-type har`)**: Accepts a HAR / proxy export (Burp, Caido, ZAP, DevTools, mitmproxy) as a scan source, one target per request. Restores a Go v2.x capability. Fixes [#1095](https://github.com/hahwul/dalfox/issues/1095).
* **Global rate limiting (`--rate-limit` / `-r` / `--rl`)**: A requests-per-second token bucket shared across all workers and targets (`0` = unlimited), bounding the aggregate outbound rate that `--delay` can't. Fixes [#1096](https://github.com/hahwul/dalfox/issues/1096).
* **Transient retry policy (`--retries` / `--retry-delay`)**: Optional exponential-backoff retries for HTTP 5xx and transient transport errors (off by default; HTTP 429 is always retried).
* **`--insecure` TLS flag**: Makes TLS certificate validation configurable for `scan` / `server` / `mcp` (default on; `--insecure=false` enforces). Fixes [#1111](https://github.com/hahwul/dalfox/issues/1111).
* **Whole-scan timeout for server & MCP (`scan_timeout`)**: Bounds total scan duration for concurrent REST / MCP jobs. Part of [#1103](https://github.com/hahwul/dalfox/pull/1103).
* **Structured output metadata (SARIF / Markdown / TOML)**: The scan `meta` envelope (version, targets, duration, request/finding counts, per-target WAF info) now appears in all three formats for parity with JSON. Fixes [#1093](https://github.com/hahwul/dalfox/issues/1093).

### Changed

* **Adaptive WAF evasion (`--waf-evasion`)**: Replaced the blunt `workers=1` / `delay=3000ms` preset with randomized inter-request jitter and an escalating cooldown on clusters of blocked responses. Part of [#1096](https://github.com/hahwul/dalfox/issues/1096).
* **HTTP server internals**: Refactored the REST server into a dedicated subsystem with an extracted job domain.

### Fixed

* Cut reflected-XSS false positives and corrected path special-character probing — higher recall with ~31% fewer requests. Fixes [#1117](https://github.com/hahwul/dalfox/pull/1117).
* Require a payload's handler/sink to survive on the marker element before verifying `[V]`, removing truncated-reflection false positives. Fixes [#1118](https://github.com/hahwul/dalfox/issues/1118).
* Demoted inert encoded-echo reflections for non-tag payloads. Fixes [#1133](https://github.com/hahwul/dalfox/pull/1133).
* Clear DOM taint on clean / sanitized reassignment, removing a class of DOM-XSS false positives. Fixes [#1087](https://github.com/hahwul/dalfox/pull/1087).
* `--encoders` now accepts `htmlpad`, `unicode`, and `zwsp`. Fixes [#1076](https://github.com/hahwul/dalfox/pull/1076).
* Closed xssmaze WAF-facade detection gaps. Fixes [#1104](https://github.com/hahwul/dalfox/pull/1104).
* Parse-DoS hardening against deeply nested hostile JS, plus assorted false-negative and WAF / lifecycle fixes. Fixes [#1115](https://github.com/hahwul/dalfox/pull/1115).
* `--blind-oob` no longer swallows the target URL. Fixes [#1132](https://github.com/hahwul/dalfox/pull/1132).
* Closed 10 latent bugs from a source audit ([#1107](https://github.com/hahwul/dalfox/pull/1107)) and a batch of low-severity fixes ([#1116](https://github.com/hahwul/dalfox/pull/1116)).

### Security & Reliability

* Hardened the scanner / server / MCP against hostile responses — capped body reads and reflection-scan work to prevent OOM and hangs ([#1119](https://github.com/hahwul/dalfox/pull/1119), [#1129](https://github.com/hahwul/dalfox/pull/1129)).
* REST responses now set an explicit `Content-Type` with `nosniff`, and the server warns on non-loopback binds without auth. Fixes [#1122](https://github.com/hahwul/dalfox/pull/1122).
* Fixed a per-job scope leak and added rate-limit / concurrency caps for server and MCP scans ([#1105](https://github.com/hahwul/dalfox/pull/1105), [#1090](https://github.com/hahwul/dalfox/pull/1090)).

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
