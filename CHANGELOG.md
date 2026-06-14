# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## 3.1.0

A feature release that broadens what Dalfox can see and how it gets there: out-of-band (blind) XSS detection, analysis of external and modern DOM sinks, CSP / Trusted Types awareness, filter-aware payload synthesis, HAR input, a global rate limiter, and a wide sweep of WAF-bypass and server/MCP hardening.

### Added

* **Blind / out-of-band XSS (`--blind-oob`)**: Adds OAST detection backed by an [interactsh](https://github.com/projectdiscovery/interactsh) server. Payloads carry a per-target, nonce-correlated callback URL, and an out-of-band interaction (DNS / HTTP) confirms execution in contexts that never reflect into the scanned response — stored, asynchronous, and otherwise blind sinks. Callback correlation is AES-256-CTR encrypted; the lifecycle is CLI-only for now (server / MCP deferred).
* **External JavaScript analysis (`--analyze-external-js`)**: Before probing, Dalfox fetches a target's same-origin `<script src>` files (capped at 16 files / 512 KiB) and runs them through the same AST DOM-XSS analysis as inline scripts, so sinks living in linked bundles are no longer invisible. CLI-only for v1. Fixes [#1094](https://github.com/hahwul/dalfox/issues/1094).
* **Wider DOM-XSS sink & source coverage**: The AST analyzer now models `Document.parseHTMLUnsafe()` and `window.open()` as sinks ([#1127](https://github.com/hahwul/dalfox/pull/1127)), unifies HTML-entity decoding across reflection contexts, and extends the recognized JS sink-name set ([#1139](https://github.com/hahwul/dalfox/pull/1139)) — building on the jQuery / `import()` / `fetch()` coverage added in 3.0.1.
* **Outdated / known-vulnerable JS library detection**: Flags out-of-date front-end libraries (e.g. known-vulnerable jQuery / Angular versions) found in script context. Opt-in and scoped to script context to avoid noise. Fixes [#1074](https://github.com/hahwul/dalfox/issues/1074).
* **CSP & Trusted Types awareness**: When a Content-Security-Policy is present, Dalfox emits `strict-dynamic` / nonce gadget payloads and adapts to Trusted Types enforcement instead of firing payloads a policy would block outright. Fixes [#1097](https://github.com/hahwul/dalfox/issues/1097).
* **Filter-aware payload synthesis**: Generates payloads tailored to the observed reflection context and filter — including exact JS breakout-sequence computation from the observed script prefix, escaped-quote-aware breakouts for JS-string filters, and nested script contexts. Fixes [#1075](https://github.com/hahwul/dalfox/issues/1075), [#1072](https://github.com/hahwul/dalfox/issues/1072), [#1073](https://github.com/hahwul/dalfox/issues/1073).
* **Attribute-decode WAF-bypass mutations**: Four new payload mutations target the HTML tokenizer's attribute-value entity decoding — a layer literal-string WAF regexes don't model. `KeywordEntityEncode` entity-encodes the first letter of a sink keyword in an event-handler / `javascript:`-URL value (`onerror=&#97;lert(1)`); `SchemeBreak` and `EntityScheme` split or entity-encode an executable URI scheme (`href=java&#9;script:…`, `href=&#106;avascript:…`) so the literal `javascript:` token never appears on the wire while the browser still resolves it; `MultiSlash` replaces *every* inter-attribute separator with `/` (`<img/src=x/onerror=alert(1)>`) to defeat regexes that re-anchor on whitespace before later attributes. Each carries a strict payload-shape gate (skipped for bare body text and `<script>`/`<style>` payloads, where no entity decoding happens) so it never emits a non-executing variant. Wired into the per-WAF strategies, and the per-payload mutation-variant cap was raised 3→4 — which only takes effect once a WAF is detected — to give them a slot alongside the proven structural mutations.
* **Size-limited WAF inspection-window bypass**: Detects WAFs that only inspect the first N bytes of a request and positions payloads past that window. Part of [#1106](https://github.com/hahwul/dalfox/pull/1106).
* **HAR input (`--input-type har`)**: `dalfox scan` now accepts a HAR / proxy export (Burp, Caido, ZAP, browser DevTools, mitmproxy) as a scan source. Every `log.entries[].request` becomes a target with its URL, method, headers, cookies, and body preserved — replacing the lossy workaround of flattening a capture to per-line URLs. HAR is auto-detected from file content (and from a stdin pipe), selectable explicitly with `-i har`, deduplicated by URL+method, and run through the same scope filters as every other input. Restores a capability the Go v2.x line had. Fixes [#1095](https://github.com/hahwul/dalfox/issues/1095).
* **Global rate limiting (`--rate-limit` / `-r` / `--rl`)**: A true requests-per-second token-bucket limiter, shared across every worker and target, caps the aggregate outbound rate (`0` = unlimited). Unlike `--delay` (which only spaces a single worker), this bounds the total in-flight burst from `workers × concurrent targets` — friendlier to shared-IP and edge-WAF thresholds. Installed process-wide from the CLI and bound per-job for concurrent MCP / REST scans. Also configurable via `rate_limit` in the config file. Fixes [#1096](https://github.com/hahwul/dalfox/issues/1096).
* **Transient retry policy (`--retries` / `--retry-delay`)**: `send_with_retry` now optionally retries HTTP 5xx and transient transport errors (timeouts, connection resets) with exponential backoff, in addition to the always-on HTTP 429 handling (which honors `Retry-After`). Off by default (`--retries 0`) so the default scan is unchanged; also configurable via `retries` / `retry_delay` in the config file.
* **`--insecure` TLS flag**: Makes the TLS-validation posture a first-class, configurable option for `scan` / `server` / `mcp`. Defaults on (scanner-friendly, matching the previous hardcoded behavior); `--insecure=false` enforces certificate validation. Also settable via the config file and server / MCP request params. Fixes [#1111](https://github.com/hahwul/dalfox/issues/1111).
* **Whole-scan timeout for server & MCP (`scan_timeout`)**: A budget that bounds total scan duration for concurrent REST / MCP jobs, complementing the existing per-request timeout. Part of [#1103](https://github.com/hahwul/dalfox/pull/1103).
* **Structured outputs (SARIF / Markdown / TOML)**: The scan metadata envelope (`meta` with `dalfox_version`, `targets`, `scan_duration_ms`, `total_requests`, `findings_count`, `target_summary` including per-target WAF/bypass info) is now included for parity with JSON/JSONL. SARIF surfaces it under `runs[].properties` and `tool.driver.properties`; Markdown renders summary tables; TOML adds a `[meta]` table. Fixes [#1093](https://github.com/hahwul/dalfox/issues/1093).

### Changed

* **Adaptive WAF evasion (`--waf-evasion`)**: Replaced the blunt `workers=1` / `delay=3000ms` preset with adaptive timing — randomized inter-request jitter (so the cadence can't be fingerprinted) plus an escalating cooldown on clusters of blocked responses. The per-WAF `extra_delay_hint_ms` is now consumed to pace injection requests on detection (previously it only appeared in JSON metadata) instead of being dead weight. Pairs with `--rate-limit`. Part of [#1096](https://github.com/hahwul/dalfox/issues/1096).
* **HTTP server internals**: Refactored the REST server into a dedicated subsystem with an extracted job domain, and named/deduplicated magic numbers and reflection helpers in the scanner, for maintainability.

### Fixed

* Cut reflected-XSS false positives and corrected path special-character probing — higher recall with roughly 31% fewer requests. Fixes [#1117](https://github.com/hahwul/dalfox/pull/1117).
* A payload's handler/sink must now survive on the marker element before a finding is verified `[V]`, removing truncated-reflection false positives. Fixes [#1118](https://github.com/hahwul/dalfox/issues/1118).
* Demoted inert encoded-echo reflections (server-escaped quote / scheme echoes) for non-tag payloads. Fixes [#1133](https://github.com/hahwul/dalfox/pull/1133).
* Clear DOM taint on unconditional clean / sanitized reassignment, removing a class of DOM-XSS false positives. Fixes [#1087](https://github.com/hahwul/dalfox/pull/1087).
* `--encoders` allowlist now accepts `htmlpad`, `unicode`, and `zwsp`. Fixes [#1076](https://github.com/hahwul/dalfox/pull/1076).
* Closed xssmaze WAF-facade detection gaps — deferred-callback DOM-XSS descent and WAF backoff. Fixes [#1104](https://github.com/hahwul/dalfox/pull/1104).
* Parse-DoS hardening against deeply nested hostile JS, plus assorted XSS false-negative and WAF / lifecycle fixes. Fixes [#1115](https://github.com/hahwul/dalfox/pull/1115).
* `--blind-oob` no longer swallows the target URL; OOB server list and nonce correlation hardened. Fixes [#1132](https://github.com/hahwul/dalfox/pull/1132).
* Closed 10 latent bugs surfaced by a source audit ([#1107](https://github.com/hahwul/dalfox/pull/1107)), plus a batch of remaining low-severity correctness / performance fixes ([#1116](https://github.com/hahwul/dalfox/pull/1116)).

### Security & Reliability

* Hardened the scanner / server / MCP against hostile responses — capped body reads and reflection-scan work to prevent OOM and hangs, failing toward reporting ([#1119](https://github.com/hahwul/dalfox/pull/1119)) — with further hot-path allocation cuts and server / MCP / OOB resource hardening ([#1129](https://github.com/hahwul/dalfox/pull/1129)).
* REST API responses now set an explicit `Content-Type` with `X-Content-Type-Options: nosniff`, and the server warns when bound to a non-loopback address without authentication. Fixes [#1122](https://github.com/hahwul/dalfox/pull/1122).
* Fixed a per-job scope leak across async tasks and added rate-limit / concurrency caps for server and MCP scans ([#1105](https://github.com/hahwul/dalfox/pull/1105)); aligned validation, reachability, progress, and blind-XSS handling across the async server / MCP interfaces ([#1090](https://github.com/hahwul/dalfox/pull/1090)).

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
