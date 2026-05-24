# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./SECURITY.md).

## [3.0.0] - 2026-05-24

### Highlights

- **Complete rewrite in Rust** (edition 2024) on top of `tokio`, `clap`,
  `reqwest`, `axum`, `oxc_*`, and `rmcp`. The Go codebase is preserved
  on the `v2` branch for security backports only.
- New subcommand layout: `scan`, `server`, `payload`, `mcp` (plus
  hidden `url` / `file` / `pipe` compatibility commands). With no
  subcommand `dalfox <target>` still defaults to `scan`.
- First-class **Model Context Protocol (MCP)** server: `dalfox mcp`
  exposes `scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`,
  `cancel_scan_dalfox`, `delete_scan_dalfox`, and `preflight_dalfox`
  over stdio JSON-RPC for LLM-driven workflows.
- Async REST API server (`dalfox server`) with optional API key, CORS,
  JSONP, and webhook callbacks; in-memory job store with real
  cancellation (`AtomicBool`) and live progress (`requests_sent`,
  `findings_so_far`, etc.).
- AST + DOM verification powered by `oxc_*` — V (Verified) findings now
  carry the evidence path that proved them, and structural V can
  accept marker-less payloads when DOM proves execution.
- Composable encoder pipelines (`url`, `2url`, `3url`, `4url`, `html`,
  `base64`, `none`) with automatic JWT / base64url / URL-encoded JSON
  inference and bracketed sandwich probes for partial-strip detection.
- WAF subsystem with confidence-scored fingerprinting
  (`--waf-min-confidence`), tag- and JS-keyword-based bypass mutations,
  per-target bypass effectiveness tracking, and tailored bypasses for
  unknown WAFs based on the inferred block reason.

### Added

- Subcommands `scan`, `server`, `payload`, `mcp`, with shared
  `error_codes` reused across CLI/server/MCP.
- Config file support (TOML, JSON) under
  `$XDG_CONFIG_HOME/dalfox/config.*` with CLI > config precedence via
  `Config::apply_to_scan_args_if_default`; `--config <path>` override.
- Output formats: `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`.
  JSON/JSONL envelopes include a `meta.target_summary` with per-target
  status / findings / error_code. Every finding carries
  `type_description` alongside the single-letter type code.
- `--dry-run`: preflight summary (target count, discovered parameters,
  estimated request count) without sending attack payloads.
- POC formats via `--poc-type`: `plain`, `curl`, `httpie`,
  `http-request`.
- `--include-request` / `--include-response` (opt-in; `--include-all`
  is a convenience that sets both).
- `--stream-findings`: opt-in mid-scan POC emission for long scans
  (off by default; the default flow renders every finding under the
  end-of-scan `WRN XSS found N XSS` summary).
- `--limit-result-type` (`all`, `v`, `r`, `a`) to control which finding
  types count toward `--limit`.
- `--scan-timeout`: hard wall-clock cap (seconds) for the per-target
  scan stage (post-preflight). Bounds the cumulative cost of sequential
  phases that each pay the per-request `--timeout` against partially-
  hung endpoints. `0` disables (default).
- Live progress: per-target progress bars showing request count, rate,
  and ETA. Overall progress line aggregates targets/findings.
- Remote payload / wordlist providers (`payloadbox`, `portswigger`,
  `burp`, `assetnote`) with process-cached `OnceLock` fetches.

### Changed

- CLI surface: scan flags reorganized under help headers (`OUTPUT`,
  `TARGETS`, `SCOPE`, `NETWORK`, `WAF`, …). See
  [`docs/content/reference/cli.md`](./docs/content/reference/cli.md) and
  [`docs/content/reference/config.md`](./docs/content/reference/config.md)
  for the current surface; flags that have no v3 analogue are gone.
- Exit codes: `0` clean, `1` findings, `2` error (input /
  configuration / runtime). The CLI no longer returns `1` for
  ambiguous failures.
- Banner suppression policy: banner is omitted automatically for
  machine-readable formats (`json`, `jsonl`, `sarif`, `toml`), for the
  `mcp` subcommand, for `--silence`, and for `dalfox payload
  <selector>` (machine-readable selector output).
- `payload` subcommand: scoped to enumeration only (`event-handlers`,
  `useful-tags`, `payloadbox`, `portswigger`, `uri-scheme`); the legacy
  `enum-*` flags from v2 are gone.

### Fixed

- **Detection coverage** (caught via pre-release dogfood against
  xss-game and xssmaze):
  - JavaScript template-literal reflection context (`` `…${marker}…` ``)
    is now recognized; the payload generator emits `${…}` expression
    breakouts. Previously these reflections fell through to a generic
    `Javascript(None)` and `'`/`"` escapes were tried in vain.
  - Free attribute-name slot inside an existing tag (`<div id='x'
    MARKER>`) is now classified as `Attribute(None)`; payloads now
    include self-triggering event handlers
    (`onfocus=… autofocus`, `ontoggle=… popover`, …) that promote
    these to V instead of stalling at R.
  - AST DOM-XSS analysis: `new Function(URLSearchParams.get('q'))`
    now reports the originating source (`URLSearchParams.get`) instead
    of falling back to `"unknown source"`.
- **Finding metadata accuracy**:
  - POST-form-discovered findings now render with `method = POST` and
    the form action URL — previously every `Location::Body` finding
    inherited the discovering page's URL and method (typically GET),
    which made the displayed PoC inconsistent with the actual request.
- **Reliability**:
  - `parameter_analysis` skips fragment-only parameters in the scan
    loop; AST DOM analysis runs over the initial response so
    `dalfox server` / `dalfox mcp` produce the same DOM-XSS findings
    as the CLI.
  - Server `axum` graceful shutdown via `tokio::signal::unix::signal`;
    SIGINT/SIGTERM no longer drop in-flight scan tasks mid-write.
  - Scan-task panics are isolated with `catch_unwind`; the task no
    longer leaks into `Queued`/`Running` forever, and pre-start
    cancellations fire the configured webhook.
  - `429 + Retry-After` is no longer auto-classified as an unknown
    WAF — that engaged bypass mutations against benign rate-limited
    backends and produced garbage results.
- **CLI hygiene**:
  - Input validation for `--format`, `--poc-type`, `--encoders`,
    `--only-poc`, `--custom-alert-type`, `--waf-bypass`, `--method`,
    and a sanity-capped `--timeout` — earlier these accepted any
    string and surfaced cryptic mid-scan errors.
  - URL scheme check is case-insensitive (`HTTP://…` no longer
    double-prefixes to `http://HTTP://…`).
  - `UNREACHABLE` preflight diagnostic now classifies the failure
    layer (`DNS_RESOLUTION_FAILED`, `TLS_HANDSHAKE_FAILED`,
    `REQUEST_TIMEOUT`, `CONNECTION_FAILED`).
  - SIGPIPE on stdout exits cleanly via a global panic hook;
    `dalfox payload event-handlers | head -10` no longer panics.
  - `--no-color` / `--silence` accepted at the root as well as on
    subcommands; `NO_COLOR` auto-engages on non-TTY stdout.
- **HTTP**:
  - Decompression for `gzip`, `deflate`, `brotli` enabled via reqwest
    features so compressed responses are inspected, not skipped.

### Removed

- v2 Go runtime entry points and dependencies. Workflows that depended
  on v2-specific flags or stdout shapes need to migrate; the v2 branch
  remains available for users who can't move yet.

### Security

- HTTP server (`dalfox server`):
  - Constant-time `X-API-KEY` comparison closes the byte-by-byte
    timing-attack surface that bitwise `==` exposed.
  - Every terminal state now fires the configured webhook —
    previously the `parse_target` error and panic-recovery paths
    transitioned the job to `Error` but skipped the callback, leaving
    subscribers hanging.
  - Strict JSONP callback validation (`[A-Za-z_$][A-Za-z0-9_$.]{0,63}`)
    to prevent XSS via the `callback` parameter.
- MCP server (`dalfox mcp`):
  - Scan tasks are wrapped in `catch_unwind`; panics and inner-runtime
    build failures now transition the job to `Error` instead of
    leaking the entry into `Queued`/`Running` forever.
  - `cancel_scan_dalfox` no longer reports `estimated_completion_pct
    = 100` for early-cancelled scans (the post-scan
    `params_tested = params_total` write is skipped on cancellation).
  - `cookie_from_raw` is intentionally not exposed over MCP to avoid
    arbitrary host-side file read (the class of issue addressed in v2
    by GHSA-35wr-x7v6-9fv2).
- CLI (`dalfox scan` / all subcommands):
  - A SIGPIPE-on-stdout panic hook exits cleanly when a downstream
    consumer (e.g. `head`, `grep -q`) closes the pipe, so
    `dalfox payload event-handlers | head -10` no longer crashes
    with `failed printing to stdout: Broken pipe (os error 32)`.
  - Per-target / per-host / streaming-printer task panics are now
    surfaced on stderr instead of being silently swallowed.

### Documentation

- `docs/` Hugo site rebuilt with v3 content: getting started,
  scanning modes, parameters, payloads, stored XSS, WAF bypass,
  output, integrations (MCP, server, skills), and full CLI / config /
  environment references.
- Packaging: AUR (`PKGBUILD`), snap, Nix flake, and Dockerfile
  refreshed for v3, with `just version-check` / `just version-update`
  to keep `Cargo.toml`, `Cargo.lock`, `flake.nix`, and snap in
  lockstep.
