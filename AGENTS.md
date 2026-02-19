# AGENTS.md

## Purpose

This file is the working guide for coding agents in this repository.
The goal is to make safe, accurate changes to the current Rust v3 Dalfox codebase.

Scope:
- `src/` runtime logic (CLI, scanning engine, server API, MCP)
- `tests/` validation
- config/default behavior consistency

---

## Project Snapshot (Verified from code)

- Language: Rust (`edition = "2024"`)
- Runtime: `tokio`
- CLI: `clap`
- HTTP: `reqwest`
- Server/API: `axum`
- MCP: `rmcp`
- AST/DOM analysis: `oxc_*` crates

Primary modules:
- `src/main.rs`: CLI entrypoint, global flags, config load/init, subcommand dispatch
- `src/cmd/scan.rs`: scan CLI args, orchestration, preflight checks, output routing
- `src/config.rs`: config schema + precedence (`apply_to_scan_args_if_default`)
- `src/scanning/`: reflection/DOM checks, payload execution pipeline, result models
- `src/parameter_analysis/`: discovery + mining + parameter filtering
- `src/payload/`: canonical payloads, dynamic payload generation, remote providers
- `src/cmd/server.rs`: async scan API server + CORS/JSONP/API-key logic
- `src/mcp/mod.rs`: MCP stdio tool server (`scan_with_dalfox`, `get_results_dalfox`)

Top-level commands:
- `scan`
- `server`
- `payload`
- `mcp`
- hidden compatibility commands: `url`, `file`, `pipe`

Behavioral default:
- No subcommand => defaults to `scan` in `src/main.rs`.

---

## Non-Negotiable Invariants

1. Keep CLI/default constants centralized.
- Source of truth: `src/cmd/scan.rs`
- Examples: `DEFAULT_TIMEOUT_SECS`, `DEFAULT_WORKERS`, `DEFAULT_ENCODERS`, `DEFAULT_METHOD`
- If a default changes, align all call sites that compare against defaults.

2. Preserve config precedence semantics.
- Config application for scan path uses `Config::apply_to_scan_args_if_default`.
- CLI should win over config.
- When adding fields, update both:
  - struct fields in `ScanConfig`
  - mapping in `apply_to_scan_args_if_default`

3. Preserve output contract.
- Output formats currently include: `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`.
- Keep serialization behavior in `src/scanning/result.rs` aligned with routing in `src/cmd/scan.rs`.
- `include_request` and `include_response` flags must remain opt-in.

4. Respect concurrency boundaries.
- Scan pipeline uses worker and semaphore limits (`workers`, `max_concurrent_targets`, `max_targets_per_host`).
- Do not introduce unbounded async fan-out.

5. Keep server and MCP behavior non-breaking.
- Server jobs are in-memory, async, and status-based (`queued/running/done/error`).
- MCP is stdio/JSON-RPC; avoid stdout noise in MCP mode (banner/log behavior matters).

6. Remote resource initialization is process-cached.
- Remote payload/wordlist fetches use OnceLock cache.
- New behavior should remain idempotent in-process.

---

## Architecture Notes for Changes

### Scanning pipeline (high-level)

1. Parse/normalize targets (`target_parser`)
2. Optional preflight content-type/CSP check
3. Parameter discovery + mining (`parameter_analysis`)
4. Reflection + DOM + AST-assisted checks (`scanning`)
5. Result aggregation
6. Format-specific output rendering

### Where to edit by feature

- New scan flag:
  - `src/cmd/scan.rs` (`ScanArgs` + behavior)
  - `src/main.rs` (default scan construction when no subcommand)
  - `src/config.rs` (`ScanConfig`, template, precedence mapping)
  - If relevant: `src/cmd/server.rs` `ScanOptions`
  - If relevant: `src/mcp/mod.rs` tool args parsing

- New payload primitive:
  - `src/payload/xss_javascript.rs` (canonical source)
  - Derived payload logic in `xss_html.rs` / `xss_event.rs`
  - verify generation path in `src/scanning/xss_common.rs`

- New encoder:
  - `src/encoding/mod.rs`
  - encoder policy application path (`apply_encoders_to_payloads`)
  - path PoC encoder logic in `src/cmd/scan.rs` (`GLOBAL_ENCODERS` usage)
  - CLI help/docs and tests

- New output format:
  - conversion in `src/scanning/result.rs`
  - dispatch branch in `src/cmd/scan.rs`
  - integration tests under `tests/integration/`

- Server API behavior:
  - `src/cmd/server.rs` (auth, CORS, JSONP, scan options mapping)
  - keep callback validation strict for JSONP

- MCP tool behavior:
  - `src/mcp/mod.rs`
  - keep tool inputs minimal and deterministic

---

## Testing Expectations

Fast local loop:
- `cargo test`

Broader validation:
- `cargo test -- --include-ignored`
- `cargo test -- --nocapture`

Targeted suites:
- unit + module-level tests in `src/**` (`#[cfg(test)]`)
- integration tests: `tests/integration/`
- functional mock-server tests: `tests/functional/`
- e2e smoke: `tests/e2e/cli_smoke_test.rs`

Handy task aliases (from `justfile`):
- `just test`
- `just test_all`
- `just dev`
- `just build`

When behavior changes, add or update tests near the touched module plus one higher-level test when the change crosses module boundaries.

---

## Change Safety Checklist

Before finishing a change, verify:

1. CLI/config consistency
- New or changed scan option is reflected in `ScanArgs`, config mapping, and default path.

2. Output compatibility
- Existing formats still render and parse as expected.

3. Concurrency stability
- No new unbounded tasks or shared-state races.

4. Request/response privacy controls
- Detailed request/response output only appears when explicitly requested.

5. Tests
- Relevant tests pass locally for touched area.

---

## Practical Agent Rules

- Prefer minimal, localized edits over broad refactors.
- Keep public behavior stable unless change explicitly requires a breaking shift.
- Reuse existing helpers (encoding/payload/target parsing) before adding new abstractions.
- Avoid `unwrap()` in runtime paths where user input or network I/O is involved.
- Keep logs user-readable in CLI mode and protocol-safe in MCP mode.

If code and docs diverge, treat code as source of truth and update docs in the same change.
