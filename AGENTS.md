# AGENTS.md

## Purpose

This file is the working guide for coding agents in this repository.
The goal is to make safe, accurate changes to the current Rust v3 Dalfox codebase.

Scope:
- `src/` runtime logic (CLI, scanning engine, server API, MCP)
- `tests/` validation
- config/default behavior consistency
- `skills/dalfox/` — agent skill bundle (SKILL.md + references/) that must stay aligned with AGENTS.md invariants and code behavior

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
- `src/cmd/scan/`: scan command, split into focused submodules — `mod.rs` (`run_scan` orchestrator + `ScanArgs`-independent glue), `args.rs` (`ScanArgs` + default/cap constants + value parsers), `validation.rs`, `preflight.rs`, `input.rs` (target resolution), `analysis.rs` (preflight/param loop), `scan_loop.rs` (scanning loop), `output.rs` (dry-run/only-discovery/result rendering), `poc.rs`, `postprocess.rs`, `logging.rs`
- `src/cmd/mod.rs`: shared `error_codes` constants + `JobStatus` enum (used by server + MCP)
- `src/config.rs`: config schema + precedence (`apply_to_scan_args_if_default`)
- `src/scanning/`: reflection/DOM checks, AST integration, payload execution pipeline, result models
- `src/parameter_analysis/`: discovery + mining + parameter filtering
- `src/payload/`: canonical payloads, dynamic payload generation, remote providers
- `src/encoding/`: payload encoding pipeline (`apply_encoders_to_payloads`) + pre-encoding detection
- `src/target_parser/`: URL/file/raw-HTTP target normalization
- `src/waf/`: WAF fingerprinting + bypass strategies
- `src/utils/`: shared CLI helpers (banner, color, logging)
- `src/cmd/server.rs`: async scan API server + CORS/JSONP/API-key logic
- `src/cmd/job.rs`: shared async job lifecycle + progress + bounds validation (used by server + MCP)
- `src/mcp/mod.rs`: MCP stdio tool server (`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`)

Top-level commands:
- `scan`
- `server`
- `payload`
- `mcp`
- hidden compatibility commands: `url`, `file`, `pipe`

Behavioral default:
- No subcommand => defaults to `scan` in `src/main.rs`.
- Banner is suppressed automatically for `mcp` and for machine-readable formats (`json`, `jsonl`, `sarif`, `toml`) so stdout stays parseable.

CLI exit codes (`ScanOutcome` in `src/cmd/scan/mod.rs`):
- `0` Clean — scan finished, no findings
- `1` Findings — scan finished, one or more findings
- `2` Error — input/configuration/runtime error

---

## Non-Negotiable Invariants

1. Keep CLI/default constants centralized.
- Source of truth: `src/cmd/scan/args.rs` (re-exported from `src/cmd/scan/mod.rs`)
- Examples: `DEFAULT_TIMEOUT_SECS`, `DEFAULT_WORKERS`, `DEFAULT_ENCODERS`, `DEFAULT_METHOD`, `DEFAULT_DELAY_MS`, `DEFAULT_MAX_CONCURRENT_TARGETS`, `DEFAULT_MAX_TARGETS_PER_HOST`, `DEFAULT_WAF_MIN_CONFIDENCE`
- CLI sanity caps also live here: `CLI_MAX_TIMEOUT_SECS`, `CLI_MAX_DELAY_MS`, `CLI_MAX_WORKERS`
- If a default changes, align all call sites that compare against defaults.

2. Preserve config precedence semantics.
- Config application for scan path uses `Config::apply_to_scan_args_if_default`.
- CLI should win over config.
- When adding fields, update both:
  - struct fields in `ScanConfig`
  - mapping in `apply_to_scan_args_if_default`

3. Preserve output contract.
- Output formats currently include: `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`.
- Keep serialization behavior in `src/scanning/result.rs` aligned with output routing in `src/cmd/scan/output.rs`.
- `include_request` and `include_response` flags must remain opt-in. `--include-all` is a convenience that sets both (resolved in `src/main.rs` before `run_scan`).
- JSON/JSONL envelope `meta` includes `target_summary` (per-target status/findings/error_code).
- All findings include `type_description` alongside the single-letter `type` code.
- `--dry-run` outputs a preflight summary instead of scan results.
- POC output type (`--poc-type`): `plain`, `curl`, `httpie`, `http-request`.

4. Respect concurrency boundaries.
- Scan pipeline uses worker and semaphore limits (`workers`, `max_concurrent_targets`, `max_targets_per_host`).
- Do not introduce unbounded async fan-out.

5. Keep server and MCP behavior non-breaking.
- Server jobs are in-memory, async, and status-based (`queued/running/done/error/cancelled`).
- MCP is stdio/JSON-RPC; avoid stdout noise in MCP mode (banner/log behavior matters).
- Both server and MCP support real cancellation via `AtomicBool` flags checked in scan loops.
- Both include progress tracking (params_total/tested, requests_sent, findings_so_far).
- Use shared error codes from `cmd::error_codes` for application-level errors.

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
  - `src/cmd/scan/args.rs` (`ScanArgs`) + behavior in `src/cmd/scan/mod.rs` (`run_scan`)
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
  - path PoC encoder logic in `src/cmd/scan/poc.rs` (`GLOBAL_ENCODERS` usage)
  - CLI help/docs and tests

- New output format:
  - conversion in `src/scanning/result.rs`
  - dispatch branch in `src/cmd/scan/output.rs`
  - integration tests under `tests/integration/`

- Server API behavior:
  - `src/cmd/server.rs` (auth, CORS, JSONP, scan options mapping)
  - keep callback validation strict for JSONP
  - Endpoints (axum path syntax `{id}`):
    - `POST /scan` — submit a scan
    - `GET /scan` — submit via query params (JSONP-friendly)
    - `GET /scan/{id}` — status + results
    - `DELETE /scan/{id}` — cancel
    - `GET /scans` — list jobs
    - `GET /result/{id}` — alias of `GET /scan/{id}`
    - `POST /preflight` — parameter discovery only
    - `GET /health` — health check

- MCP tool behavior:
  - `src/mcp/mod.rs`
  - keep tool inputs minimal and deterministic
  - Tools: `scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`
  - `cancel_*` flips the cancellation flag (job ends in `cancelled`); `delete_*` removes the job record entirely.

- New error code:
  - Add constant to `src/cmd/mod.rs` `error_codes` module
  - Use the constant in all three interfaces (CLI, server, MCP) plus the agent skill bundle (`skills/dalfox/references/results.md`)
  - Existing codes: `NO_TARGETS`, `NO_FILE`, `INVALID_INPUT_TYPE`, `PARSE_ERROR`, `FILE_READ_ERROR`, `STDIN_ERROR`, `STDIN_NOT_PIPED`, `INPUT_TOO_LARGE`, `CONNECTION_FAILED`, `DNS_RESOLUTION_FAILED`, `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`, `CONTENT_TYPE_MISMATCH`, `TRUNCATED_PER_HOST_CAP`

---

## Testing Expectations

Fast local loop:
- `cargo test`

Broader validation:
- `cargo test -- --include-ignored`
- `cargo test -- --nocapture`

Targeted suites:
- unit + module-level tests in `src/**` (`#[cfg(test)]`)
- crate-level unit tests: `tests/unit/` (encoding, target_parser, utils)
- integration tests: `tests/integration/` (markdown/sarif output, scanner pipeline)
- functional mock-server tests: `tests/functional/` (driven by `tests/functional/mock_cases/`)
- e2e smoke: `tests/e2e/cli_smoke_test.rs`, `tests/e2e/config_path_smoke_test.rs`
- standalone harnesses: `tests/remote_payload_builder_test.rs`, `tests/remote_wordlist_builder_test.rs`, `tests/request_count_probe.rs`, `tests/scan_run_paths_test.rs`

Handy task aliases (from `justfile`):
- `just test` (alias `just t`) — `cargo test`
- `just test_all` — `cargo test -- --include-ignored`
- `just dev` (alias `just d`) — debug build
- `just build` (alias `just b`) — release build
- `just version-check` (alias `just vc`) / `just version-update` (alias `just vu`) — keep version in lockstep across `Cargo.toml`, `Cargo.lock`, `flake.nix`, snap
- `just docs-serve` (alias `just ds`) — serve the docs site locally via hwaro
- `just docs-dependencies` — install docs tooling (hwaro) on macOS
- `just nix-update` — update the Nix flake lockfile

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
- The `skills/dalfox/` bundle (SKILL.md + references/*.md) is published for agent consumers and must be updated when CLI flags, MCP tool schemas, error codes, or core invariants change.

If code and docs diverge, treat code as source of truth and update docs in the same change.
