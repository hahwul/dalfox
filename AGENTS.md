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
- `src/cmd/mod.rs`: shared `error_codes` constants (used by CLI + server + MCP)
- `src/config.rs`: config schema + precedence (`apply_to_scan_args_if_default`)
- `src/scanning/`: reflection/DOM checks, AST integration, payload execution pipeline, result models. `mod.rs` keeps the scan-worker orchestration (`ScanWorkerCtx` + phases + `run_scanning`); helper clusters are sibling files — `payload_families.rs`, `waf_strategy.rs`, `request_render.rs`, `ast_dom_phase.rs`, `param_jobs.rs`, `progress.rs`. Output serialization is one `format_<fmt>.rs` per format under `src/scanning/result/`.
- `src/parameter_analysis/`: discovery + mining + parameter filtering. `discovery/` is one file per discovery surface (query/header/path/cookie/form/fragment); `mining/` is one file per probe strategy (`probe_*.rs`) plus `collapse.rs` and the cross-module `context_detect.rs` (`detect_injection_context` family)
- `src/payload/`: canonical payloads, dynamic payload generation, remote providers
- `src/encoding/`: payload encoding pipeline (`apply_encoders_to_payloads`) + pre-encoding detection
- `src/target_parser/`: URL/file/raw-HTTP target normalization
- `src/waf/`: WAF fingerprinting + bypass strategies. `bypass/` splits into `types.rs`, `strategy.rs`, and per-family mutators in `mutate.rs`
- `src/utils/`: shared CLI helpers (banner, color, logging)
- `src/server/`: async scan API server, split into focused submodules — `mod.rs` (router + `ServerArgs`), `types.rs` (`ScanOptions` + request/response bodies), `handlers.rs` (route handlers), `job_runner.rs` (`run_scan_job`), `auth.rs` (API key), `cors.rs`, `response.rs` (JSON/JSONP rendering), `util.rs` (option validation + logging)
- `src/job/`: shared job model — `JobStatus` enum, `Job` record, progress counters, retention/cap purging, and bounds helpers (`effective_rate_limit`, `effective_scan_timeout`) used by server + MCP
- `src/mcp/`: MCP stdio tool server — `mod.rs` keeps the `#[tool_router]` impl with the six tool handlers (`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`); `params.rs` holds the `*Params` input structs + serde defaults, `job_runtime.rs` / `pagination.rs` the helpers

Top-level commands:
- `scan`
- `server`
- `payload`
- `mcp`
- `completion` (writes a `clap_complete` shell script to stdout; `bash`, `zsh`, `fish`, `powershell`, `elvish`)
- hidden compatibility commands: `url`, `file`, `pipe`
- hidden packaging helper: `man` (renders the roff man page to stdout)

Both `man` and `completion` are dispatched immediately after parsing, before the
banner/config machinery writes anything, so stdout stays a pure artifact.

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
- Keep serialization behavior in `src/scanning/result/` (one `format_<fmt>.rs` per output format) aligned with output routing in `src/cmd/scan/output.rs`.
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
  - `src/cmd/scan/args.rs`: add the field to `ScanArgs` **and** its default to
    `impl Default for ScanArgs`. Construction sites use `..Default::default()`,
    so these two edits are all the plumbing there is — do not re-add
    exhaustive field lists at call sites. `scanargs_default_matches_clap_defaults`
    fails if the `Default` entry disagrees with the `default_value` you declared.
  - behavior in `src/cmd/scan/mod.rs` (`run_scan`)
  - `src/config.rs` (`ScanConfig`, template, precedence mapping)
  - If relevant: `src/server/types.rs` `ScanOptions` (plus its mapping into
    `ScanArgs` in `src/server/job_runner.rs`)
  - If relevant: `src/mcp/mod.rs` tool args parsing
  - Note: `--state-file`'s config hash covers `ScanArgs` as a whole (a denylist
    over its `Debug` repr, `cmd::scan::state_file::config_hash`), so any new
    field changes the hash and resets existing state files on upgrade. That is
    the safe direction — never add a field to the neutralized list unless it
    genuinely cannot change what a completed target was tested with.

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
  - conversion in `src/scanning/result/` (add a `format_<fmt>.rs`; the model + shared helpers live in `src/scanning/result/mod.rs`)
  - dispatch branch in `src/cmd/scan/output.rs`
  - integration tests under `tests/integration/`

- Server API behavior:
  - `src/server/` — routes in `mod.rs`, handlers in `handlers.rs`, auth in
    `auth.rs`, CORS in `cors.rs`, JSONP rendering in `response.rs`, scan-option
    mapping in `types.rs` + `job_runner.rs`
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
  - Add the constant to `src/cmd/mod.rs` `error_codes` module (the source of
    truth), and add an assertion to the wire-contract test
    `error_code_constants_have_stable_string_values` in the same file — the
    string values are part of the JSON contract.
  - Use the constant in all three interfaces (CLI, server, MCP) — never a bare
    string literal.
  - `skills/dalfox/references/results.md` carries a curated "common ones" list
    that points back to `src/cmd/mod.rs` as the canonical list; add the new code
    there only if consumers will commonly surface it, not mechanically for every code.
  - Existing codes: `NO_TARGETS`, `NO_FILE`, `INVALID_INPUT_TYPE`, `PARSE_ERROR`, `FILE_READ_ERROR`, `STDIN_ERROR`, `STDIN_NOT_PIPED`, `INPUT_TOO_LARGE`, `CONNECTION_FAILED`, `DNS_RESOLUTION_FAILED`, `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`, `CONTENT_TYPE_MISMATCH`, `TRUNCATED_PER_HOST_CAP`, `SESSION_LOST`, `INTERNAL_ERROR`

---

## Testing Expectations

Fast local loop:
- `cargo test`

Broader validation:
- `cargo test -- --include-ignored`
- `cargo test -- --nocapture`

Where a module's own tests live:
- Inline `#[cfg(test)] mod tests { … }` while the block is small — a module you
  can read end to end costs nothing to navigate.
- Once the block passes **roughly 200 lines**, move it out to a sibling file and
  leave `#[cfg(test)] mod tests;` behind. Rust 2018 resolves that to
  `<module>/tests.rs` *next to* `<module>.rs`, so no directory move and no
  `mod.rs` rename is needed: `src/scanning/check_reflection.rs` +
  `src/scanning/check_reflection/tests.rs` is the shape.
- Keep the module name (`tests`, `arg_parser_tests`, …) and the file name in
  step, so `cargo test <module>::` keeps addressing the same set. A file gets
  its module's name; splitting does not rename tests.
- The threshold is a judgement call, not a lint. It exists so a reader knows
  which convention a file follows before opening it, not to be enforced to the
  line.

Targeted suites:
- unit + module-level tests in `src/**` (`#[cfg(test)]`, inline or
  `<module>/tests.rs` per the rule above)
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
- `just version-check` (alias `just vc`) / `just version-update` (alias `just vu`) — keep version in lockstep across `Cargo.toml`, `Cargo.lock`, snap, AUR and the docs (`flake.nix` reads it from `Cargo.toml`, so it is not in the list)
- `just docs-serve` (alias `just ds`) — serve the docs site locally via hwaro
- `just docs-dependencies` — install docs tooling (hwaro) on macOS
- `just nix-update` — update the Nix flake lockfile (the flake pins its own Rust toolchain, so a stale lock breaks `nix build`)
- `just nix-check` / `just nix-build` — evaluate every flake output, or build the package the way `nix build github:hahwul/dalfox` does

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
