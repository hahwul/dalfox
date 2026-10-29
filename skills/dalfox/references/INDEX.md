# Dalfox Skill — References Index

This directory holds detailed, lookup-oriented reference material so the main `SKILL.md` can stay focused on **agent workflows and decision-making**.

## File Map

| File | Purpose | Read when... |
|------|---------|--------------|
| `cli.md` | Complete CLI flag reference, grouped by concern, with defaults and agent notes | You need the exact spelling, default value, or safe combination for a flag |
| `mcp.md` | The 6 MCP tools (`scan_with_dalfox` etc.) with full parameter schemas, validation rules, and security notes | Working via MCP tools (preferred for long/async scans) |
| `results.md` | Finding shape (V/A/R/I + `type_description`), JSON envelope + `target_summary`, `inject_type`, output formats, `--poc-type`, `include_request/response` contract | Interpreting scan output or choosing `--format` / POC style |
| `config.md` | Config file search paths, precedence (`apply_to_scan_args_if_default`), example, banner/silence interaction | User has (or should have) a `config.toml`; or you see unexpected defaults |
| `server-and-payload.md` | `dalfox server` API (flags, REST `options` keys, auth, CORS, JSONP, endpoints) **and** `dalfox payload <selector>` output | User wants a persistent API, or to list/enumerate payloads |
| `advanced.md` | WAF bypass, mining/discovery controls, scope filters, custom payloads, HPP, concurrency caps, `raw-http` / HAR, `--max-payloads-per-param`, bare vs `name:location` `-p` | WAF, huge param surfaces, custom payloads, captured-request testing, or agent fast-mode recipes |

## Design Principles for This Skill

- **Main SKILL.md is the prompt** — short decision trees, concrete workflows ("preflight → scan → poll"), and "in this situation do X".
- **References are for lookup** — exhaustive tables, exact schemas, and edge-case gotchas live here.
- **AGENTS.md invariants are explicit**:
  - `include_request` / `include_response` are opt-in only (`--include-all` is the convenience).
  - Config never overrides explicit CLI flags (precedence is enforced in `apply_to_scan_args_if_default`).
  - Concurrency is bounded (`workers`, `max_concurrent_targets`, `max_targets_per_host`).
  - Exit codes: 0 = clean, 1 = findings, 2 = error.
- **Safety first** — every workflow starts with the authorization check.
- **MCP is preferred** for agent use when the tools are available (non-blocking, progress, cancellation).

## How to Keep This Accurate

When you change behavior in:
- `src/cmd/scan/args.rs` (ScanArgs + defaults)
- `src/mcp/mod.rs` (tool signatures)
- `src/config.rs` (precedence + template)
- `src/server/` or `src/cmd/payload.rs`

...update the corresponding reference file **and** any workflow examples in the main `SKILL.md` in the same change.

`SKILL.md` is also served by the docs site. After editing it, copy it to
`docs/static/.well-known/agent-skills/dalfox/SKILL.md` and refresh the
`digest` in `docs/static/.well-known/agent-skills/index.json`
(`shasum -a 256` of the copy); `tests/agent_skills_sync_test.rs` fails otherwise.
If the frontmatter `description` changes, update it in `index.json` too.
