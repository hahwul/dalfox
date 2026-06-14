---
name: dalfox
description: >
  Use when scanning a URL or parameter for XSS (reflected, DOM, stored, blind),
  enumerating reflected parameters, or when the user explicitly mentions "dalfox"
  or "XSS scan". Runs as CLI (`dalfox scan`) or MCP server (6 tools).
  Authoritative workflows for dalfox v3 (Rust). Not for non-XSS vulnerabilities.
---

# Dalfox: XSS Scanning Skill

**Core principle**: XSS scanning sends attack payloads. Always start with authorization.

## 1. Authorization (non-negotiable first step)

Before any scan:

- Confirm the target is owned by the user, a sanctioned test lab, CTF, or authorized engagement.
- If the target is not obviously safe (e.g. not `testphp.vulnweb.com`, `xss-game.appspot.com`, or a clear lab host), ask explicitly:

  > "Confirm you are authorized to send XSS payloads to this target."

Do not proceed without a clear affirmative. Record the scope in one sentence when the user says yes.

## 2. Choose Execution Mode (check in order)

1. **MCP tools available** (`scan_with_dalfox`, `preflight_dalfox`, or tools prefixed `mcp__dalfox__`)  
   → **Prefer MCP**. Async, cancellable, progress tracking, structured results.

2. **`dalfox` binary on PATH** (`command -v dalfox`)  
   → Use CLI.

3. **Neither**  
   → Tell the user the install options: `brew install dalfox`, `cargo install --path .`, or `nix run github:hahwul/dalfox`.

When both are present, MCP is usually the better agent experience for anything longer than a quick smoke test.

See `references/mcp.md` for the exact 6 tools and parameter schemas.

## 3. Core Workflows

### A. Safe Preflight (always do this on big or sensitive targets)

**MCP**:
```json
{"target": "https://target/?q=test", "skip_mining": true}
```
Use `preflight_dalfox`. Look at `estimated_total_requests` and `reachable`.

**CLI**:
```bash
dalfox scan https://target/?q=test --dry-run --skip-mining
```

If the number is huge or `reachable == false`, report back to the user before sending real payloads.

### B. Standard Single-Target Scan (MCP preferred)

1. Preflight (see above).
2. Start the scan:
   - MCP: `scan_with_dalfox` (store the `scan_id`).
   - CLI: `dalfox scan https://target/?q=test -p q ...`
3. Poll (MCP) or watch output (CLI).
4. Present findings using the rules in `references/results.md` (lead with V, surface `type_description` and `inject_type`).
5. Clean up: `delete_scan_dalfox` (MCP) or just let the process end (CLI). Terminal jobs auto-expire after 1 h.

### C. Authenticated / Proxied / Blind XSS

See the concrete flag combinations in `references/cli.md` (search for "Polite authenticated scan" and "Blind").

Two ways to catch blind XSS (CLI):
- `--blind <url>` — you run the listener (interact.sh, Burp Collaborator, XSS Hunter) and watch it yourself.
- `--blind-oob[=servers]` — Dalfox manages an interactsh (OAST) session for you: it registers, correlates each callback to the originating payload, and polls automatically (`--blind-oob-secret` for self-hosted, `--blind-oob-wait` to tune end-of-scan polling). CLI-only for now.

Common MCP pattern:
- Supply `headers`, `cookies`, `proxy`, `blind_callback_url`, and explicit `param` with location hints. (MCP/server expose `--blind`-style callbacks; the managed `--blind-oob` lifecycle is CLI-only.)

### D. File / Many Targets

```bash
dalfox scan targets.txt --skip-mining --workers 10 --delay 150
```

Combine with `--max-concurrent-targets` and `--max-targets-per-host` for safety.

### E. Raw Captured Request (raw-http) / HAR export (har)

```bash
# One captured request:
dalfox scan -i raw-http captured-request.txt --blind https://your.interact.sh
# A whole HAR / proxy export (every request, method+headers+cookies+body preserved):
dalfox scan capture.har                 # auto-detected
dalfox scan -i har capture.har          # explicit
```

Excellent when the interesting parameters live in cookies, custom headers, or a complex JSON body. `har` fans a multi-request capture out into one target per `log.entries[].request` (deduped by URL+method); `raw-http` is the single-request form. See `references/cli.md`.

### F. Stored XSS (SXSS)

```bash
dalfox scan https://target/submit --sxss --sxss-url https://target/view --sxss-retries 5
```

### G. Server Mode (when user wants a persistent API)

```bash
dalfox server --port 6664 --api-key "$TEAM_KEY" --allowed-origins "https://team.example.com"
```

See `references/server-and-payload.md` for endpoints, CORS/JSONP details, and when to choose server vs MCP.

## 4. Result Interpretation (read this every time)

See the full guide in `references/results.md`.

Key points for agents:
- Every finding has `type` (`V`/`A`/`R`) **and** `type_description`.
- `inject_type` tells you the reflection context (`inHTML`, `inJS`, `inATTR`, etc.).
- The parameter *location* (query/body/header/...) is visible in `data` + `method`.
- `include_request` / `include_response` are opt-in only — never enable them by default.

## 5. Performance & Scope Recipes

See `references/advanced.md` for the detailed recipes:

- "Too many parameters / too slow" → preflight + `--skip-mining` + explicit `-p`
- "WAF present" → the matrix of `--waf-bypass`, `--force-waf`, `--waf-evasion`
- "Need custom payloads or markers" → `--custom-payload`, `--inject-marker`, `--custom-alert-*`
- "Captured request testing" → `-i raw-http` (single request) or `-i har` (whole proxy/DevTools export)
- Concurrency / politeness caps

## 6. Configuration & Environment

See `references/config.md`.

- `--config path` overrides everything.
- Default location: `$XDG_CONFIG_HOME/dalfox/` or `~/.config/dalfox/`.
- CLI flags always beat config values (enforced by `apply_to_scan_args_if_default`).
- A `silence = true` in config suppresses the banner the same way `-S` does.

## 7. Boundaries — What Dalfox Is Not For

- Non-XSS issues (SQLi, SSRF, auth bypass, IDOR, etc.).
- Unauthenticated mass recon on targets the user has not explicitly authorized.
- Replacing human code review for complex DOM-XSS — AST findings (`A`) still need manual verification in many cases.

## 8. Quick Reference — Where to Look Next

- Exact CLI flags + safe combos → `references/cli.md`
- MCP tool schemas + gotchas (including why `cookie_from_raw` is absent) → `references/mcp.md`
- Finding types, output formats, POC types, error codes, exit codes → `references/results.md`
- Config precedence, paths, banner behavior → `references/config.md`
- Server API + `dalfox payload` selectors → `references/server-and-payload.md`
- WAF recipes, mining control, raw-http, HPP, custom payloads → `references/advanced.md`

## 9. AGENTS.md Invariants (this skill must respect)

- `include_request` / `include_response` are opt-in only.
- Config never overrides an explicit CLI/MCP value.
- Concurrency is bounded (`workers`, `max_concurrent_targets`, `max_targets_per_host`).
- Exit codes: 0 = clean, 1 = findings, 2 = error.
- All three interfaces (CLI, server, MCP) share the error codes from `cmd::error_codes`.

When in doubt, re-read the relevant reference file and the project `AGENTS.md` before acting.
