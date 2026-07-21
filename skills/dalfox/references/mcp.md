# MCP Tools Reference

Dalfox exposes exactly **six tools** via the MCP stdio server (`dalfox mcp` or the built-in MCP mode).

Preferred agent pattern: `preflight_dalfox` → `scan_with_dalfox` → poll `get_results_dalfox` (respect `suggested_poll_interval_ms`) → `delete_scan_dalfox` when terminal.

## Tool Summary

| Tool | Purpose | Blocking? | Returns |
|------|---------|-----------|---------|
| `preflight_dalfox` | Parameter discovery + request count estimate, no payloads sent | Yes (fast) | `reachable`, `params_discovered`, `estimated_total_requests`, per-param breakdown |
| `scan_with_dalfox` | Start async scan | No (returns immediately) | `{scan_id, target, status: "queued"}` |
| `get_results_dalfox` | Poll status + results (supports offset/limit) | No | Full job with `progress`, `results[]` when done |
| `list_scans_dalfox` | List all in-memory jobs (filter by status) | No | Array of job summaries |
| `cancel_scan_dalfox` | Signal cancellation (next checkpoint) | No | Job moves to `cancelled` (partial results kept) |
| `delete_scan_dalfox` | Remove terminal job from memory | No | Job record deleted (running jobs rejected) |

Terminal jobs auto-purge after 1 hour.

## scan_with_dalfox — Full Parameters

```json
{
  "target": "https://example.com/search?q=test",   // required, must have scheme
  "param": ["q", "id:query", "user:body", "auth:header"],
  "method": "POST",
  "data": "user=admin&pass=test",                  // or JSON string
  "headers": ["Authorization: Bearer xxx"],
  "cookies": ["session=abc123"],
  "user_agent": "Mozilla/5.0...",
  "encoders": ["url", "html", "base64"],           // "none" means raw only
  "timeout": 10,                                   // 1-299 (hard validated), per-request
  "scan_timeout": 0,                               // whole-scan wall-clock budget (sec); 0 = disabled
  "delay": 0,                                      // 0-9999 ms (hard validated)
  "rate_limit": 0,                                 // global req/sec across all workers; 0 = unlimited
  "follow_redirects": false,
  "proxy": "http://127.0.0.1:8080",
  "insecure": true,                                // TLS posture; default skips cert validation, set false to enforce
  "include_request": false,                        // opt-in only — responses can be huge
  "include_response": false,
  "skip_mining": false,
  "skip_discovery": false,
  "deep_scan": false,
  "skip_ast_analysis": false,
  "analyze_external_js": false,                    // fetch same-origin <script src> bundles, AST-analyze (16 files / 512 KiB)
  "detect_outdated_libs": false,                   // also emit [I] findings for known-vulnerable JS libs (CWE-1104, 0 extra reqs)
  "blind_callback_url": "https://xyz.interact.sh", // OOB `--blind-oob` lifecycle is CLI-only; MCP uses this callback URL
  "workers": 50,                                   // 1-500 (hard validated)
  "max_payloads_per_param": 0,                     // 0 = unlimited (built-in safety cap still applies); use 10–50 for agent smoke
  "wait": false,                                   // true = block until terminal (or wait_timeout_sec) and return get_results shape
  "wait_timeout_sec": 300                          // 1–86400; only used when wait=true (default 300)
}
```

**Hard validation (returns `invalid_params` on violation):**
- `timeout` ∈ [1, 299]
- `delay` ∈ [0, 9999]
- `workers` ∈ [1, 500]
- `max_payloads_per_param` ∈ [0, 100000]
- `wait_timeout_sec` ∈ [1, 86400] when `wait=true`

**Encoder normalization**: If `"none"` is present anywhere, the list becomes `["none"]` only.

**`wait` mode (agent-friendly short scans):**
- `wait=false` (default): return `{scan_id, status: "queued"}` immediately; poll with `get_results_dalfox`.
- `wait=true`: block until `done` / `error` / `cancelled`, or until `wait_timeout_sec` (default 300). Response matches `get_results_dalfox`. On timeout: `wait_timed_out: true`, job left running (cancel with `cancel_scan_dalfox` if needed).
- Prefer `wait=true` + `max_payloads_per_param` + explicit `param` for smoke tests so the agent avoids a multi-tool poll loop.

**Security note — `cookie_from_raw` is deliberately absent** from the MCP surface. Exposing it would allow an MCP caller to cause the host to read an arbitrary file on disk and forward its cookies to an attacker-controlled target (same class of issue that produced GHSA-35wr-x7v6-9fv2 in v2). MCP callers must supply cookies directly via the `cookies` array.

## preflight_dalfox — Parameters

Fewer options (no encoders, no `include_*`, no blind, no deep scan, no workers — it only does discovery).

```json
{
  "target": "...",
  "param": [...],
  "method": "GET",
  "data": "...",
  "headers": [...],
  "cookies": [...],
  "user_agent": "...",
  "timeout": 10,
  "proxy": "...",
  "follow_redirects": false,
  "skip_mining": false,
  "skip_discovery": false
}
```

Use this before expensive scans when the user is concerned about request volume.

## get_results_dalfox — Pagination & Progress

- `offset` / `limit` for large result sets.
- Response always includes a `progress` object with `suggested_poll_interval_ms`.
  - Early scan: 1000–3000 ms
  - Near completion: ~1000 ms
  - Done / error / cancelled: 0
- Honor the suggested interval to avoid hammering the in-memory job store.

## Job Lifecycle (shared with server)

`queued` → `running` → `done` | `error` | `cancelled`

`cancel_scan_dalfox` flips an `AtomicBool`; the scan loop checks it at safe points. Partial findings are returned. The response's `cancelled` field is `true` only when the job was `queued`/`running` at the time of the call; cancelling an already-terminal job (`done`/`error`/`cancelled`) is a no-op and returns `cancelled: false` with `previous_status` set to that terminal state.

## Error Handling in MCP

- Out-of-range numbers → `invalid_params` with exact message.
- Non-`http(s)` target → `invalid_params` (rejected before queueing).
- Unreachable target in preflight → `reachable: false` + `error_code`.
- Unreachable target in `scan_with_dalfox` → terminal `status: "error"` with
  `error_message` containing `CONNECTION_FAILED` (not `done` with empty
  results), so "unreachable" is distinguishable from "no findings".
- `blind_callback_url` triggers blind-XSS probes on the scan path (parity with
  the CLI and REST server).
- `progress.params_tested` / `estimated_completion_pct` advance live as each
  parameter finishes; use them with `suggested_poll_interval_ms` for pacing.
- Use the shared error codes from `cmd::error_codes` (see `results.md`).

## Recommended Agent Loop (MCP)

### Short / smoke scan (preferred when you already know the param)

```json
{
  "target": "https://target/?q=test",
  "param": ["q"],
  "skip_mining": true,
  "skip_discovery": true,
  "max_payloads_per_param": 20,
  "wait": true,
  "wait_timeout_sec": 120
}
```

One `scan_with_dalfox` call → terminal results (or `wait_timed_out`).

### Longer / unknown surface

1. Call `preflight_dalfox` (or CLI `--dry-run`).
2. If `estimated_total_requests` is huge or `reachable == false`, report to user before proceeding.
3. `scan_with_dalfox` (async, `wait=false`) → store `scan_id`. Consider `max_payloads_per_param` and `scan_timeout`.
4. Loop: `get_results_dalfox` (respect interval) until terminal status.
5. Present findings (lead with V, then A, then R — see `results.md`).
6. `delete_scan_dalfox` (optional — terminal jobs auto-expire).

When both MCP tools and the `dalfox` binary exist, **prefer MCP** for agent-driven work.
