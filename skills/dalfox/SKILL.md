---
name: dalfox
description: Use when scanning a URL or parameter for XSS (reflected, DOM, stored, blind), enumerating reflected parameters, or when the user explicitly mentions "dalfox". Runs as a CLI (`dalfox scan <URL>`) or as an MCP server exposing scan/preflight/cancel tools. Not for non-XSS vulnerabilities or general web fuzzing.
---

# Dalfox: XSS Scanning Skill

Dalfox is an XSS scanner. It discovers parameters, checks them for reflection, verifies DOM execution, and reports findings with types **V** (verified DOM execution), **A** (AST-detected), **R** (reflected-only).

## Authorization check — do this first

**Always confirm authorization before scanning a target.** XSS scanning sends payloads to the target and is not safe on systems without permission. If the target is not clearly owned by the user (test lab, CTF, authorized engagement) or not a known test host (e.g., `http://testphp.vulnweb.com`, `https://xss-game.appspot.com`), ask:

> "Confirm you're authorized to send XSS payloads to this target."

Do not proceed without an affirmative answer. For CTFs and authorized pentests, note the scope in a short acknowledgment and continue.

## Pick a mode

Check in order:

1. **MCP tools visible** (tool names starting with `mcp__dalfox__` or `scan_with_dalfox` in the available tool list) → use MCP. It's asynchronous, supports concurrent scans, and returns structured results.
2. **`dalfox` binary on PATH** (`command -v dalfox`) → use the CLI.
3. **Neither** → tell the user how to install (`brew install dalfox`, `cargo install --path .`, or `nix run github:hahwul/dalfox`). Do not synthesize output.

When both exist, prefer MCP — it decouples "start scan" from "read results" and the user can poll without blocking.

## MCP usage

Six tools, intended pattern: `preflight` → `scan` → poll `get_results` → `delete` when done.

### Start a scan (non-blocking)

Call `scan_with_dalfox` with:

- `target` (required) — full URL with scheme, e.g. `https://example.com/search?q=test`
- `param` — restrict testing to listed names; accepts location hints like `q:query`, `user:body`, `auth:header`, `sid:cookie`
- `method`, `data`, `headers` (`"Name: Value"`), `cookies` (`"name=value"`), `user_agent`, `proxy`
- `encoders` — default `["url","html"]`; use `["none"]` to send payloads raw
- `timeout` (1–299s), `delay` (0–9999ms), `workers` — out-of-range values are rejected
- `deep_scan: true` for thorough testing, `skip_mining: true` + `skip_discovery: true` for fast sanity checks
- `blind_callback_url` for blind-XSS (Burp Collaborator, interact.sh)
- `include_request: true` / `include_response: true` only when you need forensic evidence — responses can be large

Returns `{scan_id, target, status: "queued"}`. Store the `scan_id`.

### Poll results

Call `get_results_dalfox` with `{scan_id}`. Also accepts `offset` / `limit` — use for results lists >50 items. The response includes a `progress` block with `suggested_poll_interval_ms`; honor it (~1–3s early, 1s near completion, 0 when done). Status goes through `queued → running → done | error | cancelled`.

### Other tools

- `preflight_dalfox` — synchronous. Counts discovered parameters and estimates total requests without sending payloads. Use this first when the user is worried about scan impact.
- `list_scans_dalfox` — all tracked scans; filter by `status`.
- `cancel_scan_dalfox` — signals the running task to stop at the next checkpoint. Partial results are preserved.
- `delete_scan_dalfox` — removes a terminal scan from memory. Rejects running jobs — cancel first.

Terminal jobs auto-purge after 1 hour, so short-lived workflows don't need to call delete.

## CLI usage

`dalfox` reads a target and prints findings. The minimal invocation:

```bash
dalfox scan https://example.com/search?q=test
```

The `scan` subcommand is the default — `dalfox https://example.com/?q=1` works too. Other modes: `dalfox server` (REST API), `dalfox mcp` (stdio MCP), `dalfox payload list` (browse payloads).

### Common scenarios

| Goal | Command |
|---|---|
| Single URL, default coverage | `dalfox scan https://target/?q=1` |
| POST body | `dalfox scan https://target/api -X POST -d 'user=a&pass=b'` |
| Authenticated | `dalfox scan https://target/ -H 'Authorization: Bearer xxx' --cookies 'sid=abc'` |
| Through a proxy (Burp) | `dalfox scan https://target/ --proxy http://127.0.0.1:8080` |
| Specific params only | `dalfox scan https://target/?q=1 -p q -p page` |
| Blind XSS | `dalfox scan https://target/ --blind-callback-url https://xyz.interact.sh` |
| Stored XSS (reflected on a different URL) | `dalfox scan https://target/submit --sxss --sxss-url https://target/view` |
| File of URLs | `dalfox scan targets.txt` (auto-detects, or `-i file`) |
| Pipe from stdin | `cat urls.txt \| dalfox scan -i pipe` |
| Fast smoke test (only the param you named) | `dalfox scan https://target/?q=1 -p q --skip-mining --skip-discovery` |
| Fast smoke test (keep discovery, skip slow mining) | `dalfox scan https://target/?q=1 --skip-mining` |
| Maximum coverage | `dalfox scan https://target/?q=1 --deep-scan --waf-bypass force` |
| Machine-readable | `dalfox scan ... --format json -o result.json` (`jsonl`, `sarif`, `toml` also supported) |
| Preflight only | `dalfox scan https://target/?q=1 --dry-run` |
| Ignore noisy status codes | `dalfox scan https://target/ --ignore-return 302,403,404` |

### Useful flags

- `--timeout 10` (default), `--delay 0` — add delay for rate-limited targets
- `--workers 50` (default) — lower for politeness, higher for speed; no short alias
- `--silence` / `-S` suppresses banner and noisy progress
- `--include-request` / `--include-response` — embed raw HTTP in JSON output (large); `--include-all` is the shortcut for both
- `--limit N` caps total findings; pair with `--limit-result-type v` to only count verified findings
- `--waf-bypass auto | force | off` — `auto` probes first then bypasses, `force` applies bypass without probing (pair with `--force-waf cloudflare` etc. to pin a WAF), `off` disables the feature
- `--sxss-retries 3` — how many times to poll the sxss-url (default 3); raise for slow-propagating apps
- `--cookie-from-raw raw_request.http` — lift cookies from a captured request file
- `--ignore-return 302,403,404` — drop responses with these status codes before reflection analysis (comma-separated)

Run `dalfox scan --help` for the full list.

## Reading results

Every finding includes:

- **type**: `V` (verified DOM execution — highest confidence), `A` (AST-detected in inline JS), `R` (reflected but execution not confirmed)
- `param`, `payload`, `evidence`
- `inject_type` — the *reflection context*, not the parameter location. Values: `inHTML`, `inJS`, `inATTR`, `inURL`, `inCSS`. For the parameter location (query / body / header / cookie / path / JSON) look at `data` (the probe URL) and `method`.
- `cwe` (usually `CWE-79`), `severity` — `High` for V and DOM-verified A, `Medium` for in-JS reflections, `Info` for plain R
- `message_id`, `message_str` — stable numeric id and human summary
- `data` — the URL actually probed (payload appears URL-encoded when injected in the query string)

When presenting to the user, lead with V findings, then A, then R. Group by parameter when there are many. Raw `payload` and `evidence` are already sanitized for display but still contain attack strings — surround with backticks in markdown.

## Speed vs. coverage

Default settings test a reasonable payload budget (~hundreds of requests per parameter). For big scans:

- Preflight first (`--dry-run` or `preflight_dalfox`) to see `estimated_total_requests`.
- `--skip-mining` drops DOM / dictionary / GF-pattern param discovery. Usually the biggest request saving. Query params in the URL and HTML form fields are still discovered.
- `--skip-discovery` turns off **all** discovery. Only parameters passed via `-p` are tested — do **not** pair this with an unparameterized URL or the scan will report zero targets.
- `--deep-scan` roughly 3–5× cost. Use sparingly.

## Failure modes to recognize

- **`reachable: false` in preflight** → target down, DNS issue, or WAF 403 at the front door. Try with `--proxy`, check with `curl` first.
- **All findings type R, none V** → reflection detected but DOM didn't confirm. Common on JSON APIs (no HTML to parse) — expected, not a bug.
- **Scan stuck in `running`** for many minutes → large parameter mining on a slow target. Either let it finish or `cancel_scan_dalfox` and re-run with `--skip-mining`.
- **MCP returns `invalid_params` for timeout/delay** → value out of bounds (1–299s / 0–9999ms). Dalfox rejects rather than silently clamping.

## Not for

- Non-XSS vulnerabilities (SQLi, SSRF, path traversal, auth bypass). Dalfox only tests for XSS.
- Unauthenticated recon on targets the user hasn't confirmed they own / are permitted to test.
- Replacing a manual code review for DOM-XSS hunting — the AST-detected findings still need a human to confirm.
