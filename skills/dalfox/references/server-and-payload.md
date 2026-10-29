# Server Mode & Payload Subcommand

## dalfox server

Runs an async HTTP API (axum) that exposes the same scanning engine.

### Key Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-p, --port` | 6664 | Listen port |
| `-H, --host` | 127.0.0.1 | Bind address (use 0.0.0.0 carefully) |
| `--api-key` | (none) | Required value for `X-API-KEY` header (or `DALFOX_API_KEY` env) |
| `--log-file` | (none) | Plain-text log file (no ANSI). Created `0600` on Unix; an existing file keeps its mode and is warned about if group/other-readable |
| `--rate-limit` | 0 (unlimited) | Server-wide ceiling on each scan's req/sec; a request's `rate_limit` may go lower, never higher or off |
| `--scan-timeout` | 0 (unbounded) | Server-wide ceiling on each scan's wall-clock seconds; also bounds `POST /preflight` (`504`) |
| `--max-concurrent-scans` | 100 | Active (queued + running) cap; past it `POST`/`GET /scan` → `503`. `0` = no cap |
| `--max-retained-scans` | 1000 | Finished jobs kept in memory; oldest evicted first. `0` = no cap |
| `--max-body-bytes` | 1048576 | Request-body limit for `POST /scan` and `/preflight` (`413` past it) |
| `--allowed-hosts` | (none) | Extra `Host` header names accepted (DNS-rebinding gate). Set it behind a reverse proxy that forwards a public hostname |
| `--allowed-origins` | (none) | Comma-separated. Supports `*`, exact origins (case-insensitive), `regex:<pattern>`. Patterns match the whole `Origin` (anchored), so a longer host that merely contains one is refused — and a pattern must cover the port. `*` switches the cross-site gate off, like `--jsonp` |
| `--jsonp` | false | Enable JSONP (wraps responses in callback function) |
| `--callback-param-name` | `callback` | JSONP callback query parameter |
| `--cors-allow-methods` | GET,POST,... | |
| `--cors-allow-headers` | Content-Type,X-API-KEY,... | |

### Endpoints (axum paths)

- `POST /scan` — submit scan. Body is `{"target": "https://…", "options": {…}}`; a flat option dict is an unknown field → `400`
- `GET /scan` — submit via query params (JSONP friendly)
- `GET /scan/{id}` — status + results
- `DELETE /scan/{id}` — cancel
- `GET /scans` — list jobs (supports `?status=running`)
- `GET /result/{id}` — alias of `/scan/{id}`
- `POST /preflight` — discovery only
- `GET /health` — liveness

Jobs are in-memory only. Same `queued / running / done / error / cancelled` lifecycle as MCP.

### `options` keys (POST body / GET query)

Same names and validation as MCP `scan_with_dalfox` (see `mcp.md`), with these differences:

| REST key | MCP name (accepted here as an alias) | Note |
|----------|--------------------------------------|------|
| `cookie` | `cookies` | One `Cookie` header string (`"sid=a; lang=en"`) or a list |
| `header` | `headers` | List; on `GET /scan` one `header=` value, split into headers |
| `worker` | `workers` | |
| `blind` | `blind_callback_url` | |
| `callback_url` | — (refused on MCP) | Completion webhook: the result is POSTed here |

No `wait` / `wait_timeout_sec` — poll `GET /scan/{id}`. List values on `GET /scan` are comma-separated (`?param=q,id&encoders=url,html`). `POST /preflight` takes the same `{"target", "options"}` body.

```bash
curl -s -X POST http://127.0.0.1:6664/scan -H 'Content-Type: application/json' -H "X-API-KEY: $KEY" \
  -d '{"target":"https://target/?q=1","options":{"param":["q"],"skip_mining":true,"max_payloads_per_param":20}}'
```

Blind OOB and session-loss detection reach parity with the CLI here: the `options` body (and `GET /scan` query) accept `blind_oob` (`true` / server list — `?blind_oob=true` or `?blind_oob=oast.fun,oast.me`), `blind_oob_wait`, `session_check`, and `session_check_url`. The OOB poller is started and stopped with the job (cancel/delete stop it; it counts against the job caps). A job whose authenticated session dies mid-scan settles `status: "error"` with `error_message` starting `SESSION_LOST:` rather than a false `done` (cancelled/timed out after the loss: stays `cancelled`, `SESSION_LOST:` goes to `warnings`). `--blind-oob-secret` (self-hosted auth) stays CLI/config-only; `--state-file` resume is CLI-only by design (jobs are in-memory). `GET /scan/{id}` adds a `warnings` list (absent when empty) for non-fatal conditions — OOB registration or polling failed, session monitoring inactive, params capped — so a `done` with zero findings is never silently read as clean.

`POST`/`GET /scan` require an `http(s)` `target` (`url` is a legacy alias; other schemes → `400`, like `/preflight`). Unknown keys in the body or in `options` → `400`. An unreachable target ends as `error` (message contains `CONNECTION_FAILED`), not `done` with zero findings. `GET /scan` numeric query params (`worker`/`delay`/`timeout`/`rate_limit`/`scan_timeout`/`max_payloads_per_param`) that are present but unparseable → `400` rather than silently using the default. `progress.params_tested` advances live during the scan.

Body errors: over `--max-body-bytes` → `413`, no JSON `Content-Type` → `415`, malformed JSON or schema errors → `400`. `POST /preflight` is bounded by `--scan-timeout` (`504` on expiry). `DELETE /scan/{id}?purge=1` is `409` while a cancelled scan's worker is still draining. The completion webhook body carries `error_message` (null unless the scan errored, timed out or lost its session) and, when non-empty, the same `warnings` list.

**Webhook/SSRF**: `callback_url` (and the scan target itself) are dialed server-side with no host filtering — loopback/link-local/private hosts are reachable. Set `--api-key` and restrict egress on untrusted binds. `--jsonp` exposes the API cross-origin (bypasses the CORS allow-list); enable deliberately.

**Authentication**: when `--api-key` is set, every endpoint requires it in `X-API-KEY` except `GET /health` and the `OPTIONS` CORS preflights — a browser attaches no key to a preflight. Reads (`GET /scan/{id}`, `/scans`) are included. `/health` and the preflights stay key-free but are still subject to the cross-site/`Host` gate. There is no per-caller identity: any caller holding the key can read or cancel any scan. Nothing rate-limits a wrong key, so use at least 24 random characters (the server warns below that).

**JSONP**: with `--jsonp`, every endpoint wraps its response when the callback query parameter is present (in practice a browser `<script>` can only issue GETs). The callback name is strict — 1–64 chars, first `[A-Za-z_$]`, then `[A-Za-z0-9_$.]`; anything else gets plain JSON. Every response with a body carries `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` (the bodyless `OPTIONS` 204s do not).

Use the server when:
- You want a long-lived scan service for a team / pipeline
- You need JSONP because the caller is a browser
- You prefer REST over stdio MCP

Prefer MCP tools when you are an agent that can speak JSON-RPC over stdio.

## dalfox payload <selector> [--json]

Pass `--json` to emit the selected payloads as a JSON array instead of one item per line.

Lightweight enumeration / remote fetch command. No scanning.

Supported selectors:

| Selector | What it does |
|----------|--------------|
| (no arg) | Prints usage + per-selector payload counts (`--json`: `{selectors, counts}`) |
| `javascript` | Canonical JS execution payloads for JS-string / script contexts |
| `event-handlers` | All common DOM event handler attribute names (`onclick`, `onload`, `onerror`, ...) |
| `useful-tags` | HTML tags frequently useful for XSS (`script`, `img`, `svg`, `iframe`, `object`, ...) |
| `special-chars` | Special characters + encoded variants for context probing / breakout (`<`, `>`, `"`, `&lt;`, `%3C`, ...) |
| `functions` | Confirmable sinks with filter-surviving variants (`alert(1)`, `window['alert'](1)`, `setTimeout('alert(1)')`, ...) |
| `awesome-alert` | Polished alert PoCs for clean screenshots (`alert(document.domain)`, `alert(document.cookie)`, ...) |
| `dom-clobbering` | DOM clobbering vectors |
| `mxss` | Mutation-XSS / sanitizer-bypass payloads |
| `blind` | Blind-XSS skeletons (`{}` = your OOB callback URL; change it to `{callback}` before feeding them to `--custom-blind-xss-payload`) |
| `payloadbox` | Fetches current remote XSS payloads from PayloadBox provider (requires network) |
| `portswigger` | Fetches current remote XSS payloads from PortSwigger cheat sheet |
| `uri-scheme` | Scheme-based payloads (`javascript:`, `data:text/html,...`, base64 variants, etc.) |
| `all` | Every local selector above, each under a `# name` header (no network fetch) |

These are primarily diagnostic / research helpers. The real payload selection and mutation logic lives inside the scanning engine.

Example:
```bash
dalfox payload event-handlers | head -20
dalfox payload portswigger > portswigger.txt
```

You can feed custom lists back into scans with `--custom-payload` or `--custom-blind-xss-payload` (every blind line must contain `{callback}`; lines without it are skipped with a warning).
