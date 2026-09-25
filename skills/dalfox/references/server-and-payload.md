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

`POST`/`GET /scan` require an `http(s)` `target` (`url` is a legacy alias; other schemes → `400`, like `/preflight`). Unknown keys in the body or in `options` → `400`. An unreachable target ends as `error` (message contains `CONNECTION_FAILED`), not `done` with zero findings. `GET /scan` numeric query params (`worker`/`delay`/`timeout`/`rate_limit`/`scan_timeout`/`max_payloads_per_param`) that are present but unparseable → `400` rather than silently using the default. `progress.params_tested` advances live during the scan.

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
