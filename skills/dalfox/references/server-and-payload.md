# Server Mode & Payload Subcommand

## dalfox server

Runs an async HTTP API (axum) that exposes the same scanning engine.

### Key Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-p, --port` | 6664 | Listen port |
| `-H, --host` | 127.0.0.1 | Bind address (use 0.0.0.0 carefully) |
| `--api-key` | (none) | Required value for `X-API-KEY` header (or `DALFOX_API_KEY` env) |
| `--log-file` | (none) | Plain-text log file (no ANSI) |
| `--allowed-origins` | (none) | Comma-separated. Supports `*`, exact origins, `regex:<pattern>` |
| `--jsonp` | false | Enable JSONP (wraps responses in callback function) |
| `--callback-param-name` | `callback` | JSONP callback query parameter |
| `--cors-allow-methods` | GET,POST,... | |
| `--cors-allow-headers` | Content-Type,X-API-KEY,... | |

### Endpoints (axum paths)

- `POST /scan` — submit scan (body = scan options)
- `GET /scan` — submit via query params (JSONP friendly)
- `GET /scan/{id}` — status + results
- `DELETE /scan/{id}` — cancel
- `GET /scans` — list jobs (supports `?status=running`)
- `GET /result/{id}` — alias of `/scan/{id}`
- `POST /preflight` — discovery only
- `GET /health` — liveness

Jobs are in-memory only. Same `queued / running / done / error / cancelled` lifecycle as MCP.

`POST`/`GET /scan` require an `http(s)` `url` (other schemes → `400`, like `/preflight`). An unreachable target ends as `error` (message contains `CONNECTION_FAILED`), not `done` with zero findings. `GET /scan` numeric query params (`worker`/`delay`/`timeout`) that are present but unparseable → `400` rather than silently using the default. `progress.params_tested` advances live during the scan.

**Webhook/SSRF**: `callback_url` (and the scan target itself) are dialed server-side with no host filtering — loopback/link-local/private hosts are reachable. Set `--api-key` and restrict egress on untrusted binds. `--jsonp` exposes GET endpoints cross-origin (bypasses the CORS allow-list); enable deliberately.

**Authentication**: when `--api-key` is set, every mutating endpoint requires the key. Read endpoints can be open or also protected depending on deployment choice.

**JSONP**: only works for GET endpoints and requires the callback parameter. The server is strict about the callback name to avoid XSS in the JSONP wrapper itself.

Use the server when:
- You want a long-lived scan service for a team / pipeline
- You need JSONP because the caller is a browser
- You prefer REST over stdio MCP

Prefer MCP tools when you are an agent that can speak JSON-RPC over stdio.

## dalfox payload <selector>

Lightweight enumeration / remote fetch command. No scanning.

Supported selectors:

| Selector | What it does |
|----------|--------------|
| (no arg) | Prints short help + summary of built-in JS payload count |
| `event-handlers` | All common DOM event handler attribute names (`onclick`, `onload`, `onerror`, ...) |
| `useful-tags` | HTML tags frequently useful for XSS (`script`, `img`, `svg`, `iframe`, `object`, ...) |
| `payloadbox` | Fetches current remote XSS payloads from PayloadBox provider (requires network) |
| `portswigger` | Fetches current remote XSS payloads from PortSwigger cheat sheet |
| `uri-scheme` | Scheme-based payloads (`javascript:`, `data:text/html,...`, base64 variants, etc.) |

These are primarily diagnostic / research helpers. The real payload selection and mutation logic lives inside the scanning engine.

Example:
```bash
dalfox payload event-handlers | head -20
dalfox payload portswigger > portswigger.txt
```

You can feed custom lists back into scans with `--custom-payload` or `--custom-blind-xss-payload`.
