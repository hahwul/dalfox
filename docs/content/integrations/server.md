+++
title = "REST API Server"
description = "Run Dalfox as an HTTP service with async job management, CORS, JSONP, and API-key auth."
weight = 1
toc = true
+++

`dalfox server` starts a long-lived HTTP service that queues and runs scans asynchronously. You submit a scan, get back a `scan_id`, and poll or cancel it however you like.

## Starting the server

```bash
dalfox server
# listens on http://127.0.0.1:6664 by default
```

Common options:

```bash
dalfox server \
  --port 6664 \
  --host 0.0.0.0 \
  --api-key "change-me" \
  --log-file /var/log/dalfox.log
```

### Authentication

If `--api-key` is set (or `DALFOX_API_KEY` is exported), every request must include:

```
X-API-KEY: change-me
```

If you don't set an API key, the server accepts unauthenticated requests; bind to `127.0.0.1` in that case.

### CORS

```bash
dalfox server \
  --allowed-origins "https://app.example.com,https://admin.example.com" \
  --cors-allow-methods "GET,POST,OPTIONS,DELETE" \
  --cors-allow-headers "Content-Type,X-API-KEY,Authorization"
```

`*` is accepted as a wildcard. Regex is supported via `regex:^https://.*\.example\.com$`.

### JSONP

For browser clients that can't set custom headers:

```bash
dalfox server --jsonp --callback-param-name callback
# then GET /scan?target=...&callback=myFunction
```

## Endpoints

| Method | Path | What it does |
|--------|------|--------------|
| `POST` | `/scan` | Submit a new scan (JSON body) |
| `GET` | `/scan?target=...` | Submit a new scan (query string) |
| `GET` | `/scan/:id` | Get scan status and results |
| `DELETE` | `/scan/:id` | Cancel a queued or running scan |
| `GET` | `/scans` | List all scans (optional `?status=`) |
| `GET` | `/result/:id` | Alias for `/scan/:id` |
| `POST` | `/preflight` | Discover parameters without sending payloads |
| `GET` | `/health` | Server info + capability list |

### Submit a scan

```bash
curl -X POST http://127.0.0.1:6664/scan \
  -H "X-API-KEY: change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://target.app?q=test",
    "options": {
      "worker": 50,
      "timeout": 10,
      "encoders": ["url", "html"],
      "blind": "https://callback.interact.sh"
    }
  }'
```

The scan target field is `target` (matching the MCP `scan_with_dalfox` tool and the response payload). The legacy field name `url` is still accepted as an alias — for both the JSON body and the `?target=` / `?url=` query string — so existing clients keep working.

Response:

```json
{
  "code": 200,
  "msg": "queued",
  "data": {
    "scan_id": "9f2c…",
    "target": "https://target.app?q=test"
  }
}
```

### Poll status

```bash
curl -H "X-API-KEY: change-me" http://127.0.0.1:6664/scan/9f2c…
```

Response (while running):

```json
{
  "code": 200,
  "msg": "running",
  "data": {
    "target": "https://target.app?q=test",
    "status": "running",
    "results": [],
    "progress": {
      "params_total": 12,
      "params_tested": 5,
      "requests_sent": 234,
      "findings_so_far": 1,
      "estimated_completion_pct": 41,
      "suggested_poll_interval_ms": 3000
    }
  }
}
```

When complete, `status` becomes `done` and `results` is populated.

### List scans

```bash
curl -H "X-API-KEY: change-me" 'http://127.0.0.1:6664/scans?status=running'
```

### Cancel a scan

```bash
curl -X DELETE -H "X-API-KEY: change-me" http://127.0.0.1:6664/scan/9f2c…
```

### Preflight (no attack)

```bash
curl -X POST http://127.0.0.1:6664/preflight \
  -H "X-API-KEY: change-me" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://target.app"}'
```

Response includes `params_discovered`, `estimated_total_requests`, and a list of parameters so you can scope before committing to a real scan.

### Health

```bash
curl http://127.0.0.1:6664/health
```

Returns version, `auth_required`, and the list of supported endpoints. Good for uptime checks.

## ScanOptions reference (request body)

```jsonc
{
  "url": "https://target.app",
  "options": {
    "worker": 50,
    "delay": 0,
    "timeout": 10,
    "rate_limit": 0,
    "scan_timeout": 0,
    "blind": "https://callback.interact.sh",
    "method": "POST",
    "data": "user=test",
    "header": ["Authorization: Bearer token"],
    "user_agent": "Custom",
    "encoders": ["url", "html"],
    "remote_payloads": ["portswigger"],
    "remote_wordlists": ["burp"],
    "include_request": false,
    "include_response": false,
    "callback_url": "https://your-webhook.example/dalfox",
    "param": ["q", "id:query"],
    "proxy": "http://127.0.0.1:8080",
    "insecure": true,
    "follow_redirects": false,
    "skip_mining": false,
    "skip_discovery": false,
    "deep_scan": false,
    "skip_ast_analysis": false,
    "detect_outdated_libs": false
  }
}
```

Fields mirror the CLI flags. See the [CLI reference](../../reference/cli/) for meaning and defaults.
`detect_outdated_libs` is opt-in (default `false`): set it `true` to also report
outdated / known-vulnerable JS libraries as informational `[I]` findings
(CWE-1104, 0 extra requests). The same key works as a `GET /scan` query parameter.
`insecure` defaults to `true` (TLS certificate verification is skipped, matching
the CLI scanner default); send `"insecure": false` (or `?insecure=false` on
`GET /scan`) to enforce certificate validation.

`rate_limit` caps the scan's outbound requests/second (`0` = unlimited, the
default), enforced across all worker tasks. The server-wide `--rate-limit` flag
is an upper bound: a request may ask for a lower rate but cannot exceed or
disable it.

`scan_timeout` is the whole-scan wall-clock budget in seconds (default `0` =
unbounded), distinct from the per-request `timeout`. When the budget is reached
the scan stops, keeps whatever partial findings it gathered, and settles as
`cancelled` with an `error_message` that mentions `scan_timeout` (so you can tell
a timeout apart from a client-issued cancel). The server-wide `--scan-timeout`
flag caps every submitted scan the same way `--rate-limit` does.

### Server flags worth setting

- `--rate-limit <rps>` — cap every scan's outbound request rate (protects targets).
- `--scan-timeout <secs>` — hard wall-clock budget per scan; bounds long or
  `deep_scan` jobs so one target can't pin a worker indefinitely.
- `--max-concurrent-scans <n>` — reject new submissions with `503` once `n`
  scans are queued/running (default `100`, `0` = unlimited). Bounds memory and
  the blocking pool against a flood of submissions.
- `--max-body-bytes <n>` — explicit request-body cap for `POST /scan` and
  `/preflight` (default `1048576` = 1 MiB); oversized bodies get `413`.

## Job lifecycle

```
queued → running → done
                 ↘ error
                 ↘ cancelled
```

Terminal states (`done`, `error`, `cancelled`) are sticky.

A target that can't be connected to (DNS failure, connection refused, TLS
error, timeout) ends as `error` with an `error_message` of
`target unreachable: connection failed (CONNECTION_FAILED)` — not `done` with
zero findings, so you can tell "scanned, nothing found" apart from "never
reached the host." Use `POST /preflight` first if you want to check
reachability without launching a scan. The `url` must start with `http://` or
`https://`; any other scheme is rejected with `400` (same as `/preflight`).

## Running under systemd

```ini
# /etc/systemd/system/dalfox.service
[Unit]
Description=Dalfox scanner service
After=network.target

[Service]
ExecStart=/usr/local/bin/dalfox server --port 6664 --host 127.0.0.1 --log-file /var/log/dalfox.log
Environment=DALFOX_API_KEY=change-me
Restart=on-failure
User=dalfox

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now dalfox
```

## Security notes

- **Bind to localhost** unless you absolutely need remote access.
- **Always set `--api-key`** on a remote bind.
- **Keep the API key out of logs.** Dalfox does not log it, but reverse proxies might.
- **Put it behind TLS** (nginx, Caddy, Traefik) if you expose it over a network.
- **`callback_url` and the scan target are server-side requests.** Dalfox is a
  URL scanner: it dials whatever target you submit, and on completion it POSTs
  the result JSON to `callback_url`. Only `http(s)` schemes are dialed, but the
  *host* is not filtered — loopback, link-local (e.g. cloud metadata at
  `169.254.169.254`), and private addresses are all reachable. On an
  unauthenticated bind this is a server-side request forgery + exfiltration
  primitive for anyone who can submit a scan, so set `--api-key` and restrict
  egress when exposing the API to untrusted callers.
- **`--jsonp` makes `GET` endpoints readable cross-origin** via `<script>`,
  which is not subject to the CORS allow-list. Enable it only when you intend
  that, and pair it with `--api-key`.
- **Bound scan runtime with `--scan-timeout`.** The per-request `timeout` only
  caps a single HTTP request; a scan with many parameters and payloads (or
  `deep_scan`) can still run for a long time. Set `--scan-timeout <secs>` so
  every submitted scan has a hard wall-clock budget and a single slow target
  can't tie up a worker indefinitely.
