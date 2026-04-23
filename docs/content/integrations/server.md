+++
title = "REST API Server"
description = "Run Dalfox as an HTTP service with async job management, CORS, JSONP, and API-key auth."
weight = 1
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

If you don't set an API key, the server accepts unauthenticated requests — bind to `127.0.0.1` in that case.

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
# then GET /scan?url=...&callback=myFunction
```

## Endpoints

| Method | Path | What it does |
|--------|------|--------------|
| `POST` | `/scan` | Submit a new scan (JSON body) |
| `GET` | `/scan?url=...` | Submit a new scan (query string) |
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
    "url": "https://target.app?q=test",
    "options": {
      "worker": 50,
      "timeout": 10,
      "encoders": ["url", "html"],
      "blind": "https://callback.interact.sh"
    }
  }'
```

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
    "follow_redirects": false,
    "skip_mining": false,
    "skip_discovery": false,
    "deep_scan": false,
    "skip_ast_analysis": false
  }
}
```

Fields mirror the CLI flags. See the [CLI reference](../../reference/cli/) for meaning and defaults.

## Job lifecycle

```
queued → running → done
                 ↘ error
                 ↘ cancelled
```

Terminal states (`done`, `error`, `cancelled`) are sticky.

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
