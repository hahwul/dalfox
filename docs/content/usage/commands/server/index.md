+++
title = "Server"
description = "Run Dalfox as a REST API server"
weight = 2
sort_by = "weight"

[extra]
+++

Run Dalfox as a REST API server for remote orchestration and CI/CD integration.

```bash
dalfox server [OPTIONS]
```

**Quick Start**:
```bash
dalfox server                                    # localhost:6664
dalfox server --host 0.0.0.0 --port 8080       # Custom host/port
dalfox server --api-key mysecretkey             # With auth
```

## Options

**Host** (`-H, --host`): Bind address (default: 127.0.0.1)
**Port** (`-p, --port`): Port number (default: 6664)
**API Key** (`--api-key`): Auth via X-API-KEY header (or DALFOX_API_KEY env)
**Log File** (`--log-file`): Write logs to file

{% alert_warning() %}
Use `--api-key` when binding to `0.0.0.0`
{% end %}

## CORS & JSONP

**Allowed Origins** (`--allowed-origins`): *, exact URLs, or regex patterns
```bash
dalfox server --allowed-origins "http://localhost:3000,https://app.example.com"
dalfox server --allowed-origins "regex:^https?://localhost:\\d+$"
```

**Allow Methods** (`--cors-allow-methods`): Default: GET,POST,OPTIONS,PUT,PATCH,DELETE  
**Allow Headers** (`--cors-allow-headers`): Default: Content-Type,X-API-KEY,Authorization

**JSONP** (`--jsonp`): Enable JSONP support  
**Callback Param** (`--callback-param-name`): Customize callback param (default: callback)

## API Endpoints

**POST /scan**: Submit scan (JSON body)
```bash
curl -X POST http://localhost:6664/scan -H "Content-Type: application/json" -H "X-API-KEY: key" \
  -d '{"url": "https://example.com", "options": {"worker": 50}}'
# Returns: {"code": 200, "msg": "scan_abc123"}
```

**GET /scan**: Submit scan (query params, JSONP-friendly)
```bash
curl "http://localhost:6664/scan?url=https://example.com&worker=50" -H "X-API-KEY: key"
```

**GET /result/:id** or **GET /scan/:id**: Get scan results
```bash
curl http://localhost:6664/result/scan_abc123 -H "X-API-KEY: key"
# Status: queued | running | done | error
```

## Examples

**Production**:
```bash
dalfox server --host 0.0.0.0 --port 443 --api-key secret --allowed-origins "https://app.example.com" --log-file /var/log/dalfox.log
```

**Development**:
```bash
dalfox server --jsonp --allowed-origins "http://localhost:3000"
```

## Client Examples

See full client examples in Python, JavaScript, and bash on [GitHub](https://github.com/hahwul/dalfox).

## Security

{% alert_warning() %}
- Always use `--api-key` in production
- Use HTTPS reverse proxy (nginx, Apache)
- Restrict CORS origins
- Implement rate limiting
{% end %}

## See Also

- [Scan Command](/usage/commands/scan)
- [Examples - API Mode](/usage/examples#rest-api-mode)
- [MCP Command](/usage/commands/mcp)
