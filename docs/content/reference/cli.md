+++
title = "CLI Reference"
description = "Every subcommand and flag Dalfox accepts."
weight = 1
+++

Dalfox is organised into four subcommands. The default (when you just pass a target) is `scan`.

```
dalfox [SUBCOMMAND] [TARGET] [FLAGS]
```

| Subcommand | Purpose |
|------------|---------|
| `scan` | Scan targets for XSS (default when omitted) |
| `server` | Run a REST API server |
| `payload` | List or fetch built-in/remote payloads |
| `mcp` | Run a Model Context Protocol stdio server |
| `help` | Print help for any subcommand |

## Global flags

| Flag | Description |
|------|-------------|
| `--config <FILE>` | Path to a config file (TOML or JSON). Overrides default search path. |
| `--debug` | Enable debug logging. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success, no findings |
| `1` | Success, findings reported |
| `2` | Input / config / runtime error |

---

## `dalfox scan`

Scan targets for XSS. Omitting the subcommand is equivalent.

```bash
dalfox scan [TARGETS]... [FLAGS]
```

### Input

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input-type` | `-i` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http` |

### Output

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `plain` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `--output` | `-o` | — | Write output to file |
| `--include-request` | — | false | Include HTTP request in output |
| `--include-response` | — | false | Include response body in output |
| `--include-all` | — | false | Shorthand for both include flags |
| `--no-color` | — | false | Disable ANSI colour |
| `--silence` | `-S` | false | Emit only findings to STDOUT |
| `--dry-run` | — | false | Discover and plan without sending payloads |
| `--poc-type` | — | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` | — | — | Cap total results shown |
| `--limit-result-type` | — | `all` | `all`, `v`, `r`, `a` — which types count toward `--limit` |
| `--only-poc` | — | — | Comma-separated filter: `v`, `r`, `a` |

### Target shaping

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--param` | `-p` | — | Parameter to analyse; supports `name:location` (locations: `query`, `body`, `json`, `cookie`, `header`) |
| `--data` | `-d` | — | Request body |
| `--headers` | `-H` | — | Extra HTTP header (repeatable) |
| `--cookies` | — | — | Cookie (repeatable) |
| `--method` | `-X` | `GET` | HTTP method override |
| `--user-agent` | — | — | Custom User-Agent |
| `--cookie-from-raw` | — | — | Load cookies from a raw HTTP request file |

### Scope

| Flag | Default | Description |
|------|---------|-------------|
| `--include-url` | — | Regex pattern(s) of URLs to include |
| `--exclude-url` | — | Regex pattern(s) of URLs to exclude |
| `--ignore-param` | — | Parameter name(s) to skip |
| `--out-of-scope` | — | Wildcard domain patterns to skip |
| `--out-of-scope-file` | — | File listing out-of-scope domains |

### Discovery

| Flag | Default | Description |
|------|---------|-------------|
| `--only-discovery` | false | Stop after discovery, no XSS payloads |
| `--skip-discovery` | false | Skip all discovery |
| `--skip-reflection-header` | false | Skip header-based reflection checks |
| `--skip-reflection-cookie` | false | Skip cookie-based reflection checks |
| `--skip-reflection-path` | false | Skip path-based reflection checks |

### Mining

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--mining-dict-word` | `-W` | — | Parameter wordlist file |
| `--remote-wordlists` | — | — | Remote sources: `burp`, `assetnote` |
| `--skip-mining` | — | false | Skip all mining |
| `--skip-mining-dict` | — | false | Skip dictionary mining |
| `--skip-mining-dom` | — | false | Skip DOM mining |

### Network

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | — | `10` | Request timeout (seconds) |
| `--delay` | — | `0` | Delay between requests (ms) |
| `--proxy` | — | — | Proxy URL (`http://`, `socks5://`) |
| `--follow-redirects` | `-F` | false | Follow 3xx responses |
| `--ignore-return` | — | — | HTTP status codes to ignore |

### Engine

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `50` | Concurrent workers per target |
| `--max-concurrent-targets` | `50` | Global concurrent targets |
| `--max-targets-per-host` | `100` | Per-host cap |

### XSS scanning

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--encoders` | `-e` | `url,html` | Comma-separated encoders |
| `--remote-payloads` | — | — | `portswigger`, `payloadbox` |
| `--custom-blind-xss-payload` | — | — | Custom blind payload template file |
| `--blind` | `-b` | — | Blind XSS callback URL |
| `--custom-payload` | — | — | Custom payload file |
| `--only-custom-payload` | — | false | Use only custom payloads |
| `--custom-alert-value` | — | `1` | Value inside `alert()`/`prompt()`/`confirm()` |
| `--custom-alert-type` | — | `none` | `none` or `str` |
| `--inject-marker` | — | — | Replace this token with payloads (e.g. `FUZZ`) |
| `--skip-xss-scanning` | — | false | Skip payload injection |
| `--deep-scan` | — | false | Keep testing after first finding |
| `--sxss` | — | false | Enable Stored XSS mode |
| `--sxss-url` | — | — | Retrieval URL for SXSS |
| `--sxss-method` | — | `GET` | Retrieval method |
| `--skip-ast-analysis` | — | false | Skip AST DOM-XSS |
| `--hpp` | — | false | HTTP Parameter Pollution |

### WAF

| Flag | Default | Description |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto`, `force`, `off` |
| `--skip-waf-probe` | false | Skip active WAF fingerprinting |
| `--force-waf` | — | WAF name when `--waf-bypass force` |
| `--waf-evasion` | false | Auto-throttle (`workers=1`, `delay=3000`) on WAF detection |

---

## `dalfox server`

Start the REST API server.

```bash
dalfox server [FLAGS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `6664` | Listen port |
| `--host` | `-H` | `127.0.0.1` | Bind address |
| `--api-key` | — | — | Required `X-API-KEY` header value (or `DALFOX_API_KEY`) |
| `--log-file` | — | — | Plain-text log file |
| `--allowed-origins` | — | — | CORS origins (comma-separated, supports `*` and `regex:`) |
| `--jsonp` | — | false | Wrap responses in JSONP |
| `--callback-param-name` | — | `callback` | JSONP callback param |
| `--cors-allow-methods` | — | `GET,POST,OPTIONS,PUT,PATCH,DELETE` | CORS methods |
| `--cors-allow-headers` | — | `Content-Type,X-API-KEY,Authorization` | CORS headers |

See [REST API Server](../../integrations/server/) for endpoints.

---

## `dalfox payload`

List or fetch payload collections.

```bash
dalfox payload <SELECTOR>
```

Selectors:

| Selector | What it prints |
|----------|----------------|
| `event-handlers` | DOM event handler attribute names |
| `useful-tags` | Useful HTML tags |
| `uri-scheme` | `javascript:`/`data:` URL payloads |
| `portswigger` | Remote: PortSwigger XSS cheatsheet |
| `payloadbox` | Remote: PayloadBox XSS list |

---

## `dalfox mcp`

Run the MCP stdio server.

```bash
dalfox mcp
```

No additional flags. See [MCP Server](../../integrations/mcp/) for tool definitions.

---

## See also

- [Config File reference](../config/)
- [Environment variables](../environment/)
