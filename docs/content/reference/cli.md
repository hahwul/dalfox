+++
title = "CLI Reference"
description = "Every subcommand and flag Dalfox accepts."
weight = 1
toc = true
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
| `--input-type` | `-i` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |

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
| `--stream-findings` | — | false | Emit each finding the moment it is verified instead of after the end-of-scan summary (plain format only; auto-disabled with `--output`, `--limit`, `--only-poc`) |
| `--poc-type` | — | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` | — | — | Cap total results shown |
| `--limit-result-type` | — | `all` | Which types count toward `--limit`: `all`, `v`, `r`, `a` |
| `--only-poc` | — | — | Comma-separated filter: `v`, `r`, `a` |

### Target shaping

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--param` | `-p` | — | Parameter to analyse; supports `name:location` (locations: `query`, `body`, `json`, `cookie`, `header`) |
| `--data` | `-d` | — | Request body |
| `--headers` | `-H` | — | Extra HTTP header (repeatable) |
| `--cookies` | — | — | Cookie (repeatable) |
| `--method` | `-X` | `GET` | HTTP method override (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` / RFC 10008) |
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
| `--timeout` | — | `10` | Per-request timeout in seconds (network only; does not bound total scan time) |
| `--scan-timeout` | — | `0` | Hard wall-clock cap per target for the scan stage (post-preflight), in seconds. Aborts a target once exceeded; useful when many sequential phases each pay the per-request `--timeout` cost against a partially-hung endpoint. `0` disables. |
| `--delay` | — | `0` | Delay between requests (ms), per worker |
| `--rate-limit` | `-r`, `--rl` | `0` | Cap the **global** outbound request rate in requests/second, shared across every worker and target (`0` = unlimited). Unlike `--delay` (which only spaces one worker), this bounds the total in-flight burst from `workers × concurrent targets` — friendlier to shared-IP / edge WAF thresholds. |
| `--retries` | — | `0` | Retry failed requests on HTTP 5xx and transient transport errors (timeouts, connection resets) up to this many times (`0` = off). HTTP 429 is always retried regardless. |
| `--retry-delay` | — | `1000` | Base delay (ms) for the exponential backoff between `--retries` attempts (doubles each attempt, capped internally). A server `Retry-After` header takes precedence on 429. |
| `--proxy` | — | — | Proxy URL (`http://`, `socks5://`) |
| `--insecure` | — | `true` | Skip TLS/SSL certificate verification (accept self-signed, expired, or hostname-mismatched certs). On by default for scanner use; pass `--insecure=false` to enforce certificate validation. |
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
| `--blind-oob[=servers]` | — | — | Enable OOB/OAST blind XSS via interactsh; optional comma-separated server domains (default: public mesh). Requires the `=` form: `--blind-oob=oast.fun,oast.me` |
| `--blind-oob-secret` | — | — | Auth token for a self-hosted interactsh server (sent as `Authorization` on register/poll/deregister) |
| `--blind-oob-wait` | — | `30` | Seconds to keep polling for OOB callbacks after all payloads are sent (`0` = no extra end-of-scan wait) |
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
| `--sxss-retries` | — | `3` | Retries on the retrieval URL when fetching stored output |
| `--max-payloads-per-param` | — | `0` | Cap payloads tested per parameter (`0` = no cap) |
| `--skip-ast-analysis` | — | false | Skip AST DOM-XSS |
| `--analyze-external-js` | — | false | Fetch same-origin `<script src>` bundles and run AST DOM-XSS analysis on them (preflight, once per target; up to 16 files, 512 KiB each; respects `--include-url`/`--exclude-url`) |
| `--hpp` | — | false | HTTP Parameter Pollution |
| `--detect-outdated-libs` | — | false | Also report outdated / known-vulnerable JS libraries (informational, CWE-1104; 0 extra requests) |

### WAF

| Flag | Default | Description |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto`, `force`, `off` |
| `--skip-waf-probe` | false | Skip active WAF fingerprinting |
| `--force-waf` | — | WAF name when `--waf-bypass force` |
| `--waf-evasion` | false | Adaptive evasion on WAF detection: randomized inter-request jitter + an escalating cooldown on clusters of blocked responses (replaces the old blunt `workers=1`/`delay=3000` preset). The per-WAF pacing hint is applied automatically on detection even without this flag. Pairs well with `--rate-limit`. |
| `--waf-min-confidence` | `0.3` | Drop fingerprints below this confidence (0.0–1.0). The default `0.3` suppresses weak matches like `Server: Google Frontend` (0.15). Set lower to keep weak signals; `1.0` keeps only fingerprints with full confidence. |

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
| `--rate-limit` | `-r`, `--rl` | `0` | Cap the global outbound request rate (requests/sec, `0` = unlimited) |
| `--scan-timeout` | — | `0` | Hard wall-clock cap per target for the scan stage, in seconds |
| `--max-concurrent-scans` | — | `0` | Limit on simultaneous scans (`0` = unlimited) |
| `--max-body-bytes` | — | `0` | Limit response body bytes for analysis (`0` = unlimited) |

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
