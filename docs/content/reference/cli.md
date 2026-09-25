+++
title = "CLI Reference"
description = "Every subcommand and flag Dalfox accepts."
weight = 1
toc = true
+++

Dalfox is organised into five subcommands, plus the built-in `help`. The default (when you just pass a target) is `scan`, but that short form accepts only targets and the global flags below. Any other scan flag needs the explicit subcommand: `dalfox scan <TARGET> --workers 20` works, while `dalfox <TARGET> --workers 20` is rejected as an unexpected argument.

```
dalfox [SUBCOMMAND] [TARGET] [FLAGS]
```

| Subcommand | Purpose |
|------------|---------|
| `scan` | Scan targets for XSS (default when omitted) |
| `server` | Run a REST API server |
| `payload` | List or fetch built-in/remote payloads |
| `mcp` | Run a Model Context Protocol stdio server |
| `completion` | Generate a shell completion script |
| `help` | Print help for any subcommand |

## Global flags

| Flag | Description |
|------|-------------|
| `--config <FILE>` | Path to a config file (TOML or JSON). Overrides default search path. |
| `--debug` | Enable debug logging. |
| `--no-color` | Disable ANSI colour (also honours `NO_COLOR`). |
| `-S`, `--silence` | Silence all logs except PoC output to STDOUT. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

`--config`, `--debug`, `--no-color` and `--silence` are accepted before or after any subcommand (`dalfox --config ./dalfox.toml scan …` and `dalfox scan … --config ./dalfox.toml` are the same).

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success, no findings |
| `1` | Success, findings reported (any tier — combine with `--only-poc v` to gate on `V` only) |
| `2` | Input / config / runtime error |

---

## `dalfox scan`

Scan targets for XSS. Omitting the subcommand also runs a scan, but then only targets and the global flags are accepted (see above).

```bash
dalfox scan [TARGETS]... [FLAGS]
```

### Input

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input-type` | `-i` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `--dedup-urls` | — | `exact` | Target deduplication: `exact` (drop identical URL+method), `signature` (also collapse URLs differing only in parameter *values*), `off` (scan every input line) |
| `--state-file` | — | — | Record completed targets to a file and skip them when the scan is re-run; raw HTTP/HAR request data is fingerprinted so changed captures are scanned again; run-wide credential values from `-H` / `--cookies` / `--cookie-from-raw` are excluded so a refreshed session resumes, while credentials inside a capture still count |

See [Resuming an interrupted scan](../../guide/scanning-modes/#resuming-an-interrupted-scan) for what is skipped and what is retried.

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
| `--stream-findings` | — | false | Emit each finding the moment it is verified instead of after the end-of-scan summary (plain format only; auto-disabled with `--output`, `--limit`, `--only-poc`, `--baseline`) |
| `--poc-type` | — | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` | — | — | Cap total results shown (must be at least `1`; omit for no cap) |
| `--limit-result-type` | — | `all` | Which types count toward `--limit`: `all`, `v`, `r`, `a`, `i` |
| `--only-poc` | — | — | Comma-separated filter: `v` (vulnerable), `r` (reflected), `a` (AST), `i` (informational) |
| `--baseline` | — | — | Diff against a previous Dalfox JSON/JSONL report and report only findings new since it. An ordinary `-f json -o` report is the baseline |
| `--baseline-mode` | — | `filter` | `filter` drops known findings (counts and exit code describe only what is new), `annotate` keeps them and marks each `new` |

See [Baselines](../../guide/output/#baselines-reporting-only-what-is-new) for the fingerprint rules and the CI recipe.

### Target shaping

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--param` | `-p` | — | Parameter to analyse; supports `name:location` (locations: `query`, `body`, `json`, `multipart`, `cookie`, `header`, `graphql`, `xml`) |
| `--data` | `-d` | — | Request body |
| `--headers` | `-H` | — | Extra HTTP header (repeatable) |
| `--cookies` | — | — | Cookie (repeatable) |
| `--method` | `-X` | `GET` | HTTP method override (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` / RFC 10008) |
| `--user-agent` | — | — | Custom User-Agent |
| `--cookie-from-raw` | — | — | Load cookies from a raw HTTP request file. Fatal (exit `2`) if the file cannot be read or carries no `Cookie:` header — continuing would scan logged out and report `0 XSS` |

### Session

Guards against the silent failure where an authenticated session expires
mid-scan, every later request is answered by a login page, and the run reports
zero findings. See [Session monitoring](../../guide/scanning-modes/).

Monitoring turns itself on whenever credentials are present (`--cookies`,
`--cookie-from-raw`, or a `Cookie` / `Authorization` header), and whenever either
`--session-check` flag is given. Otherwise it stays off and costs nothing.

| Flag | Default | Description |
|------|---------|-------------|
| `--session-check` | — | Regex that must keep matching an authenticated response body. Authoritative: when set, the built-in heuristics are not consulted |
| `--session-check-url` | — | Probe this URL (absolute `http(s)://`) instead of the scan target when re-validating (e.g. a cheap `/api/me` endpoint) |
| `--on-session-loss` | `abort` | `abort` stops the affected target, skips the rest of that host, and exits `2` when the run found nothing; `continue` keeps scanning and leaves the exit code alone. Either way the target is reported `incomplete` / `SESSION_LOST`, never `clean` |

### Scope

| Flag | Default | Description |
|------|---------|-------------|
| `--include-url` | — | Regex pattern(s) of URLs to include |
| `--exclude-url` | — | Regex pattern(s) of URLs to exclude |
| `--ignore-param` | — | Parameter name(s) to skip |
| `--out-of-scope` | — | Wildcard domain patterns to skip |
| `--out-of-scope-file` | — | File listing out-of-scope domains. A path that cannot be read is a fatal `FILE_READ_ERROR` — scanning on without the exclusion list would attack every host it named |

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
| `--skip-mining-dom` | — | false | Skip mining parameter names from HTML `id`/`name` attributes (not DOM-XSS detection — see `--skip-ast-analysis`) |

### Network

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | — | `10` | Per-request timeout in seconds, `1`–`3600` (network only; does not bound total scan time) |
| `--scan-timeout` | — | `0` | Hard wall-clock cap per target for the payload-injection (scan) stage, in seconds (max `86400`). Aborts a target once exceeded; useful when many sequential phases each pay the per-request `--timeout` cost against a partially-hung endpoint. Preflight and parameter analysis (discovery + mining) run before this stage and are not covered by it. `0` disables. |
| `--delay` | — | `0` | Delay between requests (ms), per worker; max `60000` |
| `--rate-limit` | `-r`, `--rl` | `0` | Cap the **global** outbound request rate in requests/second, shared across every worker and target (`0` = unlimited). Unlike `--delay` (which only spaces one worker), this bounds the total in-flight burst from `workers × concurrent targets` — friendlier to shared-IP / edge WAF thresholds. Max `100000`. |
| `--retries` | — | `0` | Retry failed requests on HTTP 5xx and transient transport errors (timeouts, connection resets) up to this many times (`0` = off, max `100`). HTTP 429 is always retried regardless. |
| `--retry-delay` | — | `1000` | Base delay (ms) for the exponential backoff between `--retries` attempts (doubles each attempt, capped internally; max `60000`). A server `Retry-After` header takes precedence on 429. |
| `--proxy` | — | — | Proxy URL — `http(s)://` or `socks4/5(h)://` only; an unroutable scheme (e.g. `ftp://`) is rejected up front instead of silently scanning direct |
| `--insecure` | — | `true` | Skip TLS/SSL certificate verification (accept self-signed, expired, or hostname-mismatched certs). On by default for scanner use; pass `--insecure=false` to enforce certificate validation. Applies to the scan target and to an OAST server you named with `--blind-oob=`; the public interactsh mesh is always verified. |
| `--follow-redirects` | `-F` | false | Follow 3xx responses |
| `--ignore-return` | — | — | HTTP status codes to ignore (comma-separated, e.g. `302,403,404`) |

### Engine

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `50` | Concurrent workers per target (`1`–`500`) |
| `--max-concurrent-targets` | `50` | Global concurrent targets (at least `1`) |
| `--max-targets-per-host` | `100` | Per-host cap (at least `1`) |

### XSS scanning

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--encoders` | `-e` | `url,html` | Comma-separated encoders: `none`, `url`, `2url`, `3url`, `4url`, `html`, `htmlpad`, `base64`, `unicode`, `zwsp` |
| `--remote-payloads` | — | — | `portswigger`, `payloadbox` |
| `--custom-blind-xss-payload` | — | — | Custom blind payload template file |
| `--blind` | `-b` | — | Blind XSS callback URL |
| `--blind-oob[=servers]` | — | — | Enable OOB/OAST blind XSS via interactsh; optional comma-separated server domains (default: public mesh). Requires the `=` form: `--blind-oob=oast.fun,oast.me` |
| `--blind-oob-secret` | — | — | Auth token for a self-hosted interactsh server (sent as `Authorization` on register/poll/deregister) |
| `--blind-oob-wait` | — | `30` | Seconds to keep polling for OOB callbacks after all payloads are sent (`0` = no extra end-of-scan wait) |
| `--custom-payload` | — | — | Custom payload file |
| `--only-custom-payload` | — | false | Use only custom payloads. Requires `--custom-payload` (exit `2` without it) |
| `--custom-alert-value` | — | `1` | Value inside `alert()`/`prompt()`/`confirm()` |
| `--custom-alert-type` | — | `none` | `none` or `str` |
| `--inject-marker` | — | — | Replace this token with payloads (e.g. `FUZZ`) |
| `--skip-xss-scanning` | — | false | Skip payload injection |
| `--deep-scan` | — | false | Keep testing after first finding |
| `--sxss` | — | false | Enable Stored XSS mode |
| `--sxss-url` | — | — | Retrieval URL for SXSS (absolute `http(s)://`); only used with `--sxss`. When omitted, `--sxss` auto-detects the retrieval page from form discovery |
| `--sxss-method` | — | `GET` | Retrieval method |
| `--sxss-retries` | — | `3` | Retries on the retrieval URL when fetching stored output (max `20`; each retry waits 500 ms × attempt, capped at 5 s) |
| `--max-payloads-per-param` | — | `0` | Cap payloads tested per parameter (`0` applies a built-in safety cap of 3000 per set unless `--deep-scan` is set) |
| `--skip-ast-analysis` | — | false | Skip AST DOM-XSS — the source→sink pass that emits `[A]` findings (not `--skip-mining-dom`) |
| `--analyze-external-js` | — | false | Fetch same-origin `<script src>` bundles and run AST DOM-XSS analysis on them (preflight, once per target; up to 16 files, 512 KiB each; respects `--include-url`/`--exclude-url`) |
| `--hpp` | — | false | HTTP Parameter Pollution |
| `--detect-outdated-libs` | — | false | Also report outdated / known-vulnerable JS libraries (informational, CWE-1104; 0 extra requests) |

### WAF

| Flag | Default | Description |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto`, `force`, `off` |
| `--skip-waf-probe` | false | Skip active WAF fingerprinting |
| `--force-waf` | — | WAF name when `--waf-bypass force`: `cloudflare`, `aws`, `akamai`, `imperva`, `modsecurity`, `owasp-crs`, `sucuri`, `f5`, `barracuda`, `fortiweb`, `azure`, `cloudarmor`, `fastly`, `wordfence`, `citrix` (case-insensitive; aliases such as `cf`, `modsec`, `incapsula`, `netscaler` also work) |
| `--waf-evasion` | false | Adaptive evasion on WAF detection: randomized inter-request jitter + an escalating cooldown on clusters of blocked responses. The per-WAF pacing hint is applied automatically on detection even without this flag. Pairs well with `--rate-limit`. |
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
| `--api-key` | — | — | Required `X-API-KEY` header value (or `DALFOX_API_KEY`; the flag wins over the variable). An empty `--api-key ""` disables auth |
| `--log-file` | — | — | Plain-text log file (created mode `0600` on Unix; the server warns at startup if an existing file is group/other-readable) |
| `--allowed-origins` | — | — | CORS origins (comma-separated, supports `*` and `regex:`) |
| `--jsonp` | — | false | Wrap responses in JSONP |
| `--callback-param-name` | — | `callback` | JSONP callback param |
| `--cors-allow-methods` | — | `GET,POST,OPTIONS,PUT,PATCH,DELETE` | CORS methods |
| `--cors-allow-headers` | — | `Content-Type,X-API-KEY,Authorization` | CORS headers |
| `--rate-limit` | — | `0` | Server-wide cap on **each** scan's outbound request rate (requests/sec, `0` = unlimited). A submitted scan may ask for less, never more |
| `--scan-timeout` | — | `0` | Server-wide cap on **each** scan's total wall-clock runtime, in seconds (`0` = unbounded). A submitted scan may ask for less, never more |
| `--max-concurrent-scans` | — | `100` | Limit on simultaneous (queued + running) scans; further submissions get `503` (`0` = unlimited) |
| `--allowed-hosts` | — | — | Extra hostnames accepted in the request `Host` header, on top of the bind host, `localhost`, and any IP literal. Needed behind a reverse proxy that forwards a public hostname |
| `--max-retained-scans` | — | `1000` | Cap on *finished* scans kept in memory; the oldest are dropped once exceeded (`0` = unlimited). Queued and running scans are never dropped |
| `--max-body-bytes` | — | `1048576` | Maximum accepted request body size (bytes) for `POST /scan` and `/preflight`; oversized bodies get `413` |

See [REST API Server](../../integrations/server/) for endpoints.

---

## `dalfox payload`

List or fetch payload collections.

```bash
dalfox payload [SELECTOR] [--json]
```

Use `--json` to print the selected payloads as a JSON array instead of one item per line. Without a selector, Dalfox prints a summary (usage examples and per-selector counts), as JSON under `--json`. An unknown selector exits `2` and suggests the closest match.

Selectors:

| Selector | What it prints |
|----------|----------------|
| `javascript` | Canonical JavaScript execution payloads for JS-string / script contexts (`alert(1)`, backtick and keyword-split variants, ...) |
| `event-handlers` | DOM event handler attribute names |
| `useful-tags` | Useful HTML tags |
| `uri-scheme` | `javascript:`/`data:` URL payloads |
| `special-chars` | Special characters (and encoded variants) for context probing |
| `functions` | Confirmable sinks with filter-surviving variants (`alert`, `prompt`, ...) |
| `awesome-alert` | Polished alert PoCs for screenshots (`alert(document.domain)`, ...) |
| `dom-clobbering` | DOM clobbering vectors |
| `mxss` | Mutation-XSS / sanitizer-bypass payloads |
| `blind` | Blind-XSS skeletons (`{}` = your OOB callback URL) |
| `portswigger` | Remote: PortSwigger XSS cheatsheet |
| `payloadbox` | Remote: PayloadBox XSS list |
| `all` | Every local selector above in one pass, each under a `# name` header (no network fetch) |

---

## `dalfox mcp`

Run the MCP stdio server.

```bash
dalfox mcp
```

No additional flags. See [MCP Server](../../integrations/mcp/) for tool definitions.

---

## `dalfox completion`

Generate a shell completion script and print it to stdout.

```bash
dalfox completion <SHELL>
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

```bash
# bash
dalfox completion bash > /etc/bash_completion.d/dalfox

# zsh
dalfox completion zsh > "${fpath[1]}/_dalfox"

# fish
dalfox completion fish > ~/.config/fish/completions/dalfox.fish
```

Nothing else is written to stdout, so the output can always be safely redirected to a file.

The deprecated `url` / `file` / `pipe` compat commands and the packaging helper `man` are hidden from `--help`, and the generated scripts leave them out too.

---

## See also

- [Config File reference](../config/)
- [Environment variables](../environment/)
