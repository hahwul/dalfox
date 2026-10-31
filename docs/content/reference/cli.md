+++
title = "CLI Reference"
description = "Complete Dalfox CLI reference for scan, server, payload, MCP, completion, hidden compatibility commands, and every flag."
weight = 1
toc = true
+++

Dalfox has five subcommands plus the built-in `help`. If you pass only a target, Dalfox runs `scan`. That short form accepts only targets and the global flags below, so any other scan flag needs the subcommand: `dalfox scan <TARGET> --workers 20` works, while `dalfox <TARGET> --workers 20` is rejected as an unexpected argument. Piping targets into bare `dalfox` works too.

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
| `1` | Success, findings reported (any tier). Add `--only-poc v` to exit `1` only on `V` findings, or `--min-confidence high` to exit `1` only on high-confidence findings |
| `2` | Input / config / runtime error |

`2` also covers a run with no findings that could not finish cleanly (every target skipped, a lost session, a crashed scan worker, heavy request loss); see [Exit codes](../../guide/output/#exit-codes) for the full rule. `server` and `mcp` exit `2` when they fail to start (for example, the port is already in use). `payload` exits `2` for an unknown selector.

---

## `dalfox scan`

Scan targets for XSS. Omitting the subcommand also runs a scan, but then only targets and the global flags are accepted (see above).

```bash
dalfox scan [TARGETS]... [FLAGS]
```

### Input

| Flag | Default | Description |
|------|---------|-------------|
| `-i`, `--input-type` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har`, `openapi` (OpenAPI 3.x / Swagger 2.0, JSON or YAML), `postman` (Postman Collection v2.1) |
| `--base-url` |  | For `openapi` / `postman`: supplies scheme, host and port for every request and is a path prefix; the spec server's path (`/api/v3`, from a relative or absolute server) or each Postman request's path is appended. Must be an absolute `http(s)` URL |
| `--dedup-urls` | `exact` | Target deduplication: `exact` (drop identical URL+method+request content), `signature` (also collapse URLs differing only in parameter *values*), `off` (scan every input line) |
| `--state-file` |  | Record completed targets to a file and skip them when the scan is re-run; raw HTTP/HAR request data is fingerprinted so changed captures are scanned again; run-wide credential values from `-H` / `--cookies` / `--cookie-from-raw` are excluded so a refreshed session resumes, while credentials inside a capture still count |

See [Resuming an interrupted scan](../../guide/scanning-modes/#resuming-an-interrupted-scan) for what is skipped and what is retried.

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-f`, `--format` | `plain` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `-o`, `--output` |  | Write output to file |
| `--include-request` | false | Include HTTP request in output |
| `--include-response` | false | Include response body in output |
| `--include-all` | false | Shorthand for both include flags |
| `--no-color` | false | Disable ANSI colour |
| `-S`, `--silence` | false | Emit only findings to STDOUT |
| `--dry-run` | false | Discover and plan without sending payloads (`-f sarif` and `toml` exit `2` with `INVALID_INPUT_TYPE`; `markdown` prints the plain report) |
| `--stream-findings` | false | Emit each finding the moment it is verified instead of after the end-of-scan summary (plain format only; auto-disabled with `--output`, `--limit`, `--only-poc`, `--baseline`) |
| `--poc-type` | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` |  | Cap total results shown (must be at least `1`; omit for no cap) |
| `--limit-result-type` | `all` | Which types count toward `--limit`: `all`, `v`, `r`, `a`, `i` (case-insensitive) |
| `--only-poc` |  | Comma-separated filter: `v` (vulnerable), `r` (reflected), `a` (AST), `i` (informational), case-insensitive |
| `--baseline` |  | Diff against a previous Dalfox JSON/JSONL report and report only findings new since it. An ordinary `-f json -o` report is the baseline |
| `--baseline-mode` | `filter` | `filter` drops known findings (counts and exit code describe only what is new), `annotate` keeps them and marks each `new` |
| `--min-confidence` | `low` | `high` drops every `low`-confidence finding (every `R`, plus AST flows Dalfox cannot stand behind) before output, `target_summary` counts, `--baseline`, and the exit code. `I` findings carry no grade and are kept. `low` keeps everything |

See [Baselines](../../guide/output/#baselines-reporting-only-what-is-new) for the fingerprint rules and the CI recipe.

### Target shaping

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--param` |  | Parameter to analyse; supports `name:location` (locations: `query`, `body`, `json`, `multipart`, `cookie`, `header`, `graphql`, `xml`, `path`, `fragment`; `path` and `fragment` only filter parameters discovery found) |
| `-d`, `--data` |  | Request body |
| `-H`, `--headers` |  | Extra HTTP header (repeatable) |
| `--cookies` |  | Cookie (repeatable) |
| `-X`, `--method` | `GET` | HTTP method override (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` / RFC 10008) |
| `--user-agent` |  | Custom User-Agent |
| `--cookie-from-raw` |  | Load cookies from a raw HTTP request file; they replace same-named cookies from `--cookies` or an imported request. Fatal (exit `2`) if the file cannot be read or has no `Cookie:` header, because continuing would scan logged out and report `0 XSS` |

### Session

Guards against the silent failure where an authenticated session expires
mid-scan, every later request is answered by a login page, and the run reports
zero findings. See [Session monitoring](../../guide/scanning-modes/#session-monitoring).

Monitoring turns itself on whenever credentials are present (`--cookies`,
`--cookie-from-raw`, or a `Cookie` / `Authorization` header), and whenever either
`--session-check` flag is given. Otherwise it stays off and costs nothing.

| Flag | Default | Description |
|------|---------|-------------|
| `--session-check` |  | Regex that must keep matching an authenticated response body. Authoritative: when set, the built-in heuristics are not consulted |
| `--session-check-url` |  | Probe this URL (absolute `http(s)://`) instead of the scan target when re-validating (e.g. a cheap `/api/me` endpoint) |
| `--on-session-loss` | `abort` | `abort` stops the affected target, skips the rest of that host, and exits `2` when the run found nothing; `continue` keeps scanning and leaves the exit code alone. Either way the target is reported `incomplete` / `SESSION_LOST`, never `clean` |

### Scope

| Flag | Default | Description |
|------|---------|-------------|
| `--include-url` |  | Scan only URLs matching this regex (unanchored). Repeat the flag for more patterns; a URL must match at least one. Also applies to form actions found on a page (discovery and blind-XSS form injection) and to `--analyze-external-js` scripts. An invalid regex is a startup error |
| `--exclude-url` |  | Skip URLs matching this regex (unanchored). Repeat the flag for more patterns. Also applies to form actions found on a page (discovery and blind-XSS form injection) and to `--analyze-external-js` scripts, so `--exclude-url /logout` keeps a logout form from being probed. An invalid regex is a startup error |
| `--ignore-param` |  | Parameter name to skip (exact match). Repeat the flag for more names |
| `--out-of-scope` |  | Skip targets whose host matches this pattern. `*.example.com` matches `example.com` and every subdomain; any other `*` matches any run of characters (`127.0.0.*`, `*.example.*`); a value without `*` must equal the host. Case-insensitive. Repeat the flag for more patterns: `--out-of-scope '*.gov' --out-of-scope cdn.example.com`. A comma is not a separator |
| `--out-of-scope-file` |  | File of out-of-scope patterns, one per line (blank and `#` lines skipped), same matching as `--out-of-scope`. A path that cannot be read is a fatal `FILE_READ_ERROR`, because scanning without the exclusion list would attack every host it names |

### Discovery

| Flag | Default | Description |
|------|---------|-------------|
| `--only-discovery` | false | Stop after discovery, no XSS payloads (no `-f sarif` or `toml`, like `--dry-run`) |
| `--skip-discovery` | false | Skip all discovery |
| `--skip-reflection-header` | false | Skip header-based reflection checks |
| `--skip-reflection-cookie` | false | Skip cookie-based reflection checks |
| `--skip-reflection-path` | false | Skip path-based reflection checks |

### Mining

| Flag | Default | Description |
|------|---------|-------------|
| `-W`, `--mining-dict-word` |  | Parameter wordlist file |
| `--remote-wordlists` |  | Remote sources, comma-separated: `burp`, `assetnote` |
| `--skip-mining` | false | Skip all mining |
| `--skip-mining-dict` | false | Skip dictionary mining |
| `--skip-mining-dom` | false | Skip mining parameter names from HTML `id`/`name` attributes. This does not turn off DOM-XSS detection; use `--skip-ast-analysis` for that |

### Network

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `10` | Per-request timeout in seconds, `1`–`3600` (network only; does not bound total scan time) |
| `--scan-timeout` | `0` | Hard wall-clock cap per target for the payload-injection (scan) stage, in seconds (max `86400`). A target that runs past it is stopped. Useful when a partly hung endpoint makes many phases each wait out `--timeout`. Preflight and parameter analysis (discovery and mining) run before this stage and are not covered. `0` disables it |
| `--delay` | `0` | Delay between requests (ms), per worker; max `60000` |
| `-r`, `--rate-limit` | `0` | Cap the global outbound request rate in requests/second, shared across every worker and target (`0` = unlimited, max `100000`). `--delay` only spaces one worker's requests; this flag bounds the total burst from `workers × concurrent targets`, which suits shared-IP and edge WAF thresholds better. Alias: `--rl` |
| `--retries` | `0` | Retry failed requests on HTTP 5xx and transient transport errors (timeouts, connection resets) up to this many times (`0` = off, max `100`). HTTP 429 is always retried regardless. |
| `--retry-delay` | `1000` | Base delay (ms) for the exponential backoff between `--retries` attempts (doubles each attempt, capped internally; max `60000`). A server `Retry-After` header takes precedence on 429. |
| `--proxy` |  | Proxy URL. Accepted schemes: `http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`. Any other scheme (e.g. `ftp://`) is rejected at startup, because the scan would otherwise skip the proxy without telling you |
| `--insecure` | `true` | Skip TLS/SSL certificate verification (accept self-signed, expired, or hostname-mismatched certs). On by default for scanner use; pass `--insecure=false` to enforce certificate validation. Applies to the scan target and to an OAST server you named with `--blind-oob=`; the public interactsh mesh is always verified. |
| `-F`, `--follow-redirects` | false | Follow 3xx responses |
| `--ignore-return` |  | HTTP status codes to ignore (comma-separated, e.g. `302,403,404`) |

### Engine

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `50` | Concurrent workers per target (`1`–`500`) |
| `--max-concurrent-targets` | `50` | Global concurrent targets (at least `1`) |
| `--max-targets-per-host` | `100` | Per-host cap (at least `1`) |

### XSS scanning

| Flag | Default | Description |
|------|---------|-------------|
| `-e`, `--encoders` | `url,html` | Comma-separated encoders: `none`, `url`, `2url`, `3url`, `4url`, `html`, `htmlpad`, `base64`, `unicode`, `zwsp` |
| `--remote-payloads` |  | Remote payload sources, comma-separated: `portswigger`, `payloadbox` |
| `--custom-blind-xss-payload` |  | Blind payload template file, one template per line. Each line must contain `{callback}`, which is replaced with the `-b` URL or an OOB callback URL; lines without it are skipped with a warning, and if no line is usable the built-in templates are sent instead. Used only with `-b` or `--blind-oob` |
| `-b`, `--blind` |  | Blind XSS callback URL |
| `--blind-oob[=servers]` |  | Enable OOB/OAST blind XSS via interactsh; optional comma-separated server domains (default: public mesh). Requires the `=` form: `--blind-oob=oast.fun,oast.me` |
| `--blind-oob-secret` |  | Auth token for a self-hosted interactsh server (sent as `Authorization` on register/poll/deregister) |
| `--blind-oob-wait` | `30` | Seconds to keep polling for OOB callbacks after all payloads are sent (`0` = no extra end-of-scan wait) |
| `--custom-payload` |  | Custom payload file, one payload per line (blank and `#` lines skipped). Added to the built-in payloads unless `--only-custom-payload` is set |
| `--only-custom-payload` | false | Use only custom payloads. Requires `--custom-payload` (exit `2` without it) |
| `--custom-alert-value` | `1` | Value inside `alert()`/`prompt()`/`confirm()` in the context-matched reflection payloads (DOM-verification and fallback payloads keep `1`) |
| `--custom-alert-type` | `none` | `none` or `str` |
| `--inject-marker` |  | Replace this token with payloads (e.g. `FUZZ`) |
| `--skip-xss-scanning` | false | Skip payload injection |
| `--deep-scan` | false | Keep testing after first finding |
| `--sxss` | false | Enable Stored XSS mode |
| `--sxss-url` |  | Retrieval URL for SXSS (absolute `http(s)://`); only used with `--sxss`. When omitted, `--sxss` auto-detects the retrieval page from form discovery |
| `--sxss-method` | `GET` | Retrieval method |
| `--sxss-retries` | `3` | Retries on the retrieval URL when fetching stored output (max `20`; each retry waits 500 ms × attempt, capped at 5 s) |
| `--max-payloads-per-param` | `0` | Cap base payloads tested per parameter (`0` applies a built-in safety cap of 3000 per set unless `--deep-scan` is set). WAF-bypass variants and a few shared payloads are added after the cap, so the real per-parameter count can be higher |
| `--skip-ast-analysis` | false | Skip AST DOM-XSS analysis, the source→sink pass that emits `[A]` findings. `--skip-mining-dom` does not do this |
| `--analyze-external-js` | false | Fetch same-origin `<script src>` bundles and run AST DOM-XSS analysis on them (preflight, once per target; up to 16 files, 512 KiB each; respects `--include-url`/`--exclude-url`). Per parameter, it also fetches up to 4 scripts whose `src` URL carries the parameter and reads `document.currentScript.src` in them as a source |
| `--hpp` | false | HTTP Parameter Pollution |
| `--detect-outdated-libs` | false | Also report outdated / known-vulnerable JS libraries (informational, CWE-1104; 0 extra requests) |

### WAF

| Flag | Default | Description |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto` applies bypass mutations and extra encoders for the detected WAF. `off` still detects and reports the WAF but changes no payloads. `force` is accepted and currently behaves like `auto`; use `--force-waf` to choose the WAF |
| `--skip-waf-probe` | false | Skip the active provocation probe (passive detection on the preflight response's headers and body still runs) |
| `--force-waf` |  | Treat the target as this WAF, replacing whatever detection found. Works under `auto` and `force`; under `off` the WAF is reported but no bypass is applied. Names: `cloudflare`, `aws`, `akamai`, `imperva`, `modsecurity`, `owasp-crs`, `sucuri`, `f5`, `barracuda`, `fortiweb`, `azure`, `cloudarmor`, `fastly`, `wordfence`, `citrix`, `wallarm`, `naxsi`, `safeline`, `reblaze` (case-insensitive; aliases such as `cf`, `modsec`, `incapsula`, `netscaler`, `chaitin` also work) |
| `--waf-evasion` | false | Adaptive evasion: randomized inter-request jitter (applied whether or not a WAF is detected), an escalating cooldown on clusters of blocked responses, and one-at-a-time payload sending per parameter. The per-WAF pacing hint is applied automatically on detection even without this flag. Pairs well with `--rate-limit`. See [WAF Bypass](../../guide/waf-bypass/#evasion-throttle). |
| `--waf-min-confidence` | `0.3` | Drop fingerprints below this confidence (0.0–1.0). The default `0.3` suppresses weak matches like `Server: Google Frontend` (0.15). Set lower to keep weak signals; `1.0` keeps only fingerprints with full confidence. |

---

## `dalfox server`

Start the REST API server.

```bash
dalfox server [FLAGS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--port` | `6664` | Listen port |
| `-H`, `--host` | `127.0.0.1` | Bind address |
| `--api-key` |  | Required `X-API-KEY` header value (or `DALFOX_API_KEY`; the flag wins over the variable). An empty `--api-key ""` disables auth |
| `--log-file` |  | Plain-text log file (created mode `0600` on Unix; the server warns at startup if an existing file is group/other-readable) |
| `--allowed-origins` |  | CORS origins (comma-separated). Exact origins, `regex:<pattern>`, or `*`. Patterns must match the whole origin, port included. `*` allows every origin and also turns off the cross-site request check |
| `--jsonp` | false | Wrap responses in JSONP |
| `--callback-param-name` | `callback` | JSONP callback param |
| `--cors-allow-methods` | `GET,POST,OPTIONS,PUT,PATCH,DELETE` | CORS methods |
| `--cors-allow-headers` | `Content-Type,X-API-KEY,Authorization` | CORS headers |
| `--rate-limit` |  | Server-wide cap on each scan's outbound request rate (requests/sec; unset or `0` = unlimited). A submitted scan may ask for less, never more |
| `--scan-timeout` |  | Server-wide cap on each scan's total wall-clock runtime, in seconds (unset or `0` = unbounded). A submitted scan may ask for less, never more |
| `--max-concurrent-scans` | `100` | Limit on simultaneous (queued + running) scans; further submissions get `503` (`0` = unlimited) |
| `--allowed-hosts` |  | Comma-separated extra hostnames accepted in the request `Host` header, on top of the bind host, `localhost`, and any IP literal. Needed behind a reverse proxy that forwards a public hostname |
| `--max-retained-scans` | `1000` | Cap on *finished* scans kept in memory; the oldest are dropped once exceeded (`0` = unlimited). Queued and running scans are never dropped |
| `--max-body-bytes` | `1048576` | Maximum accepted request body size (bytes) for `POST /scan` and `/preflight`; an oversized body is rejected with `413` before the handler parses it |

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

No flags beyond the global ones. See [MCP Server](../../integrations/mcp/) for tool definitions.

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

Nothing else goes to stdout, so you can redirect the output straight to a file. The generated scripts leave out the hidden commands below.

---

## Hidden commands

These are left out of `--help` and the completion scripts.

| Command | Equivalent |
|---------|------------|
| `dalfox url <URL> [FLAGS]` (or `-u <URL>`) | `dalfox scan -i url <URL> [FLAGS]` |
| `dalfox file <FILE> [FLAGS]` | `dalfox scan -i file <FILE> [FLAGS]` |
| `dalfox pipe [FLAGS]` | `dalfox scan -i pipe [FLAGS]` (targets from stdin) |
| `dalfox man` | Prints the roff man page to stdout (used for packaging) |

`url`, `file` and `pipe` are kept for v2-era scripts and accept every `dalfox scan` flag. An explicit `-i` still wins, so `dalfox pipe -i har` reads a HAR file from stdin. New scripts should call `dalfox scan`.

---

## See also

- [Config File reference](../config/)
- [Environment variables](../environment/)
