# CLI Reference (dalfox scan)

All flags are defined in `src/cmd/scan.rs:ScanArgs`. Defaults are centralized in the same file (`DEFAULT_*` constants).

## Input

| Flag | Default | Notes |
|------|---------|-------|
| `-i, --input-type` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `TARGET` (positional) | — | URL, file path, raw HTTP (`-i raw-http`), or HAR file (`-i har` / auto-detected) |

**`raw-http`** is powerful: you can feed a complete captured request (from Burp "Copy to file" or `curl -v` output) and dalfox will parse method, path, headers, cookies, and body.

**`har`** scans a whole HAR / proxy export at once: every `log.entries[].request` becomes a target with its URL, method, headers, cookies, and body preserved (deduplicated by URL+method). Auto-detected from file content, or force it with `-i har`; HAR can also be piped on stdin.

## Output & POC

| Flag | Default | Notes |
|------|---------|-------|
| `-f, --format` | `plain` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `-o, --output` | (stdout) | Write to file |
| `--poc-type` | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--include-request` | false | Opt-in only |
| `--include-response` | false | Opt-in only |
| `--include-all` | — | Sets both of the above |
| `--stream-findings` | false | Emit each verified finding immediately |
| `--limit N` | unlimited | Cap displayed findings |
| `--limit-result-type` | `all` | `all`, `v`, `r`, `a` (case-insensitive) |
| `--only-poc "v,r"` | all types | Comma-separated filter for which types to show |
| `-S, --silence` | false | Suppress everything except POC lines |
| `--no-color` | (auto) | Also respects `NO_COLOR` env var |

**Machine-readable formats** auto-silence the banner.

## Target & Scope Control (very useful, often under-used)

| Flag | Purpose |
|------|---------|
| `-p, --param` | Restrict to specific params (supports `name:location` hints) |
| `--include-url` | Regex whitelist (multiple) |
| `--exclude-url` | Regex blacklist (multiple) |
| `--ignore-param` | Skip these parameter names entirely |
| `--out-of-scope` | Wildcard domain patterns (e.g. `*.dev.example.com`) |
| `--out-of-scope-file` | File containing one pattern per line |

## Discovery & Mining

| Flag | Effect |
|------|--------|
| `--only-discovery` | Stop after parameter discovery (no XSS payloads) |
| `--skip-discovery` | Turn off HTML form / link / JS discovery completely |
| `--skip-mining` | Skip DOM mining + dictionary mining (biggest single win for speed) |
| `--skip-mining-dom` | Skip only DOM-based mining |
| `--skip-mining-dict` | Skip only wordlist/dictionary mining |
| `-W, --mining-dict-word` | Path to custom wordlist for dictionary mining |
| `--remote-wordlists` | `burp,assetnote` (comma-separated) |

**Common fast-mode combo**: `--skip-mining` (or `--skip-mining-dom`) + explicit `-p` params you care about.

## Network & Concurrency

| Flag | Default | Notes |
|------|---------|-------|
| `--timeout` | 10s | Per-request |
| `--scan-timeout` | 0 (disabled) | Hard wall-clock cap **per target** after preflight |
| `--delay` | 0 ms | |
| `-F, --follow-redirects` | false | |
| `--proxy` | — | `http://...` or `socks5://...` |
| `--ignore-return` | (none) | Comma-separated status codes to drop before analysis (e.g. `302,403,404`) |
| `--workers` | 50 | Concurrent workers |
| `--max-concurrent-targets` | 50 | For file/pipe input |
| `--max-targets-per-host` | 100 | Safety cap per host |

## XSS Engine

| Flag | Default | Notes |
|------|---------|-------|
| `-e, --encoders` | `url,html` | `none,url,2url,3url,4url,html,base64` (comma-separated) |
| `--remote-payloads` | (none) | `portswigger,payloadbox` |
| `--custom-payload` | — | File of extra payloads |
| `--only-custom-payload` | false | Ignore built-in set |
| `--custom-blind-xss-payload` | — | File for blind XSS |
| `-b, --blind` | — | Callback URL (interact.sh, Burp Collab, etc.) |
| `--custom-alert-value` | `1` | Value used inside `alert(...)` etc. |
| `--custom-alert-type` | `none` | `none` or `str` (wraps in quotes) |
| `--inject-marker` | — | Replace this literal string with payloads |
| `--deep-scan` | false | Keep testing even after first finding |
| `--max-payloads-per-param` | 0 (unlimited) | Hard cap on payloads per parameter |
| `--skip-xss-scanning` | false | Discovery only (different from `--only-discovery`) |
| `--skip-ast-analysis` | false | Disable oxc-based DOM XSS detection |
| `--hpp` | false | HTTP Parameter Pollution (duplicate query params) |

## Stored XSS (SXSS)

| Flag | Notes |
|------|-------|
| `--sxss` | Enable stored XSS mode |
| `--sxss-url` | Where to look for the stored reflection (auto-detect if omitted) |
| `--sxss-method` | GET/POST for the check |
| `--sxss-retries` | 3 (increase for slow propagation) |

## WAF

| Flag | Default | Notes |
|------|---------|-------|
| `--waf-bypass` | `auto` | `auto` (probe then bypass), `force`, `off` |
| `--force-waf` | — | Pin a specific engine (`cloudflare`, `akamai`, `modsecurity`, `aws`, ...) |
| `--skip-waf-probe` | false | Skip the active provocation request |
| `--waf-evasion` | false | Auto-throttle (workers=1, delay=3000 ms) when WAF detected |
| `--waf-min-confidence` | 0.3 | Discard weak fingerprints (Google Frontend, generic "blocked" messages) |

See `references/advanced.md` for recommended WAF combinations.

## Other Useful / Diagnostic

- `--cookie-from-raw request.txt` — lift cookies from a captured raw request file (CLI only)
- `--dry-run` — preflight summary only (same as MCP `preflight_dalfox`)
- `--debug` — show DBG lines
- Global root flags: `--config`, `--debug`, `--no-color`, `--silence`

## Exit Codes

See `references/results.md`.

## Common High-Value Combinations

**Fast smoke test on one param**:
```bash
dalfox scan https://target/?q=1 -p q --skip-mining --skip-discovery
```

**Polite authenticated scan through Burp**:
```bash
dalfox scan https://target/ -H 'Authorization: Bearer ...' \
  --cookies 'sid=...' --proxy http://127.0.0.1:8080 \
  --delay 300 --workers 5
```

**WAF-heavy target (Cloudflare)**:
```bash
dalfox scan https://target/ --waf-bypass force --force-waf cloudflare --waf-evasion
```

**Maximum coverage (expensive)**:
```bash
dalfox scan targets.txt --deep-scan --remote-payloads portswigger,payloadbox -e url,html,base64
```

**Raw captured request**:
```bash
dalfox scan -i raw-http captured-request.txt --blind https://your.interact.sh
```
