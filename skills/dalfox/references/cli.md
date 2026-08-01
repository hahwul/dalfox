# CLI Reference (dalfox scan)

All flags are defined in `src/cmd/scan/args.rs:ScanArgs`. Defaults are centralized in the same file (`DEFAULT_*` constants).

## Input

| Flag | Default | Notes |
|------|---------|-------|
| `-i, --input-type` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `--dedup-urls` | `exact` | `exact` (drop identical URL+method), `signature` (also collapse URLs differing only in parameter *values* — keys on method+host+path+param names), `off` (no dedup). Use `signature` for `gau`/`katana` dumps; not value-safe when an `action=`-style value picks the handler. Collapsed count is logged and lands in `meta.dedup_mode` / `meta.targets_deduplicated`. |
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
| `--stream-findings` | false | Emit each finding immediately (plain only; see the caveat in `results.md`) |
| `--limit N` | unlimited | Cap displayed findings |
| `--limit-result-type` | `all` | Which type counts toward `--limit`: `all`, `v`, `r`, `a`, `i` (case-insensitive). **Not an output filter** |
| `--only-poc "v,r"` | all types | Output filter: `v`, `r`, `a`, `i`. This is the one that hides findings |
| `--baseline PATH` | — | Diff against a previous dalfox JSON/JSONL report; only findings new since it are reported. An ordinary `-f json -o` report is the baseline |
| `--baseline-mode` | `filter` | `filter` drops known findings (counts + exit code describe only what is new), `annotate` keeps them and adds `new: true`/`new: false` to each |
| `-S, --silence` | false | Suppress everything except POC lines |
| `--no-color` | (auto) | Also respects `NO_COLOR` env var |

**Machine-readable formats** auto-silence the banner.

## Target & Scope Control (very useful, often under-used)

| Flag | Purpose |
|------|---------|
| `-X, --method` | HTTP method override: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` (RFC 10008; body-capable, safe/idempotent). Body params preserve the target method (e.g. `-X QUERY -d '…'`) |
| `-d, --data` | Request body (form or JSON) |
| `-p, --param` | Restrict to specific params. Prefer `name:location` (`query`, `body`, `json`, `multipart`, `header`, `cookie`). Bare `-p name` still works: if discovery did not seed it, dalfox synthesizes it (infers location from the request, defaults to `query`) so `--skip-discovery -p q` is not a silent no-op |
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

**Common fast-mode combo**: `--skip-mining` (or `--skip-mining-dom`) + explicit `-p` for the params you care about. With `--skip-discovery`, always pass `-p` (bare name is OK for query; use `name:location` for body/header/cookie/json).

## Network & Concurrency

| Flag | Default | Notes |
|------|---------|-------|
| `--timeout` | 10s | Per-request |
| `--scan-timeout` | 0 (disabled) | Hard wall-clock cap **per target** after preflight |
| `--delay` | 0 ms | Spaces requests **within one worker** |
| `-r, --rate-limit` (alias `--rl`) | 0 (unlimited) | Global requests/sec token bucket, shared across **all** workers + targets — bounds the aggregate burst from `workers × concurrent targets`. Friendlier to shared-IP / edge-WAF thresholds than `--delay` |
| `--retries` | 0 (off) | Retry 5xx + transient transport errors with exponential backoff (HTTP 429 is always retried regardless, honoring `Retry-After`) |
| `--retry-delay` | 1000 ms | Base delay for the `--retries` exponential backoff |
| `--insecure[=bool]` | true | TLS posture. Default skips certificate validation (scanner-friendly); `--insecure=false` enforces validation |
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
| `-b, --blind` | — | Callback URL (interact.sh, Burp Collab, etc.) — you run the listener |
| `--blind-oob[=servers]` | — | OOB/OAST blind XSS: Dalfox manages an interactsh session, correlates callbacks per-payload, and polls. Bare `--blind-oob` uses the public mesh; name servers with the `=` form (`--blind-oob=oast.fun`). CLI-only |
| `--blind-oob-secret` | — | Auth token for a self-hosted interactsh server |
| `--blind-oob-wait` | 30 | Seconds to keep polling for callbacks after payloads are sent |
| `--custom-alert-value` | `1` | Value used inside `alert(...)` etc. |
| `--custom-alert-type` | `none` | `none` or `str` (wraps in quotes) |
| `--inject-marker` | — | Replace this literal string with payloads |
| `--deep-scan` | false | Keep testing even after first finding |
| `--max-payloads-per-param` | 0 (unlimited) | Hard cap on payloads per parameter |
| `--skip-xss-scanning` | false | Discovery only (different from `--only-discovery`) |
| `--skip-ast-analysis` | false | Disable oxc-based DOM XSS detection |
| `--analyze-external-js` | false | Fetch same-origin `<script src>` bundles and run AST DOM-XSS on them (preflight, once per target; up to 16 files, 512 KiB each; respects `--include-url`/`--exclude-url`) |
| `--detect-outdated-libs` | false | Also report outdated / known-vulnerable JS libraries as informational `[I]` findings (CWE-1104; 0 extra requests — inspects already-fetched script) |
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
| `--waf-evasion` | false | Adaptive throttling on WAF detection: randomized inter-request jitter (unfingerprintable cadence) + escalating cooldown on clusters of blocked responses, paced by the per-WAF delay hint. Pairs with `--rate-limit` |
| `--waf-min-confidence` | 0.3 | Discard weak fingerprints (Google Frontend, generic "blocked" messages) |

See `references/advanced.md` for recommended WAF combinations.

## Other Useful / Diagnostic

- `--cookie-from-raw request.txt` — lift cookies from a captured raw request file (CLI only)

### Session monitoring (authenticated scans)

Auto-enabled whenever credentials are present (`--cookies`, `--cookie-from-raw`,
or a `Cookie` / `Authorization` header); off and free otherwise. Preflight
fingerprints the authenticated response for free, then re-probes per target
before and after its injection stage. Detects `401`/`403`, a redirect onto a
login-shaped URL, or a password field appearing where the baseline had none.

| Flag | Default | Notes |
|------|---------|-------|
| `--session-check <REGEX>` | — | Regex that must keep matching an authenticated body. Authoritative — replaces the heuristics entirely |
| `--session-check-url <URL>` | — | Probe a cheap authenticated endpoint (`/api/me`) instead of the scan target |
| `--on-session-loss <abort\|continue>` | `abort` | `abort` stops the target and skips the rest of that host, and exits `2`. `continue` keeps scanning and leaves the exit code alone |

On loss: `SESSION LOST` on stderr, `meta.incomplete: true`, and the target
marked `incomplete`/`SESSION_LOST` — never `clean`. Logging in is out of scope;
this is detection only.
- `--dry-run` — preflight summary only (parameter discovery + request estimate; no attack payloads). JSON/JSONL include `meta.warnings` when `-p` specs could not be seeded (e.g. `path` / `fragment` only). MCP equivalent: `preflight_dalfox` (note: preflight intentionally ignores `param` filters for impact estimation)
- `--debug` — show DBG lines
- Global root flags: `--config`, `--debug`, `--no-color`, `--silence`

## Exit Codes

See `references/results.md`.

## Common High-Value Combinations

**Fast smoke test on one query param** (safe with skip-discovery — bare `-p` synthesizes as query if needed):
```bash
dalfox scan https://target/?q=1 -p q --skip-mining --skip-discovery
# Prefer location hints when not query:
# dalfox scan https://target/search -p q:query --skip-mining --skip-discovery
# dalfox scan https://target/api -X POST -d 'user=x' -p user:body --skip-mining --skip-discovery
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
