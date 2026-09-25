# CLI Reference (dalfox scan)

All flags are defined in `src/cmd/scan/args.rs:ScanArgs`. Defaults are centralized in the same file (`DEFAULT_*` constants).

## Input

| Flag | Default | Notes |
|------|---------|-------|
| `-i, --input-type` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `--dedup-urls` | `exact` | `exact` (drop identical URL+method), `signature` (also collapse URLs differing only in parameter *values* — keys on method+host+path+param names), `off` (no dedup). Use `signature` for `gau`/`katana` dumps; not value-safe when an `action=`-style value picks the handler. Collapsed count is logged and lands in `meta.dedup_mode` / `meta.targets_deduplicated`. |
| `--state-file` | — | Resume support for mass scans: records each target's terminal state (`completed` / `cancelled` / `error`) and skips the `completed` ones on a re-run. Only `completed` is skipped — Ctrl-C, `--scan-timeout`, severe transport loss, and preflight drops are retried. Resume identity is URL, method, and a hash of the request's body, header names/values, cookie names, and user-agent (from raw HTTP/HAR captures and from `-H` / `--cookies` / `--user-agent`); only the hash is written to the state file. Run-wide credential values are excluded — every `--cookies` / `--cookie-from-raw` value and the `-H` values of `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key` / `*-Api-Key`, `X-Auth-Token` / `*-Token`, `X-CSRF-Token` / `X-XSRF-Token`, `*-Session-Id` / `X-Session-Token`, `X-Access-Key`, `X-JWT-Assertion` — so refreshing a session resumes instead of rescanning. Credentials inside a raw-HTTP/HAR capture still count (tenant A vs tenant B captures are distinct targets). Use a separate state file per account. The file's header holds a hash of the scan-affecting config (credential values neutralized the same way); a mismatch moves the file to `<path>.bak` and starts over. Skipped count lands in `meta.resumed`. CLI only. |
| `TARGET` (positional) | — | URL, file path, raw HTTP (`-i raw-http`), or HAR file (`-i har` / auto-detected) |

**Target lists are lenient, typed targets are not.** A line from a file / pipe that does not parse as a target (`mailto:`, `javascript:`, `tel:`, `ftp://`, truncated junk — the usual `gau` / `katana` sediment) is skipped with a stderr warning and counted in `meta.targets_unparsable`; one stray line no longer aborts a 50k-URL run. A target typed on the command line still fails the run, and a list where *nothing* parses is a `PARSE_ERROR`.

**A missing file is a missing file.** A path-shaped argument that is not on disk (`./urls.txt`, `/tmp/list`, `capture.har`, `-i raw-http req.txt`) is reported as `FILE_READ_ERROR`, never silently reinterpreted as a hostname. Bare hosts (`example.com`, `example.com/a?b=1`) are unaffected.

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

Every format except `plain` auto-silences the banner.

## Target & Scope Control (very useful, often under-used)

| Flag | Purpose |
|------|---------|
| `-X, --method` | HTTP method override: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` (RFC 10008; body-capable, safe/idempotent). Body params preserve the target method (e.g. `-X QUERY -d '…'`) |
| `-d, --data` | Request body (form or JSON) |
| `--user-agent` | Set a custom `User-Agent` header (e.g. `--user-agent 'Mozilla/5.0'`); unset uses the built-in default |
| `-p, --param` | Restrict to specific params. Prefer `name:location` (`query`, `body`, `json`, `multipart`, `header`, `cookie`, `graphql`, `xml`; `path` / `fragment` only filter discovered params — they cannot be synthesized). Bare `-p name` still works: if discovery did not seed it, dalfox synthesizes it (infers location from the request, defaults to `query`) so `--skip-discovery -p q` is not a silent no-op |
| `--include-url` | Regex whitelist (multiple) |
| `--exclude-url` | Regex blacklist (multiple) |
| `--ignore-param` | Skip these parameter names entirely |
| `--out-of-scope` | Domain pattern to exclude (e.g. `*.dev.example.com`). Repeat the flag per pattern — a comma is not a separator. `*.example.com` also matches the apex `example.com` |
| `--out-of-scope-file` | File containing one pattern per line. Unreadable path = fatal `FILE_READ_ERROR` (never a warning: continuing would scan the excluded hosts) |

## Discovery & Mining

| Flag | Effect |
|------|--------|
| `--only-discovery` | Stop after parameter discovery (no XSS payloads) |
| `--skip-discovery` | Skip all discovery checks (query/header/cookie/path reflection, forms, fragment) |
| `--skip-reflection-header` | Skip the blanket sweep of common request headers. Headers named explicitly with `-p name:header` are still probed |
| `--skip-reflection-cookie` | Skip the blanket sweep over supplied cookies. Cookies named explicitly with `-p name:cookie` are still probed |
| `--skip-reflection-path` | Skip path-segment reflection checks |
| `--skip-mining` | Skip DOM mining + dictionary mining (biggest single win for speed) |
| `--skip-mining-dom` | Skip only DOM-based mining |
| `--skip-mining-dict` | Skip only wordlist/dictionary mining |
| `-W, --mining-dict-word` | Path to custom wordlist for dictionary mining |
| `--remote-wordlists` | `burp,assetnote` (comma-separated) |

Dictionary and DOM mining drop duplicate names and already-discovered query
slots before probing, so a repeated entry costs no request and cannot inflate
the reflection ratio. Remaining names are packed into bounded canary buckets
(normally 64 names, with an approximately 8 KiB URL budget), so a large list is
not one request per entry. Reflected canaries identify their own names; an
ambiguous response is compared with a same-width control and split four ways
only when needed for metric-only parameters. Eligibility for the arbitrary-name
sentinel check is still measured on the wordlist as loaded, so a heavily
filtered list keeps that check. EWMA collapse is evaluated after bucket
processing: only sentinel-confirmed arbitrary reflection is folded into `any`,
while a negative sentinel keeps the individual confirmed names. Same-named
body/header parameters remain separate injection points.

**Common fast-mode combo**: `--skip-mining` (or `--skip-mining-dom`) + explicit `-p` for the params you care about. With `--skip-discovery`, always pass `-p` (bare name is OK for query; use `name:location` for body/header/cookie/json).

## Network & Concurrency

| Flag | Default | Notes |
|------|---------|-------|
| `--timeout` | 10s | Per-request |
| `--scan-timeout` | 0 (disabled) | Wall-clock cap **per target** on the payload-injection stage only (discovery/mining not covered). Max 86400 |
| `--delay` | 0 ms | Spaces requests **within one worker** |
| `-r, --rate-limit` (alias `--rl`) | 0 (unlimited) | Global requests/sec token bucket, shared across **all** workers + targets — bounds the aggregate burst from `workers × concurrent targets`. Friendlier to shared-IP / edge-WAF thresholds than `--delay` |
| `--retries` | 0 (off) | Retry 5xx + transient transport errors with exponential backoff (HTTP 429 is always retried regardless, honoring `Retry-After`) |
| `--retry-delay` | 1000 ms | Base delay for the `--retries` exponential backoff |
| `--insecure[=bool]` | true | TLS posture. Default skips certificate validation (scanner-friendly); `--insecure=false` enforces validation |
| `-F, --follow-redirects` | false | |
| `--proxy` | — | `http(s)://` or `socks4/5(h)://` only; unroutable schemes rejected up front |
| `--ignore-return` | (none) | Comma-separated status codes to drop before analysis (e.g. `302,403,404`) |
| `--workers` | 50 | Concurrent workers |
| `--max-concurrent-targets` | 50 | For file/pipe input |
| `--max-targets-per-host` | 100 | Safety cap per host |

Reflection and DOM payload batches start small and grow toward the worker limit.
An early hit therefore avoids a full batch of speculative requests. Already-fetched
responses are still checked for verified evidence after a reflection or DOM
early-exit signal. Payload order and catalogs are unchanged; `--sxss`,
`--waf-evasion`, and positive `--delay` retain serial payload requests. Targets
that need the full catalog reach it in the same number of requests but a few
more round trips, so a tight `--scan-timeout` can now cut a deep payload the
full-window batching would have reached.

## XSS Engine

| Flag | Default | Notes |
|------|---------|-------|
| `-e, --encoders` | `url,html` | `none,url,2url,3url,4url,html,htmlpad,base64,unicode,zwsp` (comma-separated) |
| `--remote-payloads` | (none) | `portswigger,payloadbox` |
| `--custom-payload` | — | File of extra payloads |
| `--only-custom-payload` | false | Use the custom file as the local base set; skip built-in families, adaptive synthesis, and shared CSP/technology payloads. Explicit remote providers and encoder/WAF variants remain active. |
| `--custom-blind-xss-payload` | — | Blind XSS template file; each line must contain `{callback}` (others skipped with a warning) |
| `-b, --blind` | — | Callback URL (interact.sh, Burp Collab, etc.) — you run the listener |
| `--blind-oob[=servers]` | — | OOB/OAST blind XSS: Dalfox manages an interactsh session, correlates callbacks per-payload, and polls. Bare `--blind-oob` uses the public mesh; name servers with the `=` form (`--blind-oob=oast.fun`). CLI-only |
| `--blind-oob-secret` | — | Auth token for a self-hosted interactsh server |
| `--blind-oob-wait` | 30 | Seconds to keep polling for callbacks after payloads are sent |
| `--custom-alert-value` | `1` | Value used inside `alert(...)` etc. |
| `--custom-alert-type` | `none` | `none` or `str` (wraps the value in single quotes → string literal) |
| `--inject-marker` | — | Replace this literal string with payloads |
| `--deep-scan` | false | Keep testing even after first finding |
| `--max-payloads-per-param` | 0 | Cap on base payloads per parameter (reflection and DOM sets each). `0` = built-in cap of 3000 per set unless `--deep-scan`. WAF/encoder variants are added on top |
| `--skip-xss-scanning` | false | Discovery only (different from `--only-discovery`) |
| `--skip-ast-analysis` | false | Disable oxc-based DOM XSS detection |
| `--analyze-external-js` | false | Fetch same-origin `<script src>` bundles and run AST DOM-XSS on them (preflight, once per target; up to 16 files, 512 KiB each; respects `--include-url`/`--exclude-url`) |
| `--detect-outdated-libs` | false | Also report outdated / known-vulnerable JS libraries as informational `[I]` findings (CWE-1104; 0 extra requests — inspects already-fetched script) |
| `--hpp` | false | HTTP Parameter Pollution (duplicate query params) |

## Stored XSS (SXSS)

| Flag | Notes |
|------|-------|
| `--sxss` | Enable stored XSS mode |
| `--sxss-url` | Where to look for the stored reflection, absolute `http(s)://` (auto-detect if omitted); only used with `--sxss` |
| `--sxss-method` | GET/POST for the check |
| `--sxss-retries` | 3 (increase for slow propagation) |

## WAF

| Flag | Default | Notes |
|------|---------|-------|
| `--waf-bypass` | `auto` | `auto` (probe then bypass), `force` (same as `auto` today), `off` (detect only: no probe, mutations, or per-WAF pacing) |
| `--force-waf` | — | Pin a specific engine (`cloudflare`, `akamai`, `modsecurity`, `aws`, ...) in any `--waf-bypass` mode |
| `--skip-waf-probe` | false | Skip the active provocation request |
| `--waf-evasion` | false | Adaptive throttling on WAF detection: randomized inter-request jitter (unfingerprintable cadence) + escalating cooldown on clusters of blocked responses, paced by the per-WAF delay hint. Pairs with `--rate-limit` |
| `--waf-min-confidence` | 0.3 | Discard weak fingerprints (Google Frontend, generic "blocked" messages) |

See `references/advanced.md` for recommended WAF combinations.

## Other Useful / Diagnostic

- `--cookie-from-raw request.txt` — lift cookies from a captured raw request file (CLI only)
- `--dry-run` — preflight summary only (parameter discovery + request estimate; no attack payloads). JSON/JSONL include `meta.warnings` when `-p` specs could not be seeded (e.g. `path` / `fragment` only). MCP equivalent: `preflight_dalfox` (note: preflight intentionally ignores `param` filters for impact estimation)
- `--debug` — show DBG lines
- Global root flags: `--config`, `--debug`, `--no-color`, `--silence`

### Session monitoring (authenticated scans)

Auto-enabled whenever credentials are present (`--cookies`, `--cookie-from-raw`,
or a `Cookie` / `Authorization` header); off and free otherwise. Preflight
fingerprints the authenticated response for free, then re-probes after each
target's injection stage (plus before it, when the baseline is already >30s
old — so on a short or single-target run only the post-scan probe fires).
Detects `401`/`403`, a redirect onto a login-shaped URL, or a password field
appearing where the baseline had none. A fingerprinted WAF suppresses the `403`
signal, since a WAF block explains it better than an expired session.

| Flag | Default | Notes |
|------|---------|-------|
| `--session-check <REGEX>` | — | Regex that must keep matching an authenticated body. Authoritative — replaces the heuristics entirely |
| `--session-check-url <URL>` | — | Probe a cheap authenticated endpoint (`/api/me`) instead of the scan target |
| `--on-session-loss <abort\|continue>` | `abort` | `abort` stops the target and skips the rest of that host; the run exits `2` if it has no findings (`1` if it does). `continue` keeps scanning and leaves the exit code alone |

On loss: `SESSION LOST` on stderr, `meta.incomplete: true`, and the target
marked `incomplete`/`SESSION_LOST` — never `clean`. Logging in is out of scope;
this is detection only.

## Exit Codes

See `references/results.md`.

## Common High-Value Combinations

**Fast smoke test on one query param** (safe with skip-discovery — bare `-p` synthesizes as query if needed):
```bash
dalfox scan 'https://target/?q=1' -p q --skip-mining --skip-discovery
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
dalfox scan https://target/ --force-waf cloudflare --waf-evasion
```

**Maximum coverage (expensive)**:
```bash
dalfox scan targets.txt --deep-scan --remote-payloads portswigger,payloadbox -e url,html,base64
```

**Raw captured request**:
```bash
dalfox scan -i raw-http captured-request.txt --blind https://your.interact.sh
```
