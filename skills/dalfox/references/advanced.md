# Advanced Techniques & Recipes

## WAF Handling

### Recommended Combinations

| Situation | Command / Flags |
|-----------|-----------------|
| Unknown / first pass | `--waf-bypass auto` (default) |
| Known Cloudflare, detection misses it | `--force-waf cloudflare` |
| Akamai or ModSecurity | `--force-waf akamai` (or `modsecurity`) |
| Very noisy / aggressive WAF | `--waf-evasion` (adaptive jitter + escalating cooldown on block clusters; pair with `--rate-limit`) |
| Only fingerprint, no bypass | `--waf-bypass off` (also skips the provocation probe and per-WAF pacing) |

`--waf-bypass force` currently behaves exactly like `auto` — the code only distinguishes `off`. `--force-waf` is what pins a profile, and it does so in any mode (under `off` the pinned WAF is reported but no bypass runs).

`--waf-min-confidence 0.3` (default) drops weak signals (Google Frontend, generic "request blocked" strings). Drop to `0.0` only when you are debugging fingerprinting.

`--skip-waf-probe` skips the active "provocation" request that improves detection of some WAFs. Use when you want pure passive header inspection.

## Parameter Discovery & Mining Control

Biggest lever for request count is usually `--skip-mining` (or the more granular `--skip-mining-dom` / `--skip-mining-dict`).

`--skip-discovery` turns off all discovery checks (query/header/cookie/path reflection, forms, fragment). **Always pass `-p` when using it** — without `-p`, a bare URL has nothing to test. Bare `-p name` synthesizes a param when discovery/mining did not seed it (location inferred from the request, default `query`). Prefer `name:location` (`q:query`, `user:body`, `auth:header`, `sid:cookie`) when the location is not obvious.

`--only-discovery` / `--dry-run` are excellent for "how many parameters will this scan actually hit?" before a long run. Dry-run JSON surfaces `meta.warnings` if an explicit `-p` could not be seeded (e.g. `path` / `fragment`).

Remote wordlists (`--remote-wordlists burp,assetnote`) are cached with OnceLock for the lifetime of the process.

Dictionary and DOM query mining use bounded canary buckets (normally 64 names,
with an approximately 8 KiB URL budget) rather than one request per candidate.
Reflected canaries identify names directly; a response change without a canary
reflection is checked with a same-width control and four-way splitting to find
metric-only parameters. Metric-only hits need a stable page (two identical
clean requests match; otherwise only a status change counts) and a repeat of
the single name; names sharing a bucket with a reflected one are re-probed
without it; a failed or size-refused bucket is split and retried, not dropped;
several canaries in one redirect `Location` are confirmed in smaller groups.
Duplicate/already-known query slots are removed before bucket construction. A negative arbitrary-name sentinel keeps the individual
confirmed names even when the EWMA reflection ratio is high, so a larger
wordlist is not cut off merely because its first bucket reflects.

When no custom or remote list is selected, the built-in seed preserves the
historical GF/XSS names and adds an attributed gori-derived set covering common
API, authentication, pagination, feature-flag, media, and operational names.

## Scope & Filtering

Use these in order of preference:

1. `-p` + location hints (`id:query`, `user:body`) — most precise
2. `--ignore-param` — drop noisy parameters you know are irrelevant
3. `--include-url` / `--exclude-url` regex — when crawling many pages
4. `--out-of-scope` + `--out-of-scope-file` — domain-level denylist (wildcards supported)

`--max-targets-per-host` is a hard safety net when feeding a large file that contains many hosts.

## Custom Payloads & Markers

- `--custom-payload file.txt` — appends to the built-in set
- `--only-custom-payload --custom-payload file.txt` — uses that file as the local base set across reflection and DOM checks; adaptive synthesis and shared CSP/technology payloads are skipped. Encoders and WAF mutations still expand those custom payloads, and explicitly requested `--remote-payloads` remain active.
- `--custom-blind-xss-payload file.txt` — blind XSS templates; each line must contain `{callback}` (lines without it are skipped)
- `--inject-marker 'FUZZ'` — lets you write `https://target/?q=FUZZ` and have payloads replace the literal `FUZZ` token (great for complex JSON bodies or non-standard locations)

`--custom-alert-value 'document.domain'` rewrites `alert(1)` → `alert(document.domain)` in the context-matched reflection payloads (clearer PoC; DOM-verification and fallback payloads keep `alert(1)`). Add `--custom-alert-type str` only for a literal: it wraps the value in single quotes (`alert('dalfox')`), so with `document.domain` you would get the string, not the domain.

## HTTP Parameter Pollution (HPP)

`--hpp` duplicates query parameters (`?q=1&q=<payload>`). Some WAFs only inspect the first or last value. Rarely the first thing you reach for, but powerful against certain legacy or misconfigured WAFs.

## Concurrency & Politeness

- Normal interactive: default 50 workers is usually fine.
- Shared / production target: `--workers 5-10 --delay 200-500`
- WAF evasion mode: let `--waf-evasion` do the throttling for you.
- Very large number of targets: combine `--max-concurrent-targets 10` with per-host caps.

`--scan-timeout` (wall-clock seconds per target, max 86400) caps only the payload-injection stage — discovery and mining are not covered. Useful when a single endpoint is hanging and you don't want one bad target to stall the entire file.

## raw-http Input (under-appreciated superpower)

```bash
# From Burp "Copy request to file"
dalfox scan -i raw-http captured.req --blind https://collab/

# Or paste a literal request (rare but works for one-off)
dalfox scan -i raw-http $'POST /login HTTP/1.1\r\nHost: ...\r\n...'
```

dalfox parses the method, path, headers (including Cookie), and body. Extremely effective when the interesting parameters are in cookies, custom headers, or a non-standard JSON structure that normal URL discovery would miss.

## When to Use --deep-scan

Only when you have evidence that the first finding on a parameter is not the only (or most severe) one. It disables the early-exit optimization after the first verified hit. Expensive — use deliberately.

## Common "I have too many requests" recipes

1. Preflight first (`--dry-run` or MCP `preflight_dalfox`).
2. Add `--skip-mining`.
3. Add explicit `-p` / MCP `param` for the 5–10 parameters you care about (`name:location` when not query).
4. Cap with `--max-payloads-per-param 30` or MCP `max_payloads_per_param`.
5. If still too much: lower `--workers`, add `--delay` / `--rate-limit`, or `--scan-timeout` / MCP `scan_timeout`.

## MCP vs CLI for advanced scenarios

Most scan flags have direct equivalents in `scan_with_dalfox` (including `max_payloads_per_param`, `wait` / `wait_timeout_sec`, remote payloads/wordlists, WAF options). Notable absences / differences:
- `--cookie-from-raw` — intentionally absent on MCP (host file-read class; supply `cookies` directly)
- Managed `--blind-oob` lifecycle — CLI-only; MCP uses `blind_callback_url`
- Multi-target / HAR / raw-http fan-out — CLI-only (call MCP once per URL)
- `preflight_dalfox.param` is accepted but **not applied** (full discovery impact estimate); pass `param` on `scan_with_dalfox`
- Some of the more exotic mining/scope filters (they exist in the engine but are not yet exposed on the MCP surface)

When you need the full power, fall back to spawning the CLI with carefully constructed arguments.
