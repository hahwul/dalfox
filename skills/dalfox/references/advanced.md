# Advanced Techniques & Recipes

## WAF Handling

### Recommended Combinations

| Situation | Command / Flags |
|-----------|-----------------|
| Unknown / first pass | `--waf-bypass auto` (default) |
| Known Cloudflare, want to force bypass mutations | `--waf-bypass force --force-waf cloudflare` |
| Akamai or ModSecurity | `--waf-bypass force --force-waf akamai` (or `modsecurity`) |
| Very noisy / aggressive WAF | `--waf-bypass force --waf-evasion` (forces workers=1 + 3s delay) |
| Only fingerprint, no bypass mutations | `--waf-bypass off` |

`--waf-min-confidence 0.3` (default) drops weak signals (Google Frontend, generic "request blocked" strings). Drop to `0.0` only when you are debugging fingerprinting.

`--skip-waf-probe` skips the active "provocation" request that improves detection of some WAFs. Use when you want pure passive header inspection.

## Parameter Discovery & Mining Control

Biggest lever for request count is usually `--skip-mining` (or the more granular `--skip-mining-dom` / `--skip-mining-dict`).

Discovery (`--skip-discovery`) turns off HTML parsing for forms, links, and inline JS. Only parameters you pass with `-p` will be tested — never use this on a bare URL without `-p`.

`--only-discovery` is excellent for a quick "how many parameters will this scan actually hit?" check before committing to a long run.

Remote wordlists (`--remote-wordlists burp,assetnote`) are cached with OnceLock for the lifetime of the process.

## Scope & Filtering

Use these in order of preference:

1. `-p` + location hints (`id:query`, `user:body`) — most precise
2. `--ignore-param` — drop noisy parameters you know are irrelevant
3. `--include-url` / `--exclude-url` regex — when crawling many pages
4. `--out-of-scope` + `--out-of-scope-file` — domain-level denylist (wildcards supported)

`--max-targets-per-host` is a hard safety net when feeding a large file that contains many hosts.

## Custom Payloads & Markers

- `--custom-payload file.txt` — appends to the built-in set
- `--only-custom-payload --custom-payload file.txt` — replaces the entire set
- `--custom-blind-xss-payload file.txt` — only affects blind XSS mode
- `--inject-marker 'FUZZ'` — lets you write `https://target/?q=FUZZ` and have payloads replace the literal `FUZZ` token (great for complex JSON bodies or non-standard locations)

`--custom-alert-value 'document.domain'` + `--custom-alert-type str` is useful when the target has a CSP that blocks bare `alert(1)` but allows `alert(document.domain)`.

## HTTP Parameter Pollution (HPP)

`--hpp` duplicates query parameters (`?q=1&q=<payload>`). Some WAFs only inspect the first or last value. Rarely the first thing you reach for, but powerful against certain legacy or misconfigured WAFs.

## Concurrency & Politeness

- Normal interactive: default 50 workers is usually fine.
- Shared / production target: `--workers 5-10 --delay 200-500`
- WAF evasion mode: let `--waf-evasion` do the throttling for you.
- Very large number of targets: combine `--max-concurrent-targets 10` with per-host caps.

`--scan-timeout` (wall-clock seconds per target after preflight) is useful when a single endpoint is hanging and you don't want one bad target to stall the entire file.

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
3. Add explicit `-p` for the 5–10 parameters you actually care about.
4. Cap with `--max-payloads-per-param 30`.
5. If still too much: lower `--workers` and add `--delay`.

## MCP vs CLI for advanced scenarios

Most of the flags above have direct equivalents in `scan_with_dalfox` parameters. The main absences on the MCP side are:
- `--cookie-from-raw` (security)
- `--remote-payloads` / `--remote-wordlists` (you can still pass custom lists via other means if needed)
- Some of the more exotic mining/scope filters (they exist in the engine but are not yet exposed on the MCP surface)

When you need the full power, fall back to spawning the CLI with carefully constructed arguments (or extend the MCP tool surface in a future change).
