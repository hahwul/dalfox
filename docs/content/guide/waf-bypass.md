+++
title = "WAF Bypass"
description = "Detect WAFs automatically and apply per-WAF evasion strategies."
weight = 4
toc = true
+++

Most real targets sit behind a WAF. Dalfox fingerprints the WAF, then automatically chooses an evasion strategy: extra encoders and payload mutations tuned to that specific WAF's rules.

## How it works

1. Dalfox matches the preflight response's headers and body against its fingerprint rules (no extra request), then sends one **provocation probe**: the target's own request with `dalfox_waf_probe=<script>alert(1)</script>` appended to the query.
2. If a known WAF signature shows up (headers like `cf-ray`, body markers like "Attention required!"), Dalfox notes the WAF and its confidence. A probe answered with 403/406/429/503 and no recognisable signature is recorded as an unknown WAF, unless the page returns that status to every request or the 429 carries `Retry-After` (plain rate limiting).
3. The scanner merges the WAF's **extra encoders** into your encoder list and adds the WAF's **mutation list** to the payload generator.
4. Payload mutations are capped (4 variants per base payload) so request volume stays sane. The cap only applies once a WAF is detected, so the extra effort lands exactly on the scans that need it.

This is all on by default. You only touch flags if you want to disable or steer it.

## Supported WAFs

- Cloudflare
- AWS WAF
- Akamai
- Imperva / Incapsula
- ModSecurity
- OWASP CRS
- Sucuri
- F5 BIG-IP
- Barracuda
- FortiWeb
- Azure WAF
- Google Cloud Armor
- Fastly
- Wordfence
- Citrix NetScaler
- Wallarm
- NAXSI
- SafeLine

Wallarm, NAXSI, and SafeLine are fingerprinted but have no dedicated strategy; like unrecognised WAFs, they get a generic fallback strategy.

## Tuning the behaviour

### Auto (default)

```bash
dalfox scan https://target.app
# equivalent to:
dalfox scan https://target.app --waf-bypass auto
```

### Force a specific WAF

Replace whatever fingerprinting found with a chosen WAF (confidence `1.0`) and apply its strategy:

```bash
dalfox scan https://target.app \
  --waf-bypass force \
  --force-waf cloudflare
```

Handy when the WAF masks its headers or sits behind a CDN. `--force-waf` is what selects the WAF; it takes effect under `auto` too, and `--waf-bypass force` without it behaves like `auto`. The provocation probe is still sent unless you add `--skip-waf-probe`.

Accepted names (case-insensitive): `cloudflare`/`cf`, `aws`/`awswaf`/`aws-waf`, `akamai`, `imperva`/`incapsula`, `modsecurity`/`modsec`, `owasp-crs`/`owaspcrs`/`crs`, `sucuri`, `f5`/`bigip`/`f5-bigip`, `barracuda`, `fortiweb`/`forti`, `azure`/`azurewaf`/`azure-waf`, `cloudarmor`/`cloud-armor`/`gcp`, `fastly`, `wordfence`, `citrix`/`netscaler`. Any other value is rejected.

### Disable WAF logic

```bash
dalfox scan https://target.app --waf-bypass off
```

No extra encoders, no mutations, no per-WAF pacing, and no provocation probe: just your configured payloads. Passive detection still runs on the preflight response, so a detected WAF is still reported in `target_summary`.

### Skip the probe

```bash
dalfox scan https://target.app --skip-waf-probe
```

Still uses passive detection on the preflight response's headers and body, but sends no provocation request. Use when the target is flaky and you don't want to burn rate limit on a probe.

### Evasion throttle

`--waf-evasion` switches Dalfox to **adaptive timing** instead of a blunt slowdown: it randomizes the inter-request interval (jitter) so the cadence can't be fingerprinted, and escalates a cooldown pause whenever it sees a cluster of blocked responses (403/406/429/503). The jitter applies whether or not a WAF was detected: with no `--delay` and no WAF pacing hint, each pause lands between 75 and 225 ms. The flag also sends each parameter's payloads one at a time instead of concurrently. The per-WAF pacing hint (for example 100 ms per request for Cloudflare, or 1.5 s when the WAF was inferred only from a 429/503 probe response) is applied automatically on detection, even without the flag.

```bash
dalfox scan https://target.app --waf-evasion
```

For a hard ceiling on the request rate (independent of WAF detection and shared across **all** workers and targets), combine it with `--rate-limit` (requests/second). This is the right knob when scanning behind a shared IP or against an edge WAF with a global threshold, since `--delay` only spaces a single worker:

```bash
# At most 15 requests/second across the whole scan, with adaptive evasion
dalfox scan https://target.app --rate-limit 15 --waf-evasion
```

Transient failures (5xx, timeouts, connection resets) can be retried with `--retries` / `--retry-delay`; HTTP 429 is always retried with `Retry-After` honored.

### Filter weak fingerprints

Each fingerprint carries a confidence score (0.0–1.0). Generic markers like `Request blocked` (0.3) or `Server: Google Frontend` (0.15) sometimes false-positive on benign origins. Use `--waf-min-confidence` to discard anything below the threshold:

```bash
# Keep only confident matches (drops 0.3/0.15 noise)
dalfox scan https://target.app --waf-min-confidence 0.7
```

Default is `0.3` (suppresses weak/generic matches like `Server: Google Frontend`). Pass `--waf-min-confidence 0.0` to keep every match, or raise it when you suspect noisy passive detection is steering Dalfox into the wrong evasion strategy.

## Mutation tactics (under the hood)

Different WAFs fall to different tricks. A small sample:

| Mutation | Example | Works against |
|----------|---------|---------------|
| **HTML comment split** | `<scr<!---->ipt>` | Signature regex |
| **Backtick call** | `` alert`1` `` | `alert(` regex |
| **Constructor chain** | `[].constructor.constructor('alert(1)')()` | Heavy keyword blocks |
| **Unicode JS escape** | `\u0061lert(1)` | JS-token filters |
| **Slash separator** | `<svg/onload=alert(1) class=x>` | CRS 941160 |
| **SVG animate** | `<svg><animate onbegin=alert(1) attributeName=x>` | CRS 941110 |
| **HTML entity parens** | `alert&#40;1&#41;` | CRS 941370 |
| **Exotic whitespace** | form-feed / vertical tab | CRS 941320 |
| **Case alternation** | `<ScRiPt>` | Case-sensitive rules |
| **zwsp insertion** (encoder) | U+200B after `<` `>` `"` `'` `(` `)` `/` `;` | Lexer-based detection |
| **Keyword entity encode** | `onerror=&#97;lert(1)` | `alert`/handler keyword regex (attribute-decoded) |
| **Multi-slash** | `<img/src="x"/onerror="alert(1)"/class=x>` | Regexes anchored on `\s` between later attributes |
| **Scheme break** | `href=java&#9;script:alert(1)` | Literal `javascript:` scheme regex (URL-parser strips the TAB) |
| **Entity scheme** | `href=&#106;avascript:alert(1)` | Literal `javascript:` scheme regex (attribute-decoded) |

Slash separators are emitted only where the HTML tokenizer will still begin a new attribute; a slash after an unquoted value is part of that value, so Dalfox preserves the whitespace there. Keyword entity encoding, scheme break, and entity scheme rely on the HTML tokenizer decoding character references **inside attribute values** before the URL parser or event-handler JS compiler sees them. Those entity mutations are skipped for bare body text and `<script>`/`<style>` payloads, where no entity decoding happens.

Dalfox does not split JavaScript identifiers with comments (`al/**/ert`). JavaScript treats the comment as a token boundary, so that form cannot call `alert`; the scanner skips the wasted variant.

You don't configure these directly; they're selected automatically per WAF. To inspect what's happening, run with `--debug`.

## Inspection-window overflow

Some WAFs (e.g. AWS WAF-style configs) only inspect the **first N bytes** of a parameter value. A vector at the start of the value trips a block, but the same vector reflects untouched once it's pushed past the inspected window.

During active probing, when a parameter's special-character probe comes back fully blocked, Dalfox re-tries it behind a long benign filler prefix. If the characters now reflect, it concludes the value sits behind a size-limited inspection window and automatically prepends that filler to every payload for the parameter — so the real vector always lands past the window. The reported PoC URL includes the filler, so it reproduces as-is. This is automatic; nothing to configure.

## Combining with encoders

Your `--encoders` list and the WAF's extra encoders are merged. So this:

```bash
dalfox scan https://target.app -e url,base64
# Cloudflare detected → extra encoders: unicode, 4url, zwsp
# Effective: url, base64, unicode, 4url, zwsp
```

Duplicates are dropped. Structural mutations are sent as-is: Dalfox does not run a mutated payload through the encoders as well, so the two kinds of variant add up rather than multiply.

## Rate limiting & backoff

Dalfox tracks consecutive blocked responses per worker. After three 429 or 503 responses in a row it backs off with an exponential sleep (2 s, doubling, capped at 30 s) to avoid permanent blocks. A 403 or 406 is treated as a block on that one payload, so Dalfox moves straight on to the next payload; the same cooldown applies to those only under `--waf-evasion`. You can help it along with `--delay` (per-request ms) and smaller `--workers` for fragile targets. Any `--delay` above 0 also makes each parameter send its payloads one at a time.

```bash
dalfox scan https://target.app --delay 500 --workers 10
```

## Debugging

Turn on the debug stream to see fingerprint decisions and the active strategy:

```bash
dalfox scan --debug https://target.app 2>&1 | grep -i waf
```

## Next

- [Stored XSS](../stored-xss/) covers the inject-here-verify-there pattern, which often interacts with WAFs.
- [Output &amp; Reports](../output/) for integrating findings into your pipeline.
