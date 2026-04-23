+++
title = "Parameters & Discovery"
description = "How Dalfox finds the inputs that matter, and how to steer the discovery phase."
weight = 2
+++

Finding XSS starts with finding the right parameter. Dalfox's discovery engine is a six-stage pipeline; you rarely need to understand all of it, but knowing the moving parts helps when you want to tune a scan.

## The pipeline, briefly

1. **Discovery** — Extract parameters from the URL, body, headers, cookies, path, fragment, and form fields.
2. **Mining** — Extend with DOM analysis (parameter names embedded in JS), dictionary wordlists, and framework-specific patterns.
3. **Active probing** — Fire a probe for each parameter to learn which special characters survive.
4. **Payload generation** — Build context-aware payloads (HTML, JS, attribute, CSS).
5. **Reflection check** — Send the payload, see whether it comes back.
6. **DOM verification** — Parse the response and confirm the payload forms a real element.

## Targeting specific parameters

Tell Dalfox exactly which parameters to test:

```bash
dalfox https://target.app/api \
  -p q \
  -p id:query \
  -p auth:header \
  -p token:cookie
```

Locations: `query`, `body`, `json`, `cookie`, `header`. Without a hint, Dalfox places the parameter wherever the target already exposes it.

## Mining with wordlists

Even if a parameter isn't in the URL, Dalfox can try common names:

```bash
# Local wordlist
dalfox https://target.app -W ./params.txt

# Remote wordlists (cached after first fetch)
dalfox https://target.app --remote-wordlists burp,assetnote
```

### Auto-collapse

Highly reflective sites (e.g., a search page that echoes everything) can cause wordlist mining to explode. Dalfox watches the reflection rate and **stops mining** once ≥85% of probes reflect — a strong signal that the page is a mirror, not a real parameter map. No flag needed; it just works.

## Pruning the noise

Ignore specific parameters:

```bash
dalfox https://target.app --ignore-param csrf --ignore-param __RequestVerificationToken
```

Scope by URL pattern:

```bash
dalfox file urls.txt \
  --include-url '^https://api\.target\.app/' \
  --exclude-url '/static/|/health'
```

Out-of-scope domain list:

```bash
dalfox file urls.txt --out-of-scope-file scope-block.txt
# or inline, with wildcards
dalfox file urls.txt --out-of-scope '*.google.com,*.cdn.cloudflare.net'
```

## Only discover, don't attack

Dry-run mode discovers and prints the attack plan without sending payloads:

```bash
dalfox https://target.app --dry-run
```

Discovery-only mode is similar but completes the probing stage:

```bash
dalfox https://target.app --only-discovery
```

Both are great for scoping and for CI pre-checks.

## Skipping stages

Need to move fast or work around a fragile target? Skip parts of the pipeline:

| Flag | Skips |
|------|-------|
| `--skip-discovery` | Entire discovery stage |
| `--skip-mining` | All wordlist/DOM mining |
| `--skip-mining-dict` | Dictionary mining only |
| `--skip-mining-dom` | DOM mining only |
| `--skip-reflection-header` | Header reflection checks |
| `--skip-reflection-cookie` | Cookie reflection checks |
| `--skip-reflection-path` | Path reflection checks |

## Injection markers

Some endpoints need the payload in a specific location (e.g., inside a JWT). Use `--inject-marker`:

```bash
dalfox https://target.app/api \
  --inject-marker FUZZ \
  -d '{"filter":"FUZZ"}'
```

Dalfox replaces every `FUZZ` with each payload and sends the request.

## Auto pre-encoding

If a parameter only accepts base64-encoded input, Dalfox detects it during the probing stage and **pre-encodes** every payload before sending. You don't need to configure anything — look for `pre_encoding: base64` in debug output.

## What makes a finding "verified"

| Result | How it's confirmed |
|--------|--------------------|
| **V — Verified** | Dalfox parses the response DOM and finds the marker element (via CSS selector) the payload injected. No guessing. |
| **A — AST-detected** | Static JavaScript analysis traced a user-controlled source to a dangerous sink (e.g., `innerHTML = location.hash`). |
| **R — Reflected** | Payload text appeared in the response body, but no DOM evidence yet. Still worth investigating manually. |

`V` and `A` are the signals. `R` is a hint.

## Safe contexts

Dalfox ignores reflections inside `<textarea>`, `<title>`, `<noscript>`, `<style>`, `<xmp>`, and `<plaintext>` — content there doesn't execute, so it would only produce false positives.

## Next

- See how payloads are built in [Payloads &amp; Encoding](../payloads/).
- Dealing with a WAF? Jump to [WAF Bypass](../waf-bypass/).
