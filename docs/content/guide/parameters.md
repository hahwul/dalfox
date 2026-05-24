+++
title = "Parameters & Discovery"
description = "How Dalfox finds the inputs that matter, and how to steer the discovery phase."
weight = 2
+++

Finding XSS starts with finding the right parameter. Dalfox's discovery engine is a multi-stage pipeline; you rarely need to understand all of it, but knowing the moving parts helps when you want to tune a scan.

## The pipeline, briefly

1. **Discovery** — Extract parameters from the URL, body, headers, cookies, path, fragment, and form fields.
2. **Mining** — Extend with DOM analysis (parameter names embedded in JS), dictionary wordlists, and framework-specific patterns.
3. **Active probing** — Fire a probe for each parameter to learn which special characters survive.
4. **Fast probe** — A single sandwich-marker request per discovered parameter. If neither a partial nor a full reflection shows up, the heavy payload loops are skipped for that parameter.
5. **Payload generation** — Build context-aware payloads (HTML, JS, attribute, CSS).
6. **Reflection check** — Send the payload, see whether it comes back.
7. **DOM verification** — Parse the response and confirm the payload forms a real element. AST-based DOM-XSS analysis runs in parallel using the response captured during the fast probe.

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

Highly reflective sites (e.g., a search page that echoes everything) can cause wordlist mining to explode. Dalfox protects against this two ways:

- **Sentinel pre-probe** — Before iterating the wordlist, three random parameter names that should never collide with real fields are tested. If every one reflects, the page is a mirror; mining is skipped and a single synthetic `any` Query parameter takes its place. Cost ceiling: 3 requests, regardless of wordlist size. Runs only when the wordlist is large enough (>15 entries) for the pre-probe to pay off.
- **EWMA collapse** — While iterating, Dalfox watches the rolling reflection ratio. Once it stays ≥85% after at least 15 attempts, mining stops and any Query params already collected are folded into the same `any` placeholder.

Both routes produce identical downstream state — Stage 5–7 sees one Query injection point regardless of which trigger fired.

## Pruning the noise

Ignore specific parameters:

```bash
dalfox https://target.app --ignore-param csrf --ignore-param __RequestVerificationToken
```

Scope by URL pattern:

```bash
dalfox scan urls.txt \
  --include-url '^https://api\.target\.app/' \
  --exclude-url '/static/|/health'
```

Out-of-scope domain list:

```bash
dalfox scan urls.txt --out-of-scope-file scope-block.txt
# or inline, with wildcards
dalfox scan urls.txt --out-of-scope '*.google.com,*.cdn.cloudflare.net'
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

Some endpoints don't accept a payload as raw text — they expect it wrapped in some structural encoding (base64, JSON, JWT, …). Dalfox inspects each parameter's existing value during discovery and, when it recognises a structure, builds a transparent encoding pipeline so payloads round-trip through the same wrapping. Nothing to configure — just look for `pre_encoding` or `pre_encoding_pipeline` in debug output.

Single-step encodings are detected on the existing parameter value:

| Detected | Encodes payload as |
|----------|-------------------|
| `base64` | `BASE64(payload)` |
| `2base64` | `BASE64(BASE64(payload))` |
| `2url` / `3url` | Two- or three-round URL encoding |

Composable pipelines turn the value's structure into a chain of transformations. When the existing value decodes as a structured wrapper, Dalfox enumerates every leaf string field as its own virtual sub-parameter:

| Wrapper shape | Pipeline |
|---------------|----------|
| Base64-of-JSON `?qs=eyJ…` | `JsonField(/leaf) → Base64` |
| Base64URL-of-JSON | `JsonField(/leaf) → Base64Url` |
| Bare URL-encoded JSON `?blob=%7B…%7D` | `JsonField(/leaf)` |
| JWT/JWS `?token=h.p.s` | `JsonField(/leaf) → Base64Url → JwtAssemble` |

Each leaf is registered as a separate Param using bracket-style display naming — e.g. a payload at the `move_url` field of `qs` shows up as `qs[move_url]`, an array element appears as `qs[items][0]`. The wire-level substitution still targets the original parent param (`qs`), so the request looks normal to the server.

For JWTs the original header and signature segments are preserved verbatim. The signature won't match the modified payload, so this only fires on endpoints that don't verify the token. Properly-signed JWTs return no findings — that's expected behaviour, not a miss.

If your target uses a wrapping that Dalfox doesn't auto-detect, you can still force the injection point with `--inject-marker` (see below).

## Reflection probe shape

Every discovery and mining probe sends a sandwich marker — `OPEN + INNER + CLOSE` — instead of a single token. The response is then classified into one of four cases:

| Reflection | Meaning |
|------------|---------|
| **Full** | The complete `OPEN+INNER+CLOSE` survived. Standard reflection. |
| **PrefixOnly** | `OPEN+INNER` is present, `CLOSE` was stripped. Suggests a suffix-strip filter. |
| **SuffixOnly** | `INNER+CLOSE` is present, `OPEN` was stripped. Suggests a prefix-strip filter. |
| **InnerOnly** | Only `INNER` survives. Suggests a regex extract or both wraps removed. |

All four are treated as "reflected" — discovery records the parameter and the scan proceeds. A naive single-token check would have missed every case except *Full*, leaving prefix-/suffix-stripping endpoints undetected. The marker tokens are scan-unique (`dlx`/`dlxmid`/`xld` prefixes plus 8 hex chars per scan), so accidental collisions in HTML are negligible.

## What makes a finding "verified"

| Result | How it's confirmed |
|--------|--------------------|
| **V — Verified** | Dalfox parses the response DOM and finds direct evidence of execution. The `evidence` field tags the path that proved it: DOM marker (CSS selector hit), executable URL (`javascript:`/`data:` in a dangerous attribute), HTML structural (an injected element with an `on*` handler whose value is a sink call), or JS-context AST (a sink call inside `<script>` that the parsed AST shows is covered by the payload's byte range). |
| **A — AST-detected** | Static JavaScript analysis traced a user-controlled source to a dangerous sink (e.g., `innerHTML = location.hash`). |
| **R — Reflected** | Payload text appeared in the response body, but no DOM evidence yet. Still worth investigating manually. |

`V` and `A` are the signals. `R` is a hint.

## Safe contexts

Dalfox ignores reflections inside `<textarea>`, `<title>`, `<noscript>`, `<style>`, `<xmp>`, and `<plaintext>` — content there doesn't execute, so it would only produce false positives.

## Next

- See how payloads are built in [Payloads &amp; Encoding](../payloads/).
- Dealing with a WAF? Jump to [WAF Bypass](../waf-bypass/).
