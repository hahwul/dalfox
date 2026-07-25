+++
title = "Detection Model"
description = "The three subsystems that find XSS, which flags govern each, and what V / A / R / I are actually evidence of."
weight = 7
toc = true
+++

Dalfox reports findings from three independent subsystems. They print to the same terminal and look similar, but they read different inputs and reason in different ways — so a flag that silences one has no effect on the others.

This page exists because that split is not obvious from the output alone. It was written up in [issue #1238](https://github.com/hahwul/dalfox/issues/1238) by [@OSTARA711](https://github.com/OSTARA711), whose account of the confusion is the basis for the model below.

## The three subsystems

### 1. Parameter mining — finding names to test

Reads the **HTML structure** of a response and harvests candidate parameter *names* from `id` and `name` attributes on forms and inputs, plus dictionary wordlists. Its only job is to extend the list of parameters worth probing when you haven't named them yourself.

| Flag | Effect |
|------|--------|
| `--skip-mining` | Skip all mining |
| `--skip-mining-dict` | Dictionary wordlists only |
| `--skip-mining-dom` | HTML `id`/`name` harvesting only |

Despite the name, **`--skip-mining-dom` has nothing to do with DOM-XSS detection.** "DOM" here refers to where the *names* come from, not to the vulnerability class.

### 2. AST analysis — reading the JavaScript

Parses the **JavaScript source** in the response into an abstract syntax tree and traces whether data from a dangerous source (`location.hash`, `location.search`, `document.referrer`, `postMessage`, …) reaches a dangerous sink (`innerHTML`, `document.write`, `eval`, …) without sanitization. It emits `[A]` findings.

This pass is **always on** and is governed by `--skip-ast-analysis`. It is not parameter-driven: it reads each `<script>` block once and reports every source→sink path it finds, which is why `[A]` findings can name inputs you never passed on the command line — including a URL fragment, which is never sent to the server at all. Restricting the scan with `-p` does not narrow it, because `-p` scopes which parameters get *requested*, and this subsystem is not making per-parameter requests.

| Flag | Effect |
|------|--------|
| `--skip-ast-analysis` | Turn off source→sink analysis (silences `[A]`) |
| `--analyze-external-js` | Also fetch and analyze same-origin `<script src>` bundles |

### 3. Reflection and DOM verification — sending payloads

The classic active pipeline: inject a payload into a parameter, send the request, and check what comes back. A payload that merely appears in the response body is `[R]`. A payload that the response parses into a **real DOM element** — matched by CSS selector against dalfox's `class=dlx…` marker — is `[V]`.

## Evidence tiers

| Tag | Means | Produced by |
|-----|-------|-------------|
| `[V]` | The payload was found as a real element in a parsed response, or an executable scheme landed in a dangerous attribute | Reflection + DOM verification |
| `[A]` | Static analysis found an unsanitized source→sink flow in the page's JavaScript | AST analysis |
| `[R]` | The payload came back in the response body, without DOM evidence | Reflection |
| `[I]` | Informational, not an exploitable XSS (e.g. a known-vulnerable JS library, CWE-1104) | Library detection (`--detect-outdated-libs`) |

Filter with `--only-poc` (e.g. `--only-poc v,a`).

### What `[V]` does not mean

`[V]` is **not** browser execution. Dalfox has no headless browser and no CDP client; it never renders a page or observes an `alert()` fire. `[V]` means the payload was found in a *parsed DOM tree built from a real HTTP response* — static analysis, just on stronger evidence than the raw string match behind `[R]`.

This has a concrete consequence for **pure client-side DOM-XSS**: the payload is written into the page by JavaScript at runtime, so it never appears in the server's response, and there is nothing for DOM verification to find. On a static page whose only vulnerability is `location.hash → innerHTML`, `[A]` is the strongest tier dalfox can reach, and `--only-poc v` will correctly return nothing.

So `[A]` is a lead to confirm, not a confirmed exploit. Open the POC URL in a browser with devtools to verify it — dalfox prints a complete POC URL on every `[A]` finding, and a `[manual POC: …]` setup hint for sources it cannot put in a URL (`window.name`, `document.referrer`, cookies, `postMessage`, …).

## Reading a scan that mixes them

```
INF found reflected 0 params
WRN XSS found 0 XSS (+3 A)
[POC][A][GET][DOM-XSS] https://target.app/?q=%3Cimg+src%3Dx+onerror%3D…
  ├── Issue: DOM-based XSS via URLSearchParams.get(q) to innerHTML (needs runtime confirmation)
  └── Payload: q=<img src=x onerror=alert(1) class=dlx1944740c>
```

- `found reflected 0 params` — the **reflection** engine found no server-side reflection. Expected on a static site.
- `XSS found 0 XSS` — the headline count is `[V]` only. `(+3 A)` names the other tiers printed below it.
- The `[A]` blocks come from **AST analysis**, independent of both lines above.

Reading only the summary lines on a DOM-XSS target would miss every finding in the report.

## Choosing flags by intent

| Goal | Flags |
|------|-------|
| Only findings dalfox confirmed itself | `--only-poc v` |
| Suppress static-analysis noise on a production target | `--skip-ast-analysis` |
| Skip name harvesting, keep DOM-XSS detection | `--skip-mining-dom` |
| Test one parameter, but still see every DOM sink | `-p q` (AST findings are not scoped by `-p`) |
