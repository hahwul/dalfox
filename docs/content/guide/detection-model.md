+++
title = "Detection Model"
description = "The three axes of a Dalfox finding — confidence, method, impact — and what each evidence tier actually proves."
weight = 7
toc = true
+++

Every Dalfox finding answers three separate questions. Reading them as one scale is the single most common source of confusion about the output, so they are separate fields:

| Axis | Field | Question |
|------|-------|----------|
| **Confidence** | `type` — `V` / `R` | Can Dalfox claim this is a vulnerability? |
| **Method** | `detection_method` | How was it found? |
| **Impact** | `severity` | How bad is it if exploited? |

Two of those three vary independently today. **`severity` does not**: for XSS
findings it is currently a restatement of the tier (`V` → `High`, `A` →
`Medium`, `R` → `Info`), so filtering or sorting on it tells you nothing that
`type` didn't. It carries real information only on `I`, where it comes from the
library advisory. Treat it as a display convenience until it grades impact on
its own.

`[A]` predates that split. It answers the *method* question while sitting in the `type` field, which is why nobody — including the code — could say where it belonged on the confidence scale. It is being absorbed; see [Migration](#migration) below.

This page exists because the split was not visible from the output alone. It was worked out in [issue #1238](https://github.com/hahwul/dalfox/issues/1238) with [@OSTARA711](https://github.com/OSTARA711), whose write-up is the basis for the model here.

## Confidence: what `type` means

| Tag | Name | Means |
|-----|------|-------|
| `V` | **Vulnerable** | Dalfox asserts this input is exploitable. Act on it. |
| `R` | **Reflected** | The payload came back in the response, but its position was not confirmed exploitable. A signal, not a claim — confirm it yourself. |
| `A` | AST-detected | Transitional — a method label. See [Migration](#migration). |
| `I` | Informational | Not an XSS claim at all (e.g. a known-vulnerable JS library, CWE-1104). |

Filter with `--only-poc` (e.g. `--only-poc v`, `--only-poc v,a`, `--only-poc i`).

### What `V` does not mean

`V` is **not** browser execution. Dalfox drives no browser and speaks no CDP; it never renders a page or watches an `alert()` fire. For the request-based methods, `V` means the payload was found in a *DOM tree parsed from a real HTTP response* — static analysis, on stronger evidence than the raw string match behind `R`.

There is exactly one method where Dalfox observes real execution: **out-of-band callbacks** (blind XSS). When an injected `<script src=…>` calls home, a real browser parsed and fetched it. That is empirical, and it is the strongest evidence Dalfox produces — but it comes from someone else's browser, not one Dalfox controls.

## Method: what `detection_method` means

| Value | Reads | Sends a payload? |
|-------|-------|------------------|
| `reflection` | The response body, for the payload's bytes | Yes |
| `dom-verification` | The response parsed as HTML, for an executable position | Yes |
| `ast` | The JavaScript in the response, for a source→sink flow | No |
| `oob` | An out-of-band callback from a real browser | Yes |
| `library` | `<script>` tags, for known-vulnerable versions | No |

**Use `detection_method == "ast"` — not `type == "A"` — to select AST findings.** The method field is stable; the tier is not.

### The combinations that actually occur

The tier and the method are chosen separately, so `V` does not imply
`dom-verification`. Every finding Dalfox emits is one of these:

| `type` | `detection_method` | `confidence` | `severity` | Produced by |
|--------|--------------------|--------------|------------|-------------|
| `V` | `dom-verification` | `high` | High | The dedicated DOM-verification request |
| `V` | `reflection` | `high` | High | The reflection phase, when the reflection response *already* parses to an executable position |
| `V` | `oob` | `high` | High | An out-of-band callback |
| `V` | `ast` | `high` **or** `low` | High | The two legacy AST promotions — the disagreement [Migration](#migration) is about |
| `A` | `ast` | `high` **or** `low` | Medium | Every other source→sink flow |
| `R` | `reflection` | `low` | Info | A reflection with no confirmed executable position, including the `--hpp` duplicate-parameter echo (`inject_type: inHTML-HPP`) |
| `I` | `library` | *(absent)* | Low / Medium / High | `--detect-outdated-libs` |

`V` + `reflection` is the row that surprises people. `reflection` names *which
request the evidence came from*, not how weak the evidence is: that row parsed
the same DOM the `dom-verification` row does — it just did it on a response it
already had, instead of spending another request.

### `dom-verification` evidence

Five ways a payload proves it reached an executable position: the Dalfox marker matched by CSS selector; an executable scheme (`javascript:`, `data:text/html`) in a dangerous attribute; an injected element carrying a sink-calling handler; a sink call inside `<script>` whose AST range covers the payload; and an inline-handler breakout where the payload terminated the surrounding JS string. The `evidence` field names which one fired.

### `ast` and the DOM-XSS ceiling

The AST pass parses the JavaScript in the response and traces data from a dangerous source (`location.hash`, `location.search`, `document.referrer`, `postMessage`, …) into a dangerous sink (`innerHTML`, `document.write`, `eval`, …) with no sanitizer on the path. It reads each `<script>` block once and reports every flow it finds, so it can name inputs you never passed on the command line — including a URL fragment, which is never sent to the server. `-p` does not narrow it: `-p` scopes which parameters get *requested*, and this pass sends nothing.

It also explains a result that looks like a gap but isn't. For a **pure client-side DOM-XSS**, the payload is written into the page by JavaScript at runtime, so it never appears in the server's response and the response-parsing methods have nothing to find. On a static page whose only sink is `location.hash → innerHTML`, `--only-poc v` correctly returns nothing. Open the POC URL in a browser with devtools to confirm — Dalfox prints a complete POC URL on every AST finding, plus a `[manual POC: …]` setup hint for sources it cannot put in a URL (`window.name`, `document.referrer`, cookies, `postMessage`, …).

| Flag | Effect |
|------|--------|
| `--skip-ast-analysis` | Turn off source→sink analysis |
| `--analyze-external-js` | Also fetch and analyze same-origin `<script src>` bundles |

Note that `--skip-mining-dom` does **not** affect this pass — it governs harvesting parameter *names* from HTML `id`/`name` attributes. See [Parameters & Discovery](../parameters/).

## `confidence`: the grade behind the claim

Every XSS finding carries a `confidence` of `high` or `low`, plus a `confidence_reason` naming the deciding signals. For request-based methods it follows the evidence directly. For AST findings it is graded from the flow's shape:

`high` requires **all** of:

- **A source an attacker can reach with a link** — `location.*`, `document.URL`, `URLSearchParams` carry the payload in the URL directly. Sources that would otherwise need an attacker-controlled driver page (`window.name`, `document.referrer`, `postMessage`, storage, `history.state`) grade `low` — *unless* the page seeds that source from a query parameter itself, which a link can also drive. That case grades `high` with the reason `non-URL source seeded from a query parameter by the page`.
- **A payload the page's CSP would let execute** — either inline script is permitted, or the sink runs script directly (`eval`, `Function`, `document.write`, `<script>` text) and so does not depend on inline-handler permission. A report-only CSP enforces nothing and never lowers the grade.
- **No Trusted Types interception** — `require-trusted-types-for 'script'` with a TrustedHTML-class sink grades `low`.

Sanitizers are not a grading signal because they are already a *filter*: the analyzer treats them as taint clearers, so a finding existing at all means no recognised sanitizer was on the path.

`confidence_reason` never mixes the two directions. A `high` grade lists the supporting signals; a `low` grade lists **only** what blocked it, so the signals that did hold are not shown. One reason is informational either way: `flow sits inside a conditional branch` records that the flow is guarded, and never changes the grade on its own.

### Where the grade is visible — and where it isn't

`confidence` is carried by `json`, `jsonl`, `toml`, `markdown` and `sarif`. The
default `plain` output does **not** print it, so the triage advice below assumes
a machine-readable format. Nothing else keys off it yet either: `--only-poc`,
`--limit-result-type`, the deduplication ranking, and the exit code all still
read `type`. The grade is a preview of the migration, not yet a control.

## Migration

That the grade drives nothing yet is the point: you can see where each finding will land before anything moves.

1. **Now** — `type` unchanged. `detection_method` and `confidence` are new. `type == "A"` is deprecated as a selector; use `detection_method == "ast"`.
2. **Next** — `--tier-model confidence` as an opt-in.
3. **Then** — that becomes the default, with `--tier-model legacy` as an escape hatch. `A` retires: `high` graded AST findings become `V`, the rest `R` — which is what `R` was always for. `R` is renamed in that release too: it will hold more than reflections by then, so the word stops being accurate at exactly that moment.

`--only-poc a` keeps working throughout; it selects `detection_method == "ast"` once the tier is gone. No flag value is ever removed.

During the transition `type` and `confidence` can disagree — a finding can read `type=V, confidence=low`. Two legacy code paths promote AST findings to `V` on evidence that does not support the claim; the grade reports what Dalfox can actually assert, the tier reports what it has historically emitted. The disagreement is the preview signal, not a bug.

When the tier does derive from the grade, everything that reads the tier follows it: the same `--only-poc v` selects a different set, the exit code flips on a different set, and deduplication ranks the survivors differently. That is the intended effect, not a side effect to work around.

## Reading a mixed scan

```
INF found reflected 0 params
WRN XSS found 0 XSS (+3 A)
[POC][A][GET][DOM-XSS] https://target.app/?q=%3Cimg+src%3Dx+onerror%3D…
  ├── Issue: DOM-based XSS via URLSearchParams.get(q) to innerHTML (needs runtime confirmation)
  └── Payload: q=<img src=x onerror=alert(1) class=dlx1944740c>
```

- `found reflected 0 params` — the **reflection** method found no server-side reflection. Expected on a static site.
- `XSS found 0 XSS` — the headline count is `V` only. `(+3 A)` names the other tiers printed below it.
- The `[A]` blocks come from the **ast** method, independent of both lines above.

Reading only the summary lines on a DOM-XSS target would miss every finding in the report.

### Why the tiers don't sum to what was found

Two post-processing passes run before anything is printed, so the tier counts
are not the number of findings recorded during the scan:

- **Redundant `R` collapse** — an `R` is dropped when a `V` exists for the same
  `(param, inject_type)` on that target. Reporting both would list the same
  input twice at two different strengths. `V` and `A` are never dropped.
- **AST deduplication** — the same source→sink flow can be found by the
  preflight, the probe, and the reflection loop. One survives per fingerprint:
  the strongest by `type`, then `severity`. `confidence` does not participate,
  so an ungraded `V` still outranks a `high` `A`.

`--stream-findings` emits each finding the moment it is recorded, which is
*before* the collapse. An `R` can therefore appear in the stream and be absent
from the final report. When the two disagree, the final report is the answer.

### Selecting tiers: `--only-poc` vs `--limit-result-type`

Both take `v` / `r` / `a` / `i`, and they do different things:

| Flag | Effect |
|------|--------|
| `--only-poc` | **Filters the output.** Findings of other tiers are discarded |
| `--limit-result-type` | **Counts toward `--limit`.** Findings of other tiers are still reported; they just don't consume the budget |

`--limit 2 --limit-result-type v` means "keep scanning until two `V` findings
accrue, then show everything found along the way". To actually hide the rest,
add `--only-poc v`.

### Exit codes

`0` means no findings, `1` means at least one finding **of any tier** — counted
after `--only-poc` and the collapse above — and `2` is a hard error (bad input,
every target unreachable, `--output` unwritable). A lone `R`, or a single `I`
from `--detect-outdated-libs`, exits `1` exactly like a `V` does. For CI that
should fail only on what Dalfox asserts is exploitable, run `--only-poc v`.

## Choosing flags by intent

| Goal | Flags |
|------|-------|
| Only what Dalfox asserts is exploitable | `--only-poc v` |
| Suppress static-analysis noise on a production target | `--skip-ast-analysis` |
| Skip name harvesting, keep DOM-XSS detection | `--skip-mining-dom` |
| Test one parameter, still see every DOM sink | `-p q` (AST findings are not scoped by `-p`) |
| Triage a large AST batch | `-f json`, sort on `confidence`, then read `confidence_reason` |
| Fail CI only on asserted vulnerabilities | `--only-poc v` (otherwise any tier exits `1`) |
