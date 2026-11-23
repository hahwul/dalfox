+++
title = "Detection Model"
description = "Understand Dalfox finding confidence, detection method, severity, evidence tiers, DOM verification, and AST-based XSS results."
weight = 7
toc = true
+++

Every Dalfox finding answers three separate questions. Reading them as one scale is the most common source of confusion about the output, so each one has its own field:

| Axis | Field | Question |
|------|-------|----------|
| **Confidence** | `type`: `V` / `R` | Can Dalfox claim this is a vulnerability? |
| **Method** | `detection_method` | How was it found? |
| **Impact** | `severity` | How bad is it if exploited? |

Only the first two vary independently today. For XSS findings, `severity` is a
restatement of the tier (`V` → `High`, `A` → `Medium`, `R` → `Info`), so
filtering or sorting on it tells you nothing that `type` doesn't. It carries
real information only on `I`, where it comes from the library advisory. Treat
it as a display convenience until it grades impact on its own.

`[A]` predates that split. It answers the *method* question while sitting in the `type` field, which is why nobody (including the code) could say where it belonged on the confidence scale. It is being absorbed; see [Migration](#migration) below.

This page exists because the split is not visible from the output alone. It was worked out in [issue #1238](https://github.com/hahwul/dalfox/issues/1238) with [@OSTARA711](https://github.com/OSTARA711), whose write-up is the basis for the model here.

## Confidence: what `type` means

| Tag | Name | Means |
|-----|------|-------|
| `V` | **Vulnerable** | Dalfox asserts this input is exploitable. Act on it. |
| `R` | **Reflected** | The payload came back in the response, but its position was not confirmed exploitable. Treat it as a signal and confirm it yourself. |
| `A` | AST-detected | Transitional: a method label. See [Migration](#migration). |
| `I` | Informational | Not an XSS claim (e.g. a known-vulnerable JS library, CWE-1104). |

Filter with `--only-poc` (e.g. `--only-poc v`, `--only-poc v,a`, `--only-poc i`).

### What `V` does not mean

`V` does not mean the payload ran in a browser. Dalfox drives no browser and speaks no CDP; it never renders a page or watches an `alert()` fire. For the request-based methods, `V` means the payload was found in a *DOM tree parsed from a real HTTP response*. That is static analysis, on stronger evidence than the raw string match behind `R`.

Dalfox observes real execution in only one method: out-of-band callbacks (blind XSS with `--blind-oob`). When an injected `<script src=…>` calls home, something loaded the payload and fetched it. That is almost always a victim's browser, but any correlated DNS or HTTP interaction counts, so a server-side fetcher that follows the URL triggers it too. This is empirical evidence and the strongest Dalfox produces, but it comes from a client Dalfox does not control. A plain `-b` callback URL sends the hit to your own listener, so Dalfox records no finding for it.

## Method: what `detection_method` means

| Value | Reads | Sends a payload? |
|-------|-------|------------------|
| `reflection` | The response body, for the payload's bytes | Yes |
| `dom-verification` | The response parsed as HTML, for an executable position | Yes |
| `ast` | The JavaScript in the response, for a source→sink flow | Not to find the flow; a flow found on a probe response gets one re-check request |
| `oob` | An out-of-band callback (DNS or HTTP) from whatever loaded the payload | Yes |
| `library` | `<script>` tags, for known-vulnerable versions | No |

To select AST findings, use `detection_method == "ast"`, not `type == "A"`. The method field is stable; the tier is not.

### The combinations that occur

The tier and the method are chosen separately, so `V` does not imply
`dom-verification`. In the default `legacy` model, every finding Dalfox emits is one of these:

| `type` | `detection_method` | `confidence` | `severity` | Produced by |
|--------|--------------------|--------------|------------|-------------|
| `V` | `dom-verification` | `high` or `low` | High | The dedicated DOM-verification request |
| `V` | `reflection` | `high` or `low` | High | The reflection phase, when the reflection response *already* parses to an executable position |
| `V` | `oob` | `high` | High | An out-of-band callback |
| `V` | `ast` | `high` or `low` | High | The two legacy AST promotions, which are the disagreement [Migration](#migration) is about |
| `A` | `ast` | `high` or `low` | Medium | Every other source→sink flow |
| `R` | `reflection` | `low` | Info | A reflection with no confirmed executable position, including the `--hpp` duplicate-parameter echo (`inject_type: inHTML-HPP`) |
| `I` | `library` | *(absent)* | Medium / High | `--detect-outdated-libs` |

`V` + `reflection` is the row that surprises people. `reflection` names *which
request the evidence came from*, not how weak the evidence is. That row parsed
the same DOM the `dom-verification` row does. It did so on a response it
already had instead of spending another request.

### `dom-verification` evidence

A payload can prove it reached an executable position in five ways:

- the Dalfox marker matched by CSS selector
- an executable scheme (`javascript:`, `data:text/html`, `vbscript:`) in a dangerous attribute
- an injected element whose handler (or `<script>` body) calls a sink
- a sink call inside `<script>` whose AST range covers the payload
- an inline-handler breakout, where the payload ended the surrounding JS string

The `evidence` field names the one that fired.

### What the response content type allows

The evidence has to hold in the parser a browser would use for that response, so the response's `Content-Type` decides which checks can succeed:

| Response type | How it is read |
|---------------|----------------|
| `text/html`, or no usable `Content-Type` with a body that starts like HTML | Parsed as HTML |
| `application/xhtml+xml`, `image/svg+xml`, other XML (`text/xml`, `application/xml`, `*+xml`) | Parsed as XML; only markup in an active namespace (XHTML, SVG) counts |
| JavaScript (`application/javascript`, `text/javascript`, …) | Read as script: only a JS-context payload such as a JSONP callback grades `V`, never HTML markup in the body |
| `application/json`, `*+json`, `text/csv`, supplied `text/plain`, binary media | Not a markup document: the reflection is dropped, with no `R` either |

`text/plain` is inert whether or not `X-Content-Type-Options: nosniff` is present, since a browser never sniffs a declared `text/plain` into HTML. The AST pass over the target page follows the same rule: it runs only when that page is an active markup document. One exception to the last row: a payload echoed in a redirect's `Location` header still records an `R`, whatever the body type.

### `ast` and the DOM-XSS ceiling

The AST pass parses the JavaScript in the response and traces data from a dangerous source (`location.hash`, `location.search`, `document.referrer`, `postMessage`, …) into a dangerous sink (`innerHTML`, `document.write`, `eval`, …) with no sanitizer on the path. It reads each `<script>` block once and reports every flow it finds, so it can name inputs you never passed on the command line, including a URL fragment, which is never sent to the server. `-p` does not narrow the pass over the landing page: `-p` scopes which parameters get *requested*, and that pass reads a response Dalfox already has.

This also explains a result that looks like a gap but isn't. In a pure client-side DOM-XSS, JavaScript writes the payload into the page at runtime, so it never appears in the server's response and the response-parsing methods have nothing to find. On a static page whose only sink is `location.hash → innerHTML`, `--only-poc v` correctly returns nothing. To confirm, open the POC URL in a browser with devtools. Dalfox prints a complete POC URL on every AST finding. On landing-page findings it adds a `[manual POC: …]` setup hint for sources it can't put in a URL (`window.name`, `document.referrer`, cookies, `postMessage`, …).

| Flag | Effect |
|------|--------|
| `--skip-ast-analysis` | Turn off source→sink analysis |
| `--analyze-external-js` | Also fetch and analyze same-origin `<script src>` bundles |

`--skip-mining-dom` does not affect this pass. It controls harvesting parameter *names* from the page: the `id`/`name` attributes of `<input>` elements and the query keys its scripts reference. See [Parameters & Discovery](../parameters/).

## `confidence`: the grade behind the claim

Every XSS finding carries a `confidence` of `high` or `low`, plus a `confidence_reason` naming the deciding signals. For request-based methods it follows the parser evidence and the evidence response's CSP header. A verified inline handler, inline `<script>` body or `javascript:` URL grades `low` under an enforcing CSP that blocks inline script, with reason `CSP does not permit inline script`. Known CSP-bypass candidates retain `high`. No policy, report-only policies retain the previous grade. Stored-XSS uses the retrieval response's policy. Only the grade changes under the default tier model. For AST findings it is graded from the flow's shape.

Reflected findings injected through a request header or cookie grade `low`, including `Referer` and `User-Agent`: a link or form cannot deliver the payload. The reason names the injection surface and keeps any existing low-confidence reason. Stored XSS (`--sxss`), blind/OOB, AST and informational findings are unaffected by this rule. The default `legacy` view keeps the type, severity and injection type.

`high` requires all of:

- **A source an attacker can reach with a link.** `location.*`, `document.URL`, and `URLSearchParams` carry the payload in the URL directly. Sources that would otherwise need an attacker-controlled driver page (`window.name`, `document.referrer`, `postMessage`, storage, `history.state`) grade `low`, *unless* the page seeds that source from a query parameter itself, which a link can also drive. That case grades `high` with the reason `non-URL source seeded from a query parameter by the page`.
- **A payload the page's CSP would let execute.** Either inline script is permitted, or the sink runs script directly (`eval`, `Function`, `document.write`, `<script>` text) and so does not depend on inline-handler permission. A report-only CSP enforces nothing and never lowers the grade.
- **No Trusted Types interception.** `require-trusted-types-for 'script'` with a TrustedHTML-class sink grades `low`.

Sanitizers are not a grading signal because they already act as a *filter*: the analyzer treats them as taint clearers, so if a finding exists at all, no recognised sanitizer was on the path. A sanitizer is recognised by name (`DOMPurify.sanitize`, `escapeHtml`, …). When the page itself defines a function under such a name and the analyzer can see that it hands its argument straight back, as in `function escapeHtml(s) { return s }`, the name is not taken as a sanitizer.

`confidence_reason` never mixes the two directions. A `high` grade lists the supporting signals; a `low` grade lists only what blocked it, so the signals that did hold are not shown. One reason is informational only: `flow sits inside a conditional branch` records that the flow is guarded. It appears on `high` grades and never changes the grade on its own.

### Where the grade is visible, and what reads it

`json`, `jsonl`, `toml`, `markdown`, and `sarif` carry `confidence` (with
`confidence_reason`). `plain` prints a `Confidence:` line with the grade
only. Four things act on it:

- `--min-confidence high` drops every `low` finding (every `R`, plus AST
  flows Dalfox cannot stand behind, and low-graded `V` findings such as direct
  header/cookie reflections or CSP-blocked inline payloads) before anything else sees it: output in
  every format, `--stream-findings`, per-target counts in `target_summary`,
  `--baseline`, `--limit` (the early stop and the display cut), and the exit
  code. `I` findings carry no grade (they are not XSS claims) and are always
  kept. The default, `low`, keeps everything. When it is set,
  `meta.min_confidence` reports `{level, dropped}`. `dropped` counts the whole
  run, not each target: a non-zero value says some `clean` target may have had
  its findings filtered, not which one. The same option is `min_confidence` in the config file,
  the REST API, and MCP.
- AST deduplication breaks a type + severity tie on the grade (`high` first).
- The exit code follows the filter above: a run whose only findings were
  `low` exits `0` under `--min-confidence high`.
- `--fail-on high` gates only the exit code: every finding stays in the
  report, and the run exits `1` only when one is graded `high`. `I` never
  fails it. When set, `meta.fail_on` reports `{level, matched}`. Config
  `fail_on`; CLI only, since REST and MCP have no exit code.

`--only-poc` and `--limit-result-type` select by the chosen tier model (with `a` selecting AST method under `confidence`), and SARIF
`level` still follows severity (the grade is under `properties`).

## Migration

The default tier model remains `legacy`. Opt in with `--tier-model confidence` (config, REST and MCP: `tier_model`) to derive tiers from the grade before deduplication and report filters. `high` becomes `V` / `High`, `low` becomes `R` / `Info`; `detection_method` and informational findings stay unchanged. SARIF levels follow those severities through the existing serializer.

1. **Now:** `type` is unchanged, and `detection_method` and `confidence` are available. `type == "A"` is deprecated as a selector; use `detection_method == "ast"`.
2. **Available now:** `--tier-model confidence` as an opt-in, across CLI, REST and MCP.
3. **Then:** that becomes the default, with `--tier-model legacy` as an escape hatch. `A` retires: `high`-graded AST findings become `V` and the rest become `R`, which is what `R` was always for. `R` gets a new name in that release too, because by then it will hold more than reflections.

Under `confidence`, `--only-poc a` and `--limit-result-type a` select `detection_method == "ast"`, including both mapped tiers. `--only-poc v` selects high findings; the scan-time and display limits use the same selection. Under `legacy`, the existing type selectors are unchanged.

Under `legacy`, `type` and `confidence` can disagree: a finding can read `type=V, confidence=low`. Two legacy code paths promote AST findings to `V` on evidence that does not support the claim. The grade reports what Dalfox can assert; the tier reports what it has historically emitted. The disagreement is the preview signal, not a bug.

Once the tier derives from the grade, everything that reads the tier follows it. The same `--only-poc v` selects a different set, the exit code flips on a different set, and deduplication ranks the survivors differently. That is intended.

## Reading a mixed scan

```
INF found reflected 0 params
WRN XSS found 0 XSS (+3 A)
[POC][A][GET][DOM-XSS] https://target.app/?q=%3Cimg+src%3Dx+onerror%3D…
  ├── Issue: DOM-based XSS via URLSearchParams.get(q) to innerHTML (needs runtime confirmation)
  ├── Payload: q=<img src=x onerror=alert(1) class=dlx1944740c>
  └── Confidence: high
```

- `found reflected 0 params`: the reflection method found no server-side reflection. Expected on a static site.
- `XSS found 0 XSS`: the headline count is `V` only. `(+3 A)` names the other tiers printed below it.
- The `[A]` blocks come from the ast method, independent of both lines above.

If you read only the summary lines on a DOM-XSS target, you miss every finding in the report.

### Why the tiers don't sum to what was found

Two post-processing passes run before anything is printed, so the tier counts
are not the number of findings recorded during the scan:

- **Redundant `R` collapse.** An `R` is dropped when a `V` exists for the same
  `(param, location, inject_type)` on that target. Reporting both would list the same
  input twice at two different strengths. `V` and `A` are never dropped.
- **AST deduplication.** The preflight, the probe, and the reflection loop can
  all find the same source→sink flow. One survives per fingerprint:
  the strongest by `type`, then `severity`, then `confidence`. Type comes
  first, so a `low`-confidence `V` still outranks a `high` `A`, unless
  `--min-confidence high` removed the `V` before deduplication ran. Under `confidence`, tiers are mapped first, so the high AST finding wins instead.

`--stream-findings` prints each scan-loop finding the moment it is recorded,
which is *before* the `R` collapse and before AST duplicates are narrowed to
the strongest. So an `R` can appear in the stream and be
absent from the final report. Findings from the landing-page AST pass,
outdated libraries, and OOB callbacks appear only in the final report. When the
two disagree, trust the final report.

### Selecting tiers: `--only-poc` vs `--limit-result-type`

Both select by tier, but they do different things. `--only-poc` takes a comma list (`v,r,a,i`); `--limit-result-type` takes one of `all` (the default), `v`, `r`, `a`, `i`.

| Flag | Effect |
|------|--------|
| `--only-poc` | **Filters the output.** Findings of other tiers are discarded |
| `--limit-result-type` | **Counts toward `--limit`.** Findings of other tiers are still reported; they just don't use up the budget |

`--limit 2 --limit-result-type v` means "keep scanning until two `V` findings
accrue, then show everything found along the way". To hide the rest,
add `--only-poc v`. With `--only-poc`, `--limit` counts only the tiers it
shows: a finding the report hides never stops the scan.

### Exit codes

`0` means no findings and `1` means at least one finding of any tier,
counted after `--min-confidence`, `--only-poc`, a `--baseline` filter, and the collapse above. `2`
is a hard error (bad input, every target unreachable, `--output` unwritable).
It also covers a run with no findings that could not finish cleanly: a lost
session under the default `--on-session-loss abort`, a crashed scan worker, or
severe transport loss. A lone `R`, or a single `I` from `--detect-outdated-libs`, exits `1` the same way a `V` does.
For CI that should fail only on what Dalfox asserts is exploitable, run
`--only-poc v`; to fail only on claims graded `high` and still report the rest, run `--fail-on high`.
The full rule is in [Exit codes](../output/#exit-codes).

## Choosing flags by intent

| Goal | Flags |
|------|-------|
| Only what Dalfox asserts is exploitable | `--only-poc v` |
| Suppress static-analysis noise on a production target | `--skip-ast-analysis` |
| Skip name harvesting, keep DOM-XSS detection | `--skip-mining-dom` |
| Test one parameter, still see every DOM sink | `-p q` (AST findings are not scoped by `-p`) |
| Triage a large AST batch | `-f json`, sort on `confidence`, then read `confidence_reason` |
| Fail CI only on asserted vulnerabilities | `--only-poc v` (otherwise any tier exits `1`) |
| Drop findings Dalfox cannot stand behind | `--min-confidence high` (`I` is kept) |
| Fail CI only on `high` claims, keep the rest in the report | `--fail-on high` |

CSP grading keeps existing-script JS-context evidence high. CSP meta policies (whose position relative to execution is not established) and unsupported `script-src-attr` / `script-src-elem` overrides conservatively retain high.

A matching nonce on an injected script retains high. Script hash permission and `unsafe-hashes` authorization are not resolved here and conservatively retain high.
