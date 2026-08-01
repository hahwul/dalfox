# Results, Findings & Output Formats

## Finding Types (the V / A / R / I model)

A finding answers three separate questions in three separate fields. Reading
them as one scale is the most common way agents misreport dalfox output.

| Axis | Field | Question |
|------|-------|----------|
| Confidence | `type` | Can dalfox claim this is a vulnerability? |
| Method | `detection_method` | How was it found? |
| Impact | `severity` | How bad is it if exploited? (today: derived from the tier) |

### `type` — the claim

| Type | Code | Meaning | When it appears |
|------|------|---------|-----------------|
| **Vulnerable** | `V` | Dalfox asserts the input is exploitable — act on it | Payload reached an executable position in a parsed response, or an out-of-band callback fired |
| **AST-detected** | `A` | Static JS analysis found a source→sink flow. A *method* label, not a confidence level | `location.hash` → `innerHTML` and friends, including sources never sent to the server |
| **Reflected** | `R` | Payload came back in the response, but its position was not confirmed exploitable. A signal, not a claim | Reflection without a confirmed executable position — JSON APIs, escaped echoes |
| **Informational** | `I` | Not an XSS claim at all | Known-vulnerable JS library (CWE-1104), opt-in via `--detect-outdated-libs` |

**`V` is not browser execution.** Dalfox drives no browser and speaks no CDP —
that is a deliberate v3 design decision, not a gap. For request-based methods
`V` means the payload was found in a DOM tree *parsed from a real HTTP
response*. The one exception is `detection_method: "oob"` (blind XSS): a real
browser fetched the injected script, which is the strongest evidence dalfox
produces. Never tell a user dalfox "watched an alert fire".

### `detection_method` — how it was found

| Value | Reads | Sends a payload? |
|-------|-------|------------------|
| `reflection` | The response body, for the payload's bytes | Yes |
| `dom-verification` | The response parsed as HTML, for an executable position | Yes |
| `ast` | The JavaScript in the response, for a source→sink flow | No |
| `oob` | An out-of-band callback from a real browser | Yes |
| `library` | `<script>` tags, for known-vulnerable versions | No |

**Select AST findings with `detection_method == "ast"`, not `type == "A"`.**
The method field is stable; the `A` tier is being absorbed into the confidence
axis (issue #1238).

### `confidence` — the grade behind the claim

Every XSS finding carries `confidence` (`"high"` / `"low"`) plus a
`confidence_reason` naming the deciding signals. It is absent on `I`.

During the tier migration `type` and `confidence` can legitimately disagree
(`type: "V"`, `confidence: "low"` from two legacy AST promotions). That is the
preview signal, not a bug. `confidence` does not yet drive filtering, ordering,
dedup, or exit codes — those still key off `type`.

**Agent rule**: lead with V, then A, then R. Within a large `A` batch, sort on
`confidence` and read `confidence_reason`. Group by parameter. Always surface
`type_description` alongside the letter, and never upgrade `A`/`R` to
"confirmed" language.

## Full Finding Shape (JSON / MCP / server)

```json
{
  "type": "V",
  "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it",
  "detection_method": "dom-verification",
  "confidence": "high",
  "confidence_reason": "DOM verification confirmed an executable position (DOM marker)",
  "inject_type": "inHTML",
  "method": "GET",
  "data": "https://target/?q=<script>alert(1)</script>",
  "param": "q",
  "payload": "<script>alert(1)</script>",
  "evidence": "DOM verification successful for param q (DOM marker)",
  "cwe": "CWE-79",
  "severity": "High",
  "message_id": 606,
  "message_str": "Triggered XSS Payload (DOM marker): q=<script>alert(1)</script>",
  "location": "Query"
}
```

`type_description` is the **long** form shown above, not the bare word. There is
no `message` field. `confidence` / `confidence_reason` / `location` are omitted
when unset. `request` / `response` appear only under the opt-in flags below.

### inject_type values (reflection context, not parameter location)

- `inHTML` — inside HTML text / tag content
- `inJS` — inside a script block or event handler
- `inATTR` — inside an attribute value
- `inURL` — inside a URL attribute (href, src, etc.)
- `inCSS` — inside style / CSS context (rare)

For the **parameter location** (query / body / header / cookie / path / JSON), look at the `data` field (the actual probed URL) + `method`.

## Output Formats (`--format`)

| Format | Best for | Notes |
|--------|----------|-------|
| `plain` (default) | Human reading, interactive | Color + banner unless silenced |
| `json` | Parsing, piping, server/MCP | Full envelope with `meta.target_summary` |
| `jsonl` | Streaming / log ingestion | One finding per line + final meta line |
| `markdown` | Reports, PR comments | Human-friendly with sections |
| `sarif` | GitHub Code Scanning, SARIF tools | Standard static-analysis interchange |
| `toml` | Config-like consumption | Rarely used |

**Machine-readable formats** (`json`, `jsonl`, `sarif`, `toml`) automatically suppress the banner so stdout stays parseable.

## POC Output (`--poc-type`)

- `plain` — the default one-line `[POC][V][GET][inHTML] https://…` style
  (`[POC][type][method][location hint][inject_type] url`; the location hint
  appears only for non-query params, e.g. `[hdr]`)
- `curl` — ready-to-run `curl '...'` command
- `httpie` — `http GET '...'` style
- `http-request` — raw HTTP request text

Use `--poc-type curl` (or httpie) when the user wants something they can copy-paste immediately.

## Request / Response Inclusion (strict opt-in)

**AGENTS.md invariant**:
- `--include-request` and `--include-response` are **opt-in only**.
- `--include-all` is the convenience flag that sets both.
- These fields are intentionally **not** on by default because responses can be enormous and may contain sensitive data.

Never turn them on "just in case" during automated scans. Only enable when the user explicitly needs forensic evidence.

In MCP: `include_request` / `include_response` default to `false` and must be set explicitly.

## Dry-run warnings (CLI)

`--dry-run` with `--format json` / `jsonl` may include `meta.warnings` (string array). Codes agents should watch for:

| Code prefix | Meaning |
|-------------|---------|
| `EXPLICIT_PARAM_NOT_SEEDED` | One or more `-p` specs could not be seeded (typically `path` / `fragment` / unknown type). Fix: use a synthesizable `name:location` such as `q:query`. |
| `EXPLICIT_PARAM_EMPTY` | `-p` was set but zero scannable params remained after analysis. |

Plain dry-run prints the same warnings under a `Warnings:` section.

## Streaming Findings

`--stream-findings` emits each finding the moment it is recorded instead of
waiting for the final summary. Useful for very long scans where you want early
signal. Off by default, plain format only, and auto-disabled with `--output`,
`--limit`, or `--only-poc`.

**Caveat**: streaming happens *before* end-of-target post-processing, so an `R`
finding can appear in the stream and then be absent from the final report — a
`V` on the same `(param, inject_type)` collapses it (see below). Report the
final results, not the stream, when the two disagree.

## Why the counts don't add up

Two post-processing passes run before output, so summed tiers are not the number
of findings recorded during the scan:

- **Redundant `R` collapse** — an `R` is dropped when a `V` exists for the same
  `(param, inject_type)` on that target. `V` and `A` are never dropped.
- **AST dedup** — one finding per equivalent AST fingerprint survives, the
  strongest by `type` then `severity`. `confidence` does not participate.

The plain headline `XSS found N XSS` counts `V` only; other tiers are appended
as `(+3 A, 1 R)` so the number agrees with the POC blocks printed under it.

## Baselines (`--baseline`)

`--baseline prev.json` suppresses findings already present in a previous
dalfox JSON/JSONL report, so a run reports only what is new. There is no
separate baseline writer — an ordinary `-f json -o` report is the baseline.

- `--baseline-mode filter` (default) drops known findings **before** `--limit`,
  the per-target summary, and the exit code, which is what makes it usable as a
  CI gate: a run whose whole backlog is in the baseline exits `0`.
- `--baseline-mode annotate` keeps everything and adds `new: true`/`new: false`
  to each finding instead.
- Matching is by vulnerability identity — host + path, parameter name and
  location, injection context, CWE, tier, and (for DOM findings) the
  source→sink pair. The payload, the query string carrying it, AST line/column
  numbers, and request/response captures are excluded, so ordinary run-to-run
  variation does not read as new. Because the tier participates, an `R` that
  becomes a `V` **is** reported as new.
- A missing, malformed, or foreign-major-version baseline warns on stderr and
  disables the diff rather than failing the scan. The `meta.baseline` block
  reports `"enabled": false` with a `warning` in that case — check it before
  reading "0 findings" as "nothing new".

## Error Codes (appear in JSON `meta`, MCP, server)

See `cmd/mod.rs` for the canonical list. Common ones:

- `NO_TARGETS`, `NO_FILE`, `INVALID_INPUT_TYPE`
- `PARSE_ERROR`, `FILE_READ_ERROR`, `STDIN_ERROR`
- `INPUT_TOO_LARGE`, `STDIN_NOT_PIPED`
- `CONNECTION_FAILED`, `DNS_RESOLUTION_FAILED`, `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`
- `CONTENT_TYPE_MISMATCH`
- `TRUNCATED_PER_HOST_CAP`

In JSON output the per-target summary contains `error_code` when the target failed before any payloads were sent.

## Exit Codes (CLI)

- `0` — Scan finished cleanly, zero findings
- `1` — Scan finished with one or more findings **of any tier**, counted after
  `--only-poc` and dedup. A lone `R`, or a single `I` from
  `--detect-outdated-libs`, exits `1` just like a `V` does. For CI that should
  fail only on asserted vulnerabilities, run `--only-poc v`
- `2` — Hard error (bad input, config, runtime failure, every target
  unreachable, or `--output` could not be written)

With `--baseline` (default `filter` mode), suppressed findings never reach the
exit-code decision, so the code reports novelty rather than the whole backlog.

MCP and server surface the same information via `status` and `error_code` fields instead of process exit codes.

## How to Present Results to Users (agent guidance)

1. Lead with count and highest-confidence findings.
2. For each interesting finding: `type` + `type_description`, `param`, `inject_type`, short evidence, and a POC (ideally `--poc-type curl`).
3. If many R-only findings on a JSON API, explain that this is expected (no HTML DOM to verify execution).
4. `A` findings need manual confirmation — open the POC URL in a browser with
   devtools. A pure client-side DOM-XSS never reaches `V`: the payload is
   written by JavaScript at runtime, so it is not in the server's response for
   the response-parsing methods to find. `--only-poc v` returning nothing on
   such a target is correct behavior, not a miss.
5. Describe `V` as "dalfox asserts this is exploitable", never as "dalfox saw it
   execute" — except for `detection_method: "oob"`, where a real browser did
   fetch the payload.
6. Offer to re-run with `--deep-scan`, specific `--poc-type`, or WAF bypass options if the first pass was noisy or blocked.
