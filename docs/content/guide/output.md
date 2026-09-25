+++
title = "Output & Reports"
description = "Plain, JSON, JSONL, Markdown, SARIF, TOML, and how to integrate findings with your pipeline."
weight = 6
toc = true
+++

Every scan produces the same internal result structure. Dalfox renders it in whichever format you pick. Machine-readable formats automatically suppress the banner so your file stays clean.

## Choosing a format

```bash
dalfox scan https://target.app -f json -o report.json
```

| Format | Flag | Machine-readable | Best for |
|--------|------|------------------|----------|
| `plain` | `-f plain` (default) | No | Human terminal output |
| `json` | `-f json` | Yes | Single JSON doc, dashboards, `jq` |
| `jsonl` | `-f jsonl` | Yes | Streaming, log pipelines |
| `markdown` | `-f markdown` | No | Reports, pull-request comments |
| `sarif` | `-f sarif` | Yes | GitHub code scanning, SARIF consumers |
| `toml` | `-f toml` | Yes | Humans + pipelines |

## Writing to a file

```bash
dalfox scan https://target.app -f jsonl -o findings.jsonl
```

Without `-o`, output goes to `stdout`.

## Result fields

Every finding includes:

| Field | Example | Meaning |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | Confidence: Vulnerable / AST-detected / Reflected / Informational |
| `type_description` | `"Vulnerable - dalfox asserts this input is exploitable; act on it"` | Human label (the full sentence, not the bare word) |
| `detection_method` | `"ast"` | How it was found: `reflection`, `dom-verification`, `ast`, `oob`, `library` |
| `confidence` | `"high"` | Whether Dalfox can claim a vulnerability (`high` / `low`); absent on `I` |
| `confidence_reason` | `"URL-carried source; inline script permitted"` | The deciding signals |
| `inject_type` | `"inHTML"` | Finding label: `inHTML` for injected payloads (`sxss-inHTML` under `--sxss`, with a `-CSTI` or framework-sink suffix such as `-VHtml` when one applies), `inHTML-HPP`, `DOM-XSS` (AST), `blind-oob-<location>-<protocol>`, `OutdatedComponent` (`I`) |
| `method` | `"GET"` | HTTP method |
| `data` | `"https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E"` | The PoC URL |
| `param` | `"q"` | Parameter that was exploited |
| `location` | `"Query"` | Where the parameter travels: `Query`, `Body`, `JsonBody`, `MultipartBody`, `GraphqlBody`, `XmlBody`, `Header` (cookies included), `Path`, `Fragment`; omitted when unknown |
| `payload` | `<svg onload=alert(1)>` | The exact payload |
| `evidence` | `"DOM verification successful for param q (DOM marker)"` | Why Dalfox believes it |
| `cwe` | `"CWE-79"` | Standard CWE |
| `severity` | `"High"` | High / Medium / Low / Info |
| `message_id` | `606` | Catalog message id |
| `message_str` | `"Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>"` | Short message |

Three more fields appear only when asked for: `new` (under `--baseline-mode annotate`), `request` (with `--include-request`), and `response` (with `--include-response`).

What each tier is actually evidence of, and why a pure client-side DOM-XSS
never reaches `V`, is covered in [Detection Model](../detection-model/).

`V` / `A` / `R` are XSS findings. `I` (**Informational**) is a non-exploitable
observation — currently only **outdated / known-vulnerable JS libraries**
(`inject_type: "OutdatedComponent"`, `CWE-1104`), rendered as a compact
`[INF]` line with no payload/parameter. It is **opt-in**: Dalfox focuses on
verified XSS by default, so library reporting is off unless you pass
`--detect-outdated-libs` (it adds **0 extra requests**, inspecting the
preflight response's `<script>` tags). Filter it out with `--only-poc v,a,r`.

Optionally include the full request/response:

```bash
dalfox scan https://target.app -f json --include-all -o report.json
# or granularly:
dalfox scan ... --include-request
dalfox scan ... --include-response
```

The recorded request is the one Dalfox sent, verbatim — every `-H` header and
the whole cookie jar included. Check a report built with `--include-request` /
`--include-all` before you share it. On Unix, `-o` creates the file `0600` so
it is not readable by other local accounts, but that says nothing about where
the file goes next.

## JSON and JSONL shape

`-f json` writes one document with the envelope under `meta` and the findings under `findings`:

```json
{
  "findings": [
    {
      "confidence": "high",
      "confidence_reason": "payload reached an executable position in the parsed response",
      "cwe": "CWE-79",
      "data": "https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E",
      "detection_method": "reflection",
      "evidence": "DOM verification successful for param q (DOM marker)",
      "inject_type": "inHTML",
      "location": "Query",
      "message_id": 606,
      "message_str": "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>",
      "method": "GET",
      "param": "q",
      "payload": "<svg onload=alert(1) class=dlx1ec4110f>",
      "severity": "High",
      "type": "V",
      "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it"
    }
  ],
  "meta": {
    "dalfox_version": "3.2.3",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 1,
    "incomplete": false,
    "scan_duration_ms": 1234,
    "target_summary": [
      { "findings_count": 1, "status": "findings", "target": "https://target.app/?q=a" }
    ],
    "targets": ["https://target.app/?q=a"],
    "targets_deduplicated": 0,
    "total_requests": 87
  }
}
```

`-f jsonl` writes the same data one object per line: the first line is `{"meta": {…}}`, and every line after it is one finding. Skip the first line (or filter on a finding field, as `jq 'select(.severity=="High")'` does) when you only want findings.

## Scan metadata envelope

JSON, JSONL, SARIF, TOML, and Markdown outputs all carry the same scan-level metadata envelope:

- `dalfox_version`
- `targets` (the input targets)
- `scan_duration_ms`
- `total_requests`
- `failed_requests` — requests that never got a response (reset, refused, timed out) after their retries. A payload that never reached the target was never tested
- `findings_count`
- `target_summary[]` — one entry per target: `target`, `status` (`findings`, `clean`, `skipped`, or `incomplete`), `findings_count`, `error_code` / `error_message` when it was skipped or cut short, and a `waf` object when a WAF was detected (`detected[]` with `type` / `confidence` / `evidence`, plus a `bypass` block with the extra encoders, mutation counts, and requests sent / blocked while bypass was active)
- `dedup_mode` / `targets_deduplicated` — the [`--dedup-urls`](../scanning-modes/) mode in effect and how many targets it collapsed, so a reduced input list is visible in the report (Markdown shows the row only when something was collapsed)
- `targets_unparsable` — only when a target-list line could not be parsed and was skipped; see [File mode](../scanning-modes/)
- `baseline` — only when `--baseline` was used; see [Baselines](#baselines-reporting-only-what-is-new)
- `resumed` — only when `--state-file` was used: `state_file` (the path) and `targets_skipped_completed` (targets skipped because an earlier run finished them)
- `incomplete` — `true` when the run was **not fully tested**: a target's authenticated session died mid-scan (see [Session monitoring](../scanning-modes/)), or at least 10% of the run's requests (and at least 3) never got a response. Read this one field instead of scanning every `target_summary` entry: `"findings_count": 0` plus `"incomplete": true` is *not* a clean bill of health

A target whose session died is reported as `"status": "incomplete"` (or `"skipped"` if it never ran) with `"error_code": "SESSION_LOST"` and the signal that fired in `"error_message"` — never as `"clean"`.

In **SARIF** the envelope is duplicated under `runs[0].properties` and `runs[0].tool.driver.properties` so GitHub code scanning and other consumers retain context. Each result's `ruleId` is `dalfox/cwe-<n>` (`dalfox/cwe-79` for XSS, `dalfox/cwe-1104` for outdated libraries), its `level` follows `severity` (High → `error`, Medium → `warning`, Low / Info → `note`), the PoC URL is the location `uri`, and `partialFingerprints["vulnIdentity/v1"]` is a stable hash that lets code scanning match a finding across runs. The finding fields (`type`, `inject_type`, `param`, `payload`, `severity`, …) are under the result's `properties`.

In **TOML** it appears as a top-level `[meta]` table (findings under `[[results]]`).

In **Markdown** it is rendered as human-readable tables (`## Scan Metadata` + `### Target Summary`) above the findings summary.

Plain text output stays findings-only.

## Silence mode

Emit **only findings** on `stdout`, no logs:

```bash
dalfox scan https://target.app --silence
# Pipe findings into another tool:
cat urls.txt | dalfox scan --silence -f jsonl | jq 'select(.severity=="High")'
```

Useful in shell pipelines and cron jobs.

## Streaming findings during long scans

By default the plain renderer prints each finding block (POC + Issue /
Payload / Line) **after** the end-of-scan `WRN XSS found N XSS` summary,
so the log reads in natural order: start → progress → summary → details.

For long scans against large targets, you can flip to mid-scan emission
with `--stream-findings`. Each finding is printed the moment it is
verified, above the progress bars:

```bash
dalfox scan https://target.app --stream-findings
```

`--stream-findings` only affects the `plain` format and is auto-disabled
when the end-of-scan path needs to apply filters the streamer can't
mirror cleanly (`--output`, `--limit`, `--only-poc`, `--baseline`).

## POC styles

Re-render the proof-of-concept in different client shapes:

```bash
dalfox scan https://target.app --poc-type curl      # curl command
dalfox scan https://target.app --poc-type httpie    # HTTPie
dalfox scan https://target.app --poc-type http-request  # raw HTTP
```

Default is `plain`. Good for filing tickets. `--poc-type` changes the POC line of the `plain` report only; structured formats always carry the PoC URL in `data`. `http-request` prints the raw request Dalfox recorded for the finding, and falls back to the URL when there is none.

## Filtering

Show only certain result types:

```bash
dalfox scan https://target.app --only-poc v     # only V (Vulnerable)
dalfox scan https://target.app --only-poc v,a   # V + AST
```

Cap the number of results:

```bash
dalfox scan https://target.app --limit 50
dalfox scan https://target.app --limit 10 --limit-result-type v
```

## Baselines: reporting only what is new

`--only-poc` and `--limit` filter by *shape*. They cannot tell a finding you already triaged from one that appeared this morning, so a repo with 100 known findings shows the same 100 on every pull request and the gate is either permanently red or switched off.

`--baseline` fixes that. Point it at a previous report and Dalfox suppresses everything already in it:

```bash
dalfox scan scope.txt -f json -o baseline.json      # once, to record the backlog
dalfox scan scope.txt --baseline baseline.json      # every run after
```

There is **no separate baseline writer** — an ordinary `-f json -o` (or `-f jsonl -o`) report *is* the baseline.

### Modes

| Mode | Flag | Behaviour |
|------|------|-----------|
| `filter` (default) | `--baseline-mode filter` | Drops known findings. Counts, `--limit`, and the **exit code** all describe only what is new — this is the CI-gate mode. |
| `annotate` | `--baseline-mode annotate` | Keeps every finding and adds `new: true` / `new: false` to each, for dashboards that want the whole set with novelty marked. |

### What counts as "the same finding"

Findings are matched on a fingerprint built from the vulnerability's identity, not the run that surfaced it:

**Included:** host + path · parameter name · parameter location (query / header / cookie / body / path) · injection context · CWE · finding tier · evidence family (the `Source → Sink` pair for DOM findings).

**Excluded:** the payload and the query string it lands in, payload ordering, AST line/column numbers, timestamps, request/response captures.

So re-running the same scan matches cleanly even though every run embeds a different payload, and a bundler that shifts `app.js` line numbers does not resurrect a triaged DOM finding. Because the **tier** is part of the fingerprint, a finding that was `R` last week and is `V` today is reported as new — an escalation is exactly what a gate should catch.

### The `meta.baseline` block

Every structured format reports what the diff did:

```json
"baseline": {
  "path": "baseline.json",
  "mode": "filter",
  "enabled": true,
  "baseline_findings": 100,
  "new": 2,
  "known": 98
}
```

A baseline that is missing, malformed, or written by a different major version **warns on stderr and disables the diff** rather than failing the scan — a stale path in a pipeline should not turn a working scan into a red build with nothing reported. That case is visible in the envelope as `"enabled": false` with a `warning`, so a pipeline can tell "nothing new" apart from "the diff never ran".

### Refreshing the baseline

There is no special command. Re-run **without** `--baseline` (so the report holds the full set, not just the new findings) and replace the file:

```bash
dalfox scan scope.txt -f json -o baseline.json
git commit -am "chore: refresh dalfox baseline"
```

Running with `--baseline` and `-o` pointed at the same file destroys the baseline under `filter` mode: the report written back holds only what was new, so the next run re-reports the whole backlog. Dalfox warns when the two paths match.

### Caveats

- **`--limit` counts before the diff.** The scan-time stop condition counts every finding as it is collected, baseline-known ones included, so `--limit 10 --baseline b.json` against a target whose first 10 findings are all known halts early and reports 0 new without testing the rest. Drop `--limit` when gating on new findings; Dalfox warns when both are set.
- **`--stream-findings` is disabled by `--baseline`**, for the same reason it is disabled by `--only-poc`: the streamer cannot know a finding is already in the baseline, so it would print the whole triaged backlog live while the summary reports only the new ones.
- **CLI only.** `--baseline` is not applied by `dalfox server` or the MCP server; a shared config file's `scan.baseline` is silently ignored there.

## Colour & TTY behaviour

```bash
dalfox scan https://target.app --no-color
# or
NO_COLOR=1 dalfox scan https://target.app
```

Dalfox also auto-disables colour when output is redirected to a file or a non-TTY.

## TOML

Same data shape as JSON (plus top-level `[meta]` envelope for parity with other formats), written as TOML. Findings render as a `[[results]]` array of tables:

```toml
[meta]
dalfox_version = "3.2.3"
dedup_mode = "exact"
failed_requests = 0
findings_count = 1
incomplete = false
scan_duration_ms = 1234
targets = ["https://target.app/?q=a"]
targets_deduplicated = 0
total_requests = 87

[[meta.target_summary]]
findings_count = 1
status = "findings"
target = "https://target.app/?q=a"

[[results]]
type = "V"
type_description = "Vulnerable - dalfox asserts this input is exploitable; act on it"
inject_type = "inHTML"
method = "GET"
data = "https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E"
param = "q"
payload = "<svg onload=alert(1) class=dlx1ec4110f>"
evidence = "DOM verification successful for param q (DOM marker)"
cwe = "CWE-79"
severity = "High"
message_id = 606
message_str = "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>"
location = "Query"
detection_method = "reflection"
confidence = "high"
confidence_reason = "payload reached an executable position in the parsed response"
```

```bash
dalfox scan https://target.app -f toml -o report.toml
```

## SARIF → GitHub code scanning

```bash
dalfox scan urls.txt -f sarif -o dalfox.sarif
```

Upload `dalfox.sarif` through GitHub's `upload-sarif` action, and findings appear in the repository's **Security → Code scanning** tab.

## CI example

```yaml
# .github/workflows/xss-scan.yml
- name: Dalfox scan
  run: dalfox scan scope.txt -f sarif -o dalfox.sarif --silence --waf-evasion

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dalfox.sarif
```

### Gating on new findings only

Commit `baseline.json` alongside the scope file and let the exit code fail the build. The step only goes red when something appeared that is not in the baseline:

```yaml
# .github/workflows/xss-scan.yml
- name: Dalfox scan (new findings gate)
  run: |
    dalfox scan scope.txt \
      --baseline .dalfox/baseline.json \
      --only-poc v \
      -f json -o dalfox.json --silence

- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: dalfox-report
    path: dalfox.json
```

To refresh the baseline after triage, re-run **without** `--baseline` and point `-o` at it:

```bash
dalfox scan scope.txt --only-poc v -f json -o .dalfox/baseline.json
```

Re-running the gate command above with `-o .dalfox/baseline.json` would write a report containing only the *new* findings over the file and wipe the recorded backlog — Dalfox warns on stderr when `--output` and `--baseline` resolve to the same path.

## Exit codes

Dalfox returns:

| Code | Meaning |
|------|---------|
| `0` | Completed successfully, no findings |
| `1` | Completed successfully, at least one finding **of any tier** |
| `2` | Input/config/runtime error, or the `-o` file could not be written. With no findings, also: every target was skipped (unreachable, wrong content type, …), a target's scan worker crashed (`INTERNAL_ERROR`), at least 10% of requests (and at least 3) never got a response, or a session was lost mid-scan under the default `--on-session-loss abort` (a run that did find something still exits `1`) |

`1` covers every tier — a lone `R`, or a single `I` from `--detect-outdated-libs`, fails the build exactly like a `V` does. To gate on what Dalfox asserts is exploitable, run `--only-poc v` and keep using the exit code; it filters before the code is decided. (Gating on `severity == "High"` with `jq` reaches nearly the same set today, because severity currently tracks the tier: `V` is `High`, `A` is `Medium`, `R` is `Info`. The exception is an `I` library finding, which carries its advisory's severity and can be `High`. See [Detection Model](../detection-model/).)

`--baseline` narrows the same code to *novelty*: under the default `filter` mode, suppressed findings never reach the exit-code decision, so a run whose entire backlog is already in the baseline exits `0`. See [Baselines](#baselines-reporting-only-what-is-new).

## Next

- Automate scans via the [REST API Server](../../integrations/server/).
- Let an AI driver handle it with the [MCP Server](../../integrations/mcp/).
