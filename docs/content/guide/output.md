+++
title = "Output & Reports"
description = "Export Dalfox XSS findings as plain text, JSON, JSONL, Markdown, SARIF, or TOML for CI and security pipelines."
weight = 6
toc = true
+++

Every scan produces the same internal result structure, and Dalfox renders it in the format you pick. Every format except `plain` suppresses the banner, so a report redirected to a file stays clean.

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

A finding carries these fields:

| Field | Example | Meaning |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | Finding tier: Vulnerable / AST-detected / Reflected / Informational |
| `type_description` | `"Vulnerable - dalfox asserts this input is exploitable; act on it"` | Human label (the full sentence, not the bare word) |
| `detection_method` | `"ast"` | How it was found: `reflection`, `dom-verification`, `ast`, `oob`, `library` |
| `confidence` | `"high"` | How strongly the evidence supports the claim (`high` / `low`); absent on `I` |
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
| `filter` | `{"allowed": ["/"], "blocked": ["(", ")"], "encoded": ["<", ">"]}` | How the parameter treated each probed special character: reflected raw (`allowed`), only as an HTML entity or `%HH` (`encoded`), stripped (`blocked`), backslash-escaped (`escaped`). `encoded` / `escaped` are omitted when empty. Present on reflection and DOM-verification findings; omitted when the probe gave no verdict and on AST / HPP / stored / OOB findings. Plain and Markdown show it on `R` findings only |

Three more fields appear only when asked for: `new` (under `--baseline-mode annotate`), `request` (with `--include-request`), and `response` (with `--include-response`).

What each tier is evidence of, and why a pure client-side DOM-XSS
never reaches `V`, is covered in [Detection Model](../detection-model/).

`V` / `A` / `R` are XSS findings. `I` (Informational) is a non-exploitable
observation. Today it only covers outdated or known-vulnerable JS libraries
(`inject_type: "OutdatedComponent"`, `CWE-1104`), rendered as a compact
`[INF]` line with no payload or parameter. It is opt-in: Dalfox focuses on
verified XSS by default, so library reporting stays off unless you pass
`--detect-outdated-libs`. It adds no requests; it inspects the `<script>` tags
of the preflight response. Filter it out with `--only-poc v,a,r`.

To include the full request and response:

```bash
dalfox scan https://target.app -f json --include-all -o report.json
# or one at a time:
dalfox scan https://target.app --include-request
dalfox scan https://target.app --include-response
```

The recorded request is the one Dalfox sent, verbatim, with every `-H` header
and the whole cookie jar. Check a report built with `--include-request` or
`--include-all` before you share it. On Unix, `-o` creates the file `0600` so
other local accounts can't read it, but that says nothing about where the file
goes next.

## JSON and JSONL shape

`-f json` writes one document with the envelope under `meta` and the findings under `findings`. Keys come out in alphabetical order:

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
      "filter": {
        "allowed": ["\"", "$", "'", "(", ")", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "[", "\\", "]", "`", "{", "|", "}"],
        "blocked": []
      },
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
    "dalfox_version": "3.2.4",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 1,
    "incomplete": false,
    "scan_duration_ms": 1234,
    "target_summary": [
      { "findings_count": 1, "method": "GET", "status": "findings", "target": "https://target.app/?q=a" }
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
- `targets`: the input targets as named (URLs, or the list/spec file path). A piped list reports `-` (stdin).
- `scan_duration_ms`
- `total_requests`
- `failed_requests`: requests that never got a response after their retries (reset, refused, timed out, or a body cut off mid-read), plus discovery and mining probes refused with HTTP 429. A payload that never reached the target was never tested.
- `findings_count`
- `target_summary[]`: one entry per target. A target is URL + method + request body, so `GET` and `POST` on one URL get separate entries. Each entry has `target`, `method`, `status` (`findings`, `clean`, `skipped`, or `incomplete`), and `findings_count`. It adds `error_code` when the target was skipped, its session was lost, or `--scan-timeout` cut it short (`SCAN_TIMEOUT`), and `error_message` naming the signal when a session was lost. A target that Ctrl-C, `--limit`, or `--scan-timeout` cut short is `incomplete`; only the `--scan-timeout` case has an `error_code`. When a WAF was detected, the entry also has a `waf` object: `detected[]` with `type` / `confidence` / `evidence`, plus a `bypass` block with the extra encoders, mutation counts, and requests sent / blocked while bypass was active.
- `dedup_mode` / `targets_deduplicated`: the [`--dedup-urls`](../scanning-modes/#collapsing-near-duplicate-urls) mode in effect and how many targets it collapsed, so a reduced input list is visible in the report. Markdown shows the row only when something was collapsed.
- `targets_unparsable`: only present when a target-list line could not be parsed, or an OpenAPI / Postman operation could not be built, and was skipped. See [File mode](../scanning-modes/#file-mode) and [OpenAPI / Postman mode](../scanning-modes/#openapi-postman-mode).
- `baseline`: only present when `--baseline` was used. See [Baselines](#baselines-reporting-only-what-is-new).
- `resumed`: only present when `--state-file` was used. Holds `state_file` (the path) and `targets_skipped_completed` (targets skipped because an earlier run finished them).
- `min_confidence`: only present when `--min-confidence` was set. See [Filtering](#filtering).
- `incomplete`: `true` when the run was not fully tested. That means a target's authenticated session died mid-scan (see [Session monitoring](../scanning-modes/#session-monitoring)), at least 10% of the run's requests (and at least 3) never got a response, or Ctrl-C / `--limit` / `--scan-timeout` stopped the run before every target finished. Read this one field instead of checking every `target_summary` entry. `"findings_count": 0` with `"incomplete": true` is *not* a clean result.

A target whose session died is reported as `"status": "incomplete"` (or `"skipped"` if it never ran) with `"error_code": "SESSION_LOST"` and the signal that fired in `"error_message"`. It is never reported as `"clean"`. A target that found nothing and that Ctrl-C, `--limit`, or `--scan-timeout` cut short (or that the run stopped before reaching) is also `"incomplete"`. A `--scan-timeout` cut adds `"error_code": "SCAN_TIMEOUT"`, even on a target that found something, so a batch run can tell which targets to re-run. The other causes have no `error_code`.

In SARIF the envelope is duplicated under `runs[0].properties` and `runs[0].tool.driver.properties` so GitHub code scanning and other consumers keep the context. Each result's `ruleId` is `dalfox/cwe-<n>` (`dalfox/cwe-79` for XSS, `dalfox/cwe-1104` for outdated libraries). Its `level` follows `severity` (High → `error`, Medium → `warning`, Low / Info → `note`), the PoC URL is the location `uri`, and `partialFingerprints["vulnIdentity/v1"]` is a stable hash that lets code scanning match a finding across runs. The finding fields (`type`, `inject_type`, `param`, `payload`, `severity`, `detection_method`, `confidence`, …) sit under the result's `properties`, and `message.text` carries `message_str` plus the evidence.

In TOML it appears as a top-level `[meta]` table (findings under `[[results]]`).

In Markdown it is rendered as tables (`## Scan Metadata` + `### Target Summary`) above the findings summary. Rows that only matter when something happened (failed requests, incomplete, deduplicated targets, baseline, resume, `--min-confidence`) appear only then.

Plain text output stays findings-only.

## Silence mode

`--silence` (`-S`) prints only findings on `stdout`, with no logs:

```bash
dalfox scan https://target.app --silence
# Pipe findings into another tool:
cat urls.txt | dalfox scan --silence -f jsonl | jq 'select(.severity=="High")'
```

Useful in shell pipelines and cron jobs.

## Streaming findings during long scans

By default the plain renderer prints each finding block (POC + Issue /
Payload / Line) after the end-of-scan `WRN XSS found N XSS` summary,
so the log reads in order: start → progress → summary → details.

For long scans against large targets, `--stream-findings` prints each finding
the moment it is verified, above the progress bars:

```bash
dalfox scan https://target.app --stream-findings
```

`--stream-findings` only works with the `plain` format. It is switched off
when the end-of-scan path has to apply something the streamer can't mirror:
`--output`, `--limit`, `--only-poc`, or `--baseline`. If you passed
`--stream-findings` on the command line, Dalfox prints a `Warning:` on stderr
naming the flag that switched it off.

## POC styles

Re-render the proof of concept for a different client:

```bash
dalfox scan https://target.app --poc-type curl      # curl command
dalfox scan https://target.app --poc-type httpie    # HTTPie
dalfox scan https://target.app --poc-type http-request  # raw HTTP
```

The default is `plain`. These are handy for filing tickets. `--poc-type` changes the POC line of the `plain` report only; structured formats always carry the PoC URL in `data`. `http-request` prints the raw request Dalfox recorded for the finding, and falls back to the URL when there is none.

## Filtering

Show only certain result types:

```bash
dalfox scan https://target.app --only-poc v     # only V (Vulnerable)
dalfox scan https://target.app --only-poc v,a   # V + AST
```

Drop findings Dalfox cannot stand behind (every `R`, plus `low`-graded AST flows):

```bash
dalfox scan https://target.app --min-confidence high
```

`--min-confidence high` filters by the `confidence` grade, not the tier, and
runs first: output in every format, `--stream-findings`, `target_summary`
counts, `--baseline`, `--limit` (the early stop and the display cut), and the
exit code all see the filtered set. `I` findings carry no grade and are kept.
The default `low` keeps everything. When the flag is set, the envelope carries
`meta.min_confidence: {"level": "high", "dropped": N}`. `N` counts the whole
run, not each target: a non-zero value says some `clean` target may have had
its findings filtered, not which one.

Cap the number of results:

```bash
dalfox scan https://target.app --limit 50
dalfox scan https://target.app --limit 10 --limit-result-type v
```

## Baselines: reporting only what is new

`--only-poc` and `--limit` filter by *shape*. They can't tell a finding you already triaged from one that appeared this morning. A repo with 100 known findings shows the same 100 on every pull request, so the gate is either always red or switched off.

`--baseline` solves this. Point it at a previous report and Dalfox suppresses everything already in it:

```bash
dalfox scan scope.txt -f json -o baseline.json      # once, to record the backlog
dalfox scan scope.txt --baseline baseline.json      # every run after
```

There is no separate baseline writer. An ordinary `-f json -o` (or `-f jsonl -o`) report is the baseline.

### Modes

| Mode | Flag | Behaviour |
|------|------|-----------|
| `filter` (default) | `--baseline-mode filter` | Drops known findings. Counts, `--limit`, and the exit code all describe only what is new. Use this mode for a CI gate. |
| `annotate` | `--baseline-mode annotate` | Keeps every finding and adds `new: true` / `new: false` to each, for dashboards that want the whole set with novelty marked. |

### What counts as "the same finding"

Findings are matched on a fingerprint built from the vulnerability's identity, not from the run that surfaced it:

**Included:** host + path · parameter name · parameter location (query / header / cookie / body / path) · injection context · CWE · finding tier · evidence family (the `Source → Sink` pair for DOM findings).

**Excluded:** the payload and the query string it lands in, payload ordering, AST line/column numbers, timestamps, request/response captures.

So re-running the same scan matches cleanly even though every run embeds a different payload, and a bundler that shifts `app.js` line numbers does not bring back a triaged DOM finding. The tier is part of the fingerprint, so a finding that was `R` last week and is `V` today is reported as new. That escalation is what a gate should catch.

### The `meta.baseline` block

Every structured format reports what the diff did:

```json
"baseline": {
  "baseline_findings": 100,
  "enabled": true,
  "known": 98,
  "mode": "filter",
  "new": 2,
  "path": "baseline.json"
}
```

A baseline that is missing, malformed, or written by a different major version prints a warning on stderr and disables the diff. The scan itself still runs, because a stale path in a pipeline should not turn a working scan into a red build with nothing reported. The envelope shows this case as `"enabled": false` with a `warning`, so a pipeline can tell "nothing new" from "the diff never ran".

### Refreshing the baseline

There is no special command. Re-run without `--baseline` (so the report holds the full set, not just the new findings) and replace the file:

```bash
dalfox scan scope.txt -f json -o baseline.json
git commit -am "chore: refresh dalfox baseline"
```

Running with `--baseline` and `-o` pointed at the same file destroys the baseline under `filter` mode: the report written back holds only what was new, so the next run re-reports the whole backlog. Dalfox warns when the two paths match.

### Caveats

- `--limit` counts before the diff. The scan-time stop condition counts every finding as it is collected, baseline-known ones included. So `--limit 10 --baseline b.json` against a target whose first 10 findings are all known stops early and reports 0 new without testing the rest. Drop `--limit` when gating on new findings; Dalfox warns when both are set.
- `--baseline` turns off `--stream-findings`, for the same reason `--only-poc` does. The streamer can't know a finding is already in the baseline, so it would print the whole triaged backlog live while the summary reports only the new ones.
- CLI only. `dalfox server` and the MCP server don't apply `--baseline`, and they ignore `scan.baseline` in a shared config file without a warning.

## Colour & TTY behaviour

```bash
dalfox scan https://target.app --no-color
# or
NO_COLOR=1 dalfox scan https://target.app
```

Dalfox also turns colour off when output is redirected to a file or a non-TTY.

## TOML

The same data as JSON, written as TOML. The envelope is the top-level `[meta]` table, and findings render as a `[[results]]` array of tables (`results`, not `findings` as in JSON):

```toml
[meta]
dalfox_version = "3.2.4"
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
method = "GET"
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

[results.filter]
allowed = ['"', "$", "'", "(", ")", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "[", '\', "]", "`", "{", "|", "}"]
blocked = []
```

```bash
dalfox scan https://target.app -f toml -o report.toml
```

## SARIF → GitHub code scanning

```bash
dalfox scan urls.txt -f sarif -o dalfox.sarif
```

Upload `dalfox.sarif` with GitHub's `upload-sarif` action, and findings appear in the repository's **Security → Code scanning** tab.

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

Commit `baseline.json` next to the scope file and let the exit code fail the build. The step only goes red when something appears that is not in the baseline:

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

To refresh the baseline after triage, re-run without `--baseline` and point `-o` at it:

```bash
dalfox scan scope.txt --only-poc v -f json -o .dalfox/baseline.json
```

Don't re-run the gate command above with `-o .dalfox/baseline.json`. It would write a report holding only the *new* findings over the file and wipe the recorded backlog. Dalfox warns on stderr when `--output` and `--baseline` resolve to the same path.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed, no findings |
| `1` | Completed, at least one finding of any tier |
| `2` | Input/config/runtime error, or the `-o` file could not be written. With no findings, also: every target was skipped (unreachable, wrong content type, …; this applies to `--dry-run` and `--only-discovery` too, whose JSON/JSONL list the skipped targets and their `error_code`), a target's scan worker crashed (`INTERNAL_ERROR`), at least 10% of requests (and at least 3) never got a response, or a session was lost mid-scan under the default `--on-session-loss abort`. A run that did find something still exits `1` in these cases |

`1` covers every tier. A lone `R`, or a single `I` from `--detect-outdated-libs`, fails the build the same way a `V` does. To gate on what Dalfox asserts is exploitable, run `--only-poc v` and keep using the exit code; the filter runs before the code is decided. `--min-confidence high` does the same on the confidence grade: a run whose only findings were `low` exits `0`. (Gating on `severity == "High"` with `jq` gets nearly the same set today, because severity follows the tier: `V` is `High`, `A` is `Medium`, `R` is `Info`. The exception is an `I` library finding, which carries its advisory's severity and can be `High`. See [Detection Model](../detection-model/).)

`--baseline` narrows the same code to novelty. Under the default `filter` mode, suppressed findings never reach the exit-code decision, so a run whose entire backlog is already in the baseline exits `0`. See [Baselines](#baselines-reporting-only-what-is-new).

## Next

- Automate scans with the [REST API Server](../../integrations/server/).
- Let an AI agent drive scans with the [MCP Server](../../integrations/mcp/).
