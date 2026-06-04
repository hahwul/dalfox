+++
title = "Output & Reports"
description = "Plain, JSON, JSONL, Markdown, SARIF, TOML, and how to integrate findings with your pipeline."
weight = 6
toc = true
+++

Every scan produces the same internal result structure. Dalfox renders it in whichever format you pick. Machine-readable formats automatically suppress the banner so your file stays clean.

## Choosing a format

```bash
dalfox https://target.app -f json -o report.json
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
dalfox https://target.app -f jsonl -o findings.jsonl
```

Without `-o`, output goes to `stdout`.

## Result fields

Every finding includes:

| Field | Example | Meaning |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | Verified / AST-detected / Reflected / Informational |
| `type_description` | `"Verified"` | Human label |
| `inject_type` | `"inHTML"` | Context (`inHTML`, `inAttr`, `inJS`, …) |
| `method` | `"GET"` | HTTP method |
| `param` | `"q"` | Parameter that was exploited |
| `payload` | `<svg/onload=alert(1)>` | The exact payload |
| `evidence` | `"payload reflected in response"` | Why Dalfox believes it |
| `cwe` | `"CWE-79"` | Standard CWE |
| `severity` | `"High"` | High / Medium / Low / Info |
| `message_str` | `"XSS found"` | Short message |

`V` / `A` / `R` are XSS findings. `I` (**Informational**) is a non-exploitable
observation — currently only **outdated / known-vulnerable JS libraries**
(`inject_type: "OutdatedComponent"`, `CWE-1104`), rendered as a compact
`[INF]` line with no payload/parameter. It is **opt-in**: Dalfox focuses on
verified XSS by default, so library reporting is off unless you pass
`--detect-outdated-libs` (it adds **0 extra requests** — it inspects the
preflight response's `<script>` tags). Filter it out with `--only-poc v,a,r`.

Optionally include the full request/response:

```bash
dalfox https://target.app -f json --include-all -o report.json
# or granularly:
dalfox ... --include-request
dalfox ... --include-response
```

## Scan metadata envelope

JSON, JSONL, SARIF, TOML, and Markdown outputs now all carry the same scan-level metadata envelope (previously JSON/JSONL only; see [#1093](https://github.com/hahwul/dalfox/issues/1093)):

- `dalfox_version`
- `targets` (the input targets)
- `scan_duration_ms`
- `total_requests`
- `findings_count`
- `target_summary[]` — per-target status, findings count, error_code (if skipped), and WAF/bypass details when detected

In **SARIF** the envelope is duplicated under `runs[0].properties` and `runs[0].tool.driver.properties` so GitHub code scanning and other consumers retain context.

In **TOML** it appears as a top-level `[meta]` table (findings under `[[results]]`).

In **Markdown** it is rendered as human-readable tables (`## Scan Metadata` + `### Target Summary`) above the findings summary.

Plain text output remains findings-focused only.

## Silence mode

Emit **only findings** on `stdout`, no logs:

```bash
dalfox https://target.app --silence
# Pipe findings into another tool:
cat urls.txt | dalfox --silence -f jsonl | jq 'select(.severity=="High")'
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
dalfox https://target.app --stream-findings
```

`--stream-findings` only affects the `plain` format and is auto-disabled
when the end-of-scan path needs to apply filters the streamer can't
mirror cleanly (`--output`, `--limit`, `--only-poc`).

## POC styles

Re-render the proof-of-concept in different client shapes:

```bash
dalfox https://target.app --poc-type curl      # curl command
dalfox https://target.app --poc-type httpie    # HTTPie
dalfox https://target.app --poc-type http-request  # raw HTTP
```

Default is `plain`. Good for filing tickets.

## Filtering

Show only certain result types:

```bash
dalfox https://target.app --only-poc v     # only verified
dalfox https://target.app --only-poc v,a   # verified + AST
```

Cap the number of results:

```bash
dalfox https://target.app --limit 50
dalfox https://target.app --limit 10 --limit-result-type v
```

## Colour & TTY behaviour

```bash
dalfox https://target.app --no-color
# or
NO_COLOR=1 dalfox https://target.app
```

Dalfox also auto-disables colour when output is redirected to a file or a non-TTY.

## TOML

Same data shape as JSON (plus top-level `[meta]` envelope for parity with other formats), written as TOML. Findings render as a `[[results]]` array of tables:

```toml
[meta]
dalfox_version = "3.x"
targets = ["https://target.app"]
scan_duration_ms = 1234
total_requests = 87
findings_count = 1
target_summary = [{ target = "https://target.app", status = "findings", findings_count = 1 }]

[[results]]
type = "V"
type_description = "Verified"
inject_type = "inHTML"
method = "GET"
data = "https://target.app/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E"
param = "q"
payload = "<svg/onload=alert(1)>"
evidence = "payload reflected and DOM element verified"
location = "Query"
cwe = "CWE-79"
severity = "High"
message_id = 606
message_str = "XSS found"
```

```bash
dalfox https://target.app -f toml -o report.toml
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

## Exit codes

Dalfox returns:

| Code | Meaning |
|------|---------|
| `0` | Completed successfully, no findings |
| `1` | Completed successfully, at least one finding |
| `2` | Input/config/runtime error |

Use `1` as a CI gate only if you're comfortable failing the build on any finding. Most teams gate on `severity >= High` using `jq` on JSON output.

## Next

- Automate scans via the [REST API Server](../../integrations/server/).
- Let an AI driver handle it with the [MCP Server](../../integrations/mcp/).
