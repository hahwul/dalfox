# Results, Findings & Output Formats

## Finding Types (the V / A / R model)

Every finding has both a single-letter `type` and a human `type_description`.

| Type | Code | Meaning | Typical Severity | When it appears |
|------|------|---------|------------------|-----------------|
| **Verified** | `V` | Payload executed in a real DOM context (confirmed by headless or AST+verification pipeline) | High | DOM sinks (innerHTML, document.write, etc.) that actually ran |
| **AST-detected** | `A` | Static analysis of inline JavaScript found a dangerous sink with attacker-controlled data | High (if DOM-verified) / Medium | `inJS` reflections where the AST engine sees dangerous patterns |
| **Reflected** | `R` | Payload appears in the HTTP response body or headers, but execution was not confirmed | Medium / Info | Pure reflection without DOM execution path, JSON APIs, etc. |

**Agent rule**: When presenting results to the user, **lead with V, then A, then R**. Group by parameter. Always surface `type_description` alongside the letter.

## Full Finding Shape (JSON / MCP / server)

```json
{
  "type": "V",
  "type_description": "Verified DOM-based XSS",
  "inject_type": "inHTML",
  "method": "GET",
  "data": "https://target/?q=<script>alert(1)</script>",
  "param": "q",
  "payload": "<script>alert(1)</script>",
  "evidence": "...snippet...",
  "cwe": "CWE-79",
  "severity": "High",
  "message_id": 1234,
  "message_str": "Reflected XSS via parameter 'q' in HTML context",
  "message": "..."
}
```

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

- `plain` — the default one-line `[POC][V][param] ...` style
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

`--stream-findings` emits each verified finding the moment it is confirmed instead of waiting for the final summary. Useful for very long scans where you want early signal. Off by default.

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
- `1` — Scan finished with one or more findings (V/A/R)
- `2` — Hard error (bad input, config, runtime failure)

MCP and server surface the same information via `status` and `error_code` fields instead of process exit codes.

## How to Present Results to Users (agent guidance)

1. Lead with count and highest-confidence findings.
2. For each interesting finding: `type` + `type_description`, `param`, `inject_type`, short evidence, and a POC (ideally `--poc-type curl`).
3. If many R-only findings on a JSON API, explain that this is expected (no HTML DOM to verify execution).
4. Offer to re-run with `--deep-scan`, specific `--poc-type`, or WAF bypass options if the first pass was noisy or blocked.
