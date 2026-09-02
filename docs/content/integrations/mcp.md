+++
title = "MCP Server"
description = "Expose Dalfox to Claude and other MCP clients as a set of scanner tools."
weight = 2
toc = true
+++

The **Model Context Protocol** (MCP) is an open standard for letting AI clients talk to external tools. `dalfox mcp` runs a stdio-based MCP server so Claude Desktop, Claude Code, Cursor, and any other MCP-compatible client can drive Dalfox scans directly.

## Starting the server

```bash
dalfox mcp
```

The server speaks MCP over `stdin`/`stdout`. Launch it from the client; you don't run it manually in a terminal.

## Claude Desktop config

Add Dalfox to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dalfox": {
      "command": "dalfox",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Desktop. Dalfox appears as a tool-provider named `dalfox`.

## Claude Code (and other CLIs)

```bash
claude mcp add dalfox -- dalfox mcp
```

## Available tools

Six tools are exposed. All are async and non-blocking: submit a scan, poll for results, then move on.

### `scan_with_dalfox`

Submit a scan. Returns immediately.

```json
{
  "target": "https://example.com/search?q=test",
  "method": "GET",
  "param": ["q"],
  "headers": ["Authorization: Bearer token"],
  "encoders": ["url", "html"],
  "timeout": 10,
  "scan_timeout": 0,
  "workers": 50,
  "rate_limit": 0,
  "insecure": true,
  "blind_callback_url": "https://callback.example",
  "deep_scan": false,
  "skip_ast_analysis": false,
  "analyze_external_js": false,
  "detect_outdated_libs": false
}
```

`encoders` accepts any combination of the implemented payload encoders:
`url`, `html`, `htmlpad`, `2url`, `3url`, `4url`, `base64`, `unicode`,
`zwsp`. The example above shows `["url", "html"]`; add more to increase
mutation coverage. Order does not matter. The scanner applies encoders
in a fixed priority order (`url` → `html` → `htmlpad` → `2url` → `3url`
→ `4url` → `base64` → `unicode` → `zwsp`) and de-duplicates the output.
Use `["none"]` to disable encoding entirely. Mirrors the `--encoders` /
`-e` CLI flag. An unknown encoder name is rejected outright — it would
otherwise match nothing and quietly shrink the scan's payload coverage.

`method` is validated against the same verb set the CLI accepts and is
uppercased for you (`"post"` → `"POST"`). Sending an unsupported verb is an
error rather than a scan that puts the wrong method on the wire.

`blind_callback_url` must be empty (meaning "no blind XSS") or start with
`http://` / `https://`. Setting it arms *stored* blind-XSS injection —
`<script src=...>` payloads are written into every query, body, header and
cookie parameter and stay in the target — so a value that could never receive
a callback is rejected outright rather than leaving those payloads behind for
nothing. `remote_payloads` / `remote_wordlists` are likewise checked against
the registered providers, because an unrecognized name would silently fetch
nothing and let the scan report `done` with the payload coverage the caller
asked for quietly missing.

`insecure` controls TLS certificate validation (default `true`, scanner-friendly):
set it `false` to enforce certificate validation and reject self-signed or
expired certs. Mirrors the `--insecure` CLI flag.

`analyze_external_js` is opt-in (default `false`): set it `true` to fetch
same-origin `<script src>` bundles at preflight time and run AST DOM-XSS
analysis on them. Useful for SPAs where all sink logic lives in external
bundles and the page has no server-side reflection. Caps: 16 files,
512 KiB per file; honours `include_url`/`exclude_url` filters.

`detect_outdated_libs` is opt-in (default `false`): set it `true` to also emit
informational `[I]` findings for outdated / known-vulnerable JS libraries
(CWE-1104, 0 extra requests). Left off, the scan reports only XSS.

`rate_limit` caps the scan's outbound requests/second (`0` = unlimited, the
default), now enforced across all worker tasks — use it to be gentle on a
fragile target or to stay under a WAF threshold.

`scan_timeout` is the whole-scan wall-clock budget in seconds (default `0` =
unbounded), distinct from the per-request `timeout`. When it trips, the scan
stops, keeps any partial findings, and settles as `cancelled` with an
`error_message` mentioning `scan_timeout`. Set it to bound long or `deep_scan`
runs so an agent's poll loop is guaranteed to terminate.

The block above is an excerpt. Every field the tool accepts, with its default —
`target` is the only required one:

```json
{
  "target": "https://example.com/search?q=test",
  "param": [],
  "method": "GET",
  "data": null,
  "headers": [],
  "cookies": [],
  "user_agent": null,
  "encoders": ["url", "html"],
  "timeout": 10,
  "scan_timeout": 0,
  "delay": 0,
  "follow_redirects": false,
  "insecure": true,
  "proxy": null,
  "include_request": false,
  "include_response": false,
  "skip_mining": false,
  "skip_discovery": false,
  "deep_scan": false,
  "skip_ast_analysis": false,
  "analyze_external_js": false,
  "detect_outdated_libs": false,
  "blind_callback_url": null,
  "workers": 50,
  "rate_limit": 0,
  "waf_bypass": "auto",
  "skip_waf_probe": false,
  "force_waf": null,
  "waf_evasion": false,
  "waf_min_confidence": 0.3,
  "remote_payloads": [],
  "remote_wordlists": [],
  "max_payloads_per_param": 0,
  "wait": false,
  "wait_timeout_sec": 300
}
```

`data` is the request body for `POST`/`PUT`, either form-urlencoded
(`"user=admin&pass=test"`) or a JSON string. `cookies` takes `"name=value"`
entries, `headers` takes full `"Name: Value"` lines, and `user_agent` overrides
the `User-Agent` header.

`delay` (default `0`, range `0`–`9999`) waits that many milliseconds between
requests, `follow_redirects` (default `false`) makes the scanner follow `3xx`
responses, and `proxy` routes every request through an HTTP or SOCKS proxy
(`"http://127.0.0.1:8080"`).

`include_request` and `include_response` (both default `false`) attach the raw
HTTP request text and the raw response body to each finding for forensic
analysis. Opt in only when you need the evidence — responses can be large.

The five WAF fields mirror the CLI's WAF flags. `waf_bypass` picks the handling
mode: `"auto"` (detect then bypass, the default), `"force"` (use `force_waf`),
or `"off"` (detect only). `skip_waf_probe` (default `false`) skips the WAF
fingerprinting probe entirely. `force_waf` pins a specific WAF profile (e.g.
`"cloudflare"`, `"akamai"`, `"modsec"`) instead of detecting one. `waf_evasion`
(default `false`) turns on adaptive evasion. `waf_min_confidence` is the
detection confidence floor in `[0.0, 1.0]` (default `0.3`); fingerprints below
it are dropped. Unknown values for `waf_bypass` or `force_waf`, and a
`waf_min_confidence` outside the range, are rejected as `invalid_params`.

`remote_payloads` and `remote_wordlists` (both default `[]`) fetch extra XSS
payloads (`"portswigger"`, `"payloadbox"`) and parameter wordlists (`"burp"`,
`"assetnote"`) from remote providers before the scan starts.

`max_payloads_per_param` caps how many payloads each parameter is tested with
(default `0` = unlimited aside from the built-in safety cap). Use a small value
such as `10`–`50` for agent smoke scans.

`wait` (default `false`) turns the call into a blocking one: instead of
returning `{scan_id, status: "queued"}` right away, it blocks until the scan is
`done` / `error` / `cancelled` and returns the same shape as
`get_results_dalfox`. `wait_timeout_sec` (default `300`, range `1`–`86400`) is
the wall-clock budget for that wait and is ignored when `wait` is `false`; on
timeout the job keeps running and the response carries `wait_timed_out: true`.

Response:

```json
{ "scan_id": "9f2c…", "target": "https://example.com/search?q=test", "status": "queued" }
```

### `get_results_dalfox`

Poll a scan. Returns status, progress, and results when ready.

```json
{ "scan_id": "9f2c…" }
```

Response (in progress):

```json
{
  "scan_id": "9f2c…",
  "target": "…",
  "status": "running",
  "progress": {
    "params_total": 10,
    "params_tested": 4,
    "requests_sent": 215,
    "findings_so_far": 1,
    "estimated_completion_pct": 40,
    "suggested_poll_interval_ms": 3000
  }
}
```

Response (done):

```json
{
  "scan_id": "9f2c…",
  "status": "done",
  "results": [
    {
      "type": "V",
      "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it",
      "detection_method": "dom-verification",
      "confidence": "high",
      "confidence_reason": "DOM verification confirmed an executable position (DOM marker)",
      "inject_type": "inHTML",
      "method": "GET",
      "param": "q",
      "payload": "<svg/onload=alert(1)>",
      "evidence": "DOM verification successful for param q (DOM marker)",
      "cwe": "CWE-79",
      "severity": "High"
    }
  ]
}
```

Every response carrying findings also carries an `_untrusted_content_notice`,
serialized as the first key so an agent reads the warning before the content it
warns about. The `evidence`, `response`, `request`, `payload`, `param`,
`location` and `message_str` fields quote bytes the scan target chose, and the
target is the thing being tested — so an agent must read them as data to report
on, never as instructions. A scanned page can embed text shaped like a directive addressed
to the model, and acting on it would let the target pick the `target`, `proxy`,
`blind_callback_url` or `include_*` of the next call. `preflight_dalfox`
attaches the same notice when it discovered parameters, since the `name` of each
discovered parameter is lifted out of the target's own markup.

`offset` and `limit` page through large result sets, and `pagination` reports
`{total, offset, limit, returned, has_more}`. A page is additionally capped at
4 MiB of findings: the target decides how many findings a scan produces, and
each one can carry 64 KiB of `evidence` plus 64 KiB of `response`. When the
budget cuts a page short, `pagination` adds `truncated_by_size: true` and
`max_page_bytes` — fewer findings came back than `limit` asked for, and the
rest are still there at the next `offset`. A single finding larger than the
budget is emitted alone rather than dropped, so paging always advances.

`progress.estimated_completion_pct` and `params_tested` advance live as each
discovered parameter finishes (they no longer sit at 0 until the scan ends), so
they are usable for pacing polls — honor `suggested_poll_interval_ms`.

If the target can't be reached (DNS failure, connection refused, TLS error,
timeout) the scan ends as `status: "error"` with `error_message` containing
`CONNECTION_FAILED`, rather than `done` with an empty `results` — the same
distinction `preflight_dalfox` reports via `reachable: false`. The `target`
must start with `http://` or `https://`.

A scan whose **authenticated session dies mid-run** ends the same way. When the
call carries credentials (`cookies`, or a `Cookie` / `Authorization` entry in
`headers`), Dalfox fingerprints the authenticated response before scanning and
re-checks it at the end; if the session expired in between, the scan settles
`status: "error"` with an `error_message` beginning `SESSION_LOST:` instead of
`done` with an empty `results`. Do not summarize such a scan as "no XSS found" —
nothing was really tested. Monitoring costs nothing when no credentials are
passed.

### `list_scans_dalfox`

List every tracked scan. Optional filter:

```json
{ "status": "running" }
```

Returns `total`, `scans: [{scan_id, target, status, result_count}]`.

### `cancel_scan_dalfox`

Abort a queued or running scan:

```json
{ "scan_id": "9f2c…" }
```

### `delete_scan_dalfox`

Permanently remove a tracked scan from memory. Only terminal scans (`done`, `error`, `cancelled`) can be deleted; running or queued scans must be cancelled first. Terminal scans are also auto-purged after 1 hour.

```json
{ "scan_id": "9f2c…" }
```

Returns `{scan_id, deleted: true, previous_status}`.

### `preflight_dalfox`

Analyse a target **without** sending payloads. Useful for scoping before committing to a scan.

```json
{
  "target": "https://example.com",
  "method": "GET",
  "skip_discovery": false,
  "skip_mining": false,
  "encoders": ["url", "html"],
  "max_payloads_per_param": 0,
  "deep_scan": false
}
```

Returns reachability, discovered parameters, and an estimated request count.

`encoders`, `max_payloads_per_param` and `deep_scan` send nothing themselves — they describe the `scan_with_dalfox` call you are sizing, so `estimated_total_requests` reflects that scan's fan-out. Pass the same values you intend to scan with.

The estimate counts both phases the scan runs per parameter — reflection and DOM verification — each truncated to the per-parameter payload cap, matching `--dry-run`. It remains a lower bound: WAF mutation/encoder expansion and the shared CSP/tech payloads appended after the cap are not counted.

## Typical agent flow

1. Agent calls `preflight_dalfox` to confirm the target and count parameters.
2. Agent calls `scan_with_dalfox`, receives a `scan_id`.
3. Agent polls `get_results_dalfox` using `suggested_poll_interval_ms` from the progress object.
4. Once `status == "done"`, the agent summarises findings and reports back to the user.

Because every tool is async, the agent stays responsive; no long-running tool call blocks the conversation.

## Authorization & safety

The MCP server enforces the same rules as the CLI: **only scan targets you're authorised to test.** Consider gating Dalfox MCP calls behind an explicit user confirmation step in your agent's system prompt, such as "Confirm the scope before every scan."

**Findings are untrusted input to your agent.** Unlike the CLI and the REST API, MCP hands scan output to a model that acts on what it reads, and every quoted byte in a finding was chosen by the target. Dalfox labels those responses with `_untrusted_content_notice`, but the label is a reminder, not a sandbox — keep the scope decision (which target, which proxy, which callback) with the operator, and never let it be changed by something the scanner read off a page.

## Troubleshooting

- **Tool not showing up?** Make sure the `dalfox` binary is on the PATH the MCP client uses. For Claude Desktop on macOS, that's often just `/usr/local/bin` or `/opt/homebrew/bin`.
- **Empty results?** Poll again; scans are async. Use `suggested_poll_interval_ms` as your cadence.
- **Want logs?** Run `dalfox mcp --debug` while you're setting things up. The debug lines go to stderr so they don't pollute the MCP channel.
