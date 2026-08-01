+++
title = "Scanning Modes"
description = "Single URL, file batch, pipeline, stored XSS, server, and MCP. Pick the mode that fits your workflow."
weight = 1
toc = true
+++

Dalfox accepts targets in several shapes. Every mode shares the same discovery, payload, and verification engine; they differ only in how you feed URLs in and where results go.

Under the hood there are four subcommands: `scan` (the scanner), `server` (long-lived REST API), `payload` (payload utilities), and `mcp` (Model Context Protocol stdio server). Everything below labelled "URL / File / Pipe / Raw HTTP / HAR / SXSS" is a *shape of input* that the `scan` subcommand handles via `--input-type`; they are not independent subcommands.

> The fan-out input shapes (`file`, `pipe`, `raw-http`, `har`) are `scan`-only: each expands one input into many targets. The `server` and `mcp` interfaces are single-target per call — they take one URL plus explicit method/headers/cookies/body (the same fidelity one HAR entry carries), so you replay a captured session by issuing one call per request.

## Auto (default)

Just give Dalfox a URL. It figures out the rest.

```bash
dalfox https://target.app/search?q=test
```

Under the hood, Dalfox uses the `scan` subcommand with `--input-type auto`. It auto-detects whether the argument is a URL, a file path, or a stream on `stdin`.

## URL mode

Force URL parsing (rarely needed, useful in scripts):

```bash
dalfox scan --input-type url https://target.app
```

## File mode

Scan a list of URLs, one per line:

```bash
# urls.txt
# https://target.app/search?q=1
# https://target.app/profile?id=2
dalfox scan urls.txt
# or, explicit:
dalfox scan --input-type file urls.txt
```

Comments (`#`) and blank lines are ignored. Each URL runs through the full pipeline.

## Pipe mode

Read from `stdin`, the common case when chaining recon tools:

```bash
cat urls.txt | dalfox scan
waybackurls example.com | gf xss | dalfox scan
hakrawler -url https://target.app | dalfox scan
```

Dalfox buffers the input, deduplicates, and scans every line as a target.

### Piping alongside a command-line target

Give Dalfox a target *and* pipe one, and the two lists merge:

```bash
cat urls.txt | dalfox scan https://target.app/one
# [info] Merged 12 target(s) from stdin and 1 target(s) from arguments
```

Here the command-line target is already enough to scan, so Dalfox waits only ~500 ms for `stdin` to produce its first byte. A pipe that a wrapper, CI job, or job runner left open and idle is skipped with a warning instead of blocking the run. Once the stream does start talking, it's read to the end — a long or slowly written list is never truncated.

To adjust that: `DALFOX_STDIN_WAIT_MS` raises the wait (or disables the merge with `0`) — see [Environment](../../reference/environment/) — and `--input-type pipe` says `stdin` *is* the input, so Dalfox waits for it however long it takes.

### Collapsing near-duplicate URLs

By default Dalfox only drops targets that are byte-identical (`--dedup-urls exact`): the full URL, query values included, plus the method. A `gau` / `katana` / `waybackurls` dump rarely looks like that — it is usually the same handful of endpoints with thousands of harvested values, and `?id=1` … `?id=9999` are 9999 separate full scans of one injection point.

`--dedup-urls signature` collapses them. The key is the method, scheme, host, port, path, and the *sorted set of parameter names* — query and body (form, JSON, multipart) alike. Values are excluded, so a value-only family becomes one target. Dalfox logs what it dropped, and the count lands in the scan metadata (`dedup_mode`, `targets_deduplicated`) so a collapsed run is never read as full coverage of the list.

The surviving representative is the first member listed, except that a member whose parameters all carry a value beats an earlier one with an empty value: recon dumps often list `?id=` before `?id=42`, and a valueless URL frequently 404s, which would report the whole family clean off a dud. Scope filters (`--include-url`, `--exclude-url`, `--out-of-scope`) are applied *before* dedup, so they always get to rule members out first.

```bash
gau target.app | dalfox scan --dedup-urls signature
# INF dedup (signature): 8214 duplicate target(s) collapsed, 37 remaining — dropped e.g. …
```

When is it safe? When the parameter *name* is what decides where input lands — the common case. It is **not** safe when a value picks the code path: an `action=` / `mode=` / `template=` discriminator that routes to a different handler on the same path, a routing token, or a locale that swaps the rendering template. There, `signature` scans one branch and reports on all of them, which is why it stays opt-in.

`--dedup-urls off` disables deduplication entirely, for the rare case where every line must be scanned as given. Note that per-target reporting is keyed by URL, so repeated lines still share one `target_summary` entry.

## Raw HTTP mode

Save a request you captured in Burp, Caido, or ZAP to a file and hand it to Dalfox:

```bash
dalfox scan --input-type raw-http request.txt
```

The file is a standard raw HTTP request (method + path + headers + blank line + body). Dalfox preserves every header, cookie, and body parameter.

For live proxy workflows (especially Caido Active Workflows) see the dedicated **[Caido integration guide](../integrations/caido/)**. It covers the exact shell pattern, the Caido boolean gotcha in If/Else nodes, and how to turn results into Findings automatically.

## HAR mode

Hand Dalfox a whole [HAR](http://www.softwareishard.com/blog/har-12-spec/) (HTTP Archive) export — the JSON capture that browser DevTools and intercepting proxies (Burp, Caido, ZAP, Charles, mitmproxy) produce — and it scans every request in it, preserving each one's URL, method, headers, cookies, and body:

```bash
# Auto-detected from the file content:
dalfox scan capture.har
# or explicit:
dalfox scan --input-type har capture.har
# or piped from another tool:
mitmdump -nr flows -w /dev/stdout --set hardump=- | dalfox scan -i har
```

Unlike flattening a HAR to a plain list of URLs (which throws away method, headers, cookies, and body), HAR mode keeps the full shape of each captured request, so a POST with a JSON body or an authenticated session is replayed faithfully. Each `log.entries[].request` becomes one target; requests are deduplicated by URL + method and run through the same scope filters as every other mode. Non-`http(s)` entries (`data:`, `blob:`, WebSocket, browser-extension URLs) are skipped automatically.

This restores a capability the Go v2.x line had that the v3 rewrite initially dropped. CLI request flags still apply on top — e.g. `-H "Authorization: Bearer …"` is appended to every entry, and `--include-url` / `--out-of-scope` narrow the set.

## Stored XSS mode (SXSS)

Test the classic "inject on form A, payload appears on page B" pattern:

```bash
dalfox scan https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox injects into the first URL, then fetches the second to check whether the payload landed. See the [Stored XSS guide](../stored-xss/) for the full flow.

## Session monitoring

Static credentials (`--cookies`, `-H 'Cookie: …'`, `--cookie-from-raw`) are
attached to every request and never revisited. If that session expires an hour
into a long scan, every request after it is answered by a login page, nothing
reflects, and Dalfox exits `0` with an empty report — indistinguishable from a
genuinely clean target.

Session monitoring closes that gap. During preflight Dalfox fingerprints the
authenticated landing response (status, where the request landed after
redirects, whether a login form was already on the page) at **no extra request
cost** — it reuses the body preflight already fetched. It then re-probes after
each target's injection stage, and again at the dispatch boundary when the
baseline is already more than 30 seconds old. (On a short or single-target run
only the post-scan probe fires — re-probing a baseline that is seconds old
proves nothing.)

```bash
# Nothing to configure: credentials switch it on.
dalfox scan https://app.example.com/dashboard?q=1 --cookies "sid=$SESSION"
```

A session is reported lost when any of these fires:

| Signal | Example |
|--------|---------|
| Status moves into `401` / `403` | the app started rejecting the cookie |
| The request now lands on a login-shaped URL | `302 → /users/sign_in` |
| A password field appeared where the baseline had none | the app now renders the login wall inline |

`403` is also what an origin or WAF returns once it decides to block a scanner.
When Dalfox has already fingerprinted a WAF on the target, the `403` signal is
suppressed entirely — a block explains it better than an expired session, and
calling it a logout would abort the host group over a WAF rule. Use
`--session-check` if you need `403`-as-expiry on a WAF-fronted origin.

### Making it exact

The heuristics are deliberately narrow — the default is to abort, so a false
positive costs a whole scan. When you know exactly what an authenticated
response looks like, say so and the heuristics step aside entirely:

```bash
dalfox scan https://app.example.com/dashboard?q=1 \
  --cookies "sid=$SESSION" \
  --session-check 'Signed in as' \
  --session-check-url https://app.example.com/api/me
```

`--session-check-url` is worth setting when the scan target is expensive,
paginated, or itself public — point it at a cheap authenticated endpoint
instead. The baseline is then taken from that endpoint too (one extra preflight
request per target, only when you set the flag), so a login-shaped probe path
like `/auth/session` is compared against its own authenticated response rather
than against the target's.

### What happens on loss

`--on-session-loss abort` (the default) stops the affected target and skips the
remaining targets for that host: continuing to spend the request budget against
a login page has no upside. `--on-session-loss continue` keeps scanning, for
targets where the heuristics misfire.

Either way the run is honest about it:

- a `SESSION LOST` line on **stderr**, so structured stdout stays parseable
- the target reported as `incomplete` (or `skipped`) with `error_code: SESSION_LOST`
  and the signal that fired in `error_message`
- `meta.incomplete: true` in the [scan metadata envelope](../output/#scan-metadata-envelope)
- exit code `2` under `abort` when the run found nothing — so
  `dalfox scan … && echo "no XSS found"` cannot print that line after being
  logged out. A run that *did* find something still exits `1`; findings are
  real regardless, and `meta.incomplete` carries the caveat. `continue` leaves
  the exit code alone entirely.

Dalfox also flags the case where the **preflight** response already looks
unauthenticated — or where a `--session-check` marker never matched the baseline
at all (a typo, or a marker that lives on another page). Both are reported as
`SESSION_LOST` rather than merely logged: from such a baseline no later probe
can detect a *change*, so stale credentials would otherwise produce a silent,
completely clean run. The target is still scanned; the flag and exit code are
what make the result honest.

Monitoring is off — and costs nothing — when no credentials are supplied and
neither `--session-check` flag is set. Logging in is out of scope: this is
detection only.

## Server mode

Run Dalfox as a long-lived HTTP service. Submit scans via REST, poll for results, cancel running jobs:

```bash
dalfox server --port 6664 --api-key "$DALFOX_API_KEY"
```

See [REST API Server](../../integrations/server/) for endpoints and request shapes.

## MCP mode

Expose Dalfox as a [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents and IDEs (like Claude) can drive scans:

```bash
dalfox mcp
```

The tools (`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`) are described in [MCP Server](../../integrations/mcp/).

## Payload mode (utility)

Not a scanning mode, but useful alongside: print or fetch payloads without running a scan.

```bash
dalfox payload event-handlers    # list DOM event handlers
dalfox payload useful-tags       # list useful HTML tags
dalfox payload portswigger       # fetch PortSwigger XSS cheatsheet
dalfox payload payloadbox        # fetch PayloadBox XSS list
dalfox payload uri-scheme        # print javascript:/data: payloads
```

## Choosing a mode

| You want to… | Use |
|--------------|-----|
| Test one URL | Auto / URL |
| Scan a list from your crawler | File or Pipe |
| Replay a specific request | Raw HTTP |
| Replay a whole captured session (proxy/DevTools export) | HAR |
| Test a form that writes to another page | SXSS |
| Run many scans from a dashboard or CI | Server |
| Let an AI agent drive scans | MCP |
| Just see what payloads Dalfox would send | Payload utility or `--dry-run` |
