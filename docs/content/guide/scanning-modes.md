+++
title = "Scanning Modes"
description = "Choose a Dalfox scan mode for URLs, files, pipelines, raw HTTP, HAR, OpenAPI / Postman specs, stored XSS, blind XSS, REST, or MCP."
weight = 1
toc = true
+++

Dalfox accepts targets in several shapes. Every mode shares the same discovery, payload, and verification engine; they differ only in how you feed URLs in and where results go.

Dalfox has four working subcommands: `scan` (the scanner), `server` (long-lived REST API), `payload` (payload utilities), and `mcp` (Model Context Protocol stdio server), plus `completion`, which prints shell completion scripts. The URL, File, Pipe, Raw HTTP, HAR, and OpenAPI / Postman modes below are input shapes that `scan` reads through `--input-type`. Stored XSS and Blind XSS are `scan` flags. None of them is a separate subcommand.

> The fan-out input shapes (`file`, `pipe`, `raw-http`, `har`, `openapi`, `postman`) are `scan`-only: each expands one input into many targets. The `server` and `mcp` interfaces take one target per call: one URL plus explicit method, headers, cookies, and body (what one HAR entry carries). To replay a captured session there, send one call per request.

## Auto (default)

Give Dalfox a URL and it works out the rest.

```bash
dalfox 'https://target.app/search?q=test'
```

This runs the `scan` subcommand with `--input-type auto`, which detects whether the argument is a URL, a URL-list file, a raw HTTP request file, a HAR file, or a stream on `stdin`. API specs are not detected; see [OpenAPI / Postman mode](#openapi-postman-mode).

The bare form takes only targets and the global flags (`--config`, `--debug`, `--no-color`, `-S`). Any scan flag needs the subcommand spelled out: `dalfox scan https://target.app -p q`, not `dalfox https://target.app -p q`.

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

A line that is not a scannable target is skipped with a warning, so one stray line in a 50k-URL list does not stop the run. Typical examples are `mailto:`, `javascript:`, and `tel:` links, `ftp://` URLs, and truncated fragments, which most `gau` / `katana` / `waybackurls` dumps contain. The skipped count goes into `meta.targets_unparsable`, so a report never reads as full coverage of a list it partly discarded. If *no* line in the list parses, the run fails with an error.

A path you meant as a file but which isn't there (`dalfox scan ./urls.txt`, `-i har capture.har`) is reported as a missing file (`FILE_READ_ERROR`). Dalfox does not reinterpret it as a hostname.

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

Here the command-line target is already enough to scan, so Dalfox waits only ~500 ms for `stdin` to produce its first byte. A pipe that a wrapper, CI job, or job runner left open and idle is skipped with a warning instead of blocking the run. Once the stream starts sending data, Dalfox reads it to the end, so a long or slowly written list is never truncated.

Two knobs adjust that. `DALFOX_STDIN_WAIT_MS` raises the wait, or disables the merge with `0` (see [Environment](../../reference/environment/)); `--input-type pipe` says `stdin` *is* the input, so Dalfox waits for it however long it takes.

### Collapsing near-duplicate URLs

By default Dalfox only drops targets that are byte-identical (`--dedup-urls exact`): the full URL with its query values, the method, and the request body. A `gau` / `katana` / `waybackurls` dump rarely has exact duplicates. It is usually the same handful of endpoints with thousands of harvested values, and `?id=1` … `?id=9999` become 9999 separate full scans of one injection point.

`--dedup-urls signature` collapses them. The key is the method, scheme, host, port, path, and the *sorted set of parameter names*, taken from the query and the body alike (form fields, top-level JSON keys, multipart fields). Values are excluded, so URLs that differ only in values become one target. Dalfox logs what it dropped, and the count goes into the scan metadata (`dedup_mode`, `targets_deduplicated`), so a collapsed run is never read as full coverage of the list.

The URL that stays is the first one listed, with one exception: a URL whose parameters all carry a value wins over an earlier one with an empty value. Recon dumps often list `?id=` before `?id=42`, and a valueless URL often returns 404, which would report the whole group clean based on a dead page. Scope filters (`--include-url`, `--exclude-url`, `--out-of-scope`) run *before* dedup, so they always get to rule URLs out first.

```bash
gau target.app | dalfox scan --dedup-urls signature
# INF dedup (signature): 8214 duplicate target(s) collapsed, 37 remaining — dropped e.g. …
```

The main gain is coverage. `--max-targets-per-host` caps a host at 100 targets by default, and a recon dump arrives sorted, so one endpoint's thousands of harvested values sit next to each other and use up the whole budget before any other endpoint is reached. Measured on a 5200-URL list (5000 × `/html?q=N`, then 200 distinct `/users/N`):

| Mode | What the 100-target budget was spent on |
|------|------------------------------------------|
| `exact` (default) | 100 variants of `/html`; the 200 `/users/N` endpoints are never scanned |
| `signature` | 1 × `/html` + 99 distinct `/users/N` |

The truncation is reported either way (`TRUNCATED_PER_HOST_CAP`), but only `signature` spends the budget on *different* endpoints. Raise `--max-targets-per-host` as well if you want both.

It is safe when the parameter *name* decides where input lands, which is the common case. It is **not** safe when a value picks the code path: an `action=` / `mode=` / `template=` discriminator that routes to a different handler on the same path, a routing token, or a locale that swaps the rendering template. There, `signature` scans one branch and reports on all of them, which is why it stays opt-in.

`--dedup-urls off` disables deduplication entirely, for the rare case where every line must be scanned as given. Per-target reporting is keyed by URL, method, and request body, so repeated identical lines still share one `target_summary` entry.

## Resuming an interrupted scan

Ctrl-C stops a scan cleanly and still reports what was found, but that is only a partial report. Nothing records *which* targets finished, so re-running a 50k-URL list that stopped at 80% redoes the 80%. The same applies to a crash, a dropped SSH session, or an OOM on a shared box.

`--state-file` (opt-in; without it nothing is recorded) records each target as it reaches a terminal state, and skips the finished ones on the next run:

```bash
dalfox scan --input-type file urls.txt --state-file scan.state
# ^C
# [!] Ctrl-C received — stopping in-flight tasks (press again to force exit)

dalfox scan --input-type file urls.txt --state-file scan.state
# INF resume: 6042 target(s) already completed per scan.state, 1958 left to scan
```

**Only completed targets are skipped.** Anything whose coverage is unknown is scanned again. A target that produced findings is recorded `completed` only after the report is written (findings live in memory until then). A kill, an OOM, or a failed `--output` write therefore cannot leave a target skipped with its findings lost; it is scanned again. Targets with no findings are recorded as soon as they finish, and everything is recorded immediately under `--stream-findings`:

| Recorded outcome | When | Next run |
|------------------|------|----------|
| `completed` | The target was scanned to the end with a live session, and its findings (if any) were written to the report | Skipped |
| `cancelled` | Ctrl-C, `--scan-timeout` expiry, a `--limit` stop, a session that died mid-scan, or severe transport loss (`meta.incomplete`) | Retried |
| `error` | Dropped during preflight (unreachable, content-type mismatch, `--max-targets-per-host` cap), or a scan worker crashed | Retried |

A target's resume identity is its URL, its method, and a hash of the request data it is sent with: body, headers, cookies, and user-agent. That covers data captured in raw HTTP and HAR inputs as well as `-H`, `--cookies`, and `--user-agent`, so a changed capture is scanned again. **Run-wide credential values are left out**: every `--cookies` and `--cookie-from-raw` cookie value, and the `-H` values of `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key` / `*-Api-Key`, `X-Auth-Token` / `*-Token`, `X-CSRF-Token` / `X-XSRF-Token`, `*-Session-Id` / `X-Session-Token`, `X-Access-Key`, and `X-JWT-Assertion`. Those flags apply to every target and are what you refresh when you log in again, so a rotated session resumes instead of rescanning; adding or removing a header or cookie still counts. Credentials *inside* an imported raw HTTP or HAR capture do count: two captures that differ only by `Authorization` (tenant A vs tenant B) are distinct requests and are tracked separately. Supplying a different *account* through the same flags also resumes, so use a separate `--state-file` per account. Only the hash is stored; the values never reach the state file. Invocations with the same flags produce the same identity, so one state file can back a shell loop of per-URL invocations as easily as a single `--input-type file` run.

**A configuration change starts over.** The file's header carries a hash of the scan-affecting configuration; when it does not match, the recorded targets were tested under settings this run does not use. Dalfox moves the old file to `scan.state.bak`, starts a new one, and scans everything:

```
Warning: scan configuration changed since 'scan.state' was written (recorded a5f8…, now 6447…) — starting fresh (previous state kept at 'scan.state.bak')
```

The old file is moved aside instead of overwritten because it records real work, and losing 40k completions to a reset would be worse than a redundant scan. Dalfox never destroys a file in place. If the file at that path is *not* a Dalfox state file (say, a typo pointing at your target list), Dalfox refuses to use it.

Output and pacing flags are left out of that hash: `--format`, `--output`, `--poc-type`, `--include-request` / `--include-response` / `--include-all`, `--silence`, `--no-color`, `--stream-findings`, `--baseline` / `--baseline-mode`, `--timeout`, `--scan-timeout`, `--delay`, `--rate-limit`, `--retries`, `--retry-delay`, `--workers`, `--max-concurrent-targets`, and the target list and `--input-type` themselves. Raising a timeout or slowing a scan down is the normal reaction to an interrupted run, and none of it changes what an already-completed target was tested with. Anything that changes payloads, discovery, coverage, or credentials does invalidate the file. That includes `--deep-scan`, `--encoders`, `--custom-payload`, the mining and discovery toggles, the WAF options, `--limit` together with `--limit-result-type`, `--only-poc`, and `--min-confidence` (they decide which findings count toward it), and the header and cookie *names* in `--headers` / `--cookies` (plus non-credential header values). Run-wide credential values and the `--cookie-from-raw` path are not hashed, as described above.

The hash also covers Dalfox's major version and every other scan option, so an upgrade that adds a scan flag starts every state file over once. That errs toward a redundant scan, never a silent skip.

The file is append-only JSONL: one header line, then one line per target. A hard kill can at worst tear the final line, which is skipped on read while every complete record before it still counts. A target whose outcome is unchanged from the last run is not re-recorded, so a permanently unreachable host does not grow the file once per run.

`--dry-run` and `--only-discovery` open the file **read-only**: their plan reflects the resume, but they send no attack payloads and complete nothing, so they never create, extend, or move the file. Estimating a `--deep-scan` run with `--dry-run` cannot lose your progress. Every envelope that applies the filter (scan, dry-run, only-discovery, Markdown) carries a `resumed` block with the state-file path and how many targets were skipped, so a short report from a resumed run is never mistaken for full coverage of the input list.

CLI only: `dalfox server` and MCP run one scan per job with their own lifecycle, and never resume a previous process's work.

## Raw HTTP mode

Save a request you captured in Burp, Caido, or ZAP to a file and hand it to Dalfox:

```bash
dalfox scan --input-type raw-http request.txt
```

The file is a standard raw HTTP request (method + path + headers + blank line + body). Dalfox preserves the headers, cookies, and body parameters. It drops only the headers it has to: `Host` (taken from the URL), `Content-Length` / `Transfer-Encoding` (recomputed for each injected body), hop-by-hop and `Accept-Encoding` headers, and lines an HTTP/1.1 client cannot send. HTTP/2 pseudo-headers (`:authority`, `:scheme`), which copy-as-cURL and HTTP/2 captures often include, are read for the host and scheme but never sent.

A request line with a bare path (`GET /search HTTP/1.1`) does not say whether the request went over HTTP or HTTPS, so Dalfox takes the scheme from the capture: a `:scheme` pseudo-header wins, then any other HTTP/2 sign (an `HTTP/2` / `HTTP/3` request line or an `:authority` pseudo-header) means HTTPS, then a `Host` ending in `:443`; anything else is scanned over `http://`. An absolute URL in the request line (`GET https://app/search HTTP/1.1`) is used as is.

For live proxy workflows (especially Caido Active Workflows), see the [Caido integration guide](../../integrations/caido/). It covers the exact shell pattern, the Caido boolean gotcha in If/Else nodes, and how to turn results into Findings automatically.

## HAR mode

A [HAR](http://www.softwareishard.com/blog/har-12-spec/) (HTTP Archive) export is the JSON capture that browser DevTools and intercepting proxies (Burp, Caido, ZAP, Charles, mitmproxy) produce. Hand Dalfox the whole file and it scans every request in it, preserving each one's URL, method, headers, cookies, and body:

```bash
# Auto-detected from the file content:
dalfox scan capture.har
# or explicit:
dalfox scan --input-type har capture.har
# or piped from another tool:
mitmdump -nr flows -w /dev/stdout --set hardump=- | dalfox scan -i har
```

Flattening a HAR to a plain list of URLs throws away the method, headers, cookies, and body. HAR mode keeps the full shape of each captured request, so a POST with a JSON body or an authenticated session is replayed as captured. Each `log.entries[].request` becomes one target and runs through the same scope filters as every other mode. Duplicates are dropped by URL + method + body, so two POSTs to the same URL with different bodies are both scanned; entries that differ only in headers or cookies (a rotated session, a drifting `Referer`) collapse. Pass `--dedup-urls off` to keep every entry. Non-`http(s)` entries (`data:`, `blob:`, WebSocket, browser-extension URLs) are skipped automatically.

CLI request flags still apply on top, for HAR, raw HTTP, OpenAPI and Postman alike. `-X`, `-d`, and `--user-agent` replace each captured request's method, body, and User-Agent; `-H` and `--cookies` are added to it (e.g. `-H "Authorization: Bearer …"` lands on every entry). A `-H` header replaces every imported header of the same name (case-insensitive), and a `--cookies` cookie replaces the imported cookie of the same name, so a stale captured session or a spec's placeholder value never goes out ahead of yours; differently named ones are kept. `-H 'Cookie: …'` replaces the captured cookies (and any `--cookies`) outright; use `--cookies` to add or replace individual cookies. Without those flags each request keeps its captured shape. `--include-url`, `--exclude-url`, and `--out-of-scope` narrow the set.

## OpenAPI / Postman mode

API-first applications usually ship a spec that already lists every endpoint, method, parameter, and body. Hand it to Dalfox instead of recording traffic first:

```bash
# OpenAPI 3.x (JSON or YAML), or Swagger 2.0
dalfox scan -i openapi openapi.yaml
# Postman Collection v2.1 export
dalfox scan -i postman api.postman_collection.json
# Point the spec at a different deployment
dalfox scan -i openapi openapi.yaml --base-url https://staging.example.com
```

Both types are explicit: `auto` does not detect a spec, so pass `-i openapi` / `-i postman`. A spec read as a target list without `-i` prints a warning naming the flag to use. A spec can also be piped (`cat openapi.json | dalfox scan -i openapi`).

**OpenAPI.** Each `get`, `post`, `put`, `patch` and `query` operation becomes one target. `delete`, `head` and `options` operations are not scanned: discovery, mining and payloads against a DELETE with placeholder ids could destroy data, and HEAD / OPTIONS responses have no body to reflect into. They are counted in a stderr warning (the same applies to Postman requests). Each target is built like this:

- **URL**: the server URL (`servers[0]`, operation and path-item `servers` win over the root) with `{variables}` replaced by their `default`, plus the path. Path parameters are filled from `example`, then `examples`, then the schema's `default` / `enum` / `example`, then a typed placeholder (`1` for numbers, `test` for strings, a fixed UUID / date for those formats). Values are percent-encoded, and a path that would leave the server's origin is skipped.
- **Query, header, cookie parameters**: placed on the request with the same value rules. Header parameters named `Accept`, `Content-Type`, or `Authorization` are ignored, as the OpenAPI spec says; pass credentials with `-H` / `--cookies`.
- **Body**: the first of JSON, form (`application/x-www-form-urlencoded`), multipart (`multipart/form-data`), and XML that the operation accepts, built from the media type's `example` or sampled from its schema (`allOf` merged, `oneOf` / `anyOf` take the first branch, `readOnly` properties dropped). Discovery then finds the injection points the same way it does for `-d`: JSON keys, form fields, XML element text, and GraphQL variables. Multipart fields are mined and tested as multipart fields.
- **`$ref`**: only local references (`#/components/...`) are followed. A remote `$ref` is never fetched; it becomes a placeholder. Reference cycles and very deep or very wide schemas are cut off, so a hostile spec can't run the import out of memory.
- **Swagger 2.0**: `schemes` / `host` / `basePath` give the server, `in: body` parameters the JSON body, and `in: formData` parameters a form body (multipart when the operation `consumes` multipart or has a `file` field).

`--base-url` follows one rule for every server shape: it supplies the scheme, host and port, and its path is a prefix; the spec server's path (or Swagger `basePath`) is appended after it, and the server's own scheme and host are dropped. So with `--base-url https://staging.example.com`, both `servers: [{url: /api/v3}]` and `servers: [{url: https://prod.example.com/api/v3}]` scan `https://staging.example.com/api/v3/...`. A scheme-relative server (`//prod.example.com/v1`) can't move the scan off the host you named either, and server variables in the dropped host don't need defaults. Without `--base-url`, a spec whose server is relative or scheme-relative, has an undeclared server variable, or has no `servers` is skipped with a hint to pass it.

**Postman.** Every request in the collection becomes one target, folders included. `{{variables}}` come from the collection's `variable` list (nested references resolve too). Environment files are not read: a request whose host is still an unresolved `{{variable}}`, or one exported with an empty value, is skipped with a warning, so pass `--base-url` to supply the origin (it replaces the origin of every request and keeps each request's path). An unresolved variable anywhere else (path, query, header, body) becomes a placeholder value, since those are the slots the scan injects into anyway. `:name` path variables are filled from the request's `url.variable`. A `url` object without `raw` is rebuilt from its `protocol` / `host` / `port` / `path` / `query` parts (disabled query entries left out). Body modes map as `raw` (sent as-is, with `Content-Type` from the raw language when the request has none), `urlencoded` (form), `formdata` (multipart; a file part's local path is never read), and `graphql` (a JSON `{query, variables}` body). `auth` is not applied at any level (collection, folder or request); pass it with `-H`.

**Leniency.** One bad operation or request (an unresolved host, a non-`http(s)` server, an unusable body) is skipped, not fatal; a warning on stderr counts the skips and quotes a few. The run fails with `PARSE_ERROR` only when the document is not a spec or nothing in it is scannable. Files are read under the same size cap as other inputs (`INPUT_TOO_LARGE`).

The expanded targets then go through the same pipeline as a HAR import: CLI request flags apply on top (see above), duplicates collapse on URL + method + body, skipped operations are counted in `meta.targets_unparsable`, `--include-url` / `--exclude-url` / `--out-of-scope` narrow the set, and `--state-file` fingerprints each target's method, body, headers and cookies.

## Stored XSS mode (SXSS)

Test the classic "inject on form A, payload appears on page B" pattern:

```bash
dalfox scan https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox injects into the first URL, then fetches the second to check whether the payload landed. It also checks the page the form was found on, the form's `action` (only on the same origin, or the same host upgraded from `http` to `https`), and the injection target itself, so `--sxss-url` is optional. Because a stored sink does not echo in the immediate response, `--sxss` also tests the fields of discovered forms and, when `-p` is not set, the request's own query and `-d` body parameters, even when they don't reflect during discovery. See the [Stored XSS guide](../stored-xss/) for the full flow.

## Blind XSS

For a payload that fires later, somewhere you can't see (an admin panel, a support dashboard), inject a callback payload:

```bash
# Your own listener: hits arrive there, Dalfox records nothing
dalfox scan 'https://target.app/?q=1' -b https://your-callback.example

# Dalfox-managed interactsh session: callbacks come back as findings
dalfox scan 'https://target.app/?q=1' --blind-oob
```

`--blind-oob` registers with an interactsh server (the public mesh, or the ones you name with `--blind-oob=oast.fun`), mints a callback host per payload, and after the scan keeps polling for `--blind-oob-wait` seconds (default `30`). A callback that arrives becomes a `V` finding with `detection_method: oob`. Blind payloads are stored attack traffic, so they are not sent under `--dry-run`, `--only-discovery`, or `--skip-xss-scanning`, nor to a target that is not scanned (unreachable, content-type mismatch, or over `--max-targets-per-host`). Templates and custom payloads are covered in [Payloads & Encoding](../payloads/#blind-xss).

## Session monitoring

Static credentials (`--cookies`, `-H 'Cookie: …'`, `-H 'Authorization: …'`, `--cookie-from-raw`, or the ones inside a captured raw HTTP / HAR request) are attached to every request and never checked again. If that session expires an hour into a long scan, every later request gets a login page, nothing reflects, and Dalfox exits `0` with an empty report. That looks exactly like a clean target.

Session monitoring catches this. During preflight Dalfox fingerprints the authenticated landing response: the status, where the request landed after redirects, and whether a login form was already on the page. This costs **no extra request**, because it reuses the body preflight already fetched. Dalfox then probes again after each target's injection stage, and also at the dispatch boundary when the baseline is more than 30 seconds old. (On a short or single-target run only the post-scan probe fires, since re-checking a baseline taken seconds ago proves nothing.)

```bash
# Nothing to configure: credentials switch it on.
dalfox scan 'https://app.example.com/dashboard?q=1' --cookies "sid=$SESSION"
```

A session is reported lost when any of these fires:

| Signal | Example |
|--------|---------|
| Status moves into `401` / `403` | the app started rejecting the cookie |
| The request now lands on a login-shaped URL | `302 → /users/sign_in` |
| A password field appeared where the baseline had none | the app now renders the login wall inline |

`403` is also what an origin or WAF returns once it decides to block a scanner. When Dalfox has already fingerprinted a WAF on the target, it ignores the `403` signal. A block explains it better than an expired session, and treating it as a logout would abort the whole host group over one WAF rule. Use `--session-check` if you need `403`-as-expiry on a WAF-fronted origin.

### Making it exact

The heuristics are kept narrow on purpose: the default action is to abort, so a false positive costs a whole scan. When you know what an authenticated response looks like, pass it with `--session-check` and Dalfox uses that instead of the heuristics:

```bash
dalfox scan 'https://app.example.com/dashboard?q=1' \
  --cookies "sid=$SESSION" \
  --session-check 'Signed in as' \
  --session-check-url https://app.example.com/api/me
```

There is one exception. If a probe response came back incomplete (a `206`, or a body cut short) before reaching the spot where the marker sat in the baseline, a missing marker proves nothing, so Dalfox falls back to the heuristics.

Set `--session-check-url` when the scan target is expensive, paginated, or public: point it at a cheap authenticated endpoint instead. The baseline is then taken from that endpoint too (one extra preflight request per target, only when you set the flag). That way a login-shaped probe path like `/auth/session` is compared against its own authenticated response, not the target's.

### What happens on loss

`--on-session-loss abort` (the default) stops the affected target and skips the remaining targets for that host, since spending more requests on a login page gains nothing. `--on-session-loss continue` keeps scanning, for targets where the heuristics misfire.

Either way, the run reports it:

- a `SESSION LOST` line on **stderr**, so structured stdout stays parseable
- the target reported as `incomplete` (or `skipped`) with `error_code: SESSION_LOST` and the signal that fired in `error_message`
- `meta.incomplete: true` in the [scan metadata envelope](../output/#scan-metadata-envelope)
- exit code `2` under `abort` when the run found nothing, so `dalfox scan … && echo "no XSS found"` cannot print that line after being logged out. A run that *did* find something still exits `1`: the findings are real, and `meta.incomplete` carries the caveat. `continue` leaves the exit code alone.

Dalfox also flags two cases at **preflight**: the response already looks unauthenticated, or a `--session-check` marker never matched the baseline (a typo, or a marker that lives on another page). Both are reported as `SESSION_LOST`, not just logged. From such a baseline no later probe can detect a *change*, so stale credentials would otherwise produce a silent, fully clean run. The target is still scanned; the flag and exit code keep the result honest.

"Already looks unauthenticated" means the sign-in page itself: a `401`, an inline password field, or a redirect to `/login`, `/signin`, or `/users/sign_in`. A redirect to a path that only *looks* auth-related is not enough. Many apps serve their authenticated home from `/auth/home` or `/sso/dashboard`, and calling that a dead session would fail a scan whose session was fine. For that case Dalfox prints a `SESSION?` advisory instead. It is visible, but adds no `SESSION_LOST` entry, does not set `meta.incomplete`, and does not change the exit code. If your app is one of those and you want an exact check, use `--session-check`.

Monitoring is off (and costs nothing) when the request carries no cookies and no `Cookie` / `Authorization` header, and neither `--session-check` flag is set. Dalfox does not log in for you; this feature only detects a lost session.

`dalfox server` and MCP jobs use the same detection rules, checked against the job's baseline and once after the scan. A lost session ends the job as `error` with a `SESSION_LOST:` message. Jobs have no `--session-check` equivalent, so they rely on the heuristics.

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
| Scan every endpoint an API spec describes | OpenAPI / Postman |
| Test a form that writes to another page | SXSS |
| Catch a payload that fires later, out of sight | Blind (`-b` / `--blind-oob`) |
| Run many scans from a dashboard or CI | Server |
| Let an AI agent drive scans | MCP |
| See what Dalfox would send, without attacking | Payload utility (the payload lists) or `--dry-run` (the per-target plan and request estimate) |
