+++
title = "Parameters & Discovery"
description = "How Dalfox finds the inputs that matter, and how to steer the discovery phase."
weight = 2
toc = true
+++

Finding XSS starts with finding the right parameter. Dalfox's discovery engine is a multi-stage pipeline; you rarely need to understand all of it, but knowing the moving parts helps when you want to tune a scan.

## The pipeline, briefly

1. **Discovery:** Probe the inputs the request already carries: query values (and query parameter *names*), headers, cookies, path segments, and the fields of forms found on the page. URL-fragment keys are recorded too, but only so AST findings can be matched to them; a fragment never reaches the server, so it is not fuzzed.
2. **Mining:** Probe the body parameters of `-d` (form, JSON, GraphQL variables, XML, multipart), then look for names the request doesn't carry: a dictionary wordlist and the `id`/`name` of `<input>` elements in the response.
3. **Active probing:** Fire a probe for each parameter to learn which special characters survive, refine the injection context, and detect servers that URL-decode more than once.
4. **Payload generation:** Build context-aware payload sets (HTML, JS, attribute, CSS). Before a parameter's payloads go out, a **fast probe** sends one sandwich-marker request (plus a numeric-only fallback for filters that strip letters). If nothing reflects, the heavy payload loops are skipped for that parameter unless `--deep-scan` is set. When active probing already saw the marker come back, the fast probe reuses that answer instead of sending its own request.
5. **Reflection check:** Send the payload, then see whether it comes back.
6. **DOM verification:** Parse the response and confirm the payload reached an executable position. AST-based DOM-XSS analysis runs once over the landing page itself, then once per parameter on the fast-probe response (or on the first reflection response when the fast probe was skipped).

## Targeting specific parameters

Tell Dalfox exactly which parameters to test:

```bash
dalfox scan https://target.app/api \
  -p q \
  -p id:query \
  -p auth:header \
  -p token:cookie
```

Locations: `query`, `body`, `json`, `multipart`, `cookie`, `header`, `graphql`, `xml`. Prefer `name:location` when the injection point is not the query string. `graphql` and `xml` are discovered automatically from the request body (see [GraphQL and XML body injection](#graphql-and-xml-body-injection)); a hint filters an already-discovered one but cannot synthesize a fresh body from a bare name. `path` and `fragment` work the same way, as filters only: path segments are named by position (`-p path_segment_0:path`).

Without a location hint (`-p q` only):

1. If discovery/mining already found a param with that name, it is kept (filter).
2. Otherwise Dalfox **synthesizes** it: location is inferred from the request (URL query → body → cookies → headers), defaulting to `query`.

That means recipes like `-p q --skip-discovery --skip-mining` still test `q` instead of silently scanning nothing.

## Mining with wordlists

Even if a parameter isn't in the URL, Dalfox can try common names:

```bash
# Local wordlist
dalfox scan https://target.app -W ./params.txt

# Remote wordlists (cached after first fetch)
dalfox scan https://target.app --remote-wordlists burp,assetnote
```

Only one list is used per scan. When `--remote-wordlists` loads, it wins and `-W` is ignored; `-W` is the fallback if the remote fetch fails. Mined names are tested as query parameters.

Dictionary and DOM candidates are tested in buckets of up to 64 names per request (kept under an ~8 KiB request line), not one request per name. A name whose canary reflects is identified from that one response. When a bucket changes the response without reflecting anything, Dalfox compares it with a same-size control request and splits the bucket to find the name behind the change. Only those ambiguous buckets cost extra requests, so a large wordlist stays cheap.

On a page whose body differs between identical requests (a rotating widget, a timestamp), only a status-code change counts as such a response change. A bucket that fails, or that the server rejects for its size (a query-length limit), is split and retried rather than dropped.

With no custom or remote wordlist selected, the built-in seed keeps Dalfox's
historical XSS-oriented names and adds an attributed, broader Param Miner seed
covering API, authentication, pagination, feature flags, media, and operational
names.

### Auto-collapse

Highly reflective sites (e.g., a search page that echoes everything) can cause wordlist mining to explode. Dalfox protects against this in two ways:

- **Sentinel pre-probe:** Before iterating the wordlist, three random-looking parameter names that should never collide with real fields are tested. If every one reflects, the page is a mirror; mining is skipped and a single synthetic `any` Query parameter takes its place. Cost ceiling: 3 requests, regardless of wordlist size. Runs only when the wordlist is large enough (>15 entries) for the pre-probe to pay off.
- **EWMA collapse:** After bucket processing, Dalfox watches the rolling reflection ratio. A high ratio (≥85% after at least 15 candidate names) triggers a confirmation check for smaller lists. If the sentinels also reflect, mined Query params are folded into the same `any` placeholder; if they do not, every confirmed candidate is kept. A negative sentinel therefore does not cut coverage from the rest of a large wordlist.

The sentinel-confirmed route produces one synthetic Query injection point. A negative sentinel preserves the individual reflected names, while still benefiting from bucketed requests.

## Pruning the noise

Ignore specific parameters:

```bash
dalfox scan https://target.app --ignore-param csrf --ignore-param __RequestVerificationToken
```

Scope by URL pattern:

```bash
dalfox scan urls.txt \
  --include-url '^https://api\.target\.app/' \
  --exclude-url '/static/|/health'
```

Out-of-scope domain list:

```bash
dalfox scan urls.txt --out-of-scope-file scope-block.txt
# or inline, with wildcards (repeat the flag; one pattern per flag)
dalfox scan urls.txt --out-of-scope '*.google.com' --out-of-scope '*.cdn.cloudflare.net'
```

`--out-of-scope` does not split on commas: `'*.google.com,*.cdn.cloudflare.net'` is read as one pattern and matches nothing.

## Only discover, don't attack

Both modes run the same discovery, mining, and active-probing requests and stop before the scan stage, so no XSS payload is sent. They differ in what they print.

Dry-run prints the attack plan: target count, the parameters found per target, and a lower-bound estimate of the requests a real scan would send. It also skips the WAF provocation probe (one request carrying a `<script>` payload), so use it when no attack-shaped request may be sent at all.

```bash
dalfox scan https://target.app --dry-run
```

Discovery-only prints one line per discovered parameter (URL, name, location):

```bash
dalfox scan https://target.app --only-discovery
```

Both help with scoping and CI pre-checks.

## Skipping stages

To move faster or work around a fragile target, skip parts of the pipeline:

| Flag | Skips |
|------|-------|
| `--skip-discovery` | Entire discovery stage (query, header, cookie, path, form, fragment) |
| `--skip-mining` | All wordlist/DOM mining |
| `--skip-mining-dict` | Dictionary mining only |
| `--skip-mining-dom` | Mining parameter names from `<input>` `id`/`name` attributes only |
| `--skip-reflection-header` | The built-in common-header sweep. Headers you pass with `-H` are still probed |
| `--skip-reflection-cookie` | Probing the cookies the request carries |
| `--skip-reflection-path` | Path-segment reflection checks |

What you name explicitly survives these flags. Body parameters from `-d` are probed even under `--skip-mining`, and a `-p name:header` or `-p name:cookie` is probed even under the matching `--skip-reflection-*` flag. The payload-side skips (`--skip-xss-scanning`, `--skip-ast-analysis`, `--skip-waf-probe`) are listed in the [CLI reference](../../reference/cli/).

> `--skip-mining-dom` only stops dalfox from harvesting parameter *names* out of the response HTML. It does **not** disable DOM-XSS detection: the static analysis of inline `<script>` blocks (which emits the `[A]` AST-detected findings, source→sink flows such as `location.hash` → `innerHTML`) is a separate pass controlled by [`--skip-ast-analysis`](../payloads/#skipping-payload-stages). To filter those findings out of the output instead, use `--only-poc v,r`. See [Detection Model](../detection-model/) for how the two subsystems differ and what each evidence tier proves.

## Injection markers

When you already know the injection point, mark it with `--inject-marker`:

```bash
dalfox scan https://target.app/api \
  --inject-marker FUZZ \
  -d '{"filter":"FUZZ"}'
```

With a marker set, discovery, mining, and active probing are skipped. Every query value, form-body value, top-level JSON string value, header value, and cookie value that contains `FUZZ` becomes a parameter, and each payload replaces that whole value. A marker anywhere else (a path segment, a nested JSON field) is not picked up.

You can also target a query parameter or a header directly:

```bash
# Query parameter
dalfox scan 'https://example.com/?q=FUZZ&page=1' --inject-marker FUZZ

# Header
dalfox scan https://example.com -H 'X-Search: FUZZ' --inject-marker FUZZ
```

## Auto pre-encoding

Some endpoints don't accept a payload as raw text. They expect it wrapped in some structural encoding (base64, JSON, JWT, and so on). During query discovery, when the plain marker does not come back for a parameter, Dalfox tries the wrapped forms below and keeps the wrapping whose marker is reflected. Payloads for that parameter then go through the same wrapping. There's nothing to configure. This applies to query parameters.

Single-step encodings are found by sending the marker already encoded:

| Detected | Encodes payload as |
|----------|-------------------|
| `base64` | `BASE64(payload)` |
| `2base64` | `BASE64(BASE64(payload))` |
| `2url` / `3url` | Two- or three-round URL encoding |

Active probing also tries `2url` / `3url` on query and path parameters whose `<` is filtered, to catch servers that URL-decode more than once.

Composable pipelines are inferred from the parameter's existing value. When it decodes as a structured wrapper, Dalfox probes every leaf string field as its own virtual sub-parameter and keeps the leaves whose marker is reflected:

| Wrapper shape | Pipeline |
|---------------|----------|
| Base64-of-JSON `?qs=eyJ…` | `JsonField(/leaf) → Base64` |
| Base64URL-of-JSON | `JsonField(/leaf) → Base64Url` |
| Bare URL-encoded JSON `?blob=%7B…%7D` | `JsonField(/leaf)` |
| JWT/JWS `?token=h.p.s` | `JsonField(/leaf) → Base64Url → JwtAssemble` |

Each leaf is registered as a separate Param using bracket-style display naming. A payload at the `move_url` field of `qs` shows up as `qs[move_url]`, and an array element appears as `qs[items][0]`. The wire-level substitution still targets the original parent param (`qs`), so the request looks normal to the server.

For JWTs the original header and signature segments are preserved verbatim. The signature won't match the modified payload, so this only fires on endpoints that don't verify the token. Properly-signed JWTs return no findings. That's expected behaviour, not a miss.

If your target uses a wrapping that Dalfox doesn't auto-detect, `--inject-marker` (see above) can still pin the injection point, but the payload is then sent as is, without the wrapping.

## GraphQL and XML body injection

When the request body (`-d`, or a captured `raw-http` / `har` request) is a GraphQL or XML document, Dalfox treats its inner values as injection points instead of testing the raw body as one opaque blob.

**GraphQL** (a JSON body; detection goes by the body's shape, not its content type): a body that carries both a GraphQL operation (a `query`/`mutation` field whose value starts with `query`/`mutation`/`subscription` or the anonymous `{ … }` shorthand) **and** a `variables` object has every string leaf inside `variables` probed, and each one that reflects becomes its own `graphql` parameter (named `variables.<path>`). Each payload rebuilds the whole request — the operation and the other variables ride along unchanged — so the server always receives a valid, parseable GraphQL request.

```bash
dalfox scan https://target.app/graphql \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query":"query($q:String!){ search(term:$q){ id } }","variables":{"q":"seed"}}'
# → variables.q is injected as a `graphql` parameter
```

A plain REST endpoint that merely has a field named `query` (a search box, `{"query":"laptop"}`) is **not** treated as GraphQL — the `variables` object and an operation-shaped value are both required, so ordinary JSON bodies stay on the normal `json` path.

**XML / SOAP** (`text/xml`, `application/xml`, `application/soap+xml`, or a body with an `<?xml …?>` prolog): each element text node and attribute value is probed, and each one that reflects becomes an `xml` parameter. A byte-range splice injects the payload in place, leaving every other byte of the document — namespaces, sibling elements, the SOAP envelope — untouched, and the request's XML content-type is preserved.

```bash
dalfox scan https://target.app/soap \
  -X POST \
  -H 'Content-Type: application/soap+xml' \
  -d '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><search><term>seed</term></search></soap:Body></soap:Envelope>'
# → the <term> text node is injected as an `xml` parameter
```

As with every reflected finding, a value only grades `[V]` when the response is a document a browser would render as markup (see [Detection Model](../detection-model/#what-the-response-content-type-allows)) — a GraphQL API that answers `application/json`, or an XML service that echoes an escaped value, is correctly reported as inert. The real reach is an admin view, report, or error page that renders the reflected value as markup.

## Reflection probe shape

Every discovery and mining probe sends a sandwich marker (`OPEN + INNER + CLOSE`) instead of a single token. The response is then classified into one of four cases:

| Reflection | Meaning |
|------------|---------|
| **Full** | The complete `OPEN+INNER+CLOSE` survived. Standard reflection. |
| **PrefixOnly** | `OPEN+INNER` is present, `CLOSE` was stripped. Suggests a suffix-strip filter. |
| **SuffixOnly** | `INNER+CLOSE` is present, `OPEN` was stripped. Suggests a prefix-strip filter. |
| **InnerOnly** | Only `INNER` survives. Suggests a regex extract or both wraps removed. |

All four are treated as "reflected": discovery records the parameter and the scan proceeds. A naive single-token check would have missed every case except *Full*, leaving prefix-/suffix-stripping endpoints undetected. The marker tokens are scan-unique (`dlx`/`dlxmid`/`xld` prefixes plus 8 hex chars per scan), so accidental collisions in HTML are negligible.

## What makes a finding "verified"

| Result | How it's confirmed |
|--------|--------------------|
| **V** (Vulnerable) | Dalfox parses the response DOM and finds the payload in a position that would execute. This is a static parse of a real response, not browser execution; see [Detection Model](../detection-model/). The `evidence` field tags the path that proved it: DOM marker (CSS selector hit), executable URL (`javascript:`/`data:` in a dangerous attribute), HTML structural (an injected element with an `on*` handler whose value is a sink call), JS-context AST (a sink call inside `<script>` that the parsed AST shows is covered by the payload's byte range), or inline-handler breakout (the payload closed the JS string inside an existing `on*` attribute). |
| **A** (AST-detected) | Static JavaScript analysis traced a user-controlled source to a dangerous sink (e.g., `innerHTML = location.hash`). |
| **R** (Reflected) | Payload text appeared in the response body, but no DOM evidence yet. Still worth investigating manually. |

`V` and `A` are the signals. `R` is a hint.

## Safe contexts

A reflection whose every occurrence sits inside `<textarea>`, `<title>`, `<noscript>`, `<xmp>`, or `<plaintext>` is not reported: content there renders as text, so it would only produce false positives. The parameter is still scanned, so a payload that closes the element first (`</textarea><svg onload=…>`) can still be found.

The same gate drops a few other inert shapes: a reflection that only lands inside `<script>` where the parsed JavaScript shows it produces no sink call, an echo the server escaped (percent- or entity-encoded) outside a URL-valued attribute, and a `javascript:` / `data:` payload that never lands at the start of a URL-valued attribute. Responses a browser would not render as markup (JSON, `text/plain`, …) are gated separately, by [content type](../detection-model/#what-the-response-content-type-allows).

## Next

- See how payloads are built in [Payloads &amp; Encoding](../payloads/).
- Dealing with a WAF? Jump to [WAF Bypass](../waf-bypass/).
