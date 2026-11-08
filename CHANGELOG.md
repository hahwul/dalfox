# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./.github/SECURITY.md).

## 3.3.0

API-spec scanning, blind OOB and session-loss detection on the server / MCP, actionable confidence, new detection classes (CSTI, JS exec sinks, file-upload XSS), and wider DOM-XSS coverage.

* **Security**: rustls bumped to 0.23.46 for RUSTSEC-2026-0346..0349 ([#1557](https://github.com/hahwul/dalfox/pull/1557)).
* `-i openapi` / `-i postman`: scan an OpenAPI 3.x / Swagger 2.0 spec or a Postman collection, with `--base-url` to retarget its servers ([#1525](https://github.com/hahwul/dalfox/pull/1525)).
* Server / MCP reach CLI parity on blind OOB (`blind_oob`, `blind_oob_wait`) and session-loss detection (`session_check`, `session_check_url`). Cancel now stops a job during preflight, discovery and mining and deregisters an in-flight OOB registration; a disconnected preflight client releases its permit ([#1524](https://github.com/hahwul/dalfox/pull/1524), [#1558](https://github.com/hahwul/dalfox/pull/1558), [#1668](https://github.com/hahwul/dalfox/pull/1668), [#1669](https://github.com/hahwul/dalfox/pull/1669), [#1670](https://github.com/hahwul/dalfox/pull/1670)).
* `--min-confidence <low|high>` filters findings on every surface (CLI, REST, MCP, the `--limit` tally, the exit code), with `meta.min_confidence.dropped` so a filtered target isn't mistaken for a clean one. Plain output shows the grade and dedup ranks by it ([#1526](https://github.com/hahwul/dalfox/pull/1526), [#1558](https://github.com/hahwul/dalfox/pull/1558)).
* Findings carry a per-parameter `filter` fingerprint (`allowed` / `blocked` / `escaped` characters) in every output format ([#1521](https://github.com/hahwul/dalfox/pull/1521)).
* New detection: CSTI on AngularJS / Vue pages that HTML-escape the reflection (low confidence, version-aware PoC, refreshed Vue 2/3 gadgets), and JS-string values that reach `eval` / `setTimeout` / `Function` / `javascript:` navigation without a breakout ([#1542](https://github.com/hahwul/dalfox/pull/1542), [#1560](https://github.com/hahwul/dalfox/pull/1560), [#1561](https://github.com/hahwul/dalfox/pull/1561), [#1686](https://github.com/hahwul/dalfox/pull/1686)).
* Stored XSS: `--sxss-url` is repeatable (config `sxss_url` takes a list), and a captured upload request injects into both the file content and its filename, then follows the upload to the stored file. `Content-Disposition: attachment` responses are never reported ([#1651](https://github.com/hahwul/dalfox/pull/1651), [#1686](https://github.com/hahwul/dalfox/pull/1686)).
* Wider DOM-XSS AST coverage: class bodies and per-object `this`, private fields, bound callbacks, parameter defaults, getters, `currentScript.src`, module `export`s, jQuery `.attr()` / `.prop()` / `.wrap*()` / `$.globalEval`, popup `document.write`, and React `dangerouslySetInnerHTML`. Navigation sinks now get a `javascript:` PoC ([#1544](https://github.com/hahwul/dalfox/pull/1544), [#1545](https://github.com/hahwul/dalfox/pull/1545), [#1552](https://github.com/hahwul/dalfox/pull/1552), [#1652](https://github.com/hahwul/dalfox/pull/1652)).
* `--detect-outdated-libs` adds DOMPurify, Underscore, Knockout, jQuery Validation and Mustache.js, reads versions from jsDelivr / unpkg / cdnjs URLs, and treats npm two-part tags (`@4.17`) as ranges ([#1594](https://github.com/hahwul/dalfox/pull/1594), [#1598](https://github.com/hahwul/dalfox/pull/1598), [#1613](https://github.com/hahwul/dalfox/pull/1613), [#1641](https://github.com/hahwul/dalfox/pull/1641), [#1642](https://github.com/hahwul/dalfox/pull/1642), [#1686](https://github.com/hahwul/dalfox/pull/1686)).
* New WAF fingerprints: DDoS-Guard, Reblaze. `--force-waf` accepts Wallarm, NAXSI and SafeLine ([#1612](https://github.com/hahwul/dalfox/pull/1612), [#1639](https://github.com/hahwul/dalfox/pull/1639), [#1640](https://github.com/hahwul/dalfox/pull/1640)).
* Per-target state is keyed by URL + method + body, so spec / HAR imports with several methods on one URL no longer share skip or finding status; `target_summary` and `meta.skipped` gain a `method` field ([#1536](https://github.com/hahwul/dalfox/pull/1536)).
* Targets cut by `--scan-timeout` report a `SCAN_TIMEOUT` error code ([#1559](https://github.com/hahwul/dalfox/pull/1559)).
* Two bug hunts, ~80 crash, silent-clean and hostile-input fixes: `--limit` accounting, 429 and unreadable bodies counted as failed requests, Ctrl-C stops preflight, scope filters gate discovered form actions, `-H 'Cookie: ...'` probed per cookie, bounded CPU on hostile pages and `<meta>` CSPs ([#1529](https://github.com/hahwul/dalfox/pull/1529), [#1530](https://github.com/hahwul/dalfox/pull/1530), [#1538](https://github.com/hahwul/dalfox/pull/1538), [#1576](https://github.com/hahwul/dalfox/pull/1576)).
* Bad input fails at startup instead of mid-scan: `--input-type`, `-p name:type`, `--ignore-return`, `--blind-oob-wait`, `-b/--blind`, `--cookies` without a `name=value` pair, an unwritable `-o` directory. REST / MCP share the same validators. `--out-of-scope` matches trailing-dot, IPv6 and IDNA hosts, and raw HTTP accepts extra whitespace in the request line ([#1588](https://github.com/hahwul/dalfox/pull/1588), [#1589](https://github.com/hahwul/dalfox/pull/1589), [#1609](https://github.com/hahwul/dalfox/pull/1609), [#1610](https://github.com/hahwul/dalfox/pull/1610), [#1671](https://github.com/hahwul/dalfox/pull/1671), [#1673](https://github.com/hahwul/dalfox/pull/1673), [#1674](https://github.com/hahwul/dalfox/pull/1674), [#1675](https://github.com/hahwul/dalfox/pull/1675), [#1676](https://github.com/hahwul/dalfox/pull/1676), [#1686](https://github.com/hahwul/dalfox/pull/1686)).
* Custom-alert substitution applies on every payload path, and custom payload files strip a BOM ([#1578](https://github.com/hahwul/dalfox/pull/1578)).
* SARIF `$schema` URL fixed (was a 404); `--help` no longer prints defaults twice or leaks internal notes; `payload --json` lists every selector ([#1541](https://github.com/hahwul/dalfox/pull/1541), [#1677](https://github.com/hahwul/dalfox/pull/1677), [#1678](https://github.com/hahwul/dalfox/pull/1678), [#1679](https://github.com/hahwul/dalfox/pull/1679)).
* Redesigned docs site and a plain-language rewrite of the EN / KO docs ([#1540](https://github.com/hahwul/dalfox/pull/1540), [#1571](https://github.com/hahwul/dalfox/pull/1571), [#1667](https://github.com/hahwul/dalfox/pull/1667)).

## 3.2.4

Fewer false positives, PoCs that reproduce the request actually sent, a fuller MCP protocol surface, and hardening against target-controlled data.

* **Security**: hardened PoC and report output against target-controlled parameter names and bodies — fish-safe shell quoting, terminal escape sequences stripped, Markdown cells escaped, `-o` reports written `0600` ([#1463](https://github.com/hahwul/dalfox/pull/1463), [#1483](https://github.com/hahwul/dalfox/pull/1483), [#1513](https://github.com/hahwul/dalfox/pull/1513)).
* **Security**: server / MCP `deep_scan` findings are capped (one job against an echo-everything target could hold gigabytes), the per-proxy client cache is bounded, and OAST TLS verification can no longer be disabled by a port-spelled host ([#1464](https://github.com/hahwul/dalfox/pull/1464), [#1513](https://github.com/hahwul/dalfox/pull/1513)).
* MCP speaks more of the protocol: structured tool output (`outputSchema` / `structuredContent`), its own `serverInfo` and instructions, progress notifications, resources, prompts, completions, and cancellation. Tool calls accept the REST argument spellings (`cookie`, `header`, ...) and reject unknown keys instead of silently dropping them — previously a scan could run without its cookies and report clean — and draining jobs can no longer be deleted ([#1464](https://github.com/hahwul/dalfox/pull/1464), [#1466](https://github.com/hahwul/dalfox/pull/1466), [#1469](https://github.com/hahwul/dalfox/pull/1469), [#1474](https://github.com/hahwul/dalfox/pull/1474)).
* Parameter mining batches candidate names into bounded canary buckets with bisection, cutting mining requests, and ships an expanded built-in wordlist ([#1473](https://github.com/hahwul/dalfox/pull/1473)).
* Wider DOM-XSS recall: reflected-markup sources (`dataset` / `getAttribute` / `textContent` / CSS), `form.action` on a form receiver, and decoded server literals ([#1495](https://github.com/hahwul/dalfox/pull/1495)).
* Fewer false positives: findings are gated by the response content type (JSON, CSV, `text/plain` and malformed XML are inert; SVG / XHTML still verify), and inline-handler `[V]` requires a real JS breakout rather than a payload sitting in a string ([#1478](https://github.com/hahwul/dalfox/pull/1478), [#1494](https://github.com/hahwul/dalfox/pull/1494)).
* PoCs reproduce the request the scan sent: no duplicated path segment, pre-encoded / cookie / multi-URL params rendered as sent, and body PoCs replay the full wire body including sibling fields ([#1477](https://github.com/hahwul/dalfox/pull/1477), [#1479](https://github.com/hahwul/dalfox/pull/1479), [#1510](https://github.com/hahwul/dalfox/pull/1510)).
* Generated HTML / attribute payloads that could reflect but never DOM-verify were repaired, `--only-custom-payload` no longer leaks generated payloads, and invalid WAF mutations were dropped ([#1475](https://github.com/hahwul/dalfox/pull/1475), [#1490](https://github.com/hahwul/dalfox/pull/1490)).
* Request construction keeps URL semantics: literal `%`-sequences, every duplicate query / form key, empty path segments, same-named header vs cookie params, and raw-HTTP / HAR bodies reaching the miners ([#1480](https://github.com/hahwul/dalfox/pull/1480), [#1484](https://github.com/hahwul/dalfox/pull/1484)).
* CSP analysis merges every enforcing policy (multiple headers and `<meta>`), and an enforcing `<meta>` beats a report-only header ([#1481](https://github.com/hahwul/dalfox/pull/1481), [#1486](https://github.com/hahwul/dalfox/pull/1486)).
* Stored XSS (`--sxss`) finds form-backed sinks that don't echo on write, and attributes each finding to the field that stored it ([#1493](https://github.com/hahwul/dalfox/pull/1493)).
* Honest run outcomes: one unparsable line no longer aborts a whole target list, targets cut short by `--limit` / Ctrl-C / `--scan-timeout` report `incomplete` instead of `clean`, findings are attributed to the target that produced them, and `--state-file` resume keys raw-HTTP / HAR targets by request content ([#1468](https://github.com/hahwul/dalfox/pull/1468), [#1485](https://github.com/hahwul/dalfox/pull/1485), [#1510](https://github.com/hahwul/dalfox/pull/1510)).
* `--delay` and `-H User-Agent` are honored everywhere, HPP targets the form action with pre-encoded payloads, and REST / MCP reachability probes match the CLI ([#1476](https://github.com/hahwul/dalfox/pull/1476), [#1487](https://github.com/hahwul/dalfox/pull/1487), [#1488](https://github.com/hahwul/dalfox/pull/1488), [#1491](https://github.com/hahwul/dalfox/pull/1491)).
* Bounded superlinear CPU / memory on hostile responses and inputs (HTML nesting estimator bypasses, XML entity amplification, AST scope cloning) ([#1504](https://github.com/hahwul/dalfox/pull/1504)).
* Chocolatey package for Windows, published on release ([#1511](https://github.com/hahwul/dalfox/pull/1511)).

## 3.2.3

A credential-leak fix, large scan-performance cuts, and wider XSS coverage.

* **Security**: a scanned page could choose where Dalfox sent the operator's `-H` headers and `--cookies`. Cross-origin `<form action>` targets are no longer probed during parameter discovery ([GHSA-mph2-gf5w-6f9f](https://github.com/hahwul/dalfox/security/advisories/GHSA-mph2-gf5w-6f9f), [#1460](https://github.com/hahwul/dalfox/pull/1460), [#1461](https://github.com/hahwul/dalfox/pull/1461)). Thanks to the DREAM Security Research Team — Arad Inbar, Adiel Sol, Erez Cohen, Nir Somech, Ben Grinberg, Daniel Lubel and Shir Sadon — for the report.
* **Security**: `--follow-redirects` now stops when a chain leaves the origin it started on, with a carve-out for the same-host `http` -> `https` upgrade. Previously a redirect off-target leaked custom credential headers on the first hop and the full `Cookie` / `Authorization` on the second ([GHSA-69jp-6fh7-wjpm](https://github.com/hahwul/dalfox/security/advisories/GHSA-69jp-6fh7-wjpm), [#1460](https://github.com/hahwul/dalfox/pull/1460), [#1461](https://github.com/hahwul/dalfox/pull/1461)).
* Scans no longer run through the environment's `HTTP_PROXY` / `HTTPS_PROXY`, which the docs already said they didn't ([#1441](https://github.com/hahwul/dalfox/pull/1441)).
* Much faster scans: payload requests now run concurrently *within* a parameter, batches ramp instead of jumping to a full `--workers` window, and endpoints that uniformly escape their echo exit early instead of running the whole catalog ([#1440](https://github.com/hahwul/dalfox/pull/1440), [#1442](https://github.com/hahwul/dalfox/pull/1442), [#1457](https://github.com/hahwul/dalfox/pull/1457)).
* New injection surfaces: GraphQL and XML / SOAP request bodies ([#1426](https://github.com/hahwul/dalfox/pull/1426), [#1427](https://github.com/hahwul/dalfox/pull/1427)).
* Wider DOM-XSS AST coverage — Promise combinators, optional chaining, static bracket paths, more sinks and sources — with fewer false positives ([#1426](https://github.com/hahwul/dalfox/pull/1426), [#1444](https://github.com/hahwul/dalfox/pull/1444)).
* Detects the sub-not-gsub angle filter: a doubled `<<svg ...>>` opens a real tag where a one-shot `str::replace` only ate the first `<` ([#1445](https://github.com/hahwul/dalfox/pull/1445)).
* Fewer escaped-echo `[R]` false positives, and quote inference is scoped to tag / element content ([#1457](https://github.com/hahwul/dalfox/pull/1457), [#1458](https://github.com/hahwul/dalfox/pull/1458)).
* A batch of server / MCP lifecycle, CLI / config, raw-HTTP / HAR import, and PoC-reproduction fixes ([#1405](https://github.com/hahwul/dalfox/pull/1405)-[#1425](https://github.com/hahwul/dalfox/pull/1425), [#1438](https://github.com/hahwul/dalfox/pull/1438)).

## 3.2.2

Request-construction / input-validation hardening, new WAF fingerprints, and shell-completion + man-page packaging.

* Hardened request building and input validation: header-value checks, raw-HTTP `//`-target Host hijack, duplicate `Content-Type`, HAR empty cookies, query injection leaking into the URL fragment, and fail-fast on unroutable `--proxy` / non-http `--sxss-url` / failed `--cookie-from-raw` ([#1404](https://github.com/hahwul/dalfox/pull/1404), [#1396](https://github.com/hahwul/dalfox/pull/1396), [#1389](https://github.com/hahwul/dalfox/pull/1389), [#1384](https://github.com/hahwul/dalfox/pull/1384)).
* MCP no longer caches the scan runtime in thread-local storage (fixes a Windows hang), and two stray panics no longer abort a whole scan ([#1398](https://github.com/hahwul/dalfox/pull/1398), [#1367](https://github.com/hahwul/dalfox/pull/1367)).
* Server / MCP stop discarding `proxy` / `callback_url` and report a correct preflight estimate; config files no longer override explicitly typed CLI flags ([#1388](https://github.com/hahwul/dalfox/pull/1388), [#1372](https://github.com/hahwul/dalfox/pull/1372)).
* New WAF fingerprints: Wallarm, NAXSI, SafeLine ([#1364](https://github.com/hahwul/dalfox/pull/1364)).
* `dalfox completion` for shell completions and a generated man page, both installed by the packages ([#1374](https://github.com/hahwul/dalfox/pull/1374), [#1365](https://github.com/hahwul/dalfox/pull/1365), [#1380](https://github.com/hahwul/dalfox/pull/1380)).
* `dalfox payload`: a `javascript` selector and slash-separated attribute breakouts for space-stripping filters ([#1386](https://github.com/hahwul/dalfox/pull/1386), [#1402](https://github.com/hahwul/dalfox/pull/1402)).

## 3.2.1

A false-positive / recall fix on framework error pages, stability hardening, and `dalfox payload` improvements.

* Fan-out cost cuts no longer delete the finding they bound: mining collapse folds away only what it mined itself — a page echoing its whole query string used to report a POC against a synthetic `any` parameter while missing the real one — and a 5xx that reflects the payload no longer ends the DOM phase ([#1362](https://github.com/hahwul/dalfox/pull/1362)).
* Hardened against crashes, hangs, and scans that reported clean without scanning: a panic on non-ASCII Trusted Types callbacks was swallowed into `0 XSS` / exit 0, quadratic HTML-nesting parses, unbounded memory in JS-breakout payloads and retained bodies, `--only-custom-payload` with no file, `--skip-xss-scanning` still firing blind payloads, `--cookies` folding into one cookie, and unvalidated `--sxss-*` ([#1361](https://github.com/hahwul/dalfox/pull/1361)).
* `dalfox server` refuses browser-driven cross-site and DNS-rebound requests via an `Origin` / `Sec-Fetch-Site` / `Host` gate ([#1356](https://github.com/hahwul/dalfox/pull/1356)).
* Cookie parameters are injected as cookies rather than same-named headers and survive the special-character probe (cookie recall 80.0% → 87.5%); no more `[V]` for `text/plain` + `nosniff`; `-f plain -o` no longer writes ANSI; `-f markdown` no longer prints the banner ([#1315](https://github.com/hahwul/dalfox/pull/1315)).
* Light-verify sends a `Content-Type` with urlencoded bodies, `--limit` aborts workers instead of detaching them, and REST / MCP `rate_limit` now covers discovery and mining ([#1360](https://github.com/hahwul/dalfox/pull/1360)).
* `dalfox payload`: JSON output, an `all` selector, per-selector counts, closest-selector suggestions, and wider uri-scheme / special-character lists ([#1358](https://github.com/hahwul/dalfox/pull/1358), [#1346](https://github.com/hahwul/dalfox/pull/1346), [#1348](https://github.com/hahwul/dalfox/pull/1348), [#1349](https://github.com/hahwul/dalfox/pull/1349), [#1350](https://github.com/hahwul/dalfox/pull/1350)).
* Modern JavaScript framework detection ([#1352](https://github.com/hahwul/dalfox/pull/1352)).

## 3.2.0

Mass-scan workflow features, wider DOM-XSS coverage, and CSP / false-positive fixes.

### Added

* `--state-file`: resume an interrupted mass scan, skipping completed targets ([#1275](https://github.com/hahwul/dalfox/issues/1275)).
* `--baseline`: report only findings new since a previous run ([#1279](https://github.com/hahwul/dalfox/pull/1279)).
* `--dedup-urls`: signature-level target deduplication for large URL lists ([#1278](https://github.com/hahwul/dalfox/pull/1278)).
* Session-loss detection: warn when auth dies mid-scan instead of reporting zero findings ([#1277](https://github.com/hahwul/dalfox/pull/1277), [#1285](https://github.com/hahwul/dalfox/pull/1285)).
* New DOM-XSS sinks: drag-drop, async clipboard, `FileReader`, `setAttributeNS`, indirect `eval`, `DOMParser` ([#1257](https://github.com/hahwul/dalfox/pull/1257), [#1258](https://github.com/hahwul/dalfox/pull/1258)).
* HTTP `QUERY` method support (RFC 10008) ([#1220](https://github.com/hahwul/dalfox/pull/1220)).
* MCP: `max_payloads_per_param` and a synchronous wait mode ([#1223](https://github.com/hahwul/dalfox/pull/1223)).
* More `dalfox payload` selectors (special chars, functions, awesome-alert, ...) ([#1271](https://github.com/hahwul/dalfox/pull/1271)).
* Findings now carry separate confidence / detection-method / impact axes ([#1246](https://github.com/hahwul/dalfox/pull/1246)).

### Fixed

* CSP analysis: `default-src` no longer overrides `script-src`, wildcard origins match deeper subdomains, and enforcing `<meta>` policies win over report-only ([#1266](https://github.com/hahwul/dalfox/pull/1266), [#1267](https://github.com/hahwul/dalfox/pull/1267), [#1268](https://github.com/hahwul/dalfox/pull/1268)).
* No more verified `[V]` for HTML-tag echoes in `application/javascript` bodies ([#1286](https://github.com/hahwul/dalfox/pull/1286)).
* Absent multipart params are now injected, and empty JSON body values no longer garble the request ([#1260](https://github.com/hahwul/dalfox/pull/1260), [#1261](https://github.com/hahwul/dalfox/pull/1261), [#1263](https://github.com/hahwul/dalfox/pull/1263)).
* SARIF output emits a matching rule and correct `ruleIndex` per finding CWE ([#1262](https://github.com/hahwul/dalfox/pull/1262)).
* Config files are validated, and an explicit CLI flag now beats a config value even when it equals the default ([#1228](https://github.com/hahwul/dalfox/pull/1228), [#1270](https://github.com/hahwul/dalfox/pull/1270), [#1280](https://github.com/hahwul/dalfox/pull/1280)).
* Server / MCP: validated `method` / `encoders` at the API boundary, deterministic scan listing order, and an honest `cancelled` response ([#1269](https://github.com/hahwul/dalfox/pull/1269), [#1264](https://github.com/hahwul/dalfox/pull/1264), [#1237](https://github.com/hahwul/dalfox/pull/1237), [#1229](https://github.com/hahwul/dalfox/pull/1229)).
* `--deep-scan` runs the preflight probe again, `--limit-result-type` no longer hides the findings it limited on, and `-i` reads every file argument ([#1212](https://github.com/hahwul/dalfox/pull/1212)).
* Honest redirect evidence, working `--sxss` discovery, bare `-p` seeding when discovery is skipped, and no stdin hang when a target is given ([#1242](https://github.com/hahwul/dalfox/pull/1242), [#1221](https://github.com/hahwul/dalfox/pull/1221), [#1241](https://github.com/hahwul/dalfox/pull/1241)).
* WAF: sink keywords match on identifier boundaries, and blocking statuses boost confidence even with an empty body ([#1259](https://github.com/hahwul/dalfox/pull/1259), [#1265](https://github.com/hahwul/dalfox/pull/1265)).
* Windows binary no longer overflows the main thread stack at startup ([#1294](https://github.com/hahwul/dalfox/pull/1294)).

### Performance

* One shared HTML parse per AST DOM phase ([#1256](https://github.com/hahwul/dalfox/pull/1256)).

### Documentation

* Korean translation and a redesigned docs site ([#1224](https://github.com/hahwul/dalfox/pull/1224), [#1230](https://github.com/hahwul/dalfox/pull/1230)).
* Documented the R/V/A detection model across every surface ([#1255](https://github.com/hahwul/dalfox/pull/1255)).

## 3.1.2

* Reject non-`http(s)` URL schemes instead of mangling them into malformed targets.
* Suppressed false `[R]` for inert `javascript:` reflections and false `[V]` for `on*` on hidden inputs ([#1183](https://github.com/hahwul/dalfox/issues/1183)).
* Resource-safety, REST / MCP parity, and hot-path performance fixes in the async scan front-ends ([#1190](https://github.com/hahwul/dalfox/pull/1190)).
* Bounded query-discovery memory during parameter mining.
* Documentation accuracy fixes across `--scan-timeout`, MCP encoders, `server` flags, and WAF values.

## 3.1.1

* Unified the scan target parameter on `target` for server / MCP (`url` kept as a REST alias) ([#1152](https://github.com/hahwul/dalfox/pull/1152)).
* Unified debug logging through a single stderr macro and structured server / MCP loggers.
* Restored reflected-XSS recall in raw-JS-expression and regex-literal contexts ([#1161](https://github.com/hahwul/dalfox/pull/1161)).
* Demoted inert URL-scheme and `javascript:` self-link reflections ([#1153](https://github.com/hahwul/dalfox/issues/1153)).
* `url` / `file` / `pipe` now apply config files, global flags, and an explicit `-i`.
* `--output` write failures report via stderr and a non-zero exit code.
* Bounded request fan-out with a per-parameter payload cap and DOM-phase early exit ([#1155](https://github.com/hahwul/dalfox/pull/1155), [#1156](https://github.com/hahwul/dalfox/pull/1156)).

## 3.1.0

A feature release: out-of-band XSS, external / modern DOM-sink analysis, CSP awareness, HAR input, and rate limiting.

### Added

* `--blind-oob`: out-of-band (blind) XSS detection via an [interactsh](https://github.com/projectdiscovery/interactsh) server. CLI-only.
* `--analyze-external-js`: fetches same-origin `<script src>` bundles and runs them through AST DOM-XSS analysis ([#1094](https://github.com/hahwul/dalfox/issues/1094)).
* `--detect-outdated-libs`: flags known-vulnerable front-end library versions ([#1074](https://github.com/hahwul/dalfox/issues/1074)).
* `--input-type har`: accepts a HAR / proxy export as a scan source ([#1095](https://github.com/hahwul/dalfox/issues/1095)).
* `--rate-limit`: a requests-per-second token bucket shared across all workers and targets ([#1096](https://github.com/hahwul/dalfox/issues/1096)).
* `--retries` / `--retry-delay`: opt-in exponential-backoff retries for 5xx and transient transport errors.
* `--insecure`: configurable TLS certificate validation ([#1111](https://github.com/hahwul/dalfox/issues/1111)).
* CSP / Trusted Types awareness, filter-aware JS breakout synthesis, and attribute-decode WAF-bypass mutations.
* Wider DOM-XSS coverage (`Document.parseHTMLUnsafe()`, `window.open()`, more JS sink names).
* `scan_timeout` for server / MCP jobs, and scan `meta` in SARIF / Markdown / TOML output.

### Changed

* `--waf-evasion` now uses randomized jitter and an escalating cooldown instead of a fixed slow preset.
* Refactored the REST server into a dedicated subsystem with an extracted job domain.

### Fixed

* Cut reflected-XSS false positives with ~31% fewer requests ([#1117](https://github.com/hahwul/dalfox/pull/1117)).
* Require a payload's handler/sink to survive on the marker element before verifying `[V]` ([#1118](https://github.com/hahwul/dalfox/issues/1118)).
* Clear DOM taint on sanitized reassignment, removing a class of DOM-XSS false positives ([#1087](https://github.com/hahwul/dalfox/pull/1087)).
* `--encoders` accepts `htmlpad`, `unicode`, and `zwsp`; `--blind-oob` no longer swallows the target URL.
* Parse-DoS hardening against deeply nested hostile JS, plus closed xssmaze WAF-facade gaps.

### Security & Reliability

* Capped body reads and reflection-scan work to prevent OOM and hangs on hostile responses.
* REST responses set an explicit `Content-Type` with `nosniff`; the server warns on non-loopback binds without auth.
* Fixed a per-job scope leak and added rate-limit / concurrency caps for server and MCP scans.

## 3.0.2

* Switched the rustls backend to `ring`, fixing source builds (AUR, `cargo install`, musl).
* Repaired `.deb` / `.rpm` generation and the release matrix, which had dropped most v3.0.1 artifacts.
* Hardened the docs site: self-hosted assets, `robots.txt`, `security.txt`, and a tighter CSP.

## 3.0.1

* DOM-XSS coverage for jQuery selector-to-HTML sinks, dynamic `import()`, and `fetch()` / XHR sources.
* NetScaler and cookie-based WAF fingerprints; orthogonal bypass expansion to avoid combinatorial blow-up.
* Native `.deb` / `.rpm` packages, musl binaries, and Snapcraft / AUR distribution.
* Explicit `-p` / `-d` targets are always tested, regardless of `--skip-*` flags (XSSMaze 92.7% → 98.2%).
* Workers shut down gracefully instead of panicking on a closed semaphore.

## 3.0.0

Dalfox v3 is a complete rewrite in Rust, replacing the legacy Go implementation (now on the `v2` branch) with an asynchronous architecture and a modern CLI structure.

### Added

* **AST-based JS analysis**: `oxc`-powered static analysis for DOM-XSS, replacing headless browsers.
* **MCP server** (`dalfox mcp`): exposes Dalfox tools to AI coding assistants over stdio.
* **Async REST API server**: `axum` with job queueing, cancellation, and webhook notifications.
* TOML / JSON config files, plus `markdown`, `sarif`, and `toml` output formats.
* `--dry-run`, `--stream-findings`, `--max-payloads-per-param`, and `--scan-timeout`.

### Changed

* All target paths consolidated under a single `scan` subcommand (`url` / `file` / `pipe` kept as aliases).
* Standardized exit codes (`0` clean, `1` findings, `2` errors) for CI integration.
* Per-target progress bars, with banners suppressed for machine-readable modes.

### Removed

* The Chromium / `chromedp` headless engine and all headless-related flags.
* Legacy non-XSS checkers (BAV), to focus strictly on XSS.
* `--found-action`, `--grep`, `--report`, and `--max-cpu`.

### Security & Reliability

* Constant-time API key comparison and strict JSONP callback validation in the REST server.
* Excluded local cookie file loaders (`--cookie-from-raw`) from the MCP tool interface.
* Panic isolation (`catch_unwind`) to prevent scanner and MCP thread crashes.
