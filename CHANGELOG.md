# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./.github/SECURITY.md).

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
