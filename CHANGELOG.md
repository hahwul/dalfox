# Changelog

All notable changes to Dalfox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The previous Go implementation lives on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2)
and continues to receive security backports per [SECURITY.md](./.github/SECURITY.md).

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
