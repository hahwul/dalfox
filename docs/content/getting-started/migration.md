+++
title = "Migrating from v2"
description = "What changed between Dalfox v2 (Go) and v3 (Rust): consolidated subcommands, renamed flags, retired features, and their replacements."
weight = 5
toc = true
+++

Dalfox v3 is a complete rewrite in Rust, replacing the legacy Go architecture. The Go sources live on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2) and receive critical security backports only — all new work happens in v3.

This page maps a v2 workflow onto v3: which subcommands collapsed, which flags were renamed, what was retired and why, and what you get in return.

## 1. Subcommand consolidation

v3 unifies the scan subcommands behind a single entrypoint.

| v2 usage | v3 equivalent | Note |
| :--- | :--- | :--- |
| `dalfox url [url]` | `dalfox scan [url]` | Or just `dalfox [url]` — `scan` is the default subcommand, but the bare form takes no scan flags beyond `--config`, `--debug`, `--no-color` and `-S` |
| `dalfox file [file]` | `dalfox scan [file]` | Input type is auto-detected |
| `dalfox pipe` | `cat targets \| dalfox scan` (or `dalfox scan --input-type pipe`) | Piped input is read from `stdin` natively |
| `dalfox sxss [url]` | `dalfox scan [url] --sxss` | Stored XSS is a scan option now — see [Stored XSS](../../guide/stored-xss/) |
| `dalfox server --type mcp` | `dalfox mcp` | MCP is its own stdio subcommand — see [MCP Server](../../integrations/mcp/) |
| `dalfox payload --entity-event-handler` (and the other `--enum-*` / `--entity-*` / `--remote-*` switches) | `dalfox payload <selector>` | One positional selector, e.g. `event-handlers`, `useful-tags`, `special-chars`, `portswigger`, `payloadbox` — run `dalfox payload --help` for the list |

{{ alert(type="info", body="The legacy url, file and pipe subcommands survive as hidden aliases. file and pipe keep their v2 shape. url does not: it takes the target through -u/--url (dalfox url -u URL), so a v2 line like dalfox url URL fails — switch it to dalfox scan URL. sxss did not survive: stored-XSS scanning moved onto the scan subcommand as the --sxss flag.") }}

v2's `--rawdata` and `--har` input switches are gone too: a captured raw HTTP request and a HAR export are auto-detected (`dalfox scan request.txt`, `dalfox scan capture.har`), or can be forced with `--input-type raw-http` / `--input-type har`. See [Quick Start](../quick-start/).

## 2. Renamed flags

| v2 flag | v3 flag | Reason & behavior |
| :--- | :--- | :--- |
| `-w, --worker <int>` | `--workers <int>` | Renamed, and there is no `-w` short form. Sets the number of concurrent scanning workers; the default dropped from 100 to 50. |
| `-H, --header <string>` | `-H, --headers <string>` | Long form pluralized; `-H` is unchanged. May be passed more than once. |
| `-C, --cookie <string>` | `--cookies <string>` | Pluralized for consistency, no `-C` short form; may be passed more than once. |
| `-p, --param <string>` | `-p, --param <string>` | Now scoped by parameter type — `-p id:query`, `-p sort:body`. |
| `--skip-mining-all` | `--skip-mining` | Renamed. |
| `--mining-dict=false`, `--mining-dom=false` | `--skip-mining-dict`, `--skip-mining-dom` | Only the `--skip-*` forms remain (they existed in v2 too). |
| `--output-request`, `--output-response` | `--include-request`, `--include-response` | Renamed; `--include-all` sets both. Still opt-in. |
| `--limit-result <int>` | `--limit <int>` | Renamed; the scan stops once the cap is reached. `--limit-result-type` keeps its name. |
| `--trigger <url>` (on `sxss`) | `--sxss-url <url>` | With `--sxss` and no `--sxss-url`, the check URL is auto-detected from form discovery. |
| `--silence-force` (on `file` / `pipe`) | `-S, --silence` | `-S` now prints only PoC output. |
| `--mass`, `--multicast`, `--mass-worker` (on `file` / `pipe`) | `--max-concurrent-targets`, `--max-targets-per-host` | Targets are always scanned concurrently; these two flags bound it. |

The full, generated flag list lives in the [CLI Reference](../../reference/cli/).

## 3. Retired features and their replacements

Some legacy flags and the heavyweight engines behind them were dropped to keep v3 fast, safe, and focused on XSS.

| Retired v2 flag | Alternative | Why |
| :--- | :--- | :--- |
| `--use-bav`, `--skip-bav` | None. | **Scope**. Basic Another Vulnerability (BAV) checks are gone; v3 is strictly an XSS scanner. Use a dedicated scanner for non-XSS classes. |
| `--found-action <cmd>`, `--found-action-shell` | [REST API webhooks](../../integrations/server/), or pipe stdout (`dalfox scan ... \| post-script.sh`). | **Security**. Arbitrary shell execution on every finding invited RCE and throttled concurrency. |
| `--skip-headless`, `--force-headless-verification` | Nothing to configure — static analysis is always on. | **Engine replaced**. Headless Chrome (`chromedp`) is gone. v3 verifies with a compiler-grade JavaScript parser (`oxc`), tracing data flows and DOM sinks without a browser. See [Detection Model](../../guide/detection-model/). |
| `--grep <file>`, `--skip-grepping` | None. | **Engine replaced**. Regex response matching gave way to context-aware AST analysis. `--only-poc g` (grep findings) went with it. |
| `--report`, `--report-format` | `-f markdown -o <file>`, `-f sarif -o <file>`. | **Standardization**. Report flags folded into the output format flags — see [Output & Reports](../../guide/output/). |
| `--max-cpu` | Automatic. | **Architecture**. The async scheduler (`tokio`) allocates work across cores; manual CPU pinning is obsolete. |
| `--no-spinner` | Automatic. | **UI**. Banners and spinners are suppressed on their own for pipes, silent mode (`-S`), and machine-readable formats (`json`, `sarif`, …). |
| `--context-aware`, `--magic-char-test` | Nothing to configure. | **Built in**. Every reflected parameter gets per-character probes (`valid_specials` / `invalid_specials`) that steer payload selection. |
| `--deep-domxss`, `--detailed-analysis`, `--fast-scan`, `--har-file-path` | None. | **Removed**. No v3 flag replaces them; v3 reads HAR files as input but does not record one. |

Because headless verification is gone, a finding's evidence class matters more than it did in v2: `[V]` means DOM-level evidence in the parsed response, `[A]` means a static-analysis source-to-sink flow worth confirming in a browser. [Detection Model](../../guide/detection-model/) explains the grading.

## 4. What v3 adds

- **MCP server (`dalfox mcp`)** — exposes Dalfox to AI coding assistants over JSON-RPC on stdio, replacing v2's `server --type mcp`. See [MCP Server](../../integrations/mcp/).
- **Hard time budget (`--scan-timeout <secs>`)** — caps the payload-injection stage per target so a half-hung server can't stall the run. Discovery and mining are bounded by `--timeout` instead.
- **Payload cap (`--max-payloads-per-param <int>`)** — keeps combinatorial payload expansion (bypasses × encoders) from turning into a request burst.
- **Preflight (`--dry-run`)** — reports discovered parameters and an estimated request count without sending a single payload.
- **Adaptive WAF evasion (`--waf-evasion`)** — the flag existed in v2 as a fixed `worker=1, delay=3s` preset. In v3, on WAF detection, it randomizes inter-request timing and escalates a cooldown when blocked responses cluster. See [WAF Bypass](../../guide/waf-bypass/).
- **HTTP parameter pollution (`--hpp`)** — duplicates query parameters to slip past string-matching WAF layers.
- **Managed OAST (`--blind-oob`)** — registers an interactsh session and correlates callbacks to the payload that caused them, alongside the plain `-b` callback URL.
- **Pacing and retries (`--rate-limit`, `--retries`)** — a global requests-per-second cap shared by every worker, and backoff retries on 5xx and transient errors.
- **Resumable and incremental runs (`--state-file`, `--baseline`)** — skip targets a previous run completed, or report only findings new since an earlier JSON report.
- **Session monitoring (`--session-check`)** — an authenticated scan whose session drops is reported as incomplete instead of clean.
- **Shell completions (`dalfox completion <shell>`)** — bash, zsh, fish, PowerShell, and Elvish.

## Next steps

- Re-read the [scanning modes](../../guide/scanning-modes/) — the flags you reach for by reflex may have moved.
- Move your recurring v2 command line into a [config file](../configuration/).
- Skim the [CLI Reference](../../reference/cli/) for flags that have no v2 ancestor at all.
