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
| `dalfox url [url]` | `dalfox scan [url]` | Or just `dalfox [url]` — `scan` is the default subcommand |
| `dalfox file [file]` | `dalfox scan [file]` | Input type is auto-detected |
| `dalfox pipe` | `cat targets \| dalfox scan` (or `dalfox scan --input-type pipe`) | Piped input is read from `stdin` natively |
| `dalfox sxss [url]` | `dalfox scan [url] --sxss` | Stored XSS is a scan option now — see [Stored XSS](../../guide/stored-xss/) |

{{ alert(type="info", body="So existing scripts keep working, the legacy url, file and pipe subcommands survive as hidden aliases. sxss did not: stored-XSS scanning moved onto the scan subcommand as the --sxss flag.") }}

Auto-detection also covers input formats v2 never read: a captured raw HTTP request (`--input-type raw-http`) and a HAR export (`dalfox scan capture.har`). See [Quick Start](../quick-start/).

## 2. Renamed flags

| v2 flag | v3 flag | Reason & behavior |
| :--- | :--- | :--- |
| `--concurrence <int>` | `--workers <int>` | Renamed. Sets the number of concurrent scanning workers. |
| `-C, --cookie <string>` | `--cookies <string>` | Pluralized for consistency; may be passed more than once. |
| `-p <string>` | `-p, --param <string>` | Now scoped by parameter type — `-p id:query`, `-p sort:body`. |

The full, generated flag list lives in the [CLI Reference](../../reference/cli/).

## 3. Retired features and their replacements

Some legacy flags and the heavyweight engines behind them were dropped to keep v3 fast, safe, and focused on XSS.

| Retired v2 flag | Alternative | Why |
| :--- | :--- | :--- |
| `--use-bav`, `--skip-bav` | None. | **Scope**. Basic Another Vulnerability (BAV) checks are gone; v3 is strictly an XSS scanner. Use a dedicated scanner for non-XSS classes. |
| `--found-action <cmd>`, `--found-action-shell` | [REST API webhooks](../../integrations/server/), or pipe stdout (`dalfox scan ... \| post-script.sh`). | **Security**. Arbitrary shell execution on every finding invited RCE and throttled concurrency. |
| `--skip-headless`, `--force-headless-verification` | Nothing to configure — static analysis is always on. | **Engine replaced**. Headless Chrome (`chromedp`) is gone. v3 verifies with a compiler-grade JavaScript parser (`oxc`), tracing data flows and DOM sinks without a browser. See [Detection Model](../../guide/detection-model/). |
| `--grep <file>`, `--skip-grep` | None. | **Engine replaced**. Regex response matching gave way to context-aware AST analysis. |
| `--report`, `--report-format` | `-f markdown -o <file>`, `-f sarif -o <file>`. | **Standardization**. Report flags folded into the output format flags — see [Output & Reports](../../guide/output/). |
| `--max-cpu` | Automatic. | **Architecture**. The async scheduler (`tokio`) allocates work across cores; manual CPU pinning is obsolete. |
| `--no-spinner` | Automatic. | **UI**. Banners and spinners are suppressed on their own for pipes, silent mode (`-S`), and machine-readable formats (`json`, `sarif`, …). |

Because headless verification is gone, a finding's evidence class matters more than it did in v2: `[V]` means DOM-level evidence in the parsed response, `[A]` means a static-analysis source-to-sink flow worth confirming in a browser. [Detection Model](../../guide/detection-model/) explains the grading.

## 4. What v3 adds

- **MCP server (`dalfox mcp`)** — exposes Dalfox to AI coding assistants over JSON-RPC. See [MCP Server](../../integrations/mcp/).
- **Hard time budget (`--scan-timeout <secs>`)** — bounds total scan time per target so a half-hung server can't stall the run.
- **Payload cap (`--max-payloads-per-param <int>`)** — keeps combinatorial payload expansion (bypasses × encoders) from turning into a request burst.
- **Preflight (`--dry-run`)** — reports discovered parameters and an estimated request count without sending a single payload.
- **Adaptive WAF evasion (`--waf-evasion`)** — on WAF detection, randomizes inter-request timing and escalates a cooldown when blocked responses cluster. See [WAF Bypass](../../guide/waf-bypass/).
- **HTTP parameter pollution (`--hpp`)** — duplicates query parameters to slip past string-matching WAF layers.

## Next steps

- Re-read the [scanning modes](../../guide/scanning-modes/) — the flags you reach for by reflex may have moved.
- Move your recurring v2 command line into a [config file](../configuration/).
- Skim the [CLI Reference](../../reference/cli/) for flags that have no v2 ancestor at all.
