# Migration Guide: Dalfox v2 to v3

Dalfox v3.0.0 is a complete rewrite in Rust, moving away from the legacy Go architecture. This guide covers changed commands, renamed flags, retired features, and their modern alternatives in v3.

---

## 1. Subcommand Consolidation

Dalfox v3 unifies multiple scan subcommands under a single, highly flexible entrypoint.

| v2 Usage | v3 Recommended Migration | Note |
| :--- | :--- | :--- |
| `dalfox url [url]` | `dalfox scan [url]` | Or simply `dalfox [url]` (defaults to `scan`) |
| `dalfox file [file]` | `dalfox scan [file]` | Input type is automatically detected |
| `dalfox pipe` | `dalfox scan -` or `cat targets \| dalfox scan` | Supports stream pipe inputs natively |
| `dalfox sxss [url]` | `dalfox scan [url] --sxss` | Stored XSS is now a scan option |

> [!NOTE]
> **Backward Compatibility**: To prevent breaking existing automated scripts, legacy commands (`url`, `file`, `pipe`, `sxss`) are preserved as **hidden aliases** and continue to function, but migrating to `dalfox scan` is highly recommended.

---

## 2. Parameter & Flag Alterations

### Renamed and Redefined Flags

| v2 Flag | v3 Flag | Reason & Behavior |
| :--- | :--- | :--- |
| `--concurrence <int>` | `--workers <int>` | Modernized naming. Dictates the number of concurrent scanning workers. |
| `-C, --cookie <string>` | `--cookies <string>` | Pluralized for consistency. Multiple occurrences are supported. |
| `-p <string>` | `-p, --param <string>` | Enhanced parameter type scoping (e.g. `-p id:query`, `-p sort:body`). |

---

## 3. Removed Features & Migration Paths

Some legacy flags and heavy engines have been retired in v3 to ensure optimal speed, security, and scanning focus.

| Retired v2 Flag | Alternative / Migration Path | Reason |
| :--- | :--- | :--- |
| `--use-bav`<br>`--skip-bav` | None. | **Deprecated**. Basic Another Vulnerability (BAV) checks are removed to strictly focus v3 as a specialized XSS scanner. Use dedicated vulnerability scanners for non-XSS checks. |
| `--found-action <cmd>`<br>`--found-action-shell` | Use REST API **webhooks** or CLI stdout **piping** (e.g., `dalfox scan ... \| post-script.sh`). | **Security Risk**. Arbitrary shell execution flags were removed to mitigate Remote Code Execution (RCE) risks and concurrency bottlenecks. |
| `--skip-headless`<br>`--force-headless-verification` | Automatically handled via static analysis. | **Engine Replaced**. The slow and resource-heavy Headless Chrome browser (`chromedp`) was completely removed. Dalfox v3 implements an extremely fast, compiler-grade JavaScript static parser (`oxc`) to analyze data-flows and trace DOM-XSS. |
| `--grep <file>`<br>`--skip-grep` | None. | **Engine Replaced**. Simple regex-based response matching is replaced by context-aware JS AST analysis for maximum accuracy. |
| `--report`<br>`--report-format` | Use `-f markdown -o <file>` or `-f sarif -o <file>`. | **Standardization**. Custom report generation flags were consolidated into unified output format parameters. |
| `--max-cpu` | Automatically managed. | **Architectural Shift**. The new async execution scheduler (`tokio`) handles core allocation automatically, making manual CPU-pinning obsolete. |
| `--no-spinner` | Automatic suppression. | **UI Overhaul**. Banners and spinners are automatically suppressed for pipe pipelines, silent modes (`-S`), or machine-readable output formats (`json`, `sarif`). |

---

## 4. Key New Capabilities in v3

Maximize your automation pipelines by leveraging these newly introduced features:

* **Model Context Protocol (`dalfox mcp`)**: Exposes Dalfox tools natively to AI coding assistants (like Claude, Cursor, Antigravity) via JSON-RPC.
* **Hard Time Budget (`--scan-timeout <secs>`)**: Bounds the total scan time per target to prevent scanning loops on partially-hung remote servers.
* **Payload Cap (`--max-payloads-per-param <int>`)**: Restricts the maximum number of tested payloads per parameter to prevent massive request bursts during combinatorial tests (bypasses + encoders).
* **Preflight Check (`--dry-run`)**: Simulates the scan, reporting discovered parameters and estimating the total request count without sending payloads.
* **WAF Evasion Tuning (`--waf-evasion`)**: Automatically throttles scanning (`workers=1`, `delay=3000`) if a WAF is triggered.
* **HTTP Parameter Pollution (`--hpp`)**: Duplicates query parameters to bypass string-matching WAF layers.
