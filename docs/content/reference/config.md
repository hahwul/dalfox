+++
title = "Config File"
description = "All keys supported in Dalfox's TOML/JSON config file."
weight = 2
toc = true
+++

Dalfox picks one config directory:

1. `$XDG_CONFIG_HOME/dalfox/` when `XDG_CONFIG_HOME` is set and non-empty
2. otherwise `$HOME/.config/dalfox/` (`%USERPROFILE%\.config\dalfox\` when `HOME` is unset, e.g. on Windows)

It does not fall through to the second directory when the first holds no file. Inside the chosen directory it reads `config.toml`, or `config.json` when there is no `config.toml`. If neither exists, it writes a commented-out `config.toml` template there and runs with built-in defaults. This happens on the first run of any subcommand except `completion` and `man`, not only `scan`.

Override with `--config <path>`. TOML and JSON are both accepted: a `.json` path is parsed as JSON first, anything else as TOML first, and the other format is tried if that fails. A `--config` path that does not exist is created from a default template (JSON for a `.json` path) and the run uses built-in defaults, with a notice on stderr. Config files are capped at 1 MiB.

Everything lives under the `[scan]` table and mirrors the `dalfox scan` flag names (snake-cased). The one rename is `--blind` / `-b`, whose key is `blind_callback_url`; the global `--debug` flag is the `debug` key.

The config file only applies to CLI scans. `dalfox server` and `dalfox mcp` take scan options from each request and ignore `[scan]`.

## Complete example

```toml
[scan]
# INPUT
input_type = "auto"   # auto, url, file, pipe, raw-http, har
dedup_urls = "exact"  # exact, signature (collapse URLs differing only in param values), off
# state_file = "scan.state"  # record completed targets and skip them on re-run. CLI only — ignored by `dalfox server` / MCP

# OUTPUT
format = "plain"
# output = "results.json"
include_request = false
include_response = false
include_all = false
silence = false
dry_run = false
stream_findings = false
poc_type = "plain"
# limit = 100
limit_result_type = "all"
only_poc = []
# baseline = "baseline.json"
baseline_mode = "filter"
no_color = false

# TARGETS
param = []
# data = "user=test"
# headers = ["Accept: text/html"]
cookies = []
method = "GET"
# user_agent = "Mozilla/5.0"
# cookie_from_raw = "request.txt"

# SESSION
# session_check = "Sign out"
# session_check_url = "https://app.example.com/api/me"
on_session_loss = "abort"

# SCOPE
include_url = []
exclude_url = []
ignore_param = []
out_of_scope = []    # one pattern per entry: ["*.gov", "cdn.example.com"]
# out_of_scope_file = "scope.txt"

# DISCOVERY
only_discovery = false
skip_discovery = false
skip_reflection_header = false
skip_reflection_cookie = false
skip_reflection_path = false

# MINING
# mining_dict_word = "params.txt"
remote_wordlists = []
skip_mining = false
skip_mining_dict = false
skip_mining_dom = false

# NETWORK
timeout = 10
scan_timeout = 0
delay = 0
rate_limit = 0
retries = 0
retry_delay = 1000
# proxy = "http://127.0.0.1:8080"
insecure = true
follow_redirects = false
ignore_return = []

# ENGINE
workers = 50
max_concurrent_targets = 50
max_targets_per_host = 100

# XSS SCANNING
encoders = ["url", "html"]
remote_payloads = []
# custom_blind_xss_payload = "blind.txt"
# blind_callback_url = "https://callback.example"
# blind_oob = []                       # [] = enable with the public interactsh mesh; or name servers: ["oast.fun"]
# blind_oob_secret = "token"           # auth token for a self-hosted interactsh server
# blind_oob_wait = 30                  # seconds to keep polling after payloads are sent
# custom_payload = "payloads.txt"
only_custom_payload = false
# inject_marker = "FUZZ"
custom_alert_value = "1"
custom_alert_type = "none"
skip_xss_scanning = false
deep_scan = false
sxss = false
# sxss_url = "https://target.app/retrieval"
sxss_method = "GET"
sxss_retries = 3
max_payloads_per_param = 0
skip_ast_analysis = false
analyze_external_js = false
detect_outdated_libs = false
hpp = false

# WAF
waf_bypass = "auto"
skip_waf_probe = false
# force_waf = "cloudflare"
waf_evasion = false
waf_min_confidence = 0.3

# LOGGING
debug = false
```

## Key reference

### Input

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `input_type` | string | `"auto"` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `dedup_urls` | string | `"exact"` | `exact`, `signature` (collapse URLs differing only in param values), `off` |
| `state_file` | string | — | Record completed targets and skip them on re-run ([Resuming an interrupted scan](../../guide/scanning-modes/#resuming-an-interrupted-scan)). **CLI only** — ignored by `dalfox server` / MCP |

### Output

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"plain"` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `output` | string | — | Output file path |
| `include_request` | bool | `false` | Attach raw HTTP request |
| `include_response` | bool | `false` | Attach response body |
| `include_all` | bool | `false` | Shorthand for both |
| `silence` | bool | `false` | Suppress logs |
| `dry_run` | bool | `false` | Don't send payloads |
| `stream_findings` | bool | `false` | Print each finding mid-scan instead of after the end-of-scan summary (plain format only; off when `output`, `limit`, `only_poc` or `baseline` is set) |
| `poc_type` | string | `"plain"` | `plain`, `curl`, `httpie`, `http-request` |
| `limit` | int | — | Cap on result count (must be at least `1`; `0` is ignored with a warning) |
| `limit_result_type` | string | `"all"` | Which types count: `all`, `v`, `r`, `a`, `i` |
| `only_poc` | array | `[]` | Filter output: `["v","a"]` |
| `baseline` | string | — | Previous JSON/JSONL report to diff against; only findings new since it are reported ([Baselines](../../guide/output/#baselines-reporting-only-what-is-new)). **CLI only** — ignored by `dalfox server` / MCP |
| `baseline_mode` | string | `"filter"` | `filter` drops known findings, `annotate` keeps them and marks each `new` |
| `no_color` | bool | `false` | Disable ANSI colour |

### Targets

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `param` | array | `[]` | Parameter names (optionally `name:location`) |
| `data` | string | — | Request body |
| `headers` | array | `[]` | HTTP headers |
| `cookies` | array | `[]` | Cookie strings |
| `method` | string | `"GET"` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY`) |
| `user_agent` | string | — | User-Agent override |
| `cookie_from_raw` | string | — | Raw-request file for cookies |

### Session

Mid-scan session-loss detection — see [Session monitoring](../../guide/scanning-modes/#session-monitoring).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `session_check` | string | — | Regex that must keep matching an authenticated response body |
| `session_check_url` | string | — | Dedicated probe URL for re-validation (absolute `http(s)://`) |
| `on_session_loss` | string | `"abort"` | `abort` or `continue` |

### Scope

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `include_url` | array | `[]` | Regex patterns (unanchored); only URLs matching at least one are scanned |
| `exclude_url` | array | `[]` | Regex patterns (unanchored) of URLs to skip |
| `ignore_param` | array | `[]` | Parameter names to skip (exact match) |
| `out_of_scope` | array | `[]` | Host patterns to skip, one per entry (`["*.gov", "cdn.example.com"]`). `*.example.com` matches `example.com` and its subdomains; other values must equal the host. A comma inside an entry is not a separator |
| `out_of_scope_file` | string | — | File of out-of-scope patterns, one per line. Unreadable path aborts the scan |

### Discovery & mining

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `only_discovery` | bool | `false` | Stop after discovery |
| `skip_discovery` | bool | `false` | Skip discovery entirely |
| `skip_reflection_header` | bool | `false` | Skip header reflection checks |
| `skip_reflection_cookie` | bool | `false` | Skip cookie reflection checks |
| `skip_reflection_path` | bool | `false` | Skip path reflection checks |
| `mining_dict_word` | string | — | Wordlist path |
| `remote_wordlists` | array | `[]` | `burp`, `assetnote` |
| `skip_mining` | bool | `false` | Skip all mining |
| `skip_mining_dict` | bool | `false` | Skip dictionary mining |
| `skip_mining_dom` | bool | `false` | Skip mining parameter names from HTML `id`/`name` attributes (not DOM-XSS detection — see `skip_ast_analysis`) |

### Network

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `timeout` | int | `10` | Request timeout (seconds, `1`–`3600`); also used for remote payload/wordlist fetches |
| `scan_timeout` | int | `0` | Hard wall-clock cap per target for the payload-injection stage in seconds (max `86400`); preflight and discovery/mining are not covered. 0 disables. |
| `delay` | int | `0` | Inter-request delay (ms), per worker; max `60000` |
| `rate_limit` | int | `0` | Global request rate cap (req/sec) shared across all workers/targets; `0` = unlimited, max `100000` |
| `retries` | int | `0` | Retry 5xx / transient transport errors this many times (`0` = off, max `100`; 429 always retried) |
| `retry_delay` | int | `1000` | Base backoff (ms) between `retries` attempts (exponential; max `60000`) |
| `proxy` | string | — | Proxy URL (`http(s)://` or `socks4/5(h)://`); also used for remote payload/wordlist fetches |
| `insecure` | bool | `true` | Skip TLS certificate verification; set `false` to enforce validation. Covers the scan target and an OAST server named with `--blind-oob=`; the public interactsh mesh is always verified |
| `follow_redirects` | bool | `false` | Follow 3xx responses |
| `ignore_return` | array | `[]` | HTTP status codes to ignore, as integers (`[302, 403]`) |

### Engine

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `workers` | int | `50` | Concurrent workers per target (`1`–`500`) |
| `max_concurrent_targets` | int | `50` | Global concurrent targets (at least `1`) |
| `max_targets_per_host` | int | `100` | Per-host cap (at least `1`) |

### XSS scanning

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `encoders` | array | `["url","html"]` | Encoders to apply: `none`, `url`, `2url`, `3url`, `4url`, `html`, `htmlpad`, `base64`, `unicode`, `zwsp` |
| `remote_payloads` | array | `[]` | Remote payload sources: `portswigger`, `payloadbox` |
| `custom_blind_xss_payload` | string | — | Blind template file; each line must contain `{callback}` (lines without it are skipped) |
| `blind_callback_url` | string | — | Blind XSS callback URL (the `--blind` / `-b` flag) |
| `blind_oob` | array | — | Enable OOB/OAST blind XSS via interactsh (`[]` = public mesh; or name servers). Mirrors `--blind-oob` |
| `blind_oob_secret` | string | — | Auth token for a self-hosted interactsh server |
| `blind_oob_wait` | int | `30` | Seconds to keep polling for OOB callbacks after payloads are sent |
| `custom_payload` | string | — | Custom payload file, one payload per line |
| `only_custom_payload` | bool | `false` | Use only custom payloads; the scan exits `2` unless `custom_payload` (or `--custom-payload`) is also set |
| `inject_marker` | string | — | Token to replace with payloads |
| `custom_alert_value` | string | `"1"` | `alert(X)` value |
| `custom_alert_type` | string | `"none"` | `none` or `str` |
| `skip_xss_scanning` | bool | `false` | Discovery without attack |
| `deep_scan` | bool | `false` | Continue after first finding |
| `sxss` | bool | `false` | Enable Stored XSS mode |
| `sxss_url` | string | — | Retrieval URL |
| `sxss_method` | string | `"GET"` | Retrieval method (same set as `method`) |
| `sxss_retries` | int | `3` | Retries when fetching the retrieval URL (max `20`) |
| `max_payloads_per_param` | int | `0` | Cap base payloads tested per parameter (`0` applies a built-in safety cap of 3000 per set unless `deep_scan` is set) |
| `skip_ast_analysis` | bool | `false` | Skip AST DOM-XSS |
| `analyze_external_js` | bool | `false` | Fetch same-origin `<script src>` bundles and run AST DOM-XSS analysis on them (preflight, once per target; up to 16 files, 512 KiB each; respects `include_url`/`exclude_url`) |
| `detect_outdated_libs` | bool | `false` | Also report outdated / known-vulnerable JS libraries (informational, CWE-1104; 0 extra requests) |
| `hpp` | bool | `false` | HTTP Parameter Pollution |

### WAF

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `waf_bypass` | string | `"auto"` | `auto` or `off` (detect and report only). `force` is accepted and behaves like `auto`; `force_waf` is what picks the WAF |
| `skip_waf_probe` | bool | `false` | Skip active fingerprinting |
| `force_waf` | string | — | Treat the target as this WAF instead of what detection found (same names as `--force-waf`, case-insensitive) |
| `waf_evasion` | bool | `false` | Adaptive evasion: randomized inter-request jitter (with or without a detected WAF) + escalating cooldown on block clusters (pairs with `rate_limit`) |
| `waf_min_confidence` | float | `0.3` | Drop fingerprints below this confidence (0.0–1.0); default suppresses weak matches |

### Logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `debug` | bool | `false` | Emit debug lines |

## Precedence

```
CLI flag  >  Config file  >  Built-in default
```

- A list key (`headers`, `encoders`, `param`, …) is replaced, not merged: one `-H` on the command line drops every `headers` entry from the config.
- A command-line flag can turn an on/off switch such as `deep_scan` or `silence` on, but never off. When the config sets one to `true`, no flag turns it back off for a single run. `insecure` is the exception: `--insecure=false` overrides the config.

## Validation

Config values skip the CLI's argument parser, so Dalfox checks them when it loads the file:

- An invalid value for a fixed-choice key (`format`, `poc_type`, `limit_result_type`, `only_poc`, `baseline_mode`, `custom_alert_type`, `dedup_urls`, `waf_bypass`, `on_session_loss`, `encoders`), an unknown `method` / `sxss_method` / `force_waf`, a `session_check` that is not a valid regex, a `session_check_url` that is not an absolute URL, or `limit = 0` prints a `Warning:` on stderr. That key then falls back to its built-in default and the scan continues. `method`, `sxss_method` and `force_waf` are case-normalised the same way the flags are.
- `proxy`, `sxss_url` and `session_check_url` go through the same startup checks as their flags. A proxy scheme Dalfox cannot route, or a URL whose scheme is not `http`/`https`, stops the scan with `PARSE_ERROR` (exit `2`).
- Numeric keys have the same limits as their flags (`workers`, `timeout`, `delay`, `scan_timeout`, `rate_limit`, `retries`, `retry_delay`, `sxss_retries`, `max_concurrent_targets`, `max_targets_per_host`, `waf_min_confidence`). An out-of-range value stops the scan with `INVALID_INPUT_TYPE` (exit `2`).
- Unknown keys, and keys placed outside the `[scan]` table, are ignored without a warning, so check the spelling and placement of a key that seems to have no effect.
- A file that fails to parse (a TOML syntax error, or a value of the wrong type such as `workers = "10"`) is dropped whole. With `--config` Dalfox prints a warning. The default-path file is dropped silently.

See [Getting Started → Configuration](../../getting-started/configuration/) for examples.
