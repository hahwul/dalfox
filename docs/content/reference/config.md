+++
title = "Config File"
description = "All keys supported in Dalfox's TOML/JSON config file."
weight = 2
+++

Dalfox looks for its config at (in order):

1. `$XDG_CONFIG_HOME/dalfox/config.toml`
2. `$HOME/.config/dalfox/config.toml`

Override with `--config <path>`. TOML and JSON are both accepted; TOML is the default.

Everything lives under the `[scan]` table and mirrors the CLI flag names (snake-cased).

## Complete example

```toml
[scan]
# INPUT
input_type = "auto"

# OUTPUT
format = "plain"
# output = "results.json"
include_request = false
include_response = false
include_all = false
silence = false
dry_run = false
poc_type = "plain"
# limit = 100
limit_result_type = "all"
only_poc = []
no_color = false

# TARGETS
param = []
# data = "user=test"
headers = ["Accept: text/html"]
cookies = []
method = "GET"
user_agent = "Dalfox/3"
# cookie_from_raw = "request.txt"

# SCOPE
include_url = []
exclude_url = []
ignore_param = []
out_of_scope = []
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
delay = 0
# proxy = "http://127.0.0.1:8080"
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
skip_ast_analysis = false
hpp = false

# WAF
waf_bypass = "auto"
skip_waf_probe = false
# force_waf = "cloudflare"
waf_evasion = false

# LOGGING
debug = false
```

## Key reference

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
| `poc_type` | string | `"plain"` | `plain`, `curl`, `httpie`, `http-request` |
| `limit` | int | — | Cap on result count |
| `limit_result_type` | string | `"all"` | Which types count: `all`, `v`, `r`, `a` |
| `only_poc` | array | `[]` | Filter output: `["v","a"]` |
| `no_color` | bool | `false` | Disable ANSI colour |

### Targets

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `param` | array | `[]` | Parameter names (optionally `name:location`) |
| `data` | string | — | Request body |
| `headers` | array | `[]` | HTTP headers |
| `cookies` | array | `[]` | Cookie strings |
| `method` | string | `"GET"` | HTTP method |
| `user_agent` | string | — | User-Agent override |
| `cookie_from_raw` | string | — | Raw-request file for cookies |

### Scope

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `include_url` | array | `[]` | Regex patterns of URLs to include |
| `exclude_url` | array | `[]` | Regex patterns of URLs to exclude |
| `ignore_param` | array | `[]` | Parameter names to skip |
| `out_of_scope` | array | `[]` | Wildcard domain patterns |
| `out_of_scope_file` | string | — | File listing out-of-scope hosts |

### Discovery & Mining

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
| `skip_mining_dom` | bool | `false` | Skip DOM mining |

### Network

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `timeout` | int | `10` | Request timeout (seconds) |
| `delay` | int | `0` | Inter-request delay (ms) |
| `proxy` | string | — | Proxy URL |
| `follow_redirects` | bool | `false` | Follow 3xx responses |
| `ignore_return` | array | `[]` | HTTP status codes to ignore |

### Engine

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `workers` | int | `50` | Concurrent workers per target |
| `max_concurrent_targets` | int | `50` | Global concurrent targets |
| `max_targets_per_host` | int | `100` | Per-host cap |

### XSS scanning

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `encoders` | array | `["url","html"]` | Encoders to apply |
| `remote_payloads` | array | `[]` | Remote payload sources |
| `custom_blind_xss_payload` | string | — | Custom blind template file |
| `blind_callback_url` | string | — | Out-of-band callback URL |
| `custom_payload` | string | — | Custom payload file |
| `only_custom_payload` | bool | `false` | Use only custom payloads |
| `inject_marker` | string | — | Token to replace with payloads |
| `custom_alert_value` | string | `"1"` | `alert(X)` value |
| `custom_alert_type` | string | `"none"` | `none` or `str` |
| `skip_xss_scanning` | bool | `false` | Discovery without attack |
| `deep_scan` | bool | `false` | Continue after first finding |
| `sxss` | bool | `false` | Enable Stored XSS mode |
| `sxss_url` | string | — | Retrieval URL |
| `sxss_method` | string | `"GET"` | Retrieval method |
| `skip_ast_analysis` | bool | `false` | Skip AST DOM-XSS |
| `hpp` | bool | `false` | HTTP Parameter Pollution |

### WAF

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `waf_bypass` | string | `"auto"` | `auto`, `force`, `off` |
| `skip_waf_probe` | bool | `false` | Skip active fingerprinting |
| `force_waf` | string | — | WAF name when `waf_bypass = "force"` |
| `waf_evasion` | bool | `false` | Auto-throttle on WAF detection |

### Logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `debug` | bool | `false` | Emit debug lines |

## Precedence

```
CLI flag  >  Config file  >  Built-in default
```

See [Getting Started → Configuration](../../getting-started/configuration/) for examples.
