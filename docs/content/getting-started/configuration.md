+++
title = "Configuration"
description = "Save your favorite flags in a Dalfox config file."
weight = 4
toc = true
+++

Dalfox reads a config file on startup so you don't have to pass the same flags every time. An explicit CLI flag always overrides what the config sets, so it's safe to keep "defaults" here.

## Where the file lives

Dalfox reads `$XDG_CONFIG_HOME/dalfox/config.toml` when `XDG_CONFIG_HOME` is set, and `$HOME/.config/dalfox/config.toml` otherwise. A `config.json` in the same directory is read when there is no `config.toml`.

You can point anywhere else with `--config`:

```bash
dalfox --config ./dalfox.toml scan https://target.app
```

If no file exists, Dalfox creates a template at the default path the first time you run it. Every line in it is commented out, so it changes nothing until you edit it.

## A minimal config

```toml
[scan]
format = "json"
output = "results.json"
timeout = 15
workers = 100
encoders = ["url", "html"]
```

Run a scan and those flags apply automatically:

```bash
dalfox 'https://target.app/?q=test'
# → writes JSON results to results.json with workers=100
```

## Precedence

```
CLI flag  >  Config file  >  Built-in defaults
```

Anything on the command line wins. This lets you keep sensible defaults in the config, then override per-scan:

```bash
# Config sets workers=100, but for this quick scan use 20
dalfox scan --workers 20 https://target.app
```

Scan flags need the explicit `scan` subcommand; the bare `dalfox <TARGET>` form accepts only targets and the global flags. A switch the config turns on, such as `deep_scan = true`, stays on for every run, because there is no command-line flag that turns it off. See [Precedence](../../reference/config/#precedence) for the details.

## Formats

Dalfox supports both TOML and JSON. TOML is the default; JSON is handy if you generate the file from a tool or UI.

```toml
# ~/.config/dalfox/config.toml
[scan]
format = "sarif"
silence = true
```

```json
{
  "scan": {
    "format": "sarif",
    "silence": true
  }
}
```

## What can I configure?

Anything that has a CLI flag under `dalfox scan` can live in the `[scan]` table (`--blind` is spelled `blind_callback_url`). The file applies to CLI scans only; `dalfox server` and `dalfox mcp` ignore it. Common examples:

| Key | Example | What it does |
|-----|---------|--------------|
| `format` | `"json"` | Output format (`plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`) |
| `output` | `"report.json"` | Default output file |
| `silence` | `true` | Suppress logs, emit only findings |
| `timeout` | `15` | Request timeout in seconds |
| `delay` | `200` | Delay between requests in ms |
| `workers` | `100` | Concurrent workers per target |
| `encoders` | `["url","html","base64"]` | Payload encoders |
| `remote_payloads` | `["portswigger"]` | Remote payload sources |
| `remote_wordlists` | `["burp"]` | Remote parameter wordlists |
| `headers` | `["Accept: text/html"]` | Extra request headers |
| `user_agent` | `"Dalfox Scanner"` | Default User-Agent |
| `waf_bypass` | `"auto"` | WAF bypass mode (`auto`, or `off` to detect only) |
| `insecure` | `true` | Skip TLS certificate verification (`false` to enforce) |
| `follow_redirects` | `true` | Follow 3xx responses |

See the [Config File reference](../../reference/config/) for every key.

## Secrets

Keep API keys, bearer tokens, and blind-XSS callback hostnames out of the config file if you commit it. The only secret Dalfox reads from the environment is the REST server's API key:

```bash
# .env or your shell profile
export DALFOX_API_KEY="..."
```

Pass the rest (`-H "Authorization: …"`, `--cookies`, `-b`) at the command line and never persist them.

## Next steps

- [Run your first scan](../quick-start/)
- [Explore scanning modes](../../guide/scanning-modes/)
- [See the full CLI reference](../../reference/cli/)
