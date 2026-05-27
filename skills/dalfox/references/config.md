# Configuration System

## Search Order & Precedence

1. Explicit `--config /path/to/file.toml` (or `.json`) — highest priority, fails visibly on parse error.
2. Default user config (no `--config` flag):
   - `$XDG_CONFIG_HOME/dalfox/config.toml` (or `.json`) if `XDG_CONFIG_HOME` is set and non-empty
   - Otherwise `$HOME/.config/dalfox/config.toml` (preferred) or `config.json`
3. If no file exists at the default location, dalfox **creates** a `config.toml` with a heavily commented template containing all keys at their defaults.

There is **no automatic project-local** `.dalfox/config.toml` discovery in the current design (unlike some other tools). Use `--config ./dalfox-scan.toml` or commit a config in the repo and point at it.

## Precedence Rule (critical invariant)

**CLI flags always win.**

The function `Config::apply_to_scan_args_if_default` only fills fields that are still at their built-in default values. Any flag the user actually typed on the command line overrides the config file.

This is the same rule used by the server and (indirectly) by MCP callers who pass explicit parameters.

## What Lives in a Config File

See the auto-generated template for the full schema. Common useful keys under `[scan]`:

- `silence = true`
- `format = "jsonl"`
- `encoders = ["url", "html", "base64"]`
- `workers = 20`
- `timeout = 15`
- `delay = 150`
- `waf_bypass = "force"`
- `force_waf = "cloudflare"`
- `deep_scan = true`
- `skip_mining = true`

The config also supports top-level keys for server defaults in future versions, but today most server behavior is passed on the `dalfox server` command line.

## Banner & Silence Interaction

Banner suppression is decided from three places (OR-ed):

- Root `--silence` / `-S`
- `scan.silence` under the subcommand
- `silence = true` in the loaded config file

Machine-readable output formats also force silence automatically.

## When to Recommend a Config File to the User

- Repeated custom encoder sets
- Corporate proxy + auth headers that must be present on every scan
- Team-standard WAF bypass policy (`waf_bypass = "force"`, `force_waf = "akamai"`)
- Lower worker count for politeness on a shared target range
- Consistent `silence = true` + `format = "json"` for automation

Example minimal team config:

```toml
[scan]
workers = 10
delay = 200
encoders = ["url", "html"]
waf_bypass = "auto"
waf_min_confidence = 0.4
```

## MCP and Server vs Config

- MCP calls go through the same `ScanArgs` construction path but most fields come from the JSON-RPC parameters (no automatic config merge for MCP at the moment — the caller is expected to supply what they want).
- The HTTP server (`dalfox server`) also accepts per-scan options in the request body and applies the same conservative default-merging logic where relevant.

## Debugging "why is my setting not taking effect?"

1. Run with `--debug` — look for config load messages.
2. `dalfox --config /path/to/your.toml scan ... --help` (or just parse the args).
3. Remember: if you typed the flag at all, the config value is ignored for that field.
