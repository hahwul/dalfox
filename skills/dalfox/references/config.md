# Configuration System

## Search Order & Precedence

1. Explicit `--config /path/to/file.toml` (or `.json`) — replaces the default location. A parse failure prints `Warning: failed to load --config …` on stderr and the run **continues on built-in defaults**; a path that does not exist is created from the template (stderr `Notice:`) and the run uses defaults. Check stderr before trusting a config took effect.
2. Default user config (no `--config` flag):
   - `$XDG_CONFIG_HOME/dalfox/config.toml` (or `.json`) if `XDG_CONFIG_HOME` is set and non-empty
   - Otherwise `$HOME/.config/dalfox/config.toml` (preferred) or `config.json`
3. If no file exists at the default location, dalfox **creates** a `config.toml` with a heavily commented template containing all keys at their defaults.

There is **no automatic project-local** `.dalfox/config.toml` discovery in the current design (unlike some other tools). Use `--config ./dalfox-scan.toml` or commit a config in the repo and point at it.

## Precedence Rule (critical invariant)

**CLI flags always win.**

The function `Config::apply_to_scan_args_if_default` only fills fields the operator did not supply on the command line. Which fields those are comes from clap's `ValueSource`, not from comparing values, so a flag typed with the value that happens to be its built-in default (`--workers 50`, `--method GET`) still wins over the config file.

Config values bypass clap's value parsers; `Config::normalize_and_validate` resets an invalid value to its default with a stderr `Warning:`.

## What Lives in a Config File

See the auto-generated template for the full schema. Common useful keys under `[scan]`:

- `silence = true`
- `format = "jsonl"`
- `encoders = ["url", "html", "base64"]`
- `workers = 20`
- `timeout = 15`
- `delay = 150`
- `waf_bypass = "off"` (only `off` changes behaviour; `force` acts like `auto`)
- `force_waf = "cloudflare"`
- `deep_scan = true`
- `skip_mining = true`

## Banner & Silence Interaction

The banner is skipped when any of these holds:

- `--silence` / `-S` (root or after `scan`), or `silence = true` in the config
- `--format` (CLI or config `format`) is anything but `plain` (`format_is_machine`)
- the subcommand is `mcp`
- `dalfox payload` with a selector or `--json` (the argless prose summary keeps it)

## When to Recommend a Config File to the User

- Repeated custom encoder sets
- Corporate proxy + auth headers that must be present on every scan
- Team-standard WAF policy (`force_waf = "akamai"` pins the profile; `waf_bypass = "off"` for detect-only)
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

Neither `dalfox mcp` nor `dalfox server` reads the config file. Their scans are built from the request (JSON-RPC arguments / REST body) plus built-in defaults, so a team config's headers, encoders or `baseline` never apply there — pass them per request.

## Debugging "why is my setting not taking effect?"

1. Check stderr for `Warning:` / `Notice:` lines about the config.
2. `dalfox scan --config /path/to/your.toml --debug --dry-run 'https://target/?q=1'` — preflight only, no payloads.
3. Remember: if you typed the flag at all, the config value is ignored for that field.
