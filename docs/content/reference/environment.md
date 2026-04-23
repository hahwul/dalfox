+++
title = "Environment"
description = "Environment variables Dalfox reads at runtime."
weight = 3
+++

Dalfox respects a small set of environment variables for configuration that doesn't belong in a file or on the command line.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `DALFOX_API_KEY` | `dalfox server` | Value required in the `X-API-KEY` header. Equivalent to `--api-key`. |
| `NO_COLOR` | all modes | Disables ANSI colour output when set to any non-empty value. Follows the [NO_COLOR](https://no-color.org) convention. |
| `XDG_CONFIG_HOME` | config loader | Base directory for the config file (`$XDG_CONFIG_HOME/dalfox/config.toml`). Falls back to `$HOME/.config`. |
| `HOME` | config loader | Used when `XDG_CONFIG_HOME` is unset. |

## Examples

### Keep the API key out of process args

```bash
export DALFOX_API_KEY="$(pass dalfox/api-key)"
dalfox server --port 6664
```

### Disable colour globally

```bash
export NO_COLOR=1
```

### Use a project-local config

```bash
XDG_CONFIG_HOME=./.config dalfox scan https://target.app
# Dalfox reads ./.config/dalfox/config.toml
```

## Not environment variables

A few things that *look* like they should be environment variables but aren't:

- **Proxy.** Use `--proxy` or `proxy` in config — Dalfox doesn't read `HTTP_PROXY`/`HTTPS_PROXY` to avoid accidental traffic interception.
- **Timeout, workers, format.** CLI flag or config only.
- **Debug.** Pass `--debug` on the command line or set `debug = true` in config.
