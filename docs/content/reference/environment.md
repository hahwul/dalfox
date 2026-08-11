+++
title = "Environment"
description = "Environment variables Dalfox reads at runtime."
weight = 3
toc = true
+++

Dalfox respects a small set of environment variables for configuration that doesn't belong in a file or on the command line.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `DALFOX_API_KEY` | `dalfox server` | Value required in the `X-API-KEY` header. Equivalent to `--api-key`. |
| `DALFOX_STDIN_WAIT_MS` | `dalfox scan` (auto input) | Milliseconds to wait for piped `stdin` to produce its first byte when targets were *also* given on the command line. Default `500`; `0` skips the stdin merge entirely. Does not apply to `--input-type pipe`/`har`, which always wait. |
| `NO_COLOR` | all modes | Disables ANSI colour output when set to any value, an empty string included. Equivalent to `--no-color`, and to `no_color = true` in the config file. See the [NO_COLOR](https://no-color.org) convention. |
| `XDG_CONFIG_HOME` | config loader | Base directory for the config file (`$XDG_CONFIG_HOME/dalfox/config.toml`). Falls back to `$HOME/.config`. |
| `HOME` | config loader | Used when `XDG_CONFIG_HOME` is unset. |
| `USERPROFILE` | config loader | Windows fallback base directory, used when both `XDG_CONFIG_HOME` and `HOME` are unset. |

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

`--no-color` does the same for a single run, and `no_color = true` in the config file does it for every run. Colour is also suppressed automatically whenever stdout is not a TTY, so a piped or redirected scan is plain text without setting anything.

```bash
dalfox scan https://target.app --no-color
dalfox scan https://target.app > scan.log   # already plain text
```

See [Colour & TTY behaviour](../../guide/output/#colour-tty-behaviour) in the output guide.

### Use a project-local config

```bash
XDG_CONFIG_HOME=./.config dalfox scan https://target.app
# Dalfox reads ./.config/dalfox/config.toml
```

## Not environment variables

A few things that *look* like they should be environment variables but aren't:

- **Proxy.** Use `--proxy` or `proxy` in config; Dalfox doesn't read `HTTP_PROXY`/`HTTPS_PROXY` to avoid accidental traffic interception.
- **Timeout, workers, format.** CLI flag or config only.
- **Debug.** Pass `--debug` on the command line or set `debug = true` in config.
