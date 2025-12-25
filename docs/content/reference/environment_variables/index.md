+++
title = "Environment Variables"
description = "Environment variables supported by Dalfox"
weight = 1
sort_by = "weight"

[extra]
+++

Dalfox supports several environment variables for configuration and authentication.

## Server Mode

### DALFOX_API_KEY

Sets the API key for server mode authentication.

**Usage**:
```bash
export DALFOX_API_KEY=your-secret-key
dalfox server
```

Clients must include the key in requests:
```bash
curl http://localhost:6664/scan?url=https://example.com \
  -H "X-API-KEY: your-secret-key"
```

Alternative to `--api-key` flag:
```bash
# These are equivalent:
dalfox server --api-key mysecret
DALFOX_API_KEY=mysecret dalfox server
```

## Configuration

### XDG_CONFIG_HOME

Overrides the default configuration directory location.

**Default**: `~/.config`

**Usage**:
```bash
export XDG_CONFIG_HOME=/custom/config/path
dalfox scan https://example.com
# Looks for config at: /custom/config/path/dalfox/config.*
```

### HOME

Used as fallback for configuration directory when `XDG_CONFIG_HOME` is not set.

**Default Config Path**: `$HOME/.config/dalfox/config.*`

## Proxy Configuration

### HTTP_PROXY / HTTPS_PROXY

Some HTTP clients respect these variables. Dalfox uses reqwest which may honor them, but it's recommended to use the `--proxy` flag for explicit control.

**Usage**:
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
dalfox scan https://example.com
```

**Recommended approach**:
```bash
dalfox scan https://example.com --proxy http://localhost:8080
```

### NO_PROXY

Bypass proxy for specific hosts (if honored by HTTP client).

**Usage**:
```bash
export NO_PROXY=localhost,127.0.0.1,.internal
```

## Rust Environment Variables

### RUST_LOG

Control Rust logging verbosity (mostly for debugging Dalfox internals).

**Levels**: `error`, `warn`, `info`, `debug`, `trace`

**Usage**:
```bash
RUST_LOG=debug dalfox scan https://example.com
RUST_LOG=dalfox=trace dalfox scan https://example.com
```

### RUST_BACKTRACE

Enable backtraces for debugging crashes.

**Usage**:
```bash
RUST_BACKTRACE=1 dalfox scan https://example.com
RUST_BACKTRACE=full dalfox scan https://example.com
```

## Examples

### Production Server with API Key

```bash
export DALFOX_API_KEY=$(cat /etc/dalfox/api.key)
dalfox server --host 0.0.0.0 --port 8080 --log-file /var/log/dalfox.log
```

### Custom Configuration Location

```bash
export XDG_CONFIG_HOME=/opt/security/config
dalfox scan https://example.com
# Uses: /opt/security/config/dalfox/config.toml
```

### Debug Mode

```bash
RUST_LOG=debug RUST_BACKTRACE=1 dalfox scan https://example.com
```

### With Proxy

```bash
# Method 1: Environment variable (may not work reliably)
export HTTP_PROXY=http://localhost:8080
dalfox scan https://example.com

# Method 2: CLI flag (recommended)
dalfox scan https://example.com --proxy http://localhost:8080
```

## Summary Table

| Variable | Purpose | Default | Example |
|----------|---------|---------|---------|
| `DALFOX_API_KEY` | Server API key | None | `mysecretkey` |
| `XDG_CONFIG_HOME` | Config directory | `~/.config` | `/opt/config` |
| `HOME` | User home dir | System default | `/home/user` |
| `HTTP_PROXY` | HTTP proxy URL | None | `http://localhost:8080` |
| `HTTPS_PROXY` | HTTPS proxy URL | None | `http://localhost:8080` |
| `NO_PROXY` | Proxy bypass list | None | `localhost,.internal` |
| `RUST_LOG` | Logging level | `info` | `debug`, `trace` |
| `RUST_BACKTRACE` | Backtrace on panic | `0` | `1`, `full` |

## See Also

- [Configuration](/usage/configuration)
- [Server Command](/usage/commands/server)
- [Troubleshooting](/support/troubleshooting)
