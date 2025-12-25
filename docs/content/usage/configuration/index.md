+++
title = "Configuration"
description = "Configure Dalfox with configuration files and environment variables"
weight = 2
sort_by = "weight"

[extra]
+++

Dalfox supports configuration files to set default values for scanning options, reducing the need for repeated command-line flags.

## Configuration File Location

Dalfox searches for configuration files in the following locations:

1. Path specified with `--config` flag
2. `$XDG_CONFIG_HOME/dalfox/config.*`
3. `$HOME/.config/dalfox/config.*`

Supported formats: **TOML**, **JSON** (auto-detected by extension)

## Default Configuration

If no configuration file exists, Dalfox automatically generates a default TOML configuration on first use.

**Default Path**: `~/.config/dalfox/config.toml`

## Configuration Options

All command-line flags can be set in the configuration file. The configuration applies default values only when the corresponding CLI flag is not provided.

### Example TOML Configuration

```toml
# Debug mode
debug = false

# Network settings
timeout = 10
delay = 0
workers = 50
max_concurrent_targets = 50
max_targets_per_host = 100
follow_redirects = false

# HTTP settings
method = "GET"
user_agent = "Dalfox/3.0"

# XSS scanning
encoders = ["url", "html"]
deep_scan = false
skip_xss_scanning = false
skip_ast_analysis = false

# Discovery & Mining
skip_discovery = false
skip_mining = false
skip_reflection_header = false
skip_reflection_cookie = false
skip_reflection_path = false

# Remote resources
remote_payloads = []  # ["portswigger", "payloadbox"]
remote_wordlists = []  # ["burp", "assetnote"]

# Output
format = "plain"
silence = false
include_request = false
include_response = false
```

### Example JSON Configuration

```json
{
  "debug": false,
  "timeout": 10,
  "delay": 0,
  "workers": 50,
  "encoders": ["url", "html"],
  "remote_payloads": ["portswigger"],
  "format": "json"
}
```

## Configuration Precedence

Command-line flags **always override** configuration file values:

1. **Highest Priority**: Command-line flags
2. **Middle Priority**: Configuration file
3. **Lowest Priority**: Built-in defaults

**Example**:
```bash
# Config file sets timeout = 10
# CLI overrides to timeout = 30
dalfox scan https://example.com --timeout 30
```

## Per-Project Configuration

Store project-specific configurations:

```bash
# Create project config
mkdir -p .dalfox
cat > .dalfox/config.toml << EOF
workers = 100
encoders = ["url", "html", "base64"]
remote_payloads = ["portswigger", "payloadbox"]
EOF

# Use project config
dalfox scan https://example.com --config .dalfox/config.toml
```

## Environment Variables

Some settings can also be configured via environment variables. See [Environment Variables](/reference/environment_variables) for details.

## Common Configurations

### High-Performance Scanning

```toml
workers = 200
max_concurrent_targets = 100
max_targets_per_host = 500
delay = 0
timeout = 5
```

### Stealth Scanning

```toml
workers = 5
max_concurrent_targets = 2
delay = 2000
timeout = 30
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Comprehensive Testing

```toml
encoders = ["url", "2url", "html", "base64"]
remote_payloads = ["portswigger", "payloadbox"]
remote_wordlists = ["burp", "assetnote"]
deep_scan = true
skip_mining = false
```

### CI/CD Pipeline

```toml
format = "sarif"
silence = true
workers = 100
timeout = 5
```

## See Also

- [Environment Variables](/reference/environment_variables)
- [Scan Command](/usage/commands/scan)
- [Performance Optimization](/advanced/performance_optimization)
