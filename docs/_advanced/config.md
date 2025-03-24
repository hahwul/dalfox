---
title: Configurations
redirect_from: /docs/config/
nav_order: 5
toc: true
layout: page
---

# Configuration Files

## Overview

Dalfox supports configuration files that allow you to define and reuse scan settings across multiple sessions. Using configuration files provides several advantages:

- **Consistency**: Maintain consistent scan settings across multiple targets
- **Reproducibility**: Easily reproduce scans with identical settings
- **Efficiency**: Save time by avoiding repetitive command-line parameter entry
- **Documentation**: Preserve and version control your scanning configurations
- **Sharing**: Easily share scan configurations with team members

Configuration files use JSON format and can include any option that's available via command-line flags.

## Creating a Configuration File

To create a configuration file, you can start with a basic template and customize it according to your needs. 

### Basic Configuration Template

Create a file named `config.json` with this basic structure:

```json
{
  "header": [],
  "cookie": "",
  "param": [],
  "blind": "",
  "custom-payload-file": "",
  "data": "",
  "user-agent": "",
  "output": "",
  "format": "plain",
  "proxy": "",
  "timeout": 10,
  "worker": 100,
  "delay": 0
}
```

### Comprehensive Configuration Example

Here's a more comprehensive configuration example that utilizes many available options:

```json
{
  "header": [
    "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "X-Custom-Header: TestValue"
  ],
  "cookie": "sessionid=1234abcd; language=en-US",
  "param": [
    "search",
    "q",
    "id"
  ],
  "blind": "https://your-callback.xss.ht",
  "custom-payload": "/path/to/custom-payloads.txt",
  "data": "username=test&password=test",
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "output": "scan-results.json",
  "format": "json",
  "found-action": "/path/to/notify-script.sh",
  "proxy": "http://127.0.0.1:8080",
  "timeout": 15,
  "worker": 150,
  "delay": 100,
  "only-discovery": false,
  "skip-bav": false,
  "mining-dict": true,
  "mining-dom": true,
  "remote-payloads": "portswigger,payloadbox",
  "remote-wordlists": "burp",
  "deep-domxss": true,
  "follow-redirects": true,
  "waf-evasion": false,
  "report": true,
  "report-format": "json",
  "poc-type": "curl",
  "custom-alert-value": "document.domain",
  "custom-alert-type": "str",
  "ignore-return": "404,403",
  "ignore-param": ["__VIEWSTATE", "csrf_token"]
}
```

## Configuration Options

Dalfox configuration files can include a wide range of options, organized into the following categories:

### Target Configuration

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `param` | Array | Specific parameters to test | `["search", "q", "id"]` |
| `ignore-param` | Array | Parameters to ignore during scanning | `["csrf_token", "nonce"]` |
| `ignore-return` | String | HTTP status codes to ignore | `"404,403,500"` |

### HTTP Request Configuration

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `header` | Array | Custom HTTP headers | `["Authorization: Bearer token"]` |
| `cookie` | String | Cookies for requests | `"sessionid=abc123; lang=en"` |
| `data` | String | POST request data | `"username=test&password=test"` |
| `user-agent` | String | Custom User-Agent | `"Mozilla/5.0 (Windows NT 10.0...)"` |
| `method` | String | HTTP request method | `"POST"` |
| `proxy` | String | Proxy server for requests | `"http://127.0.0.1:8080"` |
| `follow-redirects` | Boolean | Whether to follow redirects | `true` |
| `timeout` | Number | Request timeout in seconds | `10` |

### Scan Configuration

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `worker` | Number | Number of concurrent workers | `100` |
| `delay` | Number | Delay between requests (ms) | `100` |
| `blind` | String | Blind XSS callback URL | `"https://callback.xss.ht"` |
| `only-discovery` | Boolean | Only perform parameter discovery | `false` |
| `skip-bav` | Boolean | Skip BAV checks | `false` |
| `skip-mining-all` | Boolean | Skip all parameter mining | `false` |
| `mining-dict` | Boolean | Enable dictionary mining | `true` |
| `mining-dom` | Boolean | Enable DOM mining | `true` |
| `deep-domxss` | Boolean | Enable deep DOM XSS checks | `false` |
| `waf-evasion` | Boolean | Enable WAF evasion techniques | `true` |

### Payload Configuration

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `custom-payload` | String | Path to custom payload file | `"./payloads.txt"` |
| `remote-payloads` | String | Remote payload sources | `"portswigger,payloadbox"` |
| `remote-wordlists` | String | Remote wordlist sources | `"burp,assetnote"` |
| `custom-alert-type` | String | Custom alert type | `"str"` |
| `custom-alert-value` | String | Custom alert value | `"document.domain"` |
| `only-custom-payload` | Boolean | Only use custom payloads | `false` |

### Output Configuration

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `output` | String | Output file path | `"results.txt"` |
| `format` | String | Output format (plain/json) | `"json"` |
| `report` | Boolean | Generate detailed report | `true` |
| `report-format` | String | Format of the report | `"json"` |
| `output-all` | Boolean | Include all logs in output | `true` |
| `output-request` | Boolean | Include HTTP requests in output | `false` |
| `output-response` | Boolean | Include HTTP responses in output | `false` |
| `poc-type` | String | Format of PoC code | `"curl"` |
| `found-action` | String | Script to run when vulnerability found | `"./notify.sh"` |
| `found-action-shell` | String | Shell to use for found-action | `"bash"` |

## Using Configuration Files

To use a configuration file with Dalfox, use the `--config` flag followed by the path to your configuration file:

```bash
dalfox url https://example.com --config config.json
```

You can also override specific configuration file settings with command-line arguments:

```bash
dalfox url https://example.com --config config.json --worker 200 --blind https://different-callback.xss.ht
```

In this case, the `worker` and `blind` values from the command line will override those in the configuration file.

## Configuration Management Best Practices

### Maintaining Multiple Configurations

For different testing scenarios, you can maintain multiple configuration files:

- `config-quick.json`: For quick scans with minimal options
- `config-thorough.json`: For comprehensive scans with all checks enabled
- `config-ci.json`: For integration into CI/CD pipelines
- `config-waf.json`: Specifically tuned for WAF bypass testing

### Using Environment-Specific Configurations

For testing across different environments:

```bash
# Development environment
dalfox url https://dev.example.com --config config-dev.json

# Production environment
dalfox url https://www.example.com --config config-prod.json
```

### Sharing Configurations

When sharing configurations with a team:

1. Remove sensitive information (tokens, credentials)
2. Document any placeholders that need to be filled in
3. Consider using version control for configuration files
4. Provide comments or documentation on the purpose of each configuration

### Configuration Template Examples

#### Quick Scan Configuration

```json
{
  "worker": 150,
  "timeout": 5,
  "only-poc": "v",
  "format": "plain",
  "skip-bav": true,
  "skip-mining-dom": true
}
```

#### Thorough Scan Configuration

```json
{
  "worker": 50,
  "delay": 100,
  "timeout": 20,
  "remote-payloads": "portswigger,payloadbox",
  "remote-wordlists": "burp,assetnote",
  "deep-domxss": true,
  "report": true,
  "report-format": "json",
  "output-all": true,
  "format": "json",
  "har-file-path": "scan.har"
}
```

#### CI/CD Pipeline Configuration

```json
{
  "worker": 100,
  "timeout": 10,
  "format": "json",
  "output": "dalfox-results.json",
  "report-format": "json",
  "report": true,
  "silence": true,
  "only-poc": "v,g"
}
```

## Debugging Configuration Issues

If you encounter issues with your configuration file:

1. Validate that your JSON syntax is correct (no trailing commas, properly closed brackets)
2. Check for proper data types (strings in quotes, numbers without quotes)
3. Ensure that array values are properly formatted with square brackets
4. Verify that file paths in your configuration are correct and accessible

You can use tools like JSONLint to validate your configuration file before using it with Dalfox.

## Reference

For a complete list of available configuration options, you can refer to the [options model](https://github.com/hahwul/dalfox/blob/main/pkg/model/options.go) in the Dalfox source code, or check the [sample configuration file](https://github.com/hahwul/dalfox/blob/main/samples/sample_config.json) provided with Dalfox.