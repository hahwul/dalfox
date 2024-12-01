---
title: Configurations
redirect_from: /docs/config/
nav_order: 5
toc: true
layout: page
---

# Configurations

This guide provides detailed instructions on how to create and use a configuration file with Dalfox. Configuration files allow you to specify various options and settings for your scans.

## Creating a Configuration File

Create a configuration file named `config.json` with the following content:

```json
{
    "header": [
        ""
    ],
    "cookie": "",
    "param": [
        ""
    ],
    "blind": "",
    "custom-payload-file": "",
    "data": "",
    "user-agent": "",
    "output": "",
    "format": "",
    "found-action": "",
    "proxy": "",
    "timeout": 30,
    "worker": 100,
    "delay": 30,
    "only-discovery": false
}
```

For a sample configuration file, please check the [sample file](https://github.com/hahwul/dalfox/blob/main/samples/sample_config.json).

## Configuration Options

- **header**: Custom headers to include in the request.
- **cookie**: Cookies to include in the request.
- **param**: Parameters to include in the request.
- **blind**: Blind XSS payloads.
- **custom-payload-file**: Path to a custom payload file.
- **data**: Data to include in POST requests.
- **user-agent**: Custom User-Agent string.
- **output**: Output file path.
- **format**: Output format (e.g., JSON, plain text).
- **found-action**: Action to perform when a vulnerability is found.
- **proxy**: Proxy server to use for the requests.
- **timeout**: Request timeout in seconds.
- **worker**: Number of concurrent workers.
- **delay**: Delay between requests in milliseconds.
- **only-discovery**: Only perform discovery, without exploitation.

## Using the Configuration File

To use the configuration file with Dalfox, run the following command:

```bash
dalfox url https://google.com --config config.json
```

This command will use the settings specified in `config.json` for the scan.

## Additional Resources

For more information and advanced usage, please refer to the [official Dalfox documentation](https://github.com/hahwul/dalfox) and the [options model](https://github.com/hahwul/dalfox/blob/main/pkg/model/options.go).