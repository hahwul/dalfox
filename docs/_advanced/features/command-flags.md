---
title: Command Line Flags
redirect_from: /docs/command-flags/
nav_order: 2
parent: Features
toc: true
layout: page
---

# Command Line Flags

This page provides a comprehensive overview of Dalfox's command line flags, organized by functionality.

## Request Configuration Flags

These flags allow you to customize the HTTP requests sent by Dalfox:

| Flag | Description |
|------|-------------|
| `-b, --blind string` | Specify a blind XSS callback URL.<br>Example: `-b 'https://your-callback-url.com'` |
| `-C, --cookie string` | Add custom cookies to the request.<br>Example: `-C 'sessionid=abc123'` |
| `--cookie-from-raw string` | Load cookies from a raw HTTP request file.<br>Example: `--cookie-from-raw 'request.txt'` |
| `-d, --data string` | Use POST method and add body data.<br>Example: `-d 'username=admin&password=admin'` |
| `-F, --follow-redirects` | Follow HTTP redirects.<br>Example: `-F` |
| `-H, --header strings` | Add custom headers to the request.<br>Example: `-H 'Authorization: Bearer <token>'` |
| `-X, --method string` | Override the HTTP method (default: GET).<br>Example: `-X 'PUT'` |
| `--proxy string` | Send all requests through a proxy server.<br>Example: `--proxy 'http://127.0.0.1:8080'` |
| `--timeout int` | Set the request timeout in seconds (default: 10).<br>Example: `--timeout 10` |
| `--user-agent string` | Set a custom User-Agent header.<br>Example: `--user-agent 'Mozilla/5.0'` |

## Scanning Configuration Flags

These flags control the behavior of the scanning process:

| Flag | Description |
|------|-------------|
| `--config string` | Load configuration from a file.<br>Example: `--config 'config.json'` |
| `--custom-alert-type string` | Set a custom alert type (default: "none").<br>Example: `--custom-alert-type 'str,none'` |
| `--custom-alert-value string` | Set a custom alert value (default: "1").<br>Example: `--custom-alert-value 'document.cookie'` |
| `--custom-payload string` | Load custom payloads from a file.<br>Example: `--custom-payload 'payloads.txt'` |
| `--deep-domxss` | Enable deep DOM XSS testing with more payloads (slow).<br>Example: `--deep-domxss` |
| `--delay int` | Set the delay between requests to the same host in milliseconds.<br>Example: `--delay 1000` |
| `--force-headless-verification` | Force headless browser-based verification, useful when automatic detection fails.<br>Example: `--force-headless-verification` |
| `--ignore-param strings` | Ignore specific parameters during scanning.<br>Example: `--ignore-param 'api_token' --ignore-param 'csrf_token'` |
| `--ignore-return string` | Ignore specific HTTP return codes.<br>Example: `--ignore-return '302,403,404'` |
| `-p, --param strings` | Specify parameters to test.<br>Example: `-p 'username' -p 'password'` |
| `--remote-payloads string` | Use remote payloads for XSS testing. Supported: portswigger, payloadbox.<br>Example: `--remote-payloads 'portswigger,payloadbox'` |
| `--waf-evasion` | Enable WAF evasion by adjusting speed when detecting WAF (worker=1, delay=3s).<br>Example: `--waf-evasion` |

## Performance Flags

These flags allow you to fine-tune the performance of Dalfox:

| Flag | Description |
|------|-------------|
| `--max-cpu int` | Set the maximum number of CPUs to use (default: 1).<br>Example: `--max-cpu 1` |
| `-w, --worker int` | Set the number of concurrent workers (default: 100).<br>Example: `-w 100` |

## Parameter Mining Flags

These flags control how Dalfox discovers and tests parameters:

| Flag | Description |
|------|-------------|
| `--mining-dict` | Enable dictionary-based parameter mining (default: true).<br>Example: `--mining-dict` |
| `-W, --mining-dict-word string` | Specify a custom wordlist file for parameter mining.<br>Example: `-W 'wordlist.txt'` |
| `--mining-dom` | Enable DOM-based parameter mining (default: true).<br>Example: `--mining-dom` |
| `--remote-wordlists string` | Use remote wordlists for parameter mining. Supported: burp, assetnote.<br>Example: `--remote-wordlists 'burp'` |
| `--skip-mining-all` | Skip all parameter mining.<br>Example: `--skip-mining-all` |
| `--skip-mining-dict` | Skip dictionary-based parameter mining.<br>Example: `--skip-mining-dict` |
| `--skip-mining-dom` | Skip DOM-based parameter mining.<br>Example: `--skip-mining-dom` |

## Control Flow Flags

These flags allow you to control the scanning flow:

| Flag | Description |
|------|-------------|
| `--only-custom-payload` | Only test custom payloads.<br>Example: `--only-custom-payload` |
| `--only-discovery` | Only perform parameter analysis, skip XSS scanning.<br>Example: `--only-discovery` |
| `--skip-bav` | Skip Basic Another Vulnerability (BAV) analysis.<br>Example: `--skip-bav` |
| `--skip-discovery` | Skip the entire discovery phase, proceeding directly to XSS scanning. Requires -p flag.<br>Example: `--skip-discovery -p 'username'` |
| `--skip-grepping` | Skip built-in grepping.<br>Example: `--skip-grepping` |
| `--skip-headless` | Skip headless browser-based scanning (DOM XSS and inJS verification).<br>Example: `--skip-headless` |
| `--skip-xss-scanning` | Skip XSS scanning.<br>Example: `--skip-xss-scanning` |
| `--use-bav` | Enable Basic Another Vulnerability (BAV) analysis.<br>Example: `--use-bav` |

## Output and Reporting Flags

These flags control how Dalfox presents its findings:

| Flag | Description |
|------|-------------|
| `--debug` | Enable debug mode and save all logs.<br>Example: `--debug` |
| `--format string` | Set the output format. Supported: plain, json (default: plain).<br>Example: `--format 'json'` |
| `--found-action string` | Execute a command when a vulnerability is found.<br>Example: `--found-action './notify.sh'` |
| `--found-action-shell string` | Specify the shell to use for the found action (default: bash).<br>Example: `--found-action-shell 'bash'` |
| `--grep string` | Use a custom grepping file.<br>Example: `--grep './samples/sample_grep.json'` |
| `--har-file-path string` | Specify the path to save HAR files of scan requests.<br>Example: `--har-file-path 'scan.har'` |
| `--no-color` | Disable colorized output.<br>Example: `--no-color` |
| `--no-spinner` | Disable spinner animation.<br>Example: `--no-spinner` |
| `--only-poc string` | Show only the PoC code for the specified pattern. Supported: g (grep), r (reflected), v (verified).<br>Example: `--only-poc 'g,v'` |
| `-o, --output string` | Write output to a file.<br>Example: `-o 'output.txt'` |
| `--output-all` | Enable all log write mode (output to file or stdout).<br>Example: `--output-all` |
| `--output-request` | Include raw HTTP requests in the results.<br>Example: `--output-request` |
| `--output-response` | Include raw HTTP responses in the results.<br>Example: `--output-response` |
| `--poc-type string` | Select the PoC type. Supported: plain, curl, httpie, http-request (default: plain).<br>Example: `--poc-type 'curl'` |
| `--report` | Show detailed report.<br>Example: `--report` |
| `--report-format string` | Set the format of the report. Supported: plain, json (default: plain).<br>Example: `--report-format 'json'` |
| `-S, --silence` | Only print PoC code and progress.<br>Example: `-S` |

## Usage Examples

Basic scanning with custom headers and cookies:
```bash
dalfox url https://example.com -H 'Authorization: Bearer token' -C 'session=abc123'
```

Using POST method with data:
```bash
dalfox url https://example.com/login -d 'username=admin&password=admin'
```

Output results to a JSON file with detailed reporting:
```bash
dalfox url https://example.com --format json -o results.json --report --report-format json
```

Parameter mining with custom wordlist and increased workers:
```bash
dalfox url https://example.com -W wordlist.txt -w 200
```

Using blind XSS detection with a callback URL:
```bash
dalfox url https://example.com -b https://your-xss-catcher.com/hook
```

WAF evasion with custom payloads:
```bash
dalfox url https://example.com --waf-evasion --custom-payload payloads.txt
```

Using a proxy and following redirects:
```bash
dalfox url https://example.com --proxy http://127.0.0.1:8080 -F
```

Executing a notification script when vulnerabilities are found:
```bash
dalfox url https://example.com --found-action './notify.sh'
```

Saving HAR files for further analysis:
```bash
dalfox url https://example.com --har-file-path scan.har
```