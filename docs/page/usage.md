---
title: Usage
redirect_from: /docs/usage/
nav_order: 3
has_children: true
toc: true
layout: page
---

# Usage

Dalfox provides a powerful command-line interface with various modes and options to tailor your XSS scanning experience. The basic command structure is:

```shell
dalfox [mode] [target] [flags]
```

## Quick Start Examples

Here are some common usage examples to get you started:

```bash
# Scan a single URL
dalfox url https://example.com

# Scan a URL with parameters
dalfox url "https://example.com/search?q=test"

# Use blind XSS payload with callback URL
dalfox url https://example.com -b https://your-callback-url.com

# Scan multiple URLs from a file
dalfox file targets.txt

# Process URLs from another tool via pipeline
cat urls.txt | dalfox pipe

# Start Dalfox as a REST API server
dalfox server --host 0.0.0.0 --port 8080
```

## Available Modes

Dalfox supports several operational modes to accommodate different scanning scenarios:

| Mode | Description |
|------|-------------|
| `url` | Scan a single target URL |
| `file` | Process target URLs or raw HTTP data from a file |
| `pipe` | Read target URLs from standard input (pipeline) |
| `sxss` | Test for stored XSS vulnerabilities |
| `server` | Run as a REST API server |
| `payload` | Generate and manipulate XSS payloads |
| `version` | Display the Dalfox version |
| `help` | Show help information |

For detailed documentation on each mode, see the corresponding pages:
* [URL Mode](page/modes/url-mode/)
* [File Mode](page/modes/file-mode/)
* [Pipe Mode](page/modes/pipe-mode/)
* [SXSS Mode](page/modes/sxss-mode/)
* [Server Mode](page/modes/server-mode/)
* [Payload Mode](page/modes/payload-mode/)

## Global Flags

These flags can be used with any mode to customize your scan:

### Basic Options

```
  -b, --blind string                  Specify a blind XSS callback URL. Example: -b 'https://your-callback-url.com'
      --config string                 Load configuration from a file. Example: --config 'config.json'
  -o, --output string                 Write output to a file. Example: -o 'output.txt'
      --format string                 Set the output format. Supported: plain, json. Example: --format 'json' (default "plain")
      --report                        Show detailed report. Example: --report
      --report-format string          Set the format of the report. Supported: plain, json. Example: --report-format 'json' (default "plain")
  -S, --silence                       Only print PoC code and progress. Example: -S
      --no-color                      Disable colorized output. Example: --no-color
      --no-spinner                    Disable spinner animation. Example: --no-spinner
      --debug                         Enable debug mode and save all logs. Example: --debug
```

### HTTP Request Configuration

```
  -X, --method string                 Override the HTTP method. Example: -X 'PUT' (default "GET")
  -d, --data string                   Use POST method and add body data. Example: -d 'username=admin&password=admin'
  -H, --header strings                Add custom headers to the request. Example: -H 'Authorization: Bearer <token>'
  -C, --cookie string                 Add custom cookies to the request. Example: -C 'sessionid=abc123'
      --cookie-from-raw string        Load cookies from a raw HTTP request file. Example: --cookie-from-raw 'request.txt'
      --user-agent string             Set a custom User-Agent header. Example: --user-agent 'Mozilla/5.0'
  -F, --follow-redirects              Follow HTTP redirects. Example: -F
      --proxy string                  Send all requests through a proxy server. Example: --proxy 'http://127.0.0.1:8080'
      --timeout int                   Set the request timeout in seconds. Example: --timeout 10 (default 10)
```

### Scanning Control

```
  -p, --param strings                 Specify parameters to test. Example: -p 'username' -p 'password'
      --ignore-param strings          Ignore specific parameters during scanning. Example: --ignore-param 'api_token' 
      --ignore-return string          Ignore specific HTTP return codes. Example: --ignore-return '302,403,404'
  -w, --worker int                    Set the number of concurrent workers. Example: -w 100 (default 100)
      --delay int                     Set the delay between requests in milliseconds. Example: --delay 1000
      --max-cpu int                   Set the maximum number of CPUs to use. Example: --max-cpu 1 (default 1)
      --waf-evasion                   Enable WAF evasion by adjusting speed when detecting WAF. Example: --waf-evasion
```

### Feature Selection

```
      --custom-payload string         Load custom payloads from a file. Example: --custom-payload 'payloads.txt'
      --only-custom-payload           Only test custom payloads. Example: --only-custom-payload
      --remote-payloads string        Use remote payloads for XSS testing. Example: --remote-payloads 'portswigger,payloadbox'
      --remote-wordlists string       Use remote wordlists for parameter mining. Example: --remote-wordlists 'burp'
      --custom-alert-type string      Set a custom alert type. Example: --custom-alert-type 'str,none' (default "none")
      --custom-alert-value string     Set a custom alert value. Example: --custom-alert-value 'document.cookie' (default "1")
      --deep-domxss                   Enable deep DOM XSS testing with more payloads (slow). Example: --deep-domxss
      --force-headless-verification   Force headless browser-based verification. Example: --force-headless-verification
      --use-bav                       Enable Basic Another Vulnerability (BAV) analysis. Example: --use-bav
      --grep string                   Use a custom grepping file. Example: --grep './samples/sample_grep.json'
      --har-file-path string          Save HAR files of scan requests. Example: --har-file-path 'scan.har'
      --found-action string           Execute a command when a vulnerability is found. Example: --found-action './notify.sh'
      --found-action-shell string     Shell to use for found action. Example: --found-action-shell 'bash' (default "bash")
```

### Discovery Control

```
      --only-discovery                Only perform parameter analysis, skip XSS scanning. Example: --only-discovery
      --skip-discovery                Skip discovery phase, proceed to XSS scanning. Example: --skip-discovery -p 'username'
      --skip-bav                      Skip Basic Another Vulnerability analysis. Example: --skip-bav
      --skip-grepping                 Skip built-in grepping. Example: --skip-grepping
      --skip-headless                 Skip headless browser-based scanning. Example: --skip-headless
      --skip-mining-all               Skip all parameter mining. Example: --skip-mining-all
      --skip-mining-dict              Skip dictionary-based parameter mining. Example: --skip-mining-dict
      --skip-mining-dom               Skip DOM-based parameter mining. Example: --skip-mining-dom
      --skip-xss-scanning             Skip XSS scanning. Example: --skip-xss-scanning
      --mining-dict                   Enable dictionary-based parameter mining. Example: --mining-dict (default true)
      --mining-dom                    Enable DOM-based parameter mining. Example: --mining-dom (default true)
  -W, --mining-dict-word string       Specify a custom wordlist file for parameter mining. Example: -W 'wordlist.txt'
```

### Output Control

```
      --only-poc string               Show only specific PoC code types. Example: --only-poc 'g,v'
                                      Supported types: g (grep), r (reflected), v (verified)
      --poc-type string               Select PoC format. Example: --poc-type 'curl' (default "plain")
                                      Supported formats: plain, curl, httpie, http-request
      --output-all                    Enable all log write mode. Example: --output-all
      --output-request                Include raw HTTP requests in results. Example: --output-request
      --output-response               Include raw HTTP responses in results. Example: --output-response
```

## Mode-Specific Flags

Different modes have specific flags to customize their behavior. Here's a summary:

### Server Mode Flags
```
      --host string   Bind address (default "0.0.0.0")
      --port int      Bind Port (default 6664)
```

### Pipe/File Mode Flags
```
      --limit int         Limit number of results to display. Example: --limit 10
      --mass              Enable parallel scanning in N*Host mode. Example: --mass
      --mass-worker int   Set number of parallel workers. Example: --mass-worker 10 (default 10)
      --multicast         Enable parallel scanning (synonym for --mass). Example: --multicast
      --silence-force     Only print PoC code, suppress progress output. Example: --silence-force
```

### File-specific Flags
```
      --har               [FORMAT] Use HAR format. Example: --har
      --http              Force HTTP on raw data mode. Example: --http
      --rawdata           [FORMAT] Use raw data from Burp/ZAP. Example: --rawdata
```

### SXSS Mode Flags
```
      --request-method string   HTTP method to send to server. Example: --request-method 'POST' (default "GET")
      --sequence int            Initial sequence number for trigger URL. Example: --sequence 3 (default -1)
      --trigger string          URL to check after injecting SXSS code. Example: --trigger 'https://example.com/profile'
```

### Payload Mode Flags
```
      --encoder-url            Encode output as URL. Example: --encoder-url
      --entity-event-handler   Enumerate event handlers. Example: --entity-event-handler
      --entity-gf              Enumerate parameters from GF-Patterns. Example: --entity-gf
      --entity-special-chars   Enumerate special characters. Example: --entity-special-chars
      --entity-useful-tags     Enumerate useful tags. Example: --entity-useful-tags
      --enum-attr              Enumerate in-attribute XSS payloads. Example: --enum-attr
      --enum-common            Enumerate common XSS payloads. Example: --enum-common
      --enum-html              Enumerate in-HTML XSS payloads. Example: --enum-html
      --enum-injs              Enumerate in-JavaScript XSS payloads. Example: --enum-injs
      --make-bulk              Generate bulk payloads for stored XSS. Example: --make-bulk
      --remote-payloadbox      Use Payloadbox's XSS payloads. Example: --remote-payloadbox
      --remote-portswigger     Use PortSwigger's XSS cheatsheet. Example: --remote-portswigger
```
