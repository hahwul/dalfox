---
title: Usage
redirect_from: /docs/usage/
nav_order: 3
has_children: true
toc: true
layout: page
---
# Usage

The options for the Dalfox are largely configured with `commands` and `flags`.

```shell
dalfox [command] [flags]
```

```
Modes:
  file        Use file mode(targets list or rawdata)
  help        Help about any command
  pipe        Use pipeline mode
  server      Start API Server
  sxss        Use Stored XSS mode
  url         Use single target mode
  version     Show version

Global Flags:
  -b, --blind string                  Specify a blind XSS callback URL. Example: -b 'https://your-callback-url.com'
      --config string                 Load configuration from a file. Example: --config 'config.json'
  -C, --cookie string                 Add custom cookies to the request. Example: -C 'sessionid=abc123'
      --cookie-from-raw string        Load cookies from a raw HTTP request file. Example: --cookie-from-raw 'request.txt'
      --custom-alert-type string      Set a custom alert type. Example: --custom-alert-type 'str,none' (default "none")
      --custom-alert-value string     Set a custom alert value. Example: --custom-alert-value 'document.cookie' (default "1")
      --custom-payload string         Load custom payloads from a file. Example: --custom-payload 'payloads.txt'
  -d, --data string                   Use POST method and add body data. Example: -d 'username=admin&password=admin'
      --debug                         Enable debug mode and save all logs. Example: --debug
      --deep-domxss                   Enable deep DOM XSS testing with more payloads (slow). Example: --deep-domxss
      --delay int                     Set the delay between requests to the same host in milliseconds. Example: --delay 1000
  -F, --follow-redirects              Follow HTTP redirects. Example: -F
      --force-headless-verification   Force headless browser-based verification, useful when automatic detection fails or to override default behavior. Example: --force-headless-verification
      --format string                 Set the output format. Supported: plain, json. Example: --format 'json' (default "plain")
      --found-action string           Execute a command when a vulnerability is found. Example: --found-action './notify.sh'
      --found-action-shell string     Specify the shell to use for the found action. Example: --found-action-shell 'bash' (default "bash")
      --grep string                   Use a custom grepping file. Example: --grep './samples/sample_grep.json'
      --har-file-path string          Specify the path to save HAR files of scan requests. Example: --har-file-path 'scan.har'
  -H, --header strings                Add custom headers to the request. Example: -H 'Authorization: Bearer <token>'
      --ignore-param strings          Ignore specific parameters during scanning. Example: --ignore-param 'api_token' --ignore-param 'csrf_token'
      --ignore-return string          Ignore specific HTTP return codes. Example: --ignore-return '302,403,404'
      --max-cpu int                   Set the maximum number of CPUs to use. Example: --max-cpu 1 (default 1)
  -X, --method string                 Override the HTTP method. Example: -X 'PUT' (default "GET")
      --mining-dict                   Enable dictionary-based parameter mining. Example: --mining-dict (default true)
  -W, --mining-dict-word string       Specify a custom wordlist file for parameter mining. Example: -W 'wordlist.txt'
      --mining-dom                    Enable DOM-based parameter mining. Example: --mining-dom (default true)
      --no-color                      Disable colorized output. Example: --no-color
      --no-spinner                    Disable spinner animation. Example: --no-spinner
      --only-custom-payload           Only test custom payloads. Example: --only-custom-payload
      --only-discovery                Only perform parameter analysis, skip XSS scanning. Example: --only-discovery
      --only-poc string               Show only the PoC code for the specified pattern. Supported: g (grep), r (reflected), v (verified). Example: --only-poc 'g,v'
  -o, --output string                 Write output to a file. Example: -o 'output.txt'
      --output-all                    Enable all log write mode (output to file or stdout). Example: --output-all
      --output-request                Include raw HTTP requests in the results. Example: --output-request
      --output-response               Include raw HTTP responses in the results. Example: --output-response
  -p, --param strings                 Specify parameters to test. Example: -p 'username' -p 'password'
      --poc-type string               Select the PoC type. Supported: plain, curl, httpie, http-request. Example: --poc-type 'curl' (default "plain")
      --proxy string                  Send all requests through a proxy server. Example: --proxy 'http://127.0.0.1:8080'
      --remote-payloads string        Use remote payloads for XSS testing. Supported: portswigger, payloadbox. Example: --remote-payloads 'portswigger,payloadbox'
      --remote-wordlists string       Use remote wordlists for parameter mining. Supported: burp, assetnote. Example: --remote-wordlists 'burp'
      --report                        Show detailed report. Example: --report
      --report-format string          Set the format of the report. Supported: plain, json. Example: --report-format 'json' (default "plain")
  -S, --silence                       Only print PoC code and progress. Example: -S
      --skip-bav                      Skip Basic Another Vulnerability (BAV) analysis. Example: --skip-bav
      --skip-discovery                Skip the entire discovery phase, proceeding directly to XSS scanning. Requires -p flag to specify parameters. Example: --skip-discovery -p 'username'
      --skip-grepping                 Skip built-in grepping. Example: --skip-grepping
      --skip-headless                 Skip headless browser-based scanning (DOM XSS and inJS verification). Example: --skip-headless
      --skip-mining-all               Skip all parameter mining. Example: --skip-mining-all
      --skip-mining-dict              Skip dictionary-based parameter mining. Example: --skip-mining-dict
      --skip-mining-dom               Skip DOM-based parameter mining. Example: --skip-mining-dom
      --skip-xss-scanning             Skip XSS scanning. Example: --skip-xss-scanning
      --timeout int                   Set the request timeout in seconds. Example: --timeout 10 (default 10)
      --use-bav                       Enable Basic Another Vulnerability (BAV) analysis. Example: --use-bav
      --user-agent string             Set a custom User-Agent header. Example: --user-agent 'Mozilla/5.0'
      --waf-evasion                   Enable WAF evasion by adjusting speed when detecting WAF (worker=1, delay=3s). Example: --waf-evasion
  -w, --worker int                    Set the number of concurrent workers. Example: -w 100 (default 100)

Server Flags:
  -h, --help          help for server
      --host string   Bind address (default "0.0.0.0")
      --port int      Bind Port (default 6664)

Pipe Flags:
  -h, --help              help for pipe
      --limit int         Limit the number of results to display. Example: --limit 10
      --mass              Enable parallel scanning in N*Host mode (only shows PoC code). Example: --mass
      --mass-worker int   Set the number of parallel workers for --mass and --multicast options. Example: --mass-worker 10 (default 10)
      --multicast         Enable parallel scanning in N*Host mode (only shows PoC code). Example: --multicast
      --silence-force     Only print PoC code, suppress progress output. Example: --silence-force

File Flags:
      --har               [FORMAT] Use HAR format. Example: --har
  -h, --help              help for file
      --http              Force HTTP on raw data mode. Example: --http
      --limit int         Limit the number of results to display. Example: --limit 10
      --mass              Enable parallel scanning in N*Host mode (only shows PoC code). Example: --mass
      --mass-worker int   Set the number of parallel workers for --mass and --multicast options. Example: --mass-worker 10 (default 10)
      --multicast         Enable parallel scanning in N*Host mode (only shows PoC code). Example: --multicast
      --rawdata           [FORMAT] Use raw data from Burp/ZAP. Example: --rawdata
      --silence-force     Only print PoC code, suppress progress output. Example: --silence-force

SXSS Flags:
  -h, --help                    help for sxss
      --request-method string   Specify the HTTP request method to send to the server. Example: --request-method 'POST' (default "GET")
      --sequence int            Set the initial sequence number for the trigger URL. Example: --trigger 'https://example.com/view?no=SEQNC' --sequence 3 (default -1)
      --trigger string          Specify the URL to check after injecting SXSS code. Example: --trigger 'https://example.com/profile'

Payload Flags:
      --encoder-url            Encode output as URL. Example: --encoder-url
      --entity-event-handler   Enumerate event handlers for XSS. Example: --entity-event-handler
      --entity-gf              Enumerate parameters from GF-Patterns for XSS. Example: --entity-gf
      --entity-special-chars   Enumerate special characters for XSS. Example: --entity-special-chars
      --entity-useful-tags     Enumerate useful tags for XSS. Example: --entity-useful-tags
      --enum-attr              Enumerate in-attribute XSS payloads. Example: --enum-attr
      --enum-common            Enumerate common XSS payloads. Example: --enum-common
      --enum-html              Enumerate in-HTML XSS payloads. Example: --enum-html
      --enum-injs              Enumerate in-JavaScript XSS payloads. Example: --enum-injs
  -h, --help                   help for payload
      --make-bulk              Generate bulk payloads for stored XSS. Example: --make-bulk
      --remote-payloadbox      Enumerate payloads from Payloadbox's XSS payloads. Example: --remote-payloadbox
      --remote-portswigger     Enumerate payloads from PortSwigger's XSS cheatsheet. Example: --remote-portswigger


```

## Modes(commands)
The dalfox supports a total of five modes. (`url` / `pipe` / `file` / `sxss` / `server`)

Each mode has the following purposes.
* [URL Mode](/docs/modes/url-mode/)
* [Pipe Mode](/docs/modes/pipe-mode/)
* [File Mode](/docs/modes/file-mode/)
* [SXSS Mode](/docs/modes/sxss-mode/)
* [Server Mode](/docs/modes/server-mode/)
