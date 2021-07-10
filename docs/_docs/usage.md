---
title: Usage and Modes
permalink: /docs/usage/
---
## Usage
The options for the Dalfox are largely configured with `commands` and `flags`.
```shell
▶ dalfox [command] [flags]
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
-b, --blind string                Add your blind xss
                                    * Example: -b hahwul.xss.ht
    --config string               Using config from file
-C, --cookie string               Add custom cookie
    --cookie-from-raw string      Load cookie from burp raw http request
                                    * Example: --cookie-from-raw request.txt
    --custom-alert-type string    Change alert value type
                                    * Example: --custom-alert-type=none / --custom-alert-type=str,none (default "none")
    --custom-alert-value string   Change alert value
                                    * Example: --custom-alert-value=document.cookie (default "1")
    --custom-payload string       Add custom payloads from file
-d, --data string                 Using POST Method and add Body data
    --debug                       debug mode, save all log using -o option
    --deep-domxss                 DOM XSS Testing with more payloads on headless [so slow]
    --delay int                   Milliseconds between send to same host (1000==1s)
-F, --follow-redirects            Following redirection
    --format string               Stdout output format
                                    * Supported: plain / json (default "plain")
    --found-action string         If found weak/vuln, action(cmd) to next
                                    * Example: --found-action='./notify.sh'
    --found-action-shell string Select shell application for --found-action (default "bash")
    --grep string                 Using custom grepping file
                                    * Example: --grep ./samples/sample_grep.json
-H, --header string               Add custom headers
-h, --help                        help for dalfox
    --ignore-return string        Ignore scanning from return code
                                    * Example: --ignore-return 302,403,404
-X, --method string               Force overriding HTTP Method
                                    * Example: -X PUT (default "GET")
    --mining-dict                 Find new parameter with dictionary attack, default is Gf-Patterns=>XSS (default true)
-W, --mining-dict-word string     Custom wordlist file for param mining
                                    * Example: --mining-dict-word word.txt
    --mining-dom                  Find new parameter in DOM (attribute/js value) (default true)
    --no-color                    Not use colorize
    --no-spinner                  Not use spinner
    --only-custom-payload         Only testing custom payload (required --custom-payload)
    --only-discovery              Only testing parameter analysis (same '--skip-xss-scanning' option)
    --only-poc string             Shows only the PoC code for the specified pattern (g: grep / r: reflected / v: verified)
-o, --output string               Write to output file (By default, only the PoC code is saved)
    --output-all                  All log write mode (-o or stdout)
-p, --param string                Only testing selected parameters
    --proxy string                Send all request to proxy server
                                    * Example: --proxy http://127.0.0.1:8080
    --remote-payloads string      Using remote payload for XSS testing
                                    * Supported: portswigger/payloadbox
                                    * Example: --remote-payloads=portswigger,payloadbox
    --remote-wordlists string     Using remote wordlists for param mining
                                    * Supported: burp/assetnote
                                    * Example: --remote-wordlists=burp
-S, --silence                     Not printing all logs
    --skip-bav                    Skipping BAV(Basic Another Vulnerability) analysis
    --skip-grepping               Skipping built-in grepping
    --skip-headless               Skipping headless browser base scanning[DOM XSS and inJS verify]
    --skip-mining-all             Skipping ALL parameter mining
    --skip-mining-dict            Skipping Dict base parameter mining
    --skip-mining-dom             Skipping DOM base parameter mining
    --skip-xss-scanning           Skipping XSS Scanning (same '--only-discovery' option)
    --timeout int                 Second of timeout (default 10)
    --user-agent string           Add custom UserAgent
-w, --worker int                  Number of worker (default 100)

Server Flags:
  -h, --help          help for server
      --host string   Bind address (default "0.0.0.0")
      --port int      Bind Port (default 6664)

Pipe Flags:
  -h, --help        help for pipe
      --mass              Parallel scanning N*Host mode (show only poc code)
      --mass-worker int   Parallel worker of --mass and --multicast option (default 10)
      --multicast   Parallel scanning N*Host mode (show only poc code)

File Flags:
  -h, --help        help for file
      --http        Using force http on rawdata mode
      --mass              Parallel scanning N*Host mode (show only poc code)
      --mass-worker int   Parallel worker of --mass and --multicast option (default 10)
      --multicast   Parallel scanning N*Host mode (show only poc code)
      --rawdata     Using req rawdata from Burp/ZAP

SXSS Flags:
  -h, --help             help for sxss
      --sequence int     Set sequence to first number
                           * Example: --trigger=https://~/view?no=SEQNC --sequence=3 (default -1)
      --trigger string   Checking this url after inject sxss code
                           * Example: --trigger=https://~~/profile

Payload Flags:
      --encoder-url            Encoding output [URL]
      --entity-event-handler   Enumerate a event handlers for xss
      --entity-gf              Enumerate a gf-patterns xss params
      --entity-special-chars   Enumerate a special chars for xss
      --entity-useful-tags     Enumerate a useful tags for xss
      --enum-attr              Enumerate a in-attr xss payloads
      --enum-common            Enumerate a common xss payloads
      --enum-html              Enumerate a in-html xss payloads
      --enum-injs              Enumerate a in-js xss payloads
  -h, --help                   help for payload
      --make-bulk              Make bulk payloads for stored xss
      --remote-payloadbox      Enumerate a payloadbox's xss payloads
      --remote-portswigger     Enumerate a portswigger xss cheatsheet payloads


```

## Modes(commands)
The dalfox supports a total of five modes. (`url` / `pipe` / `file` / `sxss` / `server`)

Each mode has the following purposes.
* [URL Mode](/docs/modes/url-mode/)
* [Pipe Mode](/docs/modes/pipe-mode/)
* [File Mode](/docs/modes/file-mode/)
* [SXSS Mode](/docs/modes/sxss-mode/)
* [Server Mode](/docs/modes/server-mode/)
