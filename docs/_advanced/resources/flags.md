---
title: Global Flags
redirect_from: /docs/flags/
parent: Resources
nav_order: 5
toc: true
layout: page
---

# Global Flags

```
-b, --blind string                Add your blind xss
                                    * Example: -b your-callback-url
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
    --found-action-shell string   Select shell application for --found-action (default "bash")
    --grep string                 Using custom grepping file
                                    * Example: --grep ./samples/sample_grep.json
-H, --header strings              Add custom headers
-h, --help                        help for dalfox
    --ignore-return string        Ignore scanning from return code
                                    * Example: --ignore-return 302,403,404
-X, --method string               Force overriding HTTP Method
                                    * Example: -X PUT (default "GET")
    --request-method              Use custom method for --trigger url ( default "GET" )
    --mining-dict                 Find new parameter with dictionary attack, default is Gf-Patterns=>XSS (default true)
-W, --mining-dict-word string     Custom wordlist file for param mining
                                    * Example: --mining-dict-word word.txt
    --mining-dom                  Find new parameter in DOM (attribute/js value) (default true)
    --no-color                    Not use colorize
    --no-spinner                  Not use spinner
    --only-custom-payload         Only testing custom payload (required --custom-payload)
    --only-discovery              Only testing parameter analysis (same '--skip-xss-scanning' option)
    --only-poc string             Shows only the PoC code for the specified pattern (g: grep / r: reflected / v: verified)
                                   * Example: --only-poc='g,v'
-o, --output string               Write to output file (By default, only the PoC code is saved)
    --output-all                  All log write mode (-o or stdout)
-p, --param strings               Only testing selected parameters
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
```
