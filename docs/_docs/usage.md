---
title: Usage and Modes
permalink: /docs/usage/
---
## Usage
The options for the Dalfox are largely configured with `commands` and `flags`.
```shell
$ dalfox [command] [flags]
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
  -b, --blind string              Add your blind xss (e.g -b hahwul.xss.ht)
      --config string             Using config from file
  -C, --cookie string             Add custom cookie
      --custom-payload string     Add custom payloads from file
  -d, --data string               Using POST Method and add Body data
      --delay int                 Milliseconds between send to same host (1000==1s)
      --follow-redirects          Following redirection
      --format string             Stdout output format(plain/json) (default "plain")
      --found-action string       If found weak/vuln, action(cmd) to next
      --grep string               Using custom grepping file (e.g --grep ./samples/sample_grep.json)
  -H, --header string             Add custom headers
  -h, --help                      help for dalfox
      --ignore-return string      Ignore scanning from return code (e.g --ignore-return 302,403,404)
  -X, --method string             Force overriding HTTP Method (e.g -X PUT)
      --mining-dict               Find new parameter with dictionary attack, default is Gf-Patterns=>XSS (default true)
      --mining-dict-word string   Custom wordlist file for param mining (e.g --mining-dict-word word.txt)
      --mining-dom                Find new parameter in DOM (attribute/js value) (default true)
      --no-color                  Not use colorize
      --no-spinner                Not use spinner
      --only-custom-payload       Only testing custom payload (required --custom-payload)
      --only-discovery            Only testing parameter analysis (same '--skip-xss-scanning' option)
  -o, --output string             Write to output file
  -p, --param string              Only testing selected parameters
      --proxy string              Send all request to proxy server (e.g --proxy http://127.0.0.1:8080)
      --silence                   Not printing all logs
      --skip-bav                  Skipping BAV(Basic Another Vulnerability) analysis
      --skip-grepping             Skipping built-in grepping
      --skip-mining-all           Skipping ALL parameter mining
      --skip-mining-dict          Skipping Dict base parameter mining
      --skip-mining-dom           Skipping DOM base parameter mining
      --skip-xss-scanning         Skipping XSS Scanning (same '--only-discovery' option)
      --timeout int               Second of timeout (default 10)
      --user-agent string         Add custom UserAgent
  -w, --worker int                Number of worker (default 100)

Server Flags:
  -h, --help          help for server
      --host string   Bind address (default "0.0.0.0")
      --port int      Bind Port (default 6664)
      
Pipe Flags:
  -h, --help        help for pipe
      --multicast   Scanning N*Host mode
      
File Flags:
  -h, --help        help for file
      --http        Using force http on rawdata mode
      --multicast   Scanning N*Host mode
      --rawdata     Using req rawdata from Burp/ZAP
      
SXSS Flags:
  -h, --help             help for sxss
      --mass             Testing mass vector (comming soon)
      --sequence int     Set sequence to first number (e.g --trigger https://~/view?no=SEQNC --sequence 3) (default -1)
      --trigger string   Checking this url after inject sxss code (e.g --trigger https://~~/profile)
```

## Modes(commands)
The dalfox supports a total of five modes. (`url` / `pipe` / `file` / `sxss` / `server`)

Each mode has the following purposes.
* [URL Mode](http://frozen.hahwul.com:4000/docs/modes/url-mode/)
* [Pipe Mode](http://frozen.hahwul.com:4000/docs/modes/pipe-mode/)
* [File Mode](http://frozen.hahwul.com:4000/docs/modes/file-mode/)
* [SXSS Mode](http://frozen.hahwul.com:4000/docs/modes/sxss-mode/)
* [Server Mode](http://frozen.hahwul.com:4000/docs/modes/server-mode/)
