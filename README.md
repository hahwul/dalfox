<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/89670501-45b4a600-d91c-11ea-95d9-0b3802259dfd.png" alt="" width="260px;"></a>
  <br>
  DalFox(Finder Of XSS)
  <br>
  <img src="https://img.shields.io/github/v/release/hahwul/dalfox?style=flat-square"> 
  <a href="https://snapcraft.io/dalfox"><img alt="dalfox" src="https://snapcraft.io/dalfox/badge.svg" /></a>
  <img src="https://img.shields.io/github/languages/top/hahwul/dalfox?style=flat-square"> <img src="https://api.codacy.com/project/badge/Grade/17cac7b8d1e849a688577f2bbdd6ecd0"> <a href="https://goreportcard.com/report/github.com/hahwul/dalfox"><img src="https://goreportcard.com/badge/github.com/hahwul/dalfox"></a> <img src="https://img.shields.io/github/issues-closed/hahwul/dalfox?style=flat-square"> 
<a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat-square"></a>
</h1>
Finder Of XSS, and Dal is the Korean pronunciation of moon.

## What is DalFox 🌘🦊
Just, XSS Scanning and Parameter Analysis tool. I previously developed [XSpear](https://github.com/hahwul/XSpear), a ruby-based XSS tool, and this time, a full change occurred during the process of porting with golang!!! and created it as a new project. The basic concept is to analyze parameters, find XSS, and verify them based on DOM Parser.

I talk about naming. Dal(달) is the Korean pronunciation of moon and fox was made into Fox(Find Of XSS).

## Key features

- Paramter Analysis (find reflected parameter, find free/bad characters, Identification of injection point)
- Static Analysis (Check Bad-header like CSP, X-Frame-optiopns, etc.. with base request/response base)
- Optimization query of payloads
  - Check the injection point through abstraction and generated the fit payload.
  - Eliminate unnecessary payloads based on badchar
- XSS Scanning(Reflected + Stored) and DOM Base Verifying
- All test payloads(build-in, your custom/blind) are tested in parallel with the encoder.
  - Support to Double URL Encoder
  - Support to HTML Hex Encoder
- Friendly Pipeline (single url, from file, from IO)
- And the various options required for the testing :D
  - built-in / custom grepping for find other vulnerability
  - if you found, after action
  - etc..
- Support API Server and Swagger
- Support package manager and docker env ( `homebrew` `snapcraft` `docker hub` `github dockerhub` )

## How to Install
You can find some additional installation variations in the [Installation Guide](https://github.com/hahwul/dalfox/wiki/1.-Installation).

## Usage
```plain
    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''
Parameter Analysis and XSS Scanning tool based on golang
Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul
Usage:
  dalfox [command]

Available Commands:
  file        Use file mode(targets list or rawdata)
  help        Help about any command
  pipe        Use pipeline mode
  server      Start API Server
  sxss        Use Stored XSS mode
  url         Use single target mode
  version     Show version

Flags:
  -b, --blind string            Add your blind xss (e.g -b hahwul.xss.ht)
      --config string           Using config from file
  -C, --cookie string           Add custom cookie
      --custom-payload string   Add custom payloads from file
  -d, --data string             Using POST Method and add Body data
      --delay int               Milliseconds between send to same host (1000==1s)
      --follow-redirects        Following redirection
      --format string           stdout output format(plain/json) (default "plain")
      --found-action string     If found weak/vuln, action(cmd) to next
      --grep string             Using custom grepping file (e.g --grep ./samples/sample_grep.json)
  -H, --header string           Add custom headers
  -h, --help                    help for dalfox
      --ignore-return string    Ignore scanning from return code (e.g --ignore-return 302,403,404)
      --only-discovery          Only testing parameter analysis
  -o, --output string           Write to output file
  -p, --param string            Only testing selected parameters
      --proxy string            Send all request to proxy server (e.g --proxy http://127.0.0.1:8080)
      --silence                 Not printing all logs
      --timeout int             Second of timeout (default 10)
      --user-agent string       Add custom UserAgent
  -w, --worker int              Number of worker (default 100)

Use "dalfox [command] --help" for more information about a command.
```

```
$ dalfox [mode] [flags]
```

Single target mode
```plain
$ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://hahwul.xss.ht
```

Multiple target mode from file
```plain
$ dalfox file urls_file --custom-payload ./mypayloads.txt
```

Pipeline mode
```plain
$ cat urls_file | dalfox pipe -H "AuthToken: bbadsfkasdfadsf87"
```

Other tips, See [wiki](https://github.com/hahwul/dalfox/wiki) for detailed instructions!

## Screenshots
| ![1414](https://user-images.githubusercontent.com/13212227/89736704-4ed17e80-daa6-11ea-90d8-32f915911b52.png) | ![1415](https://user-images.githubusercontent.com/13212227/89736705-5002ab80-daa6-11ea-9ee8-d2def396c25a.png) |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Single URL Scanning                                          | API Server and Swagger                                       |
| ![1416](https://user-images.githubusercontent.com/13212227/89736707-509b4200-daa6-11ea-9ca6-8055fa714401.png) | ![1419](https://user-images.githubusercontent.com/13212227/89736914-087d1f00-daa8-11ea-87e6-e33b78e2d344.png) |
| Built-in and Custom Grepping                                 | Pipeline Scanning                                            |

