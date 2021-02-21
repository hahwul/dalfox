<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/79072646-1cdd2500-7d1d-11ea-8a6d-d24301172a17.png" alt="" width="500px;"></a>
</h1>
<h4 align="center">Finder Of XSS, and Dal(달) is the Korean pronunciation of moon.</h4>

<p align="center"> 
  <a href=""><img src="https://img.shields.io/github/v/release/hahwul/dalfox?style=flat"></a>
  <a href=""><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
  <a href=""><img src="https://api.codacy.com/project/badge/Grade/17cac7b8d1e849a688577f2bbdd6ecd0"></a>
  <a href="https://goreportcard.com/report/github.com/hahwul/dalfox"><img src="https://goreportcard.com/badge/github.com/hahwul/dalfox"></a>
  <a href=""><img src="https://github.com/hahwul/dalfox/workflows/Go%20build/badge.svg"></a>
  <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat&logo=twitter"></a>
  <a href="https://github.com/hahwul"><img src="https://img.shields.io/github/stars/hahwul?style=flat&logo=github"></a></a>
</p>

## What is DalFox 🌘🦊
DalFox is a fast, powerful parameter analysis and XSS scanner, based on a golang/DOM parser. supports friendly Pipeline, CI/CD and testing of different types of XSS. I talk about naming. Dal([달](https://en.wiktionary.org/wiki/달)) is the Korean pronunciation of moon and fox was made into Fox(Find Of XSS).

## TOC
- [Key features](#key-features)
- [How to Install](#how-to-install)
- [Usage](#usage)
- [POC format](#poc-format)
- [Screenshots](#screenshots)
- [Wiki](https://dalfox.hahwul.com/docs/home/)
- [Contribute](https://github.com/hahwul/dalfox/blob/master/CONTRIBUTING.md)
- [Contributors](#contributors)


## Key features
Mode: `url` `sxss` `pipe` `file` `server`

| Class         | Key Feature                   | Description                                                  |
| ------------- | ----------------------------- | ------------------------------------------------------------ |
| Discovery     | Parameter analysis            | - Find reflected param<br />- Find alive/bad special chars, event handler and attack code <br />- Identification of injection points(HTML/JS/Attribute) <br /> `inHTML-none` `inJS-none` `inJS-double` `inJS-single` `inJS-backtick` `inATTR-none` `inATTR-double` `inATTR-single` |
|               | Static analysis               | - Check bad-header like CSP, XFO, etc.. with req/res base    |
|               | BAV analysis                  | - Testing BAV(Basic Another Vulnerability) ,  e.g `sqli` `ssti` `open-redirects`    |
|               | Parameter Mining              | - Find new param with Dictonary attack (default is [GF-Patterns](https://github.com/1ndianl33t/Gf-Patterns))<br />- Support custom dictonary file (`--mining-dict-word`)<br />- FInd new param with DOM |
|               | Built-in Grepping             | - It Identify the basic info leak of SSTi, Credential, SQL Error, and so on |
| Scanning      | XSS Scanning                  | - Reflected xss / stored xss <br />- DOM base verifying<br />- Blind XSS testing with param, header(`-b` , `--blind` options)<br />- Only testing selected parameters (`-p`, `--param`)<br />- Only testing parameter analysis (`--only-discovery`) |
|               | Friendly Pipeline             | - Single url mode (`dalfox url`)<br />- From file mode (`dalfox file urls.txt`)<br />- From IO(pipeline) mode (`dalfox pipe`)<br />- From raw http request file mode (`dalfox file raw.txt --rawdata`) |
|               | Optimizaion query of payloads | - Check the injection point through abstraction and generated the fit payload.<br />- Eliminate unnecessary payloads based on badchar |
|               | Encoder                       | - All test payloads(build-in, your custom/blind) are tested in parallel with the encoder.<br />- To Double URL Encoder<br />- To HTML Hex Encoder |
|               | Sequence                      | - Auto-check the special page for stored xss (`--trigger`) <br />- Support (`--sequence`) options for Stored XSS , only `sxss` mode |
| HTTP          | HTTP Options                  | - Overwrite HTTP Method (`-X`, `--method`)<br />- Follow redirects (`--follow-redirects`)<br />- Add header (`-H`, `--header`)<br />- Add cookie (`-C`, `--cookie`)<br />- Add User-Agent (`--user-agent`)<br />- Set timeout (`--timeout`)<br />- Set Delay (`--delay`)<br />- Set Proxy (`--proxy`)<br />- Set ignore return codes (`--ignore-return`)<br />- Load cookie from raw request (`--cookie-from-raw`) |
| Concurrency   | Worker                        | - Set worker's number(`-w`, `--worker`)                      |
|               | N * hosts                     | - Use multicast mode (`--multicast`) , only `file` / `pipe` mode |
| Output        | Output                        | - Only the PoC code and useful information is write as Stdout<br />- Save output (`-o`, `--output`) |
|               | Format                        | - JSON / Plain (`--format`)                                  |
|               | Printing                      | - Silence mode (`--silence`)<br />- You may choose not to print the color (`--no-color`)<br />- You may choose not to print the spinner (`--no-spinner`) |
| Extensibility | REST API                      | - API Server and Swagger (`dalfox server`)                   |
|               | Found Action                  | - Lets you specify the actions to take when detected. <br />- Notify, for example (`--found-action`) |
|               | Custom Grepping               | - Can grep with custom regular expressions on response<br />- If duplicate detection, it performs deduplication (`--grep`) |
|               | Custom Payloads               | - Use custom payloads list file (`--custom-payload`) <br />- Custom alert value (`--custom-alert-value`) <br />- Custom alert type (`--custom-alert-type`)|
| Package       | Package manager                | - [pkg.go.dev](https://pkg.go.dev/github.com/hahwul/dalfox/v2)<br/>- [homebrew with tap](https://github.com/hahwul/homebrew-dalfox)<br />- [snapcraft](https://snapcraft.io/dalfox)                                  |
|               | Docker ENV                    | - [docker hub](https://hub.docker.com/repository/docker/hahwul/dalfox)<br />- [gitub package of docker](https://github.com/hahwul/dalfox/packages)                         |

And the various options required for the testing :D

## How to Install
You can find some additional installation variations in the [Installation Guide](https://dalfox.hahwul.com/docs/installation/).

## Usage
```plain
Modes: 
  file        Use file mode(targets list or rawdata)
  help        Help about any command
  pipe        Use pipeline mode
  server      Start API Server
  sxss        Use Stored XSS mode
  url         Use single target mode
  version     Show version

Global Flags:
Flags:
  -b, --blind string                Add your blind xss (e.g -b hahwul.xss.ht)
      --config string               Using config from file
  -C, --cookie string               Add custom cookie
      --cookie-from-raw string      Load cookie from burp raw http request (e.g --cookie-from-raw request.txt)
      --custom-alert-type string    Change alert value type (e.g =none / =str,none) (default "none")
      --custom-alert-value string   Change alert value (e.g custom-alert-value=document.cookie (default "1")
      --custom-payload string       Add custom payloads from file
  -d, --data string                 Using POST Method and add Body data
      --debug                       debug mode, save all log using -o option
      --delay int                   Milliseconds between send to same host (1000==1s)
      --follow-redirects            Following redirection
      --format string               Stdout output format(plain/json) (default "plain")
      --found-action string         If found weak/vuln, action(cmd) to next
      --grep string                 Using custom grepping file (e.g --grep ./samples/sample_grep.json)
  -H, --header string               Add custom headers
  -h, --help                        help for dalfox
      --ignore-return string        Ignore scanning from return code (e.g --ignore-return 302,403,404)
  -X, --method string               Force overriding HTTP Method (e.g -X PUT)
      --mining-dict                 Find new parameter with dictionary attack, default is Gf-Patterns=>XSS (default true)
      --mining-dict-word string     Custom wordlist file for param mining (e.g --mining-dict-word word.txt)
      --mining-dom                  Find new parameter in DOM (attribute/js value) (default true)
      --no-color                    Not use colorize
      --no-spinner                  Not use spinner
      --only-custom-payload         Only testing custom payload (required --custom-payload)
      --only-discovery              Only testing parameter analysis (same '--skip-xss-scanning' option)
  -o, --output string               Write to output file
  -p, --param string                Only testing selected parameters
      --proxy string                Send all request to proxy server (e.g --proxy http://127.0.0.1:8080)
      --silence                     Not printing all logs
      --skip-bav                    Skipping BAV(Basic Another Vulnerability) analysis
      --skip-grepping               Skipping built-in grepping
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
      --mass             Testing mass vector (comming soon)
      --sequence int     Set sequence to first number (e.g --trigger https://~/view?no=SEQNC --sequence 3) (default -1)
      --trigger string   Checking this url after inject sxss code (e.g --trigger https://~~/profile)
```

```
▶ dalfox [mode] [flags] [data]
```

Single target mode
```plain
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://hahwul.xss.ht
```

Multiple target mode from file
```plain
▶ dalfox file urls_file --custom-payload ./mypayloads.txt
```

Pipeline mode
```plain
▶ cat urls_file | dalfox pipe -H "AuthToken: bbadsfkasdfadsf87"
```

Other tips, See [wiki](https://github.com/hahwul/dalfox/wiki) for detailed instructions!

## POC format
Sample poc log
```
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E
```

Format
| Identity | Type | Information                     | BLANK | PoC Code                                                     |
| -------- | ---- | ------------------------------- | ----- | ------------------------------------------------------------ |
| POC      | G    | BUILT-IN/dalfox-error-mysql/GET |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox |
| POC      | R    | GET                             |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E |
| POC      | V    | GET                             |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E |

- Type: `G`(Grep) , `R`(Reflected) , ` V`(Verify)
- Informatin: Method, grepping name, etc..

Why is there a gap?
It is a method to make it easier to parse only the poc code through cut etc. For example, you can do this.
```shell
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff | cut -d " " -f 2 > output
▶ cat output
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22+class%3Ddalfox%3E
```

## Screenshots
| ![1414](https://user-images.githubusercontent.com/13212227/108603497-7a390c80-73eb-11eb-92c1-b31bd9574861.jpg) | ![1415](https://user-images.githubusercontent.com/13212227/108603373-ebc48b00-73ea-11eb-9651-7ce4617845f6.jpg) |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Single URL Scanning                                          | Massive(Multicast/Mass) Scanning                             |
| ![1416](https://user-images.githubusercontent.com/13212227/108603375-ec5d2180-73ea-11eb-8e6e-d59d915c0291.jpg) | ![1417](https://user-images.githubusercontent.com/13212227/108613244-66b19400-7433-11eb-87fc-2f195f9011b3.jpg) |
| REST API Server Mode                                 | Output and Customizing (found-action / grepping)              |

## Wiki
[Wiki](https://dalfox.hahwul.com/docs/home/)

## Contribute
[Contribute](https://github.com/hahwul/dalfox/blob/master/CONTRIBUTING.md)

## Contributors
![](/CONTRIBUTORS.svg)
