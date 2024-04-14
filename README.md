<div align="center">
  <br>
  <img src="https://github.com/hahwul/dalfox/assets/13212227/38f4e2e4-baa4-4bcd-8e71-3d1bf01ade8c" alt="dalfox" width="400px;">
</div>
<p align="center">
  <a href="https://github.com/hahwul/dalfox/actions/workflows/go.yml"><img src="https://github.com/hahwul/dalfox/actions/workflows/go.yml/badge.svg"></a>
  <a href=""><img src="https://api.codacy.com/project/badge/Grade/17cac7b8d1e849a688577f2bbdd6ecd0"></a>
  <a href="https://goreportcard.com/report/github.com/hahwul/dalfox"><img src="https://goreportcard.com/badge/github.com/hahwul/dalfox"></a>
  <a href="https://codecov.io/gh/hahwul/dalfox"><img src="https://codecov.io/gh/hahwul/dalfox/branch/main/graph/badge.svg"/></a>
  <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat&logo=x"></a>
  <a href=""><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
</p>

DalFox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters. Its advanced testing engine and niche features are designed to streamline the process of detecting and verifying vulnerabilities.

As for the name, Dal([달](https://en.wiktionary.org/wiki/달)) is the Korean word for "moon," while "Fox" stands for "Finder Of XSS" or 🦊

## TOC
- [Key features](#key-features)
- [How to Install](#how-to-install)
- [Usage](#usage)
- [POC format](#poc-format)
- [In the Code](#in-the-code)
- [Screenshots](#screenshots)
- [Wiki](#wiki)
- [Question](#question)
- [Changelog](#changelog)
- [Contributing](#contributing)

## Key features
Mode: `url` `sxss` `pipe` `file` `server` `payload`

| Class         | Key Feature                   | Description                                                  |
| ------------- | ----------------------------- | ------------------------------------------------------------ |
| Discovery     | Parameter analysis            | - Find reflected param<br />- Find alive/bad special chars, event handler and attack code <br />- Identification of injection points(HTML/JS/Attribute) <br /> `inHTML-none` `inJS-none` `inJS-double` `inJS-single` `inJS-backtick` `inATTR-none` `inATTR-double` `inATTR-single` |
|               | Static analysis               | - Check bad-header like CSP, XFO, etc.. with req/res base    |
|               | BAV analysis                  | - Testing BAV(Basic Another Vulnerability) ,  e.g `sqli` `ssti` `open-redirects`, `crlf`, `esii`    |
|               | Parameter Mining              | - Find new param with Dictionary attack (default is [GF-Patterns](https://github.com/1ndianl33t/Gf-Patterns))<br />- Support custom dictionary file (`--mining-dict-word`)<br />- Find new param with DOM<br />- Use remote wordlist to mining (`--remote-wordlists`) |
|               | Built-in Grepping             | - It Identify the basic info leak of SSTi, Credential, SQL Error, and so on |
|               | WAF Detection and Evasion     | - Detect to WAF(Web Application Firewall). <br />- if found waf and using special flag, evasion using slow request<br />- `--waf-evasion` |
| Scanning      | XSS Scanning                  | - Reflected XSS / Stored XSS / DOM XSS<br />- DOM base verifying<br />- Headless base verifying<br />- Blind XSS testing with param, header(`-b` , `--blind` options)<br />- Only testing selected parameters (`-p`, `--param`)<br />- Only testing parameter analysis (`--only-discovery`) |
|               | Friendly Pipeline             | - Single url mode (`dalfox url`)<br />- From file mode (`dalfox file urls.txt`)<br />- From IO(pipeline) mode (`dalfox pipe`)<br />- From raw http request file mode (`dalfox file raw.txt --rawdata`) |
|               | Optimization query of payloads | - Check the injection point through abstraction and generated the fit payload.<br />- Eliminate unnecessary payloads based on badchar |
|               | Encoder                       | - All test payloads(built-in, your custom/blind) are tested in parallel with the encoder.<br />- To Double URL Encoder<br />- To HTML Hex Encoder |
|               | Sequence                      | - Auto-check the special page for stored xss (`--trigger`) <br />- Support (`--sequence`) options for Stored XSS , only `sxss` mode |
| HTTP          | HTTP Options                  | - Overwrite HTTP Method (`-X`, `--method`)<br />- Follow redirects (`--follow-redirects`)<br />- Add header (`-H`, `--header`)<br />- Add cookie (`-C`, `--cookie`)<br />- Add User-Agent (`--user-agent`)<br />- Set timeout (`--timeout`)<br />- Set Delay (`--delay`)<br />- Set Proxy (`--proxy`)<br />- Set ignore return codes (`--ignore-return`)<br />- Load cookie from raw request (`--cookie-from-raw`) |
| Concurrency   | Worker                        | - Set worker's number(`-w`, `--worker`)                      |
|               | N * hosts                     | - Use multicast mode (`--multicast`) , only `file` / `pipe` mode |
| Output        | Output                        | - Only the PoC code and useful information is write as Stdout<br />- Save output (`-o`, `--output`) |
|               | Format                        | - JSON / Plain (`--format`)                                  |
|               | Printing                      | - Silence mode (`--silence`)<br />- You may choose not to print the color (`--no-color`)<br />- You may choose not to print the spinner (`--no-spinner`)<br />- You may choose show only special poc code (`--only-poc`) |
|               | Report                        | - Show detail report (`--report` and `--report-format=<plain/json>`)|
| Extensibility | REST API                      | - API Server and Swagger (`dalfox server`)                   |
|               | Payload Mode                  | - Generate and Enumerate Payloads for XSS Testing (`dalfox payload`) |
|               | Found Action                  | - Lets you specify the actions to take when detected. <br />- Notify, for example (`--found-action`) |
|               | Custom Grepping               | - Can grep with custom regular expressions on response<br />- If duplicate detection, it performs deduplication (`--grep`) |
|               | Custom Payloads               | - Use custom payloads list file (`--custom-payload`) <br />- Custom alert value (`--custom-alert-value`) <br />- Custom alert type (`--custom-alert-type`)|
|               | Remote Payloads               | - Use remote payloads from portswigger, payloadbox, etc.. (`--remote-payloads`)                  |
| Package       | Package manager                | - [pkg.go.dev](https://pkg.go.dev/github.com/hahwul/dalfox/v2)<br/>- [homebrew with tap](https://github.com/hahwul/homebrew-dalfox)<br />- [snapcraft](https://snapcraft.io/dalfox)                                  |
|               | Docker ENV                    | - [docker hub](https://hub.docker.com/repository/docker/hahwul/dalfox)<br />- [github package of docker](https://github.com/hahwul/dalfox/packages)     |
|               | Other                         | - [github action](https://github.com/marketplace/actions/xss-scan-with-dalfox) |

And the various options required for the testing :D

## How to Install
### Using homebrew (macos)
```bash
brew install dalfox

# https://formulae.brew.sh/formula/dalfox
```

### Using snapcraft (ubuntu)
```
sudo snap install dalfox
```

### From source

```bash
go install github.com/hahwul/dalfox/v2@latest

# The actual release might slightly differ. This is because go install references the main branch.
```

More information? please read [Installation guide](https://dalfox.hahwul.com/docs/installation/)

## Usage
```
dalfox [mode] [target] [flags] 
```

Single target mode
```bash
dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff \
	-b https://your-callback-url
```

Multiple target mode from file
```bash
dalfox file urls_file --custom-payload ./mypayloads.txt
```

Pipeline mode
```bash
cat urls_file | dalfox pipe -H "AuthToken: bbadsfkasdfadsf87"
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
- Information: Method, grepping name, etc..

Why is there a gap?
It is a method to make it easier to parse only the poc code through cut etc. For example, you can do this.
```bash
dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff \
	| cut -d " " -f 2 > output
cat output
# http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
# http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22+class%3Ddalfox%3E
```

## In the code
```go
package main

import (
	"fmt"

	dalfox "github.com/hahwul/dalfox/v2/lib"
)

func main() {
	opt := dalfox.Options{
		Cookie:     "ABCD=1234",
	}
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     "https://xss-game.appspot.com/level1/frame",
		Method:  "GET",
		Options: opt,
	})
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
}
```

```bash
go build -o xssapp ; ./xssapp
# [] [{V GET https://xss-game.appspot.com/level1/frame?query=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprint%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E}] 2.618998247s 2021-07-11 10:59:26.508483153 +0900 KST m=+0.000794230 2021-07-11 10:59:29.127481217 +0900 KST m=+2.619792477}
```

## Screenshots
| ![1414](https://user-images.githubusercontent.com/13212227/108603497-7a390c80-73eb-11eb-92c1-b31bd9574861.jpg) | ![1415](https://user-images.githubusercontent.com/13212227/108603373-ebc48b00-73ea-11eb-9651-7ce4617845f6.jpg) |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Single URL Scanning                                          | Massive(Multicast/Mass) Scanning                             |
| ![1416](https://user-images.githubusercontent.com/13212227/108603375-ec5d2180-73ea-11eb-8e6e-d59d915c0291.jpg) | ![1417](https://user-images.githubusercontent.com/13212227/108613244-66b19400-7433-11eb-87fc-2f195f9011b3.jpg) |
| REST API Server Mode                                 | Output and Customizing (found-action / grepping)              |

## Wiki
[Wiki](https://dalfox.hahwul.com/docs/home/)

## Question
Please use [discussions](https://github.com/hahwul/dalfox/discussions) actively!

## Changelog
Detailed changes for each release are documented in the [release notes](https://github.com/hahwul/dalfox/releases).

## Contributing
DalFox's open-source project and made it with ❤️
if you want contribute this project, please see [CONTRIBUTING.md](https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](/CONTRIBUTORS.svg)](https://github.com/hahwul/dalfox/graphs/contributors)
