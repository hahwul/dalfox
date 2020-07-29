<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/79072646-1cdd2500-7d1d-11ea-8a6d-d24301172a17.png" alt="" width="500px;"></a>
  <br>
  DalFox(Finder Of XSS)
  <br>
  <img src="https://img.shields.io/github/v/release/hahwul/dalfox?style=flat-square"> 
  <img src="https://img.shields.io/github/languages/top/hahwul/dalfox?style=flat-square"> <img src="https://api.codacy.com/project/badge/Grade/17cac7b8d1e849a688577f2bbdd6ecd0"> <a href="https://goreportcard.com/report/github.com/hahwul/dalfox"><img src="https://goreportcard.com/badge/github.com/hahwul/dalfox"></a> <img src="https://img.shields.io/github/issues-closed/hahwul/dalfox?style=flat-square"> 
<a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat-square"></a>
</h1>
Finder Of XSS, and Dal is the Korean pronunciation of moon.

## What is DalFox
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

## How to Install
There are a total of three ways to Personally, I recommend go install.
### Build and Install 
1) clone this repo
```
$ git clone https://github.com/hahwul/dalfox
```
2) install in cloned dalfox path
```
$ go install
```
3) using dalfox
```
$ ~/go/bin/dalfox
```

### Download release version
1) Open latest release page
https://github.com/hahwul/dalfox/releases/latest

2) Download file 
Download and extract the file that fits your OS.

3) You can put it in the execution directory and use it.
e.g 
```
$ cp dalfox /usr/bin/
```

### Installation Docker
Pull and run
```
$ docker pull hahwul/dalfox:latest
$ docker run -it hahwul/dalfox:latest /bin/bash
$ dalfox
```

run dalfox on docker
```
docker run -it hahwul/dalfox:latest dalfox url https://www.hahwul.com
```

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
  sxss        Use Stored XSS mode
  update      Update DalFox (Binary patch)
  url         Use single target mode
  version     Show version

Flags:
  -b, --blind string            Add your blind xss (e.g -b hahwul.xss.ht)
      --config string           Using config from file
  -C, --cookie string           Add custom cookie
      --custom-payload string   Add custom payloads from file
  -d, --data string             Using POST Method and add Body data
      --delay int               Milliseconds between send to same host (1000==1s)
      --found-action string     If found weak/vuln, action(cmd) to next
      --grep string             Using custom grepping file (e.g --grep ./samples/sample_grep.json)
  -H, --header string           Add custom headers
  -h, --help                    help for dalfox
      --ignore-return string    Ignore scanning from return code (e.g --ignore-return 302,403,404)
      --only-discovery          Only testing parameter analysis
  -o, --output string           Write to output file
      --output-format string    -o/--output 's format (txt/json/xml)
  -p, --param string            Only testing selected parameters
      --proxy string            Send all request to proxy server (e.g --proxy http://127.0.0.1:8080)
      --silence                 Not printing all logs
      --timeout int             Second of timeout (default 10)
      --user-agent string       Add custom UserAgent
  -w, --worker int              Number of worker (default 40)
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


## ScreenShot
![1414](https://user-images.githubusercontent.com/13212227/80303671-97fa0d00-87ec-11ea-814c-96d623f842ec.png)
![1415](https://user-images.githubusercontent.com/13212227/80303674-9cbec100-87ec-11ea-8307-1eae2749a203.png)
