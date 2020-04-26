<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/79072646-1cdd2500-7d1d-11ea-8a6d-d24301172a17.png" alt="" width="500px;"></a>
  <br>
  DalFox(Finder Of XSS)
  <br>
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
- XSS Scanning and DOM Base Verifying
- All test payloads(build-in, your custom/blind) are tested in parallel with the encoder.
  - Support to Double URL Encoder
  - Support to HTML Hex Encoder
- Useful for Pipeline 
  - Scanning from single url
  - Scanning from IO
  - Scanning from URLs list file
- And the various options required for the testing :D

## How to Install
```
$ go get -u github.com/hahwul/dalfox
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
  file        Use multiple targets mode from file
  help        Help about any command
  pipe        Use pipeline mode
  url         Use single target mode

Flags:
  -b, --blind string            Add your blind xss
      --config string           Using config from file
  -C, --cookie string           Add custom cookie
      --custom-payload string   Add custom payloads from file
  -d, --data string             Using POST Method and add Body data
  -H, --header string           Add custom headers
  -h, --help                    help for dalfox
      --only-discovery          Only testing parameter analysis
  -o, --output string           Write to output file
      --output-format string    -o/--output 's format (txt/json/xml)
  -p, --param string            Only testing selected parameters
      --user-agent string       Add custom UserAgent
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
![1414](https://user-images.githubusercontent.com/13212227/79870656-403f5880-841e-11ea-9fef-0e47be5dc3ee.png)
![1415](https://user-images.githubusercontent.com/13212227/79870669-46cdd000-841e-11ea-919e-a2020997c3f8.png)
