<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/79072646-1cdd2500-7d1d-11ea-8a6d-d24301172a17.png" alt="" width="500px;"></a>
  <br>
  DalFox(Find Of XSS)
  <br>
  <img src="https://img.shields.io/github/languages/top/hahwul/dalfox?style=flat-square"> <img src="https://api.codacy.com/project/badge/Grade/17cac7b8d1e849a688577f2bbdd6ecd0"> <img src="https://img.shields.io/github/issues-closed/hahwul/dalfox?style=flat-square"> 
<a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat-square"></a>
</h1>
Find Of XSS, and Dal is the Korean pronunciation of moon.

## What is DalFox
Just, XSS Scanning and Parameter Analysis tool. I previously developed [XSpear](https://github.com/hahwul/XSpear), a ruby-based XSS tool, and this time, a full change occurred during the process of porting with golang!!! and created it as a new project. The basic concept is to analyze parameters, find XSS, and examine them based on Selenium.

I talk about naming. Dal(달) is the Korean pronunciation of moon and fox was made into Fox(Find Of XSS).

## Key features

- Paramter Analysis (find reflected parameter, find free/bad characters, Identification of injection point)
- Static Analysis (Check Bad-header like CSP, X-Frame-optiopns, etc.. with base request/response base)
- Optimization query of payloads
- XSS Scanning and DOM Base Verifying
- Support Pipeline 
  - Scanning from IO
  - Scanning from Raw file(Burp suite, ZAP Request)

## How to Install
```
$ go get -u github.com/hahwul/dalfox
```

## Usage
```
    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''
Parameter Analysis and XSS Scanning tool based on golang
Find Of XSS and Dal is the Korean pronunciation of moon. @hahwul


Usage of dalfox:
  -blind string
    	Add blind XSS payload, e.g -blind https://hahwul.xss.ht
  -config string
    	config file path
  -cookie string
    	Add custom cookies
  -data string
    	POST data
  -header string
    	Add custom headers
  -help
    	Show help message
  -iL string
    	target urls(file)
  -only-discovery
    	Use only discovery mode
  -p string
    	Testing only selected parameter
  -pipe
    	Pipeline mode (default is false)
  -ua string
    	Add custom User-Agent
  -url string
    	target url
```

## ScreenShot
![1414](https://user-images.githubusercontent.com/13212227/79770664-b08ba280-8368-11ea-8a45-669e1e29baa8.png)
![1415](https://user-images.githubusercontent.com/13212227/79770982-1b3cde00-8369-11ea-8e28-ee410192aea7.png)
