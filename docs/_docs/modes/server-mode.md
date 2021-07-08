---
title: Server Mode (REST API)
permalink: /docs/modes/server-mode/
---
`server` mode is a REST API mode that takes into account scalability. Using this mode, dalfox acts as a REST API server and can perform scanning using a web request.
```
▶ dalfox server
```

e.g
```
▶ dalfox server --host 0.0.0.0 --port 8090
    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''

Parameter Analysis and XSS Scanning tool based on golang
Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul

 🎯  Target                 REST API Mode
 🧲  Listen Address         0.0.0.0:8090
 🏁  Method                 GET
 🖥  Worker                 100
 🔦  BAV                    true
 ⛏  Mining                 true (Gf-Patterns)
 🔬  Mining-DOM             true (mining from DOM)
 ⏱  Timeout                10
 📤  FollowRedirect         false
 🕰  Started at             2021-07-08 18:10:15.214339875 +0900 KST m=+0.027712246


```

and supported swagger-ui
![](https://user-images.githubusercontent.com/13212227/89736705-5002ab80-daa6-11ea-9ee8-d2def396c25a.png)

## Basic scanning
req
```
▶ curl -X POST "http://localhost:6664/scan" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"url\": \"https://www.hahwul.com\"}"
```
res
```
{"code":200,"msg":"28846e5b355577ecd60766f45735c4c687e8c1c200db65700e3f458b73234984","data":null}
```

## Scanning with options
req
```
▶ curl -X POST "http://localhost:6664/scan" \
-H "accept: application/json" \
-H "Content-Type: application/json" \
-d "{\"url\": \"https://www.hahwul.com\", \"options\":{\"cookie\":\"testz=11\",\"worker\":1}}"
```
res
```
{"code":200,"msg":"0462c53f75a528d263787af314f90e58016d693554216b9a4e34b50ad92da9ba","data":null}
```

### Options lists
The options values are approximately the same as the cli option by default.

* https://github.com/hahwul/dalfox/blob/master/pkg/model/options.go

```json
{
  "url":"target",
  "options": {
    "param":"only testing this parameter",
    "cookie": "auth=1234",
    "header": "API-Key: abcd",
    "config": "",
    "blind": "your.xss.ht",
    "data": "param=1234",
    "user-agent": "ChromeTestUA",
    "output": "output file",
    "format": "json",
    "found-action": "echo 1",
    "proxy": "http://127.0.0.1:8080",
    "grep": "TESTTOKEN",
    "ignore-return": "500",
    "trigger": "/trigger_url_using_sxss_mode",
    "timeout": 5,
    "worker": 30,
    "delay": 1,
    "sequence": 1,
    "only-discovery": false,
    "only-custom-payload": false,
    "silence": false,
    "mass": false,
    "follow-redirects": false,
    "mining-dict": true,
    "mining-dom": false,
    "mining-dict-word": "file_name",
    "no-color": false,
    "method": "GET",
    "no-spinner": false,
    "no-bav": false,
    "skip-grepping": false,
    "debug": false,
  }
}
```


## Swagger-ui
Swagger ui is available in the dalfox.
```
http://your-host:your-port/swagger/index.html
```
e.g `http://localhost:6664/swagger/index.html`
