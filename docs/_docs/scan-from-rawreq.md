---
title: Scanning From Raw Request
permalink: /docs/scan-from-rawreq/
---

`sample_rawdata.txt`
```
POST https://www.hahwul.com/?q=xspear HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3
Connection: keep-alive
Cookie: _ga=GA1.2.1102548207.1555467144; _gid=GA1.2.1362788908.1563875038
Upgrade-Insecure-Requests: 1
Host: www.hahwul.com

asdf=asdf
```

Command
```
$ dalfox file --rawdata ./samples/sample_rawdata.txt
```
Output
```
[*] Using file mode(rawdata)
[*] Target URL: https://www.hahwul.com/?q=xspear
[*] Vaild target [ code:405 / size:131 ]
[*] Using dictionary mining option [list=GF-Patterns] 📚⛏
[*] Using DOM mining option 📦⛏
[*] Start BAV(Basic Another Vulnerability) analysis / [sqli, ssti, OpenRedirect]  🔍
[*] Start parameter analysis.. 🔍
[*] Start static analysis.. 🔍
[I] Found 0 testing point in DOM Mining
[*] Static analysis done ✓
[*] BAV analysis done ✓
[*] Parameter analysis  done ✓
[*] Generate XSS payload and optimization.Optimization.. 🛠
[*] Start XSS Scanning.. with 33 queries 🗡
[*] Finish :D
```
