---
title: Result JSON Format
permalink: /docs/json/
---

## Scan Result
```json
{
 "logs": null,
 "pocs": [
  {
   "type": "R",
   "inject_type": "inHTML-none(1)-URL",
   "poc_type": "plain",
   "method": "GET",
   "data": "https://xss-game.appspot.com/level1/frame?query=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprint%281%29%3E",
   "param": "query",
   "payload": "\u003cxmp\u003e\u003cp title=\"\u003c/xmp\u003e\u003csvg/onload=print(1)\u003e",
   "evidence": "13 line:  s were found for \u003cb\u003e\u003cxmp\u003e\u003cp title=\"\u003c/xmp\u003e\u003csvg/onload=print(1)\u003e\u003c/b\u003e. \u003ca href='?'\u003e",
   "cwe": "CWE-79",
   "severity": "Medium"
  },
  {
   "type": "V",
   "inject_type": "inHTML-none(1)-URL",
   "poc_type": "plain",
   "method": "GET",
   "data": "https://xss-game.appspot.com/level1/frame?query=%3CdETAILS%250aopen%250aonToGgle%250a%3D%250aa%3Dprompt%2Ca%28%29+class%3Ddalfox%3E",
   "param": "query",
   "payload": "\u003cdETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox\u003e",
   "evidence": "13 line:  s were found for \u003cb\u003e\u003cdETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox\u003e\u003c",
   "cwe": "CWE-79",
   "severity": "High"
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
    "\u003e",
    "-",
    "\u003c",
    "\"",
    "[",
    ",",
    "\\",
    "]",
    "(",
    "$",
    ":",
    ";",
    "{",
    "`",
    "'",
    "}",
    ")",
    "+",
    "=",
    "|",
    "."
   ]
  }
 ],
 "duration": 6254560167,
 "start_time": "2022-09-16T13:24:02.693407+09:00",
 "end_time": "2022-09-16T13:24:08.947901+09:00"
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
      "param":"Parmeter",
      "payload":"Attack Value",
      "evidence":"Evidence with response body",
      "cwe":"CWE ID",
      "severity": "Severity (Low/Medium/High)"
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
| payload     | Parameter value              | - Attack code in value                                       |
| evidence    | Evidence with repsonse body | - Simple codeview of where it's injected in response body.   |
| cwe         | CWE ID                      | - Mapping CWE ID                                             |
| severity    | Severity                    | - Severity (Low/Medium/High)                                 |

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
