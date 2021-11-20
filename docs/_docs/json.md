---
title: Result JSON Format
permalink: /docs/json/
---

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
      "cwe":"CWE ID"
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
| payload     | Paramter value              | - Attack code in value                                       |
| evidence    | Evidence with repsonse body | - Simple codeview of where it's injected in response body.   |
| cwe         | CWE ID                      | - Mapping CWE ID                                             |

```json
{
      "type":"V",
      "inject_type":"inHTML-URL",
      "poc_type":"",
      "method":"GET",
      "data":"http://testphp.vulnweb.com/listproducts.php?artist=123%27%22%3E%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dalert%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E",
      "param":"artist",
      "payload":"'\"\u003e\u003ciframe srcdoc=\"\u003cinput onauxclick=alert(1)\u003e\" class=dalfox\u003e\u003c/iframe\u003e",
      "evidence":"48 line:  syntax to use near ''\"\u003e\u003ciframe srcdoc=\"\u003cinput onauxclick=alert(1)\u003e\" class=dalfox",
      "cwe":"CWE-79"
   }
```
