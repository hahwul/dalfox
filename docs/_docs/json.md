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
| payload     | Paramter value              | - Attack code in value                                       |
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
