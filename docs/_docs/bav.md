---
title: BAV
permalink: /docs/bav/
---

## What is BAV
BAV(Basic Another Vulnerability) is test to other vulnerability in xss scanning. And the default value is true.

* SQL Injection
* SSTI
* Open Redirect
* CRLF Injection

## Disable BAV
If you don't want to scan BAV, you can disable BAV with the option below.

```
$ dalfox url https://google.com --skip-bav
```

## Output format
```
[*] 🦊 Start scan [SID:Single] / URL: http://localhost:8070/xss/abcd/2
[G] Found CRLF Injection via built-in grepping / original request
[POC][G][CRLF/GET] http://localhost:8070/xss/abcd/2
[I] Found 0 testing point in DOM base parameter mining
[I] Content-Type is text/html; charset=UTF-8is 🔍
[I] Reflected PATH '/xss/dalfoxpathtest/2' => Injected: /inJS-single(1)]
[V] Triggered XSS Payload (found dialog in headless)aiting headless
[POC][V][GET] http://localhost:8070/xss/abcd'-confirm(1)-'/2?=
```
