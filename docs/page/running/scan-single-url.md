---
title: Single URL
redirect_from: /docs/scan-single-url/
parent: Running
nav_order: 1
toc: true
layout: page
---

# Scanning a Single URL with Dalfox

This guide provides detailed instructions on how to scan a single URL using Dalfox. Follow the steps below to perform a scan on a single target URL.

## Command

To scan a single URL, use the following command:

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php
```

## Output

Here is an example of the output you can expect from running the above command:

```
Parameter Analysis and XSS Scanning tool based on golang
Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul
[*] Using single target mode
[*] Target URL: http://testphp.vulnweb.com/listproducts.php
[*] Vaild target [ code:200 / size:4819 ]
[*] Using dictionary mining option [list=GF-Patterns] 📚⛏
[*] Using DOM mining option 📦⛏
[*] Start BAV(Basic Another Vulnerability) analysis / [sqli, ssti, OpenRedirect]  🔍
[*] Start static analysis.. 🔍
[*] BAV analysis done ✓
[*] Start parameter analysis.. 🔍
[I] Found 2 testing point in DOM Mining
[G] Found dalfox-error-mysql2 via built-in grepping / original request
    Warning: mysql
[POC][G][BUILT-IN/dalfox-error-mysql2/GET] http://testphp.vulnweb.com/listproducts.php
[G] Found dalfox-error-mysql via built-in grepping / original request
    Warning: mysql_fetch_array() expects parameter 1 to be resource, null given in /hj/var/www/listproducts.php on line 74
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
[*] Static analysis done ✓
[G] Found dalfox-error-mysql1 via built-in grepping / payload: dalfox>
    SQL syntax; check the manual that corresponds to your MySQL
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox%3E
[G] Found dalfox-error-mysql5 via built-in grepping / payload: dalfox>
    check the manual that corresponds to your MySQL server version
[POC][G][BUILT-IN/dalfox-error-mysql5/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox%3E
[*] Parameter analysis  done ✓
[I] Content-Type is text/html; charset=UTF-8
[I] Reflected cat param => Injected: /inHTML-none(1)  ▶
    48 line:  	Error: Unknown column 'Dalfox' in 'where cl
[*] Generate XSS payload and optimization.Optimization.. 🛠
[*] Start XSS Scanning.. with 201 queries 🗡
[V] Triggered XSS Payload (found DOM Object): cat=<dalfox class=dalfox>
    48 line:  yntax to use near '=<dalfox class=dalfox>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3Cdalfox+class%3Ddalfox%3E
[*] Finish :D
```

## Explanation of Output

- **Target URL**: The URL being scanned.
- **Valid target**: Indicates that the target URL is valid and accessible.
- **Dictionary mining option**: Uses predefined patterns to find vulnerabilities.
- **DOM mining option**: Analyzes the Document Object Model (DOM) for vulnerabilities.
- **BAV analysis**: Basic Another Vulnerability analysis, including SQL injection, SSTI, and Open Redirect.
- **Static analysis**: Analyzes the static content of the target.
- **Parameter analysis**: Analyzes the parameters of the target URL.
- **Generate XSS payload and optimization**: Generates and optimizes XSS payloads for scanning.
- **Triggered XSS Payload**: Indicates that an XSS payload was successfully triggered.
