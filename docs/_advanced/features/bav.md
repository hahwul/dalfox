---
title: BAV
redirect_from: /docs/bav/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Basic Another Vulnerability (BAV)

BAV (Basic Another Vulnerability) is a feature in Dalfox that tests for additional vulnerabilities during XSS scanning. By default, BAV is enabled.

## Vulnerabilities Tested by BAV

BAV tests for the following vulnerabilities:

- **SQL Injection**
- **Server-Side Template Injection (SSTI)**
- **Open Redirect**
- **CRLF Injection**

## Disabling BAV

If you do not want to scan for BAV, you can disable it using the `--skip-bav` option.

### Command

```bash
dalfox url https://google.com --skip-bav
```

## Output Format

Here is an example of the output you can expect when BAV is enabled:

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
