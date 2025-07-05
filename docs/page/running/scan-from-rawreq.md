---
title: From Raw Request
redirect_from: /docs/scan-from-rawreq/
parent: Running
nav_order: 3
toc: true
layout: page
---

# Scanning from Raw Request with Dalfox

This guide provides detailed instructions on how to scan a target using a raw HTTP request with Dalfox. Follow the steps below to perform a scan using a raw request.

## Using `file` mode

### Sample Raw Request

Create a file named `sample_rawdata.txt` with the following content:

```http
POST https://www.hahwul.com/?q=dalfox HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3
Connection: keep-alive
Cookie: _ga=GA1.2.1102548207.1555467144; _gid=GA1.2.1362788908.1563875038
Upgrade-Insecure-Requests: 1
Host: www.hahwul.com

asdf=asdf
```

### Command

To scan using the raw request from a file, use the following command:

```bash
dalfox file ./samples/sample_rawdata.txt --rawdata
```

## Using `pipe` mode

You can also provide the raw request via stdin using the `pipe` command.

### Command

```bash
cat ./samples/sample_rawdata.txt | dalfox pipe --rawdata
```

Or for base64 encoded requests:

```bash
cat ./samples/sample_rawdata.txt | base64 | dalfox pipe --rawdata
```

Dalfox will automatically detect if the piped input is base64 encoded and decode it before parsing.

## Output

Here is an example of the output you can expect from running the above command:

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
[*] Generate XSS payload and optimization.. 🛠
[*] Start XSS Scanning.. with 33 queries 🗡
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
