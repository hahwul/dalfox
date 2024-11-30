---
title: Output Handling
redirect_from: /docs/output-handling/
nav_order: 5
toc: true
layout: page
---

# Output Handling

This guide provides detailed instructions on how to handle the output from Dalfox. You can use various methods to save, filter, and process the output according to your needs.

## Use Dalfox Output to Other Tools via Pipeline
You can pipe the output of Dalfox to other tools for further processing. For example, you can use `grep` to filter the output and `xargs` to open URLs in a browser.

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php | grep "\[V\]" | cut -d " " -f2 | xargs -I % open %
```

## Save Only PoC Code with Stdout
You can save the Proof of Concept (PoC) code directly to a file using standard output redirection.

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php > output
```

### Output File Example
```bash
# cat output
[POC][G][BUILT-IN/dalfox-error-mysql2/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql5/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CsCriPt+class%3Ddalfox%3Eprompt%2845%29%3C%2Fscript%3E
```

## Save Only PoC Code with `-o` Flag
You can also use the `-o` flag to save the PoC code to a file.

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php -o output
```

### Output File Example
```bash
# cat output
[POC][G][BUILT-IN/dalfox-error-mysql2/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql5/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CsCriPt+class%3Ddalfox%3Eprompt%2845%29%3C%2Fscript%3E
```

## Save All Logs with `--output-all` Flag
To save all logs, including detailed analysis information, use the `--output-all` flag.

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php -o alllog.txt --output-all
```

### Output File Example
```bash
# cat alllog.txt
[*] Using single target mode
[*] Target URL: http://testphp.vulnweb.com/listproducts.php
[*] Vaild target [ code:200 / size:4819 ]
[*] Using dictionary mining option [list=GF-Patterns] 📚⛏
[*] Using DOM mining option 📦⛏
[*] Start static analysis.. 🔍
[*] Start parameter analysis.. 🔍
[*] Start BAV(Basic Another Vulnerability) analysis / [sqli, ssti, OpenRedirect]  🔍
...snip...
```

## Save Only Special PoC Code
You can filter and save only specific types of PoC code using the `--only-poc` flag. Supported types are:
* `g` (grep)
* `r` (reflected)
* `v` (verified)

### Command Example
To save only grep and verified PoC code:
```bash
dalfox url http://testphp.vulnweb.com/listproducts.php --only-poc=g,v
```

## Save Traffic in HAR File
You can save the HTTP traffic in a HAR (HTTP Archive) file for further analysis.

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php --har-file-path=log.har
```

### HAR File Example
The HAR file can be opened with tools like [HAR Viewer](http://www.softwareishard.com/har/viewer/) for detailed inspection of the HTTP requests and responses.
