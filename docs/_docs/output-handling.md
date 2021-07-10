---
title: Output Handling
permalink: /docs/output-handling/
---

## Use dalfox output to other tools via Pipeline
Command
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php | grep "\[V\]" | cut -d " " -f2 | xargs -I % open %
```

## Save only PoC code with Stdout
Command
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php > output
```

Output file
```
▶ cat output
[POC][G][BUILT-IN/dalfox-error-mysql2/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql5/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CsCriPt+class%3Ddalfox%3Eprompt%2845%29%3C%2Fscript%3E
```

## Save only PoC code with `-o` flag
Command
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php -o output
```

Output file
```
▶ cat output
[POC][G][BUILT-IN/dalfox-error-mysql2/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
[POC][G][BUILT-IN/dalfox-error-mysql5/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox.
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CsCriPt+class%3Ddalfox%3Eprompt%2845%29%3C%2Fscript%3E
```

## Save all log (with `--output-all` flag)

Command
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php -o alllog.txt --output-all
```

Output file
```
▶ cat alllog.txt
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

## Save only special PoC Code
Supported
* g(`grep`)
* r(`reflected`)
* v(`verified`)

Case
* g: `[POC][G][BUILT-IN/dalfox-error-mysql1/GET] http://testphp.vulnweb.com/listproducts.php?cat=dalfox%2C`
* r: `[POC][R][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CdETAILS%250aopen%250aonToGgle%250a%3D%250aa%3Dprompt%2Ca%28%29%3E`
* v: `[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?cat=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E`

Command (only grep and verified poc)
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php --only-poc=g,v
```
