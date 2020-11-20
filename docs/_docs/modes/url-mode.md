---
title: URL Mode
permalink: /docs/modes/url-mode/
---

`url` mode is the mode for detecting XSS for a single URL.

```shell
$ dalfox url {TARGET-URL}
```

e.g
```shell
$ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff
```
