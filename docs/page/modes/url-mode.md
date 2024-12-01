---
title: URL Mode
redirect_from: /docs/modes/url-mode/
has_children: false
parent: Usage
nav_order: 1
toc: true
layout: page
---

# URL Mode

`url` mode is the mode for detecting XSS for a single URL.

```shell
dalfox url {TARGET-URL}
```

e.g
```shell
dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff
```
