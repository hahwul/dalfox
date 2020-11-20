---
title: Using found-action
permalink: /docs/tips/found-action/
---

Found action(`--found-action`) is lets you specify the actions to take when detected.

|              | description                                                  |
| ------------ | ------------------------------------------------------------ |
| `@@query@@`  | - attack query<br />- e.g https://www.hahwul.com?q="><script~~blahblah |
| `@@target@@` | - target site<br />- e.g https://www.hahwul.com              |
| `@@type@@`   | - type of poc<br />- value:  `WEAK` / `VULN`                 |


```
$ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff --found-action "echo '@@query@@' > data"
```

```
$ cat data
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%2845%29%3E
```

## Reference
https://www.hahwul.com/2020/05/04/how-to-use-dalfoxs-fun-options/
