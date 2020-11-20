---
title: Stored XSS Mode
permalink: /docs/modes/sxss-mode/
---
`sxss` mode is a mode for easy identification of Stored XSS. The default behavior is the same as url mode, but you can specify a separate URL to validate, and you can generate a dynamic verification URL with the --sequence option in case the verification URL changes.
```
$ dalfox sxss {TARGET-URL} --trigger {VERIFY_URL}
```

e.g
```
$ dalfox sxss https://test.url.local/update_profile -d "nickname=abc" --trigger "https://test.url.local/my_profile"
```
