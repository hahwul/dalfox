---
title: Stored XSS Mode
redirect_from: /docs/modes/sxss-mode/
has_children: false
parent: Usage
nav_order: 4
toc: true
layout: page
---

# Stored XSS Mode

`sxss` mode is a mode for easy identification of Stored XSS. The default behavior is the same as url mode, but you can specify a separate URL to validate, and you can generate a dynamic verification URL with the --sequence option in case the verification URL changes.

```bash
dalfox sxss {TARGET-URL} --trigger {VERIFY_URL}
```

e.g
```bash
dalfox sxss https://test.url.local/update_profile -d "nickname=abc" --trigger "https://test.url.local/my_profile"
```

send POST request to Store the XSS payload and verify it working of the payload with an GET request
```bash
dalfox sxss -X POST https://test.url.local/update_profile -d "nickname=abc" --trigger "https://test.url.local/my_profile" --reqeust-method GET
```

