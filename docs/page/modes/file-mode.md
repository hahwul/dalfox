---
title: File Mode
redirect_from: /docs/modes/file-mode/
has_children: false
parent: Usage
nav_order: 3
toc: true
layout: page
---

# File mode

`file` mode is a mode for scanning multiple URLs or for scanning based on a raw request file in Burp Suite/ZAP. Input is filename.

```shell
dalfox file {filename}
```

If the file is a list of URLs, proceed to scan multiple URLs just like the Pipe, and if it is with the `--rawdata` option, recognize it as a raw request, analyze the file, and test it.

## scanning urls from file
```shell
dalfox file urls.txt
```

## scanning from burp/zap raw request file
```shell
dalfox file req.raw --rawdata
```
