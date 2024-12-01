---
title: Pipeline Mode
redirect_from: /docs/modes/pipe-mode/
has_children: false
parent: Usage
nav_order: 2
toc: true
layout: page
---

# Pipeline Mode

`pipe` mode is the mode for scanning multiple URLs. I receive input as system I/O, so you can connect with other tools through pipeline.
```shell
dalfox pipe
```

e.g
```shell
echo urls.txt | dalfox pipe
```
