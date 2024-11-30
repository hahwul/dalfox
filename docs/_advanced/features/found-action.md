---
title: Found Action
redirect_from: /docs/tips/found-action/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Integration with found-action

The `--found-action` option in Dalfox allows you to specify actions to take when a vulnerability is detected. This can be useful for automating responses to findings, such as logging, alerting, or further processing.

## Using found-action

The `--found-action` option lets you define a command to execute when a vulnerability is found. The following placeholders can be used within the command:

| Placeholder  | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `@@query@@`  | The attack query (e.g., `https://www.hahwul.com?q="><script~~blahblah`) |
| `@@target@@` | The target site (e.g., `https://www.hahwul.com`)             |
| `@@type@@`   | The type of proof of concept (POC) (values: `WEAK` / `VULN`) |

### Example Command

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff --found-action "echo '@@query@@' > data"
```

### Example Output

```bash
cat data
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%2845%29%3E
```

## Modifying the Shell Application for found-action

The `--found-action-shell` flag allows you to change the shell application used for executing the found action. The default value is `bash`.

### Example Command with zsh

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff --found-action "echo '@@query@@' > data" --found-action-shell=zsh
```

### Example Command with sh (for Alpine Linux)

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff --found-action "echo '@@query@@' > data" --found-action-shell=sh
```

## Additional Resources

For more information and advanced usage, please refer to the [blog post on Dalfox's fun options](https://www.hahwul.com/2020/05/04/how-to-use-dalfoxs-fun-options/).