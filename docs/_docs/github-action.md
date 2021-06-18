---
title: In the Github Action
permalink: /docs/gitaction/
---

## Github Marketplace
* [https://github.com/marketplace/actions/xss-scan-with-dalfox](https://github.com/marketplace/actions/xss-scan-with-dalfox)
* [https://github.com/hahwul/action-dalfox](https://github.com/hahwul/action-dalfox)

## Getting Started
### Usage
```yaml
- name: Dalfox scan
  uses: hahwul/action-dalfox@main
  id: xss-result
  with:
    target: 'https://www.hahwul.com'
    mode: url
    cmd_options: '--follow-redirects'
```
- Modes: `url` `pipe` `file` `sxss`
- Options: https://github.com/hahwul/dalfox#usage

### Output Handling
Send slack/github issue/Submit JIRA, etc.. with found-action option
```yaml
- name: Dalfox scan
  uses: hahwul/action-dalfox@main
  id: xss-result
  with:
    target: 'https://www.hahwul.com'
    mode: url
    cmd_options: '--found-action "curl -i -k"https://hooks.your.system"'
  - run: echo "XSS result - ${{ steps.xss-result.outputs.result }}"
```
- Found-Action: https://github.com/hahwul/dalfox/wiki/Found-action

## Sample
### Single URL Scanning
xss.yaml
```yaml
on: [push]

jobs:
  dalfox_scan:
    runs-on: ubuntu-latest
    name: XSS Scanning
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          ref: master
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-result
        with:
          target: 'https://xss-game.appspot.com/level1/frame'
          mode: url
          cmd_options: '--follow-redirects'
```

### Multi URL Scanning
xss.yaml
```yaml
on: [push]

jobs:
  dalfox_scan:
    runs-on: ubuntu-latest
    name: XSS Scanning
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          ref: master
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-result
        with:
          target: 'https://xss-game.appspot.com/level1/frame\nhttps://www.hahwul.com?q=1234'
          mode: pipe
```
