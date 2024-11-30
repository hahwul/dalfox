---
title: In the Github Action
redirect_from: /docs/gitaction/
parent: Running
nav_order: 5
toc: true
layout: page
---

# Using Dalfox in GitHub Actions

This guide provides detailed instructions on how to use Dalfox in GitHub Actions for automated XSS scanning. Follow the steps below to integrate Dalfox into your CI/CD pipeline.

## GitHub Marketplace
Dalfox GitHub Actions are available on the GitHub Marketplace:
* [XSS Scan with Dalfox](https://github.com/marketplace/actions/xss-scan-with-dalfox)
* [hahwul/action-dalfox](https://github.com/hahwul/action-dalfox)

## Getting Started

### Basic Usage
To use Dalfox in your GitHub Actions workflow, add the following step to your workflow YAML file:

```yaml
- name: Dalfox scan
  uses: hahwul/action-dalfox@main
  id: xss-result
  with:
    target: 'https://www.hahwul.com'
    mode: url
    cmd_options: '--follow-redirects'
```

### Parameters
- **Modes**: `url`, `pipe`, `file`, `sxss`
- **Options**: For a full list of command options, refer to the [Dalfox usage documentation](https://github.com/hahwul/dalfox#usage).

### Output Handling
You can handle the output of Dalfox by sending it to Slack, creating a GitHub issue, submitting to JIRA, etc., using the `--found-action` option.

```yaml
- name: Dalfox scan
  uses: hahwul/action-dalfox@main
  id: xss-result
  with:
    target: 'https://www.hahwul.com'
    mode: url
    cmd_options: '--found-action "curl -i -k https://hooks.your.system"'
- run: echo "XSS result - ${{ steps.xss-result.outputs.result }}"
```

For more details on the `--found-action` option, refer to the [Dalfox Found-action documentation](https://github.com/hahwul/dalfox/wiki/Found-action).

## Sample Workflows

### Single URL Scanning
Create a file named `xss.yaml` in your `.github/workflows` directory with the following content:

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
For scanning multiple URLs, update the `xss.yaml` file as follows:

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
          target: |
            https://xss-game.appspot.com/level1/frame
            https://www.hahwul.com?q=1234
          mode: pipe
```
