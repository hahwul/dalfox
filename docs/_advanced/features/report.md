---
title: Report
redirect_from: /docs/report/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Report

Dalfox provides a reporting feature that allows you to generate detailed reports of your scans. You can generate reports in different formats such as plain text and JSON.

## Generating a Report

To generate a report, use the `--report` option with the `dalfox` command. Here is an example:

```shell
dalfox url https://xss-game.appspot.com/level1/frame --report
```

This command will generate a report in the default format (plain text).

![Plain Text Report](https://user-images.githubusercontent.com/13212227/190555379-a4b06b07-0ae0-4f9a-859a-650ac34186ae.png)

## Generating a JSON Report

If you prefer to generate a report in JSON format, use the `--report-format` option with the value `json`:

```shell
dalfox url https://xss-game.appspot.com/level1/frame --report --report-format json
```

This command will generate a report in JSON format.

![JSON Report](https://user-images.githubusercontent.com/13212227/190555382-cb7e37b9-b4c9-4c99-b853-ff65a1df9e01.png)
