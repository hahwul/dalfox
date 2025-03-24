---
title: In the GitHub Actions
redirect_from: /docs/gitaction/
parent: Running
nav_order: 5
toc: true
layout: page
---

# Using Dalfox in GitHub Actions

## Overview

GitHub Actions enables you to automate your security testing processes directly in your GitHub repositories. By integrating Dalfox with GitHub Actions, you can:

- Automatically scan for XSS vulnerabilities when code is pushed
- Include security testing in your pull request workflows
- Create scheduled security scans of your web applications
- Generate reports on security findings as part of your CI/CD pipeline

This guide explains how to set up and use Dalfox in GitHub Actions workflows for various scanning scenarios.

## Available Actions

Dalfox offers official GitHub Actions in the GitHub Marketplace:

* [XSS Scan with Dalfox](https://github.com/marketplace/actions/xss-scan-with-dalfox)
* [hahwul/action-dalfox](https://github.com/hahwul/action-dalfox)

## Getting Started

### Basic Usage

To integrate Dalfox in your GitHub Actions workflow, add a step similar to the following to your workflow file:

```yaml
- name: Dalfox XSS Scan
  uses: hahwul/action-dalfox@main
  id: xss-scan
  with:
    target: 'https://example.com/search?q=test'
    mode: url
    cmd_options: '--follow-redirects --format json'
```

This basic example will scan the specified URL for XSS vulnerabilities using Dalfox.

### Input Parameters

The Dalfox GitHub Action accepts the following inputs:

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `target` | The target URL or URLs to scan | Yes | - |
| `mode` | Scan mode (url, pipe, file, sxss) | Yes | - |
| `cmd_options` | Additional Dalfox command options | No | '' |

### Scan Modes

Dalfox supports several scanning modes in GitHub Actions:

- `url`: Scan a single URL
- `pipe`: Scan multiple URLs provided in the target parameter
- `file`: Scan URLs from a file (requires checkout of your repository)
- `sxss`: Test for stored XSS vulnerabilities

### Output Handling

The action provides the scan results in the `result` output variable:

```yaml
- name: Dalfox XSS Scan
  uses: hahwul/action-dalfox@main
  id: xss-scan
  with:
    target: 'https://example.com/search?q=test'
    mode: url

- name: Display Results
  run: echo "Scan results - ${{ steps.xss-scan.outputs.result }}"
```

## Workflow Examples

### On-demand Single URL Scan

This workflow runs a Dalfox scan when manually triggered:

```yaml
name: XSS Security Scan

on:
  workflow_dispatch:
    inputs:
      url:
        description: 'URL to scan'
        required: true
        default: 'https://example.com'

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: ${{ github.event.inputs.url }}
          mode: url
          cmd_options: '--follow-redirects --format json --report'
      
      - name: Display Results
        run: echo "${{ steps.xss-scan.outputs.result }}"
```

### Scheduled Multi-URL Scan

This workflow runs daily to scan multiple URLs:

```yaml
name: Daily XSS Scans

on:
  schedule:
    - cron: '0 0 * * *'  # Run at midnight every day

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: |
            https://example.com/search?q=test
            https://example.com/products?id=123
            https://example.com/news?article=latest
          mode: pipe
          cmd_options: '--follow-redirects --format json --report --output scan-results.json'
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: xss-scan-results
          path: scan-results.json
          retention-days: 30
```

### Pull Request Security Check

This workflow scans the web application whenever a pull request is opened or updated:

```yaml
name: Pull Request XSS Check

on:
  pull_request:
    branches: [ main ]
    paths:
      - 'frontend/**'
      - 'web/**'

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Set up test environment
        run: |
          # Set up your application for testing
          # E.g., npm install && npm start
          echo "Starting application on http://localhost:3000"
      
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: 'http://localhost:3000'
          mode: url
          cmd_options: '--follow-redirects --deep-domxss --format json'
      
      - name: Check for vulnerabilities
        run: |
          if [[ "${{ steps.xss-scan.outputs.result }}" == *"[POC]"* ]]; then
            echo "::warning::XSS vulnerabilities were found! Check the scan results."
            exit 1
          fi
```

## Advanced Usage

### Scanning with a Configuration File

You can use a Dalfox configuration file in your GitHub Actions workflow:

```yaml
name: Configured XSS Scan

on: [push]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: 'https://example.com'
          mode: url
          cmd_options: '--config ./security/dalfox-config.json'
```

### Integrating with Security Platforms

You can send Dalfox results to security platforms using the `--found-action` option:

```yaml
name: XSS Scan with Notifications

on: [push]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: 'https://example.com'
          mode: url
          cmd_options: '--found-action "curl -X POST -H \"Content-Type: application/json\" -d \"{\\\"text\\\":\\\"XSS Found: \$\$POCURL\\\"}\" https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"'
```

### File-Based Scanning

This workflow uses a list of URLs from a file in your repository:

```yaml
name: File-Based XSS Scan

on: [push]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    name: Dalfox XSS Scanner
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Dalfox scan
        uses: hahwul/action-dalfox@main
        id: xss-scan
        with:
          target: './security/target-urls.txt'
          mode: file
          cmd_options: '--mass-worker 5 --format json --output scan-results.json'
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: xss-scan-results
          path: scan-results.json
```

## Best Practices

### Security Considerations

1. **Token Permissions**: Be careful with workflow token permissions when scanning internal applications
2. **Rate Limiting**: Adjust worker count and delay settings to avoid overwhelming your applications
3. **Secret Management**: Use GitHub Secrets for sensitive values like API tokens or webhook URLs

### Performance Optimization

1. **Selective Scanning**: Only scan URLs that have changed or are affected by recent code changes
2. **Parallel Jobs**: For large applications, split scanning tasks across multiple parallel jobs
3. **Resource Allocation**: Adjust worker settings based on the GitHub Actions runner resources

```yaml
# Example of efficient resource usage
cmd_options: '--worker 50 --delay 100 --timeout 5'
```

### Workflow Integration

1. **Reporting Integration**: Send results to your security management platforms
2. **Issue Creation**: Automatically create GitHub issues for detected vulnerabilities
3. **PR Status Checks**: Make PR approvals dependent on security scan results

```yaml
# Example of creating a GitHub issue for vulnerabilities
- if: ${{ steps.xss-scan.outputs.result != '' }}
  name: Create Issue
  uses: actions/github-script@v6
  with:
    script: |
      github.rest.issues.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        title: 'XSS Vulnerability Detected',
        body: 'Dalfox found XSS vulnerabilities in the latest scan:\n\n```\n${{ steps.xss-scan.outputs.result }}\n```'
      })
```

## Troubleshooting

### Common Issues

1. **Action fails with timeout**: 
   - Increase the timeout value in cmd_options
   - Reduce the number of targets or parallel workers

2. **Empty results**:
   - Verify that your target is accessible from GitHub Actions runners
   - Check if your application requires authentication
   - Try running with `--debug` option to see more details

3. **Permission errors**:
   - Ensure the action has proper permissions to access resources
   - Authenticate properly if scanning authenticated pages

### Getting Help

If you encounter issues with Dalfox GitHub Actions:
- Check the [Dalfox GitHub repository issues](https://github.com/hahwul/dalfox/issues)
- Join the [Dalfox community discussions](https://github.com/hahwul/dalfox/discussions)
- Report specific GitHub Actions issues in the [action-dalfox repository](https://github.com/hahwul/action-dalfox/issues)
