---
title: Report
redirect_from: /docs/report/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Comprehensive Reporting
{: .d-inline-block }

New (v2.8.0) 
{: .label .label-green }

## Overview

Dalfox's reporting feature allows you to generate detailed reports of your XSS scans, providing comprehensive information about vulnerabilities, scanning parameters, and results. These reports are invaluable for:

- Documenting security assessments
- Sharing findings with development teams
- Creating audit trails for compliance requirements
- Building knowledge bases of common vulnerabilities
- Integrating with other security tools and dashboards

## Generating Reports

### Basic Report Generation

To generate a detailed report with your scan, use the `--report` flag:

```shell
dalfox url https://example.com/search?q=test --report
```

This command will execute the scan and produce a comprehensive report in plain text format, which includes detailed information about the scan configuration, discovered parameters, and any vulnerabilities found.

![Plain Text Report](https://user-images.githubusercontent.com/13212227/190555379-a4b06b07-0ae0-4f9a-859a-650ac34186ae.png)

### JSON Report Format

For integrating with other tools or for programmatic processing of results, you can generate reports in JSON format:

```shell
dalfox url https://example.com/search?q=test --report --report-format json
```

JSON reports are particularly useful for:
- Importing results into security dashboards
- Processing with scripts or other automation tools
- Creating custom visualizations of vulnerability data
- Storing structured data in security databases

![JSON Report](https://user-images.githubusercontent.com/13212227/190555382-cb7e37b9-b4c9-4c99-b853-ff65a1df9e01.png)

## Report Contents

A comprehensive Dalfox report includes:

### 1. Scan Configuration

- Target URL or files
- Scan mode and options used
- Date and time of the scan
- Dalfox version information

### 2. Parameter Analysis

- Discovered parameters (reflected, stored, DOM)
- Parameter sources (URL, body, headers, etc.)
- Parameter reflection contexts

### 3. Vulnerabilities Found

- XSS vulnerabilities (reflected, DOM-based, stored)
- Other vulnerabilities detected through BAV
- Vulnerability verification status
- Proof of concept URLs and payloads

### 4. Technical Details

- HTTP response codes
- Content types
- Reflection points
- DOM element details for verified vulnerabilities

## Saving Reports

### Saving to a File

To save the report to a file, combine the `--report` flag with the `-o` (output) flag:

```shell
dalfox url https://example.com/search?q=test --report --report-format json -o scan_results.json
```

For plain text reports:

```shell
dalfox url https://example.com/search?q=test --report -o scan_results.txt
```

### Including Raw HTTP Data

For even more detailed reports, you can include the raw HTTP requests and responses:

```shell
dalfox url https://example.com/search?q=test --report --output-request --output-response -o full_report.txt
```

## Using Reports Effectively

### For Security Teams

1. **Prioritizing Vulnerabilities**: Use the verification status to focus on confirmed XSS issues first
2. **Documentation**: Include reports in security assessment documentation
3. **Tracking Progress**: Compare reports over time to track vulnerability remediation

### For Developers

1. **Understanding Context**: The parameter analysis helps developers understand where vulnerabilities exist
2. **Remediation Guidance**: PoC payloads show exactly how vulnerabilities can be exploited
3. **Validation Testing**: Developers can use the same payloads to verify their fixes

### For Integration with Development Pipelines

1. **JSON Format**: Use JSON reports for integration with CI/CD pipelines
2. **Automated Triage**: Process reports to automatically create tickets for confirmed vulnerabilities
3. **Historical Analysis**: Store reports to track security progress over time

## Report Examples

### Plain Text Report Example

```
[Report] Dalfox v2.9.1 | Parameter Analysis and XSS Scanner Report
[Time] 2023-01-15 14:22:18
[Target] https://example.com/search?q=test

[Scan Summary]
- Worker: 100
- Scan Mode: url
- Parameters: 1 discovered
- BAV Enabled: true
- DOM Mining: enabled
- Dict Mining: enabled
- Scan Duration: 23.4 seconds

[Parameter Analysis]
- q: Reflected in HTML context, URL parameter
  - Reflection Count: 3
  - Reflection Points: body, title, meta

[Vulnerabilities]
1. Reflected XSS in 'q' parameter
   - Verified: Yes (Headless Browser)
   - Payload: <script>alert(1)</script>
   - PoC: https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
   - Context: HTML body

2. SQL Injection Pattern Detected
   - Verified: No (Pattern Match)
   - Parameter: q
   - Error: MySQL syntax error
   - PoC: https://example.com/search?q=test%27
```

### JSON Report Structure

```json
{
  "metadata": {
    "version": "2.9.1",
    "timestamp": "2023-01-15T14:22:18Z",
    "target": "https://example.com/search?q=test",
    "scanDuration": 23.4
  },
  "configuration": {
    "workers": 100,
    "mode": "url",
    "bavEnabled": true,
    "domMining": true,
    "dictMining": true
  },
  "parameters": [
    {
      "name": "q",
      "type": "url",
      "reflectionCount": 3,
      "reflectionPoints": ["body", "title", "meta"],
      "context": "html"
    }
  ],
  "vulnerabilities": [
    {
      "type": "xss",
      "parameter": "q",
      "verified": true,
      "payload": "<script>alert(1)</script>",
      "poc": "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
      "context": "html_body"
    },
    {
      "type": "sql_injection",
      "parameter": "q",
      "verified": false,
      "pattern": "MySQL syntax error",
      "poc": "https://example.com/search?q=test%27"
    }
  ]
}
```

## Best Practices

1. **Always Generate Reports**: Use the `--report` flag for any significant security tests
2. **Use JSON for Automation**: Choose JSON format when integrating with other tools
3. **Save Reports**: Always save reports to files for future reference
4. **Include Details**: For thorough analysis, include raw requests and responses
5. **Version Control**: Store reports in version control alongside the code they relate to
6. **Combine with HAR Files**: Use together with `--har-file-path` for complete HTTP transaction records

## Troubleshooting

- **Large Reports**: For very large targets, reports may be substantial. Consider filtering with `--only-poc`
- **Format Issues**: If a JSON report seems malformed, check for Unicode characters that might affect parsing
- **Missing Information**: Ensure you're using the latest version of Dalfox for the most comprehensive reports
