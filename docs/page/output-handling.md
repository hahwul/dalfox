---
title: Output Handling
redirect_from: /docs/output-handling/
nav_order: 5
toc: true
layout: page
---

# Output Handling

This guide provides comprehensive instructions on how to capture, filter, and process the output from Dalfox. Understanding these output handling techniques will help you efficiently interpret results and integrate Dalfox into your security workflows.

## Understanding Dalfox Output Types

Dalfox generates several types of output during scanning:

- **Progress information**: Status updates about the scanning process
- **Proof of Concept (PoC) findings**: Actual vulnerabilities discovered
- **Analysis data**: Details about parameters, injection points, and vulnerability verification
- **HTTP traffic**: Raw request and response data

## Basic Output Handling Techniques

### Redirecting Output to Files

The simplest way to save Dalfox output is by using standard output redirection:

```bash
dalfox url http://example.com/vulnerable.php > results.txt
```

This captures all console output to the specified file.

### Using the Built-in Output Flag

For more controlled output saving, use the `-o` or `--output` flag:

```bash
dalfox url http://example.com/vulnerable.php -o results.txt
```

This approach is recommended as it ensures proper handling of terminal control characters.

## Advanced Output Filtering

### Processing Output with Unix Tools

Dalfox output can be piped to other tools for filtering and processing:

```bash
# Extract only verified XSS vulnerabilities
dalfox url http://example.com/vulnerable.php | grep "\[V\]" > verified_xss.txt

# Extract PoC URLs and open them in a browser
dalfox url http://example.com/vulnerable.php | grep "\[POC\]" | cut -d " " -f 2 | xargs -I % open %

# Count different types of findings
dalfox url http://example.com/vulnerable.php | grep "\[POC\]" | cut -d "[" -f 3 | cut -d "]" -f 1 | sort | uniq -c
```

### Filtering by PoC Type

Dalfox allows you to filter findings by vulnerability type with the `--only-poc` flag:

```bash
# Show only verified (V) and grep-based (G) findings
dalfox url http://example.com/vulnerable.php --only-poc=g,v
```

Available PoC types:
- `g`: Grep-based findings (potential vulnerabilities identified through response pattern matching)
- `r`: Reflected findings (parameters successfully reflected in responses)
- `v`: Verified findings (confirmed vulnerabilities through headless browser verification)

## Comprehensive Logging Options

### Capturing Complete Scan Logs

To save all scan information, including detailed analysis steps:

```bash
dalfox url http://example.com/vulnerable.php -o full_scan.log --output-all
```

Example of a comprehensive log:

```
[*] Using single target mode
[*] Target URL: http://example.com/vulnerable.php
[*] Valid target [ code:200 / size:4819 ]
[*] Using dictionary mining option [list=GF-Patterns] 📚⛏
[*] Using DOM mining option 📦⛏
[*] Start static analysis.. 🔍
[*] Start parameter analysis.. 🔍
[*] Start BAV analysis / [sqli, ssti, OpenRedirect] 🔍
[I] Found reflected parameter: q
[V] Triggered XSS Payload: q=<script>alert(1)</script>
[POC][V][GET] http://example.com/vulnerable.php?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

### Including Raw HTTP Data

To include raw HTTP requests and responses in your output:

```bash
# Include requests
dalfox url http://example.com/vulnerable.php --output-request

# Include responses
dalfox url http://example.com/vulnerable.php --output-response

# Include both
dalfox url http://example.com/vulnerable.php --output-request --output-response
```

## Output Format Options

### JSON Output

For programmatic processing or integration with other tools, use JSON output:

```bash
dalfox url http://example.com/vulnerable.php --format json -o results.json
```

This generates structured JSON data that can be easily parsed by scripts or imported into other security tools.

### Detailed Report Generation

For comprehensive reporting:

```bash
dalfox url http://example.com/vulnerable.php --report --report-format json -o detailed_report.json
```

## HTTP Archive (HAR) Integration

### Generating HAR Files

HAR files contain detailed information about HTTP transactions and can be analyzed in various tools:

```bash
dalfox url http://example.com/vulnerable.php --har-file-path=scan.har
```

### Analyzing HAR Files

The generated HAR file can be analyzed with:

- [HAR Viewer](http://www.softwareishard.com/har/viewer/)
- Chrome/Firefox Developer Tools (Import HAR)
- Specialized HTTP analysis tools

Example HAR viewer screenshot:
![HAR Viewer Example](https://user-images.githubusercontent.com/369053/218365521-5df5ff3c-759e-4bb8-9205-a45ac25481ca.png)

## Integration with Other Security Tools

### Automated Workflows

Dalfox can be integrated into CI/CD pipelines or other security automation:

```bash
# Scan and notify on findings
dalfox url http://example.com/vulnerable.php --found-action './notify_slack.sh'

# Scan multiple targets from Burp Suite
dalfox file targets.txt --format json -o findings.json
```

### Continuous Monitoring Examples

```bash
# Daily scan with timestamped output
echo "$(date +%F)_scan.log"
dalfox url http://example.com/vulnerable.php -o "$(date +%F)_scan.log"
```

## Troubleshooting Output Issues

If you encounter problems with output handling:

1. **Terminal encoding issues**: Use `--no-color` to disable ANSI color codes
2. **Output truncation**: Check terminal buffer settings or use file output
3. **Special character problems**: Use JSON output format for consistent encoding

For more information on output formats and report interpretation, see the [JSON Format Documentation](../advanced/resources/json/) and [PoC Format Documentation](../advanced/resources/format-of-poc/).
