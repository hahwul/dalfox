---
title: Remote Payloads
redirect_from: /docs/remote-payloads/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Remote Payloads

## Overview

The Remote Payloads feature allows Dalfox to dynamically fetch and use XSS payloads from well-maintained external sources. This capability significantly expands Dalfox's testing coverage by incorporating hundreds of specialized payloads developed by security researchers.

Benefits of using remote payloads include:

- **Expanded Coverage**: Access to a wider variety of XSS vectors
- **Up-to-Date Techniques**: Leverage the latest XSS bypass techniques
- **Specialized Payloads**: Test against context-specific vulnerabilities
- **Reduced Maintenance**: No need to maintain your own comprehensive payload list
- **Community Knowledge**: Benefit from the collective expertise of security researchers

## Using Remote Payloads

### Basic Usage

To use payloads from a single remote source:

```bash
dalfox url https://example.com --remote-payloads portswigger
```

### Using Multiple Sources

Combine multiple remote payload sources for maximum coverage:

```bash
dalfox url https://example.com --remote-payloads portswigger,payloadbox
```

### Combining with Custom Payloads

Remote payloads can be used alongside your custom payloads for a comprehensive approach:

```bash
dalfox url https://example.com --remote-payloads portswigger --custom-payload my-payloads.txt
```

## Supported Remote Sources

Dalfox currently supports the following remote payload sources:

### PortSwigger XSS Cheat Sheet

```bash
dalfox url https://example.com --remote-payloads portswigger
```

- **Source**: [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- **Maintainer**: PortSwigger (creators of Burp Suite)
- **Payload Count**: ~100 specialized payloads
- **Features**: 
  - Browser-specific payloads
  - Event handler payloads
  - HTML5 vectors
  - Innovative encoding techniques
  - Filter bypass strategies

### PayloadBox XSS Payload List

```bash
dalfox url https://example.com --remote-payloads payloadbox
```

- **Source**: [PayloadBox XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- **Maintainer**: PayloadBox Project
- **Payload Count**: ~200 payloads
- **Features**:
  - Basic to advanced vectors
  - Filter evasion techniques
  - Context-specific payloads
  - Polyglot payloads
  - DOM XSS specific payloads

## How Remote Payloads Work

When you use the `--remote-payloads` option, Dalfox:

1. Connects to the specified source(s) and downloads the latest payload collections
2. Parses and processes the payloads to ensure compatibility
3. Integrates them with the built-in payload database
4. Uses these payloads during the scanning process alongside Dalfox's native ones

The download process occurs once per scan, and the payloads are kept in memory for the duration of the scan.

![Remote Payloads Illustration](https://user-images.githubusercontent.com/13212227/120077625-49512d80-c0e6-11eb-9854-96c35259f276.jpg)

## Advanced Usage Scenarios

### WAF Bypass Testing

When testing against sites with Web Application Firewalls (WAFs), leverage the specialized bypass payloads:

```bash
dalfox url https://waf-protected-site.com --remote-payloads portswigger --waf-evasion
```

### High-Coverage Scanning

For maximum vulnerability detection in critical applications:

```bash
dalfox url https://critical-app.com --remote-payloads portswigger,payloadbox --deep-domxss --custom-payload ./specialized-payloads.txt
```

### Browser-Specific Testing

When testing for XSS in specific browsers:

```bash
# Testing with diverse payloads that might work in various browsers
dalfox url https://example.com --remote-payloads portswigger,payloadbox
```

## Best Practices

1. **Start with Built-In Payloads**: For quick scans, Dalfox's default payloads are often sufficient
2. **Use Remote Payloads for Thorough Testing**: Add remote payloads for comprehensive security assessments
3. **Combine Sources**: Different sources have different strengths; using multiple sources provides better coverage
4. **Consider Performance**: Using all remote sources increases scan time; for quick scans, choose one source
5. **Update Frequently**: Remote sources are periodically updated; run new scans to benefit from the latest payloads

## Troubleshooting

### Connection Issues

If Dalfox can't connect to remote sources:

- Verify your internet connection
- Check if the remote source is accessible
- Consider using a proxy if necessary:
  ```bash
  dalfox url https://example.com --remote-payloads portswigger --proxy http://your-proxy:8080
  ```

### Performance Considerations

If scanning with remote payloads is too slow:

- Use a single remote source instead of multiple
- Increase the worker count for faster processing:
  ```bash
  dalfox url https://example.com --remote-payloads portswigger -w 150
  ```
- Consider testing specific parameters only:
  ```bash
  dalfox url https://example.com --remote-payloads portswigger -p search -p q
  ```

## Future Payload Sources

The Dalfox team is continuously working to integrate additional remote payload sources. Future versions may include:

- Additional community-maintained XSS repositories
- Context-specific payload collections
- Framework-specific bypass techniques

For requests to add new remote payload sources, please open an issue on the [Dalfox GitHub repository](https://github.com/hahwul/dalfox/issues).
