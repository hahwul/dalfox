+++
title = "Payload"
description = "Manage and enumerate XSS payloads"
weight = 3
sort_by = "weight"

[extra]
+++

# Payload Command

The `payload` command allows you to enumerate and explore various XSS payloads and resources without performing an actual scan. This is useful for research, payload development, and understanding Dalfox's payload database.

## Basic Usage

```bash
dalfox payload [SELECTOR]
```

## Selectors

### Event Handlers

List all DOM event handler attribute names used for XSS payloads.

```bash
dalfox payload event-handlers
```

**Output example:**
```
onclick
onmouseover
onerror
onload
onfocus
onblur
...
```

**Use cases:**
- Building custom XSS payloads
- Understanding event-based XSS vectors
- Creating bypass techniques

### Useful Tags

Print useful HTML tag names commonly used in XSS attacks.

```bash
dalfox payload useful-tags
```

**Output example:**
```
script
img
svg
iframe
object
embed
video
audio
...
```

**Use cases:**
- Identifying alternative injection vectors
- Bypassing tag filters
- Understanding tag-based XSS techniques

### PayloadBox

Fetch and display remote XSS payloads from the PayloadBox repository.

```bash
dalfox payload payloadbox
```

**Features:**
- Community-maintained payload collection
- Regularly updated with new techniques
- Covers various XSS contexts

{% alert_info() %}
Requires internet connection to fetch remote payloads.
{% end %}

### PortSwigger

Fetch and display XSS payloads from PortSwigger (creators of Burp Suite).

```bash
dalfox payload portswigger
```

**Features:**
- Professional-grade payload collection
- Well-documented XSS vectors
- Tested against various browsers and filters

{% alert_info() %}
Requires internet connection to fetch remote payloads.
{% end %}

### URI Scheme

Display scheme-based XSS payloads using URI schemes.

```bash
dalfox payload uri-scheme
```

**Output example:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)
...
```

**Use cases:**
- Testing URL-based injection points
- Bypassing protocol filters
- Understanding scheme-based XSS vectors

## Usage Examples

### Research and Development

**Explore event handlers for custom payload:**
```bash
dalfox payload event-handlers > event-handlers.txt
```

**Fetch latest payloads from multiple sources:**
```bash
dalfox payload payloadbox > payloadbox.txt
dalfox payload portswigger > portswigger.txt
```

**Combine with grep for specific patterns:**
```bash
dalfox payload useful-tags | grep -i svg
```

### Building Custom Payload Lists

**Create a comprehensive payload file:**
```bash
#!/bin/bash

echo "# Event handlers" > custom-payloads.txt
dalfox payload event-handlers >> custom-payloads.txt

echo "" >> custom-payloads.txt
echo "# Useful tags" >> custom-payloads.txt
dalfox payload useful-tags >> custom-payloads.txt

echo "" >> custom-payloads.txt
echo "# URI schemes" >> custom-payloads.txt
dalfox payload uri-scheme >> custom-payloads.txt

echo "" >> custom-payloads.txt
echo "# Remote payloads" >> custom-payloads.txt
dalfox payload payloadbox >> custom-payloads.txt
dalfox payload portswigger >> custom-payloads.txt
```

### Integration with Other Tools

**Use with custom scripts:**
```bash
# Count event handlers
dalfox payload event-handlers | wc -l

# Filter specific tags
dalfox payload useful-tags | grep -E "(script|img|svg)"

# Create payload template
for tag in $(dalfox payload useful-tags); do
  echo "<$tag src=x onerror=alert(1)>"
done
```

**Generate context-specific payloads:**
```bash
# Generate IMG-based payloads
for handler in $(dalfox payload event-handlers | head -20); do
  echo "<img src=x $handler=alert(1)>"
done > img-payloads.txt
```

## Advanced Usage

### Custom Payload Development

Use the payload command to understand Dalfox's payload structure and create your own:

```bash
# 1. Study event handlers
dalfox payload event-handlers

# 2. Study useful tags
dalfox payload useful-tags

# 3. Combine them intelligently
# (Manual payload crafting based on the output)

# 4. Test with Dalfox
dalfox scan https://example.com --custom-payload my-payloads.txt
```

### Payload Research

**Compare payload sources:**
```bash
# Get unique payloads from PayloadBox
dalfox payload payloadbox | sort -u > pb-unique.txt

# Get unique payloads from PortSwigger
dalfox payload portswigger | sort -u > ps-unique.txt

# Find differences
diff pb-unique.txt ps-unique.txt
```

### Automated Payload Generation

```python
#!/usr/bin/env python3
import subprocess
import json

def get_event_handlers():
    result = subprocess.run(
        ['dalfox', 'payload', 'event-handlers'],
        capture_output=True,
        text=True
    )
    return result.stdout.strip().split('\n')

def get_useful_tags():
    result = subprocess.run(
        ['dalfox', 'payload', 'useful-tags'],
        capture_output=True,
        text=True
    )
    return result.stdout.strip().split('\n')

def generate_payloads():
    handlers = get_event_handlers()
    tags = get_useful_tags()
    
    payloads = []
    for tag in tags:
        for handler in handlers[:10]:  # Limit combinations
            payload = f"<{tag} {handler}=alert(1)>"
            payloads.append(payload)
    
    return payloads

if __name__ == '__main__':
    payloads = generate_payloads()
    for payload in payloads[:50]:  # Print first 50
        print(payload)
```

## Output Formats

All payload commands output plain text, one item per line. This makes it easy to:
- Pipe to other commands
- Redirect to files
- Process with scripts
- Use in automation

**Example workflow:**
```bash
# Save to file
dalfox payload event-handlers > handlers.txt

# Count items
dalfox payload useful-tags | wc -l

# Filter and process
dalfox payload payloadbox | grep -i "svg" | head -10

# Use in a loop
while read -r tag; do
  echo "Testing tag: $tag"
done < <(dalfox payload useful-tags)
```

## Network Considerations

{% collapse(title="Remote payload fetching") %}
The `payloadbox` and `portswigger` selectors fetch data from remote sources. Consider:

1. **Timeout**: Default timeout is 10 seconds
2. **Proxy**: Respects `--proxy` flag if needed
3. **Caching**: Not cached; fetched each time
4. **Availability**: Requires internet connection

If you need to use these payloads offline, save them to a file:
```bash
dalfox payload payloadbox > payloadbox-cache.txt
dalfox payload portswigger > portswigger-cache.txt
```
{% end %}

## Integration with Scan Command

Payloads enumerated with this command can be used with the scan command:

```bash
# 1. Fetch remote payloads
dalfox payload portswigger > portswigger-payloads.txt

# 2. Use them in a scan
dalfox scan https://example.com --custom-payload portswigger-payloads.txt

# 3. Or use only custom payloads
dalfox scan https://example.com \
  --custom-payload portswigger-payloads.txt \
  --only-custom-payload
```

## Practical Examples

### Bug Bounty Research

```bash
# Collect all available payloads
mkdir payloads-research
cd payloads-research

dalfox payload event-handlers > event-handlers.txt
dalfox payload useful-tags > useful-tags.txt
dalfox payload uri-scheme > uri-scheme.txt
dalfox payload payloadbox > payloadbox.txt
dalfox payload portswigger > portswigger.txt

# Create master payload list
cat *.txt | sort -u > master-payloads.txt
```

### Filter Bypass Research

```bash
# Find SVG-related payloads
dalfox payload payloadbox | grep -i svg > svg-payloads.txt
dalfox payload portswigger | grep -i svg >> svg-payloads.txt

# Find data URI payloads
dalfox payload uri-scheme | grep -i data > data-uri-payloads.txt
```

### WAF Testing

```bash
# Collect diverse payloads for WAF testing
dalfox payload payloadbox > waf-test-payloads.txt

# Test against target
dalfox scan https://example.com \
  --custom-payload waf-test-payloads.txt \
  --delay 1000 \
  -f json \
  -o waf-test-results.json
```

## See Also

- [Scan Command](/sub-commands/scan) - Using custom payloads in scans
- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Practical scanning examples
