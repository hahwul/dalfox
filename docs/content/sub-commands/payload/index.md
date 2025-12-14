+++
title = "Payload"
description = "Manage and enumerate XSS payloads"
weight = 3
sort_by = "weight"

[extra]
+++

Enumerate and explore XSS payloads without scanning. Useful for research and payload development.

```bash
dalfox payload [SELECTOR]
```

## Selectors

**event-handlers**: List DOM event handler attributes
```bash
dalfox payload event-handlers  # onclick, onerror, onload, etc.
```

**useful-tags**: Print HTML tags for XSS
```bash
dalfox payload useful-tags     # script, img, svg, iframe, etc.
```

**payloadbox**: Fetch community payloads (requires internet)
```bash
dalfox payload payloadbox
```

**portswigger**: Fetch PortSwigger payloads (requires internet)
```bash
dalfox payload portswigger
```

**uri-scheme**: Display URI scheme payloads
```bash
dalfox payload uri-scheme      # javascript:, data:, etc.
```

## Examples

**Save to file**:
```bash
dalfox payload event-handlers > handlers.txt
dalfox payload payloadbox > payloadbox.txt
```

**Filter**:
```bash
dalfox payload useful-tags | grep -i svg
```

**Generate payloads**:
```bash
for handler in $(dalfox payload event-handlers | head -20); do
  echo "<img src=x $handler=alert(1)>"
done > img-payloads.txt
```

**Build comprehensive list**:
```bash
cat <(dalfox payload event-handlers) <(dalfox payload useful-tags) <(dalfox payload payloadbox) > all.txt
```

## Use with Scan

```bash
dalfox payload portswigger > portswigger.txt
dalfox scan https://example.com --custom-payload portswigger.txt
dalfox scan https://example.com --custom-payload portswigger.txt --only-custom-payload
```

## See Also

- [Scan Command](/sub-commands/scan) - Using custom payloads in scans
- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Practical scanning examples
