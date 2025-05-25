---
title: Parameter Types
nav_order: 3 # Adjust nav_order as needed
parent: Features
grand_parent: Advanced
toc: true
layout: page
---

# Understanding Parameter Types in Dalfox

Dalfox is designed to identify and test for XSS vulnerabilities across various parts of an HTTP request. Understanding how Dalfox categorizes parameters can help you interpret its findings and fine-tune your scans. When Dalfox discovers potential injection points, it classifies them into one of the following types:

| Parameter Type | Description | Common Examples | How Dalfox Tests |
|----------------|-------------|-----------------|------------------|
| `PATH` | Segments of the URL path. | `/user/{userID}/profile`, `/product/{productName}` | Dalfox can attempt to inject payloads by replacing path segments. Useful if parts of the path are reflected in the response. |
| `QUERY` | Parameters found in the URL's query string (after the `?`). | `?id=123`, `?search=term`, `?redirect=/index.php` | Standard XSS testing location. Payloads are URL-encoded and appended to the query string. |
| `FRAGMENT` | Content within the URL's fragment identifier (after the `#`). | `#section=about`, `#user-id=45` | Often processed by client-side JavaScript. Dalfox can test query-like fragments (e.g., `#key=value`) or the entire fragment string if it's not structured like a query. |
| `HEADER` | HTTP request headers. | `User-Agent`, `Referer`, `X-Custom-Header` | Dalfox can inject payloads into specified or common HTTP headers to test for XSS if header values are reflected in the page. |
| `COOKIE` | Individual cookies sent with the request. | `sessionID=xyzabc`, `preference=dark_mode` | Tests if manipulating cookie values can lead to XSS when these values are processed and reflected by the application. |
| `BODY_FORM` | Parameters sent in the request body, typically with `application/x-www-form-urlencoded` Content-Type (e.g., from HTML forms). | `username=admin&password=secret` | Common for POST requests. Payloads are URL-encoded and sent in the request body. |
| `BODY_JSON` | Top-level keys in a JSON request body (typically with `application/json` Content-Type). | `{"userId":"1001", "comment":"text"}` | Dalfox injects payloads as string values for top-level keys in the JSON structure. The payload is JSON string-escaped. |
| `BODY_XML` | Parameters within an XML request body (e.g., `application/xml` or `text/xml` Content-Type). | `<user><id>1</id><name>test</name></user>` | (Future Enhancement) While Dalfox may detect XML content, detailed structured testing of individual XML elements/attributes is a planned enhancement. Basic string-based body testing might apply. |
| `UNKNOWN` | Parameters whose type could not be definitively determined or fall outside the above categories. | N/A | Tested with general-purpose techniques. |

**How Dalfox Uses These Types:**

-   **Discovery (`parameterAnalysis.go`)**: During the parameter analysis phase, Dalfox parses the target URL, request headers (including cookies), and request body (if provided via `-d` and method is POST/PUT etc.) to identify all potential parameters and assigns them one of these types.
-   **Targeted Testing**: Knowing the parameter type allows Dalfox to:
    -   Apply appropriate encoding (e.g., URL encoding for query parameters, JSON string escaping for JSON values).
    -   Construct test requests correctly (e.g., placing the payload in a header vs. a query string parameter).
-   **`--magic` Flag**: When you use the `--magic` flag, Dalfox searches for your magic string in values across *all* these discoverable locations (Query, Header, Cookie, Body Form/JSON). If found, it will force testing on that specific parameter, using its identified type to guide payload injection.
-   **Reporting**: Scan results may indicate the type of parameter where a vulnerability was found, aiding in remediation.

Understanding these types helps in crafting more effective Dalfox scans, especially when using options like `--custom-payload`, `--blind`, or analyzing findings.
