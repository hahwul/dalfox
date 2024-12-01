---
title: Injectable Points
redirect_from: /docs/ipoint/
nav_order: 5
parent: Resources
toc: true
layout: page
---

# Injectable Points

This guide provides detailed information on the various injectable points that Dalfox can identify during scans. Understanding these points can help you better interpret the results and understand where and how payloads are being injected.

## Injected Points

Dalfox identifies several types of injectable points in the response. Here are the main categories:

- **inHTML-none**: Injection point within HTML content without any surrounding quotes.
- **inJS-none**: Injection point within JavaScript content without any surrounding quotes.
- **inJS-double**: Injection point within JavaScript content surrounded by double quotes.
- **inJS-single**: Injection point within JavaScript content surrounded by single quotes.
- **inJS-backtick**: Injection point within JavaScript content surrounded by backticks.
- **inATTR-none**: Injection point within an HTML attribute without any surrounding quotes.
- **inATTR-double**: Injection point within an HTML attribute surrounded by double quotes.
- **inATTR-single**: Injection point within an HTML attribute surrounded by single quotes.

## Parameter Types

Dalfox can identify injectable points in different types of parameters:

- **URL**: Parameters passed in the URL query string.
- **FORM**: Parameters passed in the body of a form submission.

## Example

To illustrate how these injectable points work, consider the following example:

### inJS-double-URL

This indicates that a value entered into the URL query is reflected in a JavaScript context within double quotes in the response.

**Request**

```
/q=testabcd
```

**Response**

```html
<script>
  var a = "testabcd";
</script>
```

In this example, the value `testabcd` is injected into the JavaScript context within double quotes.
