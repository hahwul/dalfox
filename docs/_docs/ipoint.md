---
title: Injectable point
permalink: /docs/ipoint/
---

## Injected
- inHTML-none
- inJS-none
- inJS-double
- inJS-single
- inJS-backtick
- inATTR-none
- inATTR-double
- inATTR-single

## Parameter Type
- URL
- FORM

## E.g
`inJS-double-URL` is value entered into the URL query is reflected to javascript(with double quotation) area in response.

**Request**
```
/q=testabcd
```

**Response**
```html
<script>
  var a = "testabcd"
</script>
```
