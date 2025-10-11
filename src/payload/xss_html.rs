pub const XSS_HTML_PAYLOADS: &[&str] = &[
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
];
