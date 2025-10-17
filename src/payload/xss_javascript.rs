pub const XSS_JAVASCRIPT_PAYLOADS: &[&str] = &[
    "alert(1)",
    "prompt(1)",
    "confirm(1)",
    "alert`1`",
    "prompt`1`",
    "confirm`1`",
];
