/// Dynamically build attribute payloads by combining common event handlers with
/// JavaScript execution primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_ATTRIBUTE_PAYLOADS constant to ensure
/// automatic synchronization when JavaScript payload list changes.
pub fn get_dynamic_xss_attribute_payloads() -> Vec<String> {
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
        out.push(format!("onerror={}", js));
        out.push(format!("onload={}", js));
    }
    out
}
