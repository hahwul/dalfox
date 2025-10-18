/// Dynamically build attribute payloads by combining common event handlers with
/// JavaScript execution primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_ATTRIBUTE_PAYLOADS constant to ensure
/// automatic synchronization when JavaScript payload list changes.
pub fn get_dynamic_xss_attribute_payloads() -> Vec<String> {
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
        out.push(format!("onerror={}", js));
        out.push(format!("onload={}", js));
        out.push(format!("onmouseover={}", js));
        out.push(format!("onclick={}", js));
        out.push(format!("onfocus={}", js));
        out.push(format!("onmouseenter={}", js));
        out.push(format!("onmouseleave={}", js));
        out.push(format!("onkeydown={}", js));
        out.push(format!("onkeyup={}", js));
        out.push(format!("onsubmit={}", js));
        out.push(format!("onpointerover={}", js));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_payloads_non_empty() {
        let payloads = get_dynamic_xss_attribute_payloads();
        assert!(
            !payloads.is_empty(),
            "attribute payloads should not be empty"
        );
    }

    #[test]
    fn test_attribute_payloads_contains_event_names() {
        let payloads = get_dynamic_xss_attribute_payloads();
        assert!(
            payloads.iter().any(|p| p.starts_with("onerror=")),
            "should contain onerror= variants"
        );
        assert!(
            payloads.iter().any(|p| p.starts_with("onload=")),
            "should contain onload= variants"
        );
        assert!(
            payloads.iter().any(|p| p.starts_with("onmouseover=")),
            "should contain onmouseover= variants"
        );
        assert!(
            payloads.iter().any(|p| p.starts_with("onclick=")),
            "should contain onclick= variants"
        );
    }

    #[test]
    fn test_js_payloads_exposed_and_contains_alert() {
        let js = crate::payload::XSS_JAVASCRIPT_PAYLOADS;
        assert!(!js.is_empty(), "JS payload list should not be empty");
        assert!(
            js.iter().any(|p| p.contains("alert(1)")),
            "should include at least one alert(1) primitive"
        );
    }
}
