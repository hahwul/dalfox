/// Expose a focused set of most effective DOM event handler attribute names
/// for XSS testing. These are handlers that can be triggered without user interaction
/// or are commonly found vulnerable.
pub fn common_event_handler_names() -> &'static [&'static str] {
    &[
        // Most effective - auto-triggering
        "onerror",       // Triggers on element load errors (img, script)
        "onload",        // Triggers on element load
        "onfocus",       // Combined with autofocus for auto-trigger
        "onblur",        // Opposite of focus
        "onmouseover",   // User interaction but very common
        "onclick",       // Click events
        "onmouseenter",  // Similar to mouseover
        // Animation-based
        "onanimationstart",
        "onanimationend",
        // Form-related
        "oninput",
        "onchange",
        "onsubmit",
        // Additional commonly exploited
        "onpageshow",
        "ontoggle",      // For details elements
        "onhashchange",  // URL hash changes
    ]
}

/// Dynamically build attribute payloads by combining common event handlers with
/// JavaScript execution primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_ATTRIBUTE_PAYLOADS constant to ensure
/// automatic synchronization when JavaScript payload list changes.
pub fn get_dynamic_xss_attribute_payloads() -> Vec<String> {
    let mut out = Vec::new();
    for ev in common_event_handler_names().iter() {
        for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
            out.push(format!("{}={}", ev, js));
        }
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
        let js = crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL;
        assert!(!js.is_empty(), "JS payload list should not be empty");
        assert!(
            js.iter().any(|p| p.contains("alert(1)")),
            "should include at least one alert(1) primitive"
        );
    }
}
