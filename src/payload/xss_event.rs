/// Expose a comprehensive set of common DOM event handler attribute names
/// (e.g., "onmouseover", "onclick") that can be used for attribute-based XSS payloads.
pub fn common_event_handler_names() -> &'static [&'static str] {
    &[
        "onabort",
        "onanimationend",
        "onanimationiteration",
        "onanimationstart",
        "onauxclick",
        "onbeforeinput",
        "onbeforeprint",
        "onbeforeunload",
        "onblur",
        "oncancel",
        "oncanplay",
        "oncanplaythrough",
        "onchange",
        "onclick",
        "onclose",
        "oncontextmenu",
        "oncopy",
        "oncuechange",
        "oncut",
        "ondblclick",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onended",
        "onerror",
        "onfocus",
        "onfocusin",
        "onfocusout",
        "onformdata",
        "ongotpointercapture",
        "onhashchange",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onlanguagechange",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onlostpointercapture",
        "onmessage",
        "onmessageerror",
        "onmousedown",
        "onmouseenter",
        "onmouseleave",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpointercancel",
        "onpointerdown",
        "onpointerenter",
        "onpointerleave",
        "onpointermove",
        "onpointerout",
        "onpointerover",
        "onpointerup",
        "onpopstate",
        "onprogress",
        "onratechange",
        "onreset",
        "onresize",
        "onscroll",
        "onsearch",
        "onsecuritypolicyviolation",
        "onseeked",
        "onseeking",
        "onselect",
        "onselectionchange",
        "onselectstart",
        "onslotchange",
        "onstalled",
        "onstorage",
        "onsubmit",
        "onsuspend",
        "ontimeupdate",
        "ontoggle",
        "ontouchcancel",
        "ontouchend",
        "ontouchmove",
        "ontouchstart",
        "ontransitionend",
        "onunhandledrejection",
        "onvisibilitychange",
        "onvolumechange",
        "onwaiting",
        "onwheel",
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
