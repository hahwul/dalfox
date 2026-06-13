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
    // Memoized: combines the static event-handler name list with the stable
    // XSS_JAVASCRIPT_PAYLOADS_SMALL const, so the catalog is identical per
    // process. Avoids rebuilding once per reflection parameter.
    static CACHE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        let names = common_event_handler_names();
        let mut out =
            Vec::with_capacity(names.len() * crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.len());
        for ev in names.iter() {
            for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
                out.push(format!("{}={}", ev, js));
            }
        }
        out
    });
    CACHE.clone()
}

#[cfg(test)]
mod tests;
