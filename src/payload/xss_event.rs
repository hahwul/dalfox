/// Expose a comprehensive set of common DOM event handler attribute names
/// (e.g., "onmouseover", "onclick") that can be used for attribute-based XSS payloads.
pub(crate) fn common_event_handler_names() -> &'static [&'static str] {
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
///
/// **Loop order is the JS primitive on the outside, the handler name on the
/// inside**, so the handler names cycle first: the first `names.len()` payloads
/// are every handler paired with the first JS primitive, then the list repeats
/// with the next primitive. This mirrors the *effect* of the sibling generator
/// [`crate::payload::get_dynamic_xss_html_payloads`] (whose templates are its
/// inner-cycling axis) — the discriminating axis leads.
///
/// The *discriminating* axis is the handler name: whether a filter allows
/// `onwheel` but blocks `onerror`, and whether a handler auto-fires without
/// user interaction, is what decides if the parameter is exploitable. The JS
/// primitive it carries (`alert(1)` vs `prompt\`1\`` vs `confirm(1)`) changes
/// nothing about reachability — it only varies the PoC and gives WAF keyword
/// diversity.
///
/// With the axes the other way round (primitive inner, handler outer), covering
/// all [`common_event_handler_names`] entries cost `names.len() × SMALL.len()`
/// payloads (98 × 17 = 1666), so every per-parameter bound that samples a
/// *prefix* of this catalog — the `DEFAULT_PAYLOAD_SAFETY_CAP`, the DOM phase's
/// `INERT_ECHO_BUDGET`, the reflection phase's transformed-echo budget — saw
/// `onclick` seventeen times before it ever saw `onload`. Cycling the handler
/// names first puts complete handler coverage in the first `names.len()`
/// payloads and only then spends requests on sink variations.
///
/// The union is unchanged: this is a pure reordering of the same cross product.
pub(crate) fn get_dynamic_xss_attribute_payloads() -> Vec<String> {
    // Memoized: combines the static event-handler name list with the stable
    // XSS_JAVASCRIPT_PAYLOADS_SMALL const, so the catalog is identical per
    // process. Avoids rebuilding once per reflection parameter.
    static CACHE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        let names = common_event_handler_names();
        let mut out =
            Vec::with_capacity(names.len() * crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.len());
        for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
            for ev in names.iter() {
                out.push(format!("{}={}", ev, js));
            }
        }
        out
    });
    CACHE.clone()
}

#[cfg(test)]
mod tests;
