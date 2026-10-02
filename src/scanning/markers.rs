use std::sync::OnceLock;

static OPEN_MARKER: OnceLock<String> = OnceLock::new();
static INNER_MARKER: OnceLock<String> = OnceLock::new();
static CLOSE_MARKER: OnceLock<String> = OnceLock::new();
static CLASS_MARKER: OnceLock<String> = OnceLock::new();
static ID_MARKER: OnceLock<String> = OnceLock::new();
static BRACKETED_MARKER: OnceLock<String> = OnceLock::new();

fn short_id(seed: &str) -> String {
    let id = crate::utils::make_scan_id(seed);
    if id.len() >= 8 {
        id[..8].to_string()
    } else {
        id
    }
}

pub(crate) fn open_marker() -> &'static str {
    OPEN_MARKER
        .get_or_init(|| format!("dlx{}", short_id("open")))
        .as_str()
}

/// Middle segment of the sandwich probe. Distinct prefix (`dlxmid`) so
/// `probe_reflected` can identify it without colliding with
/// `open_marker()` or `close_marker()`.
pub(crate) fn inner_marker() -> &'static str {
    INNER_MARKER
        .get_or_init(|| format!("dlxmid{}", short_id("inner")))
        .as_str()
}

pub(crate) fn close_marker() -> &'static str {
    CLOSE_MARKER
        .get_or_init(|| format!("xld{}", short_id("close")))
        .as_str()
}

pub(crate) fn class_marker() -> &'static str {
    CLASS_MARKER
        .get_or_init(|| format!("dlx{}", short_id("class")))
        .as_str()
}

pub(crate) fn id_marker() -> &'static str {
    ID_MARKER
        .get_or_init(|| format!("dlx{}", short_id("id")))
        .as_str()
}

/// Fill a payload template's `{CLASS}` / `{ID}` placeholders with this
/// process's class / id markers.
pub(crate) fn fill_markers(template: &str) -> String {
    template
        .replace("{CLASS}", class_marker())
        .replace("{ID}", id_marker())
}

/// Whether `s` carries one of this process's scan markers. They are
/// session-random, so a page cannot contain one unless it reflected it.
pub(crate) fn carries_scan_marker(s: &str) -> bool {
    s.contains("dlx")
        && [open_marker(), inner_marker(), class_marker(), id_marker()]
            .iter()
            .any(|m| s.contains(m))
        || s.contains(close_marker())
}

/// Sandwich probe value: `OPEN + INNER + CLOSE`. Used by Stage 0/1/2
/// (discovery + mining + sentinel) so that response analysis can tell
/// apart a full reflection from a prefix-/suffix-stripped variant. The
/// substring `open_marker()` is preserved within this value, so legacy
/// callers that still do `text.contains(open_marker())` keep working.
pub(crate) fn bracketed_marker() -> &'static str {
    BRACKETED_MARKER
        .get_or_init(|| format!("{}{}{}", open_marker(), inner_marker(), close_marker()))
        .as_str()
}

/// Whether the bracketed probe value reflected back in any form: intact, or
/// with a prefix or suffix (or both) stripped by a server-side filter — the
/// cases a single-token `text.contains(open_marker())` check would miss. Every
/// such form carries the inner marker.
pub(crate) fn probe_reflected(text: &str) -> bool {
    text.contains(inner_marker())
}

#[cfg(test)]
mod tests;
