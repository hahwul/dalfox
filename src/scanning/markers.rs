use std::sync::OnceLock;

static OPEN_MARKER: OnceLock<String> = OnceLock::new();
static INNER_MARKER: OnceLock<String> = OnceLock::new();
static CLOSE_MARKER: OnceLock<String> = OnceLock::new();
static CLASS_MARKER: OnceLock<String> = OnceLock::new();
static ID_MARKER: OnceLock<String> = OnceLock::new();
static BRACKETED_MARKER: OnceLock<String> = OnceLock::new();
static OPEN_INNER: OnceLock<String> = OnceLock::new();
static INNER_CLOSE: OnceLock<String> = OnceLock::new();

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
/// `classify_probe_reflection` can identify it without colliding with
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

fn open_inner() -> &'static str {
    OPEN_INNER
        .get_or_init(|| format!("{}{}", open_marker(), inner_marker()))
        .as_str()
}

fn inner_close() -> &'static str {
    INNER_CLOSE
        .get_or_init(|| format!("{}{}", inner_marker(), close_marker()))
        .as_str()
}

/// How the bracketed probe value reflected back. Captures the cases
/// where a server-side filter strips a prefix or suffix off the input
/// before echoing — those would be missed by a single-token
/// `text.contains(open_marker())` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeReflection {
    /// `OPEN + INNER + CLOSE` intact in the response.
    Full,
    /// `OPEN + INNER` present but `CLOSE` was stripped (suffix-strip filter).
    PrefixOnly,
    /// `INNER + CLOSE` present but `OPEN` was stripped (prefix-strip filter).
    SuffixOnly,
    /// Only `INNER` is in the response — both wraps were stripped or the
    /// server extracted a regex capture from the value.
    InnerOnly,
    /// Nothing matched.
    None,
}

impl ProbeReflection {
    /// Whether any of the four reflected forms was detected.
    pub(crate) fn detected(self) -> bool {
        !matches!(self, ProbeReflection::None)
    }
}

/// Layered substring check: cheap `contains(inner)` first; only escalate
/// to the longer composite checks when the inner anchor is present.
pub(crate) fn classify_probe_reflection(text: &str) -> ProbeReflection {
    let inner = inner_marker();
    if !text.contains(inner) {
        return ProbeReflection::None;
    }
    if text.contains(bracketed_marker()) {
        return ProbeReflection::Full;
    }
    if text.contains(open_inner()) {
        return ProbeReflection::PrefixOnly;
    }
    if text.contains(inner_close()) {
        return ProbeReflection::SuffixOnly;
    }
    ProbeReflection::InnerOnly
}

#[cfg(test)]
mod tests;
