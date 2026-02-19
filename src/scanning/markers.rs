use std::sync::OnceLock;

static OPEN_MARKER: OnceLock<String> = OnceLock::new();
static CLOSE_MARKER: OnceLock<String> = OnceLock::new();
static CLASS_MARKER: OnceLock<String> = OnceLock::new();
static ID_MARKER: OnceLock<String> = OnceLock::new();

fn short_id(seed: &str) -> String {
    let id = crate::utils::make_scan_id(seed);
    if id.len() >= 8 {
        id[..8].to_string()
    } else {
        id
    }
}

pub fn open_marker() -> &'static str {
    OPEN_MARKER
        .get_or_init(|| format!("dlx{}", short_id("open")))
        .as_str()
}

pub fn close_marker() -> &'static str {
    CLOSE_MARKER
        .get_or_init(|| format!("xld{}", short_id("close")))
        .as_str()
}

pub fn class_marker() -> &'static str {
    CLASS_MARKER
        .get_or_init(|| format!("dlx{}", short_id("class")))
        .as_str()
}

pub fn id_marker() -> &'static str {
    ID_MARKER
        .get_or_init(|| format!("dlx{}", short_id("id")))
        .as_str()
}
