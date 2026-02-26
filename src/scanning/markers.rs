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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_id_returns_8_chars() {
        let id = short_id("test");
        assert_eq!(id.len(), 8, "short_id should be exactly 8 chars");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_open_marker_prefix_and_length() {
        let m = open_marker();
        assert!(m.starts_with("dlx"), "open_marker should start with 'dlx'");
        assert_eq!(m.len(), 11, "dlx + 8 hex chars = 11");
    }

    #[test]
    fn test_close_marker_prefix_and_length() {
        let m = close_marker();
        assert!(m.starts_with("xld"), "close_marker should start with 'xld'");
        assert_eq!(m.len(), 11, "xld + 8 hex chars = 11");
    }

    #[test]
    fn test_class_marker_prefix_and_length() {
        let m = class_marker();
        assert!(m.starts_with("dlx"), "class_marker should start with 'dlx'");
        assert_eq!(m.len(), 11);
    }

    #[test]
    fn test_id_marker_prefix_and_length() {
        let m = id_marker();
        assert!(m.starts_with("dlx"), "id_marker should start with 'dlx'");
        assert_eq!(m.len(), 11);
    }

    #[test]
    fn test_markers_are_distinct() {
        let open = open_marker();
        let close = close_marker();
        let class = class_marker();
        let id = id_marker();
        assert_ne!(open, close);
        assert_ne!(open, class);
        assert_ne!(open, id);
        assert_ne!(close, class);
        assert_ne!(close, id);
        assert_ne!(class, id);
    }

    #[test]
    fn test_markers_are_stable() {
        // OnceLock guarantees same value on repeated calls
        let a = open_marker();
        let b = open_marker();
        assert_eq!(a, b);
        assert!(std::ptr::eq(a, b), "should return same &'static str");
    }

    #[test]
    fn test_markers_are_css_safe() {
        // Class and id markers must be valid CSS identifiers (alphanumeric)
        for m in [class_marker(), id_marker()] {
            assert!(
                m.chars().all(|c| c.is_ascii_alphanumeric()),
                "marker '{}' must be alphanumeric for CSS selector usage",
                m
            );
        }
    }
}
