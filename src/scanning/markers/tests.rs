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

#[test]
fn test_inner_marker_distinct_prefix() {
    let inner = inner_marker();
    assert!(inner.starts_with("dlxmid"));
    assert!(!inner.contains(open_marker()));
    assert!(!inner.contains(close_marker()));
    // and vice-versa: open/close must not contain inner
    assert!(!open_marker().contains(inner));
    assert!(!close_marker().contains(inner));
}

#[test]
fn test_bracketed_marker_concatenation() {
    let bracketed = bracketed_marker();
    assert!(bracketed.starts_with(open_marker()));
    assert!(bracketed.ends_with(close_marker()));
    assert!(bracketed.contains(inner_marker()));
    // Legacy contains(open_marker()) check should still work
    assert!(bracketed.contains(open_marker()));
}

#[test]
fn fill_markers_substitutes_every_placeholder() {
    assert_eq!(
        fill_markers("<x class={CLASS} id={ID}>{CLASS}-{ID}"),
        format!(
            "<x class={c} id={i}>{c}-{i}",
            c = class_marker(),
            i = id_marker()
        )
    );
}

#[test]
fn probe_reflected_accepts_every_stripped_form() {
    // intact, close stripped, open stripped, both wraps stripped
    for body in [
        format!("<p>echo: {}</p>", bracketed_marker()),
        format!("<p>echo: {}{}</p>", open_marker(), inner_marker()),
        format!("<p>echo: {}{}</p>", inner_marker(), close_marker()),
        format!("<p>echo: {}</p>", inner_marker()),
    ] {
        assert!(probe_reflected(&body), "{body}");
    }
}

#[test]
fn probe_reflected_rejects_unrelated_body() {
    assert!(!probe_reflected("<p>nothing here</p>"));
    // A lone open marker without the inner anchor is not a reflection.
    assert!(!probe_reflected(&format!("<p>{} alone</p>", open_marker())));
}
