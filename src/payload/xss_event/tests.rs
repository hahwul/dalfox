use super::*;

#[test]
fn test_attribute_payloads_non_empty() {
    let payloads = get_dynamic_xss_attribute_payloads();
    assert!(
        !payloads.is_empty(),
        "attribute payloads should not be empty"
    );
}

#[test]
fn test_attribute_payloads_contains_event_names() {
    let payloads = get_dynamic_xss_attribute_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("onerror=")),
        "should contain onerror= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onload=")),
        "should contain onload= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onmouseover=")),
        "should contain onmouseover= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onclick=")),
        "should contain onclick= variants"
    );
}

#[test]
fn test_js_payloads_exposed_and_contains_alert() {
    let js = crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL;
    assert!(!js.is_empty(), "JS payload list should not be empty");
    assert!(
        js.iter().any(|p| p.contains("alert(1)")),
        "should include at least one alert(1) primitive"
    );
}

/// The handler name is the discriminating axis (does the filter allow it? does
/// it auto-fire?); the JS primitive inside is not. Every per-parameter bound in
/// the scan samples a *prefix* of this catalog, so complete handler coverage has
/// to land in the first `names.len()` payloads — not `names.len() × 17` in.
#[test]
fn test_attribute_payloads_cover_every_handler_in_the_first_cycle() {
    let names = common_event_handler_names();
    let payloads = get_dynamic_xss_attribute_payloads();
    let prefix = &payloads[..names.len()];

    let seen: std::collections::HashSet<&str> = prefix
        .iter()
        .map(|p| p.split('=').next().expect("payload has a handler name"))
        .collect();
    assert_eq!(
        seen.len(),
        names.len(),
        "the first {} payloads must name {} distinct handlers, saw {}",
        names.len(),
        names.len(),
        seen.len()
    );
    for ev in names.iter() {
        assert!(
            seen.contains(*ev),
            "handler {ev} must be represented in the first cycle"
        );
    }
    // And the first cycle is one JS primitive across all handlers, not one
    // handler across all primitives (the inverted order this pins against).
    let first_js = prefix[0]
        .split_once('=')
        .expect("payload is name=js")
        .1
        .to_string();
    assert!(
        prefix.iter().all(|p| p.ends_with(&first_js)),
        "the first cycle must hold the handler axis open and the JS primitive fixed"
    );
}

/// The reorder must be a pure permutation — same payloads, same count, no
/// duplicates introduced or dropped.
#[test]
fn test_attribute_payloads_union_is_the_full_cross_product() {
    let names = common_event_handler_names();
    let js = crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL;
    let payloads = get_dynamic_xss_attribute_payloads();

    assert_eq!(
        payloads.len(),
        names.len() * js.len(),
        "catalog must be the full handler × primitive cross product"
    );
    let actual: std::collections::HashSet<&String> = payloads.iter().collect();
    assert_eq!(
        actual.len(),
        payloads.len(),
        "the cross product must contain no duplicates"
    );
    for ev in names.iter() {
        for j in js.iter() {
            let want = format!("{}={}", ev, j);
            assert!(
                actual.contains(&want),
                "cross-product member {want} must be present"
            );
        }
    }
}
