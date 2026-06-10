use super::*;

#[test]
fn test_all_non_empty() {
    assert!(!all().is_empty());
}

#[test]
fn test_every_gadget_has_template_and_label() {
    for g in all() {
        assert!(
            !g.template.is_empty(),
            "gadget {} has empty template",
            g.label
        );
        assert!(!g.label.is_empty(), "a gadget has an empty label");
        // A gadget must be reachable somehow: either via a host allowlist or
        // under strict-dynamic. An entry with neither would be dead.
        assert!(
            !g.host_patterns.is_empty() || g.strict_dynamic,
            "gadget {} is unreachable (no host patterns and not strict-dynamic)",
            g.label
        );
    }
}

#[test]
fn test_host_patterns_are_lowercase() {
    for g in all() {
        for p in g.host_patterns {
            assert_eq!(
                *p,
                p.to_ascii_lowercase(),
                "host pattern {p:?} for {} must be lowercase (matching lowercases the origin)",
                g.label
            );
        }
    }
}

#[test]
fn test_gadgets_for_host_matches_cdnjs() {
    let hits: Vec<_> = gadgets_for_host("https://cdnjs.cloudflare.com").collect();
    assert!(hits.iter().any(|g| g.template.contains("angular")));
}

#[test]
fn test_gadgets_for_host_matches_google_jsonp() {
    let hits: Vec<_> = gadgets_for_host("https://ajax.googleapis.com").collect();
    assert!(
        hits.iter()
            .any(|g| g.template.contains("google.com/complete/search"))
    );
}

#[test]
fn test_gadgets_for_host_matches_jquery_globaleval() {
    let hits: Vec<_> = gadgets_for_host("https://code.jquery.com").collect();
    assert!(hits.iter().any(|g| g.template.contains("globalEval")));
}

#[test]
fn test_gadgets_for_host_matches_jsdelivr() {
    let hits: Vec<_> = gadgets_for_host("https://cdn.jsdelivr.net").collect();
    assert!(hits.iter().any(|g| g.template.contains("jsdelivr.net")));
}

#[test]
fn test_gadgets_for_host_unknown_returns_empty() {
    let hits: Vec<_> = gadgets_for_host("https://example.com").collect();
    assert!(hits.is_empty());
}

#[test]
fn test_gadgets_for_host_is_case_insensitive() {
    let hits: Vec<_> = gadgets_for_host("HTTPS://CODE.JQUERY.COM").collect();
    assert!(!hits.is_empty());
}

#[test]
fn test_strict_dynamic_gadgets_non_empty() {
    let g: Vec<_> = strict_dynamic_gadgets().collect();
    assert!(!g.is_empty());
    assert!(g.iter().all(|x| x.strict_dynamic));
}

#[test]
fn test_strict_dynamic_includes_requirejs_and_document_write() {
    let g: Vec<_> = strict_dynamic_gadgets().collect();
    assert!(g.iter().any(|x| x.template.contains("data-main")));
    assert!(g.iter().any(|x| x.template.contains("document.write")));
}

#[test]
fn test_pure_dom_gadget_has_no_host_patterns() {
    // The document.write gadget must work regardless of host allowlist.
    let dw = all()
        .iter()
        .find(|g| g.template.contains("document.write"))
        .expect("document.write gadget present");
    assert!(dw.host_patterns.is_empty());
    assert!(dw.strict_dynamic);
}

#[test]
fn test_render_substitutes_markers() {
    let out = render("<x class={CLASS} id={ID}>", "CLS", "IDN");
    assert_eq!(out, "<x class=CLS id=IDN>");
    assert!(!out.contains("{CLASS}"));
    assert!(!out.contains("{ID}"));
}

#[test]
fn test_render_handles_repeated_markers() {
    let out = render("{CLASS}-{CLASS}-{ID}", "C", "I");
    assert_eq!(out, "C-C-I");
}

#[test]
fn test_no_template_leaves_unrendered_marker_after_render() {
    // Sanity: every embedded template, once rendered, has no leftover
    // reflection-marker placeholders (guards against a typo like `{CLAS}`).
    // Note: framework gadgets legitimately contain `{{ }}` interpolation, so we
    // check specifically for the `{CLASS}` / `{ID}` tokens, not bare braces.
    for g in all() {
        let rendered = render(g.template, "cm", "im");
        assert!(
            !rendered.contains("{CLASS}") && !rendered.contains("{ID}"),
            "gadget {} left an unrendered marker: {rendered}",
            g.label
        );
    }
}
