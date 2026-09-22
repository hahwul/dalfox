use super::*;

#[test]
fn test_small_payloads_not_empty() {
    assert!(
        !XSS_JAVASCRIPT_PAYLOADS_SMALL.is_empty(),
        "small payloads list must not be empty"
    );
}

#[test]
fn test_full_payloads_not_empty() {
    assert!(
        !XSS_JAVASCRIPT_PAYLOADS.is_empty(),
        "full payloads list must not be empty"
    );
}

#[test]
fn test_no_empty_payloads() {
    for p in XSS_JAVASCRIPT_PAYLOADS_SMALL {
        assert!(!p.is_empty(), "small payload must not be empty string");
    }
    for p in XSS_JAVASCRIPT_PAYLOADS {
        assert!(!p.is_empty(), "full payload must not be empty string");
    }
}

#[test]
fn test_no_duplicate_small_payloads() {
    let mut seen = std::collections::HashSet::new();
    for p in XSS_JAVASCRIPT_PAYLOADS_SMALL {
        assert!(seen.insert(p), "duplicate small payload: {}", p);
    }
}

#[test]
fn test_no_duplicate_full_payloads() {
    let mut seen = std::collections::HashSet::new();
    for p in XSS_JAVASCRIPT_PAYLOADS {
        assert!(seen.insert(p), "duplicate full payload: {}", p);
    }
}

#[test]
fn test_payloads_contain_execution_primitives() {
    // At least one payload should reference alert, prompt, or confirm
    let has_exec = XSS_JAVASCRIPT_PAYLOADS
        .iter()
        .any(|p| p.contains("alert") || p.contains("prompt") || p.contains("confirm"));
    assert!(has_exec, "payloads should contain execution primitives");
}

#[test]
fn small_primitives_carry_no_angle_bracket() {
    // The SMALL list feeds *unquoted* HTML event-handler attributes
    // (`<img onerror=PRIMITIVE>`) and unquoted `javascript:` URL values. A `<`
    // or `>` inside such a primitive is fatal: `>` closes the tag early
    // (e.g. the `>` in an arrow function's `=>` truncates the handler to `(()=`
    // and drops the trailing marker), and `<` can start a stray tag. Keep every
    // SMALL primitive angle-free so it survives the unquoted-attribute contexts
    // it is dropped into. Richer primitives that need `<`/`>` (arrow functions,
    // template-string DOM sinks) belong in `XSS_JAVASCRIPT_PAYLOADS`, which is
    // only used in JS/script contexts where those bytes are safe.
    for p in XSS_JAVASCRIPT_PAYLOADS_SMALL {
        assert!(
            !p.contains('<') && !p.contains('>'),
            "SMALL primitive must be angle-free for unquoted-attribute use: {p:?}"
        );
    }
}
