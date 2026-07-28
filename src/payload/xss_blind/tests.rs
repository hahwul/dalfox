use super::*;

#[test]
fn test_blind_payloads_not_empty() {
    assert!(!XSS_BLIND_PAYLOADS.is_empty());
}

#[test]
fn test_blind_payloads_contain_callback_placeholder() {
    for p in XSS_BLIND_PAYLOADS {
        assert!(
            p.contains("{}"),
            "blind payload must contain '{{}}' callback placeholder: {}",
            p
        );
    }
}

#[test]
fn test_blind_payloads_load_callback_remotely() {
    // Every shape must reach the callback host: the `<script src>` vectors load
    // it as a remote script; the DOM-sink vector requests it from an `onerror`
    // handler. Both prove the injected markup executed when the callback fires.
    for p in XSS_BLIND_PAYLOADS {
        assert!(
            p.contains("<script") || p.contains("onerror="),
            "blind payload must load the callback remotely (script src or onerror): {}",
            p
        );
    }
}

/// At least one built-in must fire when the sink is `innerHTML`, where a
/// `<script src>` is inert — the case a stored DOM-XSS lands in. Regression
/// guard for issue #1238's follow-up.
#[test]
fn test_blind_payloads_cover_innerhtml_dom_sink() {
    assert!(
        XSS_BLIND_PAYLOADS
            .iter()
            .any(|p| p.contains("<img") && p.contains("onerror=")),
        "no blind payload fires in an innerHTML DOM sink"
    );
}

#[test]
fn test_blind_payloads_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for p in XSS_BLIND_PAYLOADS {
        assert!(seen.insert(p), "duplicate blind payload: {}", p);
    }
}
