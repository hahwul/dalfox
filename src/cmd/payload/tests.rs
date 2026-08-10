use super::{
    PayloadArgs, awesome_alert_payloads, fetch_and_print_remote, functions_payloads,
    payload_list_json, print_summary, run_payload, special_chars_payloads, uri_scheme_payloads,
};
use crate::cmd::scan::ScanOutcome;
use serde_json::Value;

#[test]
fn test_uri_scheme_payloads_shape() {
    let payloads = uri_scheme_payloads();
    assert_eq!(payloads.len(), 5);
    assert!(payloads.iter().any(|p| p.starts_with("javascript:")));
    assert!(payloads.iter().all(|p| !p.is_empty()));
}

#[test]
fn test_curated_selector_lists_are_nonempty_and_clean() {
    for list in [
        special_chars_payloads(),
        functions_payloads(),
        awesome_alert_payloads(),
    ] {
        assert!(!list.is_empty());
        assert!(list.iter().all(|p| !p.is_empty()));
        // One entry per line: no embedded newlines.
        assert!(list.iter().all(|p| !p.contains('\n')));
    }
    // Sanity: the confirmable-sink list surfaces the canonical alert sink and a
    // filter-surviving variant; the PoC list renders the host.
    assert!(functions_payloads().contains(&"alert(1)"));
    assert!(functions_payloads().contains(&"window['alert'](1)"));
    assert!(awesome_alert_payloads().contains(&"alert(document.domain)"));
}

#[test]
fn test_run_payload_known_selectors_return_clean() {
    for selector in [
        "event-handlers",
        "useful-tags",
        "uri-scheme",
        "special-chars",
        "functions",
        "awesome-alert",
        "dom-clobbering",
        "mxss",
        "blind",
    ] {
        let outcome = run_payload(PayloadArgs {
            selector: Some(selector.to_string()),
            json: false,
        });
        assert_eq!(
            outcome,
            ScanOutcome::Clean,
            "selector {} should return Clean",
            selector
        );
    }
}

#[test]
fn test_run_payload_unknown_selector_returns_error() {
    let outcome = run_payload(PayloadArgs {
        selector: Some("not-a-selector".to_string()),
        json: false,
    });
    assert_eq!(outcome, ScanOutcome::Error);
}

#[test]
fn test_run_payload_none_returns_clean() {
    let outcome = run_payload(PayloadArgs {
        selector: None,
        json: false,
    });
    assert_eq!(outcome, ScanOutcome::Clean);
}

#[test]
fn test_run_payload_debug_paths_do_not_panic() {
    let prev = crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed);
    crate::DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);

    let _ = run_payload(PayloadArgs {
        selector: Some("event-handlers".to_string()),
        json: false,
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("useful-tags".to_string()),
        json: false,
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("uri-scheme".to_string()),
        json: false,
    });

    crate::DEBUG.store(prev, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn test_run_payload_remote_selectors_dispatch_without_network_after_unknown_init() {
    // Prime remote cache to empty so provider selectors avoid network fetch in tests.
    let _ = fetch_and_print_remote("__unknown_provider__", false);
    let _ = run_payload(PayloadArgs {
        selector: Some("payloadbox".to_string()),
        json: false,
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("portswigger".to_string()),
        json: false,
    });
}

#[test]
fn test_fetch_and_print_remote_unknown_provider_no_network_path() {
    let _ = fetch_and_print_remote("__unknown_provider__", false);
}

#[test]
fn test_print_summary_executes() {
    print_summary();
}

// --- JSON output (issue #1328) ---

#[test]
fn test_payload_list_json_produces_valid_array() {
    let out = payload_list_json(&[
        "javascript:alert(1)",
        "data:text/html;,<svg/onload=alert(1)>",
    ]);
    let value: Value = serde_json::from_str(&out).expect("output must be valid JSON");
    let arr = value
        .as_array()
        .expect("output must be a JSON array of strings");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0], Value::String("javascript:alert(1)".to_string()));
    assert_eq!(
        arr[1],
        Value::String("data:text/html;,<svg/onload=alert(1)>".to_string())
    );
}

#[test]
fn test_payload_list_json_empty_is_empty_array() {
    let out = payload_list_json::<&str>(&[]);
    assert_eq!(out, "[]");
    let value: Value = serde_json::from_str(&out).unwrap();
    assert!(value.as_array().unwrap().is_empty());
}

#[test]
fn test_run_payload_json_branch_returns_clean() {
    // Exercising the `--json` path for every static selector must not panic
    // and must still report a clean outcome (the JSON array goes to stdout).
    for selector in [
        "event-handlers",
        "useful-tags",
        "uri-scheme",
        "special-chars",
        "functions",
        "awesome-alert",
        "dom-clobbering",
        "mxss",
        "blind",
    ] {
        let outcome = run_payload(PayloadArgs {
            selector: Some(selector.to_string()),
            json: true,
        });
        assert_eq!(
            outcome,
            ScanOutcome::Clean,
            "selector {} --json should return Clean",
            selector
        );
    }
}
