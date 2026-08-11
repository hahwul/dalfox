use super::{
    KNOWN_SELECTORS, PayloadArgs, awesome_alert_payloads, fetch_and_print_remote,
    functions_payloads, print_summary, run_payload, special_chars_payloads, static_selector_counts,
    summary_block, uri_scheme_payloads,
};
use crate::cmd::scan::ScanOutcome;

const NETWORK_SELECTORS: [&str; 2] = ["payloadbox", "portswigger"];

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
    });
    assert_eq!(outcome, ScanOutcome::Error);
}

#[test]
fn test_run_payload_none_returns_clean() {
    let outcome = run_payload(PayloadArgs { selector: None });
    assert_eq!(outcome, ScanOutcome::Clean);
}

#[test]
fn test_run_payload_debug_paths_do_not_panic() {
    let prev = crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed);
    crate::DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);

    let _ = run_payload(PayloadArgs {
        selector: Some("event-handlers".to_string()),
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("useful-tags".to_string()),
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("uri-scheme".to_string()),
    });

    crate::DEBUG.store(prev, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn test_run_payload_remote_selectors_dispatch_without_network_after_unknown_init() {
    // Prime remote cache to empty so provider selectors avoid network fetch in tests.
    let _ = fetch_and_print_remote("__unknown_provider__");
    let _ = run_payload(PayloadArgs {
        selector: Some("payloadbox".to_string()),
    });
    let _ = run_payload(PayloadArgs {
        selector: Some("portswigger".to_string()),
    });
}

#[test]
fn test_fetch_and_print_remote_unknown_provider_no_network_path() {
    let _ = fetch_and_print_remote("__unknown_provider__");
}

#[test]
fn test_print_summary_executes() {
    print_summary();
}

#[test]
fn test_static_selector_counts_cover_every_local_selector() {
    let named: Vec<&str> = static_selector_counts().iter().map(|(s, _)| *s).collect();

    for selector in KNOWN_SELECTORS {
        if NETWORK_SELECTORS.contains(selector) {
            assert!(
                !named.contains(selector),
                "{} needs a fetch and must not be counted",
                selector
            );
        } else {
            assert!(named.contains(selector), "{} is missing a count", selector);
        }
    }
    assert_eq!(named.len(), KNOWN_SELECTORS.len() - NETWORK_SELECTORS.len());
}

#[test]
fn test_static_selector_counts_match_the_lists_they_describe() {
    let counts = static_selector_counts();
    let count_of = |selector: &str| -> usize {
        counts
            .iter()
            .find(|(s, _)| *s == selector)
            .unwrap_or_else(|| panic!("no count for {}", selector))
            .1
    };

    assert_eq!(
        count_of("event-handlers"),
        crate::payload::xss_event::common_event_handler_names().len()
    );
    assert_eq!(
        count_of("useful-tags"),
        crate::payload::xss_html::useful_html_tag_names().len()
    );
    assert_eq!(count_of("uri-scheme"), uri_scheme_payloads().len());
    assert_eq!(count_of("special-chars"), special_chars_payloads().len());
    assert_eq!(count_of("functions"), functions_payloads().len());
    assert_eq!(count_of("awesome-alert"), awesome_alert_payloads().len());
    assert_eq!(
        count_of("dom-clobbering"),
        crate::payload::get_dom_clobbering_payloads().len()
    );
    assert_eq!(count_of("mxss"), crate::payload::get_mxss_payloads().len());
    assert_eq!(count_of("blind"), crate::payload::XSS_BLIND_PAYLOADS.len());

    // Distinct lists, so a copy-pasted accessor would collapse two counts.
    assert_ne!(count_of("special-chars"), count_of("functions"));
    assert!(counts.iter().all(|(_, n)| *n > 0));
}

#[test]
fn test_summary_block_renders_a_line_per_static_selector() {
    let rendered = summary_block();

    assert!(rendered.starts_with("Summary:\n"));
    assert!(rendered.contains(&format!(
        "- Canonical JavaScript payloads: {}\n",
        crate::payload::XSS_JAVASCRIPT_PAYLOADS.len()
    )));
    for (selector, count) in static_selector_counts() {
        assert!(
            rendered.contains(&format!("- {}: {}\n", selector, count)),
            "summary is missing the {} count",
            selector
        );
    }
    for selector in NETWORK_SELECTORS {
        assert!(
            !rendered.contains(selector),
            "{} must not appear in the summary counts",
            selector
        );
    }
}
