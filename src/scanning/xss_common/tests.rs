use super::*;

#[test]
fn test_generate_dynamic_payloads_comment() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(payloads.iter().any(|p| {
        p.to_lowercase()
            .contains(&format!("<svg onload=alert(1) class={}>", cls))
    }));
}

#[test]
fn test_generate_dynamic_payloads_string_double() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("\"") && p.ends_with("\""))
    );
}

#[test]
fn test_generate_dynamic_payloads_attribute() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(payloads.iter().any(|p| {
        p.to_lowercase()
            .contains(&format!("<img src=x onerror=alert(1) class={}>", cls))
    }));
}

#[test]
fn test_generate_dynamic_payloads_attribute_none_has_autotriggers() {
    // The unquoted-attribute branch must include marker-carrying self-
    // triggering handlers (`autofocus`, `popover`, …) so reflections in
    // the "free attribute slot" position (e.g. `<div id='x' MARKER>`)
    // promote to V instead of stalling at R — `onabort=alert(1)` never
    // fires on a static div.
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
    let id = crate::scanning::markers::id_marker();
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("autofocus") && p.contains(&format!("id={}", id))),
        "expected an `autofocus`-carrying marker payload, got: {:?}",
        &payloads[..payloads.len().min(8)]
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("ontoggle") && p.contains("popover")),
        "expected an `ontoggle=… popover` payload (auto-fires on popover open)"
    );
}

#[test]
fn test_generate_dynamic_payloads_attribute_single_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::SingleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("'")));
}

#[test]
fn test_generate_dynamic_payloads_attribute_double_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
}

#[test]
fn test_generate_dynamic_payloads_url_attribute_prioritizes_protocols() {
    let payloads = generate_dynamic_payloads(&InjectionContext::AttributeUrl(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(
        payloads[0].starts_with("javascript:")
            || payloads[0].starts_with("Javascript:")
            || payloads[0].starts_with("jAvAsCrIpT:")
            || payloads[0].starts_with("data:text/html,"),
        "expected URL-bearing attribute payloads to start with protocol vectors, got {}",
        payloads[0]
    );
}

#[test]
fn test_generate_dynamic_payloads_javascript() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(None));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p == "alert(1)"));
    assert!(
        payloads
            .iter()
            .any(|p| p == "</script><script>alert(1)</script>")
    );
}

#[test]
fn test_generate_dynamic_payloads_javascript_single_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
        DelimiterType::SingleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("'")));
}

#[test]
fn test_generate_dynamic_payloads_javascript_double_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
        DelimiterType::DoubleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\"")));
}

#[test]
fn test_generate_dynamic_payloads_javascript_comment() {
    let payloads =
        generate_dynamic_payloads(&InjectionContext::Javascript(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("*/")));
    assert!(payloads.iter().any(|p| p.starts_with("\n")));
}

#[test]
fn test_generate_dynamic_payloads_javascript_backtick() {
    // Backtick (JS template literal) context must emit `${…}` expression-
    // injection payloads — `'`/`"` escapes don't work inside template
    // literals, so we'd silently miss reflections that land in `` `…` ``.
    let payloads =
        generate_dynamic_payloads(&InjectionContext::Javascript(Some(DelimiterType::Backtick)));
    assert!(!payloads.is_empty());
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("${") && p.ends_with('}')),
        "expected at least one `${{…}}` template-expression payload, got: {:?}",
        &payloads[..payloads.len().min(5)]
    );
}

#[test]
fn test_generate_dynamic_payloads_comment_single_quote() {
    // With the new representation, comment context is represented via Html(Some(Comment))
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
}

#[test]
fn test_generate_dynamic_payloads_comment_double_quote() {
    // With the new representation, comment context is represented via Html(Some(Comment))
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("-->")));
}

#[test]
fn test_generate_dynamic_payloads_html() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Html(None));
    assert!(!payloads.is_empty());
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(
        payloads
            .iter()
            .any(|p| { p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls) })
    );
}

#[test]
fn test_get_dynamic_payloads_basic() {
    let context = InjectionContext::Html(None);
    // Overrides base_args()'s `encoders: ["none"]` — this test asserts the
    // url/html encoded variants are emitted.
    let args = ScanArgs {
        encoders: vec!["url".to_string(), "html".to_string()],
        ..base_args()
    };

    let payloads = get_dynamic_payloads(&context, &args).unwrap();
    assert!(!payloads.is_empty());
    // Check that original payloads are included
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    assert!(
        payloads
            .iter()
            .any(|p| { p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls) })
    );
    // Check encoded versions
    assert!(payloads.iter().any(|p| p.contains("%3C")));
    assert!(payloads.iter().any(|p| p.contains("&#x")));
    // Check that safe-tag breakout payloads are included
    assert!(
        payloads.iter().any(|p| p.contains("</title>")),
        "should contain title breakout payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("</textarea>")),
        "should contain textarea breakout payloads"
    );
}

#[test]
fn protocol_scheme_survives_builtin_safety_cap_in_attribute_context() {
    // Regression for the xssmaze recall drop: the protocol/URL scheme family used
    // to be appended *after* the large html + attribute breakout block, pushing
    // `javascript:` thousands of payloads in. The built-in per-parameter safety
    // cap (issue #1155, DEFAULT_PAYLOAD_SAFETY_CAP) truncates this catalog, so on
    // contexts whose only verifier is a scheme reflected in a quoted attribute
    // value (e.g. a `<meta http-equiv=refresh content="0;url=…">` echo) the cap
    // evicted the scheme and the finding was lost. Front-loading the family keeps
    // it inside the cap. Cover both quote styles and the unquoted form.
    let cap = crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP;
    for delim in [
        Some(DelimiterType::DoubleQuote),
        Some(DelimiterType::SingleQuote),
        None,
    ] {
        let label = format!("{delim:?}");
        let context = InjectionContext::Attribute(delim);
        let args = base_args();
        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        let pos = payloads
            .iter()
            .position(|p| p.contains("javascript:"))
            .unwrap_or_else(|| {
                panic!("attribute catalog ({label}) must include a javascript: scheme")
            });
        assert!(
            pos < cap,
            "javascript: scheme at index {pos} must survive the built-in safety cap {cap} ({label})"
        );
    }
}

#[test]
fn test_get_dynamic_payloads_only_custom() {
    let context = InjectionContext::Html(None);
    let args = ScanArgs {
        custom_payload: Some("test_payloads.txt".to_string()),
        only_custom_payload: true,
        ..base_args()
    };

    // This will fail if file doesn't exist, but for test structure it's fine
    let result = get_dynamic_payloads(&context, &args);
    // In real test, we'd create a temp file
    assert!(result.is_err()); // Since file doesn't exist
}

#[test]
fn test_get_dynamic_payloads_no_encoders() {
    let context = InjectionContext::Html(None);
    // base_args() already sets encoders to ["none"].
    let args = base_args();

    let payloads = get_dynamic_payloads(&context, &args).unwrap();
    assert!(!payloads.is_empty());
    // Should only have original payloads, no encoded ones
    assert!(
        payloads
            .iter()
            .all(|p| !p.contains("%3C") && !p.contains("&#x"))
    );
}

// --- CSS injection context ---

#[test]
fn test_generate_dynamic_payloads_css_unquoted() {
    let payloads = generate_dynamic_payloads(&InjectionContext::Css(None));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("</style>")));
    assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
}

#[test]
fn test_generate_dynamic_payloads_css_single_quote() {
    let payloads =
        generate_dynamic_payloads(&InjectionContext::Css(Some(DelimiterType::SingleQuote)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("');")));
    assert!(payloads.iter().any(|p| p.contains("</style>")));
}

#[test]
fn test_generate_dynamic_payloads_css_double_quote() {
    let payloads =
        generate_dynamic_payloads(&InjectionContext::Css(Some(DelimiterType::DoubleQuote)));
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.starts_with("\");")));
    assert!(payloads.iter().any(|p| p.contains("</style>")));
}

#[test]
fn test_generate_dynamic_payloads_url_attribute_single_quote() {
    let payloads = generate_dynamic_payloads(&InjectionContext::AttributeUrl(Some(
        DelimiterType::SingleQuote,
    )));
    assert!(!payloads.is_empty());
    assert!(
        payloads[0].to_lowercase().starts_with("javascript:")
            || payloads[0].starts_with("data:text/html,"),
        "expected URL attribute payloads to lead with protocol vectors, got {}",
        payloads[0]
    );
}

// --- Adaptive payload generation ---

#[test]
fn test_generate_adaptive_payloads_filters_angle_brackets_in_attribute() {
    // When < and > are blocked in an attribute context, angle-bracket
    // payloads are dropped and self-triggering event handlers are added.
    let payloads = generate_adaptive_payloads(
        &InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        &['<', '>'],
        &[],
    );
    assert!(!payloads.is_empty());
    assert!(
        payloads.iter().any(|p| p.contains("autofocus")),
        "expected an autofocus event-handler payload"
    );
}

#[test]
fn test_generate_adaptive_payloads_no_specials_keeps_base() {
    let payloads = generate_adaptive_payloads(&InjectionContext::Html(None), &[], &[]);
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
}

// --- load_custom_payloads ---

fn tmp_payload_file(name: &str, content: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox-custom-payload-{}-{}-{}.txt",
        std::process::id(),
        nanos,
        name
    ));
    std::fs::write(&p, content).expect("write temp payload file");
    p
}

#[test]
fn test_load_custom_payloads_skips_comments_and_blanks() {
    let p = tmp_payload_file("ok", "payload-alpha\n# a comment\n\npayload-beta\n");
    let result = load_custom_payloads(p.to_str().unwrap()).unwrap();
    assert_eq!(
        result,
        vec!["payload-alpha".to_string(), "payload-beta".to_string()]
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn test_load_custom_payloads_strips_crlf() {
    let p = tmp_payload_file("crlf", "a\r\nb\r\n");
    let result = load_custom_payloads(p.to_str().unwrap()).unwrap();
    assert_eq!(result, vec!["a".to_string(), "b".to_string()]);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn test_load_custom_payloads_empty_after_strip_errors() {
    let p = tmp_payload_file("empty", "# only a comment\n\n");
    let err = load_custom_payloads(p.to_str().unwrap()).unwrap_err();
    assert!(err.to_string().contains("no usable lines"), "got: {}", err);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn test_load_custom_payloads_caches_by_path() {
    let p = tmp_payload_file("cache", "only-one\n");
    let path = p.to_str().unwrap().to_string();
    let first = load_custom_payloads(&path).unwrap();
    // Remove the file; a second call must hit the cache, not the disk.
    let _ = std::fs::remove_file(&p);
    let second = load_custom_payloads(&path).unwrap();
    assert_eq!(first, second);
    assert_eq!(second, vec!["only-one".to_string()]);
}

// --- custom alert value substitution in get_dynamic_payloads ---

fn base_args() -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        workers: 10,
        max_concurrent_targets: 10,
        encoders: vec!["none".to_string()],
        waf_min_confidence: 0.0,
        ..Default::default()
    }
}

#[test]
fn test_get_dynamic_payloads_custom_numeric_alert_value() {
    let args = ScanArgs {
        custom_alert_value: "9999".to_string(),
        ..base_args()
    };
    let payloads = get_dynamic_payloads(&InjectionContext::Html(None), &args).unwrap();
    assert!(
        payloads.iter().any(|p| p.contains("alert(9999)")),
        "custom numeric alert value must be substituted into payloads"
    );
}

#[test]
fn test_get_dynamic_payloads_custom_string_alert_value() {
    let args = ScanArgs {
        custom_alert_type: "str".to_string(),
        custom_alert_value: "xss".to_string(),
        ..base_args()
    };
    let payloads = get_dynamic_payloads(&InjectionContext::Html(None), &args).unwrap();
    assert!(
        payloads.iter().any(|p| p.contains("alert('xss')")),
        "string alert type must wrap the value in quotes"
    );
}

#[test]
fn generate_dynamic_payloads_is_memoized_and_stable() {
    // The per-context catalog is memoized (process-stable markers), so repeated
    // calls return identical payloads. The returned Vec is an independent clone,
    // so mutating it must not corrupt the cache for a later call.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let first = generate_dynamic_payloads(&ctx);
    let mut second = generate_dynamic_payloads(&ctx);
    assert!(!first.is_empty(), "attribute context should yield payloads");
    assert_eq!(first, second, "memoized catalog must be stable per context");
    second.clear();
    let third = generate_dynamic_payloads(&ctx);
    assert_eq!(
        first, third,
        "mutating a returned clone must not corrupt the cache"
    );
}
