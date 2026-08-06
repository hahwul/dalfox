use super::*;
use crate::cmd::scan::ScanArgs;
use crate::target_parser::parse_target;
use std::sync::Arc;
use tokio::sync::Semaphore;

// Mock mining function for testing
fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
    // Simulate adding a reflection param
    _target.reflection_params.push(Param {
        name: "test_param".to_string(),
        value: "test_value".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });
}

#[test]
fn test_analyze_parameters_with_mock_mining() {
    let mut target = parse_target("https://example.com").unwrap();
    let args = ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        workers: 10,
        max_concurrent_targets: 10,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    // Mock mining instead of real mining
    mock_mine_parameters(&mut target, &args);

    assert!(!target.reflection_params.is_empty());
    assert_eq!(target.reflection_params[0].name, "test_param");
    assert_eq!(target.reflection_params[0].value, "test_value");
    assert_eq!(target.reflection_params[0].location, Location::Query);
    assert_eq!(
        target.reflection_params[0].injection_context,
        Some(InjectionContext::Html(None))
    );
}

#[test]
fn test_analyze_parameters_skip_mining() {
    let target = parse_target("https://example.com").unwrap();
    let _args = ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        skip_mining: true, // Skip mining
        skip_mining_dict: false,
        workers: 10,
        max_concurrent_targets: 10,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    // Even with mock, if skip_mining is true, no params should be added
    // But since we call mock manually, this tests the logic flow
    assert!(target.reflection_params.is_empty());
}

#[test]
fn test_probe_body_params_mock() {
    let mut target = parse_target("https://example.com").unwrap();
    let _args = ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        data: Some("key1=value1&key2=value2".to_string()),
        method: "POST".to_string(),
        workers: 10,
        max_concurrent_targets: 10,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    // Mock body param reflection
    target.reflection_params.push(Param {
        name: "key1".to_string(),
        value: "dalfox".to_string(),
        location: Location::Body,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });

    assert!(!target.reflection_params.is_empty());
    assert_eq!(target.reflection_params[0].location, Location::Body);
}

#[test]
fn test_check_header_discovery_mock() {
    let mut target = parse_target("https://example.com").unwrap();
    target
        .headers
        .push(("X-Test".to_string(), "value".to_string()));

    // Mock header discovery
    target.reflection_params.push(Param {
        name: "X-Test".to_string(),
        value: "dalfox".to_string(),
        location: Location::Header,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });

    assert!(!target.reflection_params.is_empty());
    assert_eq!(target.reflection_params[0].location, Location::Header);
}

#[test]
fn test_check_cookie_discovery_mock() {
    let mut target = parse_target("https://example.com").unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    // Mock cookie discovery
    target.reflection_params.push(Param {
        name: "session".to_string(),
        value: "dalfox".to_string(),
        location: Location::Header, // Cookies are sent in Header
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    });

    assert!(!target.reflection_params.is_empty());
    assert_eq!(target.reflection_params[0].location, Location::Header);
}

#[test]
fn test_cookie_from_raw() {
    let mut target = parse_target("https://example.com").unwrap();
    let args = ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        cookie_from_raw: Some("examples/sample_request.txt".to_string()),
        workers: 10,
        max_concurrent_targets: 10,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    // Simulate cookie loading
    if let Some(path) = &args.cookie_from_raw
        && let Ok(content) = std::fs::read_to_string(path)
    {
        for line in content.lines() {
            if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                for cookie in cookie_line.split("; ") {
                    if let Some((name, value)) = cookie.split_once('=') {
                        target
                            .cookies
                            .push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }
    }

    assert!(!target.cookies.is_empty());
    assert_eq!(target.cookies.len(), 2);
    assert_eq!(
        target.cookies[0],
        ("session".to_string(), "abc".to_string())
    );
    assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
}

#[test]
fn test_cookie_from_raw_no_file() {
    let mut target = parse_target("https://example.com").unwrap();
    let args = ScanArgs {
        insecure: Some(true),
        format: "json".to_string(),
        targets: vec!["https://example.com".to_string()],
        cookie_from_raw: Some("nonexistent.txt".to_string()),
        workers: 10,
        max_concurrent_targets: 10,
        waf_min_confidence: 0.0,
        ..Default::default()
    };

    // Simulate cookie loading - file doesn't exist
    if let Some(path) = &args.cookie_from_raw
        && let Ok(content) = std::fs::read_to_string(path)
    {
        for line in content.lines() {
            if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                for cookie in cookie_line.split("; ") {
                    if let Some((name, value)) = cookie.split_once('=') {
                        target
                            .cookies
                            .push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }
    }

    // Should remain empty since file doesn't exist
    assert!(target.cookies.is_empty());
}

#[test]
fn test_cookie_from_raw_malformed() {
    let mut target = parse_target("https://example.com").unwrap();
    let malformed_content = "Cookie: session=abc; invalid_cookie; user=123";

    for line in malformed_content.lines() {
        if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
            for cookie in cookie_line.split("; ") {
                if let Some((name, value)) = cookie.split_once('=') {
                    target
                        .cookies
                        .push((name.trim().to_string(), value.trim().to_string()));
                }
            }
        }
    }

    // Should parse valid cookies, skip invalid ones
    assert_eq!(target.cookies.len(), 2);
    assert_eq!(
        target.cookies[0],
        ("session".to_string(), "abc".to_string())
    );
    assert_eq!(target.cookies[1], ("user".to_string(), "123".to_string()));
}

#[test]
fn test_filter_params_by_name_and_type() {
    let mut target = parse_target("https://example.com").unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    let params = vec![
        Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Body,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "id".to_string(),
            value: "123".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "session".to_string(),
            value: "abc".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
    ];

    // Filter by name only
    let filtered = filter_params(params.clone(), &["sort".to_string()], &target);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|p| p.name == "sort"));

    // Filter by name and type
    let filtered = filter_params(params.clone(), &["sort:query".to_string()], &target);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "sort");
    assert_eq!(filtered[0].location, Location::Query);

    // Filter by cookie type
    let filtered = filter_params(params.clone(), &["session:cookie".to_string()], &target);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "session");
    assert_eq!(filtered[0].location, Location::Header);

    // No match
    let filtered = filter_params(params.clone(), &["nonexistent".to_string()], &target);
    assert_eq!(filtered.len(), 0);
}

#[test]
fn test_filter_params_multiple_filters() {
    let mut target = parse_target("https://example.com").unwrap();
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    let params = vec![
        Param {
            name: "sort".to_string(),
            value: "asc".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "id".to_string(),
            value: "123".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
        Param {
            name: "session".to_string(),
            value: "abc".to_string(),
            location: Location::Header,
            injection_context: Some(InjectionContext::Html(None)),
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        },
    ];

    // Multiple filters
    let filtered = filter_params(
        params.clone(),
        &["sort".to_string(), "id".to_string()],
        &target,
    );
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().any(|p| p.name == "sort"));
    assert!(filtered.iter().any(|p| p.name == "id"));
}

#[test]
fn test_filter_params_empty_filters() {
    let target = parse_target("https://example.com").unwrap();
    let params = vec![Param {
        name: "sort".to_string(),
        value: "asc".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }];

    // Empty filters should return all params
    let filtered = filter_params(params.clone(), &[], &target);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_filter_params_invalid_filter_format() {
    let target = parse_target("https://example.com").unwrap();
    let params = vec![Param {
        name: "sort".to_string(),
        value: "asc".to_string(),
        location: Location::Query,
        injection_context: Some(InjectionContext::Html(None)),
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }];

    // Invalid filter format (too many colons) should be treated as name only
    let filtered = filter_params(params.clone(), &["sort:query:extra".to_string()], &target);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "sort");
}

fn bare_param(name: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: String::new(),
        location,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

#[test]
fn test_ensure_explicit_params_synthesizes_missing_targets() {
    let target = parse_target("https://example.com/?present=1").unwrap();
    // Discovery seeded only `present`; the other explicit targets were dropped
    // (e.g. a --skip-* flag suppressed their phase).
    let mut params = vec![bare_param("present", Location::Query)];
    let specs = vec![
        "present:query".to_string(),      // already seeded → not duplicated
        "id:query".to_string(),           // synthesized
        "X-Api-Token:header".to_string(), // synthesized
        "sid:cookie".to_string(),         // synthesized (Header location)
    ];
    ensure_explicit_params(&mut params, &specs, &target);

    assert_eq!(
        params.iter().filter(|p| p.name == "present").count(),
        1,
        "existing target must not be duplicated"
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "id" && p.location == Location::Query)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "X-Api-Token" && p.location == Location::Header)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "sid" && p.location == Location::Header)
    );
}

#[test]
fn test_ensure_explicit_params_skips_unsynthesizable_typed_specs() {
    let target = parse_target("https://example.com").unwrap();
    let mut params: Vec<Param> = vec![];
    // path (positional) and fragment (never scanned) still cannot be synthesized
    let specs = vec!["seg:path".to_string(), "h:fragment".to_string()];
    ensure_explicit_params(&mut params, &specs, &target);
    assert!(
        params.is_empty(),
        "path / fragment specs must not be synthesized, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[test]
fn test_ensure_explicit_params_bare_name_defaults_to_query() {
    // Fast-smoke recipe: -p q --skip-discovery must still seed the param.
    let target = parse_target("https://example.com/").unwrap();
    let mut params: Vec<Param> = vec![];
    ensure_explicit_params(&mut params, &["q".to_string()], &target);
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "q");
    assert_eq!(params[0].location, Location::Query);
}

#[test]
fn test_ensure_explicit_params_bare_name_infers_from_url_query() {
    let target = parse_target("https://example.com/search?q=test&lang=en").unwrap();
    let mut params: Vec<Param> = vec![];
    ensure_explicit_params(&mut params, &["q".to_string()], &target);
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].location, Location::Query);
}

#[test]
fn test_ensure_explicit_params_bare_name_infers_body() {
    let mut target = parse_target("https://example.com/submit").unwrap();
    target.data = Some("user=alice&token=abc".to_string());
    let mut params: Vec<Param> = vec![];
    ensure_explicit_params(&mut params, &["token".to_string()], &target);
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "token");
    assert_eq!(params[0].location, Location::Body);
}

#[test]
fn test_ensure_explicit_params_bare_name_does_not_duplicate_existing() {
    let target = parse_target("https://example.com/?q=1").unwrap();
    let mut params = vec![bare_param("q", Location::Query)];
    ensure_explicit_params(&mut params, &["q".to_string()], &target);
    assert_eq!(
        params.len(),
        1,
        "bare name must not duplicate a filtered match"
    );
}

#[test]
fn test_unresolved_explicit_param_specs_reports_path_fragment() {
    let target = parse_target("https://example.com/").unwrap();
    let params: Vec<Param> = vec![];
    let missing = unresolved_explicit_param_specs(
        &params,
        &[
            "q".to_string(),
            "seg:path".to_string(),
            "h:fragment".to_string(),
        ],
        &target,
    );
    // After synthesis "q" would be present; unresolved is for post-ensure checks.
    // With empty params, all three are missing.
    assert!(missing.iter().any(|s| s == "seg:path"));
    assert!(missing.iter().any(|s| s == "h:fragment"));
    assert!(missing.iter().any(|s| s == "q"));
}

#[test]
fn test_ensure_sxss_candidate_params_seeds_query_and_body_inputs() {
    // Regression: under --sxss the write endpoint does not echo, so every
    // discovery probe (which gates on immediate-response reflection) kept zero
    // params and the scan reported clean without ever fetching --sxss-url.
    // The request's own declared inputs must be seeded as candidates.
    let mut target = parse_target("https://example.com/store?msg=1&other=2").unwrap();
    target.data = Some("comment=hi&author=bob".to_string());
    let mut args = default_scan_args();
    args.sxss = true;
    args.data = Some("comment=hi&author=bob".to_string());

    let mut params: Vec<Param> = vec![];
    ensure_sxss_candidate_params(&mut params, &target, &args);

    for (name, loc) in [
        ("msg", Location::Query),
        ("other", Location::Query),
        ("comment", Location::Body),
        ("author", Location::Body),
    ] {
        assert!(
            params.iter().any(|p| p.name == name && p.location == loc),
            "stored-XSS candidate {name} ({loc:?}) must be seeded, got {:?}",
            params
                .iter()
                .map(|p| (&p.name, &p.location))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_ensure_sxss_candidate_params_preserves_discovered_metadata() {
    // A param discovery *did* find (inline-echoing stored sink) carries probed
    // specials / injection context. Seeding must not shadow it with a bare
    // duplicate, which would both double the scan cost and lose the metadata.
    let target = parse_target("https://example.com/store?msg=1").unwrap();
    let mut args = default_scan_args();
    args.sxss = true;

    let mut discovered = bare_param("msg", Location::Query);
    discovered.valid_specials = Some(vec!['<', '>']);
    let mut params = vec![discovered];
    ensure_sxss_candidate_params(&mut params, &target, &args);

    assert_eq!(
        params.iter().filter(|p| p.name == "msg").count(),
        1,
        "discovered param must not be duplicated by seeding"
    );
    assert_eq!(
        params[0].valid_specials.as_deref(),
        Some(['<', '>'].as_slice()),
        "probe metadata must survive seeding"
    );
}

#[test]
fn test_ensure_sxss_candidate_params_honours_ignore_param() {
    let target = parse_target("https://example.com/store?msg=1&csrf=abc").unwrap();
    let mut args = default_scan_args();
    args.sxss = true;
    args.ignore_param = vec!["csrf".to_string()];

    let mut params: Vec<Param> = vec![];
    ensure_sxss_candidate_params(&mut params, &target, &args);

    assert!(params.iter().any(|p| p.name == "msg"));
    assert!(
        !params.iter().any(|p| p.name == "csrf"),
        "--ignore-param must still exclude a seeded stored-XSS candidate"
    );
}

#[test]
fn test_ensure_sxss_candidate_params_seeds_json_body_keys() {
    let target = parse_target("https://example.com/api/comment").unwrap();
    let mut args = default_scan_args();
    args.sxss = true;
    args.data = Some(r#"{"body":"hi","author":"bob"}"#.to_string());

    let mut params: Vec<Param> = vec![];
    ensure_sxss_candidate_params(&mut params, &target, &args);

    assert!(
        params
            .iter()
            .any(|p| p.name == "body" && p.location == Location::JsonBody)
    );
    assert!(
        params
            .iter()
            .any(|p| p.name == "author" && p.location == Location::JsonBody)
    );
}

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec!["http://127.0.0.1:0".to_string()],
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        skip_discovery: true,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 1,
        silence: true,
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
        encoders: vec![
            "url".to_string(),
            "html".to_string(),
            "2url".to_string(),
            "base64".to_string(),
        ],
        waf_min_confidence: 0.0,
        ..Default::default()
    }
}

fn probe_target() -> crate::target_parser::Target {
    let mut target = parse_target("http://127.0.0.1:0/a/b?x=1").unwrap();
    target.method = "POST".to_string();
    target.data = Some("foo=bar&session=orig".to_string());
    target
        .headers
        .push(("X-Test".to_string(), "header-value".to_string()));
    target
        .cookies
        .push(("session".to_string(), "cookie-value".to_string()));
    target.user_agent = Some("DalfoxTest/1.0".to_string());
    target
}

fn probe_param(name: &str, location: Location) -> Param {
    Param {
        name: name.to_string(),
        value: "v".to_string(),
        location,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    }
}

#[test]
fn test_classify_special_chars_and_encoded_variants() {
    let body = "/\\\\'{}<>\"()";
    let (valid, invalid) = classify_special_chars(body);
    assert!(valid.contains(&'/'));
    assert!(valid.contains(&'\\'));
    assert!(valid.contains(&'\''));
    assert!(valid.contains(&'<'));
    assert!(!invalid.is_empty());

    assert!(encoded_variants('<').contains(&"&lt;"));
    assert!(encoded_variants('"').contains(&"&quot;"));
    assert!(encoded_variants('x').is_empty());
}

#[test]
fn test_extract_reflected_segment_finds_marker_bounds() {
    let body = format!(
        "aaa{}middle{}bbb",
        crate::scanning::markers::open_marker(),
        crate::scanning::markers::close_marker()
    );
    let seg = extract_reflected_segment(&body).expect("segment should exist");
    assert_eq!(seg, "middle");
}

#[tokio::test]
async fn test_active_probe_param_query_path_failure_paths() {
    let target = probe_target();
    let semaphore = Arc::new(Semaphore::new(8));

    let query_res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        semaphore.clone(),
    )
    .await;
    assert!(query_res.valid_specials.as_ref().is_some());
    assert!(
        query_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let path_res = active_probe_param(
        &target,
        probe_param("path_segment_1", Location::Path),
        semaphore,
    )
    .await;
    assert!(path_res.valid_specials.as_ref().is_some());
    assert!(
        path_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );
}

#[tokio::test]
async fn test_active_probe_param_body_header_json_failure_paths() {
    let mut target = probe_target();
    target.data = Some("{\"json_key\":\"v\"}".to_string());
    let semaphore = Arc::new(Semaphore::new(8));

    let body_res = active_probe_param(
        &target,
        probe_param("foo", Location::Body),
        semaphore.clone(),
    )
    .await;
    assert!(body_res.valid_specials.as_ref().is_some());
    assert!(
        body_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let header_cookie_res = active_probe_param(
        &target,
        probe_param("session", Location::Header),
        semaphore.clone(),
    )
    .await;
    assert!(header_cookie_res.valid_specials.as_ref().is_some());
    assert!(
        header_cookie_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let header_plain_res = active_probe_param(
        &target,
        probe_param("X-Test", Location::Header),
        semaphore.clone(),
    )
    .await;
    assert!(header_plain_res.valid_specials.as_ref().is_some());
    assert!(
        header_plain_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );

    let json_res = active_probe_param(
        &target,
        probe_param("json_key", Location::JsonBody),
        semaphore,
    )
    .await;
    assert!(json_res.valid_specials.as_ref().is_some());
    assert!(
        json_res
            .invalid_specials
            .as_ref()
            .expect("invalid set")
            .len()
            >= SPECIAL_PROBE_CHARS.len()
    );
}

#[tokio::test]
async fn test_analyze_parameters_with_skip_flags_finishes_cleanly() {
    let mut target = parse_target("http://127.0.0.1:0").unwrap();
    target.workers = 1;
    let args = default_scan_args();

    analyze_parameters(&mut target, &args, None).await;
    assert!(target.reflection_params.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// Pure char-classification helpers (cases not covered above)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_extract_reflected_segment_none_without_markers() {
    // The no-marker branch (early `?` returns) wasn't exercised before.
    assert_eq!(extract_reflected_segment("no markers here"), None);
}

#[test]
fn test_char_reflected_in_segment_detects_raw_encoded_and_percent() {
    // Raw character.
    assert!(char_reflected_in_segment("abc<def", '<'));
    // HTML-entity variant.
    assert!(char_reflected_in_segment("abc&lt;def", '<'));
    // Percent-encoded (case-insensitive): '<' == 0x3C. Both `%3c` and `%3C`
    // must match (the allocation-free CI scan replaced a per-char uppercase
    // copy of the whole segment).
    assert!(char_reflected_in_segment("abc%3cdef", '<'));
    assert!(char_reflected_in_segment("abc%3Cdef", '<'));
    // Absent entirely.
    assert!(!char_reflected_in_segment("abcdef", '<'));
}

#[test]
fn test_contains_ascii_ci() {
    assert!(contains_ascii_ci("abc%3Cdef", "%3c"));
    assert!(contains_ascii_ci("abc%3cdef", "%3C"));
    assert!(contains_ascii_ci("anything", ""));
    assert!(!contains_ascii_ci("ab", "abc")); // needle longer than haystack
    assert!(!contains_ascii_ci("abcdef", "%3c"));
    // Boundary match at the very end.
    assert!(contains_ascii_ci("xy%3C", "%3c"));
}

// ===== Issue #1072: quote-escape classification =====

/// Build the reflected segment of an escape probe: `A <dq> B <sq> C <bs> D`,
/// optionally wrapped in surrounding noise to prove the slice extraction is
/// robust. `bs` is the region for the lone backslash (`\` raw, `\\` doubled).
fn esc_segment(dq: &str, sq: &str, bs: &str, prefix: &str, suffix: &str) -> String {
    format!("{prefix}{ESC_SENT_A}{dq}{ESC_SENT_B}{sq}{ESC_SENT_C}{bs}{ESC_SENT_D}{suffix}")
}

#[test]
fn classify_escaped_quotes_intact_is_empty() {
    // No escaping: quotes raw, backslash raw.
    let seg = esc_segment("\"", "'", "\\", "", "");
    assert!(classify_escaped_quotes(&seg).is_empty());
}

#[test]
fn classify_escaped_quotes_detects_both() {
    // Classic JS-string-escaping server: `\"` and `\'`, backslash passes raw.
    let seg = esc_segment("\\\"", "\\'", "\\", "", "");
    let r = classify_escaped_quotes(&seg);
    assert!(r.contains(&'"'), "expected \" escaped, got {r:?}");
    assert!(r.contains(&'\''), "expected ' escaped, got {r:?}");
}

#[test]
fn classify_escaped_quotes_detects_only_double() {
    // Only the double quote is escaped (single reflected raw).
    let seg = esc_segment("\\\"", "'", "\\", "<div id=out>", "</div>");
    assert_eq!(classify_escaped_quotes(&seg), vec!['"']);
}

#[test]
fn classify_escaped_quotes_rejects_doubled_backslash_server() {
    // A server that ALSO escapes backslashes (`\` -> `\\`) would re-escape our
    // injected `\`, neutralising the `\";…` bypass — so even though the quotes
    // come back `\"`/`\'`, we must NOT report them escaped.
    let seg = esc_segment("\\\"", "\\'", "\\\\", "", "");
    assert!(
        classify_escaped_quotes(&seg).is_empty(),
        "must not flag escaped when backslash is doubled"
    );
}

#[test]
fn classify_escaped_quotes_even_backslash_run_is_a_real_quote() {
    // `\\"` is a literal backslash followed by a *real* closing quote (even run),
    // not an escaped quote — must not be flagged.
    let seg = esc_segment("\\\\\"", "'", "\\", "", "");
    assert!(!classify_escaped_quotes(&seg).contains(&'"'));
}

#[test]
fn classify_escaped_quotes_missing_sentinels_is_empty() {
    // If the segment doesn't contain the sentinels (probe not reflected), no
    // false positives.
    assert!(classify_escaped_quotes("nothing here").is_empty());
}

#[test]
fn escape_probe_value_has_sentinels_and_quotes() {
    let p = escape_probe_value();
    assert!(p.contains(ESC_SENT_A) && p.contains(ESC_SENT_D));
    assert!(p.contains('"') && p.contains('\'') && p.contains('\\'));
}

#[test]
fn escaped_quotes_from_response_extracts_classifies_and_filters() {
    use crate::scanning::markers::{close_marker, open_marker};
    // A full response with the escape probe reflected inside a JS string, both
    // quotes server-escaped (`\"`, `\'`) and the lone backslash passing raw.
    let body = format!(
        "<html><script>var x=\"{}{}\\\"{}\\'{}\\{}{}\";</script></html>",
        open_marker(),
        ESC_SENT_A,
        ESC_SENT_B,
        ESC_SENT_C,
        ESC_SENT_D,
        close_marker()
    );
    // Both quotes valid → both reported escaped.
    let both = escaped_quotes_from_response(&body, &['"', '\'']).unwrap();
    assert!(both.contains(&'"') && both.contains(&'\''), "got {both:?}");
    // Filtered to the valid set: only `"`.
    assert_eq!(
        escaped_quotes_from_response(&body, &['"']).unwrap(),
        vec!['"']
    );
    // No probe reflected at all → None (distinct from an empty vec).
    assert!(escaped_quotes_from_response("<html>nothing</html>", &['"']).is_none());
}

#[test]
fn quote_is_backslash_escaped_counts_odd_run() {
    assert!(quote_is_backslash_escaped("\\\"", '"')); // \"  -> escaped (1)
    assert!(!quote_is_backslash_escaped("\"", '"')); // "    -> raw (0)
    assert!(!quote_is_backslash_escaped("\\\\\"", '"')); // \\" -> real quote (2)
    assert!(quote_is_backslash_escaped("\\\\\\\"", '"')); // \\\" -> escaped (3)
}

#[test]
fn slice_between_extracts_region() {
    assert_eq!(slice_between("aXXbYYc", "XX", "YY"), Some("b"));
    assert_eq!(slice_between("aXXbYYc", "ZZ", "YY"), None);
    assert_eq!(slice_between("aXXb", "XX", "YY"), None);
}

/// Integration: an AWS-WAF-style inspection-window facade. Only the first 100
/// bytes of the value are inspected; a `<`/`>` there blocks the whole request
/// (403, no reflection), but the full value reflects raw — so a vector pushed
/// past the window slips through (xssmaze `waf-facade/level2`). `active_probe_param`
/// must detect this via the window-overflow probe: reclassify the angle
/// brackets as valid and record the `wafpad` pre-encoding so payloads are sent
/// past the window.
#[tokio::test]
async fn active_probe_detects_inspection_window_waf_and_sets_wafpad() {
    use axum::{Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn window_waf(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        let window: String = v.chars().take(100).collect();
        if window.contains('<') || window.contains('>') {
            // Branded block page — note it does NOT echo the value.
            (
                StatusCode::FORBIDDEN,
                "<h1>403 ERROR</h1> Request blocked by AWS WAF".to_string(),
            )
        } else {
            // Reflects the full value raw (markers + specials intact).
            (
                StatusCode::OK,
                format!("<html><body><div class='results'>{v}</div></body></html>"),
            )
        }
    }

    let app = Router::new().route("/cat", get(window_waf));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_eq!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "size-limited inspection window should set the window-pad pre-encoding"
    );
    let valid = res.valid_specials.clone().unwrap_or_default();
    assert!(
        valid.contains(&'<') && valid.contains(&'>'),
        "angle brackets must be reclassified valid once pushed past the window; got {valid:?}"
    );
}

/// Counter-case: a WAF that blocks `<`/`>` *anywhere* in the value (no size
/// window) must NOT be mistaken for an inspection-window WAF. The batched probe
/// is blocked (None arm), the window-overflow probe is *also* blocked (padding
/// can't help), so `window_overflow_probe` returns `None` and no `wafpad` is
/// set — guarding against a false bypass.
#[tokio::test]
async fn active_probe_does_not_set_wafpad_for_position_independent_block() {
    use axum::{Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn block_anywhere(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        // Inspect the WHOLE value, not a leading window — padding never helps.
        if v.contains('<') || v.contains('>') {
            (StatusCode::FORBIDDEN, "<h1>403</h1> blocked".to_string())
        } else {
            (
                StatusCode::OK,
                format!("<html><body><div class='results'>{v}</div></body></html>"),
            )
        }
    }

    let app = Router::new().route("/cat", get(block_anywhere));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_ne!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "genuine filtering (stripping past any window) must not be treated as window-limited"
    );
}

/// Counter-case: a server that strips a fixed PREFIX (first 4 chars) and echoes
/// the rest. The batched probe's open-marker prefix is eaten, so the segment
/// isn't found (None arm) — but this is *partial reflection*, not a block: the
/// close marker survives. The genuine-block guard must skip the window-overflow
/// probe here, so no `wafpad` is set (a benign pad would otherwise be absorbed
/// by the strip and falsely look like a window bypass).
#[tokio::test]
async fn active_probe_does_not_set_wafpad_for_prefix_strip() {
    use axum::{Router, extract::Query, response::IntoResponse, routing::get};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn strip_prefix4(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {
        let v = p.get("x").cloned().unwrap_or_default();
        // Drop the first 4 chars, echo the rest raw — partial reflection.
        let echoed: String = v.chars().skip(4).collect();
        format!("<html><body><div class='results'>{echoed}</div></body></html>")
    }

    let app = Router::new().route("/cat", get(strip_prefix4));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/cat?x=1")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("x", Location::Query),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    assert_ne!(
        res.pre_encoding.as_deref(),
        Some("wafpad"),
        "a fixed-prefix-stripping server (partial reflection) must not be mistaken for a window WAF"
    );
}

/// Path regression: the dense batched special-char probe injected into a URL
/// path segment fails to reflect on a perfectly permissive server, because the
/// `/` (and other path-structural chars) in the concatenated payload reshape
/// the request into a different/non-existent route. The probe must NOT conclude
/// "all specials invalid" from that artifact — it must fall back to per-char
/// probing, which round-trips cleanly through percent-encoding, so that
/// genuinely-surviving characters (`<`, `>`, `(`, `)` …) are correctly marked
/// valid. Without this, no angle/paren-bearing payload is ever synthesized for
/// path params and exploitable path reflections (e.g. inside an HTML comment)
/// are missed.
#[tokio::test]
async fn active_probe_path_falls_back_to_per_char_when_batched_breaks_routing() {
    use axum::{Router, extract::Path as AxPath, response::Html, routing::get};
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    // Single-segment route: reflects the segment raw inside a <div>. A payload
    // containing `/` produces extra segments and misses this route (404), which
    // is exactly what happens to the concatenated batched probe.
    async fn reflect_seg(AxPath(seg): AxPath<String>) -> Html<String> {
        Html(format!("<html><body><div id=out>{seg}</div></body></html>"))
    }

    let app = Router::new().route("/p/{seg}", get(reflect_seg));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    // path_segment_1 == the `seed` segment in /p/seed.
    let target = parse_target(&format!("http://{addr}/p/seed")).unwrap();
    let res = active_probe_param(
        &target,
        probe_param("path_segment_1", Location::Path),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let valid = res.valid_specials.clone().unwrap_or_default();
    // Per-char probing must have run and reclassified the single-segment-safe
    // structural chars as valid (they survive a lone path-segment injection).
    for c in ['<', '>', '(', ')'] {
        assert!(
            valid.contains(&c),
            "per-char path fallback should mark '{c}' valid (got valid={valid:?})"
        );
    }
    // `/` cannot live inside one path segment — it must stay invalid.
    let invalid = res.invalid_specials.clone().unwrap_or_default();
    assert!(
        invalid.contains(&'/'),
        "'/' reshapes the path and must remain invalid (got invalid={invalid:?})"
    );
}

#[test]
fn test_param_type_label_covers_every_location() {
    fn param_at(name: &str, location: Location) -> Param {
        Param {
            name: name.to_string(),
            value: String::new(),
            location,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
            escaped_specials: None,
            js_breakout: None,
        }
    }

    let mut target = parse_target("https://example.com").unwrap();
    target.cookies = vec![("session".to_string(), "abc".to_string())];

    assert_eq!(
        param_type_label(&param_at("q", Location::Query), &target),
        "query"
    );
    assert_eq!(
        param_type_label(&param_at("b", Location::Body), &target),
        "body"
    );
    assert_eq!(
        param_type_label(&param_at("j", Location::JsonBody), &target),
        "json"
    );
    assert_eq!(
        param_type_label(&param_at("m", Location::MultipartBody), &target),
        "multipart"
    );
    assert_eq!(
        param_type_label(&param_at("p", Location::Path), &target),
        "path"
    );
    assert_eq!(
        param_type_label(&param_at("f", Location::Fragment), &target),
        "fragment"
    );
    // A Header-located param whose name matches a configured cookie is a
    // cookie; any other Header param is a plain header.
    assert_eq!(
        param_type_label(&param_at("session", Location::Header), &target),
        "cookie"
    );
    assert_eq!(
        param_type_label(&param_at("X-Forwarded-For", Location::Header), &target),
        "header"
    );
}

#[test]
fn test_encoded_variants_maps_every_known_special() {
    // Each arm of the lookup table contributes at least one canonical
    // encoding; the existing test only exercised `<` and `"`, leaving the
    // bulk of the table unverified.
    let expected: &[(char, &str)] = &[
        ('<', "&lt;"),
        ('>', "&gt;"),
        ('"', "&quot;"),
        ('\'', "&#39;"),
        ('(', "&#40;"),
        (')', "&#41;"),
        ('{', "&#123;"),
        ('}', "&#125;"),
        ('[', "&#91;"),
        (']', "&#93;"),
        ('`', "&#96;"),
        ('/', "&#47;"),
        ('\\', "&#92;"),
        (';', "&#59;"),
        ('=', "&#61;"),
        ('|', "&#124;"),
        ('+', "&#43;"),
        (',', "&#44;"),
        ('$', "&#36;"),
        ('-', "&#45;"),
        ('.', "&#46;"),
        (':', "&#58;"),
    ];
    for (c, enc) in expected {
        let variants = encoded_variants(*c);
        assert!(
            variants.contains(enc),
            "encoded_variants({c:?}) should include {enc:?}, got {variants:?}"
        );
    }
    // Characters with no special HTML meaning return an empty set.
    assert!(encoded_variants('a').is_empty());
    assert!(encoded_variants('0').is_empty());
}

// `effective_wire_name` selects which parameter key gets fuzzed: the parent
// HTTP param when this is a nested-field virtual param (`wire_name: Some(..)`),
// otherwise the param's own `name`. Both branches are asserted here (issue
// #1204) since production fixtures only ever build the `None` branch.
#[test]
fn test_effective_wire_name() {
    // wire_name set: returns the parent HTTP param key, not `name`.
    let nested = Param {
        name: "child".to_string(),
        value: String::new(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: Some("parent".to_string()),
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    assert_eq!(nested.effective_wire_name(), "parent");

    // wire_name None: falls back to the param's own `name`.
    let plain = Param {
        name: "q".to_string(),
        wire_name: None,
        ..nested.clone()
    };
    assert_eq!(plain.effective_wire_name(), "q");
}

// ─────────────────────────────────────────────────────────────────────────
// `send_probe_request_for_param` — request-shape coverage for the body
// locations that only had unreachable-endpoint (failure-path) tests.
//
// These arms decide what actually goes on the wire for the special-character
// probe. When the probe request carries no payload, every special classifies
// as invalid and the param's `<`/`>` payloads get pruned — a silent false
// negative rather than an error (see the multipart absent-param fix, #1260 /
// #1261). Asserting the response text is not enough for that class of bug;
// these tests assert the request the server actually received.
// ─────────────────────────────────────────────────────────────────────────

/// Echoes the raw request body back inside an HTML shell so the probe's
/// marker/special extraction sees exactly what was sent, and records each body
/// for direct assertions on the request shape.
async fn start_body_echo_server(
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> std::net::SocketAddr {
    use axum::{Router, extract::State, response::Html};
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn echo(
        State(seen): State<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
        body: String,
    ) -> Html<String> {
        seen.lock().expect("record body").push(body.clone());
        Html(format!("<div>{}</div>", body))
    }

    let app = Router::new()
        .route("/echo", axum::routing::post(echo))
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

/// The scanned multipart param is absent from the captured body: the exact-match
/// loop never places it, so the `!placed` fallback must append it. Without that
/// fallback the probe carries no payload and the param's angle-bracket payloads
/// are pruned as "invalid".
#[tokio::test]
async fn active_probe_multipart_appends_param_absent_from_captured_body() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let addr = start_body_echo_server(seen.clone()).await;
    let mut target = parse_target(&format!("http://{addr}/echo")).unwrap();
    target.method = "POST".to_string();
    target.data = Some("other=seed".to_string());

    let res = active_probe_param(
        &target,
        probe_param("q", Location::MultipartBody),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let bodies = seen.lock().expect("bodies").clone();
    assert!(!bodies.is_empty(), "the probe must have reached the server");
    let first = &bodies[0];
    assert!(
        first.contains("name=\"q\""),
        "the absent param must be appended as a multipart field, got: {first}"
    );
    assert!(
        first.contains("name=\"other\""),
        "the captured field must be preserved, got: {first}"
    );
    let valid = res.valid_specials.clone().unwrap_or_default();
    assert!(
        valid.contains(&'<') && valid.contains(&'>'),
        "the echoed payload must classify angle brackets as valid; got {valid:?}"
    );
}

/// The scanned param *is* in the captured body: it must be replaced with the
/// payload (the `placed` arm) while every sibling field keeps its captured
/// value (the `else` arm).
#[tokio::test]
async fn active_probe_multipart_replaces_present_param_and_keeps_siblings() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let addr = start_body_echo_server(seen.clone()).await;
    let mut target = parse_target(&format!("http://{addr}/echo")).unwrap();
    target.method = "POST".to_string();
    target.data = Some("q=seed&other=keepme".to_string());

    let _ = active_probe_param(
        &target,
        probe_param("q", Location::MultipartBody),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let bodies = seen.lock().expect("bodies").clone();
    let first = bodies.first().cloned().unwrap_or_default();
    assert!(
        first.contains("keepme"),
        "sibling field values must be preserved verbatim, got: {first}"
    );
    assert!(
        !first.contains("seed"),
        "the scanned param's captured value must be replaced by the payload, got: {first}"
    );
    // Exactly one `q` field — the fallback must not double-append it.
    assert_eq!(
        first.matches("name=\"q\"").count(),
        1,
        "the replaced param must not also be appended, got: {first}"
    );
}

/// A captured JSON body whose root is not an object (an array, here) must be
/// replaced by a fresh single-key object rather than dropped — otherwise the
/// probe body carries no payload at all.
#[tokio::test]
async fn active_probe_json_body_replaces_non_object_root_with_object() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let addr = start_body_echo_server(seen.clone()).await;
    let mut target = parse_target(&format!("http://{addr}/echo")).unwrap();
    target.method = "POST".to_string();
    target.data = Some("[1,2,3]".to_string());

    let res = active_probe_param(
        &target,
        probe_param("q", Location::JsonBody),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let bodies = seen.lock().expect("bodies").clone();
    let first = bodies.first().cloned().unwrap_or_default();
    let parsed: serde_json::Value =
        serde_json::from_str(&first).expect("probe body must still be valid JSON");
    assert!(
        parsed.get("q").and_then(|v| v.as_str()).is_some(),
        "the array root must be replaced by an object keyed on the param, got: {first}"
    );
    let valid = res.valid_specials.clone().unwrap_or_default();
    assert!(
        !valid.is_empty(),
        "the payload must have been echoed back for classification"
    );
}

/// Fragment params are DOM-side: the fragment never travels to the server, so
/// the probe must still send a well-formed request whose path and query are
/// untouched. A fragment builder that leaked into the query would silently
/// change which endpoint gets probed.
#[tokio::test]
async fn active_probe_fragment_leaves_path_and_query_intact() {
    use axum::{Router, extract::State, http::Uri, response::Html, routing::get};
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    async fn record(
        State(seen): State<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
        uri: Uri,
    ) -> Html<String> {
        seen.lock().expect("record uri").push(uri.to_string());
        Html("<div>ok</div>".to_string())
    }

    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/p", get(record))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{addr}/p?a=1")).unwrap();
    let _ = active_probe_param(
        &target,
        probe_param("f", Location::Fragment),
        Arc::new(Semaphore::new(8)),
    )
    .await;

    let uris = seen.lock().expect("uris").clone();
    assert!(!uris.is_empty(), "the fragment probe must still be sent");
    for uri in &uris {
        assert_eq!(
            uri, "/p?a=1",
            "the fragment must not leak into the request line"
        );
    }
}
