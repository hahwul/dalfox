use super::*;

#[test]
fn test_analyze_csp_unsafe_inline() {
    let csp = "script-src 'self' 'unsafe-inline'; style-src 'self'";
    let analysis = analyze_csp(csp);
    assert!(analysis.has_unsafe_inline);
    assert!(!analysis.has_unsafe_eval);
    assert!(analysis.missing_base_uri);
    assert!(analysis.missing_object_src);
}

#[test]
fn test_analyze_csp_unsafe_eval() {
    let csp = "script-src 'self' 'unsafe-eval'; base-uri 'self'";
    let analysis = analyze_csp(csp);
    assert!(!analysis.has_unsafe_inline);
    assert!(analysis.has_unsafe_eval);
    assert!(!analysis.missing_base_uri);
}

#[test]
fn test_analyze_csp_data_scheme() {
    let csp = "script-src 'self' data:";
    let analysis = analyze_csp(csp);
    assert!(analysis.allows_data_scheme);
}

#[test]
fn test_analyze_csp_whitelisted_domains() {
    let csp =
        "script-src 'self' https://cdnjs.cloudflare.com https://www.google.com; object-src 'none'";
    let analysis = analyze_csp(csp);
    assert_eq!(analysis.whitelisted_domains.len(), 2);
    assert!(!analysis.missing_object_src);
}

#[test]
fn test_analyze_csp_no_script_src_with_default() {
    let csp = "default-src 'self'";
    let analysis = analyze_csp(csp);
    assert!(!analysis.missing_script_src);
}

#[test]
fn test_analyze_csp_no_directives() {
    let csp = "";
    let analysis = analyze_csp(csp);
    assert!(analysis.missing_script_src);
}

#[test]
fn test_bypass_payloads_unsafe_inline() {
    let analysis = CspAnalysis {
        has_unsafe_inline: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("<script")));
}

#[test]
fn test_bypass_payloads_data_scheme() {
    let analysis = CspAnalysis {
        allows_data_scheme: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("data:")));
}

#[test]
fn test_bypass_payloads_missing_base_uri() {
    let analysis = CspAnalysis {
        missing_base_uri: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("<base")));
}

#[test]
fn test_bypass_payloads_cdn_gadgets() {
    let analysis = CspAnalysis {
        whitelisted_domains: vec!["https://cdnjs.cloudflare.com".to_string()],
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("angular")));
}

#[test]
fn test_bypass_payloads_no_script_src() {
    let analysis = CspAnalysis {
        missing_script_src: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(!payloads.is_empty());
    // Should include basic payloads since CSP doesn't restrict scripts
    assert!(payloads.iter().any(|p| p.contains("alert(1)")));
}

#[test]
fn test_analyze_csp_blob_scheme() {
    let analysis = analyze_csp("script-src 'self' blob:");
    assert!(analysis.allows_blob_scheme);
    // `blob:` is a scheme keyword, not a whitelisted host.
    assert!(analysis.whitelisted_domains.is_empty());
}

#[test]
fn test_analyze_csp_strict_dynamic() {
    let analysis = analyze_csp("script-src 'strict-dynamic' 'nonce-abc'");
    assert!(analysis.has_strict_dynamic);
}

#[test]
fn test_analyze_csp_script_src_elem_counts_as_script_src() {
    let analysis = analyze_csp("script-src-elem 'unsafe-inline'");
    assert!(analysis.has_unsafe_inline);
    assert!(!analysis.missing_script_src);
}

#[test]
fn test_analyze_csp_default_src_unsafe_inline_and_eval() {
    // unsafe-inline / unsafe-eval declared on default-src must be picked up.
    let analysis = analyze_csp("default-src 'self' 'unsafe-inline' 'unsafe-eval'");
    assert!(analysis.has_unsafe_inline);
    assert!(analysis.has_unsafe_eval);
    assert!(!analysis.missing_script_src);
}

#[test]
fn test_analyze_csp_wildcard_and_keywords_not_whitelisted() {
    let analysis = analyze_csp("script-src 'self' 'none' * data: blob:");
    assert!(analysis.whitelisted_domains.is_empty());
}

#[test]
fn test_analyze_csp_object_src_and_base_uri_present() {
    let analysis = analyze_csp("script-src 'self'; object-src 'none'; base-uri 'self'");
    assert!(!analysis.missing_object_src);
    assert!(!analysis.missing_base_uri);
}

#[test]
fn test_bypass_payloads_unsafe_eval() {
    let analysis = CspAnalysis {
        has_unsafe_eval: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("eval('alert(1)')")));
    assert!(payloads.iter().any(|p| p.contains("Function('alert(1)')")));
}

#[test]
fn test_bypass_payloads_blob_scheme() {
    let analysis = CspAnalysis {
        allows_blob_scheme: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("createObjectURL")));
}

#[test]
fn test_bypass_payloads_missing_object_src() {
    let analysis = CspAnalysis {
        missing_object_src: true,
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("<object")));
    assert!(payloads.iter().any(|p| p.contains("<embed")));
}

#[test]
fn test_bypass_payloads_google_jsonp_gadget() {
    let analysis = CspAnalysis {
        whitelisted_domains: vec!["https://ajax.googleapis.com".to_string()],
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("google.com/complete/search"))
    );
}

#[test]
fn test_bypass_payloads_jquery_gadget() {
    let analysis = CspAnalysis {
        whitelisted_domains: vec!["https://code.jquery.com".to_string()],
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("globalEval")));
}

#[test]
fn test_bypass_payloads_jsdelivr_gadget() {
    let analysis = CspAnalysis {
        whitelisted_domains: vec!["https://cdn.jsdelivr.net".to_string()],
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().any(|p| p.contains("jsdelivr.net")));
}

// --- nonce / hash parsing -------------------------------------------------

#[test]
fn test_analyze_csp_parses_nonce_value_case_preserved() {
    let analysis = analyze_csp("script-src 'nonce-AbC123==' 'strict-dynamic'");
    assert_eq!(analysis.nonce_values, vec!["AbC123==".to_string()]);
    // The nonce token must not leak into the host allowlist.
    assert!(analysis.whitelisted_domains.is_empty());
}

#[test]
fn test_analyze_csp_parses_multiple_nonces() {
    let analysis = analyze_csp("script-src 'nonce-aaa' 'nonce-bbb'");
    assert_eq!(
        analysis.nonce_values,
        vec!["aaa".to_string(), "bbb".to_string()]
    );
}

#[test]
fn test_analyze_csp_empty_nonce_ignored() {
    let analysis = analyze_csp("script-src 'nonce-'");
    assert!(analysis.nonce_values.is_empty());
}

#[test]
fn test_analyze_csp_parses_hashes() {
    let analysis = analyze_csp("script-src 'sha256-abc123=' 'sha384-def' 'sha512-ghi'");
    assert_eq!(
        analysis.hash_values,
        vec![
            "sha256-abc123=".to_string(),
            "sha384-def".to_string(),
            "sha512-ghi".to_string()
        ]
    );
    assert!(analysis.whitelisted_domains.is_empty());
}

#[test]
fn test_analyze_csp_nonce_not_whitelisted_with_host() {
    let analysis = analyze_csp("script-src 'nonce-xyz' https://cdn.example.com");
    assert_eq!(analysis.nonce_values, vec!["xyz".to_string()]);
    assert_eq!(
        analysis.whitelisted_domains,
        vec!["https://cdn.example.com".to_string()]
    );
}

// --- Trusted Types directive parsing --------------------------------------

#[test]
fn test_analyze_csp_require_trusted_types_for_script() {
    let analysis = analyze_csp("require-trusted-types-for 'script'");
    assert!(analysis.require_trusted_types_for);
}

#[test]
fn test_analyze_csp_require_trusted_types_for_unquoted() {
    // Some servers omit the quotes; accept both spellings.
    let analysis = analyze_csp("require-trusted-types-for script");
    assert!(analysis.require_trusted_types_for);
}

#[test]
fn test_analyze_csp_no_require_trusted_types_by_default() {
    let analysis = analyze_csp("script-src 'self'");
    assert!(!analysis.require_trusted_types_for);
    assert!(analysis.trusted_types.is_none());
}

#[test]
fn test_analyze_csp_trusted_types_policy_list() {
    let analysis = analyze_csp("trusted-types default dompurify 'allow-duplicates'");
    let tt = analysis.trusted_types.expect("trusted-types parsed");
    assert_eq!(
        tt,
        vec![
            "default".to_string(),
            "dompurify".to_string(),
            "allow-duplicates".to_string()
        ]
    );
}

#[test]
fn test_analyze_csp_trusted_types_empty_means_no_policies() {
    let analysis = analyze_csp("trusted-types;");
    assert_eq!(analysis.trusted_types, Some(vec![]));
}

// --- classification helpers ----------------------------------------------

#[test]
fn test_is_nonce_or_hash_based() {
    assert!(analyze_csp("script-src 'nonce-x'").is_nonce_or_hash_based());
    assert!(analyze_csp("script-src 'sha256-x='").is_nonce_or_hash_based());
    assert!(!analyze_csp("script-src 'self' https://cdn.example.com").is_nonce_or_hash_based());
}

#[test]
fn test_hardened_nonce_only_csp() {
    // nonce + hash, no strict-dynamic, no unsafe-*, no gadget host → hardened.
    let analysis =
        analyze_csp("script-src 'nonce-r4nd0m' 'sha256-abc='; object-src 'none'; base-uri 'none'");
    assert!(analysis.is_hardened());
    assert!(!analysis.is_gadget_bypassable());
    // And it emits no actionable script-execution payloads beyond what missing
    // directives (none here) would add.
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().all(|p| !p.contains("nonce=")));
}

#[test]
fn test_gadget_bypassable_strict_dynamic() {
    let analysis = analyze_csp("script-src 'nonce-r4nd0m' 'strict-dynamic'");
    assert!(analysis.is_gadget_bypassable());
    assert!(!analysis.is_hardened());
}

#[test]
fn test_gadget_bypassable_whitelisted_gadget_host() {
    let analysis = analyze_csp("script-src 'nonce-x' https://cdnjs.cloudflare.com");
    assert!(analysis.is_gadget_bypassable());
    assert!(!analysis.is_hardened());
}

#[test]
fn test_unsafe_inline_is_gadget_bypassable() {
    let analysis = analyze_csp("script-src 'unsafe-inline'");
    assert!(analysis.is_gadget_bypassable());
}

// --- strict-dynamic payload generation ------------------------------------

#[test]
fn test_strict_dynamic_emits_nonce_reuse_payloads() {
    let analysis = analyze_csp("script-src 'strict-dynamic' 'nonce-PRED1CT4BLE'");
    let payloads = get_csp_bypass_payloads(&analysis);
    // Nonce reuse: an injected <script> carrying the captured nonce.
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("nonce=PRED1CT4BLE") && p.contains("<script"))
    );
}

#[test]
fn test_strict_dynamic_emits_dom_gadgets() {
    let analysis = analyze_csp("script-src 'strict-dynamic' 'nonce-x'");
    let payloads = get_csp_bypass_payloads(&analysis);
    // DOM script-gadgets survive strict-dynamic; require.js data-main and the
    // document.write self-propagating gadget are the canonical ones.
    assert!(payloads.iter().any(|p| p.contains("data-main")));
    assert!(payloads.iter().any(|p| p.contains("document.write")));
}

#[test]
fn test_strict_dynamic_without_nonce_still_emits_dom_gadgets() {
    // hash-pinned strict-dynamic with no nonce: no nonce-reuse payload, but the
    // DOM gadgets still apply.
    let analysis = analyze_csp("script-src 'strict-dynamic' 'sha256-abc='");
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(payloads.iter().all(|p| !p.contains("nonce=")));
    assert!(payloads.iter().any(|p| p.contains("data-main")));
}

#[test]
fn test_strict_dynamic_ignores_host_allowlist_gadgets() {
    // Under strict-dynamic the host allowlist is ignored, so a plain
    // host-loaded JSONP gadget (Google complete/search) must NOT be emitted —
    // only the DOM script-gadgets that survive strict-dynamic.
    let analysis = analyze_csp("script-src 'strict-dynamic' 'nonce-x' https://ajax.googleapis.com");
    let payloads = get_csp_bypass_payloads(&analysis);
    assert!(
        payloads
            .iter()
            .all(|p| !p.contains("google.com/complete/search")),
        "host-allowlist JSONP gadget should be suppressed under strict-dynamic"
    );
}

#[test]
fn test_payloads_are_deduped() {
    // A host matching multiple gadget patterns must not yield duplicate payloads.
    let analysis = CspAnalysis {
        whitelisted_domains: vec![
            "https://code.jquery.com".to_string(),
            "https://code.jquery.com".to_string(),
        ],
        ..Default::default()
    };
    let payloads = get_csp_bypass_payloads(&analysis);
    let mut sorted = payloads.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), payloads.len(), "payloads must be unique");
}

#[test]
fn test_report_only_and_full_csp_parse_identically() {
    // analyze_csp takes only the value, so report-only headers (handled at the
    // header layer) parse the same directives.
    let value = "script-src 'nonce-abc' 'strict-dynamic'; require-trusted-types-for 'script'";
    let analysis = analyze_csp(value);
    assert!(analysis.has_strict_dynamic);
    assert_eq!(analysis.nonce_values, vec!["abc".to_string()]);
    assert!(analysis.require_trusted_types_for);
}
