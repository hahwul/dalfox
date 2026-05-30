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
