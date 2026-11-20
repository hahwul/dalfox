//! Reflection grading; parser verification and legacy tiers stay unchanged.

use super::ast_integration::PageSecurityPosture;
use super::result::Confidence;
use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use reqwest::header::HeaderMap;
use std::sync::OnceLock;

/// Stored values can reach another viewer independently of the write request.
/// Direct header/cookie reflections need a separate delivery mechanism.
pub(crate) fn reflection_grade(
    grade: (Confidence, String),
    target: &Target,
    param: &Param,
    stored: bool,
) -> (Confidence, String) {
    if stored || param.location != Location::Header {
        return grade;
    }
    let reason = if super::url_inject::param_is_cookie(target, param) {
        "injected through a cookie; a link or form cannot deliver it"
    } else {
        "injected through a request header; a link or form cannot deliver it"
    };
    let reason = if grade.0 == Confidence::Low {
        format!("{}; {reason}", grade.1)
    } else {
        reason.to_string()
    };
    (Confidence::Low, reason)
}

/// Prefer the policy on the response that supplied the evidence, including
/// retrieval responses under --sxss. Absence/report-only leaves confidence high.
/// Meta policies and per-surface script directives are left high conservatively.
/// Only inline payload shapes are affected; existing script-context injection
/// and known CSP-bypass candidates keep their original grade.
pub(crate) fn inline_blocked(headers: &HeaderMap, payload: &str) -> bool {
    // Meta policies are order-sensitive; without locating the evidence relative
    // to the meta, applying it could hide a script that ran before the policy.
    let policy = super::select_csp_policy(headers, || None);
    let Some((name, policy)) = policy else {
        return false;
    };
    // The shared parser does not model per-surface script directives. Keep
    // the grade high rather than demoting a handler an override authorizes.
    if policy
        .split([';', ','])
        .filter_map(|d| d.split_whitespace().next())
        .any(|d| {
            d.eq_ignore_ascii_case("script-src-attr") || d.eq_ignore_ascii_case("script-src-elem")
        })
    {
        return false;
    }
    if policy
        .split([';', ','])
        .flat_map(str::split_whitespace)
        .any(|token| {
            token
                .trim_end_matches([';', ','])
                .eq_ignore_ascii_case("'unsafe-hashes'")
        })
    {
        // Handler hash authorization is not modeled by the shared posture.
        return false;
    }
    for policy in policy.split(',') {
        let (mut script_seen, mut default_seen) = (false, false);
        for name in policy
            .split(';')
            .filter_map(|d| d.split_whitespace().next())
        {
            let seen = if name.eq_ignore_ascii_case("script-src") {
                &mut script_seen
            } else if name.eq_ignore_ascii_case("default-src") {
                &mut default_seen
            } else {
                continue;
            };
            // Browsers keep the first duplicate directive; the shared analyzer
            // merges them, so it cannot prove an inline payload is blocked.
            if std::mem::replace(seen, true) {
                return false;
            }
        }
    }
    let csp = crate::payload::xss_csp_bypass::analyze_csp_from(&name, &policy);
    let posture = PageSecurityPosture::from_csp(Some(&csp));
    if posture.inline_script_allowed {
        return false;
    }
    if crate::payload::xss_csp_bypass::get_csp_bypass_payloads(&csp)
        .iter()
        .any(|p| p == payload)
    {
        return false;
    }
    let decoded = super::decode_html_entities(payload);
    // A script with src loads an external resource, rather than an inline body.
    // Its origin permissions are outside this inline-only grading rule.
    if decoded.to_ascii_lowercase().contains("<script") {
        let doc = crate::utils::html::parse_document_bounded(&decoded);
        let scripts: Vec<_> = doc.select(super::selectors::script()).collect();
        if scripts.iter().any(|script| {
            script
                .value()
                .attr("nonce")
                .is_some_and(|nonce| csp.nonce_values.iter().any(|n| n == nonce))
        }) || (!scripts.is_empty() && !csp.hash_values.is_empty())
        {
            // A matching nonce authorizes the injected script. Hash permission
            // is not resolved here, so retain high rather than hide a valid PoC.
            return false;
        }
        if !scripts.is_empty()
            && scripts.iter().all(|s| s.value().attr("src").is_some())
            && !decoded.to_ascii_lowercase().contains("javascript:")
        {
            // An external script alone needs no inline permission.
            static HANDLER: OnceLock<regex::Regex> = OnceLock::new();
            if !HANDLER
                .get_or_init(|| {
                    regex::Regex::new(r"(?i)\bon[a-z0-9_-]+\s*=").expect("constant handler regex")
                })
                .is_match(&decoded)
            {
                return false;
            }
        }
    }
    true
}

pub(crate) fn verified_grade(
    blocked: bool,
    kind: Option<super::check_dom_verification::DomEvidenceKind>,
    reason: impl Into<String>,
) -> (Confidence, String) {
    // JS-context evidence runs inside an existing script (possibly nonce-
    // authorized), rather than injecting a new inline handler or script body.
    if blocked && kind != Some(super::check_dom_verification::DomEvidenceKind::JsContext) {
        (
            Confidence::Low,
            "CSP does not permit inline script".to_string(),
        )
    } else {
        (Confidence::High, reason.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflection_delivery_grades_headers_and_cookies_and_preserves_blockers() {
        let mut target = crate::target_parser::parse_target("https://example.com/").unwrap();
        target.cookies.push(("q".into(), "seed".into()));
        for (name, identity, surface) in [
            ("q", Some(false), "request header"),
            ("Referer", None, "request header"),
            ("User-Agent", None, "request header"),
            ("q", Some(true), "cookie"),
            ("q", None, "cookie"),
        ] {
            let mut param = Param::new(name, "seed", Location::Header);
            param.is_cookie = identity;
            let reason = format!("injected through a {surface}; a link or form cannot deliver it");
            assert_eq!(
                reflection_grade(
                    (Confidence::High, "executable".into()),
                    &target,
                    &param,
                    false
                ),
                (Confidence::Low, reason.clone())
            );
            for blocker in ["CSP does not permit inline script", "bare echo"] {
                let grade = (Confidence::Low, blocker.to_string());
                assert_eq!(
                    reflection_grade(grade.clone(), &target, &param, false),
                    (Confidence::Low, format!("{blocker}; {reason}"))
                );
                assert_eq!(
                    reflection_grade(grade.clone(), &target, &param, true),
                    grade
                );
            }
            let grade = (Confidence::High, "stored evidence".into());
            assert_eq!(
                reflection_grade(grade.clone(), &target, &param, true),
                grade
            );
        }
        for location in [
            Location::Query,
            Location::Body,
            Location::JsonBody,
            Location::MultipartBody,
            Location::GraphqlBody,
            Location::XmlBody,
            Location::Path,
            Location::Fragment,
        ] {
            let param = Param::new("q", "seed", location);
            for confidence in [Confidence::High, Confidence::Low] {
                let grade = (confidence, "existing reason".into());
                assert_eq!(
                    reflection_grade(grade.clone(), &target, &param, false),
                    grade
                );
            }
        }
    }

    #[test]
    fn csp_grades_inline_shapes_without_changing_verification() {
        for (policy, report_only, blocked) in [
            (
                "script-src 'self'; object-src 'none'; base-uri 'none'",
                false,
                true,
            ),
            ("script-src 'self' 'unsafe-inline'", false, false),
            ("script-src 'self'", true, false),
            (
                "default-src 'self' 'unsafe-inline' 'nonce-gap'",
                false,
                true,
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                if report_only {
                    "content-security-policy-report-only"
                } else {
                    "content-security-policy"
                },
                policy.parse().unwrap(),
            );
            for payload in [
                "<img src=x onerror=alert(1)>",
                "<script>alert(1)</script>",
                "<a href=javascript:alert(1)>x</a>",
                "<a href=java&#115;cript:alert(1)>x</a>",
            ] {
                assert_eq!(
                    inline_blocked(&headers, payload),
                    blocked,
                    "{policy}: {payload}"
                );
            }
            assert_eq!(inline_blocked(&headers, "';alert(1);//"), blocked);
            assert!(!inline_blocked(
                &headers,
                "<script src=https://cdn.example/x.js></script>"
            ));
        }
        assert!(!inline_blocked(&HeaderMap::new(), "<img onerror=alert(1)>"));
    }

    #[test]
    fn nonce_and_unresolved_hash_permissions_keep_high() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "script-src 'nonce-test'".parse().unwrap(),
        );
        assert!(!inline_blocked(
            &headers,
            "<script nonce=test>alert(1)</script>"
        ));
        assert!(inline_blocked(
            &headers,
            "<script nonce=wrong>alert(1)</script>"
        ));
        headers.insert(
            "content-security-policy",
            "script-src 'sha256-example'".parse().unwrap(),
        );
        assert!(!inline_blocked(&headers, "<script>alert(1)</script>"));
        headers.insert(
            "content-security-policy",
            "script-src 'unsafe-hashes' 'sha256-example'"
                .parse()
                .unwrap(),
        );
        assert!(!inline_blocked(&headers, "<img onerror=alert(1)>"));
        headers.insert(
            "content-security-policy",
            "script-src 'sha256-example' 'unsafe-hashes';object-src 'none';base-uri 'none'"
                .parse()
                .unwrap(),
        );
        assert!(!inline_blocked(&headers, "<img onerror=alert(1)>"));
        headers.insert(
            "content-security-policy",
            "script-src 'unsafe-inline';script-src 'nonce-test'"
                .parse()
                .unwrap(),
        );
        assert!(!inline_blocked(&headers, "<img onerror=alert(1)>"));
    }

    #[test]
    fn csp_bypass_candidate_keeps_high_grade() {
        let policy = "script-src https://ajax.googleapis.com; object-src 'none'; base-uri 'none'";
        let csp =
            crate::payload::xss_csp_bypass::analyze_csp_from("content-security-policy", policy);
        let payloads = crate::payload::xss_csp_bypass::get_csp_bypass_payloads(&csp);
        assert!(!payloads.is_empty());
        let mut headers = HeaderMap::new();
        headers.insert("content-security-policy", policy.parse().unwrap());
        for payload in payloads {
            assert!(!inline_blocked(&headers, &payload), "{payload}");
        }
    }

    #[test]
    fn repeated_headers_apply_but_order_sensitive_meta_is_conservative() {
        let payload = "<img onerror=alert(1)>";
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "script-src 'unsafe-inline'".parse().unwrap(),
        );
        headers.append(
            "content-security-policy",
            "script-src 'self'".parse().unwrap(),
        );
        assert!(inline_blocked(&headers, payload));
        assert!(!inline_blocked(&HeaderMap::new(), payload));
        assert_eq!(
            verified_grade(true, None, "DOM evidence").0,
            Confidence::Low
        );
        assert_eq!(
            verified_grade(false, None, "DOM evidence").0,
            Confidence::High
        );
    }
}
