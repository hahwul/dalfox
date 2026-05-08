use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap as AxumHeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use std::collections::HashMap;
use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct ProbeRecorder {
    /// Number of times the GET handler was hit.
    get_hits: AtomicUsize,
    /// Number of times the POST handler was hit.
    post_hits: AtomicUsize,
    /// Whether any POST request observed a non-empty body.
    post_saw_body: AtomicBool,
    /// Whether any handler observed the dalfox_waf_probe query parameter.
    saw_probe_param: AtomicBool,
    /// Whether any handler observed the auth Cookie sent on the target.
    saw_auth_cookie: AtomicBool,
}

async fn probe_get_handler(
    State(state): State<StdArc<ProbeRecorder>>,
    Query(q): Query<HashMap<String, String>>,
    headers: AxumHeaderMap,
) -> impl IntoResponse {
    state.get_hits.fetch_add(1, Ordering::Relaxed);
    if q.contains_key("dalfox_waf_probe") {
        state.saw_probe_param.store(true, Ordering::Relaxed);
    }
    if headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.contains("session=abc"))
    {
        state.saw_auth_cookie.store(true, Ordering::Relaxed);
    }
    (StatusCode::OK, "ok")
}

async fn probe_post_handler(
    State(state): State<StdArc<ProbeRecorder>>,
    Query(q): Query<HashMap<String, String>>,
    headers: AxumHeaderMap,
    body: String,
) -> impl IntoResponse {
    state.post_hits.fetch_add(1, Ordering::Relaxed);
    if !body.is_empty() {
        state.post_saw_body.store(true, Ordering::Relaxed);
    }
    if q.contains_key("dalfox_waf_probe") {
        state.saw_probe_param.store(true, Ordering::Relaxed);
    }
    if headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.contains("session=abc"))
    {
        state.saw_auth_cookie.store(true, Ordering::Relaxed);
    }
    (StatusCode::OK, "ok")
}

async fn spawn_probe_recorder()
-> (String, StdArc<ProbeRecorder>, tokio::task::JoinHandle<()>) {
    let state = StdArc::new(ProbeRecorder::default());
    let app = Router::new()
        .route("/r", get(probe_get_handler).post(probe_post_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}/r", addr), state, handle)
}

#[tokio::test]
async fn probe_mirrors_target_method_and_preserves_auth_for_get() {
    let (url, state, handle) = spawn_probe_recorder().await;
    let mut target = crate::target_parser::parse_target(&url).expect("valid target");
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    let client = target.build_client_or_default();
    let _ = fingerprint_with_probe(&target, &client).await;
    handle.abort();

    assert_eq!(
        state.get_hits.load(Ordering::Relaxed),
        1,
        "GET target → GET probe"
    );
    assert_eq!(
        state.post_hits.load(Ordering::Relaxed),
        0,
        "GET target must not hit POST handler"
    );
    assert!(
        state.saw_probe_param.load(Ordering::Relaxed),
        "probe param should reach the server"
    );
    assert!(
        state.saw_auth_cookie.load(Ordering::Relaxed),
        "target cookies must travel with the probe"
    );
}

#[tokio::test]
async fn probe_mirrors_target_method_and_body_for_post() {
    let (url, state, handle) = spawn_probe_recorder().await;
    let mut target = crate::target_parser::parse_target(&url).expect("valid target");
    target.method = "POST".to_string();
    target.data = Some("user=admin&op=update".to_string());
    target
        .cookies
        .push(("session".to_string(), "abc".to_string()));

    let client = target.build_client_or_default();
    let _ = fingerprint_with_probe(&target, &client).await;
    handle.abort();

    assert_eq!(
        state.post_hits.load(Ordering::Relaxed),
        1,
        "POST target → POST probe (no more 405-from-GET-on-POST-only origin)"
    );
    assert_eq!(
        state.get_hits.load(Ordering::Relaxed),
        0,
        "POST target must not hit GET handler"
    );
    assert!(
        state.post_saw_body.load(Ordering::Relaxed),
        "target.data must travel with the probe so WAFs that inspect bodies trigger"
    );
    assert!(
        state.saw_probe_param.load(Ordering::Relaxed),
        "probe param still rides on the URL even on POST"
    );
    assert!(
        state.saw_auth_cookie.load(Ordering::Relaxed),
        "target cookies must travel with the probe"
    );
}

/// `rules.toml` is the canonical source of detection patterns. A
/// malformed edit would surface as a startup panic via the OnceLock
/// init; this test guards against silent loss of coverage by
/// asserting the load succeeds and we still have at least one rule
/// per known WAF family.
#[test]
fn rules_toml_loads_and_covers_all_waf_families() {
    let r = super::rules();
    assert!(!r.headers.is_empty(), "expected header rules to load");
    assert!(!r.bodies.is_empty(), "expected body rules to load");
    let waf_names: std::collections::HashSet<&str> = r
        .headers
        .iter()
        .map(|h| h.waf_type.as_str())
        .chain(r.bodies.iter().map(|b| b.waf_type.as_str()))
        .collect();
    for expected in [
        "Cloudflare",
        "AwsWaf",
        "Akamai",
        "Imperva",
        "ModSecurity",
        "OwaspCrs",
        "Sucuri",
        "F5BigIp",
        "Barracuda",
        "FortiWeb",
        "AzureWaf",
        "CloudArmor",
        "Fastly",
        "Wordfence",
    ] {
        assert!(
            waf_names.contains(expected),
            "rules.toml is missing coverage for {}",
            expected
        );
    }
}

fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

#[test]
fn test_cloudflare_detection_by_header() {
    let headers = make_headers(&[("cf-ray", "abc123"), ("server", "cloudflare")]);
    let result = fingerprint_from_response(&headers, None, 200);
    assert!(!result.is_empty());
    let primary = result.primary().unwrap();
    assert_eq!(primary.waf_type, WafType::Cloudflare);
    assert!(primary.confidence >= 0.9);
}

#[test]
fn test_imperva_detection_by_body() {
    let headers = make_headers(&[]);
    let body = "Request blocked. Incapsula incident ID: 123456";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(!result.is_empty());
    assert!(result.waf_types().contains(&&WafType::Imperva));
}

#[test]
fn test_wordfence_detection() {
    let headers = make_headers(&[]);
    let body = "This response was generated by Wordfence.";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::Wordfence));
}

#[test]
fn test_aws_waf_header_detection() {
    let headers = make_headers(&[("x-amzn-waf-action", "block")]);
    let result = fingerprint_from_response(&headers, None, 403);
    assert!(result.waf_types().contains(&&WafType::AwsWaf));
    assert!(result.primary().unwrap().confidence >= 0.9);
}

#[test]
fn test_modsecurity_body_detection() {
    let headers = make_headers(&[]);
    let body = "<html><body>ModSecurity - Access Denied</body></html>";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::ModSecurity));
}

#[test]
fn test_no_waf_detected() {
    let headers = make_headers(&[("server", "nginx"), ("content-type", "text/html")]);
    let result = fingerprint_from_response(&headers, Some("<html>ok</html>"), 200);
    assert!(result.is_empty());
}

#[test]
fn test_multiple_waf_detection() {
    // Cloudflare CDN + ModSecurity origin (common setup)
    let headers = make_headers(&[("cf-ray", "abc"), ("server", "cloudflare")]);
    let body = "ModSecurity Action denied";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::Cloudflare));
    assert!(result.waf_types().contains(&&WafType::ModSecurity));
}

#[test]
fn test_merge_results_takes_max_confidence() {
    let mut a = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.5,
            evidence: "header".to_string(),
        }],
    };
    let b = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.9,
            evidence: "probe".to_string(),
        }],
    };
    merge_results(&mut a, b);
    assert_eq!(a.detected.len(), 1);
    assert!(a.detected[0].confidence >= 0.9);
    // The higher-confidence finding's evidence should take over: this is
    // what users see in `target_summary.waf.detected[]`.
    assert_eq!(a.detected[0].evidence, "probe");
}

#[test]
fn test_merge_results_into_empty_a() {
    let mut a = WafDetectionResult::default();
    let b = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::AwsWaf,
            confidence: 0.7,
            evidence: "x-amzn-waf-action".to_string(),
        }],
    };
    merge_results(&mut a, b);
    assert_eq!(a.detected.len(), 1);
    assert_eq!(a.detected[0].waf_type, WafType::AwsWaf);
}

#[test]
fn test_merge_results_empty_b_is_noop() {
    let mut a = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.7,
            evidence: "cf-ray".to_string(),
        }],
    };
    merge_results(&mut a, WafDetectionResult::default());
    assert_eq!(a.detected.len(), 1);
    assert_eq!(a.detected[0].waf_type, WafType::Cloudflare);
}

#[test]
fn test_merge_results_keeps_distinct_wafs() {
    let mut a = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.6,
            evidence: "cf-ray".to_string(),
        }],
    };
    let b = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::ModSecurity,
            confidence: 0.8,
            evidence: "ModSecurity body".to_string(),
        }],
    };
    merge_results(&mut a, b);
    assert_eq!(a.detected.len(), 2);
    let types: Vec<&WafType> = a.detected.iter().map(|fp| &fp.waf_type).collect();
    assert!(types.contains(&&WafType::Cloudflare));
    assert!(types.contains(&&WafType::ModSecurity));
}

#[test]
fn test_merge_results_sorts_by_confidence_desc() {
    let mut a = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.4,
            evidence: "weak".to_string(),
        }],
    };
    let b = WafDetectionResult {
        detected: vec![
            WafFingerprint {
                waf_type: WafType::Imperva,
                confidence: 0.95,
                evidence: "strong".to_string(),
            },
            WafFingerprint {
                waf_type: WafType::ModSecurity,
                confidence: 0.7,
                evidence: "medium".to_string(),
            },
        ],
    };
    merge_results(&mut a, b);
    // primary() and the first slot must agree, and ordering is by
    // descending confidence so the strongest signal is reported first.
    let primary = a.primary().unwrap();
    assert_eq!(primary.waf_type, WafType::Imperva);
    assert_eq!(a.detected[0].waf_type, WafType::Imperva);
    assert!(a.detected[0].confidence >= a.detected[1].confidence);
    assert!(a.detected[1].confidence >= a.detected[2].confidence);
}

#[test]
fn test_merge_results_keeps_existing_evidence_when_lower_conf_arrives() {
    let mut a = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.9,
            evidence: "probe".to_string(),
        }],
    };
    let b = WafDetectionResult {
        detected: vec![WafFingerprint {
            waf_type: WafType::Cloudflare,
            confidence: 0.5,
            evidence: "weak header".to_string(),
        }],
    };
    merge_results(&mut a, b);
    assert_eq!(a.detected.len(), 1);
    assert_eq!(a.detected[0].confidence, 0.9);
    assert_eq!(a.detected[0].evidence, "probe");
}

#[test]
fn test_sucuri_detection() {
    let headers = make_headers(&[("x-sucuri-id", "12345")]);
    let body = "Access Denied - Sucuri Website Firewall";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::Sucuri));
    assert!(result.primary().unwrap().confidence >= 0.9);
}

#[test]
fn test_fastly_detection() {
    let headers = make_headers(&[("x-fastly-request-id", "abc123")]);
    let result = fingerprint_from_response(&headers, None, 200);
    assert!(result.waf_types().contains(&&WafType::Fastly));
}

#[test]
fn test_display_waf_types() {
    assert_eq!(format!("{}", WafType::Cloudflare), "Cloudflare");
    assert_eq!(format!("{}", WafType::Imperva), "Imperva/Incapsula");
    assert_eq!(format!("{}", WafType::OwaspCrs), "OWASP CRS");
    assert_eq!(
        format!("{}", WafType::Unknown("test".to_string())),
        "Unknown (test)"
    );
}

#[test]
fn test_owasp_crs_detection_by_rule_id() {
    let headers = make_headers(&[]);
    let body = r#"<html><body>ModSecurity: Access denied with code 403. id "941110"</body></html>"#;
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::OwaspCrs));
}

#[test]
fn test_owasp_crs_detection_by_name() {
    let headers = make_headers(&[]);
    let body = "Blocked by OWASP_CRS/3.3.4";
    let result = fingerprint_from_response(&headers, Some(body), 403);
    assert!(result.waf_types().contains(&&WafType::OwaspCrs));
}

#[test]
fn test_owasp_crs_plus_modsecurity_dual_detect() {
    let headers = make_headers(&[("server", "Apache/2.4 (ModSecurity)")]);
    let body = r#"ModSecurity: Access denied. id "941100" OWASP_CRS/3.3.4"#;
    let result = fingerprint_from_response(&headers, Some(body), 403);
    // Should detect both ModSecurity engine and OWASP CRS ruleset
    assert!(result.waf_types().contains(&&WafType::OwaspCrs));
    assert!(result.waf_types().contains(&&WafType::ModSecurity));
}
