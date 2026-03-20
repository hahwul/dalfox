//! WAF (Web Application Firewall) fingerprinting and bypass module.
//!
//! Detects WAF presence from HTTP response headers, status codes, and body patterns.
//! Provides per-WAF bypass strategies for payload mutation and encoding selection.

pub mod bypass;

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

// WAF block tracking uses global atomics in lib.rs (WAF_BLOCK_COUNT,
// WAF_CONSECUTIVE_BLOCKS) rather than a per-instance tracker, because
// WAF rate-limiting is IP-level and applies across all concurrent scan
// tasks for the same target.

/// Known WAF types that can be fingerprinted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WafType {
    Cloudflare,
    AwsWaf,
    Akamai,
    Imperva,
    ModSecurity,
    /// OWASP Core Rule Set — detected when ModSecurity + CRS body patterns are present.
    /// Gets a dedicated bypass strategy tuned to CRS rule IDs 941xxx.
    OwaspCrs,
    Sucuri,
    F5BigIp,
    Barracuda,
    FortiWeb,
    AzureWaf,
    CloudArmor,
    Fastly,
    Wordfence,
    Unknown(String),
}

impl std::fmt::Display for WafType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafType::Cloudflare => write!(f, "Cloudflare"),
            WafType::AwsWaf => write!(f, "AWS WAF"),
            WafType::Akamai => write!(f, "Akamai"),
            WafType::Imperva => write!(f, "Imperva/Incapsula"),
            WafType::ModSecurity => write!(f, "ModSecurity"),
            WafType::OwaspCrs => write!(f, "OWASP CRS"),
            WafType::Sucuri => write!(f, "Sucuri"),
            WafType::F5BigIp => write!(f, "F5 BIG-IP"),
            WafType::Barracuda => write!(f, "Barracuda"),
            WafType::FortiWeb => write!(f, "FortiWeb"),
            WafType::AzureWaf => write!(f, "Azure WAF"),
            WafType::CloudArmor => write!(f, "Google Cloud Armor"),
            WafType::Fastly => write!(f, "Fastly"),
            WafType::Wordfence => write!(f, "Wordfence"),
            WafType::Unknown(hint) => write!(f, "Unknown ({})", hint),
        }
    }
}

/// A single WAF detection result with confidence and evidence.
#[derive(Debug, Clone)]
pub struct WafFingerprint {
    pub waf_type: WafType,
    pub confidence: f32,
    pub evidence: String,
}

/// Aggregated WAF detection result for a target.
#[derive(Debug, Clone, Default)]
pub struct WafDetectionResult {
    pub detected: Vec<WafFingerprint>,
}

impl WafDetectionResult {
    pub fn is_empty(&self) -> bool {
        self.detected.is_empty()
    }

    /// Return the highest-confidence WAF detected, if any.
    pub fn primary(&self) -> Option<&WafFingerprint> {
        self.detected
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Return all detected WAF types.
    pub fn waf_types(&self) -> Vec<&WafType> {
        self.detected.iter().map(|f| &f.waf_type).collect()
    }
}

/// Header-based fingerprint rule.
struct HeaderRule {
    /// Header name to check (lowercase).
    header: &'static str,
    /// Substring to look for in the header value (case-insensitive). None = header existence is enough.
    value_contains: Option<&'static str>,
    waf_type: WafType,
    confidence: f32,
    evidence_label: &'static str,
}

/// Body-based fingerprint rule.
struct BodyRule {
    /// Substring to look for in the response body (case-insensitive).
    pattern: &'static str,
    waf_type: WafType,
    confidence: f32,
    evidence_label: &'static str,
}

/// Fingerprint WAFs from response headers and body content.
///
/// This runs during preflight with zero extra requests — it only analyzes the
/// headers and body already fetched for content-type / CSP checks.
pub fn fingerprint_from_response(
    headers: &HeaderMap,
    body: Option<&str>,
    status_code: u16,
) -> WafDetectionResult {
    let mut result = WafDetectionResult::default();

    // ── Header-based detection ──────────────────────────────────────
    let header_rules: Vec<HeaderRule> = vec![
        // Cloudflare
        HeaderRule { header: "cf-ray", value_contains: None, waf_type: WafType::Cloudflare, confidence: 0.9, evidence_label: "cf-ray header" },
        HeaderRule { header: "cf-cache-status", value_contains: None, waf_type: WafType::Cloudflare, confidence: 0.7, evidence_label: "cf-cache-status header" },
        HeaderRule { header: "server", value_contains: Some("cloudflare"), waf_type: WafType::Cloudflare, confidence: 0.95, evidence_label: "Server: cloudflare" },
        // AWS WAF / CloudFront
        HeaderRule { header: "x-amzn-requestid", value_contains: None, waf_type: WafType::AwsWaf, confidence: 0.6, evidence_label: "x-amzn-requestid header" },
        HeaderRule { header: "x-amz-cf-id", value_contains: None, waf_type: WafType::AwsWaf, confidence: 0.7, evidence_label: "x-amz-cf-id header (CloudFront)" },
        HeaderRule { header: "x-amzn-waf-action", value_contains: None, waf_type: WafType::AwsWaf, confidence: 0.95, evidence_label: "x-amzn-waf-action header" },
        // Akamai
        HeaderRule { header: "x-akamai-transformed", value_contains: None, waf_type: WafType::Akamai, confidence: 0.85, evidence_label: "x-akamai-transformed header" },
        HeaderRule { header: "server", value_contains: Some("akamaighost"), waf_type: WafType::Akamai, confidence: 0.9, evidence_label: "Server: AkamaiGHost" },
        HeaderRule { header: "x-akamai-session-info", value_contains: None, waf_type: WafType::Akamai, confidence: 0.8, evidence_label: "x-akamai-session-info header" },
        // Imperva / Incapsula
        HeaderRule { header: "x-cdn", value_contains: Some("imperva"), waf_type: WafType::Imperva, confidence: 0.9, evidence_label: "X-CDN: Imperva" },
        HeaderRule { header: "x-iinfo", value_contains: None, waf_type: WafType::Imperva, confidence: 0.8, evidence_label: "x-iinfo header" },
        HeaderRule { header: "x-cdn-forward", value_contains: None, waf_type: WafType::Imperva, confidence: 0.6, evidence_label: "x-cdn-forward header" },
        // ModSecurity
        HeaderRule { header: "server", value_contains: Some("mod_security"), waf_type: WafType::ModSecurity, confidence: 0.95, evidence_label: "Server: mod_security" },
        HeaderRule { header: "server", value_contains: Some("modsecurity"), waf_type: WafType::ModSecurity, confidence: 0.95, evidence_label: "Server: ModSecurity" },
        // Sucuri
        HeaderRule { header: "x-sucuri-id", value_contains: None, waf_type: WafType::Sucuri, confidence: 0.95, evidence_label: "x-sucuri-id header" },
        HeaderRule { header: "x-sucuri-cache", value_contains: None, waf_type: WafType::Sucuri, confidence: 0.8, evidence_label: "x-sucuri-cache header" },
        HeaderRule { header: "server", value_contains: Some("sucuri"), waf_type: WafType::Sucuri, confidence: 0.9, evidence_label: "Server: Sucuri" },
        // F5 BIG-IP
        HeaderRule { header: "server", value_contains: Some("bigip"), waf_type: WafType::F5BigIp, confidence: 0.9, evidence_label: "Server: BigIP" },
        HeaderRule { header: "x-wa-info", value_contains: None, waf_type: WafType::F5BigIp, confidence: 0.7, evidence_label: "x-wa-info header" },
        // Barracuda
        HeaderRule { header: "server", value_contains: Some("barracuda"), waf_type: WafType::Barracuda, confidence: 0.9, evidence_label: "Server: Barracuda" },
        HeaderRule { header: "barra_counter_session", value_contains: None, waf_type: WafType::Barracuda, confidence: 0.85, evidence_label: "barra_counter_session cookie header" },
        // FortiWeb
        HeaderRule { header: "x-fw-server", value_contains: None, waf_type: WafType::FortiWeb, confidence: 0.85, evidence_label: "x-fw-server header" },
        HeaderRule { header: "server", value_contains: Some("fortiweb"), waf_type: WafType::FortiWeb, confidence: 0.9, evidence_label: "Server: FortiWeb" },
        // Azure WAF
        HeaderRule { header: "x-azure-ref", value_contains: None, waf_type: WafType::AzureWaf, confidence: 0.7, evidence_label: "x-azure-ref header" },
        HeaderRule { header: "x-ms-forbidden-ip", value_contains: None, waf_type: WafType::AzureWaf, confidence: 0.85, evidence_label: "x-ms-forbidden-ip header" },
        // Google Cloud Armor
        HeaderRule { header: "server", value_contains: Some("google frontend"), waf_type: WafType::CloudArmor, confidence: 0.5, evidence_label: "Server: Google Frontend" },
        HeaderRule { header: "x-goog-request-info", value_contains: None, waf_type: WafType::CloudArmor, confidence: 0.6, evidence_label: "x-goog-request-info header" },
        // Fastly
        HeaderRule { header: "x-fastly-request-id", value_contains: None, waf_type: WafType::Fastly, confidence: 0.8, evidence_label: "x-fastly-request-id header" },
        HeaderRule { header: "via", value_contains: Some("varnish"), waf_type: WafType::Fastly, confidence: 0.5, evidence_label: "Via: varnish (possibly Fastly)" },
    ];

    for rule in &header_rules {
        if let Some(val) = headers.get(rule.header) {
            let matched = match rule.value_contains {
                None => true,
                Some(substr) => val
                    .to_str()
                    .ok()
                    .map(|v| v.to_ascii_lowercase().contains(substr))
                    .unwrap_or(false),
            };
            if matched {
                merge_fingerprint(&mut result, WafFingerprint {
                    waf_type: rule.waf_type.clone(),
                    confidence: rule.confidence,
                    evidence: rule.evidence_label.to_string(),
                });
            }
        }
    }

    // ── Body-based detection ────────────────────────────────────────
    if let Some(body_text) = body {
        let body_lower = body_text.to_ascii_lowercase();

        let body_rules: Vec<BodyRule> = vec![
            // Cloudflare
            BodyRule { pattern: "attention required! | cloudflare", waf_type: WafType::Cloudflare, confidence: 0.9, evidence_label: "Cloudflare block page" },
            BodyRule { pattern: "cloudflare ray id", waf_type: WafType::Cloudflare, confidence: 0.85, evidence_label: "Cloudflare Ray ID in body" },
            // Imperva
            BodyRule { pattern: "incapsula incident id", waf_type: WafType::Imperva, confidence: 0.95, evidence_label: "Incapsula incident ID in body" },
            BodyRule { pattern: "powered by incapsula", waf_type: WafType::Imperva, confidence: 0.9, evidence_label: "Powered by Incapsula" },
            // ModSecurity
            BodyRule { pattern: "modsecurity", waf_type: WafType::ModSecurity, confidence: 0.85, evidence_label: "ModSecurity in body" },
            BodyRule { pattern: "mod_security", waf_type: WafType::ModSecurity, confidence: 0.85, evidence_label: "mod_security in body" },
            BodyRule { pattern: "not acceptable!", waf_type: WafType::ModSecurity, confidence: 0.4, evidence_label: "Not Acceptable error (possible ModSecurity)" },
            // OWASP CRS (often runs on ModSecurity but has distinctive patterns)
            BodyRule { pattern: "owasp_crs", waf_type: WafType::OwaspCrs, confidence: 0.95, evidence_label: "OWASP CRS rule ID in body" },
            BodyRule { pattern: "owasp crs", waf_type: WafType::OwaspCrs, confidence: 0.9, evidence_label: "OWASP CRS mention in body" },
            BodyRule { pattern: "coreruleset", waf_type: WafType::OwaspCrs, confidence: 0.9, evidence_label: "CoreRuleSet reference in body" },
            BodyRule { pattern: "core rule set", waf_type: WafType::OwaspCrs, confidence: 0.85, evidence_label: "Core Rule Set reference in body" },
            BodyRule { pattern: "id \"941", waf_type: WafType::OwaspCrs, confidence: 0.95, evidence_label: "CRS XSS rule ID 941xxx in body" },
            BodyRule { pattern: "id \"942", waf_type: WafType::OwaspCrs, confidence: 0.9, evidence_label: "CRS SQLi rule ID 942xxx in body" },
            BodyRule { pattern: "id \"949", waf_type: WafType::OwaspCrs, confidence: 0.9, evidence_label: "CRS blocking rule ID 949xxx in body" },
            BodyRule { pattern: "id \"980", waf_type: WafType::OwaspCrs, confidence: 0.85, evidence_label: "CRS correlation rule ID 980xxx in body" },
            // Sucuri
            BodyRule { pattern: "access denied - sucuri website firewall", waf_type: WafType::Sucuri, confidence: 0.95, evidence_label: "Sucuri block page" },
            BodyRule { pattern: "sucuri cloudproxy", waf_type: WafType::Sucuri, confidence: 0.9, evidence_label: "Sucuri CloudProxy in body" },
            // Wordfence
            BodyRule { pattern: "generated by wordfence", waf_type: WafType::Wordfence, confidence: 0.95, evidence_label: "Wordfence block page" },
            BodyRule { pattern: "wordfence", waf_type: WafType::Wordfence, confidence: 0.6, evidence_label: "Wordfence mention in body" },
            // AWS WAF
            BodyRule { pattern: "request blocked", waf_type: WafType::AwsWaf, confidence: 0.3, evidence_label: "Request blocked (possible AWS WAF)" },
            // F5 BIG-IP ASM
            BodyRule { pattern: "the requested url was rejected", waf_type: WafType::F5BigIp, confidence: 0.7, evidence_label: "F5 ASM block page" },
            BodyRule { pattern: "support id:", waf_type: WafType::F5BigIp, confidence: 0.5, evidence_label: "F5 support ID in body" },
            // Barracuda
            BodyRule { pattern: "barracuda web application firewall", waf_type: WafType::Barracuda, confidence: 0.95, evidence_label: "Barracuda WAF block page" },
            // FortiWeb
            BodyRule { pattern: "fortiweb", waf_type: WafType::FortiWeb, confidence: 0.7, evidence_label: "FortiWeb in body" },
            BodyRule { pattern: "fortigate", waf_type: WafType::FortiWeb, confidence: 0.5, evidence_label: "FortiGate in body" },
            // Azure WAF
            BodyRule { pattern: "azure front door", waf_type: WafType::AzureWaf, confidence: 0.6, evidence_label: "Azure Front Door in body" },
            // Google Cloud Armor
            BodyRule { pattern: "google cloud armor", waf_type: WafType::CloudArmor, confidence: 0.9, evidence_label: "Google Cloud Armor in body" },
        ];

        for rule in &body_rules {
            if body_lower.contains(rule.pattern) {
                merge_fingerprint(&mut result, WafFingerprint {
                    waf_type: rule.waf_type.clone(),
                    confidence: rule.confidence,
                    evidence: rule.evidence_label.to_string(),
                });
            }
        }

        // Status code hints (boost confidence for known WAF block codes)
        if status_code == 403 || status_code == 406 || status_code == 429 || status_code == 503 {
            // Boost all existing detections slightly if we see a blocking status
            for fp in &mut result.detected {
                fp.confidence = (fp.confidence + 0.05).min(1.0);
            }
        }
    }

    // Sort by confidence descending
    result.detected.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    result
}

/// Fingerprint WAFs using a provocation probe: send a blatantly malicious payload
/// and analyze the blocking response. This costs one extra request.
pub async fn fingerprint_with_probe(
    target: &crate::target_parser::Target,
    client: &reqwest::Client,
) -> WafDetectionResult {
    // Send a request with an obvious XSS payload in a dummy parameter
    let mut probe_url = target.url.clone();
    probe_url
        .query_pairs_mut()
        .append_pair("dalfox_waf_probe", "<script>alert(1)</script>");

    let rb = client.get(probe_url.clone());
    let rb = crate::utils::apply_headers_ua_cookies(rb, target, None);

    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let resp = match rb.send().await {
        Ok(r) => r,
        Err(_) => return WafDetectionResult::default(),
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.ok();

    let mut result = fingerprint_from_response(&headers, body.as_deref(), status);

    // If we got a blocking status code but no WAF was identified, mark as Unknown
    if result.is_empty() && (status == 403 || status == 406 || status == 429 || status == 503) {
        result.detected.push(WafFingerprint {
            waf_type: WafType::Unknown(format!("HTTP {}", status)),
            confidence: 0.4,
            evidence: format!("Provocation probe returned HTTP {}", status),
        });
    }

    result
}

/// Merge a new fingerprint into the result, taking the max confidence per WAF type.
fn merge_fingerprint(result: &mut WafDetectionResult, fp: WafFingerprint) {
    if let Some(existing) = result.detected.iter_mut().find(|e| e.waf_type == fp.waf_type) {
        if fp.confidence > existing.confidence {
            existing.confidence = fp.confidence;
            existing.evidence = fp.evidence;
        }
    } else {
        result.detected.push(fp);
    }
}

/// Merge two detection results together, keeping highest confidence per WAF.
pub fn merge_results(a: &mut WafDetectionResult, b: WafDetectionResult) {
    for fp in b.detected {
        merge_fingerprint(a, fp);
    }
    a.detected.sort_by(|x, y| y.confidence.partial_cmp(&x.confidence).unwrap_or(std::cmp::Ordering::Equal));
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

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
        assert_eq!(format!("{}", WafType::Unknown("test".to_string())), "Unknown (test)");
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
}
