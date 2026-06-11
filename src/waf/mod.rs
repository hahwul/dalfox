//! WAF (Web Application Firewall) fingerprinting and bypass module.
//!
//! Detects WAF presence from HTTP response headers, status codes, and body patterns.
//! Provides per-WAF bypass strategies for payload mutation and encoding selection.

pub mod bypass;

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

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
    /// Citrix NetScaler (AppFirewall). Fingerprinted by its scrambled
    /// `Connection` header (`nnCoection` / `Cneonction`) and `citrix_ns_id`
    /// / `ns_af` persistence cookies.
    Citrix,
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
            WafType::Citrix => write!(f, "Citrix NetScaler"),
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
        self.detected.iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Return all detected WAF types.
    pub fn waf_types(&self) -> Vec<&WafType> {
        self.detected.iter().map(|f| &f.waf_type).collect()
    }
}

/// Header-based fingerprint rule. Loaded from `rules.toml` at first use.
#[derive(Debug, Deserialize)]
struct HeaderRule {
    /// Header name to check (case-insensitive).
    header: String,
    /// Optional case-insensitive substring on the header value;
    /// omit to match on header presence alone.
    #[serde(default)]
    value_contains: Option<String>,
    /// WafType variant name (parsed via `parse_waf_type`).
    waf_type: String,
    confidence: f32,
    evidence_label: String,
}

/// Body-based fingerprint rule. Loaded from `rules.toml` at first use.
#[derive(Debug, Deserialize)]
struct BodyRule {
    /// Case-insensitive substring on the lowercased response body.
    pattern: String,
    /// WafType variant name (parsed via `parse_waf_type`).
    waf_type: String,
    confidence: f32,
    evidence_label: String,
}

/// Top-level shape of the embedded `rules.toml` file.
#[derive(Debug, Deserialize, Default)]
struct RulesData {
    #[serde(default, rename = "header")]
    headers: Vec<HeaderRule>,
    #[serde(default, rename = "body")]
    bodies: Vec<BodyRule>,
}

/// Parse a WafType variant name into the enum. Unknown names fall
/// through to `WafType::Unknown(name)` with the original string
/// preserved as the hint, so adding a new rule with an unrecognized
/// `waf_type` doesn't crash — it lands as Unknown and the bypass
/// strategy still picks a sensible default.
fn parse_waf_type_from_rule(name: &str) -> WafType {
    match name {
        "Cloudflare" => WafType::Cloudflare,
        "AwsWaf" => WafType::AwsWaf,
        "Akamai" => WafType::Akamai,
        "Imperva" => WafType::Imperva,
        "ModSecurity" => WafType::ModSecurity,
        "OwaspCrs" => WafType::OwaspCrs,
        "Sucuri" => WafType::Sucuri,
        "F5BigIp" => WafType::F5BigIp,
        "Barracuda" => WafType::Barracuda,
        "FortiWeb" => WafType::FortiWeb,
        "AzureWaf" => WafType::AzureWaf,
        "CloudArmor" => WafType::CloudArmor,
        "Fastly" => WafType::Fastly,
        "Wordfence" => WafType::Wordfence,
        "Citrix" => WafType::Citrix,
        other => WafType::Unknown(other.to_string()),
    }
}

/// Embedded rule set. Parsed once on first access.
fn rules() -> &'static RulesData {
    static CACHE: OnceLock<RulesData> = OnceLock::new();
    CACHE.get_or_init(|| {
        const SRC: &str = include_str!("rules.toml");
        toml::from_str(SRC).unwrap_or_else(|e| {
            // The rules file is checked in alongside the source; a parse
            // failure means a malformed edit slipped past CI. Surface
            // the error rather than silently scanning with zero rules.
            panic!("failed to parse waf/rules.toml: {}", e);
        })
    })
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
    // Iterate `get_all` rather than `get` so repeated headers are each
    // checked: `set-cookie` is emitted once per cookie, and `get` would
    // only see the first — masking the WAF persistence/bot cookies
    // (`__cf_bm`, `incap_ses`, `_abck`, `citrix_ns_id`, …) that many
    // vendors are most reliably fingerprinted by. `via` can likewise
    // carry multiple proxy hops. For the common single-value header the
    // iterator yields exactly one item, so there's no extra cost.
    for rule in &rules().headers {
        let matched = headers.get_all(rule.header.as_str()).iter().any(|val| {
            match rule.value_contains.as_deref() {
                None => true,
                Some(substr) => val
                    .to_str()
                    .ok()
                    .is_some_and(|v| v.to_ascii_lowercase().contains(substr)),
            }
        });
        if matched {
            merge_fingerprint(
                &mut result,
                WafFingerprint {
                    waf_type: parse_waf_type_from_rule(&rule.waf_type),
                    confidence: rule.confidence,
                    evidence: rule.evidence_label.clone(),
                },
            );
        }
    }

    // ── Body-based detection ────────────────────────────────────────
    if let Some(body_text) = body {
        let body_lower = body_text.to_ascii_lowercase();
        for rule in &rules().bodies {
            if body_lower.contains(rule.pattern.as_str()) {
                merge_fingerprint(
                    &mut result,
                    WafFingerprint {
                        waf_type: parse_waf_type_from_rule(&rule.waf_type),
                        confidence: rule.confidence,
                        evidence: rule.evidence_label.clone(),
                    },
                );
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
    result.detected.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    result
}

/// Fingerprint WAFs using a provocation probe: send a blatantly malicious
/// payload and analyze the blocking response. This costs one extra request.
///
/// The probe **mirrors the target's request shape** — same method, same
/// body, same auth context — so it triggers the same WAF rules that
/// actual scan requests would. Sending a GET probe to a POST-only
/// endpoint historically caused two failure modes: (1) a 405 from the
/// origin getting misread as `WafType::Unknown(HTTP 405)`, and (2)
/// missing WAFs that only inspect POST bodies. Auth (headers, UA,
/// cookies) is preserved via `apply_headers_ua_cookies`.
pub async fn fingerprint_with_probe(
    target: &crate::target_parser::Target,
    client: &reqwest::Client,
) -> WafDetectionResult {
    // Append the provocation marker to the URL query. Keeping the
    // existing query intact means routing/host-header checks behave
    // the same as a normal request to this target.
    let mut probe_url = target.url.clone();
    probe_url
        .query_pairs_mut()
        .append_pair("dalfox_waf_probe", "<script>alert(1)</script>");

    // Use the target's method and (for body-bearing methods) original
    // body so the probe shape matches the actual scan traffic. The
    // payload sits in the query for both shapes — WAFs typically
    // inspect the URL regardless of method, and putting the probe in
    // the body would risk corrupting structured payloads (JSON, XML).
    let method = target.parse_method();
    let body = target.data.clone();
    let rb = crate::utils::build_request(client, target, method, probe_url, body);

    crate::record_outbound_request().await;

    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[DBG] waf probe network error for {}: {}", target.url, e);
            }
            return WafDetectionResult::default();
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body_text = crate::utils::http::read_body(resp).await.ok();

    let mut result = fingerprint_from_response(&headers, body_text.as_deref(), status);

    // If we got a blocking status code but no WAF was identified, mark
    // as Unknown — *except* when the response is a plain rate-limit
    // (429 + `Retry-After`), which is application-level throttling, not
    // a WAF. Auto-classifying that as `WafType::Unknown` engaged bypass
    // mutations against benign rate-limited backends and produced
    // garbage results.
    let is_plain_rate_limit = status == 429 && headers.get("retry-after").is_some();
    if result.is_empty()
        && (status == 403 || status == 406 || status == 429 || status == 503)
        && !is_plain_rate_limit
    {
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
    if let Some(existing) = result
        .detected
        .iter_mut()
        .find(|e| e.waf_type == fp.waf_type)
    {
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
    a.detected.sort_by(|x, y| {
        y.confidence
            .partial_cmp(&x.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

#[cfg(test)]
mod tests;
