//! Preflight probing: the HEAD/GET content-type + CSP + WAF + tech-detect
//! pass that runs before the attack phase, plus reqwest failure
//! classification and the `--force-waf` parser. Split out of `scan.rs`.

use super::args::ScanArgs;
use crate::scanning::selectors;
use reqwest::header::CONTENT_TYPE;
use scraper::Html;
use std::time::Duration;

pub(crate) fn is_allowed_content_type(ct: &str) -> bool {
    crate::utils::is_xss_scannable_content_type(ct)
}

/// Preflight result containing content-type, CSP, body, WAF, and tech detection info.
pub(crate) struct PreflightResult {
    pub(crate) content_type: String,
    pub(crate) csp_header: Option<(String, String)>,
    pub(crate) response_body: Option<String>,
    pub(crate) waf_result: crate::waf::WafDetectionResult,
    pub(crate) tech_result: crate::scanning::tech_detect::TechDetectionResult,
}

/// Outcome of the `preflight_content_type` probe. We split out the
/// "couldn't get a response" case from the "got a response but no usable
/// Content-Type" case so callers can promote a hard reachability failure
/// to a skipped-target outcome (and ultimately `ScanOutcome::Error`)
/// without also skipping legitimate POST-only endpoints whose GET probe
/// returns no Content-Type.
pub(crate) enum PreflightOutcome {
    /// HEAD/GET preflight returned a response with a usable Content-Type.
    WithContentType(PreflightResult),
    /// Response was received (e.g. 405 from a POST-only endpoint) but
    /// no Content-Type header — keep scanning, just without preflight
    /// metadata (CSP, WAF, tech).
    NoContentType,
    /// Hard reachability failure — the `&'static str` carries the
    /// specific error_code (`DNS_RESOLUTION_FAILED`,
    /// `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`, or
    /// `CONNECTION_FAILED`) so target_summary surfaces *which* layer
    /// failed instead of lumping DNS / refused / handshake together.
    Unreachable(&'static str),
}

/// Compact, user-facing summary of a reqwest network failure. Keeps the
/// preflight banner single-line (e.g. "TLS timeout", "connection refused",
/// "DNS error") instead of dumping the full reqwest::Error chain.
fn describe_reqwest_failure(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        return "timeout";
    }
    if err.is_redirect() {
        return "redirect loop";
    }
    if err.is_status() {
        return "bad status";
    }
    if err.is_body() {
        return "body read failed";
    }
    if err.is_decode() {
        return "decode error";
    }
    if err.is_builder() {
        return "request build error";
    }
    // For connect / request errors, walk the source chain so we can
    // tell "DNS failed" from "TLS handshake failed" from "TCP refused"
    // in the UNREACHABLE diagnostic instead of lumping every layer
    // under "connection failed".
    if err.is_connect() || err.is_request() {
        let mut cur: Option<&dyn std::error::Error> = Some(err);
        while let Some(e) = cur {
            let s = e.to_string().to_lowercase();
            if s.contains("dns")
                || s.contains("name resolution")
                || s.contains("nodename")
                || s.contains("failed to lookup")
            {
                return "DNS resolution failed";
            }
            if s.contains("certificate")
                || s.contains("handshake")
                || s.contains("tls")
                || s.contains("ssl")
            {
                return "TLS handshake failed";
            }
            if s.contains("connection refused") {
                return "connection refused";
            }
            cur = e.source();
        }
        if err.is_connect() {
            return "connection failed";
        }
        return "request error";
    }
    "network error"
}

/// Pick the right error code for a reqwest failure so target_summary
/// surfaces DNS / TLS / timeout / refused separately. reqwest doesn't
/// expose a structured "kind" enum publicly; sniff the chained source
/// for `hyper_util::client::legacy::Error` / `hickory_resolver` /
/// `rustls`-style messages. Falls back to CONNECTION_FAILED when we
/// can't classify, which preserves prior behavior.
fn classify_reqwest_error_code(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        return crate::cmd::error_codes::REQUEST_TIMEOUT;
    }
    // Walk the source chain looking for telltale substrings.
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        let s = e.to_string().to_lowercase();
        if s.contains("dns")
            || s.contains("name resolution")
            || s.contains("nodename")
            || s.contains("failed to lookup")
        {
            return crate::cmd::error_codes::DNS_RESOLUTION_FAILED;
        }
        if s.contains("tls")
            || s.contains("handshake")
            || s.contains("certificate")
            || s.contains("ssl")
        {
            return crate::cmd::error_codes::TLS_HANDSHAKE_FAILED;
        }
        cur = e.source();
    }
    crate::cmd::error_codes::CONNECTION_FAILED
}

pub(crate) async fn preflight_content_type(
    target: &crate::target_parser::Target,
    args: &ScanArgs,
) -> PreflightOutcome {
    let client = match target.build_client() {
        Ok(c) => c,
        Err(e) => {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "[DBG] preflight: failed to build HTTP client for {}: {}",
                    target.url, e
                );
            }
            return PreflightOutcome::Unreachable(crate::cmd::error_codes::CONNECTION_FAILED);
        }
    };

    // Prefer HEAD for fast Content-Type detection
    // build_preflight_request already applies headers, UA, and cookies consistently
    if target.delay > 0 {
        tokio::time::sleep(Duration::from_millis(target.delay)).await;
    }
    // Retry once on transient connect/timeout errors. At high worker counts
    // ECONNREFUSED can spuriously fire even against healthy servers as the OS
    // throttles new connection establishment; a single short backoff usually
    // recovers without losing the target. Non-connect errors (status / body /
    // decode) fail fast — retry can't help.
    const PREFLIGHT_MAX_ATTEMPTS: u32 = 2;
    const PREFLIGHT_RETRY_BACKOFF_MS: u64 = 200;
    let mut attempt = 0u32;
    let resp = loop {
        attempt += 1;
        let request_builder =
            crate::utils::build_preflight_request(&client, target, true, Some(8192));
        crate::tick_request_count();
        match request_builder.send().await {
            Ok(r) => break r,
            Err(e) => {
                let transient = e.is_connect() || e.is_timeout();
                if transient && attempt < PREFLIGHT_MAX_ATTEMPTS {
                    if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                        eprintln!(
                            "[DBG] preflight transient {} (attempt {}): {} — retrying",
                            describe_reqwest_failure(&e),
                            attempt,
                            target.url
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(PREFLIGHT_RETRY_BACKOFF_MS)).await;
                    continue;
                }
                // Surface a single-line diagnostic for hard reachability failures
                // (TLS timeouts, connection refused, DNS, etc.) so users can
                // distinguish a quiet scan from an unreachable target. Suppressed
                // when --silence is on; the debug channel always carries it.
                let reason = describe_reqwest_failure(&e);
                if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!("[DBG] preflight unreachable: {} ({})", target.url, reason);
                }
                if !args.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    crate::ceprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[31mUNREACHABLE\x1b[0m {} ({})",
                        ts,
                        target.url,
                        reason
                    );
                }
                return PreflightOutcome::Unreachable(classify_reqwest_error_code(&e));
            }
        }
    };
    let head_status = resp.status().as_u16();
    let head_headers = resp.headers().clone();
    let ct_opt = head_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let mut csp_header = head_headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|v| ("Content-Security-Policy".to_string(), v.to_string()))
        .or_else(|| {
            head_headers
                .get("content-security-policy-report-only")
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    (
                        "Content-Security-Policy-Report-Only".to_string(),
                        v.to_string(),
                    )
                })
        });

    // Technology detection accumulator
    let mut tech_result = crate::scanning::tech_detect::TechDetectionResult::default();

    // WAF detection from HEAD response headers (zero extra requests).
    // Detection runs unconditionally so the operator still sees `waf.detected`
    // in target_summary even with `--waf-bypass off` — that flag only
    // disables payload mutations, not fingerprinting. To suppress
    // detection too, use `--skip-waf-probe` (no provocation request)
    // or just don't read the `waf` field.
    let mut waf_result = crate::waf::fingerprint_from_response(&head_headers, None, head_status);

    // Always fetch a small body for CSP parsing and AST analysis
    let mut response_body: Option<String> = None;
    let get_req = crate::utils::build_preflight_request(&client, target, false, Some(8192));
    crate::tick_request_count();
    if let Ok(get_resp) = get_req.send().await {
        let get_status = get_resp.status().as_u16();
        let get_headers = get_resp.headers().clone();
        if let Ok(body) = get_resp.text().await {
            response_body = Some(body.clone());

            // WAF detection from GET response (headers + body). Same
            // reasoning as the HEAD-based pass above — fingerprinting
            // runs unconditionally so operators using `--waf-bypass off`
            // still get the `waf.detected` field populated.
            let body_waf =
                crate::waf::fingerprint_from_response(&get_headers, Some(&body), get_status);
            crate::waf::merge_results(&mut waf_result, body_waf);

            // Technology/framework detection from GET response
            tech_result =
                crate::scanning::tech_detect::detect_technologies(&get_headers, Some(&body));

            // Only parse CSP if not already found
            if csp_header.is_none() {
                let doc = Html::parse_document(&body);
                {
                    let sel = selectors::meta_csp();
                    for el in doc.select(sel) {
                        let http_equiv = el
                            .value()
                            .attr("http-equiv")
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if http_equiv == "content-security-policy"
                            || http_equiv == "content-security-policy-report-only"
                        {
                            let content = el.value().attr("content").unwrap_or("").to_string();
                            if !content.is_empty() {
                                let name = if http_equiv == "content-security-policy" {
                                    "Content-Security-Policy".to_string()
                                } else {
                                    "Content-Security-Policy-Report-Only".to_string()
                                };
                                csp_header = Some((name, content));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Provocation probe for stronger WAF detection (costs one extra request)
    if args.waf_bypass != "off" && !args.skip_waf_probe {
        let probe_result = crate::waf::fingerprint_with_probe(target, &client).await;
        crate::waf::merge_results(&mut waf_result, probe_result);
    }

    // Handle --force-waf override
    if let Some(ref forced) = args.force_waf {
        waf_result = crate::waf::WafDetectionResult {
            detected: vec![crate::waf::WafFingerprint {
                waf_type: parse_waf_type(forced),
                confidence: 1.0,
                evidence: "forced via --force-waf".to_string(),
            }],
        };
    }

    // Drop fingerprints below the user-configured minimum confidence.
    // Default 0.0 keeps every match; users tighten this to suppress
    // weak signals (0.3 "Request blocked", 0.5 "Server: Google
    // Frontend", etc.) that often false-positive on benign origins.
    if args.waf_min_confidence > 0.0 {
        waf_result
            .detected
            .retain(|fp| fp.confidence >= args.waf_min_confidence);
    }

    match ct_opt {
        Some(ct) => PreflightOutcome::WithContentType(PreflightResult {
            content_type: ct,
            csp_header,
            response_body,
            waf_result,
            tech_result,
        }),
        None => PreflightOutcome::NoContentType,
    }
}

/// Parse a WAF type string (from --force-waf) into a WafType enum.
fn parse_waf_type(s: &str) -> crate::waf::WafType {
    match s.to_ascii_lowercase().as_str() {
        "cloudflare" | "cf" => crate::waf::WafType::Cloudflare,
        "aws" | "awswaf" | "aws-waf" => crate::waf::WafType::AwsWaf,
        "akamai" => crate::waf::WafType::Akamai,
        "imperva" | "incapsula" => crate::waf::WafType::Imperva,
        "modsecurity" | "modsec" => crate::waf::WafType::ModSecurity,
        "owasp-crs" | "owaspcrs" | "crs" => crate::waf::WafType::OwaspCrs,
        "sucuri" => crate::waf::WafType::Sucuri,
        "f5" | "bigip" | "f5-bigip" => crate::waf::WafType::F5BigIp,
        "barracuda" => crate::waf::WafType::Barracuda,
        "fortiweb" | "forti" => crate::waf::WafType::FortiWeb,
        "azure" | "azurewaf" | "azure-waf" => crate::waf::WafType::AzureWaf,
        "cloudarmor" | "cloud-armor" | "gcp" => crate::waf::WafType::CloudArmor,
        "fastly" => crate::waf::WafType::Fastly,
        "wordfence" => crate::waf::WafType::Wordfence,
        other => crate::waf::WafType::Unknown(other.to_string()),
    }
}
