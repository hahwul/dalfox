//! Preflight probing: the HEAD/GET content-type + CSP + WAF + tech-detect
//! pass that runs before the attack phase, plus reqwest failure
//! classification and the `--force-waf` parser. Split out of `scan.rs`.

use super::args::ScanArgs;
use reqwest::header::CONTENT_TYPE;
use std::time::Duration;

pub(crate) fn is_allowed_content_type(ct: &str) -> bool {
    crate::utils::is_xss_scannable_content_type(ct)
}

/// Byte budget for the preflight body fetch, sent as `Range: bytes=0-8191`.
///
/// Named rather than inlined because the session baseline is derived from this
/// same response: `session::classify` has to know how much of the page the
/// baseline could see before it compares a probe against it (see
/// `SessionBaseline::body_len`).
pub(crate) const PREFLIGHT_BODY_BYTES: usize = 8192;

/// Preflight result containing content-type, CSP, body, WAF, and tech detection info.
pub(crate) struct PreflightResult {
    pub(crate) content_type: String,
    /// Content-Type from the GET response whose body is captured below. It can
    /// differ from HEAD on servers that route the methods separately.
    pub(crate) response_content_type: String,
    pub(crate) csp_header: Option<(String, String)>,
    pub(crate) response_body: Option<String>,
    pub(crate) waf_result: crate::waf::WafDetectionResult,
    pub(crate) tech_result: crate::scanning::tech_detect::TechDetectionResult,
    /// Fingerprint of the authenticated landing response, for mid-scan
    /// session-loss detection. Derived from the GET below, so it costs no
    /// extra request; `None` when this target isn't monitored (see
    /// [`crate::cmd::scan::session::monitoring_enabled`]).
    pub(crate) session_baseline: Option<super::session::SessionBaseline>,
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
    /// HEAD returned no Content-Type header — keep scanning and carry the
    /// GET body/type through for MIME-aware initial-page analysis.
    ///
    /// The session baseline rides along rather than being dropped with the
    /// rest: the target still gets scanned, so it still has a session that can
    /// die, and with `--session-check-url` the extra baseline request has
    /// already been spent. Discarding it silently disabled monitoring the
    /// operator explicitly asked for.
    NoContentType {
        session_baseline: Option<super::session::SessionBaseline>,
        response_body: Option<String>,
        response_content_type: String,
    },
    /// Hard reachability failure — the `&'static str` carries the
    /// specific error_code (`DNS_RESOLUTION_FAILED`,
    /// `TLS_HANDSHAKE_FAILED`, `REQUEST_TIMEOUT`, or
    /// `CONNECTION_FAILED`) so target_summary surfaces *which* layer
    /// failed instead of lumping DNS / refused / handshake together.
    Unreachable(&'static str),
}

/// Which layer a connect/request failure died at, read off the error chain.
enum FailureLayer {
    Dns,
    Tls,
    Refused,
    Unknown,
}

/// Sniff the source chain for the failing layer. The walk starts at
/// `err.source()`: the top-level reqwest error's Display embeds the request URL
/// (`error sending request for url (...)`), so matching it would classify a
/// plain refused connection to `/dns/x` or `tls.example.com` as DNS / TLS.
/// Shared by the banner text and the error code so they cannot drift.
fn failure_layer(err: &reqwest::Error) -> FailureLayer {
    let mut cur = std::error::Error::source(err);
    while let Some(e) = cur {
        let s = e.to_string().to_lowercase();
        if s.contains("connection refused") {
            return FailureLayer::Refused;
        }
        if s.contains("dns")
            || s.contains("name resolution")
            || s.contains("nodename")
            || s.contains("failed to lookup")
        {
            return FailureLayer::Dns;
        }
        if s.contains("certificate")
            || s.contains("handshake")
            || s.contains("tls")
            || s.contains("ssl")
        {
            return FailureLayer::Tls;
        }
        cur = e.source();
    }
    FailureLayer::Unknown
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
    // For connect / request errors, tell "DNS failed" from "TLS handshake
    // failed" from "TCP refused" in the UNREACHABLE diagnostic instead of
    // lumping every layer under "connection failed".
    if err.is_connect() || err.is_request() {
        return match failure_layer(err) {
            FailureLayer::Dns => "DNS resolution failed",
            FailureLayer::Tls => "TLS handshake failed",
            FailureLayer::Refused => "connection refused",
            FailureLayer::Unknown if err.is_connect() => "connection failed",
            FailureLayer::Unknown => "request error",
        };
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
    match failure_layer(err) {
        FailureLayer::Dns => crate::cmd::error_codes::DNS_RESOLUTION_FAILED,
        FailureLayer::Tls => crate::cmd::error_codes::TLS_HANDSHAKE_FAILED,
        FailureLayer::Refused | FailureLayer::Unknown => crate::cmd::error_codes::CONNECTION_FAILED,
    }
}

/// Print the single-line UNREACHABLE diagnostic for a hard reachability
/// failure (TLS timeouts, connection refused, DNS, etc.) so users can tell a
/// quiet scan from an unreachable target. Suppressed by `--silence`; the debug
/// channel always carries it.
fn unreachable_outcome(
    target: &crate::target_parser::Target,
    args: &ScanArgs,
    e: &reqwest::Error,
) -> PreflightOutcome {
    let reason = describe_reqwest_failure(e);
    crate::dbg_log!("preflight unreachable: {} ({})", target.url, reason);
    if !args.silence {
        crate::ceprintln!(
            "{} {} ({})",
            crate::utils::log::log_prefix("31", "UNREACHABLE"),
            target.url,
            reason
        );
    }
    PreflightOutcome::Unreachable(classify_reqwest_error_code(e))
}

pub(crate) async fn preflight_content_type(
    target: &crate::target_parser::Target,
    args: &ScanArgs,
) -> PreflightOutcome {
    let client = match target.build_client() {
        Ok(c) => c,
        Err(e) => {
            crate::dbg_log!(
                "preflight: failed to build HTTP client for {}: {}",
                target.url,
                e
            );
            return PreflightOutcome::Unreachable(crate::cmd::error_codes::CONNECTION_FAILED);
        }
    };

    // Prefer HEAD for fast Content-Type detection
    // build_preflight_request already applies headers, UA, and cookies consistently
    if target.delay > 0 {
        tokio::time::sleep(Duration::from_millis(target.delay)).await;
    }
    // Retry once on transient connect errors. At high worker counts
    // ECONNREFUSED can spuriously fire even against healthy servers as the OS
    // throttles new connection establishment; a single short backoff usually
    // recovers without losing the target. Non-connect errors (status / body /
    // decode) fail fast — retry can't help.
    const PREFLIGHT_MAX_ATTEMPTS: u32 = 2;
    const PREFLIGHT_RETRY_BACKOFF_MS: u64 = 200;
    let mut attempt = 0u32;
    // A HEAD that dies *after* the connection was made (reset, hang) is not a
    // reachability verdict: some origins and middleboxes drop HEAD and serve
    // GET normally. Keep the error and let the GET below arbitrate.
    let mut head_failure: Option<reqwest::Error> = None;
    let resp = loop {
        attempt += 1;
        let request_builder = crate::utils::build_preflight_request(
            &client,
            target,
            true,
            Some(PREFLIGHT_BODY_BYTES),
        );
        crate::record_outbound_request().await;
        match request_builder.send().await {
            Ok(r) => break Some(r),
            Err(e) => {
                // A timed-out HEAD is not retried: the GET fallback below is
                // its second attempt, so a tarpit host still costs two
                // timeouts, not three.
                if e.is_connect() && attempt < PREFLIGHT_MAX_ATTEMPTS {
                    crate::dbg_log!(
                        "preflight transient {} (attempt {}): {} — retrying",
                        describe_reqwest_failure(&e),
                        attempt,
                        target.url
                    );
                    tokio::time::sleep(Duration::from_millis(PREFLIGHT_RETRY_BACKOFF_MS)).await;
                    continue;
                }
                if !e.is_connect() {
                    crate::dbg_log!(
                        "preflight HEAD failed ({}): {} — falling back to GET",
                        describe_reqwest_failure(&e),
                        target.url
                    );
                    head_failure = Some(e);
                    break None;
                }
                return unreachable_outcome(target, args, &e);
            }
        }
    };
    let head_status = resp.as_ref().map(|r| r.status().as_u16());
    let mut head_headers = resp
        .as_ref()
        .map(|r| r.headers().clone())
        .unwrap_or_default();
    // Technology detection accumulator
    let mut tech_result = crate::scanning::tech_detect::TechDetectionResult::default();

    // WAF detection from HEAD response headers (zero extra requests).
    // Detection runs unconditionally so the operator still sees `waf.detected`
    // in target_summary even with `--waf-bypass off` — that flag only
    // disables payload mutations, not fingerprinting. To suppress
    // detection too, use `--skip-waf-probe` (no provocation request)
    // or just don't read the `waf` field.
    let mut waf_result = head_status
        .map(|status| crate::waf::fingerprint_from_response(&head_headers, None, status))
        .unwrap_or_default();
    let mut baseline_status = head_status;

    // Always fetch a small body for CSP parsing and AST analysis
    let mut response_body: Option<String> = None;
    let mut response_content_type = String::new();
    let mut session_baseline: Option<super::session::SessionBaseline> = None;
    let monitor_session = super::session::monitoring_enabled(args, target);
    let get_req =
        crate::utils::build_preflight_request(&client, target, false, Some(PREFLIGHT_BODY_BYTES));
    crate::record_outbound_request().await;
    let get_send = get_req.send().await;
    // HEAD failed, so GET is the only reachability arbiter left.
    if let (Err(e), Some(_)) = (&get_send, &head_failure) {
        return unreachable_outcome(target, args, e);
    }
    if let Ok(get_resp) = get_send {
        let get_status = get_resp.status().as_u16();
        baseline_status = Some(get_status);
        let get_headers = get_resp.headers().clone();
        if head_failure.is_some() {
            // No HEAD to read the Content-Type / CSP header from.
            head_headers = get_headers.clone();
        }
        response_content_type = get_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Captured before `read_body` consumes the response. Under
        // `--follow-redirects` this is where the chain actually ended, which is
        // the only thing the session baseline can meaningfully compare against.
        let get_final_url = get_resp.url().clone();
        if let Ok(body) = crate::utils::http::read_body_counted(get_resp).await {
            response_body = Some(body.clone());

            // Authenticated-state fingerprint for mid-scan session-loss
            // detection. Reuses this response, so monitoring adds no request
            // to the preflight budget — except with an explicit
            // `--session-check-url`, whose baseline has to come from that same
            // endpoint (see `baseline_from_check_url`).
            if monitor_session {
                // Already validated in `run_scan`; `ok().flatten()` here just
                // avoids threading a Result through preflight for a case that
                // cannot occur.
                let check_re = super::session::compile_session_check(args).ok().flatten();
                session_baseline = match args.session_check_url.as_deref() {
                    Some(check_url) => {
                        super::session::baseline_from_check_url(
                            target,
                            check_url,
                            check_re.as_ref(),
                        )
                        .await
                    }
                    None => Some(super::session::baseline_from_preflight(
                        &target.url,
                        &get_final_url,
                        get_status,
                        &get_headers,
                        &body,
                        check_re.as_ref(),
                    )),
                };
            }

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
        }
    }

    // Header policy from the HEAD response, `<meta>` policy from the GET
    // body, combined with the precedence the server / MCP surfaces use
    // (`csp_header_from_response`) — a page must be analysed identically on
    // every interface.
    let csp_header = crate::scanning::select_csp_policy(&head_headers, || {
        response_body
            .as_deref()
            .and_then(crate::scanning::extract_meta_csp)
    });

    // The landing page's own status is the probe's baseline: a probe that
    // merely gets the same blocking status back is not evidence of a WAF.
    let waf_result = finish_waf_detection(waf_result, baseline_status, target, &client, args).await;

    let ct_opt = head_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    match ct_opt {
        Some(ct) => PreflightOutcome::WithContentType(PreflightResult {
            content_type: ct,
            response_content_type,
            csp_header,
            response_body,
            waf_result,
            tech_result,
            session_baseline,
        }),
        None => PreflightOutcome::NoContentType {
            session_baseline,
            response_body,
            response_content_type,
        },
    }
}

/// Parse a WAF type string (from --force-waf) into a WafType enum.
/// Complete WAF detection from the passive fingerprints of the landing page:
/// the provocation probe, `--force-waf`, and `--waf-min-confidence`.
///
/// Shared by the CLI preflight and the server / MCP job runner
/// (`job::runner::execute_scan`). The runner used to skip WAF detection
/// entirely, so `waf_bypass` / `force_waf` / `waf_min_confidence` were accepted
/// by REST and MCP and then ignored: `compute_waf_strategy` never saw a
/// fingerprint and a job against a WAF-fronted target ran without a single
/// bypass mutation, extra encoder or pacing hint.
pub(crate) async fn finish_waf_detection(
    mut waf_result: crate::waf::WafDetectionResult,
    baseline_status: Option<u16>,
    target: &crate::target_parser::Target,
    client: &reqwest::Client,
    args: &ScanArgs,
) -> crate::waf::WafDetectionResult {
    // Provocation probe for stronger WAF detection (costs one extra request).
    // Not under `--dry-run` (nor the REST / MCP preflight, which runs as a
    // dry run): the probe carries a `<script>` payload, and a dry run promises
    // to report what would be scanned without sending attack payloads.
    if args.waf_bypass != "off" && !args.skip_waf_probe && !args.dry_run {
        let probe_result =
            crate::waf::fingerprint_with_probe(target, client, baseline_status).await;
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
    waf_result
}

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
        "citrix" | "netscaler" => crate::waf::WafType::Citrix,
        other => crate::waf::WafType::Unknown(other.to_string()),
    }
}

#[cfg(test)]
mod waf_type_tests {
    use super::parse_waf_type;
    use crate::waf::WafType;

    #[test]
    fn parses_known_waf_aliases_case_insensitively() {
        assert_eq!(parse_waf_type("CloudFlare"), WafType::Cloudflare);
        assert_eq!(parse_waf_type("cf"), WafType::Cloudflare);
        assert_eq!(parse_waf_type("aws-waf"), WafType::AwsWaf);
        assert_eq!(parse_waf_type("incapsula"), WafType::Imperva);
        assert_eq!(parse_waf_type("modsec"), WafType::ModSecurity);
        assert_eq!(parse_waf_type("crs"), WafType::OwaspCrs);
        assert_eq!(parse_waf_type("f5-bigip"), WafType::F5BigIp);
        assert_eq!(parse_waf_type("forti"), WafType::FortiWeb);
        assert_eq!(parse_waf_type("cloud-armor"), WafType::CloudArmor);
        assert_eq!(parse_waf_type("wordfence"), WafType::Wordfence);
        assert_eq!(parse_waf_type("netscaler"), WafType::Citrix);
        assert_eq!(parse_waf_type("Citrix"), WafType::Citrix);
    }

    #[test]
    fn parses_unknown_waf_as_unknown_variant() {
        assert_eq!(
            parse_waf_type("SomethingElse"),
            WafType::Unknown("somethingelse".to_string())
        );
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn args() -> ScanArgs {
        ScanArgs {
            insecure: Some(true),
            silence: true,
            skip_waf_probe: true,
            ..Default::default()
        }
    }

    /// A port nothing listens on: bind, note the port, drop the listener.
    async fn dead_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    /// The error code must come from the failing layer, not from words that
    /// merely appear in the request URL.
    #[tokio::test]
    async fn refused_connection_is_not_classified_from_url_words() {
        let port = dead_port().await;
        for path in ["x", "dns/x", "ssl/x", "tls/handshake/certificate"] {
            let target =
                crate::target_parser::parse_target(&format!("http://127.0.0.1:{port}/{path}?q=1"))
                    .unwrap();
            match preflight_content_type(&target, &args()).await {
                PreflightOutcome::Unreachable(code) => assert_eq!(
                    code,
                    crate::cmd::error_codes::CONNECTION_FAILED,
                    "path /{path}"
                ),
                _ => panic!("dead port must be unreachable (path /{path})"),
            }
        }
    }

    /// Serve HEAD by slamming the connection shut and GET with a 200.
    async fn spawn_head_hostile_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if buf[..n].starts_with(b"HEAD") {
                        return; // drop => connection closed with no response
                    }
                    let body = "<html>ok</html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn head_reset_falls_back_to_get() {
        let port = spawn_head_hostile_server().await;
        let target =
            crate::target_parser::parse_target(&format!("http://127.0.0.1:{port}/?q=1")).unwrap();
        match preflight_content_type(&target, &args()).await {
            PreflightOutcome::WithContentType(r) => {
                assert!(r.content_type.contains("text/html"));
                assert_eq!(r.response_body.as_deref(), Some("<html>ok</html>"));
            }
            PreflightOutcome::NoContentType { .. } => panic!("GET carried a Content-Type"),
            PreflightOutcome::Unreachable(c) => panic!("HEAD-only failure must not skip: {c}"),
        }
    }

    /// A HEAD that hangs past the timeout goes straight to the GET fallback
    /// instead of a second HEAD, so a tarpit costs two timeouts, not three.
    #[tokio::test]
    async fn head_timeout_is_not_retried_before_get() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let heads = Arc::new(AtomicUsize::new(0));
        let counter = heads.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if buf[..n].starts_with(b"HEAD") {
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        return;
                    }
                    let body = "<html>ok</html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        let mut target =
            crate::target_parser::parse_target(&format!("http://127.0.0.1:{port}/?q=1")).unwrap();
        target.timeout = 1;
        assert!(matches!(
            preflight_content_type(&target, &args()).await,
            PreflightOutcome::WithContentType(_)
        ));
        assert_eq!(heads.load(Ordering::SeqCst), 1, "timed-out HEAD retried");
    }
}
