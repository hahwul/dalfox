//! HAR (HTTP Archive) input support.
//!
//! A HAR file is a JSON capture of HTTP traffic exported by browser dev tools
//! and intercepting proxies (Burp, Caido, ZAP, Charles, mitmproxy, …). Each
//! `log.entries[].request` carries the full per-request shape — URL, method,
//! headers, cookies, and body — that a flattened per-line URL list throws
//! away. [`parse_har`] turns those requests into [`Target`]s so a captured
//! session can drive a scan directly, restoring a capability Dalfox Go v2 had
//! that the v3 rewrite dropped (see issue #1095).
//!
//! Only the request side is read; responses, timings, and page groupings are
//! ignored. The produced `Target`s reuse the same header/cookie/body modelling
//! as [`super::parse_raw_http_request`], then flow through the regular
//! `resolve_targets` pipeline (CLI overrides, `url|method` dedupe, scope and
//! out-of-scope filters), so HAR input behaves like any other source from that
//! point on.

use super::Target;
use serde::Deserialize;
use url::Url;

// HAR 1.2 schema, narrowed to the request fields we consume. Unknown fields
// (response, timings, cache, pages, creator, …) are ignored by serde, so this
// parses real-world exports from any tool without tracking the full spec.

#[derive(Debug, Deserialize)]
struct Har {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    #[serde(default)]
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<HarNameValue>,
    #[serde(default)]
    cookies: Vec<HarNameValue>,
    #[serde(rename = "postData", default)]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarNameValue {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(default)]
    text: Option<String>,
    /// Some exporters omit `text` and only provide parsed `params` (e.g. for
    /// `application/x-www-form-urlencoded` or multipart bodies). We synthesize
    /// a urlencoded-shaped body from these when `text` is absent.
    #[serde(default)]
    params: Vec<HarPostParam>,
}

#[derive(Debug, Deserialize)]
struct HarPostParam {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: Option<String>,
}

/// Cheap, allocation-free heuristic for the `auto` input-type detector: does
/// this text look like a HAR document? A real parse happens later in
/// [`parse_har`]; this only needs to be specific enough to distinguish a HAR
/// from a URL list or a raw HTTP request without paying for a full JSON parse
/// of a file that may be hundreds of megabytes. Requires a leading `{` (after
/// an optional UTF-8 BOM / whitespace) plus the two structural keys every HAR
/// has: `"log"` and `"entries"`. Explicit `--input-type har` bypasses this for
/// the rare ambiguous case.
pub fn is_har_content(s: &str) -> bool {
    let trimmed = s.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with('{') && trimmed.contains("\"log\"") && trimmed.contains("\"entries\"")
}

/// Parse a HAR document into one [`Target`] per usable request.
///
/// Header handling mirrors [`super::parse_raw_http_request`]: the `Host` header
/// is dropped (reqwest derives it from the URL), `Cookie` is split into
/// `target.cookies` rather than kept verbatim (so cookie auto-composition and
/// per-cookie injection work and no duplicate `Cookie` header is sent),
/// `User-Agent` is lifted into `target.user_agent`, and HTTP/2 pseudo-headers
/// plus hop-by-hop / length / encoding headers are stripped so reqwest can
/// manage the connection and transparent decompression itself.
///
/// Entries whose URL is unparseable or non-`http(s)` (`data:`, `blob:`, `ws:`,
/// browser-extension schemes, …) are skipped. Returns `Err` only when the JSON
/// is not a HAR or yields zero scannable requests; deduplication by
/// `url|method` is left to `resolve_targets`, matching the issue's contract.
pub fn parse_har(content: &str) -> Result<Vec<Target>, Box<dyn std::error::Error>> {
    // serde_json does not skip a UTF-8 BOM; strip it so exports that carry one
    // (common on Windows) parse instead of failing on the first byte.
    let content = content.trim_start_matches('\u{feff}');
    let har: Har = serde_json::from_str(content).map_err(|e| format!("invalid HAR JSON: {}", e))?;

    // Hard cap on produced targets so a large-but-valid HAR can't amplify into
    // multi-GiB resident memory (each Target plus the downstream all_target_urls
    // / host_groups / dedup copies) beyond the input byte budget. Set far above
    // any realistic capture; truncation is surfaced as a warning.
    const MAX_HAR_TARGETS: usize = 1_000_000;

    let total_entries = har.log.entries.len();
    let mut targets = Vec::new();
    let mut skipped_non_http = 0usize;

    for entry in har.log.entries {
        if targets.len() >= MAX_HAR_TARGETS {
            eprintln!(
                "[warn] HAR has {} entries; capping at {} targets to bound memory",
                total_entries, MAX_HAR_TARGETS
            );
            break;
        }
        let req = entry.request;

        let url = match Url::parse(req.url.trim()) {
            Ok(u) if matches!(u.scheme(), "http" | "https") => u,
            _ => {
                skipped_non_http += 1;
                continue;
            }
        };

        let mut headers: Vec<(String, String)> = Vec::new();
        let mut cookies: Vec<(String, String)> = Vec::new();
        let mut user_agent: Option<String> = None;

        for h in &req.headers {
            let name = h.name.trim();
            // HTTP/2 pseudo-headers (:method, :path, :scheme, :authority) are
            // not valid on the wire for reqwest's HTTP/1.1 requests.
            if name.is_empty() || name.starts_with(':') {
                continue;
            }
            if name.eq_ignore_ascii_case("cookie") {
                for kv in h.value.split(';') {
                    if let Some((k, v)) = kv.trim().split_once('=') {
                        let k = k.trim();
                        // Skip empty-name pairs (e.g. a leading `=val` or `;=v;`
                        // segment): an empty cookie name is invalid and would
                        // re-serialize into a malformed `=val` Cookie segment.
                        if k.is_empty() {
                            continue;
                        }
                        cookies.push((k.to_string(), v.trim().to_string()));
                    }
                }
                continue;
            }
            if name.eq_ignore_ascii_case("user-agent") {
                user_agent = Some(h.value.clone());
                continue;
            }
            if is_skippable_har_header(name) {
                continue;
            }
            headers.push((name.to_string(), h.value.clone()));
        }

        // The structured `cookies` array is a fallback for captures that carry
        // no usable `Cookie` header. Gate on whether the header path actually
        // produced cookies, not on whether a `Cookie` header merely existed: a
        // redacting/normalising exporter can emit an empty (or all-invalid)
        // `Cookie` header alongside a populated `cookies[]`, and keying on the
        // header's presence would then discard the real cookies and scan the
        // capture logged-out. When the header did yield cookies this stays
        // non-empty, so the fallback still can't double-count.
        if cookies.is_empty() && !req.cookies.is_empty() {
            cookies = req
                .cookies
                .iter()
                // Trim the value too, matching the Cookie-header path above, so
                // the same cookie parses identically whichever HAR field carries it.
                .map(|c| (c.name.trim(), c.value.trim()))
                // Drop empty-name cookies for parity with the Cookie-header path.
                .filter(|(k, _)| !k.is_empty())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        }

        let data = req.post_data.and_then(har_body);

        let method = {
            let m = req.method.trim();
            if m.is_empty() {
                "GET".to_string()
            } else {
                m.to_uppercase()
            }
        };

        targets.push(Target {
            method,
            data,
            headers,
            cookies,
            user_agent,
            ..Target::for_url(url)
        });
    }

    if targets.is_empty() {
        return if skipped_non_http > 0 {
            Err(format!(
                "HAR contained {} request(s) but none used an http/https URL",
                skipped_non_http
            )
            .into())
        } else {
            Err("HAR contained no requests (log.entries was empty)".into())
        };
    }

    Ok(targets)
}

/// Request headers that must not be forwarded verbatim from a HAR capture.
/// `Host` is set by reqwest from the URL; `Content-Length` is recomputed (a
/// stale value corrupts the body); `Accept-Encoding` is left to reqwest so its
/// transparent decompression stays enabled (a manual value disables it and
/// yields compressed gibberish); the rest are hop-by-hop headers tied to the
/// original connection. `Cookie` and `User-Agent` are handled separately by the
/// caller and are intentionally not listed here.
fn is_skippable_har_header(name: &str) -> bool {
    // Single source of truth shared with the raw-HTTP request parser.
    super::is_skippable_request_header(name)
}

/// Extract a request body from `postData`, preferring the captured raw `text`
/// and falling back to reconstructing an `x-www-form-urlencoded` body from
/// parsed `params`. Returns `None` for an empty body so GET-style targets stay
/// body-less.
fn har_body(pd: HarPostData) -> Option<String> {
    if let Some(text) = pd.text.filter(|t| !t.is_empty()) {
        return Some(text);
    }
    if !pd.params.is_empty() {
        // No raw `text` — reconstruct the body from the structured params. HAR
        // stores these decoded, so percent-encode each name/value (a value with
        // `&`, `=`, a space, or unicode would otherwise corrupt the body) and
        // always emit `name=` even when the value is absent. Going through the
        // form serializer keeps the result well-formed so dalfox's own
        // body-param parser re-splits it into the same fields it was built from.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                pd.params
                    .iter()
                    .map(|p| (p.name.as_str(), p.value.as_deref().unwrap_or(""))),
            )
            .finish();
        if !body.is_empty() {
            return Some(body);
        }
    }
    None
}

#[cfg(test)]
mod tests;
