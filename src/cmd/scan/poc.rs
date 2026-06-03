//! Proof-of-concept rendering: `plain` / `curl` / `httpie` / `http-request`
//! POC lines plus the full plain-text finding block (POC header + tree). Split
//! out of `scan.rs` so the rendering logic lives apart from orchestration.

use super::GLOBAL_ENCODERS;
use super::postprocess::extract_context;
use crate::encoding::{
    base64_encode, double_url_encode, html_entity_encode, quadruple_url_encode, triple_url_encode,
    url_encode,
};
use crate::scanning::result::FindingType;

// Kept around for unit-test coverage of the message-shape contract.
// The actual scan, server, and MCP paths now go through
// `ast_integration::run_initial_ast_dom_analysis`, which inlines the
// same hint logic. If the contract drifts the unit tests under
// `src/cmd/scan/tests.rs` will catch it.
#[allow(dead_code)]
pub(crate) fn build_ast_dom_message(
    description: &str,
    source: &str,
    target_url: &str,
    payload: &str,
) -> String {
    if let Some(hint) =
        crate::scanning::ast_integration::build_dom_xss_manual_poc_hint(target_url, source, payload)
    {
        format!("{description} (검증 필요) [manual POC: {hint}]")
    } else {
        format!("{description} (검증 필요) [경량 확인: 파라미터 없음]")
    }
}

/// Short label used in the plain POC line so a reader can tell at a glance
/// whether the param lived in the URL, an HTTP header (or cookie jar),
/// the body, or the URL fragment. The `Cookie` header gets its own tag
/// since users typically copy/paste cookie strings rather than raw headers.
fn poc_location_tag(location: &str, param: &str) -> Option<&'static str> {
    match location {
        // Header location with the literal `Cookie` name folds to a cookie POC.
        "Header" if param.eq_ignore_ascii_case("cookie") => Some("cookie"),
        "Header" => Some("hdr"),
        "Body" | "JsonBody" | "MultipartBody" => Some("body"),
        "Path" => Some("path"),
        "Fragment" => Some("frag"),
        // Query is the historical default — omit the tag to keep the
        // existing plain output stable for the common case.
        "" | "Query" => None,
        _ => None,
    }
}

/// Returns true when the wire location is something the POC URL alone
/// can express. Header / Cookie / Body / JsonBody / MultipartBody all
/// require side channels (header, cookie jar, body) so we must NOT
/// synthesize a `?param=payload` query — that historically produced
/// misleading POC URLs like `http://target/?X-Custom-Header=<svg…>` for
/// findings that actually came from header injection.
fn poc_location_in_url(location: &str) -> bool {
    matches!(location, "" | "Query" | "Path" | "Fragment")
}

pub(crate) fn generate_poc(result: &crate::scanning::result::Result, poc_type: &str) -> String {
    // Helper: selective path encoding (space, #, ?, % only) to keep exploit chars visible.
    fn selective_path_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for ch in s.chars() {
            match ch {
                ' ' => out.push_str("%20"),
                '#' => out.push_str("%23"),
                '?' => out.push_str("%3F"),
                '%' => out.push_str("%25"),
                _ => out.push(ch),
            }
        }
        out
    }

    // Apply user-specified encoders (highest precedence first) to path payload if requested.
    // We only transform the payload portion inside the path (if any); query/body already handled upstream.
    fn apply_path_encoders_if_requested(payload: &str) -> String {
        let Some(encs) = GLOBAL_ENCODERS.get() else {
            return selective_path_encode(payload);
        };
        // Priority order: explicit user order (stop at first transforming encoder that is not 'none')
        for enc in encs {
            match enc.as_str() {
                "none" => continue,
                "url" => return url_encode(payload),
                "2url" => return double_url_encode(payload),
                "3url" => return triple_url_encode(payload),
                "4url" => return quadruple_url_encode(payload),
                "html" => return html_entity_encode(payload),
                "base64" => return base64_encode(payload),
                _ => {}
            }
        }
        // Fallback to selective path encode
        selective_path_encode(payload)
    }

    let url_can_carry_payload = poc_location_in_url(&result.location);

    let attack_url = {
        let mut url = result.data.clone();
        if result.param.starts_with("path_segment_") {
            // Determine if payload (raw or already selectively encoded) is present
            let sel = selective_path_encode(&result.payload);
            let transformed = apply_path_encoders_if_requested(&result.payload);
            if url.contains(&result.payload) {
                // Replace raw with transformed (which might be url/html/base64 etc.)
                url = url.replace(&result.payload, &transformed);
            } else if url.contains(&sel) {
                // Already selectively encoded; consider upgrading if user asked for stronger encoding
                if sel != transformed {
                    url = url.replace(&sel, &transformed);
                }
            } else {
                // Payload not visible (unexpected) – append as synthetic segment
                if !url.ends_with('/') {
                    url.push('/');
                }
                url.push_str(&transformed);
            }
        } else if url.contains('?') {
            // Query mutation already embedded
        } else if result.param == "-" {
            // AST DOM-XSS findings use `"-"` as a synthetic param name
            // and have already built a complete POC URL via
            // `ast_integration::build_dom_xss_poc_url` (which places
            // the payload in the fragment / search / path according
            // to the detected DOM source). Skip query synthesis here
            // — otherwise we'd append `?-=<payload>` after a URL that
            // already carries `#<payload>`, producing a confusing
            // double-injection POC.
        } else if !url.contains(&result.payload) && url_can_carry_payload {
            // Synthesize `?param=payload` ONLY when the param actually
            // travels on the URL. For Header/Cookie/Body locations the
            // payload is delivered via a side channel, so injecting it
            // into the query would produce a POC that doesn't reproduce
            // the finding.
            let sep = if url.contains('?') { '&' } else { '?' };
            url = format!(
                "{}{}{}={}",
                url,
                sep,
                result.param,
                urlencoding::encode(&result.payload)
            );
        }
        url
    };

    // Short location hint surfaced in plain POC (e.g. `[GET][hdr]`).
    let loc_segment = match poc_location_tag(&result.location, &result.param) {
        Some(tag) => format!("[{}]", tag),
        None => String::new(),
    };

    match poc_type {
        "plain" => format!(
            "[POC][{}][{}]{}[{}] {}\n",
            result.result_type, result.method, loc_segment, result.inject_type, attack_url
        ),
        "curl" => render_curl_poc(result, &attack_url),
        "httpie" => render_httpie_poc(result, &attack_url),
        "http-request" => {
            if let Some(request) = &result.request {
                format!("{}\n", request)
            } else {
                format!("{}\n", attack_url)
            }
        }
        _ => format!(
            "[POC][{}][{}]{}[{}] {}\n",
            result.result_type, result.method, loc_segment, result.inject_type, attack_url
        ),
    }
}

/// Render a runnable `curl` invocation that reproduces the finding.
/// For header / cookie / body locations we emit the matching side-channel
/// flag so copy-pasting actually exercises the same wire request — a plain
/// URL would silently lose the payload.
fn render_curl_poc(result: &crate::scanning::result::Result, attack_url: &str) -> String {
    let method = result.method.to_uppercase();
    let escaped = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    match result.location.as_str() {
        "Header" if result.param.eq_ignore_ascii_case("cookie") => format!(
            "curl -X {} -b \"{}={}\" \"{}\"\n",
            method,
            result.param,
            escaped(&result.payload),
            attack_url
        ),
        "Header" => format!(
            "curl -X {} -H \"{}: {}\" \"{}\"\n",
            method,
            result.param,
            escaped(&result.payload),
            attack_url
        ),
        "Body" | "MultipartBody" => format!(
            "curl -X {} --data \"{}={}\" \"{}\"\n",
            method,
            result.param,
            escaped(&result.payload),
            attack_url
        ),
        "JsonBody" => format!(
            "curl -X {} -H \"Content-Type: application/json\" --data \"{{\\\"{}\\\":\\\"{}\\\"}}\" \"{}\"\n",
            method,
            result.param,
            escaped(&result.payload),
            attack_url
        ),
        _ => format!("curl -X {} \"{}\"\n", method, attack_url),
    }
}

/// `httpie` mirror of [`render_curl_poc`].
fn render_httpie_poc(result: &crate::scanning::result::Result, attack_url: &str) -> String {
    let method = result.method.to_lowercase();
    match result.location.as_str() {
        "Header" if result.param.eq_ignore_ascii_case("cookie") => format!(
            "http {} \"{}\" \"Cookie:{}={}\"\n",
            method, attack_url, result.param, result.payload
        ),
        "Header" => format!(
            "http {} \"{}\" \"{}:{}\"\n",
            method, attack_url, result.param, result.payload
        ),
        "Body" | "MultipartBody" => format!(
            "http -f {} \"{}\" \"{}={}\"\n",
            method, attack_url, result.param, result.payload
        ),
        "JsonBody" => format!(
            "http {} \"{}\" \"{}={}\"\n",
            method, attack_url, result.param, result.payload
        ),
        _ => format!("http {} \"{}\"\n", method, attack_url),
    }
}

/// Render a single finding as the user-visible "plain" block — POC header
/// line followed by the tree details (Issue / Payload / optional Line /
/// optional Request / optional Response). Always emits ANSI escape codes;
/// the caller decides whether to print as-is or strip via `cprintln!` /
/// `strip_ansi` (e.g. when `--no-color` is in effect).
///
/// Shared by the end-of-scan plain renderer and the mid-scan streaming
/// printer so the two paths can't drift apart and so the same finding
/// isn't emitted twice with different shapes (the old streamer printed
/// just the POC line, then end-of-scan re-emitted POC + tree, leaving
/// users with a duplicated POC URL).
/// Render an informational finding (no payload/parameter): a single tagged
/// summary line plus an evidence sub-line. Cyan in `plain`, uncolored otherwise.
fn render_informational_block(result: &crate::scanning::result::Result, poc_type: &str) -> String {
    let tag = if result.inject_type.is_empty() {
        "Informational".to_string()
    } else {
        result.inject_type.clone()
    };
    let line = format!("[INF][{}] {} | {}", tag, result.data, result.message_str);
    let mut output = String::new();
    if poc_type == "plain" {
        output.push_str(&format!("\x1b[36m{}\x1b[0m\n", line.trim_end()));
    } else {
        output.push_str(line.trim_end());
        output.push('\n');
    }
    if !result.evidence.is_empty() {
        output.push_str(&format!(
            "  \x1b[90m└──\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
            result.evidence
        ));
    }
    output
}

pub(crate) fn render_finding_block(
    result: &crate::scanning::result::Result,
    poc_type: &str,
    include_request: bool,
    include_response: bool,
) -> String {
    // Informational findings (e.g. outdated/vulnerable libraries) have no
    // payload/parameter, so the payload-oriented POC block below doesn't apply —
    // render a compact, self-contained line instead.
    if result.result_type == FindingType::Informational {
        return render_informational_block(result, poc_type);
    }

    let mut output = String::new();

    let poc_line = generate_poc(result, poc_type);
    let trimmed = poc_line.trim_end();
    // Type-based colorization only makes sense for the `plain` POC; the
    // other formats (curl / httpie / http-request) are meant to be
    // copy-pasted into a shell and shouldn't have ANSI bytes baked in.
    let colored_poc = if poc_type == "plain" {
        match result.result_type {
            FindingType::Verified => format!("\x1b[31m{}\x1b[0m", trimmed),
            FindingType::Reflected => format!("\x1b[33m{}\x1b[0m", trimmed),
            FindingType::AstDetected => format!("\x1b[35m{}\x1b[0m", trimmed),
            // Unreachable (early-returned above) but required for exhaustiveness.
            FindingType::Informational => trimmed.to_string(),
        }
    } else {
        trimmed.to_string()
    };
    output.push_str(&colored_poc);
    output.push('\n');

    let context_info = if let Some(resp) = &result.response {
        extract_context(resp, &result.payload)
    } else {
        None
    };

    let mut sections: Vec<&str> = vec!["Issue", "Payload"];
    if context_info.is_some() {
        sections.push("Line");
    }
    let want_request = include_request && result.request.is_some();
    let want_response = include_response && result.response.is_some();
    if want_request {
        sections.push("Request");
    }
    if want_response {
        sections.push("Response");
    }
    let last_idx = sections.len().saturating_sub(1);
    let bullet_for = |i: usize| {
        if i == last_idx {
            "└──"
        } else {
            "├──"
        }
    };

    let mut idx = 0usize;

    let issue_text = if result.result_type == FindingType::Reflected {
        "XSS payload reflected"
    } else {
        "XSS payload DOM object identified"
    };
    output.push_str(&format!(
        "  \x1b[90m{}\x1b[0m \x1b[38;5;247mIssue:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
        bullet_for(idx),
        issue_text
    ));
    idx += 1;

    output.push_str(&format!(
        "  \x1b[90m{}\x1b[0m \x1b[38;5;247mPayload:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
        bullet_for(idx),
        result.payload
    ));
    idx += 1;

    if let Some((line_num, context)) = context_info {
        output.push_str(&format!(
            "  \x1b[90m{}\x1b[0m \x1b[38;5;247mL{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
            bullet_for(idx),
            line_num,
            context
        ));
        idx += 1;
    }

    if want_request {
        output.push_str(&format!(
            "  \x1b[90m{}\x1b[0m \x1b[38;5;247mRequest:\x1b[0m\n",
            bullet_for(idx)
        ));
        if let Some(req) = &result.request {
            for line in req.lines() {
                output.push_str(&format!("      \x1b[38;5;247m{}\x1b[0m\n", line));
            }
        }
        idx += 1;
    }

    if want_response {
        output.push_str(&format!(
            "  \x1b[90m{}\x1b[0m \x1b[38;5;247mResponse:\x1b[0m\n",
            bullet_for(idx)
        ));
        if let Some(resp) = &result.response {
            for line in resp.lines() {
                output.push_str(&format!("      \x1b[38;5;247m{}\x1b[0m\n", line));
            }
        }
    }

    output
}

#[cfg(test)]
mod tests;
