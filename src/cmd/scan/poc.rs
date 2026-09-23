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
use crate::utils::term::{sanitize_display, sanitize_display_block};

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
        format!("{description} (needs runtime confirmation) [manual POC: {hint}]")
    } else {
        format!("{description} (needs runtime confirmation)")
    }
}

/// Short label used in the plain POC line so a reader can tell at a glance
/// whether the param lived in the URL, an HTTP header (or cookie jar),
/// the body, or the URL fragment. The `Cookie` header gets its own tag
/// since users typically copy/paste cookie strings rather than raw headers.
fn poc_location_tag(location: &str, param: &str, cookie_param: bool) -> Option<&'static str> {
    match location {
        // A per-cookie param, or the literal `Cookie` header, folds to a
        // cookie POC.
        "Header" if cookie_param || param.eq_ignore_ascii_case("cookie") => Some("cookie"),
        "Header" => Some("hdr"),
        "GraphqlBody" => Some("graphql"),
        "XmlBody" => Some("xml"),
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
        if result.location == "Path" {
            // Every producer that tags a finding `Path` stores in `data` the
            // exact URL it sent (`build_injected_url`, which already encodes
            // the segment). Use it verbatim. The legacy rewrite below looks
            // for the *raw* payload in `data`; `build_injected_url`'s output
            // percent-encodes `<`, `>`, `"` and spaces, so for nearly every
            // HTML payload it missed and appended the payload again as an
            // extra trailing segment (`/a/<p>/c/<p>`) — a different route, so
            // the POC reproduced nothing. It also re-encoded the payload with
            // the first `--encoders` entry (`html`, `base64`, …), a value the
            // scan never sent to this URL.
        } else if result.param.starts_with("path_segment_") {
            // Legacy results with no recorded location (deserialized from an
            // older report): rebuild the path POC from the payload.
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
        } else if result.poc_url_complete || result.param == "-" {
            // AST DOM-XSS findings have already built a complete POC URL via
            // `ast_integration::build_dom_xss_poc_url` (which places the
            // payload in the fragment / search / path according to the
            // detected DOM source). Skip query synthesis here — otherwise
            // we'd append `?q=<payload>` after a URL that already carries
            // `#<payload>`, producing a confusing double-injection POC.
            //
            // The `"-"` arm is the legacy sentinel those findings used to
            // carry before they reported the real source parameter (#1238);
            // kept so any deserialized/older result still renders correctly.
        } else if !url.contains(&result.payload) && url_can_carry_payload {
            // Synthesize `?param=payload` ONLY when the param actually
            // travels on the URL. For Header/Cookie/Body locations the
            // payload is delivered via a side channel, so injecting it
            // into the query would produce a POC that doesn't reproduce
            // the finding.
            let sep = if url.contains('?') { '&' } else { '?' };
            // The name is percent-encoded like the value. Parameter names are
            // target-derived (page forms, parameter mining) and pass no
            // character filter, so a name carrying `&`, `#` or `=` used to
            // splice extra query structure — or a fragment — into the POC URL.
            url = format!(
                "{}{}{}={}",
                url,
                sep,
                urlencoding::encode(&result.param),
                urlencoding::encode(&result.payload)
            );
        }
        url
    };

    // Short location hint surfaced in plain POC (e.g. `[GET][hdr]`).
    let loc_segment = match poc_location_tag(&result.location, &result.param, result.cookie_param) {
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

/// Wrap `s` in POSIX single quotes so a shell passes it through as one
/// literal argument.
///
/// Every field interpolated into a `curl` / `httpie` POC — the parameter
/// name, the payload, the attack URL, a content type, a request body — is
/// target-derived: parameter names come from the page's own forms and from
/// parameter mining, which apply no character filter. Double quotes (the old
/// scheme) still let the shell see `$`, a backtick or `\`, so a page could
/// choose a parameter name like `a";id;"b` or `c$(id)d` and have the operator
/// run it by pasting the POC. Single quotes disable every shell expansion;
/// the only character needing care is `'` itself, closed and re-opened
/// around an escaped literal (`'\''`).
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// The value a side-channel (header / cookie / body) POC must send: the
/// as-sent, pre-encoded value when the scan applied one (see
/// `Result::wire_payload`), otherwise the raw payload.
///
/// Query / path POCs don't need this — `result.data` is already built from the
/// as-sent value — but a header, cookie or body POC interpolates the value
/// itself, and the raw payload drops e.g. the WAF window-pad prefix the
/// finding only got past the WAF with.
fn poc_wire_value(result: &crate::scanning::result::Result) -> &str {
    result.wire_payload.as_deref().unwrap_or(&result.payload)
}

/// Render a runnable `curl` invocation that reproduces the finding.
/// For header / cookie / body locations we emit the matching side-channel
/// flag so copy-pasting actually exercises the same wire request — a plain
/// URL would silently lose the payload.
///
/// Every interpolated value goes through [`shell_single_quote`]; nothing is
/// pasted into the command unquoted.
fn render_curl_poc(result: &crate::scanning::result::Result, attack_url: &str) -> String {
    let method = shell_single_quote(&result.method.to_uppercase());
    let url = shell_single_quote(attack_url);
    let field = |name: &str, value: &str| shell_single_quote(&format!("{}={}", name, value));
    let value = poc_wire_value(result);
    match result.location.as_str() {
        // A cookie param travels as `Cookie: name=value` (see
        // `url_inject::build_header_request`). A header param that merely
        // happens to be *named* `Cookie` is sent as `Cookie: <value>` and is
        // rendered by the plain `-H` arm below — `-b 'Cookie=<value>'` would
        // send a cookie named `Cookie` instead.
        "Header" if result.cookie_param => format!(
            "curl -X {} -b {} {}\n",
            method,
            field(&result.param, value),
            url
        ),
        "Header" => format!(
            "curl -X {} -H {} {}\n",
            method,
            shell_single_quote(&format!("{}: {}", result.param, value)),
            url
        ),
        // `--data` sends its argument verbatim, so a payload carrying `&`, `+`
        // or `%` (entity-encoded variants, `'ale'+'rt'` splits, …) was split
        // into extra fields, turned into spaces, or percent-decoded by the
        // server — not the value the scanner sent through a form serializer.
        // `--data-urlencode name=content` encodes the content; the name part
        // is taken as already encoded, so encode it here.
        "Body" => format!(
            "curl -X {} --data-urlencode {} {}\n",
            method,
            field(&urlencoding::encode(&result.param), value),
            url
        ),
        // `--data` sends `application/x-www-form-urlencoded`; a multipart
        // finding only reproduces as a multipart request. `--form-string`
        // builds one (with curl's own boundary), matching the
        // `reqwest::multipart::Form` the scanner actually sent. It must be
        // `--form-string`, not `-F`: under `-F` a value with a leading `<` or
        // `@` means "read the field from this file" — and every HTML payload
        // starts with `<`, so `-F` would try to open a bogus file.
        "MultipartBody" => format!(
            "curl -X {} --form-string {} {}\n",
            method,
            field(&result.param, value),
            url
        ),
        // Built with `serde_json` rather than hand-spliced into a `{"k":"v"}`
        // template: a parameter name or payload carrying `"` or a backslash
        // used to produce a body that wasn't valid JSON at all, so the POC
        // reproduced nothing.
        "JsonBody" => format!(
            "curl -X {} -H 'Content-Type: application/json' --data {} {}\n",
            method,
            shell_single_quote(&json_object_body(&result.param, value)),
            url
        ),
        // GraphQL / XML carry a full structured document as the body — a
        // faithful one-liner can't be rebuilt from (param, payload) alone, so
        // replay the exact recorded request body (rebuilt from the param's
        // pipeline in `build_request_text`). Falls back to a plain-URL curl if
        // the request text wasn't recorded.
        "GraphqlBody" | "XmlBody" => match request_content_type_and_body(result.request.as_deref())
        {
            Some((ct, body)) => format!(
                "curl -X {} -H {} --data {} {}\n",
                method,
                shell_single_quote(&format!("Content-Type: {}", ct)),
                shell_single_quote(body),
                url
            ),
            None => format!("curl -X {} {}\n", method, url),
        },
        _ => format!("curl -X {} {}\n", method, url),
    }
}

/// Build a one-field JSON object body (`{"param":"payload"}`) with
/// `serde_json`, so quoting/escaping inside either value is the serializer's
/// problem rather than a hand-written template's.
fn json_object_body(param: &str, payload: &str) -> String {
    let mut map = serde_json::Map::with_capacity(1);
    map.insert(
        param.to_string(),
        serde_json::Value::String(payload.to_string()),
    );
    serde_json::Value::Object(map).to_string()
}

/// Extract `(Content-Type, body)` from a recorded raw HTTP request text
/// (`build_request_text` output). The body is everything after the blank line
/// that separates headers from body (`\r\n\r\n`); the Content-Type is read
/// from the headers. Returns `None` when there is no body section.
fn request_content_type_and_body(request: Option<&str>) -> Option<(String, &str)> {
    let request = request?;
    let (head, body) = request.split_once("\r\n\r\n")?;
    let ct = head
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-type")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_else(|| "application/octet-stream".to_string());
    Some((ct, body))
}

/// Escape httpie's own request-item separators inside a field/header *name*.
///
/// Shell quoting only gets the string to httpie in one piece; httpie then
/// splits each item on the first unescaped `:` / `=` / `@` / `;`, so a mined
/// parameter name containing one of those was rejected outright ("Invalid
/// item") and the POC reproduced nothing. A backslash makes httpie take the
/// character literally.
fn httpie_escape_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if matches!(ch, '\\' | ':' | '=' | '@' | ';') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `httpie` mirror of [`render_curl_poc`]. Same quoting rule: every
/// interpolated value is single-quoted.
fn render_httpie_poc(result: &crate::scanning::result::Result, attack_url: &str) -> String {
    let method = shell_single_quote(&result.method.to_lowercase());
    let url = shell_single_quote(attack_url);
    let value = poc_wire_value(result);
    match result.location.as_str() {
        "Header" if result.cookie_param => format!(
            "http {} {} {}\n",
            method,
            url,
            shell_single_quote(&format!("Cookie:{}={}", result.param, value))
        ),
        "Header" => format!(
            "http {} {} {}\n",
            method,
            url,
            shell_single_quote(&format!("{}:{}", httpie_escape_name(&result.param), value))
        ),
        "Body" => format!(
            "http -f {} {} {}\n",
            method,
            url,
            shell_single_quote(&format!("{}={}", httpie_escape_name(&result.param), value))
        ),
        // httpie's `-f`/`--form` sends urlencoded unless a file field is
        // present; `--multipart` forces the multipart/form-data request a
        // multipart finding needs to reproduce.
        "MultipartBody" => format!(
            "http --multipart {} {} {}\n",
            method,
            url,
            shell_single_quote(&format!("{}={}", httpie_escape_name(&result.param), value))
        ),
        "JsonBody" => format!(
            "http {} {} {}\n",
            method,
            url,
            shell_single_quote(&format!("{}={}", httpie_escape_name(&result.param), value))
        ),
        // Feed the exact recorded structured body to httpie via stdin — its
        // `key=value` field syntax can't express a full GraphQL/XML document.
        "GraphqlBody" | "XmlBody" => match request_content_type_and_body(result.request.as_deref())
        {
            Some((ct, body)) => format!(
                "http {} {} {} <<< {}\n",
                method,
                url,
                shell_single_quote(&format!("Content-Type:{}", ct)),
                shell_single_quote(body)
            ),
            None => format!("http {} {}\n", method, url),
        },
        _ => format!("http {} {}\n", method, url),
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
    let line = format!(
        "[INF][{}] {} | {}",
        sanitize_display(&tag),
        sanitize_display(&result.data),
        sanitize_display(&result.message_str)
    );
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
            sanitize_display(&result.evidence)
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
    // The POC line embeds target-derived bytes (the URL, the parameter name,
    // and for `http-request` the whole recorded request). Escape control
    // bytes before anything is printed — `strip_ansi` only runs on the
    // `--no-color` path, so on a colour terminal a response could otherwise
    // drive OSC sequences straight at the operator. `sanitize_display_block`
    // keeps the raw-HTTP line structure so the request POC stays pasteable.
    let poc_line = sanitize_display_block(&poc_line);
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
    // Only populated under `--baseline-mode annotate`; without a baseline the
    // block keeps its historical shape.
    if result.new_since_baseline.is_some() {
        sections.push("Baseline");
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

    // AST DOM-XSS findings — the `DOM-XSS` producers that carry no catalog
    // message id — describe the source→sink flow and its confirmation status:
    // "DOM-based XSS via URLSearchParams.get(q) to innerHTML (needs runtime
    // confirmation)". The generic labels below threw that away and described a
    // static inference as an observation, which is what made `[A]` results
    // read like verified ones (#1238). JSON already carried the real text.
    let is_ast_dom_finding =
        result.message_id == 0 && result.inject_type == "DOM-XSS" && !result.message_str.is_empty();
    let issue_text = if is_ast_dom_finding {
        result.message_str.as_str()
    } else if result.result_type == FindingType::Reflected {
        "XSS payload reflected"
    } else {
        "XSS payload DOM object identified"
    };
    output.push_str(&format!(
        "  \x1b[90m{}\x1b[0m \x1b[38;5;247mIssue:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
        bullet_for(idx),
        sanitize_display(issue_text)
    ));
    idx += 1;

    output.push_str(&format!(
        "  \x1b[90m{}\x1b[0m \x1b[38;5;247mPayload:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
        bullet_for(idx),
        sanitize_display(&result.payload)
    ));
    idx += 1;

    if let Some((line_num, context)) = context_info {
        output.push_str(&format!(
            "  \x1b[90m{}\x1b[0m \x1b[38;5;247mL{}:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
            bullet_for(idx),
            line_num,
            sanitize_display(&context)
        ));
        idx += 1;
    }

    if let Some(is_new) = result.new_since_baseline {
        output.push_str(&format!(
            "  \x1b[90m{}\x1b[0m \x1b[38;5;247mBaseline:\x1b[0m \x1b[38;5;247m{}\x1b[0m\n",
            bullet_for(idx),
            if is_new { "new" } else { "known" }
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
                output.push_str(&format!(
                    "      \x1b[38;5;247m{}\x1b[0m\n",
                    sanitize_display(line)
                ));
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
                output.push_str(&format!(
                    "      \x1b[38;5;247m{}\x1b[0m\n",
                    sanitize_display(line)
                ));
            }
        }
    }

    output
}

#[cfg(test)]
mod tests;
