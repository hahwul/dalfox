//! Response serialization, the shared `{code,msg,data}` envelope, and JSONP
//! wrapping. `make_api_response` is the single exit point every handler uses
//! so CORS headers and JSONP behave identically across endpoints.

use super::*;

// Validate JSONP callback name to prevent XSS via callback parameter.
// Rules:
// - 1..=64 length
// - First char: [A-Za-z_$]
// - Subsequent chars: [A-Za-z0-9_$\.]
pub(crate) fn validate_jsonp_callback(cb: &str) -> Option<String> {
    let cb = cb.trim();
    if cb.is_empty() || cb.len() > 64 {
        return None;
    }
    let mut chars = cb.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return None;
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '.') {
            return None;
        }
    }
    Some(cb.to_string())
}

/// Try to extract a valid JSONP callback from query params. Returns `Some(cb)` if JSONP is
/// enabled and a valid callback name is present; `None` otherwise.
pub(crate) fn extract_jsonp_callback(
    state: &AppState,
    params: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if !state.jsonp_enabled {
        return None;
    }
    params
        .get(&state.callback_param_name)
        .and_then(|s| validate_jsonp_callback(s))
}

/// Build the final HTTP response body, applying JSONP wrapping when a valid callback is present.
/// Returns `(content_type_override, body_string)`.  When `jsonp_cb` is `Some`, the body is
/// wrapped as `callback(json);` and the content-type is set to `application/javascript`.
pub(crate) fn build_response_body<T: Serialize>(
    resp: &T,
    jsonp_cb: Option<&str>,
) -> (Option<&'static str>, String) {
    let json = serde_json::to_string(resp).expect("serializable response");
    match jsonp_cb {
        Some(cb) => {
            // serde_json leaves U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH
            // SEPARATOR) as raw bytes. They're valid inside JSON strings, but in
            // a JSONP body served as application/javascript they are string-
            // literal line terminators on pre-ES2019 engines — an attacker-
            // influenced finding field (target URL, payload, evidence) carrying
            // one would break the wrapped `callback(...)` into a syntax error or
            // split its string literal. Escape them so the JS stays valid
            // regardless of finding content.
            let safe = json
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029");
            (
                Some("application/javascript; charset=utf-8"),
                format!("{}({});", cb, safe),
            )
        }
        None => (None, json),
    }
}

/// Convenience: build a complete axum response tuple with CORS + optional JSONP.
pub(crate) fn make_api_response<T: Serialize>(
    state: &AppState,
    req_headers: &HeaderMap,
    params: &std::collections::HashMap<String, String>,
    status: StatusCode,
    resp: &T,
) -> (StatusCode, HeaderMap, String) {
    let mut cors = build_cors_headers(state, req_headers);
    let cb = extract_jsonp_callback(state, params);
    let (ct, body) = build_response_body(resp, cb.as_deref());
    // Always set an explicit Content-Type so the body is never served as
    // axum's `String` default of `text/plain; charset=utf-8`:
    // `application/json` for the normal path, `application/javascript` for
    // JSONP (chosen by `build_response_body`).
    let content_type = ct.unwrap_or("application/json; charset=utf-8");
    cors.insert(
        "Content-Type",
        content_type.parse().expect("static content-type"),
    );
    // Forbid MIME sniffing on every API response. The body reflects
    // attacker-influenced input (target URLs, payload/evidence strings, error
    // messages); `nosniff` stops a browser from re-interpreting a JSON or
    // JSONP body as HTML and executing it, closing a content-type-confusion
    // XSS path regardless of how a client loads the response.
    cors.insert(
        "X-Content-Type-Options",
        "nosniff".parse().expect("static nosniff header"),
    );
    (status, cors, body)
}
