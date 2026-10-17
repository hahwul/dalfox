//! Response serialization, the shared `{code,msg,data}` envelope, and JSONP
//! wrapping. `make_api_response` is the single exit point every handler uses
//! so CORS headers and JSONP behave identically across endpoints.

use super::*;
use axum::http::HeaderValue;

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
) -> ApiReply {
    let mut cors = build_cors_headers(state, req_headers);
    // JSONP only when enabled and the named query param is a valid callback.
    let cb = (state.jsonp_enabled)
        .then(|| params.get(&state.callback_param_name))
        .flatten()
        .and_then(|s| validate_jsonp_callback(s));
    let (ct, body) = build_response_body(resp, cb.as_deref());
    // Always set an explicit Content-Type so the body is never served as
    // axum's `String` default of `text/plain; charset=utf-8`:
    // `application/json` for the normal path, `application/javascript` for
    // JSONP (chosen by `build_response_body`).
    let content_type = ct.unwrap_or("application/json; charset=utf-8");
    cors.insert("Content-Type", HeaderValue::from_static(content_type));
    // Forbid MIME sniffing on every API response. The body reflects
    // attacker-influenced input (target URLs, payload/evidence strings, error
    // messages); `nosniff` stops a browser from re-interpreting a JSON or
    // JSONP body as HTML and executing it, closing a content-type-confusion
    // XSS path regardless of how a client loads the response.
    cors.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    // Every response with a body is per-caller and sensitive: `GET /scan/{id}`
    // and `/scans` return findings — including full request/response bodies
    // when the submitter asked for them — and all of it is gated on a header
    // (`X-API-KEY`) that no cache keys on. Without an explicit directive a
    // shared cache or a reverse proxy may store a 200 under heuristic freshness
    // and replay it to a caller who never presented the key, and the browser
    // disk cache keeps a JSONP result around for whoever reads the profile
    // next. `no-store` is the only directive that keeps it out of both.
    cors.insert("Cache-Control", HeaderValue::from_static("no-store"));
    (status, cors, body)
}

pub(crate) type ApiReply = (StatusCode, HeaderMap, String);

/// The request context every API response is built from: CORS keys on
/// `headers`, JSONP on `params`.
pub(crate) struct Reply<'a> {
    pub(crate) state: &'a AppState,
    headers: &'a HeaderMap,
    params: &'a std::collections::HashMap<String, String>,
}

impl<'a> Reply<'a> {
    pub(crate) fn new(
        state: &'a AppState,
        headers: &'a HeaderMap,
        params: &'a std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            state,
            headers,
            params,
        }
    }

    /// `{code: 200, msg: "ok", data}` success envelope.
    pub(crate) fn ok<T: Serialize>(&self, data: T) -> ApiReply {
        let resp = ApiResponse {
            code: 200,
            msg: "ok".to_string(),
            data: Some(data),
        };
        make_api_response(self.state, self.headers, self.params, StatusCode::OK, &resp)
    }

    /// `{code, msg}` error envelope whose `code` mirrors the HTTP status.
    pub(crate) fn err(&self, status: StatusCode, msg: impl Into<String>) -> ApiReply {
        let resp = ApiResponse::<serde_json::Value> {
            code: status.as_u16() as i32,
            msg: msg.into(),
            data: None,
        };
        make_api_response(self.state, self.headers, self.params, status, &resp)
    }

    /// Log a refused request under `route` and answer with its envelope.
    pub(crate) fn deny(&self, denied: &Denied, route: &str) -> ApiReply {
        log(self.state, "AUTH", &denied.log_message(route));
        let resp = denied.api_response();
        make_api_response(
            self.state,
            self.headers,
            self.params,
            denied.status(),
            &resp,
        )
    }

    /// Preamble of every API-key route: the full authorization gate, then the
    /// throttled retention purge. `Some` is the refusal (logged under `route`)
    /// to return as-is.
    pub(crate) async fn authorize(&self, route: &str) -> Option<ApiReply> {
        if let Err(denied) = authorize_request(self.state, self.headers) {
            return Some(self.deny(&denied, route));
        }
        purge_expired_jobs(self.state).await;
        None
    }
}
