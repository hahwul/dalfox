//! CORS response-header construction driven by the configured allow-lists.

use super::*;

pub(crate) fn build_cors_headers(state: &AppState, req_headers: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if state.allowed_origins.is_none() {
        return headers;
    }

    // Methods/Headers (configured or defaults)
    let allow_methods = state.allow_methods.parse().unwrap_or_else(|_| {
        "GET,POST,OPTIONS,PUT,PATCH,DELETE"
            .parse()
            .expect("static CORS methods header")
    });
    let allow_headers = state.allow_headers.parse().unwrap_or_else(|_| {
        "Content-Type,X-API-KEY,Authorization"
            .parse()
            .expect("static CORS headers header")
    });

    // Wildcard
    if state.allow_all_origins {
        headers.insert(
            "Access-Control-Allow-Origin",
            "*".parse().expect("static wildcard origin"),
        );
        headers.insert("Access-Control-Allow-Methods", allow_methods);
        headers.insert("Access-Control-Allow-Headers", allow_headers);
        return headers;
    }

    // Reflect allowed origins
    if let Some(origin_val) = req_headers.get("Origin")
        && let Ok(origin_str) = origin_val.to_str()
    {
        let exact_allowed = state.allowed_origins.as_ref().is_some_and(|v| {
            v.iter()
                .any(|o| !o.starts_with("regex:") && o != "*" && o == origin_str)
        });
        let regex_allowed = state
            .allowed_origin_regexes
            .iter()
            .any(|re| re.is_match(origin_str));

        if exact_allowed || regex_allowed {
            headers.insert("Access-Control-Allow-Origin", origin_val.clone());
            headers.insert("Vary", "Origin".parse().expect("static Vary header"));
        }
    }

    headers.insert("Access-Control-Allow-Methods", allow_methods);
    headers.insert("Access-Control-Allow-Headers", allow_headers);
    headers
}
