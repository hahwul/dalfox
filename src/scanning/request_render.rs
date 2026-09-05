//! human-readable request text (PoC).
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

pub(crate) fn build_request_text(target: &Target, param: &Param, payload: &str) -> String {
    use crate::parameter_analysis::Location;
    let url = match param.location {
        Location::Query => {
            // Show the request against the actual sink URL — form action when
            // the param came from form discovery, otherwise target.url. The
            // displayed PoC must match the URL that scanning actually hits.
            let base = crate::scanning::url_inject::effective_query_base(&target.url, param);
            let mut pairs: Vec<(String, String)> = base
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param.name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param.name.clone(), payload.to_string()));
            }
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = base;
            url.set_query(Some(&query));
            url
        }
        Location::Path => {
            // Inject into a specific path segment (param.name pattern: path_segment_{idx})
            let mut url = target.url.clone();
            if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                let original_path = url.path();
                let mut segments: Vec<&str> = if original_path == "/" {
                    Vec::new()
                } else {
                    original_path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .collect()
                };
                if idx < segments.len() {
                    segments[idx] = payload;
                    let new_path = if segments.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", segments.join("/"))
                    };
                    url.set_path(&new_path);
                }
            }
            url
        }
        Location::Body
        | Location::JsonBody
        | Location::MultipartBody
        | Location::GraphqlBody
        | Location::XmlBody => {
            // Body params use the form action URL when discovered from a form,
            // so the displayed request matches the POST actually sent.
            crate::scanning::url_inject::effective_query_base(&target.url, param)
        }
        _ => target.url.clone(),
    };

    let method = crate::scanning::url_inject::effective_method(&target.method, param);
    // Body-bearing locations always send a body; synthesize one when the
    // target has no original `data`, so the displayed PoC isn't an empty POST.
    let (body, content_type): (Option<String>, Option<String>) = match param.location {
        Location::Body => {
            let body = crate::scanning::url_inject::urlencoded_body(
                target.data.as_deref(),
                &param.name,
                payload,
            );
            (
                Some(body),
                Some("application/x-www-form-urlencoded".to_string()),
            )
        }
        Location::JsonBody => {
            let body = crate::scanning::url_inject::json_body(
                target.data.as_deref(),
                &param.name,
                &param.value,
                payload,
            );
            (Some(body), Some("application/json".to_string()))
        }
        Location::MultipartBody => (target.data.clone(), Some("multipart/form-data".to_string())),
        // GraphQL / XML rebuild the whole body from the param's pipeline
        // (`JsonField` into the GraphQL request / `Splice` around the XML
        // injection point). `apply_param_encoding` runs that pipeline on the
        // raw `payload`, so the displayed PoC body is exactly what goes on the
        // wire.
        Location::GraphqlBody => {
            let body = crate::encoding::pre_encoding::apply_param_encoding(payload, param);
            (Some(body), Some("application/json".to_string()))
        }
        Location::XmlBody => {
            let body = crate::encoding::pre_encoding::apply_param_encoding(payload, param);
            (
                Some(body),
                Some(crate::scanning::url_inject::xml_request_content_type(
                    target,
                )),
            )
        }
        _ => (target.data.clone(), None),
    };

    let mut buf = String::with_capacity(512);

    // Request line
    buf.push_str(&method);
    buf.push(' ');
    buf.push_str(url.path());
    if let Some(q) = url.query() {
        buf.push('?');
        buf.push_str(q);
    }
    buf.push_str(" HTTP/1.1\r\nHost: ");
    buf.push_str(url.host_str().unwrap_or(""));
    // `Host` is host *and port*. Dropping it made every PoC against a
    // non-default port replay to :80/:443 — a different service, or nothing.
    // `Url::port()` is already `None` for the scheme's default port, which is
    // exactly when the Host header should omit it.
    if let Some(port) = url.port() {
        buf.push(':');
        buf.push_str(&port.to_string());
    }

    // A `Location::Header` param is injected into the request itself, not the
    // URL — as a header of its own name, or, when the name is one of the
    // target's cookies, into `Cookie` (see `url_inject::build_header_request`,
    // which this must mirror or the PoC does not reproduce what was sent).
    let header_param = matches!(param.location, Location::Header);
    let cookie_param = header_param && crate::scanning::url_inject::param_is_cookie(target, param);
    let injected_header = header_param && !cookie_param;

    for (k, v) in &target.headers {
        // `apply_header_overrides` replaces rather than appends, so a
        // same-named original is not on the wire and must not be shown here.
        if injected_header && k.eq_ignore_ascii_case(&param.name) {
            continue;
        }
        // Same for the composed `Cookie` a cookie param is injected through
        // (`build_request_with_cookie` overrides any captured Cookie header),
        // and for a captured `Content-Type` on a body injection, which
        // `build_body_request_base` drops in favour of the injector's.
        if cookie_param && k.eq_ignore_ascii_case("cookie") {
            continue;
        }
        if content_type.is_some() && k.eq_ignore_ascii_case("content-type") {
            continue;
        }
        buf.push_str("\r\n");
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(v);
    }
    if injected_header {
        buf.push_str("\r\n");
        buf.push_str(&param.name);
        buf.push_str(": ");
        buf.push_str(payload);
    }
    // Body injectors always set their own `Content-Type` on the wire; a
    // Query/Path injector re-sends the original body verbatim and passes
    // `None` here, keeping whatever the target captured.
    if let Some(ct) = &content_type {
        buf.push_str("\r\nContent-Type: ");
        buf.push_str(ct);
    }

    // Cookies. For a cookie param the injected value is written first and the
    // target's other cookies follow, matching `build_header_request` — those
    // neighbours often carry the session state the sink needs to render at all.
    if cookie_param {
        buf.push_str("\r\nCookie: ");
        buf.push_str(&param.name);
        buf.push('=');
        buf.push_str(payload);
        if let Some(rest) =
            crate::utils::compose_cookie_header_excluding(&target.cookies, Some(&param.name))
            && !rest.is_empty()
        {
            buf.push_str("; ");
            buf.push_str(&rest);
        }
    } else if !target.cookies.is_empty()
        && !target
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cookie"))
    {
        // Mirrors `apply_headers_ua_cookies`: `target.cookies` are auto-attached
        // only when the target does not already carry its own Cookie header
        // (already emitted above), never as a second Cookie line.
        buf.push_str("\r\nCookie: ");
        for (i, (k, v)) in target.cookies.iter().enumerate() {
            if i > 0 {
                buf.push_str("; ");
            }
            buf.push_str(k);
            buf.push('=');
            buf.push_str(v);
        }
    }

    if let Some(data) = &body {
        buf.push_str("\r\nContent-Length: ");
        buf.push_str(&data.len().to_string());
        buf.push_str("\r\n\r\n");
        buf.push_str(data);
    } else {
        buf.push_str("\r\n");
    }

    buf
}
