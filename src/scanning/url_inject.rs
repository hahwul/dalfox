//! Shared helpers for constructing injected URLs for reflection / DOM XSS testing.
//!
//! This consolidates logic that previously appeared in multiple modules (reflection checks,
//! scanning orchestration, etc.). Centralizing the transformation avoids subtle divergence
//! (e.g., inconsistent path segment encoding or query param insertion).
//!
//! Notes:
//! - Query parameter injection: replaces existing parameter value or appends when absent.
//! - Path segment injection: parameter name pattern "path_segment_{idx}" where idx is the
//!   zero-based index of the segment in the URL path. Only simple visible encoding is
//!   applied (space, '#', '?', '%') to keep the payload recognizable in PoCs without
//!   breaking path semantics. Additional encoding strategies (full percent-encoding,
//!   unicode escaping) can be layered in higher-level modules if needed.

use crate::parameter_analysis::{Location, Param};
use crate::target_parser::Target;
use reqwest::Client;
use std::borrow::Cow;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Percent-encode a query component directly into `out`, preserving existing `%XX` sequences.
fn encode_query_component_preserving_pct_into(raw: &str, out: &mut String) {
    let bytes = raw.as_bytes();
    let mut idx = 0;

    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && is_hex(bytes[idx + 1])
            && is_hex(bytes[idx + 2])
        {
            out.push('%');
            out.push(bytes[idx + 1] as char);
            out.push(bytes[idx + 2] as char);
            idx += 3;
            continue;
        }

        let ch = raw[idx..].chars().next().expect("valid utf-8 char");
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).as_bytes() {
                out.push('%');
                out.push(HEX[(*byte >> 4) as usize] as char);
                out.push(HEX[(*byte & 0xF) as usize] as char);
            }
        }
        idx += ch.len_utf8();
    }
}

/// Selectively encode a path segment for readability while preserving most characters
/// for exploit clarity. This mirrors prior inline logic (space, '#', '?', '%').
/// If more rigorous encoding is desired, enhance or replace this function centrally.
fn selective_path_segment_encode(raw: &str) -> Cow<'_, str> {
    // Fast path: if no special chars, return borrowed (no allocation)
    if !raw
        .bytes()
        .any(|b| matches!(b, b' ' | b'#' | b'?' | b'%' | b'\n' | b'\t' | b'\r'))
    {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        match ch {
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\t' => out.push_str("%09"),
            '\r' => out.push_str("%0D"),
            _ => out.push(ch),
        }
    }
    Cow::Owned(out)
}

/// Resolve the URL where a Query-location param should be probed.
///
/// When `param` was discovered through a `<form action=...>`, its
/// `form_action_url` points at the form's action endpoint — that's the URL
/// hosting the sink, not the page where the `<form>` tag was found. Without
/// this redirection, GET-form scans probe the form-host page (no sink) and
/// produce a false negative even though discovery flagged the field as
/// reflecting at the action URL.
///
/// For non-Query locations and for params without a `form_action_url`, the
/// caller's `target_url` is returned unchanged.
pub fn effective_query_base(target_url: &url::Url, param: &Param) -> url::Url {
    let uses_form_action = matches!(
        param.location,
        Location::Query | Location::Body | Location::JsonBody | Location::MultipartBody
    );
    if uses_form_action
        && let Some(ref action) = param.form_action_url
        && let Ok(parsed) = url::Url::parse(action)
    {
        return parsed;
    }
    target_url.clone()
}

/// Method used when mining/injecting against the target's own request body
/// (`-d` / imported body) without a form-discovery context.
///
/// Body-less verbs (GET/HEAD/OPTIONS/TRACE) force POST. Body-capable verbs
/// (POST/PUT/PATCH/DELETE/QUERY/…) are preserved so scans like
/// `-X QUERY -d '…'` actually send QUERY (RFC 10008).
pub fn body_location_method(target_method: &str) -> reqwest::Method {
    match target_method.trim().to_ascii_uppercase().as_str() {
        "" | "GET" | "HEAD" | "OPTIONS" | "TRACE" => reqwest::Method::POST,
        other => other.parse().unwrap_or(reqwest::Method::POST),
    }
}

/// Method used for Body / JsonBody / MultipartBody injection for a concrete
/// param. HTML form-discovered sinks (`form_action_url` set) always submit as
/// POST — forms never use QUERY/PUT/etc. Own-body params fall through to
/// [`body_location_method`].
pub fn body_location_method_for_param(target_method: &str, param: &Param) -> reqwest::Method {
    if param.form_action_url.is_some() {
        return reqwest::Method::POST;
    }
    body_location_method(target_method)
}

/// HTTP method that will actually be used to send a payload-bearing
/// request for `param`. Body-bearing locations use
/// [`body_location_method_for_param`]; other locations keep the target's own
/// method. Finding metadata must match the verb that is actually sent.
pub fn effective_method(target_method: &str, param: &Param) -> String {
    match param.location {
        Location::Body | Location::JsonBody | Location::MultipartBody => {
            body_location_method_for_param(target_method, param)
                .as_str()
                .to_string()
        }
        _ => target_method.to_string(),
    }
}

/// Build a URL string with the given parameter injected/replaced by `injected`.
/// For Location::Query it rewrites or appends the query pair.
/// For Location::Path it replaces the indexed segment derived from param name pattern
/// "path_segment_{idx}". Other locations return the original URL unchanged.
///
/// Returns the new URL as a String. (We return String instead of Url to avoid
/// repeated parse/serialize overhead in hot loops; caller already holds original Url.)
pub fn build_injected_url(base: &url::Url, param: &Param, injected: &str) -> String {
    match param.location {
        Location::Query => {
            // Build the URL string directly without cloning Url or allocating Vec
            let base_str = base.as_str();
            // Find prefix before query (scheme + authority + path)
            let prefix = if let Some(q_pos) = base_str.find('?') {
                &base_str[..q_pos]
            } else {
                base_str
            };
            // Preserve fragment
            let fragment = base.fragment();

            let mut result = String::with_capacity(base_str.len() + injected.len() + 16);
            result.push_str(prefix);
            result.push('?');

            // Special handling for parameter key injection: payload becomes the key
            if param.name == "__dalfox_key_inject__" {
                let mut first = true;
                for (k, v) in base.query_pairs() {
                    if !first {
                        result.push('&');
                    }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(&v, &mut result);
                }
                if !first {
                    result.push('&');
                }
                encode_query_component_preserving_pct_into(injected, &mut result);
                result.push_str("=1");
            } else {
                let mut found = false;
                let mut first = true;
                for (k, v) in base.query_pairs() {
                    if !first {
                        result.push('&');
                    }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    if k == param.effective_wire_name() && !found {
                        encode_query_component_preserving_pct_into(injected, &mut result);
                        found = true;
                    } else {
                        encode_query_component_preserving_pct_into(&v, &mut result);
                    }
                }
                if !found {
                    if !first {
                        result.push('&');
                    }
                    encode_query_component_preserving_pct_into(
                        param.effective_wire_name(),
                        &mut result,
                    );
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                }
            }
            if let Some(frag) = fragment {
                result.push('#');
                result.push_str(frag);
            }
            result
        }
        Location::Path => {
            let mut url = base.clone();
            if let Some(idx_str) = param.name.strip_prefix("path_segment_")
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                let original_path = url.path().to_string();
                if original_path != "/" {
                    let encoded = selective_path_segment_encode(injected);
                    let mut new_path = String::with_capacity(original_path.len() + encoded.len());
                    let segments = original_path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty());
                    let mut count = 0;
                    for (i, segment) in segments.enumerate() {
                        new_path.push('/');
                        if i == idx {
                            new_path.push_str(&encoded);
                        } else {
                            new_path.push_str(segment);
                        }
                        count = i + 1;
                    }
                    if idx < count {
                        url.set_path(&new_path);
                    }
                }
            }
            url.to_string()
        }
        Location::Body | Location::JsonBody | Location::MultipartBody => {
            // For body params, the URL itself does not change.
            // Return the base URL as-is; actual payload injection happens in the
            // request body (handled by the caller when building the request).
            base.to_string()
        }
        Location::Header => {
            // Header injection does not alter the URL.
            base.to_string()
        }
        Location::Fragment => {
            // Fragment injection: replace the target param value inside the URL fragment.
            // Supports SPA-style routing fragments like `#/redir?url=value` and simple
            // `#key=value` fragments.
            let base_str = base.as_str();
            let frag = base.fragment().unwrap_or("");

            // Split fragment into route prefix and query part
            let (route_prefix, query_part) = if let Some(q_pos) = frag.find('?') {
                (&frag[..q_pos], &frag[q_pos + 1..])
            } else {
                // No '?' — treat the whole fragment as key=value pairs
                ("", frag)
            };

            // Parse key=value pairs from the query part
            let pairs: Vec<(&str, &str)> = query_part
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|pair| {
                    if let Some((k, v)) = pair.split_once('=') {
                        (k, v)
                    } else {
                        (pair, "")
                    }
                })
                .collect();

            // Rebuild the fragment with injected value
            let mut new_frag = String::with_capacity(frag.len() + injected.len() + 16);
            new_frag.push_str(route_prefix);
            if !route_prefix.is_empty() {
                new_frag.push('?');
            }

            let mut found = false;
            let mut first = true;
            for (k, v) in &pairs {
                if !first {
                    new_frag.push('&');
                }
                first = false;
                new_frag.push_str(k);
                new_frag.push('=');
                if *k == param.name && !found {
                    new_frag.push_str(injected);
                    found = true;
                } else {
                    new_frag.push_str(v);
                }
            }
            if !found {
                if !first {
                    new_frag.push('&');
                }
                new_frag.push_str(&param.name);
                new_frag.push('=');
                new_frag.push_str(injected);
            }

            // Build result: everything before '#' + new fragment
            let prefix = if let Some(hash_pos) = base_str.find('#') {
                &base_str[..hash_pos]
            } else {
                base_str
            };
            let mut result = String::with_capacity(prefix.len() + 1 + new_frag.len());
            result.push_str(prefix);
            result.push('#');
            result.push_str(&new_frag);
            result
        }
    }
}

/// HPP (HTTP Parameter Pollution) strategy variants.
/// Different server stacks handle duplicate query parameters differently,
/// so we generate multiple HPP variants to increase bypass probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HppPosition {
    /// Payload appears as the last duplicate: `?p=safe&p=<payload>`
    /// Effective against: PHP/Apache (uses last), Ruby/Rack (uses last)
    Last,
    /// Payload appears as the first duplicate: `?p=<payload>&p=safe`
    /// Effective against: JSP/Tomcat (uses first), Python/Flask (uses first)
    First,
    /// Payload only, no safe decoy: `?p=<payload>&p=<payload>`
    /// Useful when server concatenates (ASP.NET/IIS joins with comma)
    Both,
}

/// Build an HPP URL variant for a query parameter.
/// Returns the URL with the parameter duplicated according to the given `position`.
/// For non-Query locations, returns `None` (HPP only applies to query params).
pub fn build_hpp_url(
    base: &url::Url,
    param: &Param,
    injected: &str,
    position: HppPosition,
) -> Option<String> {
    if param.location != Location::Query {
        return None;
    }

    let base_str = base.as_str();
    let prefix = if let Some(q_pos) = base_str.find('?') {
        &base_str[..q_pos]
    } else {
        base_str
    };
    let fragment = base.fragment();

    let safe_value = &param.value;

    let mut result = String::with_capacity(base_str.len() + injected.len() + param.name.len() + 32);
    result.push_str(prefix);
    result.push('?');

    let mut first = true;
    let mut replaced = false;

    // Rebuild existing query pairs, replacing the target param's value
    for (k, v) in base.query_pairs() {
        if k == param.name && !replaced {
            replaced = true;
            match position {
                HppPosition::Last => {
                    // safe value first, payload second
                    if !first {
                        result.push('&');
                    }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(safe_value, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                }
                HppPosition::First => {
                    // payload first, safe value second
                    if !first {
                        result.push('&');
                    }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(safe_value, &mut result);
                }
                HppPosition::Both => {
                    // payload in both positions
                    if !first {
                        result.push('&');
                    }
                    first = false;
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                    result.push('&');
                    encode_query_component_preserving_pct_into(&k, &mut result);
                    result.push('=');
                    encode_query_component_preserving_pct_into(injected, &mut result);
                }
            }
        } else {
            if !first {
                result.push('&');
            }
            first = false;
            encode_query_component_preserving_pct_into(&k, &mut result);
            result.push('=');
            encode_query_component_preserving_pct_into(&v, &mut result);
        }
    }

    // If param wasn't in the original query, append the HPP pair
    if !replaced {
        match position {
            HppPosition::Last => {
                if !first {
                    result.push('&');
                }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(safe_value, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
            }
            HppPosition::First => {
                if !first {
                    result.push('&');
                }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(safe_value, &mut result);
            }
            HppPosition::Both => {
                if !first {
                    result.push('&');
                }
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
                result.push('&');
                encode_query_component_preserving_pct_into(&param.name, &mut result);
                result.push('=');
                encode_query_component_preserving_pct_into(injected, &mut result);
            }
        }
    }

    if let Some(frag) = fragment {
        result.push('#');
        result.push_str(frag);
    }

    Some(result)
}

/// Generate all HPP URL variants for a given payload.
/// Returns up to 3 variants (Last, First, Both) for query params, empty vec for others.
pub fn build_hpp_urls(
    base: &url::Url,
    param: &Param,
    injected: &str,
) -> Vec<(String, HppPosition)> {
    [HppPosition::Last, HppPosition::First, HppPosition::Both]
        .iter()
        .filter_map(|&pos| build_hpp_url(base, param, injected, pos).map(|url| (url, pos)))
        .collect()
}

/// Build an `application/x-www-form-urlencoded` body that carries `value` for
/// `name`, replacing the existing value when the param is already present and
/// appending it otherwise.
///
/// This is the single source of truth for form-body injection. It was
/// previously copy-pasted (byte-identical) across the reflection check, light
/// verify, DOM verify, and PoC builders; keeping one implementation prevents
/// the drift those parallel copies were prone to.
/// True when `param` is one of the target's cookies rather than a plain
/// request header.
///
/// Cookies have no `Location` of their own — per-cookie discovery
/// (`parameter_analysis::discovery`) files them as [`Location::Header`] with the
/// *cookie's* name — so every injection site has to re-derive this. Matching
/// `param_type_label`, which reports exactly these params as `"cookie"` to the
/// user.
pub fn param_is_cookie(target: &Target, param: &Param) -> bool {
    matches!(param.location, Location::Header)
        && target.cookies.iter().any(|(name, _)| name == &param.name)
}

/// Build a request injecting `value` into a [`Location::Header`] parameter,
/// routing cookie params into the `Cookie` header instead of a header of the
/// same name.
///
/// This distinction is load-bearing and was previously implemented in only one
/// of the three injection paths. Per-cookie discovery yields a param named
/// after the cookie (`session`, `theme`, …); injecting that as
/// `session: <payload>` sets an HTTP header the application never reads, so
/// the payload never reaches the sink, no reflection is observed, and the whole
/// parameter is dropped. Measured: a page reflecting the *first* of three
/// cookies was found when it was the only cookie and missed entirely when two
/// others followed it.
///
/// The injected cookie is written first and the target's other cookies are
/// preserved after it, so neighbouring cookies keep whatever session state the
/// application needs to render the sink at all.
pub fn build_header_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    let parsed_url = target.url.clone();
    if param_is_cookie(target, param) {
        let others =
            crate::utils::compose_cookie_header_excluding(&target.cookies, Some(&param.name));
        let cookie_header = match others {
            Some(rest) if !rest.is_empty() => format!("{}={}; {}", param.name, value, rest),
            _ => format!("{}={}", param.name, value),
        };
        crate::utils::build_request_with_cookie(
            client,
            target,
            method,
            parsed_url,
            target.data.clone(),
            Some(cookie_header),
        )
    } else {
        let base =
            crate::utils::build_request(client, target, method, parsed_url, target.data.clone());
        crate::utils::apply_header_overrides(base, &[(param.name.clone(), value.to_string())])
    }
}

pub fn urlencoded_body(data: Option<&str>, name: &str, value: &str) -> String {
    match data {
        Some(data) => {
            let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == name {
                    pair.1 = value.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((name.to_string(), value.to_string()));
            }
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish()
        }
        None => format!(
            "{}={}",
            urlencoding::encode(name),
            urlencoding::encode(value)
        ),
    }
}

/// Build a JSON body that carries `value` for `name`.
///
/// - Valid JSON object body → insert/overwrite the `name` key.
/// - Non-JSON body with an empty `param_value` → re-serialize as `{name: value}`
///   (an empty `str::replace` pattern would splice the payload between every
///   byte of the body).
/// - Non-JSON body with a non-empty `param_value` → textual replace of the
///   original value, preserving the surrounding (non-JSON) structure.
/// - No captured body → `{name: value}`.
///
/// Single source of truth for the reflection / light-verify / DOM-verify / PoC
/// JSON builders, which were byte-identical copies.
pub fn json_body(data: Option<&str>, name: &str, param_value: &str, value: &str) -> String {
    match data {
        Some(data) => {
            if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(obj) = json_val.as_object_mut() {
                    obj.insert(
                        name.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                }
                serde_json::to_string(&json_val).unwrap_or_else(|_| data.to_string())
            } else if param_value.is_empty() {
                serde_json::json!({ name: value }).to_string()
            } else {
                data.replace(param_value, value)
            }
        }
        None => serde_json::json!({ name: value }).to_string(),
    }
}

/// Build a `multipart/form-data` form that carries `value` for `name`,
/// replacing the matching field from the captured `data` and appending it when
/// absent so an explicit `--param` not present in an imported body still ships
/// its payload.
///
/// Single source of truth for the reflection / light-verify / DOM-verify /
/// probe multipart builders.
pub fn multipart_form(data: Option<&str>, name: &str, value: &str) -> reqwest::multipart::Form {
    let mut form = reqwest::multipart::Form::new();
    let mut found = false;
    if let Some(data) = data {
        for pair in data.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let k = urlencoding::decode(k)
                    .unwrap_or(Cow::Borrowed(k))
                    .to_string();
                let v = urlencoding::decode(v)
                    .unwrap_or(Cow::Borrowed(v))
                    .to_string();
                if k == name {
                    form = form.text(k, value.to_string());
                    found = true;
                } else {
                    form = form.text(k, v);
                }
            }
        }
    }
    if !found {
        form = form.text(name.to_string(), value.to_string());
    }
    form
}

/// Resolve the URL a body-bearing injection must be sent to: the discovered
/// `<form action=...>` endpoint when the param came from a form, else the
/// target's own URL. A form-discovered body param reflects at the action
/// endpoint, not at the page that contained the form.
pub fn resolve_form_action_url(param: &Param, target: &Target) -> url::Url {
    param
        .form_action_url
        .as_ref()
        .and_then(|u| url::Url::parse(u).ok())
        .unwrap_or_else(|| target.url.clone())
}

/// `application/x-www-form-urlencoded` body injection.
pub fn build_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let body = Some(urlencoded_body(target.data.as_deref(), &param.name, value));
    let method = body_location_method_for_param(&target.method, param);
    let base = crate::utils::build_request(client, target, method, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
    )
}

/// `application/json` body injection.
pub fn build_json_body_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let body = Some(json_body(
        target.data.as_deref(),
        &param.name,
        &param.value,
        value,
    ));
    let method = body_location_method_for_param(&target.method, param);
    let base = crate::utils::build_request(client, target, method, parsed_url, body);
    crate::utils::apply_header_overrides(
        base,
        &[("Content-Type".to_string(), "application/json".to_string())],
    )
}

/// `multipart/form-data` body injection. No explicit `Content-Type` override:
/// reqwest derives it from the form, and it must carry the generated boundary.
pub fn build_multipart_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
) -> reqwest::RequestBuilder {
    let parsed_url = resolve_form_action_url(param, target);
    let form = multipart_form(target.data.as_deref(), &param.name, value);
    let method = body_location_method_for_param(&target.method, param);
    crate::utils::build_request(client, target, method, parsed_url, None).multipart(form)
}

/// Query / Path injection: the payload goes into the URL and the target's own
/// body (if any) rides along unchanged.
pub fn build_url_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
    method: reqwest::Method,
) -> reqwest::RequestBuilder {
    // Query params discovered through a `<form action=...>` must be injected at
    // the action URL — that's where the sink lives. Path params keep
    // `target.url` because path-segment injection depends on the original path
    // layout.
    let base_url = effective_query_base(&target.url, param);
    let inject_url_str = build_injected_url(&base_url, param, value);
    let inject_url = url::Url::parse(&inject_url_str).unwrap_or_else(|_| base_url.clone());
    crate::utils::build_request(client, target, method, inject_url, target.data.clone())
}

/// Build the injection request for `value` at `param`'s location.
///
/// Single source of truth for the reflection / light-verify / DOM-verify
/// request builders, which were three near-identical copies of this `match`.
/// They had already drifted: the light-verify copy sent an urlencoded body
/// with **no `Content-Type`**, so form-parsing servers never bound the param
/// and the verification silently came back negative.
pub fn build_inject_request(
    client: &Client,
    target: &Target,
    param: &Param,
    value: &str,
) -> reqwest::RequestBuilder {
    let default_method = target.parse_method();
    match param.location {
        // A cookie param must go into the `Cookie` header, not a header named
        // after the cookie — see `build_header_request`.
        Location::Header => build_header_request(client, target, param, value, default_method),
        Location::Body => build_body_request(client, target, param, value),
        Location::JsonBody => build_json_body_request(client, target, param, value),
        Location::MultipartBody => build_multipart_request(client, target, param, value),
        _ => build_url_inject_request(client, target, param, value, default_method),
    }
}

#[cfg(test)]
mod tests;
