//! Postman Collection (v2.1, and the near-identical v2.0) input support
//! (`-i postman`, issue #1517).
//!
//! Every request in the collection — folders are walked recursively — becomes
//! one [`Target`] carrying its method, URL, headers, cookies and body (raw,
//! urlencoded, form-data as multipart, or GraphQL as JSON). `{{var}}`
//! placeholders resolve from the collection's `variable` list. A request whose
//! *host* still has an unresolved variable can't be aimed anywhere and is
//! skipped with a warning (pass `--base-url` to supply the origin); one left
//! in the path, query, headers or body becomes a placeholder value, since
//! those are exactly the slots the scan injects into anyway.

use super::{ImportedHeaders, MAX_IMPORT_REQUEST_BYTES, SpecImport, Target};
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

/// Most bytes one `{{var}}` expansion may grow a string to; keeps a variable
/// referencing itself many times from amplifying a small collection.
const MAX_EXPANDED_BYTES: usize = 1 << 20;
/// Nested-variable passes (`{{a}}` → `{{b}}` → value); also ends cycles.
const MAX_VAR_PASSES: usize = 4;
/// What an unresolved non-host variable becomes.
const PLACEHOLDER: &str = "1";

/// Parse a Postman collection export. `base_url` (`--base-url`) replaces the
/// origin of every request (its path prefix is kept in front of the request
/// path), which also rescues requests whose host is an environment variable
/// the collection itself doesn't define. Returns `Err` only when the document
/// is not a collection or yields no request.
pub fn parse_postman(
    content: &str,
    base_url: Option<&Url>,
) -> Result<SpecImport, Box<dyn std::error::Error>> {
    let content = content.trim_start_matches('\u{feff}');
    let doc: Value =
        serde_json::from_str(content).map_err(|e| format!("invalid Postman JSON: {e}"))?;
    let items = doc
        .get("item")
        .and_then(Value::as_array)
        .ok_or("not a Postman collection (no top-level `item` array)")?;

    let mut vars: HashMap<String, String> = HashMap::new();
    for v in doc
        .get("variable")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if v.get("disabled").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(k) = v.get("key").and_then(Value::as_str) {
            vars.insert(k.to_string(), v.get("value").map(text).unwrap_or_default());
        }
    }

    let mut out = SpecImport::default();
    let mut budget = crate::utils::fs::MAX_FILE_READ_BYTES as usize;
    // Explicit stack (reversed pushes keep document order): folder nesting is
    // bounded by serde_json's recursion limit, but no recursion is needed.
    let mut stack: Vec<(&Value, String)> = items.iter().rev().map(|i| (i, String::new())).collect();
    while let Some((item, parent)) = stack.pop() {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)");
        let label = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        if let Some(children) = item.get("item").and_then(Value::as_array) {
            stack.extend(children.iter().rev().map(|c| (c, label.clone())));
            continue;
        }
        let Some(req) = item.get("request") else {
            continue;
        };
        if out.targets.len() >= super::MAX_IMPORT_TARGETS || budget == 0 {
            out.skipped.push(format!(
                "{label}: stopped — collection expands past the import size cap"
            ));
            break;
        }
        match build_request(req, &vars, base_url) {
            Ok(t) => {
                let size = t.url.as_str().len()
                    + t.data.as_ref().map_or(0, String::len)
                    + t.headers
                        .iter()
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>();
                budget = budget.saturating_sub(size);
                out.targets.push(t);
            }
            Err(e) => out.skipped.push(format!("{label}: {e}")),
        }
    }

    if out.targets.is_empty() {
        let why = out
            .skipped
            .first()
            .map(|s| format!(" (e.g. {s})"))
            .unwrap_or_default();
        return Err(format!(
            "collection yielded no scannable request ({} skipped){why}",
            out.skipped.len()
        )
        .into());
    }
    Ok(out)
}

fn too_large() -> String {
    format!(
        "request expands past {} MiB",
        MAX_IMPORT_REQUEST_BYTES >> 20
    )
}

/// A Postman scalar as text (values may be strings, numbers or booleans).
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Expand `{{name}}` from `vars`. An unknown name is kept verbatim (`fill`
/// false) or replaced by [`PLACEHOLDER`] (`fill` true). Postman's dynamic
/// variables (`{{$guid}}`, …) are unknown names too.
fn substitute(s: &str, vars: &HashMap<String, String>, fill: bool) -> Result<String, String> {
    let mut cur = s.to_string();
    for _ in 0..MAX_VAR_PASSES {
        if !cur.contains("{{") {
            break;
        }
        let mut out = String::with_capacity(cur.len());
        let mut rest = cur.as_str();
        let mut changed = false;
        while let Some(open) = rest.find("{{") {
            let Some(close) = rest[open + 2..].find("}}") else {
                break;
            };
            let name = rest[open + 2..open + 2 + close].trim();
            out.push_str(&rest[..open]);
            match vars.get(name) {
                Some(v) => {
                    out.push_str(v);
                    changed = true;
                }
                None if fill => out.push_str(PLACEHOLDER),
                None => out.push_str(&rest[open..open + close + 4]),
            }
            if out.len() > MAX_EXPANDED_BYTES {
                return Err("variable expansion exceeds 1 MiB".to_string());
            }
            rest = &rest[open + close + 4..];
        }
        out.push_str(rest);
        cur = out;
        if !changed {
            break;
        }
    }
    Ok(cur)
}

/// Enabled `{key, value}` entries of a Postman list (headers, urlencoded,
/// formdata, url.variable), with variables expanded.
fn pairs(
    list: Option<&Value>,
    vars: &HashMap<String, String>,
) -> Result<Vec<(String, String, Option<String>)>, String> {
    let mut out = Vec::new();
    let mut size = 0usize;
    for e in list.and_then(Value::as_array).into_iter().flatten() {
        if e.get("disabled").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(k) = e.get("key").and_then(Value::as_str) else {
            continue;
        };
        let v = e.get("value").map(text).unwrap_or_default();
        let ty = e.get("type").and_then(Value::as_str).map(str::to_string);
        let (k, v) = (substitute(k, vars, true)?, substitute(&v, vars, true)?);
        size += k.len() + v.len();
        if size > MAX_IMPORT_REQUEST_BYTES {
            return Err(too_large());
        }
        out.push((k, v, ty));
    }
    Ok(out)
}

fn build_request(
    req: &Value,
    vars: &HashMap<String, String>,
    base_url: Option<&Url>,
) -> Result<Target, String> {
    // `request` may be a bare URL string.
    let url_field = if req.is_string() {
        Some(req)
    } else {
        req.get("url")
    };
    let raw = match url_field {
        Some(Value::String(s)) => s.as_str(),
        Some(u) => u
            .get("raw")
            .and_then(Value::as_str)
            .ok_or("url has no `raw` form")?,
        None => return Err("request has no url".to_string()),
    };
    let raw = substitute(raw.trim(), vars, false)?;

    // Split origin from the rest before filling placeholders: a variable
    // still unresolved in the origin is a host nobody named.
    let (scheme, after) = match raw.find("://") {
        Some(i) => (&raw[..i], &raw[i + 3..]),
        None => ("http", raw.as_str()),
    };
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    // Path variables (`/users/:id`) from `url.variable`.
    let path_vars: HashMap<String, String> =
        pairs(url_field.and_then(|u| u.get("variable")), vars)?
            .into_iter()
            .map(|(k, v, _)| (k, v))
            .collect();
    let rest = fill_path_vars(&substitute(rest, vars, true)?, &path_vars);

    let url = match base_url {
        Some(base) => super::openapi::join_path(base, &rest)?,
        None => {
            if scheme.contains("{{") || authority.contains("{{") {
                return Err(format!(
                    "unresolved variable in host '{scheme}://{authority}' (define it in the collection or pass --base-url)"
                ));
            }
            let s = format!("{scheme}://{authority}{rest}");
            let url = Url::parse(&s).map_err(|e| format!("invalid URL '{s}': {e}"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(format!("'{url}' is not an http/https URL"));
            }
            url
        }
    };

    let method = req
        .get("method")
        .and_then(Value::as_str)
        .map(|m| m.trim().to_ascii_uppercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "GET".to_string());
    if reqwest::Method::from_bytes(method.as_bytes()).is_err() {
        return Err(format!("invalid HTTP method '{method}'"));
    }

    let mut imported = ImportedHeaders::default();
    match req.get("header") {
        // v2.0 also allows the headers as one raw `K: v` block.
        Some(Value::String(block)) => {
            let mut size = 0usize;
            for line in block.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    let (k, v) = (
                        substitute(k, vars, true)?,
                        substitute(v.trim(), vars, true)?,
                    );
                    size += k.len() + v.len();
                    if size > MAX_IMPORT_REQUEST_BYTES {
                        return Err(too_large());
                    }
                    imported.push(&k, &v);
                }
            }
        }
        list => {
            for (k, v, _) in pairs(list, vars)? {
                imported.push(&k, &v);
            }
        }
    }

    let mut target = Target {
        method,
        ..Target::for_url(url)
    };
    let mut content_type: Option<&str> = None;
    if let Some(body) = req
        .get("body")
        .filter(|b| b.get("disabled").and_then(Value::as_bool) != Some(true))
    {
        match body.get("mode").and_then(Value::as_str) {
            Some("raw") => {
                let raw = body.get("raw").and_then(Value::as_str).unwrap_or("");
                if !raw.is_empty() {
                    target.data = Some(substitute(raw, vars, true)?);
                    content_type = match body
                        .pointer("/options/raw/language")
                        .and_then(Value::as_str)
                    {
                        Some("json") => Some("application/json"),
                        Some("xml") => Some("application/xml"),
                        _ => None,
                    };
                }
            }
            Some("urlencoded") => {
                let fields = pairs(body.get("urlencoded"), vars)?;
                target.data = Some(form_body(fields.iter().map(|(k, v, _)| (k, v.as_str()))));
                content_type = Some("application/x-www-form-urlencoded");
            }
            Some("formdata") => {
                // File parts carry a local path (`src`), never read: the
                // field is still an injection point, so it gets a value.
                let fields = pairs(body.get("formdata"), vars)?;
                target.data = Some(form_body(fields.iter().map(|(k, v, ty)| {
                    (
                        k,
                        if ty.as_deref() == Some("file") {
                            "test"
                        } else {
                            v.as_str()
                        },
                    )
                })));
                target.multipart = true;
            }
            Some("graphql") => {
                let gql = body.get("graphql");
                let query = gql
                    .and_then(|g| g.get("query"))
                    .map(text)
                    .unwrap_or_default();
                let variables = gql
                    .and_then(|g| g.get("variables"))
                    .map(text)
                    .and_then(|v| {
                        serde_json::from_str::<Value>(&substitute(&v, vars, true).ok()?).ok()
                    })
                    .unwrap_or_else(|| Value::Object(Default::default()));
                target.data = Some(
                    serde_json::json!({ "query": substitute(&query, vars, true)?, "variables": variables })
                        .to_string(),
                );
                content_type = Some("application/json");
            }
            _ => {} // `file`, `none`, unknown: no body dalfox can rebuild
        }
    }

    if target.multipart {
        // The multipart builders set their own boundary; a collection's
        // `multipart/form-data; boundary=…` would mis-frame every other
        // request, which re-sends `data` urlencoded.
        imported
            .headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
    } else if let Some(ct) = content_type
        && !crate::utils::http::has_header(&imported.headers, "Content-Type")
    {
        imported.push("Content-Type", ct);
    }
    target.headers = imported.headers;
    target.cookies = imported.cookies;
    target.user_agent = imported.user_agent;
    Ok(target)
}

fn form_body<'a>(fields: impl Iterator<Item = (&'a String, &'a str)>) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish()
}

/// Replace `:name` path segments with their `url.variable` value
/// (percent-encoded; an unknown one gets [`PLACEHOLDER`]).
fn fill_path_vars(rest: &str, path_vars: &HashMap<String, String>) -> String {
    let split = rest.find(['?', '#']).unwrap_or(rest.len());
    let (path, tail) = rest.split_at(split);
    let filled: Vec<String> = path
        .split('/')
        .map(|seg| match seg.strip_prefix(':') {
            Some(name) if !name.is_empty() => {
                let v = path_vars.get(name).filter(|v| !v.is_empty());
                urlencoding::encode(v.map_or(PLACEHOLDER, String::as_str)).into_owned()
            }
            _ => seg.to_string(),
        })
        .collect();
    format!("{}{tail}", filled.join("/"))
}

#[cfg(test)]
mod tests;
