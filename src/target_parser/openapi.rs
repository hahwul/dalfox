//! OpenAPI 3.x / Swagger 2.0 input support (`-i openapi`, issue #1517).
//!
//! An API spec already enumerates every endpoint, method, parameter and body
//! schema. [`parse_openapi`] expands each operation into one [`Target`]:
//! server URL + path (path parameters filled from `example` / `default` /
//! a typed placeholder), query / header / cookie parameters, and a JSON, form,
//! multipart or XML body built from the request schema. The targets then flow
//! through the regular `resolve_targets` pipeline (CLI overrides, dedup,
//! `--include-url` / `--out-of-scope` filters), exactly like HAR entries, and
//! the existing discovery/mining stages find the injection points.
//!
//! Hostile-spec rules:
//! - `$ref` is resolved only inside the document (`#/…`). A remote ref is
//!   never fetched (SSRF, and the scan must not depend on a third host); it
//!   degrades to a placeholder.
//! - Schema expansion is bounded by depth, a per-body node budget, and a
//!   ref stack that cuts cycles; output bytes across the whole document are
//!   capped at the input byte budget, so a small spec can't amplify.
//! - Paths are appended to the server URL textually and the result must stay
//!   on the server's origin; path-parameter values are percent-encoded.
//! - One bad operation is skipped with a reason, never fatal.

use super::{ImportedHeaders, MAX_IMPORT_REQUEST_BYTES, SpecImport, Target};
use serde_json::{Map, Value};
use url::Url;

/// Operation keys of a Path Item that become requests. `trace` is left out
/// (dalfox doesn't send it); `query` is the OAS 3.2 / RFC 10008 method.
const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "query",
];
/// Deepest schema nesting (each `$ref` hop counts) that is expanded.
const MAX_SCHEMA_DEPTH: usize = 12;
/// Schema nodes one sample value may visit; bounds wide-and-deep schemas.
const MAX_SCHEMA_NODES: usize = 1000;
/// Properties sampled per object schema.
const MAX_OBJECT_PROPS: usize = 64;
/// `$ref` hops followed when resolving a parameter / body / path item.
const MAX_REF_HOPS: usize = 16;
/// Parameters one operation may declare (path item + operation).
const MAX_OP_PARAMS: usize = 1024;

fn too_large() -> String {
    super::too_large("operation")
}

/// The spec version field as text. YAML reads an unquoted `swagger: 2.0` or
/// `openapi: 3.0` as a number.
fn version(doc: &Value, key: &str) -> Option<String> {
    match doc.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_f64().map(|f| format!("{f:.1}")),
        _ => None,
    }
}

/// Parse an OpenAPI 3.x (JSON or YAML) or Swagger 2.0 document.
///
/// `base_url` (`--base-url`) replaces the spec's absolute server URL; a
/// relative server URL (`/api/v3`, or no `servers` at all) is resolved against
/// it, and is an error without it. Returns `Err` only when the document is not
/// a parseable spec or yields no target at all.
pub fn parse_openapi(
    content: &str,
    base_url: Option<&Url>,
) -> Result<SpecImport, Box<dyn std::error::Error>> {
    let doc = parse_document(content)?;
    let swagger2 = match (version(&doc, "openapi"), version(&doc, "swagger")) {
        (Some(v), _) if v.starts_with("3.") => false,
        (_, Some(v)) if v == "2.0" => true,
        _ => {
            return Err(
                "not an OpenAPI 3.x / Swagger 2.0 document (no `openapi: 3.x` or `swagger: \"2.0\"`)"
                    .into(),
            );
        }
    };
    let paths = doc
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("spec has no `paths` object")?;

    let mut out = SpecImport::default();
    let mut budget = crate::utils::fs::MAX_FILE_READ_BYTES as usize;
    // `x-…` keys are specification extensions, not paths.
    'paths: for (path, item) in paths.iter().filter(|(p, _)| !p.starts_with("x-")) {
        let Some(item) = resolve(&doc, item) else {
            out.skipped
                .push(format!("{path}: unresolvable path item $ref"));
            continue;
        };
        for method in METHODS {
            let Some(op) = item.get(*method).filter(|o| o.is_object()) else {
                continue;
            };
            if super::is_unscanned_spec_method(method) {
                out.unscanned_methods += 1;
                continue;
            }
            let label = format!("{} {}", method.to_ascii_uppercase(), path);
            if out.targets.len() >= super::MAX_IMPORT_TARGETS || budget == 0 {
                out.skipped.push(format!(
                    "{label}: stopped — spec expands past the import size cap"
                ));
                break 'paths;
            }
            let op_ctx = Op {
                doc: &doc,
                swagger2,
                path,
                method,
                item,
                op,
            };
            match op_ctx.build(base_url) {
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
    }

    if out.targets.is_empty() {
        let why = out
            .skipped
            .first()
            .map(|s| format!(" (e.g. {s})"))
            .unwrap_or_default();
        return Err(format!(
            "spec yielded no scannable operation ({} skipped, {} DELETE/HEAD/OPTIONS not scanned){why}",
            out.skipped.len(),
            out.unscanned_methods
        )
        .into());
    }
    Ok(out)
}

/// JSON when the document opens with `{`, YAML otherwise. YAML parsing runs
/// under serde-saphyr's budget (alias/anchor expansion, nesting depth), with
/// the node/event/scalar caps raised so a large real spec still fits under the
/// input byte cap.
pub(super) fn parse_document(content: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let content = content.trim_start_matches('\u{feff}');
    if content.trim_start().starts_with('{') {
        return Ok(serde_json::from_str(content).map_err(|e| format!("invalid spec JSON: {e}"))?);
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_events = 50_000_000;
    budget.max_nodes = 8_000_000;
    budget.max_total_scalar_bytes = crate::utils::fs::MAX_FILE_READ_BYTES as usize;
    // Specs legitimately reuse one anchor (`*defaultError`) hundreds of times,
    // which the alias-to-anchor ratio heuristic rejects. Billion laughs is
    // still stopped by the absolute caps: alias count, retained anchor
    // events/bytes, and total nodes.
    budget.enforce_alias_anchor_ratio = false;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    serde_saphyr::from_str_with_options(content, options)
        .map_err(|e| format!("invalid spec YAML: {e}").into())
}

/// Follow a local `$ref` (`#/a/b`, JSON-pointer escaped, possibly
/// percent-encoded) to its target. Remote refs (`other.yaml#/x`,
/// `https://…`) return `None`: they are never fetched.
fn pointer<'a>(doc: &'a Value, r: &str) -> Option<&'a Value> {
    let frag = r.strip_prefix('#')?;
    let frag = urlencoding::decode(frag).ok()?;
    doc.pointer(&frag)
}

/// `v` with any chain of `$ref`s followed (bounded, so a ref cycle ends).
fn resolve<'a>(doc: &'a Value, mut v: &'a Value) -> Option<&'a Value> {
    for _ in 0..MAX_REF_HOPS {
        match v.get("$ref").and_then(Value::as_str) {
            Some(r) => v = pointer(doc, r)?,
            None => return Some(v),
        }
    }
    None
}

/// A scalar rendered for the wire: strings verbatim, an array as its first
/// element (a query `?ids=1`, not `?ids=["1"]`), objects as JSON.
fn wire_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "test".to_string(),
        Value::Array(a) => a.first().map(wire_string).unwrap_or_default(),
        other => other.to_string(),
    }
}

/// Example-or-schema sampler for one value. `nodes` and `stack` make every
/// expansion finite: a node budget for width, the ref stack for cycles, and
/// the depth limit for everything else.
struct Sampler<'a> {
    doc: &'a Value,
    nodes: usize,
    /// Bytes of spec-given examples copied so far.
    bytes: usize,
    stack: Vec<&'a str>,
}

impl<'a> Sampler<'a> {
    fn new(doc: &'a Value) -> Self {
        Sampler {
            doc,
            nodes: 0,
            bytes: 0,
            stack: Vec::new(),
        }
    }

    fn sample(&mut self, schema: &'a Value, depth: usize) -> Value {
        self.nodes += 1;
        if depth > MAX_SCHEMA_DEPTH || self.nodes > MAX_SCHEMA_NODES || !schema.is_object() {
            return Value::Null;
        }
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            if self.stack.contains(&r) {
                return Value::Null; // cycle: stop here
            }
            let Some(target) = pointer(self.doc, r) else {
                return Value::String("test".to_string()); // remote / dangling
            };
            self.stack.push(r);
            let v = self.sample(target, depth + 1);
            self.stack.pop();
            return v;
        }
        // `example` / `default` / `const`, then the JSON Schema (OAS 3.1)
        // `examples` array and the first enum value.
        let given = ["example", "default", "const"]
            .iter()
            .find_map(|k| schema.get(*k))
            .or_else(|| {
                ["examples", "enum"]
                    .iter()
                    .find_map(|k| schema.get(*k)?.as_array()?.first())
            });
        if let Some(v) = given {
            // One large example `$ref`'d from many properties must not
            // multiply: past half the request cap (so the body still fits
            // under it), further copies become null.
            if self.bytes > MAX_IMPORT_REQUEST_BYTES / 2 {
                return Value::Null;
            }
            self.bytes += match v {
                Value::String(s) => s.len(),
                other => other.to_string().len(),
            };
            return v.clone();
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            let mut merged = Map::new();
            for sub in all {
                match self.sample(sub, depth + 1) {
                    Value::Object(m) => merged.extend(m),
                    other if all.len() == 1 => return other,
                    _ => {}
                }
            }
            return Value::Object(merged);
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(first) = schema
                .get(key)
                .and_then(Value::as_array)
                .and_then(|a| a.first())
            {
                return self.sample(first, depth + 1);
            }
        }
        // `type` may be a list in OAS 3.1 (`["string", "null"]`).
        let ty = match schema.get("type") {
            Some(Value::String(t)) => t.as_str(),
            Some(Value::Array(ts)) => ts
                .iter()
                .filter_map(Value::as_str)
                .find(|t| *t != "null")
                .unwrap_or("null"),
            _ if schema.get("properties").is_some() => "object",
            _ if schema.get("items").is_some() => "array",
            _ => "string",
        };
        match ty {
            "object" => {
                let mut map = Map::new();
                if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                    for (k, sub) in props.iter().take(MAX_OBJECT_PROPS) {
                        // readOnly properties are response-only: not sent.
                        if sub.get("readOnly").and_then(Value::as_bool) == Some(true) {
                            continue;
                        }
                        map.insert(k.clone(), self.sample(sub, depth + 1));
                    }
                }
                Value::Object(map)
            }
            "array" => match schema.get("items") {
                Some(items) => Value::Array(vec![self.sample(items, depth + 1)]),
                None => Value::Array(vec![]),
            },
            "integer" | "number" => Value::from(1),
            "boolean" => Value::Bool(true),
            "null" => Value::Null,
            _ => Value::String(
                match schema.get("format").and_then(Value::as_str) {
                    Some("date") => "2024-01-01",
                    Some("date-time") => "2024-01-01T00:00:00Z",
                    Some("email") => "test@example.com",
                    Some("uuid") => "00000000-0000-4000-8000-000000000000",
                    Some("uri" | "url") => "https://example.com",
                    _ => "test",
                }
                .to_string(),
            ),
        }
    }
}

/// Body encodings dalfox can rebuild, in preference order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum BodyKind {
    Json,
    Form,
    Multipart,
    Xml,
}

fn body_kind(media_type: &str) -> Option<BodyKind> {
    let mt = media_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match mt.as_str() {
        "application/json" | "*/*" | "application/*" => Some(BodyKind::Json),
        "application/x-www-form-urlencoded" => Some(BodyKind::Form),
        "multipart/form-data" | "multipart/mixed" => Some(BodyKind::Multipart),
        "application/xml" | "text/xml" => Some(BodyKind::Xml),
        _ if mt.ends_with("+json") => Some(BodyKind::Json),
        _ if mt.ends_with("+xml") => Some(BodyKind::Xml),
        _ => None,
    }
}

/// One operation being expanded.
struct Op<'a> {
    doc: &'a Value,
    swagger2: bool,
    path: &'a str,
    method: &'a str,
    item: &'a Value,
    op: &'a Value,
}

impl<'a> Op<'a> {
    fn build(&self, base_override: Option<&Url>) -> Result<Target, String> {
        let base = self.base_url(base_override)?;

        // Path-item parameters, then operation parameters overriding by
        // (name, in) — the OAS merge rule.
        let mut params: Vec<&Value> = Vec::new();
        for list in [self.item.get("parameters"), self.op.get("parameters")] {
            for p in list.and_then(Value::as_array).into_iter().flatten() {
                let Some(p) = resolve(self.doc, p) else {
                    continue; // remote $ref: not fetched
                };
                let key = |v: &'a Value| (v.get("name"), v.get("in"));
                params.retain(|q| key(q) != key(p));
                params.push(p);
                // The override scan above is quadratic; no real operation
                // comes near this.
                if params.len() > MAX_OP_PARAMS {
                    return Err(format!("more than {MAX_OP_PARAMS} parameters"));
                }
            }
        }

        let mut path = String::with_capacity(self.path.len());
        let mut rest = self.path;
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            path.push_str(&rest[..open]);
            let name = &rest[open + 1..open + close];
            let value = params
                .iter()
                .find(|p| {
                    param_is(p, "path") && p.get("name").and_then(Value::as_str) == Some(name)
                })
                .map(|p| self.param_value(p))
                .unwrap_or_else(|| "1".to_string());
            path.push_str(&urlencoding::encode(&value));
            if path.len() > MAX_IMPORT_REQUEST_BYTES {
                return Err(too_large());
            }
            rest = &rest[open + close + 1..];
        }
        path.push_str(rest);
        let mut url = join_path(&base, &path)?;

        let mut imported = ImportedHeaders::default();
        let mut form_fields: Vec<(String, String)> = Vec::new();
        let mut has_file_field = false;
        let mut body_schema: Option<&Value> = None;
        let mut size = path.len();
        for p in &params {
            let Some(name) = p.get("name").and_then(Value::as_str) else {
                continue;
            };
            let location = p.get("in").and_then(Value::as_str);
            if location == Some("body") {
                // Swagger 2.0 bodies are parameters.
                body_schema = p.get("schema");
                continue;
            }
            let value = self.param_value(p);
            size += name.len() + value.len();
            if size > MAX_IMPORT_REQUEST_BYTES {
                return Err(too_large());
            }
            match location {
                Some("query") => {
                    url.query_pairs_mut().append_pair(name, &value);
                }
                // OAS: header params named Accept / Content-Type /
                // Authorization are ignored (the body and security schemes
                // own them).
                Some("header")
                    if !["accept", "content-type", "authorization"]
                        .contains(&name.to_ascii_lowercase().as_str()) =>
                {
                    imported.push(name, &value);
                }
                Some("cookie") => imported.push_cookie(name, &value),
                Some("formData") => {
                    has_file_field |= p.get("type").and_then(Value::as_str) == Some("file");
                    form_fields.push((name.to_string(), value));
                }
                _ => {}
            }
        }

        let mut target = Target {
            method: self.method.to_ascii_uppercase(),
            ..Target::for_url(url)
        };

        let body = if self.swagger2 {
            let consumes = self.swagger2_consumes();
            if !form_fields.is_empty() {
                let kind = if has_file_field
                    || consumes
                        .iter()
                        .any(|c| body_kind(c) == Some(BodyKind::Multipart))
                {
                    BodyKind::Multipart
                } else {
                    BodyKind::Form
                };
                Some((
                    kind,
                    None,
                    Value::Object(
                        form_fields
                            .into_iter()
                            .map(|(k, v)| (k, Value::String(v)))
                            .collect(),
                    ),
                    None,
                ))
            } else if let Some(schema) = body_schema {
                let kind = consumes
                    .iter()
                    .filter_map(|c| body_kind(c).map(|k| (k, *c)))
                    .min_by_key(|(k, _)| *k);
                let (kind, mt) = match kind {
                    Some((k, mt)) => (k, Some(mt)),
                    None => (BodyKind::Json, None),
                };
                let value = Sampler::new(self.doc).sample(schema, 0);
                Some((kind, mt, value, xml_root(self.doc, schema)))
            } else {
                None
            }
        } else {
            self.oas3_body()
        };

        // A form schema that isn't an object has no fields to send; the
        // operation is still scanned through its other parameters.
        let body = body.filter(|(kind, _, value, _)| {
            !matches!(kind, BodyKind::Form | BodyKind::Multipart) || value.is_object()
        });
        if let Some((kind, media_type, value, xml_name)) = body {
            let (data, default_ct) = match kind {
                BodyKind::Json => (
                    match &value {
                        // A string example that already is JSON goes out as-is.
                        Value::String(s) if serde_json::from_str::<Value>(s).is_ok() => s.clone(),
                        v => v.to_string(),
                    },
                    "application/json",
                ),
                BodyKind::Form | BodyKind::Multipart => {
                    let fields = value.as_object().into_iter().flatten();
                    let body = url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(fields.map(|(k, v)| (k, wire_string(v))))
                        .finish();
                    (body, "application/x-www-form-urlencoded")
                }
                BodyKind::Xml => (
                    match &value {
                        Value::String(s) if s.trim_start().starts_with('<') => s.clone(),
                        v => {
                            let mut out = String::new();
                            render_xml(xml_name.as_deref().unwrap_or("root"), v, &mut out, 0);
                            out
                        }
                    },
                    "application/xml",
                ),
            };
            if size + data.len() > MAX_IMPORT_REQUEST_BYTES {
                return Err(too_large());
            }
            if kind == BodyKind::Multipart {
                // The multipart builders set their own boundary-bearing
                // Content-Type; `data` stays urlencoded (see Target::multipart).
                target.multipart = true;
            } else {
                let ct = media_type
                    .filter(|mt| {
                        !mt.contains('*') && super::is_forwardable_header("Content-Type", mt)
                    })
                    .unwrap_or(default_ct);
                imported.push("Content-Type", ct);
            }
            target.data = Some(data);
        }

        target.headers = imported.headers;
        target.cookies = imported.cookies;
        target.user_agent = imported.user_agent;
        Ok(target)
    }

    /// The server URL in effect for this operation: operation `servers`, then
    /// path-item `servers`, then the root (OAS 3); `schemes`/`host`/`basePath`
    /// (Swagger 2.0).
    ///
    /// With `--base-url` one rule applies to every server shape: the base URL
    /// supplies scheme, host and port and is a path *prefix*; only the
    /// server's path (or `basePath`) is appended. A spec server can therefore
    /// never move the scan off the host the operator named — not even a
    /// scheme-relative `//prod.example.com/v1`.
    fn base_url(&self, base_override: Option<&Url>) -> Result<Url, String> {
        let declared = if self.swagger2 {
            swagger2_server(self.doc)
        } else {
            [self.op, self.item, self.doc]
                .iter()
                .filter_map(|v| v.get("servers").and_then(Value::as_array))
                .find(|s| !s.is_empty())
                .and_then(|s| s.first())
                .map(oas3_server_url)
                .transpose()?
        };
        let unresolved = |s: &str| {
            let open = s.find('{')?;
            let close = s[open..].find('}').map_or(s.len(), |c| open + c + 1);
            Some(format!(
                "server variable {} has no default (pass --base-url to say where the API lives)",
                &s[open..close]
            ))
        };
        let base = match (declared, base_override) {
            (Some(d), Some(o)) => {
                // The server's origin (and any variable in it) is discarded.
                let (_, path) = split_server(&d);
                if let Some(e) = unresolved(path) {
                    return Err(e);
                }
                join_path(o, path)?
            }
            (Some(d), None) => {
                if let Some(e) = unresolved(&d) {
                    return Err(e);
                }
                match split_server(&d) {
                    (Some(origin), _) if origin.contains("://") => {
                        Url::parse(&d).map_err(|e| format!("invalid server URL '{d}': {e}"))?
                    }
                    _ => {
                        return Err(format!(
                            "server URL '{d}' is relative; pass --base-url to say where the API lives"
                        ));
                    }
                }
            }
            (None, Some(o)) => o.clone(),
            (None, None) => {
                return Err(
                    "spec declares no server URL; pass --base-url to say where the API lives"
                        .to_string(),
                );
            }
        };
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            return Err(format!("server URL '{base}' is not an http/https URL"));
        }
        Ok(base)
    }

    fn swagger2_consumes(&self) -> Vec<&'a str> {
        self.op
            .get("consumes")
            .or_else(|| self.doc.get("consumes"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// OAS 3 `requestBody`: the most useful media type dalfox can rebuild,
    /// its example (or a schema sample), and the XML root name.
    #[allow(clippy::type_complexity)]
    fn oas3_body(&self) -> Option<(BodyKind, Option<&'a str>, Value, Option<String>)> {
        let rb = resolve(self.doc, self.op.get("requestBody")?)?;
        let (kind, mt, media) = rb
            .get("content")?
            .as_object()?
            .iter()
            .filter_map(|(mt, media)| body_kind(mt).map(|k| (k, mt.as_str(), media)))
            .min_by_key(|(k, _, _)| *k)?;
        let example = media.get("example").cloned().or_else(|| {
            let first = media.get("examples")?.as_object()?.values().next()?;
            resolve(self.doc, first)?.get("value").cloned()
        });
        let schema = media.get("schema");
        let value = match example {
            Some(v) => v,
            None => Sampler::new(self.doc).sample(schema?, 0),
        };
        Some((
            kind,
            Some(mt),
            value,
            schema.and_then(|s| xml_root(self.doc, s)),
        ))
    }

    /// A parameter's wire value: `example`, first of `examples`, then a
    /// sample of its `schema` (OAS 3) or of the parameter itself (Swagger 2.0
    /// keeps `type`/`default`/`enum` on the parameter).
    fn param_value(&self, p: &'a Value) -> String {
        if let Some(v) = p.get("example") {
            return wire_string(v);
        }
        if let Some(v) = p
            .get("examples")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .and_then(|e| resolve(self.doc, e))
            .and_then(|e| e.get("value"))
        {
            return wire_string(v);
        }
        let schema = p.get("schema").unwrap_or(p);
        wire_string(&Sampler::new(self.doc).sample(schema, 0))
    }
}

fn param_is(p: &Value, location: &str) -> bool {
    p.get("in").and_then(Value::as_str) == Some(location)
}

/// Split a server URL into its origin (`scheme://authority`, or a
/// scheme-relative `//authority`, backslashes included) and its path. A
/// server with neither (`/api/v3`, `api`) has no origin.
fn split_server(s: &str) -> (Option<&str>, &str) {
    let s = s.trim();
    let first_sep = s.find(['/', '\\', '?', '#']).unwrap_or(s.len());
    let authority_start = match s.find("://") {
        Some(i) if i <= first_sep => i + 3,
        _ if s.starts_with("//") || s.starts_with("\\\\") || s.starts_with("/\\") => 2,
        _ => return (None, s),
    };
    let end = s[authority_start..]
        .find(['/', '\\', '?', '#'])
        .map_or(s.len(), |e| authority_start + e);
    (Some(&s[..end]), &s[end..])
}

/// `servers[0].url` with `{variables}` replaced by their `default` (or first
/// `enum`). A variable without one is left as `{name}` for the caller to
/// reject — unless `--base-url` discards the part it sits in.
fn oas3_server_url(server: &Value) -> Result<String, String> {
    let raw = server
        .get("url")
        .and_then(Value::as_str)
        .ok_or("server entry has no url")?;
    let vars = server.get("variables");
    let mut out = String::new();
    let mut rest = raw;
    while let Some(open) = rest.find('{') {
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| format!("server URL '{raw}' has an unclosed {{"))?;
        let name = &rest[open + 1..open + close];
        let var = vars.and_then(|v| v.get(name));
        let value = var
            .and_then(|v| v.get("default"))
            .or_else(|| var.and_then(|v| v.get("enum")?.as_array()?.first()))
            .and_then(Value::as_str);
        out.push_str(&rest[..open]);
        match value {
            Some(v) => out.push_str(v),
            None => out.push_str(&rest[open..open + close + 1]),
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Swagger 2.0 `schemes` + `host` + `basePath`. Without `host` the base is
/// relative (`basePath`), which `--base-url` must anchor.
fn swagger2_server(doc: &Value) -> Option<String> {
    let base_path = doc.get("basePath").and_then(Value::as_str).unwrap_or("/");
    let host = doc.get("host").and_then(Value::as_str);
    let schemes: Vec<&str> = doc
        .get("schemes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let scheme = if schemes.is_empty() || schemes.contains(&"https") {
        "https"
    } else {
        schemes[0]
    };
    Some(match host {
        Some(h) => format!("{scheme}://{h}{base_path}"),
        None => base_path.to_string(),
    })
}

/// Append a (template-filled) path to the server URL. Textual, not
/// `Url::join`: a `//host` path is a network-path reference to `join` and
/// would retarget the scan. The result must stay on the server's origin.
pub(super) fn join_path(base: &Url, path: &str) -> Result<Url, String> {
    let mut b = base.clone();
    b.set_query(None);
    b.set_fragment(None);
    // Leading slashes / backslashes collapse to one separator, so neither a
    // `//host` nor a `\\host` path can read as a new authority.
    let path = path.trim_start_matches(['/', '\\']);
    let joined = format!("{}/{path}", b.as_str().trim_end_matches('/'));
    let url = Url::parse(&joined).map_err(|e| format!("invalid URL '{joined}': {e}"))?;
    if url.scheme() != b.scheme()
        || url.host_str() != b.host_str()
        || url.port_or_known_default() != b.port_or_known_default()
    {
        return Err(format!("path leaves the server origin ({url})"));
    }
    Ok(url)
}

/// XML root element name: the schema's `xml.name`, else the referenced
/// component's name.
fn xml_root(doc: &Value, schema: &Value) -> Option<String> {
    let named = |s: &Value| {
        s.get("xml")
            .and_then(|x| x.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    named(schema).or_else(|| {
        let r = schema.get("$ref")?.as_str()?;
        resolve(doc, schema)
            .and_then(named)
            .or_else(|| r.rsplit('/').next().map(str::to_string))
    })
}

/// Minimal XML for a sampled value: objects become child elements, arrays
/// repeat their element, scalars become escaped text. Names that are not
/// XML-safe fall back to `item`.
fn render_xml(name: &str, v: &Value, out: &mut String, depth: usize) {
    let safe = !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    let name = if safe { name } else { "item" };
    if let Value::Array(items) = v {
        for i in items {
            render_xml(name, i, out, depth + 1);
        }
        return;
    }
    out.push('<');
    out.push_str(name);
    out.push('>');
    match v {
        Value::Object(m) if depth < MAX_SCHEMA_DEPTH => {
            for (k, child) in m {
                render_xml(k, child, out, depth + 1);
            }
        }
        Value::Object(_) => {}
        other => {
            for c in wire_string(other).chars() {
                match c {
                    '<' => out.push_str("&lt;"),
                    '>' => out.push_str("&gt;"),
                    '&' => out.push_str("&amp;"),
                    c => out.push(c),
                }
            }
        }
    }
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

#[cfg(test)]
mod tests;
