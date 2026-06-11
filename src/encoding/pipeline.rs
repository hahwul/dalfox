//! Composable pre-encoding pipelines.
//!
//! The legacy `pre_encoding: Option<String>` slot supports a single
//! transformation (`base64`, `2base64`, `2url`, `3url`). Real-world endpoints
//! often wrap payloads in multiple layers, e.g.
//!
//! ```text
//! ?qs=BASE64({"move_url":"<INJECT>", "acc_domain":"…"})
//! ```
//!
//! where the actual injection point is one *field* of a JSON object that is
//! itself base64-encoded as the query value. To express that, payloads are
//! transformed through an ordered `EncodingPipeline` before they hit the wire.
//!
//! `infer_nested_pipelines` inspects an existing parameter value and, when it
//! looks like base64-of-JSON, returns one [`NestedField`] per leaf string
//! field — each carrying the pipeline that injects a payload at that field.
//! The reflection check is invariant to the pipeline because the server
//! decodes/parses the payload back to a plain string before reflecting it.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};

/// A single transformation applied to a payload string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncodingStep {
    /// Plug the payload into a JSON template at the given RFC 6901 pointer
    /// and serialize the result. The template carries every other field of
    /// the original value verbatim, so the server-side parser sees a complete
    /// object.
    JsonField {
        pointer: String,
        template: serde_json::Value,
    },
    /// Standard base64 (with padding).
    Base64,
    /// URL-safe base64 without padding (RFC 4648 §5). Used for JWT/JWS
    /// segments and for opaque tokens passed in URL query strings where
    /// `+`/`/` would need percent-encoding anyway.
    Base64Url,
    /// Single-round percent encoding. Useful when an outer layer (e.g. JSON
    /// stringify) preserves characters that a query value cannot carry.
    Url,
    /// Assemble a JWT/JWS by gluing the supplied (already base64url-encoded)
    /// header and signature segments around the input. The input is treated
    /// as the already-encoded payload segment, so this step is normally
    /// preceded by `JsonField → Base64Url`.
    ///
    /// The signature is preserved verbatim from the original token; this
    /// produces a token whose signature does not match the modified
    /// payload. It will only fire on endpoints that don't verify the
    /// signature (or that verify with `alg=none` / a known weak key).
    JwtAssemble {
        header_b64u: String,
        signature_b64u: String,
    },
}

impl EncodingStep {
    pub fn apply(&self, payload: &str) -> Result<String, String> {
        match self {
            EncodingStep::Base64 => Ok(STANDARD.encode(payload)),
            EncodingStep::Base64Url => Ok(URL_SAFE_NO_PAD.encode(payload)),
            EncodingStep::Url => Ok(urlencoding::encode(payload).to_string()),
            EncodingStep::JsonField { pointer, template } => {
                let mut value = template.clone();
                set_by_pointer(
                    &mut value,
                    pointer,
                    serde_json::Value::String(payload.to_string()),
                )?;
                serde_json::to_string(&value).map_err(|e| e.to_string())
            }
            EncodingStep::JwtAssemble {
                header_b64u,
                signature_b64u,
            } => Ok(format!("{header_b64u}.{payload}.{signature_b64u}")),
        }
    }
}

/// Ordered list of transformations applied left-to-right.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EncodingPipeline {
    pub steps: Vec<EncodingStep>,
}

impl EncodingPipeline {
    pub fn new(steps: Vec<EncodingStep>) -> Self {
        Self { steps }
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Run the payload through every step in order. Returns `Err` if any
    /// step fails (e.g. invalid JSON pointer); callers may fall back to the
    /// raw payload.
    pub fn apply(&self, payload: &str) -> Result<String, String> {
        let mut current = payload.to_string();
        for step in &self.steps {
            current = step.apply(&current)?;
        }
        Ok(current)
    }
}

/// Set the value at `pointer` (RFC 6901) inside `root`. Creates the leaf
/// entry on objects when it doesn't exist; for arrays the index must already
/// be in range. Empty pointer replaces `root` itself.
fn set_by_pointer(
    root: &mut serde_json::Value,
    pointer: &str,
    new_val: serde_json::Value,
) -> Result<(), String> {
    if pointer.is_empty() {
        *root = new_val;
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(format!("pointer must start with '/': {pointer}"));
    }
    let segs: Vec<String> = pointer[1..]
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect();
    let last_idx = segs.len() - 1;
    let mut cur = root;
    for (i, seg) in segs.iter().enumerate() {
        let last = i == last_idx;
        match cur {
            serde_json::Value::Object(map) => {
                if last {
                    map.insert(seg.clone(), new_val);
                    return Ok(());
                }
                cur = map
                    .get_mut(seg)
                    .ok_or_else(|| format!("missing key {seg}"))?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = seg
                    .parse()
                    .map_err(|_| format!("array segment is not an index: {seg}"))?;
                if idx >= arr.len() {
                    return Err(format!("index out of range: {idx}"));
                }
                if last {
                    arr[idx] = new_val;
                    return Ok(());
                }
                cur = &mut arr[idx];
            }
            _ => return Err(format!("cannot descend into scalar at segment {seg}")),
        }
    }
    Ok(())
}

/// One inferred injection point inside a structurally-encoded parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct NestedField {
    /// JSON pointer to the leaf, e.g. `/move_url` or `/items/0/name`.
    pub pointer: String,
    /// Field path components, for human-readable naming. Indexes are stored
    /// as decimal strings (`["items","0","name"]`).
    pub path: Vec<String>,
    /// Original leaf value (so probing can preserve realistic context if
    /// needed in the future).
    pub original_value: String,
    /// Pipeline that maps a raw payload to the wire value of the *outer*
    /// parameter (e.g. base64-of-JSON-with-this-field-replaced).
    pub pipeline: EncodingPipeline,
}

/// Maximum recursion depth into nested objects/arrays.
const MAX_DEPTH: usize = 4;
/// Maximum number of leaf fields to enumerate per parameter.
const MAX_LEAVES: usize = 32;
/// Minimum value length before we attempt base64 decoding. Below this the
/// false-positive rate is too high — short tokens ("abc=") look like b64.
const MIN_B64_CANDIDATE_LEN: usize = 16;

/// Inspect a parameter value and return one [`NestedField`] per leaf string
/// field that we can re-inject through a structural encoding pipeline.
///
/// Strategies tried in order, first non-empty result wins:
///
/// 1. **JWT/JWS** — three dot-separated base64url segments where the middle
///    one decodes to JSON. Pipeline: `JsonField → Base64Url → JwtAssemble`.
/// 2. **URL-encoded JSON** — value already starts with `{`/`[` (or `%7B`).
///    Pipeline: `JsonField` (the URL layer is added by the HTTP client).
/// 3. **base64-of-JSON** — standard alphabet. Pipeline: `JsonField → Base64`.
/// 4. **base64url-of-JSON** — URL-safe alphabet, no padding.
///    Pipeline: `JsonField → Base64Url`.
///
/// Returns an empty vec when nothing matches — every caller treats "no
/// nested fields" as "fall back to plain probes".
pub fn infer_nested_pipelines(value: &str) -> Vec<NestedField> {
    type Strategy = fn(&str) -> Vec<NestedField>;
    const STRATEGIES: &[Strategy] = &[infer_jwt, infer_url_json, infer_b64_or_b64url_json];
    for strategy in STRATEGIES {
        let result = strategy(value);
        if !result.is_empty() {
            return result;
        }
    }
    Vec::new()
}

/// Try base64-of-JSON with whichever alphabet the value hints at. Standard
/// alphabet (`+`/`/`) and url-safe (`-`/`_`) are mutually distinctive; for
/// values whose chars sit in the shared subset (alphanumeric only) we prefer
/// standard since it's the more common wire shape for opaque tokens.
fn infer_b64_or_b64url_json(value: &str) -> Vec<NestedField> {
    let trimmed = value.trim();
    let has_url_safe = trimmed.contains('-') || trimmed.contains('_');
    let has_standard = trimmed.contains('+') || trimmed.contains('/');
    if has_url_safe && !has_standard {
        infer_b64url_json(value)
    } else {
        let result = infer_b64_json(value);
        if !result.is_empty() {
            return result;
        }
        // Fall back to url-safe in the ambiguous (shared-alphabet) case.
        infer_b64url_json(value)
    }
}

/// Strategy: standard-alphabet base64 wrapping a JSON object/array.
fn infer_b64_json(value: &str) -> Vec<NestedField> {
    // `query_pairs()` URL-decoding turns a raw `+` in the value into a space, so
    // a standard-alphabet base64 value carrying `+` arrives space-mangled and
    // would be rejected. Undo that for the standard-alphabet attempt (url-safe
    // base64 has no `+`, so its path is unaffected). A non-base64/non-JSON value
    // still bails at the decode/JSON checks below, so this can't cause a false
    // discovery.
    let restored = value.replace(' ', "+");
    let value = restored.as_str();
    if !looks_like_b64(value, /*allow_url_safe=*/ false) {
        return Vec::new();
    }
    let Ok(decoded_bytes) = STANDARD.decode(value) else {
        return Vec::new();
    };
    let Ok(decoded) = std::str::from_utf8(&decoded_bytes) else {
        return Vec::new();
    };
    let Some(json) = parse_json_object_or_array(decoded) else {
        return Vec::new();
    };
    let leaves = collect_leaves(&json);
    attach_pipelines(leaves, move |pointer| {
        EncodingPipeline::new(vec![
            EncodingStep::JsonField {
                pointer,
                template: json.clone(),
            },
            EncodingStep::Base64,
        ])
    })
}

/// Strategy: URL-safe base64 (no padding) wrapping a JSON object/array.
/// Distinct from `infer_b64_json` because the alphabet (`-_` vs `+/`) is
/// preserved when re-encoding so the wire shape round-trips byte-for-byte.
fn infer_b64url_json(value: &str) -> Vec<NestedField> {
    if !looks_like_b64(value, /*allow_url_safe=*/ true) {
        return Vec::new();
    }
    let Ok(decoded_bytes) = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')) else {
        return Vec::new();
    };
    let Ok(decoded) = std::str::from_utf8(&decoded_bytes) else {
        return Vec::new();
    };
    let Some(json) = parse_json_object_or_array(decoded) else {
        return Vec::new();
    };
    let leaves = collect_leaves(&json);
    attach_pipelines(leaves, move |pointer| {
        EncodingPipeline::new(vec![
            EncodingStep::JsonField {
                pointer,
                template: json.clone(),
            },
            EncodingStep::Base64Url,
        ])
    })
}

/// Strategy: JWT/JWS — three dot-separated base64url segments where the
/// middle (payload) is JSON. The pipeline preserves the original header
/// and signature segments verbatim. The signature won't match the modified
/// payload, so this only fires on endpoints that skip verification or use
/// `alg=none`; discovery's per-leaf marker probe will silently report
/// nothing for properly-validated tokens.
fn infer_jwt(value: &str) -> Vec<NestedField> {
    let segments: Vec<&str> = value.split('.').collect();
    if segments.len() != 3 {
        return Vec::new();
    }
    let [header_b64u, payload_b64u, sig_b64u] = [segments[0], segments[1], segments[2]];
    if header_b64u.is_empty() || payload_b64u.is_empty() {
        return Vec::new();
    }
    // Sanity: every segment must be base64url charset. Padding (`=`) is
    // rejected since RFC 7515 forbids it for JWS.
    fn is_b64url_no_pad(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }
    if !is_b64url_no_pad(header_b64u)
        || !is_b64url_no_pad(payload_b64u)
        || !is_b64url_no_pad(sig_b64u)
    {
        return Vec::new();
    }
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64u) else {
        return Vec::new();
    };
    let Ok(payload_str) = std::str::from_utf8(&payload_bytes) else {
        return Vec::new();
    };
    let Some(json) = parse_json_object_or_array(payload_str) else {
        return Vec::new();
    };
    let header = header_b64u.to_string();
    let signature = sig_b64u.to_string();
    let leaves = collect_leaves(&json);
    attach_pipelines(leaves, move |pointer| {
        EncodingPipeline::new(vec![
            EncodingStep::JsonField {
                pointer,
                template: json.clone(),
            },
            EncodingStep::Base64Url,
            EncodingStep::JwtAssemble {
                header_b64u: header.clone(),
                signature_b64u: signature.clone(),
            },
        ])
    })
}

/// Strategy: bare JSON in the parameter value (`?data={...}` after URL-decode).
/// `query_pairs()` already URL-decodes, so by the time we see the value the
/// `%7B`/`%5B` prefix has been resolved to `{`/`[`.
fn infer_url_json(value: &str) -> Vec<NestedField> {
    let Some(json) = parse_json_object_or_array(value) else {
        return Vec::new();
    };
    let leaves = collect_leaves(&json);
    attach_pipelines(leaves, move |pointer| {
        EncodingPipeline::new(vec![EncodingStep::JsonField {
            pointer,
            template: json.clone(),
        }])
    })
}

fn parse_json_object_or_array(s: &str) -> Option<serde_json::Value> {
    let trimmed = s.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(s).ok()
}

/// Walk every string leaf inside `json`. Pipeline construction is left to
/// the caller (which typically wants to move owned data — templates, JWT
/// header/signature segments — into the per-leaf pipeline).
fn collect_leaves(json: &serde_json::Value) -> Vec<NestedField> {
    let mut leaves: Vec<NestedField> = Vec::new();
    walk_json(json, &mut Vec::new(), &mut leaves, 0);
    leaves
}

/// Build per-leaf `NestedField`s by attaching pipelines from `make_pipeline`.
fn attach_pipelines<F>(leaves: Vec<NestedField>, mut make_pipeline: F) -> Vec<NestedField>
where
    F: FnMut(String) -> EncodingPipeline,
{
    leaves
        .into_iter()
        .map(|mut nf| {
            nf.pipeline = make_pipeline(nf.pointer.clone());
            nf
        })
        .collect()
}

/// Cheap charset/length filter for base64 — we only run a real decode after
/// this passes. `allow_url_safe = false` accepts only the standard alphabet
/// (`+/`); `true` accepts the url-safe alphabet (`-_`) instead. Padding
/// (`=`) is permitted in both modes since some encoders pad url-safe values.
fn looks_like_b64(s: &str, allow_url_safe: bool) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < MIN_B64_CANDIDATE_LEN {
        return false;
    }
    let mut accepted = 0usize;
    let mut other = 0usize;
    for c in trimmed.chars() {
        let ok = c.is_ascii_alphanumeric()
            || c == '='
            || (allow_url_safe && (c == '-' || c == '_'))
            || (!allow_url_safe && (c == '+' || c == '/'));
        if ok {
            accepted += 1;
        } else {
            other += 1;
        }
    }
    other == 0 && accepted >= MIN_B64_CANDIDATE_LEN
}

fn walk_json(
    node: &serde_json::Value,
    path: &mut Vec<String>,
    out: &mut Vec<NestedField>,
    depth: usize,
) {
    if out.len() >= MAX_LEAVES || depth > MAX_DEPTH {
        return;
    }
    match node {
        serde_json::Value::String(s) => {
            out.push(NestedField {
                pointer: build_pointer(path),
                path: path.clone(),
                original_value: s.clone(),
                pipeline: EncodingPipeline::default(),
            });
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                walk_json(v, path, out, depth + 1);
                path.pop();
                if out.len() >= MAX_LEAVES {
                    break;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                path.push(i.to_string());
                walk_json(v, path, out, depth + 1);
                path.pop();
                if out.len() >= MAX_LEAVES {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn build_pointer(path: &[String]) -> String {
    let mut s = String::new();
    for seg in path {
        s.push('/');
        for c in seg.chars() {
            match c {
                '~' => s.push_str("~0"),
                '/' => s.push_str("~1"),
                _ => s.push(c),
            }
        }
    }
    s
}

#[cfg(test)]
mod tests;
