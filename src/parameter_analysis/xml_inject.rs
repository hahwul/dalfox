//! XML / SOAP request-body injection-point discovery.
//!
//! Locates the exact byte range of every element **text node** and **attribute
//! value** in an XML document so the scanner can splice a payload into one leaf
//! and leave the rest of the document byte-for-byte intact. This is a
//! deliberately small, self-contained tokenizer — it is NOT a conforming XML
//! parser (no namespace resolution, entity expansion, or DTD handling), and it
//! never rewrites the document. Injection is a `Splice` of the original bytes
//! around the located range (see [`crate::encoding::pipeline::EncodingStep::Splice`]),
//! which sidesteps the lossy parse-and-reserialize round-trip that garbled the
//! JSON builder.
//!
//! False-positive safety: a body that does not tokenize into any text/attribute
//! leaf yields an empty result, and every caller treats "no points" as "not an
//! XML injection target" (silent fall-back to the original body). Discovery
//! itself is still gated on the marker actually reflecting, so a benign XML
//! body that echoes nothing seeds no params.

/// One injectable leaf inside an XML document, addressed by an exact byte range
/// in the original body.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XmlInjectionPoint {
    /// Human-readable name, e.g. `note/to` for a text node or `item@id` for an
    /// attribute value. De-duplicated across the document (`_2`, `_3`, …).
    pub name: String,
    /// The original leaf text (attribute value, or trimmed element text).
    pub value: String,
    /// Byte offset (inclusive) where the payload replaces the leaf.
    pub start: usize,
    /// Byte offset (exclusive) where the replacement ends.
    pub end: usize,
}

/// Upper bound on discovered points, mirroring the JSON walker's leaf cap so a
/// pathological document can't fan out into thousands of probe requests.
const MAX_POINTS: usize = 64;

/// Tokenize `data` as XML and return every element text node and attribute
/// value as an [`XmlInjectionPoint`]. Comments, CDATA, the XML declaration,
/// processing instructions, and DOCTYPE are skipped. Returns an empty vec when
/// the body is not XML-shaped or yields no leaves.
pub(crate) fn xml_injection_points(data: &str) -> Vec<XmlInjectionPoint> {
    let bytes = data.as_bytes();
    let n = bytes.len();
    // Cheap shape gate: an XML body must open with a `<` (after leading
    // whitespace/BOM). Anything else (JSON, form-urlencoded, plain text) is not
    // ours.
    let first_non_ws = data.trim_start();
    if !first_non_ws.starts_with('<') {
        return Vec::new();
    }

    let mut points: Vec<XmlInjectionPoint> = Vec::new();
    let mut raw: Vec<(String, String, usize, usize)> = Vec::new(); // (name, value, start, end)
    let mut i = 0usize;

    while i < n {
        if bytes[i] == b'<' {
            // Dispatch on the bytes right after '<'.
            if starts_with(bytes, i, b"<!--") {
                i = find_after(bytes, i + 4, b"-->").unwrap_or(n);
                continue;
            }
            if starts_with(bytes, i, b"<![CDATA[") {
                i = find_after(bytes, i + 9, b"]]>").unwrap_or(n);
                continue;
            }
            if starts_with(bytes, i, b"<?") {
                i = find_after(bytes, i + 2, b"?>").unwrap_or(n);
                continue;
            }
            if starts_with(bytes, i, b"<!") {
                // DOCTYPE / other markup declaration. Skip to the matching '>'
                // (internal subset '[...]' is not handled — rare, and the
                // whole-body fallback stays correct if we over-skip).
                i = skip_to_gt(bytes, i + 2).map(|g| g + 1).unwrap_or(n);
                continue;
            }
            if starts_with(bytes, i, b"</") {
                // End tag: no attributes, no injectable content.
                i = skip_to_gt(bytes, i + 2).map(|g| g + 1).unwrap_or(n);
                continue;
            }
            // Start tag or empty-element tag: parse name + attributes, honoring
            // quotes so a '>' inside an attribute value doesn't end the tag.
            match parse_tag(bytes, i) {
                Some((tag_name, attrs, tag_end)) => {
                    for (attr_name, vstart, vend) in attrs {
                        if vend > vstart {
                            let value = data[vstart..vend].to_string();
                            raw.push((format!("{tag_name}@{attr_name}"), value, vstart, vend));
                        }
                    }
                    // After the tag, element content (text) runs until the next
                    // '<'. Record it as a text node when non-whitespace.
                    let content_start = tag_end + 1;
                    let mut j = content_start;
                    while j < n && bytes[j] != b'<' {
                        j += 1;
                    }
                    let run = &data[content_start..j];
                    let trimmed = run.trim();
                    if !trimmed.is_empty() {
                        // Byte range of the trimmed content, so surrounding
                        // indentation/newlines are preserved.
                        let lead = run.len() - run.trim_start().len();
                        let ts = content_start + lead;
                        let te = ts + trimmed.len();
                        raw.push((tag_name.clone(), trimmed.to_string(), ts, te));
                    }
                    i = content_start; // continue scanning from element content
                }
                None => {
                    // Malformed start tag — bail on this '<' and move on.
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }

    // De-duplicate display names (`to`, `to_2`, `item@id`, `item@id_2`, …) so
    // each probe/param slot is addressable and unambiguous.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (name, value, start, end) in raw {
        if points.len() >= MAX_POINTS {
            break;
        }
        let count = seen.entry(name.clone()).or_insert(0);
        *count += 1;
        let display = if *count == 1 {
            name
        } else {
            format!("{name}_{count}")
        };
        points.push(XmlInjectionPoint {
            name: display,
            value,
            start,
            end,
        });
    }
    points
}

/// Whether `bytes[at..]` begins with `needle`.
fn starts_with(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    bytes.len() >= at + needle.len() && &bytes[at..at + needle.len()] == needle
}

/// Index one past the end of the first `needle` found at or after `from`.
fn find_after(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from > bytes.len() {
        return None;
    }
    let end = bytes.len();
    let mut i = from;
    while i + needle.len() <= end {
        if &bytes[i..i + needle.len()] == needle {
            return Some(i + needle.len());
        }
        i += 1;
    }
    None
}

/// Index of the next unquoted `>` at or after `from` (quote-aware).
fn skip_to_gt(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(i),
                _ => {}
            },
        }
        i += 1;
    }
    None
}

/// Parse a start/empty-element tag beginning at `bytes[start] == '<'`. Returns
/// `(tag_name, attributes, tag_end_index)` where `tag_end_index` points at the
/// closing `>` and each attribute is `(name, value_start, value_end)` with the
/// value range excluding the surrounding quotes. `None` on a malformed tag.
#[allow(clippy::type_complexity)]
fn parse_tag(bytes: &[u8], start: usize) -> Option<(String, Vec<(String, usize, usize)>, usize)> {
    let n = bytes.len();
    let mut i = start + 1; // past '<'
    // Element name: up to whitespace, '>', or '/'.
    let name_start = i;
    while i < n && !is_space(bytes[i]) && bytes[i] != b'>' && bytes[i] != b'/' {
        i += 1;
    }
    if i == name_start {
        return None; // no name
    }
    let tag_name = std::str::from_utf8(&bytes[name_start..i]).ok()?.to_string();

    let mut attrs: Vec<(String, usize, usize)> = Vec::new();
    loop {
        // Skip whitespace between attributes.
        while i < n && is_space(bytes[i]) {
            i += 1;
        }
        if i >= n {
            return None; // unterminated tag
        }
        match bytes[i] {
            b'>' => return Some((tag_name, attrs, i)),
            b'/' => {
                // Empty-element tag: expect '/>' (tolerate stray whitespace).
                let mut j = i + 1;
                while j < n && is_space(bytes[j]) {
                    j += 1;
                }
                if j < n && bytes[j] == b'>' {
                    return Some((tag_name, attrs, j));
                }
                return None;
            }
            _ => {
                // Attribute name up to '=', whitespace, '>', or '/'.
                let an_start = i;
                while i < n
                    && bytes[i] != b'='
                    && !is_space(bytes[i])
                    && bytes[i] != b'>'
                    && bytes[i] != b'/'
                {
                    i += 1;
                }
                let attr_name = std::str::from_utf8(&bytes[an_start..i]).ok()?.to_string();
                // Skip whitespace before '='.
                while i < n && is_space(bytes[i]) {
                    i += 1;
                }
                if i < n && bytes[i] == b'=' {
                    i += 1; // past '='
                    while i < n && is_space(bytes[i]) {
                        i += 1;
                    }
                    if i < n && (bytes[i] == b'"' || bytes[i] == b'\'') {
                        let quote = bytes[i];
                        i += 1;
                        let vstart = i;
                        while i < n && bytes[i] != quote {
                            i += 1;
                        }
                        if i >= n {
                            return None; // unterminated attribute value
                        }
                        let vend = i;
                        i += 1; // past closing quote
                        if std::str::from_utf8(&bytes[vstart..vend]).is_ok() {
                            attrs.push((attr_name, vstart, vend));
                        }
                    }
                    // Unquoted / valueless attribute: not an injectable string.
                } else if attr_name.is_empty() {
                    // No progress and no '=': malformed.
                    return None;
                }
            }
        }
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests;
