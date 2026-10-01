//! Bounded XML parsing for untrusted HTTP response bodies.
//!
//! `roxmltree` builds nested nodes recursively. A small linear depth scan must
//! run before it sees a response, and parse failures use the bounded HTML
//! parser as a recovery view so a DTD/entity error or malformed tail does not
//! hide active markup that a browser parsed before the error.

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

use scraper::{ElementRef, Html};

pub(crate) const MAX_XML_NESTING_DEPTH: usize = 512;

/// Upper bound on the text internal DTD entities may expand to before the
/// document is handed to roxmltree. roxmltree's loop detector caps nesting
/// depth (10) and references per *root* reference (255), but nothing bounds
/// the total: a 64 KiB entity referenced 250 times by a second entity, which
/// the body then references 16 times, is a 66 KB response that expands to
/// 262 MB (~700 MB RSS, ~10 s). Real XHTML/SVG declares few, short entities.
pub(crate) const MAX_XML_ENTITY_EXPANSION_BYTES: usize = 8 * 1024 * 1024;

pub(crate) enum XmlDocument<'a> {
    Parsed(roxmltree::Document<'a>),
    Recovered(RecoveredXml<'a>),
}

pub(crate) struct RecoveredXml<'a> {
    pub(crate) document: Html,
    source_prefix: &'a str,
    allow_active_root: bool,
    depth_limited: bool,
    /// Lexical facts about `source_prefix`, built once on first use. The
    /// per-element checks used to rescan the whole source for each element,
    /// which is quadratic in element count (16 000 siblings: ~52 s).
    index: OnceCell<RecoveredSourceIndex>,
}

impl RecoveredXml<'_> {
    pub(crate) fn source_prefix(&self) -> &str {
        self.source_prefix
    }

    fn index(&self) -> &RecoveredSourceIndex {
        self.index
            .get_or_init(|| RecoveredSourceIndex::build(self.source_prefix))
    }
}

/// One linear pass over the recovery source answering the questions the
/// per-element checks ask.
#[derive(Default)]
struct RecoveredSourceIndex {
    /// Names `n` for which `</n>` appears verbatim.
    closed: HashSet<String>,
    /// Start-tag names that appear at least once as `<n …/>`.
    self_closing: HashSet<String>,
    /// Prefixes `p` declared as `xmlns:p`.
    declared_prefixes: HashSet<String>,
}

impl RecoveredSourceIndex {
    /// Longest `</name>` recorded. A name is a single token; this only stops a
    /// run of `</</</…` from rescanning toward a distant `>` at every `</`.
    const MAX_CLOSE_NAME: usize = 1024;

    fn build(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut index = Self {
            self_closing: self_closing_tag_names(source),
            ..Self::default()
        };
        let mut from = 0usize;
        while let Some(rel) = source[from..].find("</") {
            let name_start = from + rel + 2;
            let window_end = (name_start + Self::MAX_CLOSE_NAME + 1).min(bytes.len());
            if let Some(gt) = bytes[name_start..window_end]
                .iter()
                .position(|&b| b == b'>')
            {
                index
                    .closed
                    .insert(source[name_start..name_start + gt].to_string());
            }
            from = name_start;
        }
        let mut from = 0usize;
        while let Some(rel) = source[from..].find("xmlns:") {
            let name_start = from + rel + "xmlns:".len();
            let mut name_end = name_start;
            while name_end < bytes.len() && is_name_char(bytes[name_end]) && bytes[name_end] != b':'
            {
                name_end += 1;
            }
            if name_end > name_start {
                index
                    .declared_prefixes
                    .insert(source[name_start..name_end].to_string());
            }
            from = name_start;
        }
        index
    }
}

/// Parse XML without exposing roxmltree to hostile nesting depth. DTD parsing
/// is enabled because it is part of normal XHTML/SVG documents; external
/// entities remain unresolved because no resolver is installed. Any parser
/// error (including unknown entities) is returned as a recovery HTML tree.
pub(crate) fn parse_xml_document(xml: &str) -> XmlDocument<'_> {
    if let Some(cut) = nesting_overflow_offset(xml, MAX_XML_NESTING_DEPTH) {
        crate::dbg_log!(
            "XML nesting exceeds {} levels; using bounded recovery parsing",
            MAX_XML_NESTING_DEPTH
        );
        return XmlDocument::Recovered(recover_xml(&xml[..cut], true, true));
    }
    if entity_expansion_exceeds(xml, MAX_XML_ENTITY_EXPANSION_BYTES) {
        crate::dbg_log!(
            "XML entity expansion may exceed {} bytes; using bounded recovery parsing",
            MAX_XML_ENTITY_EXPANSION_BYTES
        );
        // Same view as an unknown entity: the browser-visible markup is
        // still recovered over the complete body, just without expansion.
        return XmlDocument::Recovered(recover_xml(xml, true, false));
    }

    let options = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    };
    match roxmltree::Document::parse_with_options(xml, options) {
        Ok(document) => XmlDocument::Parsed(document),
        Err(error) => {
            crate::dbg_log!("XML parse failed; using bounded recovery parsing: {error}");
            let error_offset = xml_error_offset(xml, &error);
            // XHTML public DTDs define entities such as `&nbsp;` that
            // roxmltree does not expand. The browser can still parse content
            // after those references, so recover those documents over the
            // complete body instead of dropping the suffix at the error.
            let recover_complete_body = matches!(
                error,
                roxmltree::Error::UnknownEntityReference(_, _) | roxmltree::Error::DtdDetected
            );
            let recovery_source = if recover_complete_body {
                xml
            } else {
                &xml[..error_offset.min(xml.len())]
            };
            XmlDocument::Recovered(recover_xml(recovery_source, recover_complete_body, false))
        }
    }
}

/// Decide whether an already-parsed XML response would be an active browser
/// document. This lets AST extraction share the XML tree with the content-type
/// gate instead of parsing the same response a second time.
pub(crate) fn document_has_markup_for_content_type(
    content_type: &str,
    xml: &str,
    document: &XmlDocument<'_>,
) -> bool {
    let Some(primary) = crate::utils::content_type_primary(content_type) else {
        return false;
    };
    match primary.as_str() {
        "application/xhtml+xml" => {
            xml_root_is(document, xml, "http://www.w3.org/1999/xhtml", "html")
        }
        "image/svg+xml" => xml_root_is(document, xml, "http://www.w3.org/2000/svg", "svg"),
        _ if crate::utils::is_xml_content_type(&primary) => match document {
            XmlDocument::Parsed(document) => parsed_xml_has_active_markup(document),
            XmlDocument::Recovered(document) => recovered_xml_has_markup(document),
        },
        _ => false,
    }
}

fn xml_root_is(document: &XmlDocument<'_>, xml: &str, namespace: &str, local_name: &str) -> bool {
    match document {
        XmlDocument::Parsed(document) => {
            let root = document.root_element().tag_name();
            root.namespace() == Some(namespace) && root.name() == local_name
        }
        XmlDocument::Recovered(document) => {
            recovered_xml_root_is(xml, document, namespace, local_name)
        }
    }
}

fn recover_xml(
    source_prefix: &str,
    allow_active_root: bool,
    depth_limited: bool,
) -> RecoveredXml<'_> {
    RecoveredXml {
        document: crate::utils::html::parse_document_bounded(source_prefix),
        source_prefix,
        allow_active_root,
        depth_limited,
        index: OnceCell::new(),
    }
}

/// Whether expanding the internal general entities declared in `xml` could
/// produce more than `budget` bytes. An over-estimate: every `&` in the
/// document is charged the largest entity expansion, so a document that
/// passes cannot make roxmltree build more than `budget` bytes of entity text.
fn entity_expansion_exceeds(xml: &str, budget: usize) -> bool {
    let entities = internal_general_entities(xml);
    if entities.is_empty() {
        return false;
    }
    let mut memo = HashMap::new();
    let largest = entities
        .keys()
        .map(|name| expanded_entity_len(name, &entities, &mut memo, 0))
        .max()
        .unwrap_or(0);
    let references = xml.bytes().filter(|&b| b == b'&').count();
    references.saturating_mul(largest) > budget
}

/// `<!ENTITY name "value">` declarations (general, internal — the only kind
/// roxmltree expands), keyed by name. Parameter entities (`%`) and external
/// (`SYSTEM`/`PUBLIC`) ones are skipped.
fn internal_general_entities(xml: &str) -> HashMap<&str, &str> {
    let bytes = xml.as_bytes();
    let mut entities = HashMap::new();
    let mut from = 0usize;
    while let Some(rel) = xml[from..].find("<!ENTITY") {
        let mut i = from + rel + "<!ENTITY".len();
        from = i;
        let skip_ws = |mut i: usize| {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            i
        };
        i = skip_ws(i);
        if bytes.get(i) == Some(&b'%') {
            continue;
        }
        let name_start = i;
        while i < bytes.len() && is_name_char(bytes[i]) {
            i += 1;
        }
        if i == name_start {
            continue;
        }
        let name = &xml[name_start..i];
        i = skip_ws(i);
        let Some(&quote) = bytes.get(i).filter(|b| matches!(b, b'"' | b'\'')) else {
            continue;
        };
        let value_start = i + 1;
        let Some(len) = bytes[value_start..].iter().position(|&b| b == quote) else {
            break;
        };
        entities
            .entry(name)
            .or_insert(&xml[value_start..value_start + len]);
        from = value_start + len + 1;
    }
    entities
}

/// Fully expanded byte length of entity `name`, saturating. Depth is capped at
/// roxmltree's own limit (10); a deeper chain is a parse error there, so its
/// size here only needs to be finite.
fn expanded_entity_len<'a>(
    name: &'a str,
    entities: &HashMap<&'a str, &'a str>,
    memo: &mut HashMap<&'a str, usize>,
    depth: usize,
) -> usize {
    if let Some(&len) = memo.get(name) {
        return len;
    }
    let Some(&value) = entities.get(name) else {
        return 0;
    };
    if depth > 10 {
        return value.len();
    }
    let bytes = value.as_bytes();
    let mut total = value.len();
    let mut i = 0usize;
    while let Some(rel) = bytes[i..].iter().position(|&b| b == b'&') {
        let start = i + rel + 1;
        let mut end = start;
        while end < bytes.len() && is_name_char(bytes[end]) {
            end += 1;
        }
        if end > start && bytes.get(end) == Some(&b';') {
            let inner = expanded_entity_len(&value[start..end], entities, memo, depth + 1);
            total = total.saturating_add(inner);
        }
        i = start;
    }
    memo.insert(name, total);
    total
}

fn xml_error_offset(xml: &str, error: &roxmltree::Error) -> usize {
    match error {
        roxmltree::Error::UnexpectedEndOfStream | roxmltree::Error::UnclosedRootNode => xml.len(),
        roxmltree::Error::NoRootNode => 0,
        _ => {
            let position = error.pos();
            let target_row = position.row.saturating_sub(1) as usize;
            let mut row = 0usize;
            let mut line_start = 0usize;
            for (offset, byte) in xml.bytes().enumerate() {
                if byte == b'\n' {
                    if row == target_row {
                        return line_start
                            + xml[line_start..offset]
                                .char_indices()
                                .nth(position.col.saturating_sub(1) as usize)
                                .map(|(char_offset, _)| char_offset)
                                .unwrap_or(offset - line_start);
                    }
                    row += 1;
                    line_start = offset + 1;
                }
            }
            if row == target_row {
                line_start
                    + xml[line_start..]
                        .char_indices()
                        .nth(position.col.saturating_sub(1) as usize)
                        .map(|(char_offset, _)| char_offset)
                        .unwrap_or(xml.len() - line_start)
            } else {
                xml.len()
            }
        }
    }
}

pub(crate) fn parsed_xml_has_active_markup(document: &roxmltree::Document<'_>) -> bool {
    document.descendants().any(|node| {
        matches!(
            node.tag_name().namespace(),
            Some("http://www.w3.org/1999/xhtml" | "http://www.w3.org/2000/svg")
        )
    })
}

pub(crate) fn recovered_xml_has_active_markup(recovered: &RecoveredXml<'_>) -> bool {
    recovered
        .document
        .root_element()
        .descendent_elements()
        .any(|element| recovered_element_is_active_xml(recovered, element))
}

pub(crate) fn recovered_xml_has_markup(recovered: &RecoveredXml<'_>) -> bool {
    recovered.allow_active_root && recovered_xml_has_active_markup(recovered)
        || recovered_xml_has_executable_markup(recovered)
}

pub(crate) fn recovered_xml_has_executable_markup_before_error(
    recovered: &RecoveredXml<'_>,
) -> bool {
    recovered_xml_has_executable_markup(recovered)
}

pub(crate) fn recovered_xml_element_is_complete(
    recovered: &RecoveredXml<'_>,
    element: ElementRef<'_>,
) -> bool {
    let tag_name = element.value().name();
    let index = recovered.index();
    index.self_closing.contains(tag_name) || index.closed.contains(tag_name)
}

fn recovered_xml_has_executable_markup(recovered: &RecoveredXml<'_>) -> bool {
    recovered
        .document
        .root_element()
        .descendent_elements()
        .any(|element| {
            if !recovered_element_is_active_xml(recovered, element) {
                return false;
            }
            let tag_name = element.value().name();
            if (tag_name == "script" || tag_name.ends_with(":script"))
                && recovered.index().closed.contains(tag_name)
            {
                return true;
            }
            if recovered.depth_limited
                && element
                    .value()
                    .attrs()
                    .any(|(name, _)| name.eq_ignore_ascii_case("onload"))
            {
                return recovered.index().self_closing.contains(tag_name);
            }
            false
        })
}

pub(crate) fn recovered_xml_root_is(
    xml: &str,
    recovered: &RecoveredXml<'_>,
    namespace: &str,
    local_name: &str,
) -> bool {
    let Some(source_root) = first_xml_element_name(xml) else {
        return false;
    };
    let (prefix, source_local) = split_qualified_name(source_root);
    if source_local != local_name {
        return false;
    }

    (recovered.allow_active_root || recovered_xml_has_executable_markup(recovered))
        && recovered
            .document
            .root_element()
            .descendent_elements()
            .any(|element| {
                let (element_prefix, element_local) = split_qualified_name(element.value().name());
                element_local == local_name
                    && element_prefix == prefix
                    && recovered_element_namespace(recovered, element, prefix) == Some(namespace)
            })
}

/// Every start-tag name that appears at least once in self-closing form
/// (`<name …/>`). One pass; answers what used to be a whole-source scan per
/// element.
fn self_closing_tag_names(source: &str) -> HashSet<String> {
    let bytes = source.as_bytes();
    let mut names = HashSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(relative) = bytes[i..].iter().position(|byte| *byte == b'<') else {
            break;
        };
        i += relative;
        if bytes.get(i + 1) == Some(&b'/') {
            i = skip_tag(bytes, i + 2);
            continue;
        }
        let name_start = i + 1;
        let mut name_end = name_start;
        while name_end < bytes.len() && is_name_char(bytes[name_end]) {
            name_end += 1;
        }
        let end = skip_tag(bytes, name_end);
        let self_closing = bytes[name_start..end]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
            .is_some_and(|relative| bytes[name_start + relative] == b'/');
        if self_closing && let Some(name) = source.get(name_start..name_end) {
            names.insert(name.to_string());
        }
        i = end;
    }
    names
}

/// Whether this recovered HTML element inherited an active XML namespace.
/// HTML parsing keeps `xmlns` declarations as ordinary attributes, so walk up
/// the recovery tree to resolve the element's prefix/default namespace.
pub(crate) fn recovered_element_is_active_xml(
    recovered: &RecoveredXml<'_>,
    element: ElementRef<'_>,
) -> bool {
    matches!(
        recovered_element_namespace(
            recovered,
            element,
            split_qualified_name(element.value().name()).0
        ),
        Some("http://www.w3.org/1999/xhtml" | "http://www.w3.org/2000/svg")
    )
}

fn recovered_element_namespace<'a>(
    recovered: &RecoveredXml<'a>,
    element: ElementRef<'a>,
    prefix: Option<&str>,
) -> Option<&'a str> {
    let (declaration, prefix_declared) = match prefix {
        Some(prefix) => (
            prefix.to_string(),
            recovered.index().declared_prefixes.contains(prefix),
        ),
        None => ("xmlns".to_string(), true),
    };
    if !prefix_declared {
        return None;
    }
    let mut current = Some(element);
    while let Some(node) = current {
        if let Some((_, namespace)) = node.value().attrs().find(|(name, _)| *name == declaration) {
            return Some(namespace);
        }
        current = node.parent().and_then(ElementRef::wrap);
    }
    None
}

fn split_qualified_name(name: &str) -> (Option<&str>, &str) {
    match name.split_once(':') {
        Some((prefix, local)) => (Some(prefix), local),
        None => (None, name),
    }
}

/// Find the first element start tag in an XML-shaped source, skipping the
/// declaration, comments, processing instructions, and a DOCTYPE internal
/// subset. Used only to preserve the XHTML/SVG root checks after recovery.
fn first_xml_element_name(xml: &str) -> Option<&str> {
    let bytes = xml.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let relative = bytes[i..].iter().position(|byte| *byte == b'<')?;
        i += relative;
        let start = i;
        let next = *bytes.get(i + 1)?;
        match next {
            b'!' if bytes.get(i + 2..i + 4) == Some(b"--") => {
                i = find_after(bytes, i + 4, b"-->").unwrap_or(bytes.len());
            }
            b'!' => i = skip_declaration(bytes, i + 2),
            b'?' => i = find_after(bytes, i + 2, b"?>").unwrap_or(bytes.len()),
            b'/' => {
                i = skip_tag(bytes, i + 2);
            }
            b if is_name_start(b) => {
                let mut end = i + 1;
                while end < bytes.len() && is_name_char(bytes[end]) {
                    end += 1;
                }
                return std::str::from_utf8(&bytes[i + 1..end]).ok();
            }
            _ => i = start + 1,
        }
    }
    None
}

/// Byte offset of the first open tag that would exceed `limit`, or `None` if
/// nesting stays within the bound. This is intentionally lexical and linear:
/// mismatched tags may make it overestimate depth, which only selects the safe
/// recovery path; it must never underestimate valid nested XML.
fn nesting_overflow_offset(xml: &str, limit: usize) -> Option<usize> {
    let bytes = xml.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let start = i;
        let next = *bytes.get(i + 1)?;
        match next {
            b'!' if bytes.get(i + 2..i + 4) == Some(b"--") => {
                i = find_after(bytes, i + 4, b"-->").unwrap_or(bytes.len());
            }
            b'!' if bytes.get(i + 2..i + 9) == Some(b"[CDATA[") => {
                i = find_after(bytes, i + 9, b"]]>").unwrap_or(bytes.len());
            }
            b'!' => i = skip_declaration(bytes, i + 2),
            b'?' => i = find_after(bytes, i + 2, b"?>").unwrap_or(bytes.len()),
            b'/' => {
                i = skip_tag(bytes, i + 2);
                depth = depth.saturating_sub(1);
            }
            b if is_name_start(b) => {
                let mut name_end = i + 1;
                while name_end < bytes.len() && is_name_char(bytes[name_end]) {
                    name_end += 1;
                }
                let end = skip_tag(bytes, name_end);
                let self_closing = bytes[i..end]
                    .iter()
                    .rposition(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
                    .is_some_and(|relative| bytes[i + relative] == b'/');
                i = end;
                if !self_closing {
                    depth += 1;
                    if depth > limit {
                        return Some(start);
                    }
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':') || byte >= 0x80
}

fn is_name_char(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
}

fn skip_tag(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    let mut quote = None;
    while i < bytes.len() {
        let byte = bytes[i];
        match quote {
            Some(q) if byte == q => quote = None,
            Some(_) => {}
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None if byte == b'>' => return i + 1,
            None => {}
        }
        i += 1;
    }
    bytes.len()
}

fn skip_declaration(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    let mut quote = None;
    let mut subset_depth = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        match quote {
            Some(q) if byte == q => quote = None,
            Some(_) => {}
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None if byte == b'[' => subset_depth += 1,
            None if byte == b']' => subset_depth = subset_depth.saturating_sub(1),
            None if byte == b'>' && subset_depth == 0 => return i + 1,
            None => {}
        }
        i += 1;
    }
    bytes.len()
}

fn find_after(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from + at + needle.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_scan_ignores_non_markup_and_quoted_delimiters() {
        let xml = concat!(
            "<!DOCTYPE root [<!ENTITY fake '<bad><bad>'>]>",
            "<!-- <comment> --><?pi <fake>?>",
            "<root attr=\"<fake>\"><![CDATA[<cdata>]]><a/></root>"
        );
        assert_eq!(nesting_overflow_offset(xml, 2), None);
        assert!(nesting_overflow_offset("<a><b><c/></b></a>", 1).is_some());
    }

    #[test]
    fn parser_allows_doctypes_and_recovers_unknown_entities() {
        let doctype = "<!DOCTYPE html><html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>";
        assert!(matches!(
            parse_xml_document(doctype),
            XmlDocument::Parsed(_)
        ));

        let unknown = "<!DOCTYPE html><html xmlns=\"http://www.w3.org/1999/xhtml\"><body>&nbsp;</body></html>";
        let XmlDocument::Recovered(recovered) = parse_xml_document(unknown) else {
            panic!("unknown entity should use recovery parsing")
        };
        assert!(recovered_xml_root_is(
            unknown,
            &recovered,
            "http://www.w3.org/1999/xhtml",
            "html"
        ));
    }

    #[test]
    fn depth_at_least_ten_thousand_takes_bounded_recovery_path() {
        let xml = format!("<root>{}</root>", "<n>".repeat(10_000));
        assert!(matches!(
            parse_xml_document(&xml),
            XmlDocument::Recovered(_)
        ));
    }

    /// Two-level entity amplification: a 64 KiB entity referenced 250 times
    /// by a second one, which the body references 16 times. A ~66 KB body
    /// that used to expand to ~262 MB (≈700 MB RSS) inside roxmltree.
    fn amplifying_entities(refs: usize) -> String {
        format!(
            "<!DOCTYPE r [<!ENTITY a \"{}\"><!ENTITY b \"{}\">]><r>{}</r>",
            "x".repeat(64 * 1024),
            "&a;".repeat(250),
            "&b;".repeat(refs)
        )
    }

    #[test]
    fn amplifying_entities_take_the_recovery_path() {
        let xml = amplifying_entities(16);
        let start = std::time::Instant::now();
        assert!(matches!(
            parse_xml_document(&xml),
            XmlDocument::Recovered(_)
        ));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "entity guard took {:?}",
            start.elapsed()
        );
        // The content-type gate reaches the same parser.
        let _ = crate::utils::http::response_has_markup_document("application/xml", &xml);
    }

    #[test]
    fn small_internal_entities_still_parse() {
        let xml = concat!(
            "<!DOCTYPE html [<!ENTITY nbsp \"&#160;\"><!ENTITY co \"ACME &amp; Co\">]>",
            "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body>&co;&nbsp;&co;</body></html>"
        );
        let XmlDocument::Parsed(document) = parse_xml_document(xml) else {
            panic!("small internal entities must stay on the roxmltree path")
        };
        assert!(
            document
                .descendants()
                .filter_map(|n| n.text())
                .any(|t| t.contains("ACME & Co"))
        );
    }

    #[test]
    fn entity_expansion_estimate_follows_nested_references() {
        let xml = amplifying_entities(1);
        let entities = internal_general_entities(&xml);
        let mut memo = HashMap::new();
        assert_eq!(
            expanded_entity_len("b", &entities, &mut memo, 0),
            250 * 3 + 250 * 64 * 1024
        );
        // A self-referencing entity is a roxmltree error, but must terminate here.
        let looped = internal_general_entities("<!DOCTYPE r [<!ENTITY a '&a;&a;'>]>");
        assert!(expanded_entity_len("a", &looped, &mut HashMap::new(), 0) > 0);
    }

    #[test]
    fn recovered_per_element_checks_stay_linear() {
        // An unknown entity forces recovery; every sibling then asks the
        // completeness / namespace questions that used to rescan the source.
        let siblings: String = (0..16_000)
            .map(|i| format!("<p:e{i} xmlns:q=\"x\"></p:e{i}><br/>"))
            .collect();
        let xml = format!(
            "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body>&nbsp;{siblings}<script>1</script></body></html>"
        );
        let start = std::time::Instant::now();
        let XmlDocument::Recovered(recovered) = parse_xml_document(&xml) else {
            panic!("unknown entity should use recovery parsing")
        };
        let complete = recovered
            .document
            .root_element()
            .descendent_elements()
            .filter(|e| recovered_xml_element_is_complete(&recovered, *e))
            .count();
        let _ = recovered_xml_has_markup(&recovered);
        let _ = crate::scanning::ast_integration::extract_js_and_script_ids_from_xml(&xml);
        assert!(complete >= 16_000, "complete={complete}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "recovered checks took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn recovered_index_matches_lexical_source_facts() {
        let source = "<a/><b x='/>'></b><svg:script xmlns:svg='u'>1</svg:script></</c><d />";
        let index = RecoveredSourceIndex::build(source);
        assert!(index.self_closing.contains("a"));
        assert!(index.self_closing.contains("d"));
        assert!(!index.self_closing.contains("b"));
        assert!(index.closed.contains("b"));
        assert!(index.closed.contains("svg:script"));
        assert!(index.closed.contains("c"));
        assert!(!index.closed.contains("a"));
        assert!(index.declared_prefixes.contains("svg"));
        assert!(!index.declared_prefixes.contains("sv"));
    }
}
