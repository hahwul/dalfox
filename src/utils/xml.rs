//! Bounded XML parsing for untrusted HTTP response bodies.
//!
//! `roxmltree` builds nested nodes recursively. A small linear depth scan must
//! run before it sees a response, and parse failures use the bounded HTML
//! parser as a recovery view so a DTD/entity error or malformed tail does not
//! hide active markup that a browser parsed before the error.

use scraper::{ElementRef, Html};

pub(crate) const MAX_XML_NESTING_DEPTH: usize = 512;

pub(crate) enum XmlDocument<'a> {
    Parsed(roxmltree::Document<'a>),
    Recovered(RecoveredXml<'a>),
}

pub(crate) struct RecoveredXml<'a> {
    pub(crate) document: Html,
    source_prefix: &'a str,
    allow_active_root: bool,
    depth_limited: bool,
}

impl RecoveredXml<'_> {
    pub(crate) fn source_prefix(&self) -> &str {
        self.source_prefix
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
    }
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
    source_has_self_closing_tag(recovered.source_prefix, tag_name)
        || recovered.source_prefix.contains(&format!("</{tag_name}>"))
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
            if tag_name == "script" || tag_name.ends_with(":script") {
                let close_tag = format!("</{tag_name}>");
                if recovered.source_prefix.contains(&close_tag) {
                    return true;
                }
            }
            if recovered.depth_limited
                && element
                    .value()
                    .attrs()
                    .any(|(name, _)| name.eq_ignore_ascii_case("onload"))
            {
                return source_has_self_closing_tag(recovered.source_prefix, tag_name);
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

fn source_has_self_closing_tag(source: &str, tag_name: &str) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(relative) = bytes[i..].iter().position(|byte| *byte == b'<') else {
            return false;
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
        if source.get(name_start..name_end) == Some(tag_name) {
            let end = skip_tag(bytes, name_end);
            let self_closing = bytes[name_start..end]
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
                .is_some_and(|relative| bytes[name_start + relative] == b'/');
            if self_closing {
                return true;
            }
            i = end;
            continue;
        }
        i = skip_tag(bytes, name_end);
    }
    false
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
            recovered.source_prefix.contains(&format!("xmlns:{prefix}")),
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
}
