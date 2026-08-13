/*!
Bounded HTML parsing.

Every response dalfox looks at is parsed by html5ever (via `scraper`) several
times — meta-CSP extraction, injection-context detection, DOM verification,
inline-script collection. html5ever's tree builder consults the *open elements
stack* on essentially every tag (the "have element in scope" checks), so its
cost is `O(depth)` per element and therefore **quadratic in nesting depth** for
a document that nests without bound. There is no depth limit inside html5ever.

Measured against the real scanner (debug build, localhost server):

| body                       | size    | one scan |
|----------------------------|---------|----------|
| 8 000 `<div>` nested       |  88 KiB |    7.2 s |
| 8 000 `<div>` **siblings** |  96 KiB |    0.26 s |
| 16 000 `<div>` nested      | 176 KiB |     29 s |
| 60 000 `<div>` nested      | 660 KiB |  > 150 s |

Size is not the driver — depth is; doubling depth quadruples the time. A single
hostile (or merely generated) response could therefore stall a scan
indefinitely, which is a worse outcome than analyzing a truncated document:
a wedged target is 100% recall loss *plus* a hang.

So: estimate nesting depth with one cheap linear pass, and when a document
nests past [`MAX_HTML_NESTING_DEPTH`], hand the parser only the prefix up to
that point. Browsers do the same thing — Blink and Gecko both cap HTML parser
tree depth in the same ballpark (512) and flatten anything deeper — so markup
past the bound does not nest the way it claims in a real browser either.

Only the tree-based analyses are bounded by this. The byte/text-level
reflection checks never parse HTML and always see the full body.
*/

use std::borrow::Cow;

/// Maximum element nesting depth handed to html5ever. Matches the order of the
/// caps real browser parsers apply; real-world documents are one to two orders
/// of magnitude shallower.
pub const MAX_HTML_NESTING_DEPTH: usize = 512;

/// Elements that never nest: they have no end tag at all.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Start tags that implicitly close an already-open element, and the barrier
/// elements that stop that search.
///
/// `(start_tag, closes, barriers)`: seeing `start_tag` pops the stack down to
/// and including the nearest open element named in `closes`, unless one of
/// `barriers` is reached first. This is what makes ordinary sloppy markup — a
/// 600-item `<ul>` whose `<li>`s are never closed, a table whose `<td>`s are
/// never closed — read as depth 2 rather than depth 601.
///
/// The barriers are what keep *deliberately* deep markup honest: `<ul><li>`
/// repeated 30 000 times really is 30 000 levels deep in a browser, and the
/// intervening `ul` stops the implied close, so the estimate grows with it.
/// Without barriers this table would be an attacker's way around the guard.
const IMPLIED_END_TAGS: &[(&str, &[&str], &[&str])] = &[
    ("li", &["li"], &["ul", "ol", "menu"]),
    ("dt", &["dt", "dd"], &["dl"]),
    ("dd", &["dt", "dd"], &["dl"]),
    ("p", &["p"], &[]),
    ("option", &["option"], &["select", "datalist", "optgroup"]),
    ("optgroup", &["option", "optgroup"], &["select", "datalist"]),
    ("tr", &["td", "th", "tr"], &["table"]),
    ("td", &["td", "th"], &["table", "tr"]),
    ("th", &["td", "th"], &["table", "tr"]),
    (
        "thead",
        &["td", "th", "tr", "thead", "tbody", "tfoot"],
        &["table"],
    ),
    (
        "tbody",
        &["td", "th", "tr", "thead", "tbody", "tfoot"],
        &["table"],
    ),
    (
        "tfoot",
        &["td", "th", "tr", "thead", "tbody", "tfoot"],
        &["table"],
    ),
    ("rt", &["rt", "rp"], &["ruby"]),
    ("rp", &["rt", "rp"], &["ruby"]),
];

/// Elements whose content is raw text, not markup. `<script>if (a<b) {}</script>`
/// must not be read as opening a `<b>`.
const RAWTEXT_ELEMENTS: &[&str] = &["script", "style", "textarea", "title"];

/// Lowercased ASCII tag name starting at `bytes[i]` (just past `<` or `</`),
/// plus the offset just after it. Empty when the byte is not a name start.
fn tag_name_at(bytes: &[u8], i: usize) -> (String, usize) {
    let mut end = i;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-') {
        end += 1;
    }
    (
        String::from_utf8_lossy(&bytes[i..end]).to_ascii_lowercase(),
        end,
    )
}

/// Offset of the byte just past the `>` that ends the tag starting at `from`
/// (or the end of input).
///
/// Quote-aware: a `>` inside a quoted attribute value does not end the tag.
/// Without that, `<iframe srcdoc="<div><div>…">` ended the tag at the first
/// `>` inside `srcdoc` and the rest of the attribute value was rescanned as
/// markup — 600 `<div>`s in an attribute read as 600 open elements and
/// truncated a 3 KiB document. Raw `<` and `>` are legal inside a quoted
/// attribute value, and html5ever treats all of it as text.
fn skip_to_gt(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return i + 1,
            None => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Whether the tag that ends at `gt_end` (offset just past its `>`) was
/// self-closing (`<div/>`).
fn tag_is_self_closing(bytes: &[u8], gt_end: usize) -> bool {
    gt_end >= 2 && bytes[gt_end - 1] == b'>' && bytes[gt_end - 2] == b'/'
}

/// Offset of the first ASCII-case-insensitive occurrence of `needle` in
/// `bytes[from..]`, as an absolute offset.
///
/// Allocation-free on purpose. The obvious spelling — lowercasing the rest of
/// the document and calling `find` — allocates a copy of the *remaining* body
/// at each call site, so a page with 10 000 `<script>` tags would allocate
/// 10 000 progressively shorter copies: quadratic memory traffic inside the
/// very guard that exists to stop a quadratic blowup.
fn find_ascii_case_insensitive(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= bytes.len() {
        return None;
    }
    let first = needle[0];
    let end = bytes.len().checked_sub(needle.len())?;
    (from..=end).find(|&start| {
        bytes[start].eq_ignore_ascii_case(&first)
            && bytes[start..start + needle.len()].eq_ignore_ascii_case(needle)
    })
}

/// The estimator's open-element stack, with an O(1) "is this name open?" test.
///
/// The count map is what lets an end tag unwind without a lookback limit. The
/// previous version capped the search at 32 entries, which meant an end tag
/// whose match sat deeper simply popped nothing — so every unclosed inline
/// element inside it leaked one stack entry *permanently*, and ordinary legacy
/// markup (20 blog posts each with 35 unclosed `<font>`s) crossed a 512 cap on
/// a 9 KiB page whose real depth is 3. Here a name that is not open at all is
/// rejected in O(1), and a name that is open is always unwound to; since every
/// entry is pushed once and popped once, the total work stays linear.
#[derive(Default)]
struct OpenElements {
    stack: Vec<String>,
    counts: std::collections::HashMap<String, usize>,
}

impl OpenElements {
    fn len(&self) -> usize {
        self.stack.len()
    }

    fn is_open(&self, name: &str) -> bool {
        self.counts.get(name).is_some_and(|&n| n > 0)
    }

    fn push(&mut self, name: String) {
        *self.counts.entry(name.clone()).or_insert(0) += 1;
        self.stack.push(name);
    }

    /// Pop everything above `idx`, plus `idx` itself.
    fn truncate_including(&mut self, idx: usize) {
        for name in self.stack.drain(idx..) {
            if let Some(c) = self.counts.get_mut(&name) {
                *c = c.saturating_sub(1);
            }
        }
    }

    /// Index of the topmost open element named `name`, searching down from the
    /// top and stopping at any of `barriers`. `None` when a barrier is reached
    /// first or the name is not open.
    fn nearest(&self, names: &[&str], barriers: &[&str]) -> Option<usize> {
        if !names.iter().any(|n| self.is_open(n)) {
            return None;
        }
        self.stack
            .iter()
            .rposition(|open| names.contains(&open.as_str()) || barriers.contains(&open.as_str()))
            .filter(|&idx| names.contains(&self.stack[idx].as_str()))
    }
}

/// Byte offset of the `<` whose element would push nesting past `limit`, or
/// `None` when the document stays within it.
///
/// A deliberately approximate scanner: it models only what drives html5ever's
/// cost (how deep the open-elements stack gets). Where it is inexact it is
/// inexact toward *under*-estimating, because an over-estimate truncates a
/// legitimate page and silently costs findings, while an under-estimate only
/// costs parse time. (An earlier version got this backwards — see
/// [`OpenElements`].)
fn nesting_overflow_offset(html: &str, limit: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut open = OpenElements::default();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let tag_start = i;
        let next = i + 1;
        if next >= bytes.len() {
            break;
        }
        match bytes[next] {
            // Comment, doctype, CDATA, processing instruction: no element.
            b'!' | b'?' => {
                if bytes[next..].starts_with(b"!--") {
                    i = match html[next + 3..].find("-->") {
                        Some(rel) => next + 3 + rel + 3,
                        None => bytes.len(),
                    };
                } else {
                    i = skip_to_gt(bytes, next);
                }
            }
            // End tag: unwind to the matching open element if there is one.
            // Doing this for *every* name is what clears the inline elements a
            // `</td>` or `</div>` implicitly closes.
            b'/' => {
                let (name, name_end) = tag_name_at(bytes, next + 1);
                i = skip_to_gt(bytes, name_end);
                if name.is_empty() || !open.is_open(&name) {
                    continue;
                }
                if let Some(idx) = open.stack.iter().rposition(|o| *o == name) {
                    open.truncate_including(idx);
                }
            }
            _ => {
                let (name, name_end) = tag_name_at(bytes, next);
                if name.is_empty() {
                    // A bare `<` in text ("a < b"): not a tag at all.
                    i = next;
                    continue;
                }
                let gt_end = skip_to_gt(bytes, name_end);
                if RAWTEXT_ELEMENTS.contains(&name.as_str()) {
                    // Jump over the raw-text content wholesale; its `<`s are
                    // data. The search starts at `gt_end`, which is already
                    // past this tag's `>`, so the cursor always advances.
                    let close = format!("</{name}");
                    i = find_ascii_case_insensitive(bytes, gt_end, close.as_bytes())
                        .unwrap_or(bytes.len());
                    continue;
                }
                i = gt_end;
                if VOID_ELEMENTS.contains(&name.as_str()) || tag_is_self_closing(bytes, gt_end) {
                    continue;
                }
                // Implied end tags: `<li>` after an open `<li>` closes it, and
                // so does `<td>` after an open `<td>` — unless a barrier
                // (`<ul>`, `<table>`, …) says the new one is genuinely nested.
                if let Some((_, closes, barriers)) = IMPLIED_END_TAGS
                    .iter()
                    .find(|(start, _, _)| *start == name.as_str())
                    && let Some(idx) = open.nearest(closes, barriers)
                {
                    open.truncate_including(idx);
                }
                open.push(name);
                if open.len() > limit {
                    return Some(tag_start);
                }
            }
        }
    }
    None
}

/// `html`, truncated just before the point where its element nesting would
/// exceed [`MAX_HTML_NESTING_DEPTH`]. Borrows unchanged in the overwhelmingly
/// common case that the document is within the bound.
pub fn bound_html_nesting(html: &str) -> Cow<'_, str> {
    match nesting_overflow_offset(html, MAX_HTML_NESTING_DEPTH) {
        Some(cut) => {
            crate::dbg_log!(
                "html nesting exceeds {} levels at byte {}; parsing the prefix only",
                MAX_HTML_NESTING_DEPTH,
                cut
            );
            Cow::Borrowed(&html[..cut])
        }
        None => Cow::Borrowed(html),
    }
}

/// `scraper::Html::parse_document` with the nesting guard applied. Use this
/// anywhere the input is (or could be) a response body.
pub fn parse_document_bounded(html: &str) -> scraper::Html {
    scraper::Html::parse_document(&bound_html_nesting(html))
}

#[cfg(test)]
mod tests;
