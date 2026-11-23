/*!
Where each byte of a response sits, as an HTML tokenizer reads it.

The reflection gates used to answer "is this echo in text or inside a tag?" by
walking *backwards* from the echo to the nearest `<` or `>`. That cannot tell
`<p>a > ECHO</p>` from `<img title='a > ECHO'>`, so the gates had to refuse
every payload that carries a quote. [`Segments`] walks the document forwards
instead, following the WHATWG tokenizer states that decide where markup starts
and ends, and reports the stretches that are **not** markup structure:

* [`SegmentKind::Text`] — character data between tags,
* [`SegmentKind::RawText`] — the content of `<script>`, `<style>`,
  `<textarea>`, `<title>` and the other raw-text elements,
* [`SegmentKind::AttrValue`] — one attribute value of a start tag, without its
  quotes,
* [`SegmentKind::Comment`] — the text of a `<!-- … -->` comment.

Anything outside a segment is structure: a tag name, an attribute name, the
space between attributes, a doctype, a bogus comment. A caller asking "is this echo
inert?" treats a byte outside every segment as live.

The tokenizer only needs the tree builder for two decisions: which start tags
switch it into a raw-text state, and whether it is inside foreign (SVG/MathML)
content, where those switches do not happen. Both are modelled here with one
rule: when the model cannot be sure, it stops and reports the rest of the
document as [`SegmentKind::Unparsed`]. It must never claim "text" for bytes a
browser would read as markup; the reverse only costs a suppression.
*/

use std::collections::VecDeque;

use super::{FOREIGN_BREAKOUT_TAGS, comment_extent, skip_to_first_gt};

/// One stretch of the document that is not markup structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment<'a> {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: SegmentKind<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SegmentKind<'a> {
    /// Character data between tags.
    Text,
    /// Content of a raw-text element in HTML content. `element` is the tag
    /// name as written, `open_tag` the whole start tag. `closed` is false when
    /// the document ended before the element's end tag (`<plaintext>` has no
    /// end tag and counts as closed).
    RawText {
        element: &'a str,
        open_tag: &'a str,
        closed: bool,
    },
    /// The value of one attribute of a start tag, quotes excluded. `element`
    /// and `name` are as written in the document.
    AttrValue { element: &'a str, name: &'a str },
    /// The text of a `<!-- … -->` comment, delimiters excluded.
    Comment,
    /// From here to the end of the document the model gives no answer.
    Unparsed,
}

/// Elements whose start tag switches the tokenizer out of the data state.
/// (`noscript` does because scripting is enabled in a browser.)
const RAW_TEXT_ELEMENTS: &[&str] = &[
    "script",
    "style",
    "textarea",
    "title",
    "xmp",
    "iframe",
    "noembed",
    "noframes",
    "noscript",
    "plaintext",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForeignRoot {
    Svg,
    Math,
}

impl ForeignRoot {
    fn name(self) -> &'static str {
        match self {
            ForeignRoot::Svg => "svg",
            ForeignRoot::Math => "math",
        }
    }

    /// Elements of this namespace whose children are parsed as HTML again.
    fn integration_points(self) -> &'static [&'static str] {
        match self {
            ForeignRoot::Svg => &["foreignobject", "desc", "title"],
            ForeignRoot::Math => &["mi", "mo", "mn", "ms", "mtext"],
        }
    }
}

/// What the insertion point is nested in, innermost last. Empty means plain
/// HTML content.
#[derive(Debug)]
enum Frame {
    /// Inside `<svg>` / `<math>`. `depth` counts same-named roots nested
    /// directly in this foreign content, so each `</svg>` closes one.
    Foreign { root: ForeignRoot, depth: usize },
    /// Inside an integration point of the frame below: HTML content again.
    Html { element: &'static str },
}

fn is_tag_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// A byte that ends a tag name (and, in the raw-text states, decides whether
/// `</name` is the element's end tag).
fn ends_tag_name(b: u8) -> bool {
    is_tag_space(b) || b == b'/' || b == b'>'
}

fn name_in(name: &str, list: &[&str]) -> bool {
    list.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// Whether the `<` at `lt` starts markup. In the data state a `<` followed by
/// anything but a letter, `!`, `?` or `/` is an ordinary character.
fn starts_markup(bytes: &[u8], lt: usize) -> bool {
    match bytes.get(lt + 1) {
        Some(b) if b.is_ascii_alphabetic() => true,
        Some(b'!' | b'?') => true,
        // `</` at the very end of input is text; anything else after it is an
        // end tag, the empty `</>` or a bogus comment.
        Some(b'/') => bytes.get(lt + 2).is_some(),
        _ => false,
    }
}

struct ScannedTag {
    /// Offset just past the tag's `>`.
    end: usize,
    self_closing: bool,
}

/// Tokenize the attributes of the tag whose name ends at `from`, calling
/// `on_value(name, value_start, value_end)` for every attribute that has a
/// value. `None` when the input ends inside the tag: the tokenizer then emits
/// no tag at all.
fn scan_tag<'a>(
    html: &'a str,
    from: usize,
    mut on_value: impl FnMut(&'a str, usize, usize),
) -> Option<ScannedTag> {
    let bytes = html.as_bytes();
    let mut i = from;
    loop {
        // Before attribute name.
        while i < bytes.len() && is_tag_space(bytes[i]) {
            i += 1;
        }
        match *bytes.get(i)? {
            b'>' => {
                return Some(ScannedTag {
                    end: i + 1,
                    self_closing: false,
                });
            }
            b'/' => {
                if bytes.get(i + 1) == Some(&b'>') {
                    return Some(ScannedTag {
                        end: i + 2,
                        self_closing: true,
                    });
                }
                i += 1;
                continue;
            }
            _ => {}
        }
        // Attribute name. A leading `=` is part of the name.
        let name_start = i;
        i += 1;
        while i < bytes.len() && !ends_tag_name(bytes[i]) && bytes[i] != b'=' {
            i += 1;
        }
        let name = &html[name_start..i];
        // After attribute name.
        while i < bytes.len() && is_tag_space(bytes[i]) {
            i += 1;
        }
        if *bytes.get(i)? != b'=' {
            // No value. The byte is re-read as the start of the next attribute
            // (or as `/` / `>`).
            continue;
        }
        // Before attribute value.
        i += 1;
        while i < bytes.len() && is_tag_space(bytes[i]) {
            i += 1;
        }
        match *bytes.get(i)? {
            quote @ (b'"' | b'\'') => {
                let value_start = i + 1;
                let len = bytes[value_start..].iter().position(|&b| b == quote)?;
                on_value(name, value_start, value_start + len);
                i = value_start + len + 1;
            }
            // `<a href=>`: the value is missing and the tag ends here.
            b'>' => {
                return Some(ScannedTag {
                    end: i + 1,
                    self_closing: false,
                });
            }
            _ => {
                let value_start = i;
                while i < bytes.len() && !is_tag_space(bytes[i]) && bytes[i] != b'>' {
                    i += 1;
                }
                bytes.get(i)?;
                on_value(name, value_start, i);
            }
        }
    }
}

/// Offset of the `</name` that ends an RCDATA / RAWTEXT element whose content
/// starts at `from`.
fn raw_text_end(bytes: &[u8], from: usize, name: &str) -> Option<usize> {
    let name = name.as_bytes();
    let mut i = from;
    while let Some(rel) = bytes[i.min(bytes.len())..].iter().position(|&b| b == b'<') {
        let lt = i + rel;
        let after = lt + 2 + name.len();
        if bytes.get(lt + 1) == Some(&b'/')
            && bytes
                .get(lt + 2..after)
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
            && bytes.get(after).is_some_and(|&b| ends_tag_name(b))
        {
            return Some(lt);
        }
        i = lt + 1;
    }
    None
}

/// Offset of the `</script` that ends a script element whose content starts at
/// `from`, following the script-data escape states: after `<!--`, a nested
/// `<script` makes the next `</script` part of the text instead of the end.
fn script_data_end(bytes: &[u8], from: usize) -> Option<usize> {
    #[derive(PartialEq)]
    enum State {
        Data,
        Escaped,
        DoubleEscaped,
    }
    let is_script_at = |at: usize| {
        bytes
            .get(at..at + 6)
            .is_some_and(|n| n.eq_ignore_ascii_case(b"script"))
            && bytes.get(at + 6).is_some_and(|&b| ends_tag_name(b))
    };
    let mut state = State::Data;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'<' if bytes.get(i + 1) == Some(&b'/') && is_script_at(i + 2) => {
                if state == State::DoubleEscaped {
                    state = State::Escaped;
                    i += 8;
                } else {
                    return Some(i);
                }
            }
            b'<' if state == State::Data && bytes[i + 1..].starts_with(b"!--") => {
                state = State::Escaped;
                // Leave the two dashes unread: `<!-->` and `<!--->` end the
                // escape at once.
                i += 2;
            }
            b'<' if state == State::Escaped && is_script_at(i + 1) => {
                state = State::DoubleEscaped;
                i += 7;
            }
            b'-' if state != State::Data && bytes[i..].starts_with(b"-->") => {
                state = State::Data;
                i += 3;
            }
            _ => i += 1,
        }
    }
    None
}

/// Iterator over the [`Segment`]s of a document, in document order.
pub(crate) struct Segments<'a> {
    html: &'a str,
    pos: usize,
    queue: VecDeque<Segment<'a>>,
    frames: Vec<Frame>,
    /// Between `<select>` and `</select>` in HTML content.
    in_select: bool,
    finished: bool,
}

/// Segment `html`. Linear in the document length.
pub(crate) fn segments(html: &str) -> Segments<'_> {
    Segments {
        html,
        pos: 0,
        queue: VecDeque::new(),
        frames: Vec::new(),
        in_select: false,
        finished: false,
    }
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Segment<'a>> {
        loop {
            if let Some(segment) = self.queue.pop_front() {
                return Some(segment);
            }
            if self.finished {
                return None;
            }
            self.advance();
        }
    }
}

impl<'a> Segments<'a> {
    fn push(&mut self, start: usize, end: usize, kind: SegmentKind<'a>) {
        self.queue.push_back(Segment { start, end, kind });
    }

    /// Give up from `at` on.
    fn stop_at(&mut self, at: usize) {
        let end = self.html.len();
        self.push(at, end, SegmentKind::Unparsed);
        self.pos = end;
        self.finished = true;
    }

    fn foreign_root(&self) -> Option<ForeignRoot> {
        match self.frames.last() {
            Some(Frame::Foreign { root, .. }) => Some(*root),
            _ => None,
        }
    }

    fn leave_foreign_content(&mut self) {
        while matches!(self.frames.last(), Some(Frame::Foreign { .. })) {
            self.frames.pop();
        }
    }

    /// Emit the text up to the next piece of markup, then consume that markup.
    fn advance(&mut self) {
        let bytes = self.html.as_bytes();
        let text_start = self.pos;
        let mut from = self.pos;
        let lt = loop {
            match bytes[from..].iter().position(|&b| b == b'<') {
                None => break bytes.len(),
                Some(rel) if starts_markup(bytes, from + rel) => break from + rel,
                Some(rel) => from += rel + 1,
            }
        };
        if lt > text_start {
            self.push(text_start, lt, SegmentKind::Text);
        }
        if lt >= bytes.len() {
            self.pos = bytes.len();
            self.finished = true;
            return;
        }
        match bytes[lt + 1] {
            b'!' if bytes[lt + 2..].starts_with(b"--") => {
                let text_start = lt + 4;
                // `<!-->` and `<!--->` close on the opening dashes and hold no
                // text; a comment the input ends inside runs to the end.
                let (text_end, end) = comment_extent(bytes, text_start);
                if text_end > text_start {
                    self.push(text_start, text_end, SegmentKind::Comment);
                }
                self.pos = end;
            }
            // A real CDATA section exists only in foreign content, and what it
            // holds there is text the model has not followed.
            b'!' if bytes[lt + 2..].starts_with(b"[CDATA[") && !self.frames.is_empty() => {
                self.stop_at(lt);
            }
            // Doctype or bogus comment: ends at the first `>`.
            b'!' | b'?' => self.pos = skip_to_first_gt(bytes, lt + 1),
            b'/' => self.end_tag(lt),
            _ => self.start_tag(lt),
        }
    }

    fn end_tag(&mut self, lt: usize) {
        let bytes = self.html.as_bytes();
        let name_start = lt + 2;
        if bytes[name_start] == b'>' {
            // `</>` is dropped.
            self.pos = name_start + 1;
            return;
        }
        if !bytes[name_start].is_ascii_alphabetic() {
            self.pos = skip_to_first_gt(bytes, name_start);
            return;
        }
        let mut name_end = name_start;
        while name_end < bytes.len() && !ends_tag_name(bytes[name_end]) {
            name_end += 1;
        }
        let name = &self.html[name_start..name_end];
        let Some(tag) = scan_tag(self.html, name_end, |_, _, _| {}) else {
            self.pos = bytes.len();
            self.finished = true;
            return;
        };
        self.pos = tag.end;
        if name.eq_ignore_ascii_case("select") {
            self.in_select = false;
        }
        enum Action {
            Keep,
            LeaveForeign,
            CloseRoot,
            CloseIntegrationPoint,
            Stop,
        }
        let action = match self.frames.last() {
            // These two end tags are handled as HTML and close the foreign
            // content.
            Some(Frame::Foreign { .. }) if name_in(name, &["p", "br"]) => Action::LeaveForeign,
            Some(Frame::Foreign { root, .. }) if name.eq_ignore_ascii_case(root.name()) => {
                Action::CloseRoot
            }
            // Any other end tag may close an HTML ancestor and the foreign
            // root with it. Staying "foreign" then is the safe side.
            Some(Frame::Foreign { .. }) => Action::Keep,
            Some(Frame::Html { element }) if name.eq_ignore_ascii_case(element) => {
                Action::CloseIntegrationPoint
            }
            // Whether this closes the enclosing root depends on which HTML
            // elements are open inside the integration point.
            Some(Frame::Html { .. }) if name_in(name, &["svg", "math"]) => Action::Stop,
            _ => Action::Keep,
        };
        match action {
            Action::Keep => {}
            Action::LeaveForeign => self.leave_foreign_content(),
            Action::CloseRoot => {
                if let Some(Frame::Foreign { depth, .. }) = self.frames.last_mut() {
                    *depth -= 1;
                    if *depth == 0 {
                        self.frames.pop();
                    }
                }
            }
            Action::CloseIntegrationPoint => {
                self.frames.pop();
            }
            Action::Stop => self.stop_at(lt),
        }
    }

    fn start_tag(&mut self, lt: usize) {
        let bytes = self.html.as_bytes();
        let name_start = lt + 1;
        let mut name_end = name_start;
        while name_end < bytes.len() && !ends_tag_name(bytes[name_end]) {
            name_end += 1;
        }
        let html = self.html;
        let name = &html[name_start..name_end];
        let queued = self.queue.len();
        let queue = &mut self.queue;
        let Some(tag) = scan_tag(html, name_end, |attr, start, end| {
            queue.push_back(Segment {
                start,
                end,
                kind: SegmentKind::AttrValue {
                    element: name,
                    name: attr,
                },
            });
        }) else {
            // The input ended inside the tag, so the tag never existed.
            self.queue.truncate(queued);
            self.pos = bytes.len();
            self.finished = true;
            return;
        };
        self.pos = tag.end;

        if let Some(root) = self.foreign_root() {
            if name_in(name, FOREIGN_BREAKOUT_TAGS) {
                if name.eq_ignore_ascii_case("font") {
                    // Breaks out only with a color/face/size attribute.
                    self.queue.truncate(queued);
                    self.stop_at(lt);
                    return;
                }
                self.leave_foreign_content();
            } else {
                if name.eq_ignore_ascii_case(root.name()) {
                    if !tag.self_closing
                        && let Some(Frame::Foreign { depth, .. }) = self.frames.last_mut()
                    {
                        *depth += 1;
                    }
                } else if let Some(element) = root
                    .integration_points()
                    .iter()
                    .find(|p| name.eq_ignore_ascii_case(p))
                {
                    if !tag.self_closing {
                        self.frames.push(Frame::Html { element });
                    }
                } else if name_in(name, &["script", "style", "annotation-xml"]) {
                    // A foreign `<script>` runs its text and a foreign
                    // `<style>` is CSS, but neither is a raw-text element, and
                    // `annotation-xml` is an integration point only for some
                    // `encoding` values.
                    self.queue.truncate(queued);
                    self.stop_at(lt);
                }
                return;
            }
        }

        // HTML content.
        let foreign_root = if name.eq_ignore_ascii_case("svg") {
            Some(ForeignRoot::Svg)
        } else if name.eq_ignore_ascii_case("math") {
            Some(ForeignRoot::Math)
        } else {
            None
        };
        if let Some(root) = foreign_root {
            if !tag.self_closing {
                self.frames.push(Frame::Foreign { root, depth: 1 });
            }
            return;
        }
        if name.eq_ignore_ascii_case("select") {
            self.in_select = true;
            return;
        }
        if name.eq_ignore_ascii_case("frameset") {
            // In a frameset document the tree builder ignores the start tags
            // that would switch the tokenizer to raw text.
            self.queue.truncate(queued);
            self.stop_at(lt);
            return;
        }
        if !name_in(name, RAW_TEXT_ELEMENTS) {
            return;
        }
        if self.in_select && !name_in(name, &["script", "textarea"]) {
            // Inside `<select>` a parser may drop this start tag and keep
            // reading its content as markup.
            self.queue.truncate(queued);
            self.stop_at(lt);
            return;
        }
        let content_start = tag.end;
        let plaintext = name.eq_ignore_ascii_case("plaintext");
        let content_end = if plaintext {
            // Never ends: there is no end tag in the PLAINTEXT state.
            None
        } else if name.eq_ignore_ascii_case("script") {
            script_data_end(bytes, content_start)
        } else {
            raw_text_end(bytes, content_start, name)
        };
        let end = content_end.unwrap_or(bytes.len());
        self.push(
            content_start,
            end,
            SegmentKind::RawText {
                element: name,
                open_tag: &html[lt..tag.end],
                closed: plaintext || content_end.is_some(),
            },
        );
        self.pos = end;
    }
}

#[cfg(test)]
mod tests;
