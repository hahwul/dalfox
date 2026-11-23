use super::*;

fn texts(html: &str) -> Vec<&str> {
    segments(html)
        .filter(|s| s.kind == SegmentKind::Text)
        .map(|s| &html[s.start..s.end])
        .collect()
}

fn attrs(html: &str) -> Vec<(&str, &str, &str)> {
    segments(html)
        .filter_map(|s| match s.kind {
            SegmentKind::AttrValue { element, name } => {
                Some((element, name, &html[s.start..s.end]))
            }
            _ => None,
        })
        .collect()
}

fn raw_texts(html: &str) -> Vec<(&str, &str, bool)> {
    segments(html)
        .filter_map(|s| match s.kind {
            SegmentKind::RawText {
                element, closed, ..
            } => Some((element, &html[s.start..s.end], closed)),
            _ => None,
        })
        .collect()
}

fn unparsed_from(html: &str) -> Option<usize> {
    segments(html)
        .find(|s| s.kind == SegmentKind::Unparsed)
        .map(|s| s.start)
}

#[test]
fn text_between_tags_is_text() {
    assert_eq!(texts("a<b>c</b>d"), ["a", "c", "d"]);
    assert_eq!(texts("<div>x</div>"), ["x"]);
    assert!(texts("").is_empty());
}

#[test]
fn a_lone_less_than_is_text() {
    assert_eq!(texts("a < b"), ["a < b"]);
    assert_eq!(texts("1<2 and 3<4"), ["1<2 and 3<4"]);
    assert_eq!(texts("tail <"), ["tail <"]);
    assert_eq!(texts("tail </"), ["tail </"]);
}

#[test]
fn a_gt_inside_a_quoted_value_does_not_end_the_tag() {
    // The case a backward walk gets wrong: everything after `a > ` is still
    // the attribute value.
    let html = "<img title='a > PAYLOAD'>";
    assert!(texts(html).is_empty());
    assert_eq!(attrs(html), [("img", "title", "a > PAYLOAD")]);
    let html = r#"<p>a > PAYLOAD</p>"#;
    assert_eq!(texts(html), ["a > PAYLOAD"]);
}

#[test]
fn attribute_value_forms() {
    assert_eq!(attrs(r#"<a href="x y">"#), [("a", "href", "x y")]);
    assert_eq!(attrs("<a href='x\"y'>"), [("a", "href", "x\"y")]);
    assert_eq!(attrs("<a href=x/y>"), [("a", "href", "x/y")]);
    assert_eq!(attrs("<a href = x>"), [("a", "href", "x")]);
    assert_eq!(
        attrs(r#"<a b="1"c='2' d=3>"#),
        [("a", "b", "1"), ("a", "c", "2"), ("a", "d", "3")]
    );
    // No value: nothing to report, and the tag still ends.
    assert!(attrs("<input disabled><a href=>").is_empty());
    assert_eq!(texts("<input disabled>x<a href=>y"), ["x", "y"]);
}

#[test]
fn an_unquoted_value_ends_at_whitespace() {
    // The payload's second word is an attribute name, not part of the value.
    let html = "<input value=x onfocus=alert(1)>";
    assert_eq!(
        attrs(html),
        [("input", "value", "x"), ("input", "onfocus", "alert(1)")]
    );
}

#[test]
fn a_quote_opens_a_value_only_after_an_equals_sign() {
    // `"` in an attribute-name position is part of a name.
    assert_eq!(texts(r#"<div x">text</div>"#), ["text"]);
    assert_eq!(attrs(r#"<div x" y=1>"#), [("div", "y", "1")]);
}

#[test]
fn a_tag_the_input_ends_inside_does_not_exist() {
    assert_eq!(texts("a<div title=\"x"), ["a"]);
    assert!(attrs("a<div title=\"x").is_empty());
    assert_eq!(texts("a<div"), ["a"]);
    assert!(attrs("<a b=1 c=").is_empty());
}

#[test]
fn comments_and_declarations_are_not_text() {
    assert_eq!(texts("a<!-- <b>x</b> -->b"), ["a", "b"]);
    assert_eq!(texts("a<!-->b"), ["a", "b"]);
    assert_eq!(texts("a<!--->b"), ["a", "b"]);
    assert_eq!(texts("a<!-- x --!>b"), ["a", "b"]);
    assert_eq!(texts("<!DOCTYPE html>a"), ["a"]);
    assert_eq!(texts("a<?php x ?>b"), ["a", "b"]);
    assert_eq!(texts("a</ x>b"), ["a", "b"]);
    assert_eq!(texts("a</>b"), ["a", "b"]);
    assert_eq!(texts("a<!-- never closed <p>x"), ["a"]);
}

fn comments(html: &str) -> Vec<&str> {
    segments(html)
        .filter(|s| s.kind == SegmentKind::Comment)
        .map(|s| &html[s.start..s.end])
        .collect()
}

#[test]
fn comment_text_excludes_its_delimiters() {
    assert_eq!(comments("a<!-- x <b> y -->c"), [" x <b> y "]);
    assert_eq!(comments("<!--x--!>y"), ["x"]);
    assert_eq!(comments("<!--x-->y<!--z-->"), ["x", "z"]);
    // The first `-->` ends it; the rest is text.
    assert_eq!(comments("<!--x-->y-->"), ["x"]);
    assert_eq!(texts("<!--x-->y-->"), ["y-->"]);
    // Empty forms hold nothing.
    assert!(comments("<!-->a<!--->b<!---->c").is_empty());
    assert_eq!(texts("<!-->a<!--->b<!---->c"), ["a", "b", "c"]);
    // Never closed: the comment runs to the end of input.
    assert_eq!(comments("a<!-- x <p>y"), [" x <p>y"]);
    // Bogus comments and doctypes are structure, not comment text.
    assert!(comments("<!x><?y></ z><!DOCTYPE html>").is_empty());
    // Inside raw text `<!--` is not a comment.
    assert!(comments("<textarea><!-- x --></textarea>").is_empty());
}

#[test]
fn raw_text_elements_hold_their_markup_as_text() {
    assert_eq!(
        raw_texts("<textarea><b>x</b></textarea>y"),
        [("textarea", "<b>x</b>", true)]
    );
    assert_eq!(texts("<textarea><b>x</b></textarea>y"), ["y"]);
    assert_eq!(raw_texts("<TITLE>a</tItLe >b"), [("TITLE", "a", true)]);
    assert_eq!(
        raw_texts("<style>a</styleX></style>"),
        [("style", "a</styleX>", true)]
    );
    assert_eq!(
        raw_texts("<xmp>never closed"),
        [("xmp", "never closed", false)]
    );
    assert_eq!(
        raw_texts("<plaintext></plaintext><b>"),
        [("plaintext", "</plaintext><b>", true)]
    );
}

#[test]
fn raw_text_reports_its_start_tag() {
    let html = r#"<script type="application/json">{}</script>"#;
    let open_tags: Vec<&str> = segments(html)
        .filter_map(|s| match s.kind {
            SegmentKind::RawText { open_tag, .. } => Some(open_tag),
            _ => None,
        })
        .collect();
    assert_eq!(open_tags, [r#"<script type="application/json">"#]);
    assert_eq!(attrs(html), [("script", "type", "application/json")]);
}

#[test]
fn script_content_follows_the_escape_states() {
    assert_eq!(
        raw_texts("<script>var a = '<b>';</script>x"),
        [("script", "var a = '<b>';", true)]
    );
    // `<!--` then `<script`: the first `</script>` is part of the text.
    assert_eq!(
        raw_texts("<script><!--<script>a</script>b</script>c"),
        [("script", "<!--<script>a</script>b", true)]
    );
    // `-->` leaves the escape, so the next `</script>` ends the element.
    assert_eq!(
        raw_texts("<script><!--<script>a-->b</script>c</script>"),
        [("script", "<!--<script>a-->b", true)]
    );
    // An escape with no nested `<script` changes nothing.
    assert_eq!(
        raw_texts("<script><!-- a </script>b"),
        [("script", "<!-- a ", true)]
    );
    assert_eq!(
        raw_texts("<script><!--><script>a</script>b"),
        [("script", "<!--><script>a", true)]
    );
    assert_eq!(
        raw_texts("<script>a</scriptx>b"),
        [("script", "a</scriptx>b", false)]
    );
}

#[test]
fn foreign_content_has_no_raw_text_elements() {
    // In SVG `<title>` is an ordinary element (an HTML integration point), so
    // markup inside it is markup.
    let html = "<svg><title><img src=x onerror=alert(1)></title></svg>";
    assert!(raw_texts(html).is_empty());
    assert_eq!(
        attrs(html),
        [("img", "src", "x"), ("img", "onerror", "alert(1)")]
    );
    // After `</svg>` it is a raw-text element again.
    let html = "<svg><g><path d='M0'/></g></svg><title><img></title>";
    assert_eq!(raw_texts(html), [("title", "<img>", true)]);
    assert_eq!(unparsed_from(html), None);
    // A self-closing root opens nothing.
    assert_eq!(raw_texts("<svg/><title>a</title>"), [("title", "a", true)]);
    // HTML inside an integration point has raw-text elements.
    assert_eq!(
        raw_texts("<svg><foreignObject><textarea><b></textarea></foreignObject></svg>"),
        [("textarea", "<b>", true)]
    );
    // A breakout tag closes the foreign content.
    assert_eq!(
        raw_texts("<svg><div><textarea><b></textarea>"),
        [("textarea", "<b>", true)]
    );
    assert_eq!(
        raw_texts("<math><mi>x</mi><mo><title>a</title></mo></math>"),
        [("title", "a", true)]
    );
    // `mi` is an integration point in MathML only, and `title` in SVG only.
    assert!(raw_texts("<svg><mi><textarea><b></textarea>").is_empty());
    assert!(raw_texts("<math><title><textarea><b></textarea>").is_empty());
}

#[test]
fn well_formed_foreign_content_is_followed_to_its_end() {
    let html = "<svg><g><svg><title>t</title><path d='M0'></svg><circle/></g></svg>\
                <textarea><i></textarea>";
    assert_eq!(unparsed_from(html), None);
    assert_eq!(raw_texts(html), [("textarea", "<i>", true)]);
    // An end tag closes through the foreign elements above the one it names.
    let html = "<svg><g><path><rect></g></svg><xmp><i></xmp>";
    assert_eq!(unparsed_from(html), None);
    assert_eq!(raw_texts(html), [("xmp", "<i>", true)]);
    // `</p>` and `</br>` leave foreign content, like a breakout start tag.
    assert_eq!(
        raw_texts("<svg><g></p><xmp><i></xmp>"),
        [("xmp", "<i>", true)]
    );
    // Void and raw-text elements do not stay open inside an integration point.
    let html = "<svg><desc>a<br><img src=x><textarea>t</textarea></desc></svg><xmp>x</xmp>";
    assert_eq!(unparsed_from(html), None);
    assert_eq!(
        raw_texts(html),
        [("textarea", "t", true), ("xmp", "x", true)]
    );
}

/// Where following the namespace would take the stack of open elements, the
/// model stops instead of guessing. Each document is paired with the offset
/// it stops at; the comments say what a browser does with it.
#[test]
fn the_model_stops_where_it_cannot_follow_the_tree_builder() {
    for (html, at) in [
        // A foreign `<script>` runs its text; a foreign `<style>` is CSS.
        ("a<svg><script>alert(1)</script></svg>", 6),
        ("<svg><style>x</style>", 5),
        ("<svg><![CDATA[<b>]]></svg>", 5),
        ("<svg><font color=red><title>", 5),
        ("<math><annotation-xml encoding='text/html'><title>", 6),
        // `</div>` closes the `<div>` and the `<svg>` in it. The `<title>`
        // after it is then MathML, not an SVG integration point.
        ("<div><svg></div><math><title><title><img></title>", 10),
        // `</g>` closes `<title>` and `<g>`, so the next `<title>` is another
        // integration point holding real markup.
        ("<svg><g><title></g><title><img></title>", 15),
        ("<svg><foreignObject><div></svg><title>", 25),
        // With `<div>` open, `</foreignObject>` is ignored: still HTML.
        (
            "<svg><foreignObject><div></foreignObject><title><textarea></title><img>",
            25,
        ),
        // The inner `<title>` is a raw-text element; a `<b>` would stay open.
        ("<svg><title><b></title><title><img></title>", 15),
        // `mglyph` in a text integration point is MathML again.
        ("<math><mtext><mglyph><title><img></title>", 13),
        ("<math><mi><malignmark><title><img></title>", 10),
        // Table structure is not stopped by an integration point.
        ("<table><td><svg><title></td><title><img></title>", 23),
        ("<table><td><svg><desc><col><title><img></title>", 22),
        // `</foreignObject>` closes `<mi>`, `<math>` and itself: SVG again.
        (
            "<svg><foreignObject><math><mi></foreignObject><title><img></title>",
            30,
        ),
        ("<template><svg><title></template><title><img></title>", 22),
        // The tree builder drops these start tags instead of acting on them.
        ("<select><xmp><img></xmp></select>", 8),
        ("<frameset><textarea>", 0),
        ("<template><col><title></template><img>", 10),
    ] {
        assert_eq!(unparsed_from(html), Some(at), "{html}");
    }
    // Not in the way otherwise.
    for html in [
        "<svg><path d=''/></svg><script>1</script>",
        "<select><option>a</select><xmp>b</xmp>",
        "<p><![CDATA[x]]></p>",
        "<template><p>a</p></template><title>t</title>",
        "<table><colgroup><col></colgroup><tr><td><textarea>x</textarea>",
    ] {
        assert_eq!(unparsed_from(html), None, "{html}");
    }
}

#[test]
fn a_raw_text_end_tag_is_not_matched_against_the_frames() {
    // The inner `</title>` belongs to the HTML `<title>` inside the SVG one.
    let html = "<svg><title><title>a</title>b</title></svg><xmp>c</xmp>";
    assert_eq!(unparsed_from(html), None);
    assert_eq!(raw_texts(html), [("title", "a", true), ("xmp", "c", true)]);
    assert_eq!(texts(html), ["b"]);
}

#[test]
fn deeply_nested_foreign_content_stops_instead_of_growing() {
    let html = format!("<svg>{}<title>t</title>", "<g>".repeat(5000));
    assert!(unparsed_from(&html).is_some());
}

#[test]
fn segments_come_in_document_order_and_never_overlap() {
    let html = r#"<a href="/x?q=1" title='t'>text</a><script>s</script><!-- c --><p class=k>z"#;
    let mut last_end = 0;
    for s in segments(html) {
        assert!(s.start >= last_end, "{s:?} starts before {last_end}");
        assert!(s.end >= s.start);
        last_end = s.end;
    }
    assert_eq!(last_end, html.len());
}

#[test]
fn multibyte_text_keeps_char_boundaries() {
    let html = "<p title=\"한글 ＜\">日本語<b>＞</b>";
    assert_eq!(attrs(html), [("p", "title", "한글 ＜")]);
    assert_eq!(texts(html), ["日本語", "＞"]);
}

// ---- property test against html5ever's tree builder -----------------------

/// The differential test below drives html5ever's *tokenizer* and switches its
/// raw-text states by tag name, so it cannot see the decisions that need the
/// tree builder: foreign content, integration points, `select`, `template`,
/// tables. This one parses whole documents with `scraper` and checks the one
/// property the segmenter's caller relies on: bytes that became an element
/// are never reported as data.
mod tree_builder {
    use super::super::{SegmentKind, segments};

    const PROBE: &str = "<img data-probe=x>";

    /// Ways to end a document with the probe. In plain HTML content the first
    /// four hold it as text; whether they do depends on everything before.
    const ENDINGS: &[(&str, &str)] = &[
        ("<title>", "</title>"),
        ("<textarea>", "</textarea>"),
        ("<xmp>", "</xmp>"),
        ("<noscript>", "</noscript>"),
        ("<!--", "-->"),
        ("", ""),
        // The probe ends up inside a raw-text element the prefix opened only
        // if the prefix's own `<textarea>` / `<xmp>` was a start tag.
        ("", "</textarea>"),
        ("", "</xmp>"),
    ];

    const NAMES: &[&str] = &[
        "svg",
        "math",
        "foreignObject",
        "desc",
        "title",
        "mi",
        "mo",
        "mtext",
        "mglyph",
        "malignmark",
        "annotation-xml",
        "g",
        "a",
        "path",
        "div",
        "p",
        "span",
        "b",
        "table",
        "tbody",
        "tr",
        "td",
        "th",
        "caption",
        "colgroup",
        "col",
        "select",
        "option",
        "optgroup",
        "template",
        "button",
        "object",
        "applet",
        "marquee",
        "form",
        "font",
        "textarea",
        "xmp",
        "noscript",
        "style",
        "script",
        "iframe",
        "frameset",
        "body",
        "head",
        "br",
        "img",
        "li",
        "ul",
        "input",
        "nobr",
        "h1",
    ];

    const EXTRA: &[&str] = &[
        "<svg/>",
        "<path/>",
        "<g/>",
        "<title/>",
        "<foreignObject/>",
        "<mi/>",
        "<desc/>",
        "<font color=red>",
        "<annotation-xml encoding=\"text/html\">",
        "<![CDATA[",
        "]]>",
        "<!--",
        "-->",
        "x",
        " ",
        "<svg><title>",
        "<math><mtext>",
        "</svg></svg>",
    ];

    fn probe_became_an_element(html: &str) -> bool {
        let selector = scraper::Selector::parse("img[data-probe]").expect("selector");
        scraper::Html::parse_document(html)
            .select(&selector)
            .next()
            .is_some()
    }

    /// Whether the segmenter reports the probe at `at` as data: wholly inside
    /// a segment, anything but the "no answer" one.
    fn probe_reported_as_data(html: &str, at: usize) -> bool {
        segments(html)
            .any(|s| s.kind != SegmentKind::Unparsed && s.start <= at && at + PROBE.len() <= s.end)
    }

    fn violates(prefix: &str, ending: (&str, &str)) -> Option<String> {
        let html = format!("{prefix}{}{PROBE}{}", ending.0, ending.1);
        let at = prefix.len() + ending.0.len();
        (probe_reported_as_data(&html, at) && probe_became_an_element(&html)).then_some(html)
    }

    struct XorShift(u64);

    impl XorShift {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    #[test]
    fn an_element_is_never_reported_as_data() {
        let mut atoms: Vec<String> = EXTRA.iter().map(|a| a.to_string()).collect();
        for name in NAMES {
            atoms.push(format!("<{name}>"));
            atoms.push(format!("</{name}>"));
        }
        let mut rng = XorShift(0x0123_4567_89AB_CDEF);
        let mut reported_as_data = 0u32;
        for _ in 0..40_000 {
            let len = 1 + rng.below(12);
            let prefix: String = (0..len)
                .map(|_| atoms[rng.below(atoms.len())].as_str())
                .collect();
            let ending = ENDINGS[rng.below(ENDINGS.len())];
            if let Some(html) = violates(&prefix, ending) {
                panic!("reported as data, parsed as an element: {html:?}");
            }
            let at = prefix.len() + ending.0.len();
            let html = format!("{prefix}{}{PROBE}{}", ending.0, ending.1);
            reported_as_data += u32::from(probe_reported_as_data(&html, at));
        }
        // The property is vacuous if the model stops on everything.
        assert!(
            reported_as_data > 4_000,
            "only {reported_as_data} documents were followed to the probe"
        );
    }

    #[test]
    fn known_tree_builder_cases() {
        for (prefix, ending) in [
            ("<svg><g><title></g>", ENDINGS[0]),
            ("<div><svg></div><math><title>", ENDINGS[0]),
            (
                "<svg><foreignObject><div></foreignObject><title><textarea></title>",
                ENDINGS[1],
            ),
            ("<math><mtext><mglyph>", ENDINGS[0]),
            ("<template><col><title></template>", ENDINGS[5]),
            ("<table><td><svg><title></td></title><title>", ENDINGS[0]),
            ("<svg><title><title></title></title>", ENDINGS[0]),
            ("<select><xmp>", ENDINGS[5]),
            ("<div><svg></div><math></svg>", ENDINGS[0]),
            // A stale "inside SVG" belief makes the HTML `<title>` an
            // integration point, and the `<textarea>` in it a start tag.
            (
                "<table><td><svg><title></td></title><title><textarea></title>",
                ENDINGS[6],
            ),
            // `col` is void, so only the table-structure rule sees it.
            (
                "<table><td><svg><desc><col></desc><title><textarea></title>",
                ENDINGS[6],
            ),
            // The end tag names an integration point further out.
            ("<svg><foreignObject><math><mi></foreignObject>", ENDINGS[0]),
            (
                "<svg><foreignObject><p></foreignObject><title><xmp></title>",
                ENDINGS[7],
            ),
        ] {
            assert_eq!(violates(prefix, ending), None);
        }
    }
}

// ---- differential test against html5ever's tokenizer ----------------------

mod differential {
    use super::super::{SegmentKind, segments};
    use html5ever::TokenizerResult;
    use html5ever::tendril::StrTendril;
    use html5ever::tokenizer::states::RawKind;
    use html5ever::tokenizer::{
        BufferQueue, CharacterTokens, EndTag, StartTag, TagToken, Token, TokenSink,
        TokenSinkResult, Tokenizer, TokenizerOpts,
    };
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Event {
        Text(String),
        Attr(String, String, String),
        Raw(String, String),
        Comment(String),
    }

    #[derive(Default)]
    struct State {
        events: Vec<Event>,
        /// Element whose raw-text content is being collected.
        raw: Option<(String, String)>,
        saw_duplicate_attributes: bool,
    }

    #[derive(Default)]
    struct Oracle {
        state: RefCell<State>,
    }

    fn push_text(events: &mut Vec<Event>, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Some(Event::Text(last)) = events.last_mut() {
            last.push_str(text);
        } else {
            events.push(Event::Text(text.to_string()));
        }
    }

    impl TokenSink for Oracle {
        type Handle = ();

        fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
            let mut st = self.state.borrow_mut();
            match token {
                CharacterTokens(text) => match st.raw.as_mut() {
                    Some((_, content)) => content.push_str(&text),
                    None => push_text(&mut st.events, &text),
                },
                TagToken(tag) if tag.kind == StartTag => {
                    st.saw_duplicate_attributes |= tag.had_duplicate_attributes;
                    let name = tag.name.to_string();
                    for attr in &tag.attrs {
                        if !attr.value.is_empty() {
                            st.events.push(Event::Attr(
                                name.clone(),
                                attr.name.local.to_string(),
                                attr.value.to_string(),
                            ));
                        }
                    }
                    let kind = match name.as_str() {
                        "script" => RawKind::ScriptData,
                        "textarea" | "title" => RawKind::Rcdata,
                        "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                            RawKind::Rawtext
                        }
                        "plaintext" => {
                            st.raw = Some((name, String::new()));
                            return TokenSinkResult::Plaintext;
                        }
                        _ => return TokenSinkResult::Continue,
                    };
                    st.raw = Some((name, String::new()));
                    return TokenSinkResult::RawData(kind);
                }
                TagToken(tag) if tag.kind == EndTag => {
                    if let Some((name, content)) = st.raw.take() {
                        st.events.push(Event::Raw(name, content));
                    }
                }
                Token::CommentToken(text) if !text.is_empty() => {
                    st.events.push(Event::Comment(text.to_string()));
                }
                _ => {}
            }
            TokenSinkResult::Continue
        }

        fn end(&self) {
            let mut st = self.state.borrow_mut();
            if let Some((name, content)) = st.raw.take() {
                st.events.push(Event::Raw(name, content));
            }
        }
    }

    /// `None` when a tag had duplicate attributes: html5ever keeps the first
    /// and drops the rest, which the segmenter does not model (it reports
    /// every valued attribute, the safe side for its caller).
    fn oracle_events(html: &str) -> Option<Vec<Event>> {
        let tokenizer = Tokenizer::new(Oracle::default(), TokenizerOpts::default());
        let input = BufferQueue::default();
        input.push_back(StrTendril::from(html));
        while let TokenizerResult::Script(()) = tokenizer.feed(&input) {}
        tokenizer.end();
        let state = tokenizer.sink.state.into_inner();
        (!state.saw_duplicate_attributes).then_some(state.events)
    }

    fn segment_events(html: &str) -> Vec<Event> {
        let mut events = Vec::new();
        for s in segments(html) {
            let body = &html[s.start..s.end];
            match s.kind {
                SegmentKind::Text => push_text(&mut events, body),
                SegmentKind::AttrValue { element, name } => {
                    if !body.is_empty() {
                        events.push(Event::Attr(
                            element.to_ascii_lowercase(),
                            name.to_ascii_lowercase(),
                            body.to_string(),
                        ));
                    }
                }
                SegmentKind::RawText { element, .. } => {
                    events.push(Event::Raw(element.to_ascii_lowercase(), body.to_string()));
                }
                SegmentKind::Comment => events.push(Event::Comment(body.to_string())),
                SegmentKind::Unparsed => panic!("unexpected stop in {html:?}"),
            }
        }
        events
    }

    /// Building blocks chosen to hit the tokenizer states the segmenter
    /// models: tag open, attribute name/value in each quoting, comments,
    /// bogus comments, every raw-text element and the script escapes. No `&`
    /// (html5ever decodes character references, the segmenter reports raw
    /// bytes), no CR or NUL (html5ever normalizes them), and no `svg`, `math`,
    /// `select` or `frameset`, which need a tree builder.
    const ATOMS: &[&str] = &[
        "<",
        "<",
        ">",
        ">",
        "/",
        "=",
        "=",
        "\"",
        "'",
        " ",
        " ",
        "\n",
        "\t",
        "a",
        "x",
        "b1",
        "div",
        "img",
        "p",
        "href",
        "onclick",
        "-",
        "--",
        "!",
        "?",
        "`",
        "<!--",
        "-->",
        "--!>",
        "<!",
        "<?",
        "</",
        "/>",
        "<a ",
        "<div ",
        "<img src=",
        "</a>",
        "</div>",
        " x=y",
        " k='v'",
        " t=\"u\"",
        "<script>",
        "</script>",
        "<script ",
        "</script ",
        "<!--<script>",
        "script",
        "<textarea>",
        "</textarea>",
        "<title>",
        "</title>",
        "<style>",
        "</style>",
        "<xmp>",
        "</xmp>",
        "<noscript>",
        "</noscript>",
        "<iframe>",
        "</iframe>",
        "<noembed>",
        "</noembed>",
        "<noframes>",
        "</noframes>",
        "textarea",
        "title",
        "<plaintext>",
        "<!DOCTYPE html>",
        "<![CDATA[",
        "]]>",
        "é",
        "＜",
    ];

    /// html5ever reports a bogus comment (`<!x>`, `<?x>`, `</ x>`) as a comment
    /// token too; the segmenter reports no text for those. Comment events are
    /// compared only for documents that cannot contain one. The test is on the
    /// raw bytes, so it also skips documents where the sequence sits in an
    /// attribute value or raw text; that only costs coverage.
    fn may_hold_a_bogus_comment(html: &str) -> bool {
        let bytes = html.as_bytes();
        (0..bytes.len()).any(|i| {
            bytes[i] == b'<'
                && match bytes.get(i + 1) {
                    Some(b'!') => !bytes[i + 2..].starts_with(b"--"),
                    Some(b'?') => true,
                    Some(b'/') => bytes
                        .get(i + 2)
                        .is_some_and(|b| !b.is_ascii_alphabetic() && *b != b'>'),
                    _ => false,
                }
        })
    }

    /// Both event lists for `html`, or `None` when they are not comparable.
    fn compared(html: &str) -> Option<(Vec<Event>, Vec<Event>)> {
        let mut expected = oracle_events(html)?;
        let mut actual = segment_events(html);
        if may_hold_a_bogus_comment(html) {
            for events in [&mut expected, &mut actual] {
                events.retain(|e| !matches!(e, Event::Comment(_)));
                // Text on both sides of a dropped comment reads as one run.
                let mut merged: Vec<Event> = Vec::with_capacity(events.len());
                for event in events.drain(..) {
                    match (merged.last_mut(), event) {
                        (Some(Event::Text(last)), Event::Text(more)) => last.push_str(&more),
                        (_, event) => merged.push(event),
                    }
                }
                *events = merged;
            }
        }
        Some((actual, expected))
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn segments_agree_with_html5ever_on_generated_documents() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let mut compared_documents = 0u32;
        for _ in 0..60_000 {
            let len = 1 + (rng.next() % 28) as usize;
            let html: String = (0..len)
                .map(|_| ATOMS[(rng.next() % ATOMS.len() as u64) as usize])
                .collect();
            let Some((actual, expected)) = compared(&html) else {
                continue;
            };
            assert_eq!(actual, expected, "document: {html:?}");
            compared_documents += 1;
        }
        // The duplicate-attribute skip must stay a minority.
        assert!(
            compared_documents > 40_000,
            "only {compared_documents} documents compared"
        );
    }

    #[test]
    fn segments_agree_with_html5ever_on_fixed_documents() {
        for html in [
            "<a href=\"x\">t</a>",
            "<a =x=y z>",
            "<a b = 'c' / d>e",
            "<a b=c/>d",
            "<a/b=c>d",
            "<a b='c'd=e>",
            "<script><!--<script></script>--></script>x",
            "<script><!--<script ></script ></script>x",
            "<script><!-- <scriptx></script>y",
            "<textarea></textareax></textarea>y",
            "<title></title/>y",
            "x</title y='>'>z",
            "<!--a--!>b<!--c-->d",
            "<!---->a<!--->b<!-->c<!----->d",
            "<!--a--b-->c<!--d->e-->f",
            "<!--a<!--b-->c-->d",
            "x<!--a--",
            "x<!--a-",
            "x<!--a",
            "<! a>b<? c>d</ e>f",
            "<div title=\"a > b\">c",
            "<div title=a>b",
        ] {
            let (actual, expected) = compared(html).expect("no duplicate attributes");
            assert_eq!(actual, expected, "document: {html:?}");
        }
    }
}
