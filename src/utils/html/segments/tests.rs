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
    let html = "<svg><g></g></svg><title><img></title>";
    assert_eq!(raw_texts(html), [("title", "<img>", true)]);
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
        raw_texts("<math><mi><title>a</title></mi></math>"),
        [("title", "a", true)]
    );
    // `mi` is an integration point in MathML only.
    assert!(raw_texts("<svg><mi><title><b></title>").is_empty());
}

#[test]
fn nested_foreign_roots_close_one_at_a_time() {
    let html = "<svg><svg></svg><title><b></title></svg><title><i></title>";
    assert_eq!(raw_texts(html), [("title", "<i>", true)]);
}

#[test]
fn the_model_stops_where_it_cannot_follow_the_tree_builder() {
    let html = "a<svg><script>alert(1)</script></svg>";
    assert_eq!(unparsed_from(html), Some(6));
    assert_eq!(texts(html), ["a"]);
    assert_eq!(unparsed_from("<svg><style>x</style>"), Some(5));
    assert_eq!(unparsed_from("<svg><![CDATA[<b>]]></svg>"), Some(5));
    assert_eq!(unparsed_from("<svg><font color=red><title>"), Some(5));
    assert_eq!(
        unparsed_from("<svg><foreignObject><div></svg><title>"),
        Some(25)
    );
    assert_eq!(unparsed_from("<select><xmp><img></xmp></select>"), Some(8));
    assert_eq!(unparsed_from("<frameset><textarea>"), Some(0));
    // Not in the way otherwise.
    assert_eq!(
        unparsed_from("<svg><path d=''/></svg><script>1</script>"),
        None
    );
    assert_eq!(
        unparsed_from("<select><option>a</select><xmp>b</xmp>"),
        None
    );
    assert_eq!(unparsed_from("<p><![CDATA[x]]></p>"), None);
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
        let mut compared = 0u32;
        for _ in 0..60_000 {
            let len = 1 + (rng.next() % 28) as usize;
            let html: String = (0..len)
                .map(|_| ATOMS[(rng.next() % ATOMS.len() as u64) as usize])
                .collect();
            let Some(expected) = oracle_events(&html) else {
                continue;
            };
            assert_eq!(segment_events(&html), expected, "document: {html:?}");
            compared += 1;
        }
        // The duplicate-attribute skip must stay a minority.
        assert!(compared > 40_000, "only {compared} documents compared");
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
            "<! a>b<? c>d</ e>f",
            "<div title=\"a > b\">c",
            "<div title=a>b",
        ] {
            assert_eq!(
                Some(segment_events(html)),
                oracle_events(html),
                "document: {html:?}"
            );
        }
    }
}
