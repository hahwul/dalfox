use super::*;
use std::time::Instant;

#[test]
fn ordinary_document_is_borrowed_unchanged() {
    let html = "<html><body><div><p>hi</p><span>x</span></div></body></html>";
    let bounded = bound_html_nesting(html);
    assert!(matches!(bounded, Cow::Borrowed(_)));
    assert_eq!(bounded.len(), html.len());
}

#[test]
fn depth_just_under_the_cap_is_untouched() {
    let n = MAX_HTML_NESTING_DEPTH - 8;
    let html = format!(
        "<html><body>{}MARK{}</body></html>",
        "<div>".repeat(n),
        "</div>".repeat(n)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn depth_past_the_cap_is_truncated_at_a_tag_boundary() {
    let n = MAX_HTML_NESTING_DEPTH * 4;
    let html = format!(
        "<html><body>{}MARK{}</body></html>",
        "<div>".repeat(n),
        "</div>".repeat(n)
    );
    let bounded = bound_html_nesting(&html);
    assert!(
        bounded.len() < html.len(),
        "deep document must be truncated"
    );
    assert!(bounded.ends_with('>'), "cut must land on a tag boundary");
    // Everything kept is still valid UTF-8 prefix of the original.
    assert!(html.starts_with(bounded.as_ref()));
}

#[test]
fn sibling_elements_never_trip_the_guard() {
    // 20 000 siblings are depth 3, not depth 20 000.
    let html = format!(
        "<html><body>{}</body></html>",
        "<div>x</div>".repeat(20_000)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn unclosed_optional_end_tags_never_trip_the_guard() {
    // A 5 000-item list whose <li>s are never closed is ordinary markup.
    let html = format!(
        "<html><body><ul>{}</ul></body></html>",
        "<li>item".repeat(5_000)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
    let rows = format!("<table><tr>{}</tr></table>", "<td>c".repeat(5_000));
    assert_eq!(bound_html_nesting(&rows).len(), rows.len());
}

#[test]
fn void_elements_do_not_accumulate_depth() {
    let html = format!(
        "<html><body>{}</body></html>",
        "<br><img src=x><input>".repeat(5_000)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn self_closing_tags_do_not_accumulate_depth() {
    let html = format!(
        "<html><body>{}</body></html>",
        "<custom-tag/>".repeat(5_000)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn script_contents_are_not_read_as_markup() {
    // `a<b` inside a script must not open 5 000 <b> elements.
    let js = "if (a<b) { c(); }".repeat(5_000);
    let html = format!("<html><body><script>{js}</script></body></html>");
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn comments_are_skipped_wholesale() {
    let html = format!("<html><body><!--{}--></body></html>", "<div>".repeat(5_000));
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn bare_less_than_in_text_is_not_a_tag() {
    let html = format!(
        "<html><body>{}</body></html>",
        "a < b and c < d ".repeat(5_000)
    );
    assert_eq!(bound_html_nesting(&html).len(), html.len());
}

#[test]
fn mismatched_end_tags_do_not_cost_quadratic_time() {
    // The pathological shape for an unbounded end-tag lookback.
    let html = format!("{}{}", "<div>".repeat(400), "</span>".repeat(50_000));
    let start = Instant::now();
    let _ = bound_html_nesting(&html);
    assert!(
        start.elapsed().as_millis() < 500,
        "end-tag lookback must stay bounded, took {:?}",
        start.elapsed()
    );
}

#[test]
fn deeply_nested_document_parses_promptly() {
    // The regression this module exists for: unguarded, 16 000 levels took ~29 s
    // through the scanner. Through the guard the parse must be near-instant.
    let n = 16_000;
    let html = format!(
        "<html><body>{}MARK{}</body></html>",
        "<div>".repeat(n),
        "</div>".repeat(n)
    );
    let start = Instant::now();
    let doc = parse_document_bounded(&html);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 2,
        "bounded parse of a {n}-deep document took {elapsed:?}"
    );
    // Still a usable document: the outer levels survive.
    assert!(doc.select(crate::scanning::selectors::universal()).count() > 100);
}

#[test]
fn shallow_document_parse_is_equivalent_to_unbounded() {
    let html = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head>
                  <body><div id="a">hello</div><input name="q" value="v"></body></html>"#;
    let bounded = parse_document_bounded(html);
    let direct = scraper::Html::parse_document(html);
    assert_eq!(bounded.html(), direct.html());
}

#[test]
fn many_rawtext_elements_do_not_cost_quadratic_time() {
    // The rawtext skip used to lowercase the *rest of the document* on every
    // <script> it met, so a page with many small scripts allocated one
    // progressively-shorter copy each — quadratic work inside the guard whose
    // whole job is preventing quadratic work.
    let html = format!(
        "<html><body>{}</body></html>",
        "<script>var a = 1;</script><div>x</div>".repeat(20_000)
    );
    let start = Instant::now();
    let bounded = bound_html_nesting(&html);
    let elapsed = start.elapsed();
    assert_eq!(bounded.len(), html.len(), "this page is shallow, not deep");
    assert!(
        elapsed.as_millis() < 500,
        "rawtext skip must stay linear, took {elapsed:?} on {} KiB",
        html.len() / 1024
    );
}

#[test]
fn empty_and_unterminated_rawtext_elements_terminate() {
    // Cursor-advance edge cases: an empty script, an unclosed script, a lone
    // `<`, a lone `</`, and an unterminated comment must all return promptly.
    for html in [
        "<html><script></script><div>x</div></html>",
        "<html><script>never closed",
        "<html><body>trailing <",
        "<html><body></",
        "<html><body><!-- never closed",
        "<",
        "",
    ] {
        let start = Instant::now();
        let bounded = bound_html_nesting(html);
        assert!(
            start.elapsed().as_millis() < 200,
            "input {html:?} did not terminate promptly"
        );
        assert_eq!(bounded.len(), html.len());
    }
}

#[test]
fn uppercase_close_tag_ends_rawtext() {
    // The rawtext skip is ASCII-case-insensitive, so `</SCRIPT>` closes the
    // block and the markup after it is scanned normally.
    let deep = "<div>".repeat(MAX_HTML_NESTING_DEPTH * 2);
    let html = format!("<html><SCRIPT>a<b</SCRIPT>{deep}</html>");
    assert!(
        bound_html_nesting(&html).len() < html.len(),
        "nesting after an uppercase </SCRIPT> must still be seen"
    );
}

// --- over-estimation regressions (adversarial review, 2026-08-13) -----------
//
// The first version of this estimator claimed every approximation
// under-estimates. It did not: elements with optional end tags were never
// pushed, so `</td>` / `</li>` could not unwind the inline elements inside
// them, and a 32-entry end-tag lookback left permanent residue. Ordinary
// legacy markup therefore crossed the 512 cap and had its tail truncated —
// silent recall loss on a real page. Each case below is a real-world markup
// shape whose true depth is single-digit.

/// The tail marker must survive: if it does, nothing was truncated.
fn assert_not_truncated(name: &str, html: &str) {
    let bounded = bound_html_nesting(html);
    assert_eq!(
        bounded.len(),
        html.len(),
        "{name}: a {}-byte page with single-digit real depth was truncated to {}",
        html.len(),
        bounded.len()
    );
    assert!(bounded.contains("MARK"), "{name}: tail marker was cut");
}

#[test]
fn legacy_posts_with_unclosed_font_are_not_truncated() {
    // 20 blog posts, each with 35 unclosed <font>s closed only by </div>.
    let block = format!("<div class=post>{}Text</div>", "<font size=2>".repeat(35));
    let html = format!(
        "<html><body>{}<div id=late>MARK</div></body></html>",
        block.repeat(20)
    );
    assert_not_truncated("legacy_font_posts", &html);
}

#[test]
fn table_rows_with_unclosed_inline_elements_are_not_truncated() {
    // `</td>` must unwind the <font> inside it. Real depth: table>tr>td>font.
    let html = format!(
        "<html><body><table>{}</table><div id=late>MARK</div></body></html>",
        "<tr><td><font color=red>x</td></tr>".repeat(600)
    );
    assert_not_truncated("table_rows_unclosed_font", &html);

    let anchors = format!(
        "<html><body><table>{}</table><div id=late>MARK</div></body></html>",
        "<tr><td><a href=#>x</td></tr>".repeat(600)
    );
    assert_not_truncated("td_unclosed_anchor", &anchors);
}

#[test]
fn list_items_with_unclosed_inline_elements_are_not_truncated() {
    // No `</li>` at all: the implied end tag has to close the previous item.
    let html = format!(
        "<html><body><ul>{}</ul><div id=late>MARK</div></body></html>",
        "<li><span>x".repeat(600)
    );
    assert_not_truncated("list_unclosed_span", &html);
}

#[test]
fn paragraphs_and_definition_lists_do_not_accumulate() {
    let ps = format!(
        "<html><body>{}<div id=late>MARK</div></body></html>",
        "<p><b>bold text".repeat(600)
    );
    assert_not_truncated("unclosed_p_with_bold", &ps);
    let dl = format!(
        "<html><body><dl>{}</dl><div id=late>MARK</div></body></html>",
        "<dt><i>term<dd><i>def".repeat(400)
    );
    assert_not_truncated("unclosed_dt_dd", &dl);
}

#[test]
fn markup_inside_a_quoted_attribute_is_not_counted() {
    // `<iframe srcdoc="…">` legitimately carries raw markup in an attribute.
    let html = format!(
        r#"<html><body><iframe srcdoc="{}"></iframe><div id=late>MARK</div></body></html>"#,
        "<div>".repeat(600)
    );
    assert_not_truncated("iframe_srcdoc", &html);
}

// --- the attack shapes must still be caught ---------------------------------

/// Deliberately deep markup must still trip the guard, whatever tag it uses:
/// the implied-end-tag barriers exist so a nested list cannot smuggle depth
/// past the estimator.
fn assert_truncated(name: &str, html: &str) {
    let bounded = bound_html_nesting(html);
    assert!(
        bounded.len() < html.len(),
        "{name}: {}-byte deeply-nested document was NOT truncated",
        html.len()
    );
}

#[test]
fn deliberately_nested_lists_are_still_caught() {
    let n = 20_000;
    let html = format!(
        "<html><body>{}MARK{}</body></html>",
        "<ul><li>".repeat(n),
        "</li></ul>".repeat(n)
    );
    assert_truncated("nested_list_attack", &html);
}

#[test]
fn deliberately_nested_inline_elements_are_still_caught() {
    for tag in ["span", "font", "b", "a"] {
        let n = 20_000;
        let html = format!(
            "<html><body>{}MARK{}</body></html>",
            format!("<{tag}>").repeat(n),
            format!("</{tag}>").repeat(n)
        );
        assert_truncated(&format!("nested_{tag}_attack"), &html);
    }
}

#[test]
fn deliberately_nested_table_cells_are_still_caught() {
    // Each `<table>` is a barrier, so genuinely nested tables keep their depth.
    let n = 5_000;
    let html = format!(
        "<html><body>{}MARK{}</body></html>",
        "<table><tr><td>".repeat(n),
        "</td></tr></table>".repeat(n)
    );
    assert_truncated("nested_table_attack", &html);
}

#[test]
fn unmatched_end_tags_stay_linear_with_a_deep_stack() {
    // The count map must reject a never-opened end tag in O(1); otherwise a
    // near-full stack plus a flood of unmatched end tags is quadratic again.
    let html = format!("{}{}", "<div>".repeat(400), "</span>".repeat(200_000));
    let start = Instant::now();
    let _ = bound_html_nesting(&html);
    assert!(
        start.elapsed().as_millis() < 1000,
        "unmatched end tags took {:?}",
        start.elapsed()
    );
}
