//! Centralized CSS selector cache.
//!
//! Selectors used across multiple scanning/analysis modules are defined here
//! once and shared via `OnceLock` so they are parsed exactly once per process.

use scraper::Selector;
use std::sync::OnceLock;

pub fn universal() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| Selector::parse("*").expect("valid CSS universal selector"))
}

pub fn script() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| Selector::parse("script").expect("valid CSS script selector"))
}

pub fn style() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| Selector::parse("style").expect("valid CSS style selector"))
}

pub fn input_with_id_or_name() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| Selector::parse("input[id], input[name]").expect("valid CSS input selector"))
}

pub fn form() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| Selector::parse("form").expect("valid CSS form selector"))
}

pub fn input_textarea_select() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        Selector::parse("input, textarea, select")
            .expect("valid CSS input/textarea/select selector")
    })
}

pub fn meta_csp() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        Selector::parse("meta[http-equiv][content]").expect("valid CSS meta CSP selector")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scraper::Html;

    /// Each call to a selector accessor must return the SAME static
    /// reference — that's the contract the OnceLock cache provides and
    /// what makes the rest of the scanner cheap to call in hot loops.
    #[test]
    fn selectors_are_cached_across_calls() {
        let a = universal() as *const Selector;
        let b = universal() as *const Selector;
        assert_eq!(a, b);

        let a = script() as *const Selector;
        let b = script() as *const Selector;
        assert_eq!(a, b);
    }

    #[test]
    fn universal_matches_any_element() {
        let doc = Html::parse_fragment("<div><span>x</span></div>");
        let count = doc.select(universal()).count();
        assert!(count >= 2, "universal selector must match all elements");
    }

    #[test]
    fn script_and_style_match_their_tags() {
        let doc = Html::parse_document(
            "<html><head><style>a{}</style></head><body><script>1</script></body></html>",
        );
        assert_eq!(doc.select(script()).count(), 1);
        assert_eq!(doc.select(style()).count(), 1);
    }

    #[test]
    fn input_with_id_or_name_matches_either_attribute() {
        let doc = Html::parse_fragment(
            "<input id=\"a\"><input name=\"b\"><input><input id=\"c\" name=\"d\">",
        );
        // 3 inputs have id or name; the bare <input> does not.
        assert_eq!(doc.select(input_with_id_or_name()).count(), 3);
    }

    #[test]
    fn input_textarea_select_matches_all_three_form_controls() {
        let doc =
            Html::parse_fragment("<form><input><textarea></textarea><select></select></form>");
        assert_eq!(doc.select(input_textarea_select()).count(), 3);
        assert_eq!(doc.select(form()).count(), 1);
    }

    #[test]
    fn meta_csp_requires_both_http_equiv_and_content() {
        let doc = Html::parse_fragment(
            r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
               <meta http-equiv="X-UA-Compatible">
               <meta name="viewport" content="width=device-width">"#,
        );
        // Only the first meta has both http-equiv and content.
        assert_eq!(doc.select(meta_csp()).count(), 1);
    }
}
