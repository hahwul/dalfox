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
        Selector::parse("input, textarea, select").expect("valid CSS input/textarea/select selector")
    })
}

pub fn meta_csp() -> &'static Selector {
    static SEL: OnceLock<Selector> = OnceLock::new();
    SEL.get_or_init(|| {
        Selector::parse("meta[http-equiv][content]").expect("valid CSS meta CSP selector")
    })
}
