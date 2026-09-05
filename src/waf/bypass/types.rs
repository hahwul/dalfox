//! Payload-mutation vocabulary and the per-WAF strategy shape.
//!
//! `MutationType` names each bypass technique and renders a stable PascalCase
//! key via `Display`; `BypassStrategy` is what `strategy::get_bypass_strategy`
//! returns; `MutationStats` / `MutationStatsSnapshot` are the runtime
//! accounting the scan loop keeps per target.

/// Types of payload mutations that can be applied for WAF bypass.
///
/// `Display` produces a stable PascalCase name suitable for JSON keys
/// in `target_summary.waf.bypass.mutations_applied[]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationType {
    /// Insert HTML comments inside tag names: `<scr<!---->ipt>`
    HtmlCommentSplit,
    /// Tab/newline between tag and attribute: `<img\t\nsrc=x>`
    WhitespaceMutation,
    /// JavaScript comment splitting: `al/**/ert(1)`
    JsCommentSplit,
    /// Backtick instead of parentheses: `` alert`1` ``
    BacktickParens,
    /// Constructor chain: `[].constructor.constructor('alert(1)')()`
    ConstructorChain,
    /// Unicode escapes in JS: `\u0061lert(1)`
    UnicodeJsEscape,
    /// Mixed decimal/hex HTML entities
    MixedHtmlEntities,
    /// Alternating case for HTML tags: `<ScRiPt>`
    CaseAlternation,
    // ── CRS-targeting mutations ─────────────────────────────────────
    /// Use `/` instead of space between tag and attributes: `<svg/onload=alert(1)>`
    /// Bypasses CRS 941160 regex that expects whitespace before attributes.
    SlashSeparator,
    /// Replace parentheses with HTML entities: `alert&#40;1&#41;`
    /// Bypasses CRS 941370 JS function call detection.
    HtmlEntityParens,
    /// SVG animate/set element execution: `<svg><animate onbegin=alert(1) attributeName=x>`
    /// Bypasses CRS 941110 tag denylist which may not include SVG animation elements.
    SvgAnimateExec,
    /// Exotic whitespace chars (vertical tab 0x0B, form feed 0x0C) between tag and attrs.
    /// Bypasses CRS 941320 tag handler regex that only checks \\s (space/tab/newline).
    ExoticWhitespace,
    // ── Attribute-decode-layer mutations ────────────────────────────
    // These exploit that the HTML tokenizer decodes character references
    // *inside attribute values* before the value is handed to the URL parser
    // or the event-handler JS compiler. They carry strict payload-shape gates
    // (see the mutation impls): they fire ONLY in attribute / event-handler /
    // `javascript:`-URL context and NO-OP inside `<script>`/`<style>` raw text
    // and in bare body-text, where no entity decoding happens.
    /// HTML-entity-encode the first letter of a JS sink keyword in an
    /// event-handler / `javascript:`-URL attribute value: `onerror=alert(1)` →
    /// `onerror=&#97;lert(1)`. The tokenizer decodes `&#97;` to `a` before the
    /// handler is compiled, so a literal-`alert` keyword regex misses it.
    KeywordEntityEncode,
    /// Replace EVERY top-level whitespace attribute separator in the first tag
    /// with `/`: `<img src=x onerror=alert(1)>` → `<img/src=x/onerror=alert(1)>`.
    /// Defeats regexes that tolerate one `/` but re-anchor on `\s` before later
    /// attributes. Distinct from [`MutationType::SlashSeparator`] (first only).
    MultiSlash,
    /// Insert a numeric control-char entity (`&#9;` TAB) inside an executable
    /// URI scheme keyword: `href=javascript:…` → `href=java&#9;script:…`. The
    /// tokenizer decodes it to a TAB in the attribute value and the WHATWG URL
    /// parser strips the TAB before scheme parsing, so the URL still resolves
    /// to `javascript:` while a literal-scheme WAF regex misses it.
    SchemeBreak,
    /// HTML-entity-encode the leading letter of an executable URI scheme:
    /// `href=javascript:…` → `href=&#106;avascript:…`. A different wire
    /// signature than [`MutationType::SchemeBreak`] (entity-encode vs
    /// control-char insertion) for the same attribute-decode mechanism.
    EntityScheme,
}

impl std::fmt::Display for MutationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            MutationType::HtmlCommentSplit => "HtmlCommentSplit",
            MutationType::WhitespaceMutation => "WhitespaceMutation",
            MutationType::JsCommentSplit => "JsCommentSplit",
            MutationType::BacktickParens => "BacktickParens",
            MutationType::ConstructorChain => "ConstructorChain",
            MutationType::UnicodeJsEscape => "UnicodeJsEscape",
            MutationType::MixedHtmlEntities => "MixedHtmlEntities",
            MutationType::CaseAlternation => "CaseAlternation",
            MutationType::SlashSeparator => "SlashSeparator",
            MutationType::HtmlEntityParens => "HtmlEntityParens",
            MutationType::SvgAnimateExec => "SvgAnimateExec",
            MutationType::ExoticWhitespace => "ExoticWhitespace",
            MutationType::KeywordEntityEncode => "KeywordEntityEncode",
            MutationType::MultiSlash => "MultiSlash",
            MutationType::SchemeBreak => "SchemeBreak",
            MutationType::EntityScheme => "EntityScheme",
        };
        f.write_str(name)
    }
}

/// Per-target effectiveness telemetry for the WAF bypass pass.
///
/// `variants_generated` records, per `MutationType`, how many distinct
/// payload variants the mutation contributed *for this target*
/// (post-dedup, pre-encoder). It's a "did the mutation even apply"
/// signal — a value of 0 means the strategy declared the mutation but
/// the target's payload set didn't shape-match any of it.
///
/// `bypass_requests` is the total HTTP request count sent under the
/// active bypass strategy, and `bypass_blocks` is the subset that
/// returned a WAF block status (403/406/429/503). The ratio gives a
/// rough "did the bypass help" signal that surfaces alongside the
/// detected WAF in `target_summary.waf.bypass`.
#[derive(Debug, Default)]
pub struct MutationStats {
    pub variants_generated: std::sync::Mutex<std::collections::HashMap<MutationType, u64>>,
    pub bypass_requests: std::sync::atomic::AtomicU64,
    pub bypass_blocks: std::sync::atomic::AtomicU64,
}

impl MutationStats {
    pub(crate) fn record_variant(&self, m: MutationType) {
        if let Ok(mut g) = self.variants_generated.lock() {
            *g.entry(m).or_insert(0) += 1;
        }
    }
    pub(crate) fn record_request(&self, blocked: bool) {
        self.bypass_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if blocked {
            self.bypass_blocks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    pub(crate) fn snapshot(&self) -> MutationStatsSnapshot {
        let variants = self
            .variants_generated
            .lock()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default();
        MutationStatsSnapshot {
            variants,
            bypass_requests: self
                .bypass_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            bypass_blocks: self
                .bypass_blocks
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// Plain-data view of `MutationStats` suitable for JSON serialization.
#[derive(Debug, Default, Clone)]
pub(crate) struct MutationStatsSnapshot {
    pub variants: std::collections::HashMap<MutationType, u64>,
    pub bypass_requests: u64,
    pub bypass_blocks: u64,
}

/// A bypass strategy composed of extra encoders and payload mutations.
#[derive(Debug, Clone, Default)]
pub(crate) struct BypassStrategy {
    /// Extra encoder names to add beyond user-specified ones.
    pub extra_encoders: Vec<String>,
    /// Payload mutations to apply.
    pub mutations: Vec<MutationType>,
    /// Extra delay (ms) hint to avoid rate-limiting WAFs.
    pub extra_delay_hint_ms: u64,
}
