//! Per-WAF bypass strategy selection.
//!
//! Maps a detected `WafType` to the mutations/encoders best suited to evade it
//! (`get_bypass_strategy`), plus the multi-WAF merge used when fingerprinting
//! is ambiguous (`merge_strategies`).

use crate::waf::WafType;
use super::types::{BypassStrategy, MutationType};

/// Get the optimal bypass strategy for a specific WAF type.
pub(crate) fn get_bypass_strategy(waf: &WafType) -> BypassStrategy {
    match waf {
        WafType::Cloudflare => BypassStrategy {
            extra_encoders: vec!["unicode".into(), "4url".into(), "zwsp".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::BacktickParens,
                MutationType::SchemeBreak,
                MutationType::EntityScheme,
                MutationType::JsCommentSplit,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 100,
        },
        WafType::AwsWaf => BypassStrategy {
            extra_encoders: vec!["2url".into(), "3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::WhitespaceMutation,
                MutationType::MultiSlash,
                MutationType::UnicodeJsEscape,
                MutationType::SchemeBreak,
                MutationType::ConstructorChain,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Akamai => BypassStrategy {
            extra_encoders: vec!["3url".into(), "4url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::SchemeBreak,
                MutationType::ConstructorChain,
                MutationType::CaseAlternation,
                MutationType::BacktickParens,
            ],
            extra_delay_hint_ms: 50,
        },
        WafType::Imperva => BypassStrategy {
            extra_encoders: vec!["zwsp".into(), "unicode".into(), "2url".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::BacktickParens,
                MutationType::SchemeBreak,
                MutationType::MultiSlash,
                MutationType::JsCommentSplit,
                MutationType::MixedHtmlEntities,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 100,
        },
        WafType::ModSecurity => BypassStrategy {
            extra_encoders: vec!["4url".into(), "2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::MultiSlash,
                MutationType::HtmlCommentSplit,
                MutationType::SchemeBreak,
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
                MutationType::MultiSlash,
                MutationType::KeywordEntityEncode,
                MutationType::SlashSeparator,
                MutationType::SchemeBreak,
                MutationType::SvgAnimateExec,
                MutationType::HtmlEntityParens,
                MutationType::EntityScheme,
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
                MutationType::KeywordEntityEncode,
                MutationType::BacktickParens,
                MutationType::SchemeBreak,
                MutationType::WhitespaceMutation,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::F5BigIp => BypassStrategy {
            extra_encoders: vec!["3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::ConstructorChain,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Barracuda => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::MixedHtmlEntities,
                MutationType::MultiSlash,
                MutationType::WhitespaceMutation,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::FortiWeb => BypassStrategy {
            extra_encoders: vec!["unicode".into(), "3url".into(), "zwsp".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::SchemeBreak,
                MutationType::BacktickParens,
                MutationType::UnicodeJsEscape,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::AzureWaf => BypassStrategy {
            extra_encoders: vec!["4url".into(), "unicode".into(), "zwsp".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::UnicodeJsEscape,
                MutationType::ConstructorChain,
            ],
            extra_delay_hint_ms: 50,
        },
        WafType::CloudArmor => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::BacktickParens,
                MutationType::MixedHtmlEntities,
                MutationType::CaseAlternation,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Fastly => BypassStrategy {
            extra_encoders: vec!["3url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::WhitespaceMutation,
                MutationType::JsCommentSplit,
                MutationType::BacktickParens,
            ],
            extra_delay_hint_ms: 0,
        },
        WafType::Wordfence => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::CaseAlternation,
                MutationType::BacktickParens,
                MutationType::WhitespaceMutation,
            ],
            extra_delay_hint_ms: 0,
        },
        // NetScaler AppFirewall is signature/regex driven and keys heavily
        // on literal tag/keyword shapes. Structural mutations that break the
        // literal `<tag>` and `alert(` shapes (comment split, case, exotic
        // whitespace) plus backtick calls are the highest-yield levers; pair
        // with url/unicode encoders for its body-decoding path.
        WafType::Citrix => BypassStrategy {
            extra_encoders: vec!["2url".into(), "unicode".into(), "zwsp".into()],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::HtmlCommentSplit,
                MutationType::MultiSlash,
                MutationType::CaseAlternation,
                MutationType::WhitespaceMutation,
                MutationType::SchemeBreak,
                MutationType::BacktickParens,
            ],
            extra_delay_hint_ms: 0,
        },
        // No WAF-specific mutation strategy yet; use the conservative
        // generic strategy until fingerprint-specific bypass behavior is
        // validated.
        WafType::Wallarm => unknown_strategy_for("Wallarm"),
        WafType::Naxsi => unknown_strategy_for("NAXSI"),
        WafType::SafeLine => unknown_strategy_for("SafeLine"),
        WafType::Unknown(hint) => unknown_strategy_for(hint),
    }
}

/// Pick a bypass strategy for `WafType::Unknown(hint)` based on what the
/// detector inferred about the block. Two hint shapes reach here today:
///
///   - `"HTTP <code>"` from `fingerprint_with_probe` when a provocation
///     payload elicited a 403/406/429/503 but no header/body fingerprint
///     matched. The status code carries useful intent: 429/503 means the
///     edge is rate-limiting, 406 is content-type/encoding-driven, 403 is
///     a generic block.
///   - Arbitrary `--force-waf <name>` when the user supplied a name we
///     don't recognize. Falls through to the conservative default.
fn unknown_strategy_for(hint: &str) -> BypassStrategy {
    let lower = hint.to_ascii_lowercase();
    if lower.contains("429") || lower.contains("503") {
        // Rate-limit / overload block. Keep mutation count low so we
        // don't keep tripping the limiter; lean on a delay hint so the
        // scan-level throttle has something to reach for.
        return BypassStrategy {
            extra_encoders: vec!["unicode".into(), "2url".into()],
            mutations: vec![MutationType::CaseAlternation],
            extra_delay_hint_ms: 1500,
        };
    }
    if lower.contains("406") {
        // Content-type / encoding-driven block. Heavier encoder mix
        // (mutations alone won't change the wire encoding the WAF cares
        // about); skip mutations that don't shift bytes meaningfully.
        return BypassStrategy {
            extra_encoders: vec![
                "unicode".into(),
                "2url".into(),
                "3url".into(),
                "4url".into(),
            ],
            mutations: vec![
                MutationType::KeywordEntityEncode,
                MutationType::MixedHtmlEntities,
                MutationType::UnicodeJsEscape,
                MutationType::HtmlCommentSplit,
            ],
            extra_delay_hint_ms: 0,
        };
    }
    // Generic 403 / forced-unknown: conservative default that exercises
    // the most common WAF weaknesses without committing to a specific
    // vendor's behavior.
    BypassStrategy {
        extra_encoders: vec!["2url".into(), "unicode".into(), "zwsp".into()],
        mutations: vec![
            MutationType::KeywordEntityEncode,
            MutationType::HtmlCommentSplit,
            MutationType::MultiSlash,
            MutationType::BacktickParens,
            MutationType::SchemeBreak,
            MutationType::CaseAlternation,
            MutationType::WhitespaceMutation,
        ],
        extra_delay_hint_ms: 0,
    }
}

/// Merge bypass strategies from multiple detected WAFs into a single combined strategy.
pub(crate) fn merge_strategies(waf_types: &[&WafType]) -> BypassStrategy {
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
                seen_mutations.insert(mutation);
                combined.mutations.push(mutation);
            }
        }

        // Take the max delay hint
        combined.extra_delay_hint_ms = combined
            .extra_delay_hint_ms
            .max(strategy.extra_delay_hint_ms);
    }

    combined
}
