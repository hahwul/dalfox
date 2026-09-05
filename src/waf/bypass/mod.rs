//! WAF-specific bypass strategies.
//!
//! Each detected WAF type maps to a set of encoding, mutation, and evasion
//! techniques optimized for that particular WAF. This module wires the pieces:
//! [`types`] (mutation vocabulary + strategy shape), [`strategy`] (WAF ->
//! strategy selection), and [`mutate`] (the payload rewrites), exposing the
//! small surface the scan loop consumes.

mod mutate;
mod strategy;
mod types;

// Production surface consumed elsewhere in the crate.
pub(crate) use strategy::merge_strategies;
pub(crate) use types::{BypassStrategy, MutationStats, MutationType};

// The dispatch below calls the per-family mutators (`pub(super)` in `mutate`).
use mutate::*;

// Test-only prelude: `tests.rs` reaches these via `use super::*`. They are not
// part of the production surface — `get_bypass_strategy` is exercised at
// runtime only through `merge_strategies`, and the mutation primitives are
// module-internal — so the re-exports are gated to keep non-test builds
// warning-clean.
#[cfg(test)]
use {crate::waf::WafType, strategy::get_bypass_strategy};

/// Apply payload mutations to a list of base payloads, generating additional bypass variants.
/// Returns the original payloads plus mutated variants.
///
/// The `max_variants_per_payload` parameter caps how many mutation variants are generated
/// per base payload to prevent payload explosion.
/// Untagged form of [`apply_mutations_tagged`]. Production takes the tagged
/// path (it needs each variant's origin for telemetry); this stays as the
/// shape the mutation tests assert against.
#[cfg(test)]
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
        MutationType::KeywordEntityEncode => keyword_entity_encode(payload),
        MutationType::MultiSlash => multi_slash(payload),
        MutationType::SchemeBreak => scheme_break(payload),
        MutationType::EntityScheme => entity_scheme(payload),
    }
}

#[cfg(test)]
mod tests;
