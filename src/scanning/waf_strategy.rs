//! WAF strategy selection + payload expansion + CSP helpers.
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

/// Maximum number of WAF mutation variants generated per base payload.
/// Prevents payload explosion when WAF bypass mutations are applied. This cap
/// only takes effect when a WAF is detected and bypass is on (the only path
/// that calls `expand_waf_payloads`), so it scales effort exactly on the scans
/// that want more bypass attempts — not the common no-WAF path. Sized to give
/// the attribute-decode-layer mutations (KeywordEntityEncode / MultiSlash /
/// SchemeBreak) a slot alongside the proven structural ones for payloads where
/// many mutations shape-match.
pub(crate) const MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD: usize = 4;
/// Compute the WAF bypass strategy for this scan. Returns `None` when WAF
/// bypass is disabled (`--waf-bypass off`), no WAF was fingerprinted, or the
/// fingerprint set is empty — in which case payload generation skips the
/// mutation / extra-encoder expansion entirely.
pub(crate) fn compute_waf_strategy(
    target: &Target,
    args: &ScanArgs,
) -> Option<crate::waf::bypass::BypassStrategy> {
    if args.waf_bypass == "off" {
        return None;
    }
    target.waf_info.as_ref().and_then(|waf_info| {
        if waf_info.is_empty() {
            None
        } else {
            let waf_types: Vec<&crate::waf::WafType> = waf_info.waf_types();
            Some(crate::waf::bypass::merge_strategies(&waf_types))
        }
    })
}
/// Find a CSP declared with `<meta http-equiv>`, returning the equivalent
/// header name and the policy text. Pages served without a CSP header commonly
/// carry one this way, and the CLI preflight has always honoured it — this is
/// that logic, shared so the server / MCP surfaces cannot analyse a different
/// policy than the CLI does for the same page.
pub(crate) fn extract_meta_csp(html: &str) -> Option<(String, String)> {
    let doc = crate::utils::html::parse_document_bounded(html);
    // Prefer an ENFORCING `Content-Security-Policy` meta over a report-only one,
    // mirroring the header path's enforcing-over-report-only `.or_else`. A page
    // may carry both (report-only for telemetry, enforcing for protection), and
    // their document order is arbitrary — returning whichever appears first
    // could hand back the report-only policy, which downstream marks
    // `report_only = true` and zeroes `require_trusted_types_for`. That drops
    // the real enforcing policy: a TT-hardened enforcing meta would then be
    // ignored and its (neutralised) DOM findings surface as false positives.
    let mut report_only: Option<(String, String)> = None;
    for el in doc.select(crate::scanning::selectors::meta_csp()) {
        let http_equiv = el
            .value()
            .attr("http-equiv")
            .unwrap_or("")
            .to_ascii_lowercase();
        let content = el.value().attr("content").unwrap_or("");
        if content.is_empty() {
            continue;
        }
        match http_equiv.as_str() {
            "content-security-policy" => {
                // Enforcing policy wins outright.
                return Some(("Content-Security-Policy".to_string(), content.to_string()));
            }
            "content-security-policy-report-only" => {
                // Remember the first report-only, but keep scanning for an
                // enforcing policy which takes precedence.
                report_only.get_or_insert_with(|| {
                    (
                        "Content-Security-Policy-Report-Only".to_string(),
                        content.to_string(),
                    )
                });
            }
            _ => continue,
        }
    }
    report_only
}
/// Pre-merge the payloads shared across every parameter: CSP-bypass payloads
/// (when CSP was analysed) followed by technology-specific payloads (when a
/// stack was fingerprinted). Built once per scan so [`generate_param_jobs`]
/// can clone the merged set per parameter instead of recomputing it.
pub(crate) fn build_shared_payloads(target: &Target) -> Vec<String> {
    let csp_bypass_payloads: Vec<String> = target
        .csp_analysis
        .as_ref()
        .map(crate::payload::xss_csp_bypass::get_csp_bypass_payloads)
        .unwrap_or_default();
    let tech_payloads: Vec<String> = target
        .tech_info
        .as_ref()
        .map(crate::scanning::tech_detect::get_tech_specific_payloads)
        .unwrap_or_default();
    let mut shared = Vec::with_capacity(csp_bypass_payloads.len() + tech_payloads.len());
    shared.extend(csp_bypass_payloads);
    shared.extend(tech_payloads);
    shared
}
/// Expand a parameter's base payload set into its WAF-bypass variants,
/// keeping the two bypass axes orthogonal instead of multiplying them.
///
/// Output order (front to back), de-duplicated while preserving first
/// occurrence:
///   1. the originals — cheapest, browser-native; they reflect first so a
///      param whose base shape isn't filtered short-circuits immediately;
///   2. raw structural mutations (`<scr<!---->ipt>`, `<ScRiPt>`, …) — the
///      highest-probability WAF bypass that needs no server-side decode,
///      front-loaded so an actively-blocking WAF surfaces a working bypass
///      before we spend requests on the heavier encoder variants;
///   3. encoder variants of the originals (`%3C…`, fullwidth, zwsp, …) —
///      transport-style evasion that relies on the app decoding the wire
///      bytes back into an executable payload.
///
/// Crucially this does *not* emit `encode(mutate(p))`: cross-encoding a
/// structural mutation buries its bypass under transport encoding and needs
/// both an app-side decode *and* browser tolerance of the mutated shape — a
/// compound condition that rarely lands while costing one request apiece.
/// Skipping it shrinks the per-param request count from `N·(1+m)·(1+k)` to
/// `N·(1+m+k)` with no loss of reach on either axis.
///
/// `stats`, when present, records each generated mutation variant against
/// its `MutationType` for `target_summary.waf.bypass.mutations_applied[]`
/// (counted pre-dedup against the encoder set, matching the prior
/// "did the mutation apply" semantics).
pub(crate) fn expand_waf_payloads(
    base: &[String],
    strategy: &crate::waf::bypass::BypassStrategy,
    stats: Option<&crate::waf::bypass::MutationStats>,
) -> Vec<String> {
    // Size both collections to the orthogonal output estimate
    // (`N·(1+m+k)`) so the mutation/encoder passes don't repeatedly rehash
    // and realloc — `base.len()` alone under-allocates by that whole factor.
    let est = base
        .len()
        .saturating_mul(1 + strategy.mutations.len() + strategy.extra_encoders.len());
    let mut seen: HashSet<String> = HashSet::with_capacity(est);
    let mut out: Vec<String> = Vec::with_capacity(est);

    // 1. Originals (de-duplicated), kept at the front.
    for p in base {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }

    // 2. Raw structural mutations — no transport encoding applied.
    if !strategy.mutations.is_empty() {
        let tagged = crate::waf::bypass::apply_mutations_tagged(
            base,
            &strategy.mutations,
            MAX_WAF_MUTATION_VARIANTS_PER_PAYLOAD,
        );
        for (p, origin) in tagged {
            // `None` is the unmodified base, already emitted in step 1.
            if let Some(m) = origin {
                if let Some(stats) = stats {
                    stats.record_variant(m);
                }
                if seen.insert(p.clone()) {
                    out.push(p);
                }
            }
        }
    }

    // 3. Encoder variants of the originals. `apply_encoders_to_payloads`
    //    re-emits each original as the first variant of its base; those
    //    collide with step 1 and are dropped by `seen`, leaving only the
    //    genuinely encoded forms.
    if !strategy.extra_encoders.is_empty() {
        for v in crate::encoding::apply_encoders_to_payloads(base, &strategy.extra_encoders) {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }

    out
}
