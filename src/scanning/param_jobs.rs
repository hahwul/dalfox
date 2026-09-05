//! per-parameter job planning + HTTP-scannability.
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

/// Requests one parameter will cost the scan, mirroring `run_scanning`'s own
/// fan-out: it builds a reflection payload set and a DOM payload set, truncates
/// **each** to the effective per-parameter cap, and then sends one request per
/// payload in both (`total_tasks += reflection.len() + dom.len()`).
///
/// The DOM half used to be missing here, so `/preflight` quoted roughly half the
/// requests the scan would send — on the one number the endpoint exists to
/// produce. `cmd::scan::analysis` already estimated it this way for `--dry-run`;
/// this brings the REST and MCP endpoints onto the same arithmetic.
///
/// Still a lower bound: WAF mutation/encoder expansion and the shared CSP/tech
/// payloads appended after the cap are not counted, matching the CLI's caveat.
pub(crate) fn estimate_param_requests(
    p: &Param,
    scan_args: &ScanArgs,
    enc_factor: usize,
    apply_cap: &dyn Fn(usize) -> usize,
) -> usize {
    let refl_len = if let Some(ctx) = &p.injection_context {
        crate::scanning::xss_common::get_dynamic_payloads(ctx, scan_args)
            .unwrap_or_else(|_| vec![])
            .len()
    } else {
        let html_len = crate::payload::get_dynamic_xss_html_payloads().len() * enc_factor;
        let js_len = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len() * enc_factor;
        html_len + js_len
    };
    let dom_len = match &p.injection_context {
        // A JS-context param gets no DOM-verification pass.
        Some(crate::parameter_analysis::InjectionContext::Javascript(_)) => 0,
        Some(ctx) => crate::scanning::xss_common::generate_dynamic_payloads(ctx).len() * enc_factor,
        None => {
            (crate::payload::get_dynamic_xss_html_payloads().len()
                + crate::payload::get_dynamic_xss_attribute_payloads().len())
                * enc_factor
        }
    };
    apply_cap(refl_len).saturating_add(apply_cap(dom_len))
}
/// === Stage 4: Payload Generation — build per-parameter payload sets ===
///
/// For each (non-fragment) reflection parameter, build a [`ParamPayloadJob`]
/// of `(param, reflection payloads, DOM payloads)` by applying, in order:
/// context-aware base generation, the shared CSP/tech payloads, WAF bypass
/// mutations + extra encoders, the adaptive angle prune/hoist, and the
/// `--max-payloads-per-param` cap. Returns the jobs plus the total payload
/// count used to size the progress bar (one tick per reflection + DOM
/// payload).
/// Whether the HTTP scan phase will actually test `param`.
///
/// URL fragments are client-side only — HTTP servers never see them — so
/// `generate_param_jobs` spawns no worker for `Location::Fragment` params (the
/// AST DOM analyzer detects `location.hash` sources from response JS
/// independently, so coverage isn't lost). Async front-ends use this so their
/// `params_total` matches the number of per-parameter workers actually run
/// (keeping `estimated_completion_pct` honest) and so preflight estimates don't
/// bill requests for params that send none.
pub(crate) fn param_is_http_scannable(param: &crate::parameter_analysis::Param) -> bool {
    !matches!(
        param.location,
        crate::parameter_analysis::Location::Fragment
    )
}
/// Count of a target's parameters the HTTP scan phase will actually test.
pub(crate) fn http_scannable_param_count(target: &Target) -> usize {
    target
        .reflection_params
        .iter()
        .filter(|p| param_is_http_scannable(p))
        .count()
}
pub(crate) fn generate_param_jobs(
    target: &Target,
    args: &ScanArgs,
    waf_strategy: Option<&crate::waf::bypass::BypassStrategy>,
    shared_payloads: &[String],
) -> (Vec<ParamPayloadJob>, u64) {
    let mut total_tasks = 0u64;
    let mut param_jobs: Vec<ParamPayloadJob> = Vec::with_capacity(target.reflection_params.len());
    for param in &target.reflection_params {
        // URL fragments are client-side only — HTTP servers never see them, so
        // reflection probes for `Location::Fragment` params would be pure-waste
        // requests. See `param_is_http_scannable`.
        if !param_is_http_scannable(param) {
            continue;
        }
        let mut reflection_payloads = if let Some(context) = &param.injection_context {
            crate::scanning::xss_common::get_dynamic_payloads(context, args)
                .unwrap_or_else(|_| vec![])
        } else {
            get_fallback_reflection_payloads(args).unwrap_or_else(|_| vec![])
        };
        let mut dom_payloads = get_dom_payloads(param, args).unwrap_or_else(|_| vec![]);

        // Issue #1075: prepend filter-constrained synthesized payloads to the
        // reflection set when active probing produced a character profile for
        // this parameter. (Non-JS DOM payloads receive synthesis separately
        // inside `get_dom_payloads` → `generate_adaptive_payloads`; JS-context
        // DOM payloads use the dedicated script-breakout set instead.) Placing
        // them first lets the first-hit-wins reflection loop try shapes built
        // for this exact filter before the broad catalog, lifting detection on
        // custom filters; under non-`--deep-scan` runs that ordering can also
        // cut requests by hitting earlier.
        //
        // Note: with an explicit small `--max-payloads-per-param` (< the synth
        // count), the truncation below can evict the catalog entirely in favour
        // of these higher-signal synthesized payloads — intentional, since the
        // user asked for few payloads and these are the ones most likely to fire.
        if let Some(context) = &param.injection_context
            && (param.invalid_specials.is_some() || param.valid_specials.is_some())
        {
            let invalid = param.invalid_specials.as_deref().unwrap_or_default();
            let valid = param.valid_specials.as_deref().unwrap_or_default();
            // #1072: escaped-quote signal (JS string contexts) drives synthesis
            // to emit backslash-prefixed breakouts that survive server escaping.
            let escaped = param.escaped_specials.as_deref().unwrap_or_default();
            // #1073 follow-up: the breakout computed from this site's observed
            // inline-<script> prefix, emitted ahead of the fixed catalog.
            let observed_breakout = param.js_breakout.as_deref();
            let synthesized = crate::payload::synthesis::synthesize_payloads(
                context,
                invalid,
                valid,
                escaped,
                observed_breakout,
            );
            if !synthesized.is_empty() {
                let mut seen: std::collections::HashSet<String> =
                    std::collections::HashSet::with_capacity(
                        synthesized.len() + reflection_payloads.len(),
                    );
                let mut merged = Vec::with_capacity(synthesized.len() + reflection_payloads.len());
                for p in synthesized.into_iter().chain(reflection_payloads) {
                    if seen.insert(p.clone()) {
                        merged.push(p);
                    }
                }
                reflection_payloads = merged;
            }
        }

        // Cap the *base* reflection and DOM catalogs independently (each to
        // `cap`) BEFORE WAF-bypass expansion and the shared-payload append below.
        // An explicit --max-payloads-per-param wins; otherwise a built-in safety
        // cap bounds the request fan-out on parameters that reflect every payload
        // without DOM-verifying (self-link echoes — issue #1153), where the DOM
        // phase would otherwise send the full ~10k+ payload set. --deep-scan lifts
        // the built-in cap (truly unlimited).
        //
        // Capping the BASE catalog (not the post-expansion set) is deliberate:
        // `expand_waf_payloads` keeps the de-duplicated originals at the front and
        // appends every structural-mutation / extra-encoder variant at the tail,
        // so capping *after* expansion truncates 100% of the WAF-bypass variants
        // whenever the base alone exceeds the cap (e.g. ~9k attribute-context
        // payloads vs the 3000 default) — silently defeating WAF bypass on exactly
        // the params it was selected for. Capping first lets each surviving base
        // payload keep its full bypass expansion; with no WAF the set is unchanged
        // by expansion, so the self-link amplification is still bounded to `cap`.
        let cap = effective_payload_cap(args.max_payloads_per_param, args.deep_scan);
        if cap > 0 {
            let refl_dropped = reflection_payloads.len().saturating_sub(cap);
            let dom_dropped = dom_payloads.len().saturating_sub(cap);
            reflection_payloads.truncate(cap);
            dom_payloads.truncate(cap);
            // Surface the built-in cap (an explicit user cap is the operator's own
            // deliberate choice, not a silent one) so a trimmed run is never
            // silent — "No silent caps".
            if args.max_payloads_per_param == 0 && (refl_dropped > 0 || dom_dropped > 0) {
                crate::dbg_log!(
                    "param {}: built-in payload safety cap {} trimmed {} reflection + {} DOM base payload(s); raise with --max-payloads-per-param or --deep-scan",
                    param.name,
                    cap,
                    refl_dropped,
                    dom_dropped
                );
            }
        }

        // Apply WAF bypass expansion if a WAF was detected. The two bypass
        // axes are kept orthogonal rather than multiplied together (see
        // `expand_waf_payloads`): structural mutations are sent raw and
        // encoder variants are applied to the originals only, so we never
        // emit the low-yield `encode(mutate(p))` cross product. The tagged
        // mutation pass still feeds `record_variant`, which powers the
        // per-target effectiveness counter in
        // target_summary.waf.bypass.mutations_applied[].
        if let Some(strategy) = waf_strategy {
            let stats = target.mutation_stats.as_deref();
            reflection_payloads = expand_waf_payloads(&reflection_payloads, strategy, stats);
            dom_payloads = expand_waf_payloads(&dom_payloads, strategy, stats);
        }

        // Adaptive prune + reorder: when active probing recorded that the
        // server strips `<` / `>`, (a) drop reflection/DOM payloads whose
        // raw bytes carry those characters (guaranteed misses), and
        // (b) hoist payloads that carry no `<`/`>` in any encoded form to
        // the front of the list. The reorder is the bigger lever: the
        // loop's `reflection_found_locally` short-circuit means the first
        // reflecting payload zeros out the rest of the budget, so putting
        // angle-free payloads (event-handler / quote-breakout shapes that
        // actually work against an angle-stripping filter) before the
        // angle-encoded variants collapses the per-param request count
        // from thousands to dozens on attribute-context params.
        if let Some(invalid) = param.invalid_specials.as_deref()
            && !invalid.is_empty()
        {
            let refl_before = reflection_payloads.len();
            let dom_before = dom_payloads.len();
            reflection_payloads = prune_blocked_raw_angles(reflection_payloads, invalid);
            dom_payloads = prune_blocked_raw_angles(dom_payloads, invalid);
            reflection_payloads = hoist_angle_free_payloads(reflection_payloads, invalid);
            dom_payloads = hoist_angle_free_payloads(dom_payloads, invalid);
            if refl_before != reflection_payloads.len() || dom_before != dom_payloads.len() {
                crate::dbg_log!(
                    "adaptive prune (param={}): reflection {}→{}, dom {}→{} (invalid_specials={:?})",
                    param.name,
                    refl_before,
                    reflection_payloads.len(),
                    dom_before,
                    dom_payloads.len(),
                    invalid,
                );
            }
        }

        // Append shared payloads (CSP bypass + tech-specific) AFTER the cap so
        // the safety cap can never trim these few, high-value payloads. They
        // still get the same WAF-bypass expansion as the base set.
        if !shared_payloads.is_empty() {
            let mut shared_refl: Vec<String> = shared_payloads.to_vec();
            let mut shared_dom: Vec<String> = shared_payloads.to_vec();
            if let Some(strategy) = waf_strategy {
                let stats = target.mutation_stats.as_deref();
                shared_refl = expand_waf_payloads(&shared_refl, strategy, stats);
                shared_dom = expand_waf_payloads(&shared_dom, strategy, stats);
            }
            // Apply the same adaptive prune the base set got: when the server
            // strips `<`/`>`, angle-bearing shared payloads (many CSP-bypass
            // shapes) are guaranteed misses, so drop them rather than spend a
            // request each. Preserves the pre-cap-reorder behavior for shared.
            if let Some(invalid) = param.invalid_specials.as_deref()
                && !invalid.is_empty()
            {
                shared_refl = prune_blocked_raw_angles(shared_refl, invalid);
                shared_dom = prune_blocked_raw_angles(shared_dom, invalid);
            }
            reflection_payloads.extend(shared_refl);
            dom_payloads.extend(shared_dom);
        }

        // One pb.inc(1) per reflection payload plus one per DOM payload.
        // The previous `len * (1 + len)` formula overcounted by orders of
        // magnitude, which made `{eta}` meaningless (it would project hours
        // for a sub-minute scan).
        total_tasks += reflection_payloads.len() as u64 + dom_payloads.len() as u64;
        param_jobs.push((param.clone(), reflection_payloads, dom_payloads));
    }
    (param_jobs, total_tasks)
}
