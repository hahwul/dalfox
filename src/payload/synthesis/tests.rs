use super::*;
use crate::parameter_analysis::{DelimiterType, InjectionContext};

/// Every probed special character, used to assert the filter-constraint
/// invariant exhaustively.
const ALL_SPECIALS: &[char] = crate::parameter_analysis::SPECIAL_PROBE_CHARS;

/// Core invariant: a synthesized payload must never contain a character the
/// filter is known to strip.
fn assert_obeys_filter(payloads: &[String], invalid: &[char]) {
    for p in payloads {
        for c in p.chars() {
            assert!(
                !invalid.contains(&c),
                "synthesized payload {:?} uses blocked char {:?} (invalid={:?})",
                p,
                c,
                invalid
            );
        }
    }
}

fn html() -> InjectionContext {
    InjectionContext::Html(None)
}

#[test]
fn produces_payloads_for_every_context_when_unfiltered() {
    let contexts = [
        InjectionContext::Html(None),
        InjectionContext::Html(Some(DelimiterType::Comment)),
        InjectionContext::Attribute(Some(DelimiterType::SingleQuote)),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Attribute(None),
        InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::Backtick)),
        InjectionContext::Javascript(Some(DelimiterType::Comment)),
        InjectionContext::Javascript(None),
        InjectionContext::Css(None),
        InjectionContext::Css(Some(DelimiterType::SingleQuote)),
        InjectionContext::Css(Some(DelimiterType::DoubleQuote)),
    ];
    for ctx in contexts {
        let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
        assert!(
            !payloads.is_empty(),
            "expected synthesized payloads for {:?}",
            ctx
        );
    }
}

#[test]
fn output_is_capped_and_deduped() {
    // Exercise every context; none may exceed the cap or contain duplicates.
    for ctx in [
        InjectionContext::Html(None),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
    ] {
        let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
        assert!(
            payloads.len() <= MAX_SYNTHESIZED,
            "cap exceeded for {:?}",
            ctx
        );
        let mut sorted = payloads.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), payloads.len(), "duplicates for {:?}", ctx);
    }
}

#[test]
fn obeys_filter_for_assorted_blocked_sets() {
    let blocked_sets: &[&[char]] = &[
        &['<', '>'],
        &['('],
        &['(', ')'],
        &['"'],
        &['\''],
        &['<', '>', '(', ')'],
        &[';', '/'],
        &['=', '<', '>'],
        ALL_SPECIALS, // everything blocked
    ];
    let contexts = [
        InjectionContext::Html(None),
        InjectionContext::Html(Some(DelimiterType::Comment)),
        InjectionContext::Attribute(Some(DelimiterType::SingleQuote)),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Attribute(None),
        InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::Backtick)),
        InjectionContext::Javascript(None),
        InjectionContext::Css(None),
    ];
    for invalid in blocked_sets {
        for ctx in &contexts {
            let payloads = synthesize_payloads(ctx, invalid, &[], &[]);
            assert_obeys_filter(&payloads, invalid);
        }
    }
}

#[test]
fn everything_blocked_yields_nothing() {
    // With every special character stripped there is no way to construct an
    // executing payload, so synthesis must bow out (and let the caller fall
    // back) rather than emit junk.
    for ctx in [
        html(),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
    ] {
        let payloads = synthesize_payloads(&ctx, ALL_SPECIALS, &[], &[]);
        assert!(payloads.is_empty(), "expected empty for {:?}", ctx);
    }
}

#[test]
fn html_text_context_needs_angles() {
    // HTML element-content reflection can only execute by injecting a tag, so a
    // filter that strips `<` defeats synthesis here.
    let payloads = synthesize_payloads(&html(), &['<'], &[], &[]);
    assert!(
        payloads.is_empty(),
        "HTML text context should yield nothing when `<` is stripped, got {:?}",
        payloads
    );
}

#[test]
fn attribute_context_survives_angle_stripping() {
    // The key win: a quoted-attribute reflection stays exploitable without
    // `<`/`>` via stay-in-tag event injection.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &['<', '>'], &[], &[]);
    assert!(
        !payloads.is_empty(),
        "attribute context should still synthesize angle-free payloads"
    );
    for p in &payloads {
        assert!(
            !p.contains('<') && !p.contains('>'),
            "angle leaked in {:?}",
            p
        );
    }
    // At least one must be a real event-handler injection that can fire.
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("onmouseover=") || p.contains("onfocus=")),
        "expected an event-handler injection, got {:?}",
        payloads
    );
}

#[test]
fn paren_blocked_falls_back_to_backtick_call() {
    // With `(`/`)` stripped, the only surviving execution primitive is the
    // tagged-template call `alert`1``.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &['(', ')'], &[], &[]);
    assert!(!payloads.is_empty());
    assert_obeys_filter(&payloads, &['(', ')']);
    assert!(
        payloads.iter().any(|p| p.contains("alert`1`")),
        "expected a backtick call form, got {:?}",
        payloads
    );
    assert!(
        payloads.iter().all(|p| !p.contains("alert(1)")),
        "paren call should have been filtered out"
    );
}

#[test]
fn single_quote_attr_needs_the_quote() {
    // Breaking out of a single-quoted value requires emitting `'`; if that is
    // stripped, synthesis bows out (escaped-quote handling is tracked
    // separately).
    let ctx = InjectionContext::Attribute(Some(DelimiterType::SingleQuote));
    let payloads = synthesize_payloads(&ctx, &['\''], &[], &[]);
    assert!(
        payloads.is_empty(),
        "single-quote attribute with `'` stripped should yield nothing, got {:?}",
        payloads
    );
}

#[test]
fn backtick_js_context_uses_template_interpolation() {
    let ctx = InjectionContext::Javascript(Some(DelimiterType::Backtick));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
    assert!(
        payloads.iter().any(|p| p.contains("${alert(1)}")),
        "expected `${{alert(1)}}` interpolation, got {:?}",
        payloads
    );
}

#[test]
fn js_string_context_includes_nested_closer_breakouts() {
    // Issue #1073: synthesis must emit exact nested-closer breakouts for JS
    // string contexts, not just the bare quote-close.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
    // Bare close (depth 0) and a deep array-in-object-in-call close (depth 3).
    assert!(
        payloads.iter().any(|p| p == "\";alert(1)//"),
        "expected the bare string-close breakout, got {:?}",
        payloads
    );
    assert!(
        payloads.iter().any(|p| p == "\"]});alert(1)//"),
        "expected the nested array-in-object-in-call breakout, got {:?}",
        payloads
    );
}

#[test]
fn js_string_context_survives_angle_stripping() {
    // A reflection inside a JS string can break out with quotes alone — no
    // `</script>` tag needed — so angle stripping does not defeat it.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::SingleQuote));
    let payloads = synthesize_payloads(&ctx, &['<', '>'], &[], &[]);
    assert!(!payloads.is_empty());
    assert!(
        payloads.iter().any(|p| p.starts_with('\'')),
        "expected a quote-breakout JS payload, got {:?}",
        payloads
    );
}

#[test]
fn high_confidence_payloads_carry_a_marker() {
    // The lead payloads for marker-friendly contexts must embed a DOM marker so
    // a reflection can promote straight to [V].
    let class = crate::scanning::markers::class_marker();
    let id = crate::scanning::markers::id_marker();
    for ctx in [
        html(),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Css(None),
    ] {
        let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
        assert!(
            payloads
                .iter()
                .take(3)
                .any(|p| p.contains(class) || p.contains(id)),
            "expected a marker in the lead payloads for {:?}: {:?}",
            ctx,
            &payloads[..payloads.len().min(3)]
        );
    }
}

#[test]
fn html_lead_payload_is_the_most_reliable_shape() {
    // Confidence ordering: the first HTML candidate should be the auto-firing
    // svg/onload tag.
    let payloads = synthesize_payloads(&html(), &[], &[], &[]);
    assert!(
        payloads[0].starts_with("<svg onload=alert(1)"),
        "unexpected lead payload: {:?}",
        payloads[0]
    );
}

#[test]
fn attribute_url_context_includes_protocol_payload() {
    let ctx = InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[]);
    assert!(
        payloads.iter().any(|p| p.contains("javascript:alert(1)")),
        "expected a javascript: protocol payload, got {:?}",
        payloads
    );
}

#[test]
fn empty_profile_matches_no_filtering() {
    // No probe data → nothing is "blocked" → full-strength synthesis.
    let payloads = synthesize_payloads(&html(), &[], &[], &[]);
    assert!(payloads.len() > 5);
}

#[test]
fn escaped_quote_js_context_emits_backslash_breakout() {
    // Issue #1072: the escaped-quote signal drives synthesis to emit a
    // backslash-prefixed breakout for a server that escapes the JS-string quote.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));

    // No escaped signal → only the raw quote-close breakout.
    let plain = synthesize_payloads(&ctx, &[], &[], &[]);
    assert!(plain.iter().any(|p| p == "\";alert(1)//"));
    assert!(
        !plain.iter().any(|p| p == "\\\";alert(1)//"),
        "must not emit an escaped breakout without the escaped signal"
    );

    // Escaped signal for `"` → emit ONLY the backslash-prefixed breakouts; the
    // raw quote-close is inert under escaping, so it is dropped (keeping the cap
    // free for the marker-carrying `</script>` template).
    let escaped = synthesize_payloads(&ctx, &[], &[], &['"']);
    assert!(
        escaped.iter().any(|p| p == "\\\";alert(1)//"),
        "expected the escaped breakout `\\\";alert(1)//`, got {escaped:?}"
    );
    assert!(
        escaped.iter().any(|p| p == "\\\"]});alert(1)//"),
        "expected a nested escaped breakout"
    );
    assert!(
        !escaped.iter().any(|p| p == "\"]});alert(1)//"),
        "the inert raw *nested* breakouts must be dropped when the delimiter is escaped \
         (the depth-0 close still comes from the static JS templates)"
    );
    // The marker-carrying </script> breakout still survives the cap (works under
    // escaping regardless), so V-promotion isn't lost.
    assert!(
        escaped.iter().any(|p| p.contains("</script>")),
        "expected the marker-carrying </script> breakout to survive the cap"
    );
}

// ===================================================================
// Effectiveness benchmark (deterministic): does synthesis add executable,
// verifiable payloads the static catalog cannot express for a given filter?
//
// For each (context, blocked-chars) scenario we count, over a payload set, those
// that (a) survive the filter unchanged and (b) carry an executing construct —
// and, separately, those that additionally carry a DOM marker (so they can
// promote to a *verified* [V] finding). The SAME structural oracle is applied to
// catalog and synthesis, so the comparison is fair. The counts are upper bounds
// on real executability and are used only for relative comparison.
//
// We deliberately do NOT assert "catalog ∪ synth ≥ catalog": a superset can
// never cover less, so that would be vacuous. The falsifiable claims this test
// makes are (1) synthesis closes complete gaps — scenarios where the catalog
// yields zero verifiable payloads and synthesis yields some — and (2) synthesis
// contributes verifiable payloads that are NOT already in the catalog (net-new
// coverage). Either assertion can fail if synthesis is ineffective.
// ===================================================================

/// True when `payload` uses no character the filter strips (survives intact).
fn survives(payload: &str, blocked: &[char]) -> bool {
    payload.chars().all(|c| !blocked.contains(&c))
}

/// True when `payload` carries a construct that executes script.
fn executes(payload: &str) -> bool {
    let p = payload.to_ascii_lowercase();
    // A direct JS call (covers reflections inside an existing script where no
    // tag/handler is needed, e.g. `';alert(1)//`).
    let js_call = [
        "alert(", "confirm(", "prompt(", "alert`", "confirm`", "prompt`", "eval(",
    ]
    .iter()
    .any(|needle| p.contains(needle));
    // event handler `on<name>=`, an injected <script>, a javascript: URL, or a
    // template-literal interpolation.
    js_call || p.contains("<script") || p.contains("javascript:") || p.contains("${") || {
        // crude `on<letters>=` detector without pulling in regex here
        let bytes = p.as_bytes();
        let mut i = 0;
        let mut found = false;
        while i + 2 < bytes.len() {
            if &bytes[i..i + 2] == b"on" {
                let mut j = i + 2;
                while j < bytes.len() && bytes[j].is_ascii_lowercase() {
                    j += 1;
                }
                if j > i + 2 && j < bytes.len() && bytes[j] == b'=' {
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        found
    }
}

fn has_marker(payload: &str, class: &str, id: &str) -> bool {
    payload.contains(class) || payload.contains(id)
}

#[derive(Default, Clone, Copy)]
struct Coverage {
    exec: usize,
    verifiable: usize,
}

fn coverage(payloads: &[String], blocked: &[char], class: &str, id: &str) -> Coverage {
    let mut c = Coverage::default();
    for p in payloads {
        if survives(p, blocked) && executes(p) {
            c.exec += 1;
            if has_marker(p, class, id) {
                c.verifiable += 1;
            }
        }
    }
    c
}

#[test]
fn synthesis_closes_catalog_coverage_gaps() {
    let class = crate::scanning::markers::class_marker();
    let id = crate::scanning::markers::id_marker();

    // (label, context, characters the server-side filter strips)
    let scenarios: &[(&str, InjectionContext, &[char])] = &[
        (
            "attr(\") + strip <>",
            InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
            &['<', '>'],
        ),
        (
            "attr(\") + strip ()",
            InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
            &['(', ')'],
        ),
        (
            "attr(\") + strip <> ()",
            InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
            &['<', '>', '(', ')'],
        ),
        (
            "attr(') + strip <> ()",
            InjectionContext::Attribute(Some(DelimiterType::SingleQuote)),
            &['<', '>', '(', ')'],
        ),
        (
            "html + strip \"'",
            InjectionContext::Html(None),
            &['"', '\''],
        ),
        ("html + strip ()", InjectionContext::Html(None), &['(', ')']),
        (
            "js(') + strip <>",
            InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
            &['<', '>'],
        ),
        (
            "attrUrl(\") + strip <>",
            InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote)),
            &['<', '>'],
        ),
    ];

    let mut total_catalog_verif = 0usize;
    let mut total_netnew_verif = 0usize;
    let mut gaps_closed = 0usize;

    println!(
        "\n{:<26} | catalog(exec/verif) | synth(exec/verif) | net-new verif",
        "scenario"
    );
    println!("{}", "-".repeat(82));

    for (label, ctx, blocked) in scenarios {
        // Dedup the catalog so duplicates don't inflate its coverage.
        let mut catalog = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
        catalog.sort();
        catalog.dedup();
        let synth = synthesize_payloads(ctx, blocked, &[], &[]);

        // Net-new = synthesized payloads the catalog does not already contain.
        // This is the coverage synthesis genuinely *adds*, not an artifact of
        // concatenation — counting it on the set difference makes the headline
        // assertion falsifiable (it is 0 if synthesis only echoes the catalog).
        let catalog_set: std::collections::HashSet<&String> = catalog.iter().collect();
        let synth_only: Vec<String> = synth
            .iter()
            .filter(|p| !catalog_set.contains(*p))
            .cloned()
            .collect();

        let cat = coverage(&catalog, blocked, class, id);
        let syn = coverage(&synth, blocked, class, id);
        let netnew = coverage(&synth_only, blocked, class, id);

        println!(
            "{:<26} | {:>6}/{:<6}      | {:>5}/{:<5}     | {}",
            label, cat.exec, cat.verifiable, syn.exec, syn.verifiable, netnew.verifiable
        );

        total_catalog_verif += cat.verifiable;
        total_netnew_verif += netnew.verifiable;
        if cat.verifiable == 0 && syn.verifiable > 0 {
            gaps_closed += 1;
        }
    }

    println!("{}", "-".repeat(82));
    println!(
        "verifiable payloads — catalog total: {}, net-new from synthesis: {}, complete gaps closed: {}",
        total_catalog_verif, total_netnew_verif, gaps_closed
    );

    // (1) Synthesis must produce verifiable payloads in at least one scenario
    //     where the catalog produces none — a gap the catalog cannot express.
    assert!(
        gaps_closed > 0,
        "synthesis closed no catalog coverage gaps — expected at least one"
    );
    // (2) Synthesis must contribute verifiable payloads absent from the catalog
    //     (net-new coverage), aggregated across scenarios.
    assert!(
        total_netnew_verif > 0,
        "synthesis added no verifiable payloads beyond the catalog"
    );
}

#[test]
fn synthesis_is_fast_and_bounded() {
    // Performance guard: synthesis runs once per parameter inside the scan loop,
    // so it must be cheap. 20k calls across a mix of contexts/filters should be
    // far under a second even in debug; we assert a generous ceiling to stay
    // non-flaky in CI while still catching pathological regressions.
    let contexts = [
        InjectionContext::Html(None),
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
        InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Css(None),
    ];
    let blocked_sets: &[&[char]] = &[&[], &['<', '>'], &['(', ')'], &['<', '>', '(', ')']];

    let start = std::time::Instant::now();
    let mut produced = 0usize;
    let iterations = 1_000;
    for _ in 0..iterations {
        for ctx in &contexts {
            for blocked in blocked_sets {
                let out = synthesize_payloads(ctx, blocked, &[], &[]);
                assert!(out.len() <= MAX_SYNTHESIZED);
                produced += out.len();
            }
        }
    }
    let elapsed = start.elapsed();
    let calls = iterations * contexts.len() * blocked_sets.len();
    println!(
        "synthesis perf: {} calls, {} payloads, {:?} ({:.1} ns/call)",
        calls,
        produced,
        elapsed,
        elapsed.as_nanos() as f64 / calls as f64
    );
    assert!(
        elapsed.as_secs() < 5,
        "synthesis unexpectedly slow: {:?} for {} calls",
        elapsed,
        calls
    );
}
