use super::*;

#[test]
fn test_apply_encoders_none_only() {
    let bases = vec!["<x>".to_string(), "<x>".to_string()];
    let encs = vec!["none".to_string()];
    let out = apply_encoders_to_payloads(&bases, &encs);
    // Only unique originals
    assert_eq!(out, vec!["<x>".to_string()]);
}

#[test]
fn test_apply_encoders_order_and_dedup() {
    let bases = vec!["<x>".to_string(), "<x>".to_string()];
    let encs = vec![
        "base64".to_string(),
        "html".to_string(),
        "url".to_string(),
        "url".to_string(),
    ];
    let out = apply_encoders_to_payloads(&bases, &encs);
    assert_eq!(
        out,
        vec![
            "<x>".to_string(),
            url_encode("<x>"),
            html_entity_encode("<x>"),
            base64_encode("<x>"),
        ]
    );
}

#[test]
fn test_each_payload_encoder_known_output() {
    type Encoder = fn(&str) -> String;

    let cases: [(&str, &str, Encoder, &str); 9] = [
        ("url", "<", url_encode, "%3C"),
        ("html", "<", html_entity_encode, "&#x003c;"),
        (
            "htmlpad",
            "<",
            html_entity_zero_padded_encode,
            "&#x000003c;",
        ),
        ("2url", "<", double_url_encode, "%253C"),
        ("3url", "<", triple_url_encode, "%25253C"),
        ("4url", "<", quadruple_url_encode, "%2525253C"),
        ("base64", "<svg>", base64_encode, "PHN2Zz4="),
        ("unicode", "<", unicode_fullwidth_encode, "＜"),
        ("zwsp", "<", zero_width_encode, "<\u{200B}"),
    ];

    for (name, input, encoder, expected) in cases {
        assert_eq!(encoder(input), expected, "encoder {name}");
    }
}

#[test]
fn test_expand_single_payload() {
    let out = expand_payload_with_encoders(
        "<",
        &["2url".to_string(), "3url".to_string(), "base64".to_string()],
    );
    assert!(out.contains(&"<".to_string()));
    assert!(out.contains(&double_url_encode("<")));
    assert!(out.contains(&triple_url_encode("<")));
    assert!(out.contains(&base64_encode("<")));
}

// ---------------------------------------------------------------------------
// `encoder_expansion_factor` — the multiplier every request-count estimate
// (`--dry-run`, the debug preflight estimate, REST `/preflight`, MCP
// `preflight_dalfox`) uses to size a scan before running it.
//
// All four call sites used to re-derive it from a hand-written literal list
// that had silently drifted out of step with the expansion below: it named only
// url/html/2url/3url/4url/base64, so `htmlpad`, `unicode` and `zwsp` — all
// accepted by `--encoders` and all genuinely expanded — contributed nothing to
// the estimate. A caller asking for them was quoted a request budget well under
// what the scan would actually send. These tests pin the helper to the real
// expansion so the two can't drift again.
// ---------------------------------------------------------------------------

/// The factor is not an independent guess: it must equal the width the real
/// expansion produces. Uses a base payload whose variants are all distinct
/// under every encoder, so nothing is de-duplicated away and the row width is
/// exactly `1 + active encoders`.
#[test]
fn test_encoder_expansion_factor_matches_the_real_expansion() {
    let bases = vec!["<a href=\"x\">".to_string()];
    for encs in [
        vec![],
        vec!["url".to_string()],
        vec!["url".to_string(), "html".to_string()],
        // The three the old hand-rolled list forgot.
        vec!["htmlpad".to_string()],
        vec!["unicode".to_string()],
        vec!["zwsp".to_string()],
        vec!["url".to_string(), "html".to_string(), "htmlpad".to_string()],
        crate::cmd::scan::ENCODER_VALUES
            .iter()
            .filter(|e| **e != "none")
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    ] {
        let expanded = apply_encoders_to_payloads(&bases, &encs);
        assert_eq!(
            encoder_expansion_factor(&encs),
            expanded.len(),
            "factor must match the expansion width for encoders {encs:?} (expanded: {expanded:?})"
        );
    }
}

/// Every value `--encoders` accepts (bar `none`) must add to the factor.
/// Asserting the total against `ENCODER_VALUES` is what catches a newly
/// supported encoder being wired into the expansion but not the estimate.
#[test]
fn test_encoder_expansion_factor_counts_every_supported_encoder() {
    let all: Vec<String> = crate::cmd::scan::ENCODER_VALUES
        .iter()
        .filter(|e| **e != "none")
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        encoder_expansion_factor(&all),
        all.len() + 1,
        "every non-`none` encoder must contribute one variant on top of the original"
    );
    // `none` wins outright: only the originals are sent, whatever else is listed.
    assert_eq!(
        encoder_expansion_factor(&["none".to_string(), "url".to_string()]),
        1
    );
    // An unrecognised name contributes nothing (validation rejects it earlier).
    assert_eq!(
        encoder_expansion_factor(&["url".to_string(), "urlencode".to_string()]),
        2
    );
}
