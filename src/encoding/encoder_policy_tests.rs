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
