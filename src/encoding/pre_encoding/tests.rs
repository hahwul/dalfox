use super::*;

#[test]
fn test_apply_pre_encoding_none() {
    assert_eq!(apply_pre_encoding("test", &None), "test");
    assert_eq!(
        apply_pre_encoding("test", &Some("unknown".to_string())),
        "test"
    );
}

#[test]
fn test_apply_pre_encoding_base64() {
    assert_eq!(
        apply_pre_encoding("<script>", &Some("base64".to_string())),
        base64_encode("<script>")
    );
}

#[test]
fn test_apply_pre_encoding_2base64() {
    let expected = base64_encode(&base64_encode("<script>"));
    assert_eq!(
        apply_pre_encoding("<script>", &Some("2base64".to_string())),
        expected
    );
}

#[test]
fn test_apply_pre_encoding_2url() {
    let expected = url_encode(&url_encode("<"));
    assert_eq!(apply_pre_encoding("<", &Some("2url".to_string())), expected);
}

#[test]
fn test_apply_pre_encoding_3url() {
    let expected = url_encode(&url_encode(&url_encode("<")));
    assert_eq!(apply_pre_encoding("<", &Some("3url".to_string())), expected);
}

#[test]
fn test_pre_encoding_type_roundtrip() {
    for enc in &[
        PreEncodingType::Base64,
        PreEncodingType::DoubleBase64,
        PreEncodingType::DoubleUrl,
        PreEncodingType::TripleUrl,
        PreEncodingType::WafWindowPad,
    ] {
        let s = enc.as_str();
        let parsed = PreEncodingType::parse(s).unwrap();
        assert_eq!(&parsed, enc);
    }
}

#[test]
fn test_waf_window_pad_prepends_inert_prefix() {
    // The WAF inspection-window-overflow transform prepends a benign filler so
    // the real vector lands past a size-limited WAF inspection window. The
    // original payload must survive verbatim as a suffix (so reflection / DOM
    // matching against the raw payload still works), and the prefix must carry
    // no HTML/JS metacharacters that could shift the reflection context.
    let payload = "<svg onload=alert(1)>";
    let out = apply_pre_encoding(payload, &Some("wafpad".to_string()));

    let pad = waf_window_pad();
    assert_eq!(pad.len(), WAF_WINDOW_PAD_LEN);
    assert_eq!(out, format!("{pad}{payload}"));
    assert!(
        out.ends_with(payload),
        "raw payload must survive as a suffix"
    );
    assert!(
        out.len() > WAF_WINDOW_PAD_LEN,
        "padded payload must exceed the inspection window"
    );
    // The pad itself must be context-inert.
    assert!(!pad.contains(['<', '>', '"', '\'', '&', '/', '=', ';', '(', ')']));
}

#[test]
fn test_encoding_probes_cover_all_types() {
    let probes = encoding_probes();
    assert_eq!(probes.len(), 4);

    // Verify each probe encodes correctly
    let payload = "<test>";
    for (enc_type, encode_fn) in probes {
        assert_eq!(encode_fn(payload), enc_type.encode(payload));
    }
}

#[test]
fn test_multi_url_decode_probes() {
    let probes = multi_url_decode_probes();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0], (PreEncodingType::DoubleUrl, 1));
    assert_eq!(probes[1], (PreEncodingType::TripleUrl, 2));
}

#[test]
fn test_encode_consistency() {
    // Ensure apply_pre_encoding matches PreEncodingType::encode
    let payload = "<script>alert(1)</script>";
    for enc in &[
        PreEncodingType::Base64,
        PreEncodingType::DoubleBase64,
        PreEncodingType::DoubleUrl,
        PreEncodingType::TripleUrl,
    ] {
        assert_eq!(
            apply_pre_encoding(payload, &Some(enc.as_str().to_string())),
            enc.encode(payload)
        );
    }
}

#[test]
fn multi_url_path_param_decodes_back_to_the_payload_on_the_wire() {
    // An `Nurl` path param is one whose segment is percent-decoded N times in
    // total (once by the server's router, N-1 more by the app) — that is what
    // the path detection probe measures. The as-sent segment must therefore
    // carry exactly N layers once `build_injected_url` escapes its `%`.
    use crate::parameter_analysis::{Location, Param};
    let payload = "<svg/onload=alert(1)>";
    let base = url::Url::parse("https://ex.com/a/b").unwrap();
    for (enc, decodes) in [("2url", 2), ("3url", 3)] {
        let mut param = Param::new(
            "path_segment_1".to_string(),
            "b".to_string(),
            Location::Path,
        );
        param.pre_encoding = Some(enc.to_string());
        let sent = crate::scanning::url_inject::build_injected_url(
            &base,
            &param,
            &apply_param_encoding(payload, &param),
        );
        let mut seg = sent.rsplit('/').next().unwrap().to_string();
        for _ in 0..decodes {
            seg = urlencoding::decode(&seg).unwrap().into_owned();
        }
        assert_eq!(seg, payload, "{enc}: sent {sent}");
    }

    // Query params are unchanged: the query builder preserves `%XX`, so the
    // full N rounds are exactly N layers there.
    let mut q = Param::new("q".to_string(), String::new(), Location::Query);
    q.pre_encoding = Some("2url".to_string());
    assert_eq!(apply_param_encoding("<", &q), "%253C");
}
