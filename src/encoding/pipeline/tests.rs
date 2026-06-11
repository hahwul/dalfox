use super::*;

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

fn b64u(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s)
}

fn make_jwt(header: &str, payload: &str, sig: &str) -> String {
    format!("{}.{}.{}", b64u(header), b64u(payload), b64u(sig))
}

#[test]
fn step_base64_roundtrip() {
    let s = EncodingStep::Base64;
    let out = s.apply("hello").expect("base64 encode");
    assert_eq!(out, "aGVsbG8=");
}

#[test]
fn step_url_basic() {
    let s = EncodingStep::Url;
    let out = s.apply("a b<c").expect("url encode");
    assert_eq!(out, "a%20b%3Cc");
}

#[test]
fn step_jsonfield_top_level_replace() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"a":"x","b":"y"}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/a".to_string(),
        template,
    };
    let out = step.apply("PAYLOAD").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(
        parsed["a"],
        serde_json::Value::String("PAYLOAD".to_string())
    );
    // Sibling preserved
    assert_eq!(parsed["b"], serde_json::Value::String("y".to_string()));
}

#[test]
fn step_jsonfield_nested_object() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"outer":{"inner":"x"},"sib":"y"}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/outer/inner".to_string(),
        template,
    };
    let out = step.apply("XSS").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(parsed["outer"]["inner"], "XSS");
    assert_eq!(parsed["sib"], "y");
}

#[test]
fn step_jsonfield_array_index() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"items":["a","b","c"]}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/items/1".to_string(),
        template,
    };
    let out = step.apply("Z").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(parsed["items"][0], "a");
    assert_eq!(parsed["items"][1], "Z");
    assert_eq!(parsed["items"][2], "c");
}

#[test]
fn step_jsonfield_invalid_pointer_returns_err() {
    let template: serde_json::Value = serde_json::from_str(r#"{"a":"x"}"#).expect("parse");
    let step = EncodingStep::JsonField {
        pointer: "no-leading-slash".to_string(),
        template,
    };
    assert!(step.apply("p").is_err());
}

#[test]
fn pipeline_chains_jsonfield_then_base64() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"move_url":"x","domain":"k.com"}"#).expect("parse");
    let pipeline = EncodingPipeline::new(vec![
        EncodingStep::JsonField {
            pointer: "/move_url".to_string(),
            template,
        },
        EncodingStep::Base64,
    ]);
    let out = pipeline.apply("PAYLOAD").expect("apply");
    // Decoded should be valid JSON with move_url=PAYLOAD
    let decoded = String::from_utf8(STANDARD.decode(&out).expect("b64")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
    assert_eq!(parsed["move_url"], "PAYLOAD");
    assert_eq!(parsed["domain"], "k.com");
}

#[test]
fn pipeline_empty_returns_payload_unchanged() {
    let pipeline = EncodingPipeline::default();
    assert_eq!(pipeline.apply("hi").expect("apply"), "hi");
    assert!(pipeline.is_empty());
}

#[test]
fn infer_returns_empty_for_short_value() {
    assert!(infer_nested_pipelines("abc").is_empty());
    assert!(infer_nested_pipelines("eyJ=").is_empty()); // length < 16
}

#[test]
fn infer_returns_empty_for_non_b64_charset() {
    let v = "hello world this is not base64";
    assert!(infer_nested_pipelines(v).is_empty());
}

#[test]
fn infer_returns_empty_for_b64_of_non_json() {
    let v = b64("just a plain string, not JSON, but long enough");
    assert!(infer_nested_pipelines(&v).is_empty());
}

#[test]
fn infer_finds_top_level_string_fields() {
    let json = r#"{"move_url":"as","acc_domain":"k.com"}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    assert_eq!(nested.len(), 2);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/move_url"));
    assert!(pointers.contains(&"/acc_domain"));
}

#[test]
fn infer_pipeline_roundtrips_to_kakao_shape() {
    // Mirrors the real-world payload structure.
    let json = r#"{"move_url":"as","acc_domain":"kakaoinvestment.com","auth_domain":"en.kakaoinvestment.com"}"#;
    let value = b64(json);
    let nested = infer_nested_pipelines(&value);
    let move_url = nested
        .iter()
        .find(|n| n.pointer == "/move_url")
        .expect("found move_url");
    let injected = move_url.pipeline.apply("DALFOX_MARKER").expect("apply");
    let decoded = String::from_utf8(STANDARD.decode(&injected).expect("b64")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
    assert_eq!(parsed["move_url"], "DALFOX_MARKER");
    // Other fields preserved verbatim
    assert_eq!(parsed["acc_domain"], "kakaoinvestment.com");
    assert_eq!(parsed["auth_domain"], "en.kakaoinvestment.com");
}

#[test]
fn infer_walks_into_nested_objects() {
    let json = r#"{"outer":{"inner":"v"},"top":"t"}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/outer/inner"));
    assert!(pointers.contains(&"/top"));
}

#[test]
fn infer_walks_into_arrays() {
    let json = r#"{"items":["a","b"]}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/items/0"));
    assert!(pointers.contains(&"/items/1"));
}

#[test]
fn infer_skips_non_string_leaves() {
    let json = r#"{"name":"x","count":3,"flag":true,"nada":null}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].pointer, "/name");
}

#[test]
fn infer_caps_total_leaves() {
    // Build an object with way more than MAX_LEAVES string keys.
    let mut map = serde_json::Map::new();
    for i in 0..100 {
        map.insert(format!("k{}", i), serde_json::Value::String("v".into()));
    }
    let json = serde_json::Value::Object(map).to_string();
    let v = b64(&json);
    let nested = infer_nested_pipelines(&v);
    assert!(
        nested.len() <= MAX_LEAVES,
        "expected ≤ {} leaves, got {}",
        MAX_LEAVES,
        nested.len()
    );
}

#[test]
fn infer_handles_url_encoded_b64_survivors() {
    // %2b → '+' is a common surviving character; our charset filter must
    // still accept the value once URL-decoding occurred upstream.
    let json = r#"{"f":"v_long_enough_now"}"#;
    let v = b64(json);
    assert!(looks_like_b64(&v, /*allow_url_safe=*/ false));
}

#[test]
fn infer_path_segments_preserve_dots_and_brackets_for_display() {
    // The `path` field on NestedField is what discovery joins into a
    // bracket-style display name. Dotted/bracketed keys must round-trip
    // verbatim so the chosen `qs[a.b]` / `qs[c[d]]` shape stays unambiguous.
    let mut map = serde_json::Map::new();
    map.insert("a.b".into(), serde_json::Value::String("x".into()));
    map.insert("c[d]".into(), serde_json::Value::String("y".into()));
    let json = serde_json::Value::Object(map).to_string();
    let v = b64(&json);
    let nested = infer_nested_pipelines(&v);
    let segs: std::collections::HashSet<String> =
        nested.iter().flat_map(|n| n.path.iter().cloned()).collect();
    assert!(segs.contains("a.b"), "got: {segs:?}");
    assert!(segs.contains("c[d]"), "got: {segs:?}");
}

#[test]
fn step_base64url_no_padding() {
    let s = EncodingStep::Base64Url;
    // The "??" payload (0x3f 0x3f) base64-standard is "Pz8=" — url-safe no
    // pad must drop the `=` and use the same alphabet (no `+`/`/` to swap).
    let out = s.apply("??").expect("apply");
    assert_eq!(out, "Pz8");
    // Bytes that produce `+` and `/` in standard alphabet end up as `-`/`_`
    // in url-safe. Use bytes containing the bit patterns that map to the
    // problematic chars.
    let raw = String::from_utf8_lossy(&[0xfb, 0xff, 0xff]).to_string();
    let out = s.apply(&raw).expect("apply");
    assert!(!out.contains('+'));
    assert!(!out.contains('/'));
    assert!(!out.contains('='));
}

#[test]
fn step_jwt_assemble_concatenates_segments() {
    let s = EncodingStep::JwtAssemble {
        header_b64u: "AAA".to_string(),
        signature_b64u: "ZZZ".to_string(),
    };
    assert_eq!(s.apply("MIDDLE").expect("apply"), "AAA.MIDDLE.ZZZ");
}

#[test]
fn infer_strategy_url_json_no_encoding() {
    // Bare JSON in the value (after URL-decode by query_pairs).
    let v = r#"{"name":"alice","email":"a@b"}"#;
    let nested = infer_nested_pipelines(v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/name"));
    assert!(pointers.contains(&"/email"));
    // Pipeline should be a single JsonField step (no base64).
    let name_field = nested.iter().find(|n| n.pointer == "/name").unwrap();
    assert_eq!(name_field.pipeline.steps.len(), 1);
    assert!(matches!(
        name_field.pipeline.steps[0],
        EncodingStep::JsonField { .. }
    ));
    // Round-trip
    let injected = name_field.pipeline.apply("PAYLOAD").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&injected).expect("json");
    assert_eq!(parsed["name"], "PAYLOAD");
    assert_eq!(parsed["email"], "a@b");
}

#[test]
fn infer_strategy_b64url_json() {
    // Use a value whose JSON contains bytes that produce `-`/`_` in url-safe
    // (and `+`/`/` in standard) — the `?` byte and some non-ASCII content.
    // The `>>>` chunk encodes to `Pj4-` in url-safe vs `Pj4+` in standard,
    // so the orchestrator's alphabet hint will pick b64url.
    let json = r#"{"sub":"a>>>b","note":"x"}"#;
    let v = b64u(json);
    assert!(
        v.contains('-') || v.contains('_'),
        "test fixture must have url-safe-distinctive char: {v}"
    );
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/sub"));
    assert!(pointers.contains(&"/note"));
    let sub = nested.iter().find(|n| n.pointer == "/sub").unwrap();
    assert!(
        matches!(sub.pipeline.steps.last().unwrap(), EncodingStep::Base64Url),
        "expected Base64Url, got pipeline: {:?}",
        sub.pipeline.steps
    );
    // Round-trip
    let injected = sub.pipeline.apply("MARKER").expect("apply");
    let decoded =
        String::from_utf8(URL_SAFE_NO_PAD.decode(&injected).expect("b64u")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
    assert_eq!(parsed["sub"], "MARKER");
    assert_eq!(parsed["note"], "x");
}

#[test]
fn infer_strategy_shared_alphabet_falls_back_to_b64() {
    // Shared-alphabet (alphanumeric-only) values should pick standard b64.
    // Both decoders would succeed on the same bytes; we pick b64 for
    // back-compat with existing opaque-token usage.
    let json = r#"{"f":"alphanumeric_value"}"#;
    let v = b64(json);
    assert!(!v.contains('-') && !v.contains('_') && !v.contains('+') && !v.contains('/'));
    let nested = infer_nested_pipelines(&v);
    let f = nested.iter().find(|n| n.pointer == "/f").unwrap();
    assert!(matches!(
        f.pipeline.steps.last().unwrap(),
        EncodingStep::Base64
    ));
}

#[test]
fn infer_strategy_jwt_classic_shape() {
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"alice","name":"Alice","iat":1234567890}"#;
    let sig = "fake_signature_bytes_here";
    let jwt = make_jwt(header, payload, sig);
    let nested = infer_nested_pipelines(&jwt);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    // Only string leaves — `iat` (number) is skipped.
    assert!(pointers.contains(&"/sub"));
    assert!(pointers.contains(&"/name"));
    assert!(!pointers.contains(&"/iat"));

    let name_field = nested.iter().find(|n| n.pointer == "/name").unwrap();
    // Pipeline shape: JsonField → Base64Url → JwtAssemble
    assert_eq!(name_field.pipeline.steps.len(), 3);
    assert!(matches!(
        name_field.pipeline.steps[2],
        EncodingStep::JwtAssemble { .. }
    ));

    // Round-trip: applied output must be a 3-segment dotted token whose
    // middle segment decodes to the modified payload, and whose header /
    // signature segments are preserved verbatim.
    let injected = name_field.pipeline.apply("XSS_MARKER").expect("apply");
    let segs: Vec<&str> = injected.split('.').collect();
    assert_eq!(segs.len(), 3);
    assert_eq!(segs[0], b64u(header));
    assert_eq!(segs[2], b64u(sig));
    let payload_decoded =
        String::from_utf8(URL_SAFE_NO_PAD.decode(segs[1]).expect("b64u")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&payload_decoded).expect("json");
    assert_eq!(parsed["name"], "XSS_MARKER");
    assert_eq!(parsed["sub"], "alice");
}

#[test]
fn infer_strategy_jwt_rejects_non_three_segment() {
    // Two segments — not a JWT.
    assert!(infer_jwt(&format!("{}.{}", b64u("{\"a\":\"b\"}"), b64u("c"))).is_empty());
    // Four segments.
    assert!(
        infer_jwt(&format!(
            "{}.{}.{}.{}",
            b64u("{}"),
            b64u("{}"),
            b64u("z"),
            b64u("z")
        ))
        .is_empty()
    );
    // Three segments but middle isn't JSON.
    assert!(infer_jwt(&format!("{}.{}.{}", b64u("AAA"), b64u("plain"), b64u("z"))).is_empty());
    // Three segments but with characters outside the b64url alphabet
    // (e.g. legacy `+/` that some implementations accidentally produce).
    assert!(infer_jwt("a+b.c/d.e=f").is_empty());
}

#[test]
fn infer_strategy_priority_jwt_beats_b64() {
    // A JWT-shaped string also has b64url-charset segments. Make sure the
    // JWT strategy wins (we get the JwtAssemble pipeline, not a plain
    // base64 result on the whole string).
    let jwt = make_jwt(r#"{"a":"b"}"#, r#"{"sub":"u"}"#, "sig");
    let nested = infer_nested_pipelines(&jwt);
    assert!(!nested.is_empty());
    let sub = nested.iter().find(|n| n.pointer == "/sub").unwrap();
    assert_eq!(sub.pipeline.steps.len(), 3);
    assert!(matches!(
        sub.pipeline.steps[2],
        EncodingStep::JwtAssemble { .. }
    ));
}

#[test]
fn infer_strategy_priority_url_json_beats_b64() {
    // Bare JSON like `{"a":"b"}` would never decode as b64-of-JSON anyway,
    // but the orchestrator should pick `infer_url_json` first so its
    // single-step pipeline (no Base64) is what callers see.
    let v = r#"{"a":"long_value_here_to_pass_filters"}"#;
    let nested = infer_nested_pipelines(v);
    let a = nested.iter().find(|n| n.pointer == "/a").unwrap();
    assert_eq!(a.pipeline.steps.len(), 1);
}

#[test]
fn pointer_escapes_special_chars() {
    // Field names with `/` and `~` should round-trip through the pointer
    // encoding back to the original key.
    let mut map = serde_json::Map::new();
    map.insert("a/b".into(), serde_json::Value::String("x".into()));
    map.insert("c~d".into(), serde_json::Value::String("y".into()));
    let json = serde_json::Value::Object(map).to_string();
    let v = b64(&json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.iter().any(|p| p.contains("~1"))); // '/' escape
    assert!(pointers.iter().any(|p| p.contains("~0"))); // '~' escape

    // Apply each pipeline and verify the leaf actually got replaced.
    for nf in &nested {
        let out = nf.pipeline.apply("ZZZ").expect("apply");
        let decoded = String::from_utf8(STANDARD.decode(&out).expect("b64")).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
        let key = nf.path[0].clone();
        assert_eq!(parsed[&key], "ZZZ", "field {key} replaced");
    }
}

#[test]
fn b64_json_discovery_survives_plus_decoded_to_space() {
    // `query_pairs()` turns a raw `+` in a base64 value into a space, so a
    // standard-alphabet base64-of-JSON value carrying `+` arrives space-mangled.
    // Discovery must still find the leaf (the `+` is restored before decoding).
    // Pick a JSON whose STANDARD base64 contains a `+`.
    let mut fixture = None;
    for len in 1..=12usize {
        let json = format!(r#"{{"k":"{}"}}"#, ">".repeat(len));
        let enc = b64(&json);
        if enc.contains('+') {
            fixture = Some(enc);
            break;
        }
    }
    let enc = fixture.expect("a '>'-run JSON whose standard base64 contains '+'");
    let mangled = enc.replace('+', " "); // simulate query_pairs '+' -> space
    let leaves = infer_nested_pipelines(&mangled);
    assert!(
        !leaves.is_empty(),
        "standard base64-of-JSON discovery must survive '+'->space (enc={enc}, mangled={mangled})"
    );
}
