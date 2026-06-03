use super::*;
use url::Url;

fn make_url(u: &str) -> Url {
    Url::parse(u).expect("valid url")
}

#[test]
fn test_query_injection_replace() {
    let base = make_url("https://example.com/path?a=1&b=2");
    let param = Param {
        name: "a".into(),
        value: "1".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "PAY");
    assert!(out.contains("a=PAY"));
    assert!(out.contains("b=2"));
}

#[test]
fn test_query_injection_append() {
    let base = make_url("https://example.com/path");
    let param = Param {
        name: "q".into(),
        value: "".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "X");
    assert!(out.contains("q=X"));
}

#[test]
fn test_query_injection_preserves_existing_percent_encoding() {
    let base = make_url("https://example.com/path?q=seed");
    let param = Param {
        name: "q".into(),
        value: "seed".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "%3Cimg%20src=x%3E");
    assert!(out.contains("q=%3Cimg%20src%3Dx%3E"));
    assert!(!out.contains("%253Cimg"));
}

#[test]
fn test_query_injection_encodes_raw_spaces_without_plus() {
    let base = make_url("https://example.com/path?q=seed");
    let param = Param {
        name: "q".into(),
        value: "seed".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "PAY LOAD");
    assert!(out.contains("q=PAY%20LOAD"));
}

#[test]
fn test_path_injection_basic() {
    let base = make_url("https://example.com/a/b/c");
    let param = Param {
        name: "path_segment_1".into(),
        value: "b".into(),
        location: Location::Path,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "PAY LOAD");
    // space should be %20
    assert!(out.contains("/a/PAY%20LOAD/c"));
}

#[test]
fn test_path_injection_index_out_of_bounds() {
    let base = make_url("https://example.com/a");
    let param = Param {
        name: "path_segment_5".into(),
        value: "".into(),
        location: Location::Path,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "X");
    assert_eq!(out, "https://example.com/a");
}

#[test]
fn test_non_target_location_passthrough() {
    let base = make_url("https://example.com/x?y=1");
    let param = Param {
        name: "headerX".into(),
        value: "".into(),
        location: Location::Header,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "IGNORED");
    assert_eq!(out, base.as_str());
}

#[test]
fn test_fragment_injection_spa_route() {
    let base = make_url("http://example.com/#/redir?url=foo");
    let param = Param {
        name: "url".into(),
        value: "foo".into(),
        location: Location::Fragment,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "javascript:alert()");
    assert_eq!(out, "http://example.com/#/redir?url=javascript:alert()");
}

#[test]
fn test_fragment_injection_simple_kv() {
    let base = make_url("http://example.com/#key=val&other=123");
    let param = Param {
        name: "key".into(),
        value: "val".into(),
        location: Location::Fragment,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "PAYLOAD");
    assert_eq!(out, "http://example.com/#key=PAYLOAD&other=123");
}

#[test]
fn test_fragment_injection_append_when_absent() {
    let base = make_url("http://example.com/#/path?existing=1");
    let param = Param {
        name: "newparam".into(),
        value: "".into(),
        location: Location::Fragment,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "INJECTED");
    assert_eq!(
        out,
        "http://example.com/#/path?existing=1&newparam=INJECTED"
    );
}

#[test]
fn test_fragment_injection_no_existing_fragment() {
    let base = make_url("http://example.com/page");
    let param = Param {
        name: "url".into(),
        value: "".into(),
        location: Location::Fragment,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "PAY");
    assert_eq!(out, "http://example.com/page#url=PAY");
}

#[test]
fn test_fragment_injection_multiple_params() {
    let base = make_url("http://example.com/#/app?a=1&b=2&c=3");
    let param = Param {
        name: "b".into(),
        value: "2".into(),
        location: Location::Fragment,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_injected_url(&base, &param, "XSS");
    assert_eq!(out, "http://example.com/#/app?a=1&b=XSS&c=3");
}

// --- HPP tests ---

#[test]
fn test_hpp_last_position() {
    let base = make_url("https://example.com/path?q=safe&b=2");
    let param = Param {
        name: "q".into(),
        value: "safe".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_hpp_url(&base, &param, "<script>", HppPosition::Last).unwrap();
    assert!(out.contains("q=safe&q=%3Cscript%3E"));
    assert!(out.contains("b=2"));
}

#[test]
fn test_hpp_first_position() {
    let base = make_url("https://example.com/path?q=safe&b=2");
    let param = Param {
        name: "q".into(),
        value: "safe".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_hpp_url(&base, &param, "<script>", HppPosition::First).unwrap();
    assert!(out.contains("q=%3Cscript%3E&q=safe"));
    assert!(out.contains("b=2"));
}

#[test]
fn test_hpp_both_position() {
    let base = make_url("https://example.com/path?q=safe");
    let param = Param {
        name: "q".into(),
        value: "safe".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_hpp_url(&base, &param, "PAYLOAD", HppPosition::Both).unwrap();
    assert!(out.contains("q=PAYLOAD&q=PAYLOAD"));
}

#[test]
fn test_hpp_non_query_returns_none() {
    let base = make_url("https://example.com/path");
    let param = Param {
        name: "path_segment_0".into(),
        value: "path".into(),
        location: Location::Path,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    assert!(build_hpp_url(&base, &param, "PAYLOAD", HppPosition::Last).is_none());
}

#[test]
fn test_hpp_absent_param_appended() {
    let base = make_url("https://example.com/path?other=1");
    let param = Param {
        name: "q".into(),
        value: "".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_hpp_url(&base, &param, "XSS", HppPosition::Last).unwrap();
    assert!(out.contains("other=1"));
    assert!(out.contains("q=&q=XSS"));
}

#[test]
fn test_hpp_preserves_fragment() {
    let base = make_url("https://example.com/path?q=safe#frag");
    let param = Param {
        name: "q".into(),
        value: "safe".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let out = build_hpp_url(&base, &param, "PAY", HppPosition::Last).unwrap();
    assert!(out.ends_with("#frag"));
}

#[test]
fn test_build_hpp_urls_returns_3_variants() {
    let base = make_url("https://example.com/?q=safe");
    let param = Param {
        name: "q".into(),
        value: "safe".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let variants = build_hpp_urls(&base, &param, "XSS");
    assert_eq!(variants.len(), 3);
    assert_eq!(variants[0].1, HppPosition::Last);
    assert_eq!(variants[1].1, HppPosition::First);
    assert_eq!(variants[2].1, HppPosition::Both);
}

// Regression: issue #424 — Query param discovered via `<form action=...>`
// must be probed at the action endpoint, not the page hosting the form.
#[test]
fn effective_query_base_uses_form_action_for_query_params() {
    let target = make_url("https://example.com/page");
    let mut param = Param {
        name: "xss".into(),
        value: "".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("https://example.com/app.php".to_string()),
        form_origin_url: Some("https://example.com/page".to_string()),
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let base = effective_query_base(&target, &param);
    assert_eq!(base.as_str(), "https://example.com/app.php");

    // Building the injected URL on top of the resolved base must hit /app.php
    let out = build_injected_url(&base, &param, "PAY");
    assert!(
        out.starts_with("https://example.com/app.php?"),
        "expected app.php probe, got: {out}"
    );
    assert!(out.contains("xss=PAY"));

    // No form_action_url -> stays on target
    param.form_action_url = None;
    assert_eq!(
        effective_query_base(&target, &param).as_str(),
        target.as_str()
    );
}

#[test]
fn effective_query_base_uses_form_action_for_body_locations() {
    let target = make_url("https://example.com/page");
    let mut param = Param {
        name: "xss".into(),
        value: "".into(),
        location: Location::Body,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("https://example.com/app.php".to_string()),
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    // Body / JsonBody / MultipartBody params point at the form's action URL,
    // so the displayed PoC matches the POST that was actually sent (not the
    // page the form was discovered on).
    for loc in [Location::Body, Location::JsonBody, Location::MultipartBody] {
        param.location = loc;
        assert_eq!(
            effective_query_base(&target, &param).as_str(),
            "https://example.com/app.php"
        );
    }
}

#[test]
fn effective_query_base_ignores_form_action_for_header_fragment() {
    let target = make_url("https://example.com/page");
    let mut param = Param {
        name: "xss".into(),
        value: "".into(),
        location: Location::Header,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("https://example.com/app.php".to_string()),
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    for loc in [Location::Header, Location::Fragment] {
        param.location = loc;
        assert_eq!(
            effective_query_base(&target, &param).as_str(),
            target.as_str()
        );
    }
}

#[test]
fn effective_query_base_preserves_existing_query_on_action() {
    // `<form action="/app.php?ref=login">` — the action URL already has
    // its own query params. Injecting our target field must keep them.
    let target = make_url("https://example.com/page");
    let param = Param {
        name: "xss".into(),
        value: "".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("https://example.com/app.php?ref=login".to_string()),
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    let base = effective_query_base(&target, &param);
    let out = build_injected_url(&base, &param, "PAY");
    assert!(
        out.starts_with("https://example.com/app.php?"),
        "expected app.php probe, got: {out}"
    );
    assert!(out.contains("ref=login"), "lost preexisting query: {out}");
    assert!(out.contains("xss=PAY"), "missing injected param: {out}");
}

#[test]
fn effective_query_base_falls_back_when_action_unparseable() {
    let target = make_url("https://example.com/page");
    let param = Param {
        name: "xss".into(),
        value: "".into(),
        location: Location::Query,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("::not a url::".to_string()),
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    assert_eq!(
        effective_query_base(&target, &param).as_str(),
        target.as_str()
    );
}
