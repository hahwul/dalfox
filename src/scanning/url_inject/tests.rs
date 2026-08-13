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

/// Only the space arm of the path-segment encoder was exercised. The rest of
/// the table encodes the characters that would otherwise *truncate or reshape*
/// the URL — `#` starts a fragment, `?` starts a query, `%` would corrupt the
/// following bytes, and CR/LF/TAB are request-splitting material. If any arm
/// regressed to a raw push the injected payload would silently land in a
/// different URL component than the path segment under test.
#[test]
fn test_path_injection_encodes_url_structural_characters() {
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
    let out = build_injected_url(&base, &param, "x#y?z%w\nq\tr\ns");
    assert!(
        out.contains("%23") && out.contains("%3F") && out.contains("%25"),
        "#, ? and % must be percent-encoded, got: {out}"
    );
    assert!(
        out.contains("%0A") && out.contains("%09"),
        "LF and TAB must be percent-encoded, got: {out}"
    );
    // The payload must stay inside the path: no fragment, no query.
    assert!(
        !out.contains('#') && !out.contains('?'),
        "structural characters leaked out of the path segment: {out}"
    );
    assert!(out.starts_with("https://example.com/a/"));
    assert!(out.ends_with("/c"));
}

/// CR is on the encode table too, but a bare `\r` in a path is also something
/// `Url::set_path` would reject or rewrite — pin that the encoder gets there
/// first and the result stays a well-formed URL.
#[test]
fn test_path_injection_encodes_carriage_return() {
    let base = make_url("https://example.com/a/b");
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
    let out = build_injected_url(&base, &param, "a\rb");
    assert!(
        out.contains("%0D"),
        "CR must be percent-encoded, got: {out}"
    );
    assert!(!out.contains('\r'), "raw CR must not survive: {out:?}");
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

/// The append branch (param absent from the original query) has one arm per
/// position, and only `Last` was covered. `First`/`Both` emit the *same*
/// pair ordering as their replace-branch counterparts — a mismatch here would
/// mean `--hpp` silently probes only one real ordering on mined/dictionary
/// params, which are exactly the ones absent from the URL.
#[test]
fn test_hpp_absent_param_appended_first_position() {
    let base = make_url("https://example.com/path?other=1");
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
    let out = build_hpp_url(&base, &param, "XSS", HppPosition::First).unwrap();
    assert_eq!(out, "https://example.com/path?other=1&q=XSS&q=safe");
}

#[test]
fn test_hpp_absent_param_appended_both_position() {
    let base = make_url("https://example.com/path?other=1");
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
    let out = build_hpp_url(&base, &param, "XSS", HppPosition::Both).unwrap();
    assert_eq!(out, "https://example.com/path?other=1&q=XSS&q=XSS");
}

/// Appending onto a URL with *no* existing query must not emit a leading `&`
/// (`?&q=...`), which several servers parse as an empty first parameter and
/// which would make the whole HPP probe malformed.
#[test]
fn test_hpp_absent_param_appended_on_bare_url_has_no_leading_amp() {
    let base = make_url("https://example.com/path");
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
    for (position, expected) in [
        (HppPosition::Last, "https://example.com/path?q=safe&q=XSS"),
        (HppPosition::First, "https://example.com/path?q=XSS&q=safe"),
        (HppPosition::Both, "https://example.com/path?q=XSS&q=XSS"),
    ] {
        let out = build_hpp_url(&base, &param, "XSS", position).unwrap();
        assert_eq!(out, expected, "position {:?}", position);
    }
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
fn body_location_method_forces_post_for_bodyless_verbs() {
    for verb in ["GET", "get", "HEAD", "OPTIONS", "TRACE", "", "  "] {
        assert_eq!(
            body_location_method(verb),
            reqwest::Method::POST,
            "expected POST for body-less verb {verb:?}"
        );
    }
}

#[test]
fn body_location_method_preserves_body_capable_verbs() {
    for (verb, expected) in [
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("PATCH", "PATCH"),
        ("DELETE", "DELETE"),
        ("QUERY", "QUERY"),
        ("query", "QUERY"),
        ("  Query ", "QUERY"),
    ] {
        assert_eq!(
            body_location_method(verb).as_str(),
            expected,
            "expected {expected} for {verb:?}"
        );
    }
}

#[test]
fn effective_method_body_locations_respect_query_method() {
    let mut param = Param {
        name: "q".into(),
        value: "".into(),
        location: Location::Body,
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
    for loc in [Location::Body, Location::JsonBody, Location::MultipartBody] {
        param.location = loc;
        assert_eq!(effective_method("QUERY", &param), "QUERY");
        assert_eq!(effective_method("GET", &param), "POST");
        assert_eq!(effective_method("PUT", &param), "PUT");
    }
    param.location = Location::Query;
    assert_eq!(effective_method("QUERY", &param), "QUERY");
    assert_eq!(effective_method("GET", &param), "GET");
}

#[test]
fn form_discovered_body_params_always_post_even_on_query_target() {
    // HTML forms submit as POST regardless of how the page was loaded
    // (QUERY/PUT/…). Without this, -X QUERY would mis-verb form fields.
    let mut param = Param {
        name: "comment".into(),
        value: "".into(),
        location: Location::Body,
        injection_context: None,
        valid_specials: None,
        invalid_specials: None,
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: Some("https://example.com/submit".to_string()),
        form_origin_url: Some("https://example.com/page".to_string()),
        framework_sink: None,
        escaped_specials: None,
        js_breakout: None,
    };
    for loc in [Location::Body, Location::JsonBody, Location::MultipartBody] {
        param.location = loc;
        assert_eq!(
            body_location_method_for_param("QUERY", &param),
            reqwest::Method::POST
        );
        assert_eq!(effective_method("QUERY", &param), "POST");
        assert_eq!(effective_method("PUT", &param), "POST");
    }
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

// --- Shared body-injection helpers -----------------------------------------
// These consolidate logic that was previously copy-pasted across the
// reflection / light-verify / DOM-verify / PoC / probe builders. Cover the
// replace-vs-append and no-data branches so the single source of truth stays
// honest.

#[test]
fn urlencoded_body_replaces_existing_value() {
    let out = urlencoded_body(Some("a=1&b=2"), "a", "PAY");
    assert_eq!(out, "a=PAY&b=2");
}

#[test]
fn urlencoded_body_appends_when_absent() {
    let out = urlencoded_body(Some("a=1"), "b", "PAY");
    assert_eq!(out, "a=1&b=PAY");
}

#[test]
fn urlencoded_body_no_data_encodes_pair() {
    let out = urlencoded_body(None, "q", "a b&c");
    assert_eq!(out, "q=a%20b%26c");
}

#[test]
fn urlencoded_body_only_replaces_exact_name_not_substring() {
    // `id` must not rewrite `userid`.
    let out = urlencoded_body(Some("userid=9&id=1"), "id", "PAY");
    assert_eq!(out, "userid=9&id=PAY");
}

#[test]
fn json_body_inserts_into_object() {
    let out = json_body(Some(r#"{"a":"1"}"#), "b", "", "PAY");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["a"], "1");
    assert_eq!(v["b"], "PAY");
}

#[test]
fn json_body_empty_param_value_reserializes_not_splices() {
    // A non-JSON body with an empty param value must NOT go through
    // `str::replace("")`, which would splice the payload between every byte.
    let out = json_body(Some("not json"), "q", "", "PAY");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["q"], "PAY");
}

#[test]
fn json_body_non_empty_param_value_textual_replace() {
    let out = json_body(Some("prefix ORIG suffix"), "q", "ORIG", "PAY");
    assert_eq!(out, "prefix PAY suffix");
}

#[test]
fn json_body_no_data_builds_object() {
    let out = json_body(None, "q", "", "PAY");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["q"], "PAY");
}

// ---------------------------------------------------------------------------
// Cookie params are headers by Location but must be injected into `Cookie`.
// ---------------------------------------------------------------------------

#[test]
fn test_param_is_cookie_distinguishes_cookies_from_headers() {
    let target = cookie_target(&[("session", "abc")]);
    let cookie_param = make_param(Location::Header, "session");
    let header_param = make_param(Location::Header, "X-Forwarded-For");
    // Same name, but a query param is never a cookie.
    let query_param = make_param(Location::Query, "session");

    assert!(param_is_cookie(&target, &cookie_param));
    assert!(!param_is_cookie(&target, &header_param));
    assert!(!param_is_cookie(&target, &query_param));
}

#[test]
fn test_build_header_request_routes_cookie_params_into_the_cookie_header() {
    // Regression: a cookie param used to be injected as an HTTP header named
    // after the cookie (`session: <payload>`), which the application never
    // reads — so the payload never reached the sink, no reflection was seen,
    // and the parameter was dropped. A page reflecting the FIRST of three
    // cookies was detected when it was the only cookie and missed entirely
    // once two others followed it.
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = cookie_target(&[("first", "a"), ("second", "b")]);
    let param = make_param(Location::Header, "first");
    let req = build_header_request(&client, &target, &param, "PAYLOAD", reqwest::Method::GET)
        .build()
        .expect("request builds");

    let cookie = req
        .headers()
        .get(reqwest::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("a Cookie header is set");

    // The payload lands on the right cookie...
    assert!(
        cookie.contains("first=PAYLOAD"),
        "payload must be injected into the cookie, got: {cookie}"
    );
    // ...the neighbours survive, so the app still renders the sink...
    assert!(
        cookie.contains("second=b"),
        "other cookies must be preserved, got: {cookie}"
    );
    // ...and no header named after the cookie is added.
    assert!(
        req.headers().get("first").is_none(),
        "a cookie param must not become a header of the same name"
    );
}

#[test]
fn test_build_header_request_still_sets_plain_headers() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = cookie_target(&[("session", "abc")]);
    let param = make_param(Location::Header, "X-Forwarded-For");
    let req = build_header_request(&client, &target, &param, "PAYLOAD", reqwest::Method::GET)
        .build()
        .expect("request builds");

    assert_eq!(
        req.headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok()),
        Some("PAYLOAD")
    );
}

/// A `Body` injection must declare `application/x-www-form-urlencoded`.
///
/// Regression: the reflection and DOM-verify paths set this, but the
/// light-verify path built its own request and omitted it. A form-parsing
/// server given a body with no `Content-Type` never binds the parameter, so
/// the payload never reached the sink and light verification reported a
/// negative — a silent false negative on every `Body` param it re-checked.
/// All three paths now share `build_inject_request`, so the header is set once.
#[test]
fn test_build_inject_request_body_sets_urlencoded_content_type() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = crate::target_parser::parse_target("http://example.test/").expect("target");
    let param = make_param(Location::Body, "q");
    let req = build_inject_request(&client, &target, &param, "PAYLOAD")
        .build()
        .expect("request builds");

    assert_eq!(
        req.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-www-form-urlencoded"),
        "a urlencoded body must declare its Content-Type or the server won't parse it"
    );
    let body = req
        .body()
        .and_then(|b| b.as_bytes())
        .map(|b| String::from_utf8_lossy(b).to_string())
        .expect("a body is sent");
    assert!(
        body.contains("q=PAYLOAD"),
        "payload must be in the body: {body}"
    );
}

/// A `JsonBody` injection must declare `application/json`.
#[test]
fn test_build_inject_request_json_body_sets_json_content_type() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = crate::target_parser::parse_target("http://example.test/").expect("target");
    let param = make_param(Location::JsonBody, "q");
    let req = build_inject_request(&client, &target, &param, "PAYLOAD")
        .build()
        .expect("request builds");

    assert_eq!(
        req.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
}

/// Multipart must NOT get a hand-written `Content-Type`: reqwest derives it
/// from the form so it carries the generated boundary. Overriding it with a
/// bare `multipart/form-data` would make the body unparseable.
#[test]
fn test_build_inject_request_multipart_keeps_generated_boundary() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = crate::target_parser::parse_target("http://example.test/").expect("target");
    let param = make_param(Location::MultipartBody, "q");
    let req = build_inject_request(&client, &target, &param, "PAYLOAD")
        .build()
        .expect("request builds");

    let ct = req
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .expect("multipart sets a Content-Type");
    assert!(
        ct.starts_with("multipart/form-data; boundary="),
        "multipart Content-Type must carry the boundary, got: {ct}"
    );
}

/// A cookie param routes to the `Cookie` header, not a same-named header —
/// the dispatcher must keep delegating `Header` to `build_header_request`.
#[test]
fn test_build_inject_request_header_location_routes_cookies() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = cookie_target(&[("session", "abc")]);
    let param = make_param(Location::Header, "session");
    let req = build_inject_request(&client, &target, &param, "PAYLOAD")
        .build()
        .expect("request builds");

    assert!(
        req.headers()
            .get(reqwest::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.contains("session=PAYLOAD")),
        "a cookie param must be injected into the Cookie header"
    );
    assert!(req.headers().get("session").is_none());
}

/// Query injection puts the payload in the URL and leaves headers alone.
#[test]
fn test_build_inject_request_query_injects_into_url() {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let target = crate::target_parser::parse_target("http://example.test/?q=1").expect("target");
    let param = make_param(Location::Query, "q");
    let req = build_inject_request(&client, &target, &param, "PAYLOAD")
        .build()
        .expect("request builds");

    assert!(
        req.url().as_str().contains("q=PAYLOAD"),
        "payload must be in the query string, got: {}",
        req.url()
    );
}

/// A target carrying `cookies`, for the cookie-injection tests above.
fn cookie_target(cookies: &[(&str, &str)]) -> Target {
    let mut target = crate::target_parser::parse_target("http://example.test/").expect("target");
    target.cookies = cookies
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    target
}

/// Minimal `Param` for the cookie-injection tests above.
fn make_param(location: Location, name: &str) -> Param {
    Param {
        name: name.into(),
        value: "".into(),
        location,
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
    }
}
