use super::*;
use crate::target_parser::parse_target;
use axum::{Router, extract::Query, response::Html, routing::get};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::{Duration, sleep};

fn default_scan_args() -> ScanArgs {
    ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec!["http://127.0.0.1:1".to_string()],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: 1,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 1,
        max_concurrent_targets: 1,
        max_targets_per_host: 1,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

#[test]
fn test_mining_sample_stats_collapses_after_sustained_reflection() {
    let mut stats = MiningSampleStats::new();
    assert!(!stats.should_collapse());

    for _ in 0..15 {
        stats.record_attempt();
        stats.record_reflection();
    }

    assert!(stats.reflections >= 5);
    assert!(stats.attempts >= 15);
    assert!(stats.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD);
    assert!(stats.should_collapse());
}

#[test]
fn test_mining_sample_stats_non_reflection_keeps_low_ewma() {
    let mut stats = MiningSampleStats::new();
    for _ in 0..20 {
        stats.record_attempt();
        stats.record_non_reflection();
    }
    assert_eq!(stats.reflections, 0);
    assert!(!stats.should_collapse());
}

#[test]
fn test_detect_injection_context_without_marker_is_html() {
    let ctx = detect_injection_context("<html><body>plain</body></html>");
    assert_eq!(ctx, InjectionContext::Html(None));
}

#[test]
fn test_detect_injection_context_comment_delimiter() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<!-- {} -->", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(ctx, InjectionContext::Html(Some(DelimiterType::Comment)));
}

#[test]
fn test_detect_injection_context_script_single_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var x='{}';</script>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote))
    );
}

#[test]
fn test_detect_injection_context_script_backtick_template_literal() {
    // Reflection inside a JS template literal (backtick-quoted string)
    // must report Backtick so the payload generator emits `${…}` breakouts
    // instead of the `'`/`"` escapes that don't apply.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var content = `{}`;</script>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::Backtick))
    );
}

#[test]
fn test_detect_injection_context_script_backtick_wins_over_earlier_quote() {
    // When both an earlier `'`/`"` and a backtick precede the marker, the
    // closer (innermost) one is the actual surrounding delimiter.
    // Regression: a naive max-position scan that only considered `'`/`"`
    // would mislabel this as DoubleQuote.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var s = \"x\"; var t = `{}`;</script>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::Backtick))
    );
}

#[test]
fn test_detect_js_breakout_bare_double_quote_string() {
    // Reflection inside a plain double-quoted JS string: the closer is just the
    // quote that returns to statement position.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var x = \"{}\";</script>", marker);
    assert_eq!(detect_js_breakout(&body).as_deref(), Some("\""));
}

#[test]
fn test_detect_js_breakout_nested_call_array_object() {
    // The motivating case from issue #1073: a reflection nested inside an open
    // string, array, object and call. The exact closer derived from the *real*
    // observed prefix must close all of them: `"` then `]` `}` `)`.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>foo({{ bar: [ \"{}\" ] }});</script>", marker);
    assert_eq!(detect_js_breakout(&body).as_deref(), Some("\"]})"));
}

#[test]
fn test_detect_js_breakout_uses_observed_prefix_not_fixed_shell() {
    // A nesting shape the fixed depth-0–3 catalog does NOT enumerate
    // (array-of-array-of-object inside a call) — only an observed-prefix
    // computation reaches it, proving the wiring is prefix-derived.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>g([[{{k:\"{}\"}}]]);</script>", marker);
    // open: ( [ [ { "  -> close: " } ] ] )
    assert_eq!(detect_js_breakout(&body).as_deref(), Some("\"}]])"));
}

#[test]
fn test_detect_js_breakout_template_literal() {
    // Inside a backtick template literal the closer is the backtick.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>tag(`hi {}`);</script>", marker);
    assert_eq!(detect_js_breakout(&body).as_deref(), Some("`)"));
}

#[test]
fn test_detect_js_breakout_none_outside_script() {
    // A reflection in HTML text (not inside <script>) has no JS breakout — the
    // script-tag requirement scopes the carrier to inline-script contexts.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<div>{}</div>", marker);
    assert_eq!(detect_js_breakout(&body), None);
}

#[test]
fn test_detect_js_breakout_none_at_statement_position() {
    // Marker already at statement position (raw JS, no open string/structure):
    // empty closer -> None, so synthesis falls back to the raw-JS catalog.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var x = 1; {}</script>", marker);
    assert_eq!(detect_js_breakout(&body), None);
}

#[test]
fn test_detect_js_breakout_none_after_closing_script() {
    // Marker sits AFTER a closed <script> (between scripts). The </script>
    // guard rejects it rather than computing a bogus closer from the prior
    // script body.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<script>var a = 1;</script><div>{}</div>", marker);
    assert_eq!(detect_js_breakout(&body), None);
}

#[test]
fn test_detect_js_breakout_with_marker_custom() {
    // The explicit-marker variant used by the numeric-only discovery probe.
    let body = "<script>h([\"4815162342\"]);</script>";
    // prefix `h(["` opens ( [ and the string → close `"` `]` `)`.
    assert_eq!(
        detect_js_breakout_with_marker(body, "4815162342").as_deref(),
        Some("\"])")
    );
}

#[test]
fn test_detect_js_breakout_picks_innermost_script_opener() {
    // With an earlier closed <script> and a second open one containing the
    // marker, `rfind("<script")` lands on the second opener, so the prefix is
    // local to the script the marker actually lives in.
    let marker = crate::scanning::markers::open_marker();
    let body = format!(
        "<script>var done = true;</script>\n<script>obj({{a:\"{}\"</script>",
        marker
    );
    assert_eq!(detect_js_breakout(&body).as_deref(), Some("\"})"));
}

#[test]
fn test_detect_injection_context_attribute_double_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<img alt=\"{}\">", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote))
    );
}

#[test]
fn test_detect_injection_context_attribute_name_slot() {
    // Reflection lands as a free attribute *name* inside an existing tag
    // (e.g. `<div id='x' MARKER>`). The HTML5 parser treats MARKER as a
    // boolean attribute, so the value-side scan finds nothing — but the
    // position is exploitable via bare event-handler attributes
    // (`onmouseover=alert(1)`). Classifying as Attribute(None) routes
    // payload generation to the unquoted-attribute branch that emits
    // them; previously this fell through to Html(None) and dalfox tried
    // `<svg…>` tag payloads that just become more attribute names.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<div id='x' {}>more</div>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(ctx, InjectionContext::Attribute(None));
}

#[test]
fn test_detect_injection_context_url_attribute_double_quote() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<iframe src=\"{}\"></iframe>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote))
    );
}

#[test]
fn test_detect_injection_context_onload_attribute_is_javascript() {
    // Event-handler attributes (`on*`) hold JavaScript source, not
    // HTML — escaping `'` / `"` produces JS-breakout payloads. Regression
    // for xss-game level 4: marker lives inside
    // `<img onload="startTimer('MARKER');">` and was previously
    // bucketed as `Attribute(SingleQuote)`, so the scanner sent HTML
    // tag breakouts that the browser serialised back into the JS
    // string instead of executing.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<img onload=\"startTimer('{}');\">", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::SingleQuote))
    );
}

#[test]
fn test_detect_injection_context_onerror_double_quote_is_javascript() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<img src=x onerror='alert(\"{}\")'>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Javascript(Some(DelimiterType::DoubleQuote))
    );
}

#[test]
fn test_detect_injection_context_non_on_attribute_stays_attribute() {
    // Confirm we didn't accidentally promote regular attribute echoes.
    // `on` prefix alone isn't enough — needs a full handler name.
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<input value=\"{}\" name=\"ones\">", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(
        ctx,
        InjectionContext::Attribute(Some(DelimiterType::DoubleQuote))
    );
}

// --- Framework innerHTML sink detection ---

#[test]
fn test_framework_html_sink_recognises_vue_v_html() {
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div v-html=\"{}\"></div>", marker);
    assert_eq!(detect_framework_html_sink(&body, marker), Some("v-html"));
}

#[test]
fn test_framework_html_sink_rejects_quoted_html_substring_in_data_bind() {
    // `data-bind="text: 'html: link'"` shares the `html:` substring
    // with a real innerHTML sink clause but lives inside a quoted
    // string — Knockout binds `text:` here, not `html:`. The
    // boundary-aware parser must skip the false positive.
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div data-bind=\"text: 'html: {} link'\"></div>", marker);
    assert_eq!(detect_framework_html_sink(&body, marker), None);
}

#[test]
fn test_framework_html_sink_recognises_data_bind_html_after_comma() {
    // Multi-clause `data-bind` where `html:` is the second binding.
    // The clause boundary detector must accept `,` and whitespace
    // before `html:`, not just position 0.
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div data-bind=\"text: name, html: '{}'\"></div>", marker);
    assert_eq!(detect_framework_html_sink(&body, marker), Some("data-bind"));
}

#[test]
fn test_framework_html_sink_recognises_knockout_html_clause() {
    // Knockout `data-bind` accepts multiple clauses. Only the `html:`
    // clause maps to innerHTML — pure `text:` bindings escape input
    // and should not be tagged as a sink.
    let marker = crate::scanning::markers::bracketed_marker();
    let html_bind = format!("<div data-bind=\"html: '{}'\"></div>", marker);
    assert_eq!(
        detect_framework_html_sink(&html_bind, marker),
        Some("data-bind")
    );

    let text_bind = format!("<div data-bind=\"text: '{}'\"></div>", marker);
    assert_eq!(detect_framework_html_sink(&text_bind, marker), None);
}

#[test]
fn test_framework_html_sink_recognises_angular_ng_bind_html() {
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div ng-bind-html=\"{}\"></div>", marker);
    assert_eq!(
        detect_framework_html_sink(&body, marker),
        Some("ng-bind-html")
    );
}

#[test]
fn test_framework_html_sink_recognises_angular_property_binding() {
    // Angular 2+ uses `[innerHTML]` for property binding to innerHTML.
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div [innerHTML]=\"{}\"></div>", marker);
    assert_eq!(
        detect_framework_html_sink(&body, marker),
        Some("ng-bind-html")
    );
}

#[test]
fn test_framework_html_sink_ignores_plain_text_reflection() {
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<div>Hello {}</div>", marker);
    assert_eq!(detect_framework_html_sink(&body, marker), None);
}

#[test]
fn test_framework_html_sink_ignores_non_sink_attribute() {
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!("<input value=\"{}\">", marker);
    assert_eq!(detect_framework_html_sink(&body, marker), None);
}

#[test]
fn test_framework_html_sink_returns_none_for_missing_marker() {
    let marker = crate::scanning::markers::bracketed_marker();
    assert_eq!(
        detect_framework_html_sink("<html><body>no marker</body></html>", marker),
        None
    );
}

#[test]
fn test_framework_html_sink_rejects_mixed_attribute_sinks() {
    // Marker shows up in BOTH `v-html` AND `ng-bind-html`. The
    // exploitation path is ambiguous, so we conservatively return
    // None and fall back to the generic attribute label.
    let marker = crate::scanning::markers::bracketed_marker();
    let body = format!(
        "<div v-html=\"{}\"></div><div ng-bind-html=\"{}\"></div>",
        marker, marker
    );
    assert_eq!(detect_framework_html_sink(&body, marker), None);
}

#[tokio::test]
async fn test_probe_dictionary_params_returns_when_wordlist_file_missing() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.mining_dict_word = Some("/definitely/not/found/dalfox-wordlist.txt".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    probe_dictionary_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_probe_body_params_without_data_is_noop() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

    probe_body_params(&target, &args, reflection_params.clone(), semaphore, None).await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_probe_json_body_params_returns_for_invalid_or_non_object_data() {
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

    let mut invalid_json_args = default_scan_args();
    invalid_json_args.data = Some("{not-json".to_string());
    probe_json_body_params(
        &target,
        &invalid_json_args,
        reflection_params.clone(),
        semaphore.clone(),
        None,
    )
    .await;
    assert!(reflection_params.lock().await.is_empty());

    let mut non_object_json_args = default_scan_args();
    non_object_json_args.data = Some("[1,2,3]".to_string());
    probe_json_body_params(
        &target,
        &non_object_json_args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_mine_parameters_skip_mining_leaves_params_untouched() {
    let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = true;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_mine_parameters_dom_only_on_unreachable_target_does_not_panic() {
    let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = false;
    args.skip_mining_dict = true;
    args.skip_mining_dom = false;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    assert!(reflection_params.lock().await.is_empty());
}

async fn dom_mining_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let marker = params.get("search").cloned().unwrap_or_default();
    Html(format!(
        "<form><input id=\"search\" name=\"search\" value=\"seed\"></form><div>{}</div>",
        marker
    ))
}

async fn start_dom_mining_server() -> SocketAddr {
    let app = Router::new().route("/dom-mining", get(dom_mining_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_response_id_params_discovers_reflected_input_name() {
    let addr = start_dom_mining_server().await;
    let target = parse_target(&format!("http://{}:{}/dom-mining", addr.ip(), addr.port()))
        .expect("parse target");
    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

    probe_response_id_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(params.iter().any(|p| {
        p.name == "search"
            && p.location == Location::Query
            && p.value == crate::scanning::markers::bracketed_marker()
    }));
}

// --- Context detection: CSS / HTML text / inner-marker / empty marker ---

#[test]
fn test_detect_injection_context_css_style_block() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!(
        "<html><head><style>.x{{ color: \"{}\"; }}</style></head></html>",
        marker
    );
    let ctx = detect_injection_context(&body);
    assert!(
        matches!(ctx, InjectionContext::Css(_)),
        "expected Css context, got {:?}",
        ctx
    );
}

#[test]
fn test_detect_injection_context_plain_html_text_node() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<html><body><div>{}</div></body></html>", marker);
    let ctx = detect_injection_context(&body);
    assert_eq!(ctx, InjectionContext::Html(None));
}

#[test]
fn test_detect_injection_context_uses_inner_marker_branch() {
    // bracketed_marker() embeds inner_marker(), exercising the
    // inner-marker fast path in detect_injection_context.
    let body = format!(
        "<html><body><p>{}</p></body></html>",
        crate::scanning::markers::bracketed_marker()
    );
    let ctx = detect_injection_context(&body);
    assert_eq!(ctx, InjectionContext::Html(None));
}

#[test]
fn test_detect_injection_context_with_marker_returns_html_when_marker_missing() {
    let ctx = detect_injection_context_with_marker("<html></html>", "ZZ_NOT_PRESENT_ZZ");
    assert_eq!(ctx, InjectionContext::Html(None));
}

#[test]
fn test_framework_html_sink_returns_none_for_empty_marker() {
    assert_eq!(
        detect_framework_html_sink("<div v-html=\"x\"></div>", ""),
        None
    );
}

// --- Pure-helper coverage: make_any_query_param / collapse_to_any_query_param ---

#[test]
fn test_make_any_query_param_fills_classification_and_context() {
    let marker = crate::scanning::markers::open_marker();
    let body = format!("<div>{} '\"<>(){{}}</div>", marker);
    let p = make_any_query_param(&body);
    assert_eq!(p.name, "any");
    assert_eq!(p.location, Location::Query);
    assert_eq!(p.value, crate::scanning::markers::bracketed_marker());
    // Marker lives in a plain text node here, so context is generic HTML.
    assert_eq!(p.injection_context, Some(InjectionContext::Html(None)));
    let valid = p.valid_specials.expect("valid specials populated");
    let invalid = p.invalid_specials.expect("invalid specials populated");
    // Specials seen in body should be in `valid`; absent ones in `invalid`.
    assert!(valid.contains(&'<'));
    assert!(valid.contains(&'>'));
    assert!(invalid.contains(&'\\'));
}

#[tokio::test]
async fn test_collapse_to_any_query_param_keeps_non_query_and_replaces_query() {
    let initial = vec![
        Param {
            name: "q_old".into(),
            value: "v".into(),
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
        },
        Param {
            name: "q_old_2".into(),
            value: "v".into(),
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
        },
        Param {
            name: "h".into(),
            value: "hv".into(),
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
        },
    ];
    let params = Arc::new(Mutex::new(initial));
    collapse_to_any_query_param(params.clone(), "<html></html>").await;
    let guard = params.lock().await;
    assert_eq!(guard.len(), 2);
    assert!(
        guard
            .iter()
            .any(|p| p.name == "h" && p.location == Location::Header)
    );
    let any_q = guard
        .iter()
        .find(|p| p.location == Location::Query)
        .expect("any query param present");
    assert_eq!(any_q.name, "any");
}

// --- Server-driven coverage for probe_* functions ---

/// RAII guard that writes a wordlist to a unique temp path and removes
/// it on drop — so panicking assertions don't leak files into temp_dir.
struct TempWordlist {
    path: std::path::PathBuf,
}

impl TempWordlist {
    fn new(tag: &str, contents: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "dalfox-test-{}-{}-{}.txt",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::write(&path, contents).expect("write wordlist");
        Self { path }
    }
    fn as_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempWordlist {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn reflect_all_query_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let mut body = String::from("<html><body>");
    for (_, v) in params.iter() {
        body.push_str(&format!("<div>{}</div>", v));
    }
    body.push_str("</body></html>");
    Html(body)
}

async fn start_reflect_all_server() -> SocketAddr {
    let app = Router::new().route("/r", get(reflect_all_query_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_dictionary_params_discovers_with_custom_wordlist() {
    let addr = start_reflect_all_server().await;
    let target =
        parse_target(&format!("http://{}:{}/r", addr.ip(), addr.port())).expect("parse target");

    // Small wordlist (<= SENTINEL_PROBE_COUNT*5) → sentinel pre-probe is skipped.
    let wordlist = TempWordlist::new("wordlist", "foo\nbar\nbaz\n");

    let mut args = default_scan_args();
    args.mining_dict_word = Some(wordlist.as_str());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    probe_dictionary_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.name == "foo" && p.location == Location::Query),
        "expected 'foo' to be discovered, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_probe_dictionary_params_sentinel_pre_probe_collapses() {
    let addr = start_reflect_all_server().await;
    let target =
        parse_target(&format!("http://{}:{}/r", addr.ip(), addr.port())).expect("parse target");

    // Wordlist length > SENTINEL_PROBE_COUNT*5 triggers sentinel pre-probe.
    // The server reflects every query param, so every sentinel reflects and
    // pre_collapse_query_probe returns Some(..) → mining short-circuits to `any`.
    let mut words = String::new();
    for i in 0..50 {
        words.push_str(&format!("p_{}\n", i));
    }
    let wordlist = TempWordlist::new("collapse-wordlist", &words);

    let mut args = default_scan_args();
    args.mining_dict_word = Some(wordlist.as_str());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    probe_dictionary_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    // After sentinel collapse with an empty starting set we expect exactly
    // one synthetic 'any' Query param — nothing from the wordlist iteration.
    assert_eq!(
        params.len(),
        1,
        "expected exactly one param after collapse, got {:?}",
        params
    );
    let only = &params[0];
    assert_eq!(only.name, "any");
    assert_eq!(only.location, Location::Query);
}

async fn reflect_body_handler(body: axum::body::Bytes) -> Html<String> {
    let s = String::from_utf8_lossy(&body).into_owned();
    let pairs: Vec<(String, String)> = form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut body = String::from("<html><body>");
    for (_, v) in pairs {
        body.push_str(&format!("<div>{}</div>", v));
    }
    body.push_str("</body></html>");
    Html(body)
}

async fn start_body_reflect_server() -> SocketAddr {
    let app = Router::new().route("/b", axum::routing::post(reflect_body_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_body_params_discovers_reflected_form_field() {
    let addr = start_body_reflect_server().await;
    let target =
        parse_target(&format!("http://{}:{}/b", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.data = Some("user=alice&token=t".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    probe_body_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.location == Location::Body && (p.name == "user" || p.name == "token")),
        "expected a body param discovered, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

async fn reflect_json_handler(body: axum::body::Bytes) -> Html<String> {
    let s = String::from_utf8_lossy(&body).into_owned();
    let parsed: serde_json::Value =
        serde_json::from_str(&s).unwrap_or(serde_json::Value::Object(Default::default()));
    let mut body = String::from("<html><body>");
    if let Some(obj) = parsed.as_object() {
        for (_, v) in obj {
            if let Some(s) = v.as_str() {
                body.push_str(&format!("<div>{}</div>", s));
            }
        }
    }
    body.push_str("</body></html>");
    Html(body)
}

async fn start_json_reflect_server() -> SocketAddr {
    let app = Router::new().route("/j", axum::routing::post(reflect_json_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_json_body_params_discovers_reflected_top_level_key() {
    let addr = start_json_reflect_server().await;
    let target =
        parse_target(&format!("http://{}:{}/j", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.data = Some(r#"{"name":"a","tag":"b"}"#.to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    probe_json_body_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.location == Location::JsonBody && (p.name == "name" || p.name == "tag")),
        "expected a JSON-body param discovered, got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_mine_parameters_runs_dom_against_reflecting_server() {
    let addr = start_dom_mining_server().await;
    let mut target = parse_target(&format!("http://{}:{}/dom-mining", addr.ip(), addr.port()))
        .expect("parse target");
    let mut args = default_scan_args();
    // Skip dictionary mining (uses default GF list — slow + irrelevant here),
    // exercise the DOM mining branch of `mine_parameters` end-to-end.
    args.skip_mining = false;
    args.skip_mining_dict = true;
    args.skip_mining_dom = false;

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params.iter().any(|p| p.name == "search"),
        "expected DOM mining to discover 'search', got {:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_mine_parameters_seeds_explicit_body_params_under_skip_mining() {
    // Regression: `--skip-mining` switches off *discovery* of parameters the
    // user did not name, but body params supplied via `-d` are explicit input.
    // They have no entry point other than the body probes, so skipping them
    // dropped the entire POST/JSON body surface — even with `-p name:body`.
    let addr = start_body_reflect_server().await;
    let mut target =
        parse_target(&format!("http://{}:{}/b", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = true;
    args.method = "POST".to_string();
    args.data = Some("user=alice&token=t".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.location == Location::Body && (p.name == "user" || p.name == "token")),
        "explicit -d body params must be seeded even under --skip-mining, got {:?}",
        params
            .iter()
            .map(|p| (&p.name, &p.location))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_mine_parameters_seeds_explicit_body_params_under_skip_mining_dict() {
    // `--skip-mining-dict` skips the slow dictionary brute-force but must not
    // drop explicit `-d` body params (they used to live inside that gate).
    let addr = start_body_reflect_server().await;
    let mut target =
        parse_target(&format!("http://{}:{}/b", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = false;
    args.skip_mining_dict = true;
    args.skip_mining_dom = true;
    args.method = "POST".to_string();
    args.data = Some("user=alice&token=t".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.location == Location::Body && (p.name == "user" || p.name == "token")),
        "explicit -d body params must be seeded even under --skip-mining-dict, got {:?}",
        params
            .iter()
            .map(|p| (&p.name, &p.location))
            .collect::<Vec<_>>()
    );
}

async fn reflect_raw_body_handler(body: axum::body::Bytes) -> Html<String> {
    // Echo the raw request body. A multipart/form-data body carries each text
    // field's value verbatim, so the probe marker shows up in the response.
    Html(format!(
        "<html><body>{}</body></html>",
        String::from_utf8_lossy(&body)
    ))
}

async fn start_raw_body_reflect_server() -> SocketAddr {
    let app = Router::new().route("/r", axum::routing::post(reflect_raw_body_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn test_probe_multipart_params_seeds_explicit_field() {
    // `-p file:multipart` is a known multipart sink. Before, MultipartBody
    // params were only seeded from discovered HTML forms, so this explicit
    // injection point had no entry point. Now `-d` + `-p :multipart` seeds it.
    let addr = start_raw_body_reflect_server().await;
    let target =
        parse_target(&format!("http://{}:{}/r", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.method = "POST".to_string();
    args.data = Some("file=a&other=b".to_string());
    args.param = vec!["file:multipart".to_string()];

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    probe_multipart_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.name == "file" && p.location == Location::MultipartBody),
        "explicit -p file:multipart must seed a MultipartBody param, got {:?}",
        params
            .iter()
            .map(|p| (&p.name, &p.location))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_probe_multipart_params_noop_without_multipart_spec() {
    // Multipart is opt-in: with `-d` but no `-p :multipart`, this is a no-op
    // (we don't re-send every body as multipart).
    let target = parse_target("http://127.0.0.1:1").expect("parse target");
    let mut args = default_scan_args();
    args.data = Some("file=a".to_string());

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    probe_multipart_params(&target, &args, reflection_params.clone(), semaphore, None).await;
    assert!(reflection_params.lock().await.is_empty());
}

#[tokio::test]
async fn test_mine_parameters_multipart_survives_same_named_body_param() {
    // `-d file=a -p file:multipart`: `probe_body_params` seeds `file` as a Body
    // param from the same `-d`, but the multipart slot must still be seeded —
    // otherwise the `-p file:multipart` location filter drops the Body entry
    // and nothing is left to scan.
    let addr = start_raw_body_reflect_server().await;
    let mut target =
        parse_target(&format!("http://{}:{}/r", addr.ip(), addr.port())).expect("parse target");
    let mut args = default_scan_args();
    args.skip_mining = true;
    args.method = "POST".to_string();
    args.data = Some("file=a".to_string());
    args.param = vec!["file:multipart".to_string()];

    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
    mine_parameters(
        &mut target,
        &args,
        reflection_params.clone(),
        semaphore,
        None,
    )
    .await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.name == "file" && p.location == Location::MultipartBody),
        "multipart slot for `file` must be seeded even when a Body `file` exists, got {:?}",
        params
            .iter()
            .map(|p| (&p.name, &p.location))
            .collect::<Vec<_>>()
    );
}
