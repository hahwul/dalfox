use super::*;

#[test]
fn test_extract_javascript_from_html() {
    let html = r#"
<html>
<head>
<script>
    var x = 1;
</script>
</head>
<body>
<script>
    let y = location.search;
    document.getElementById('foo').innerHTML = y;
</script>
</body>
</html>
"#;
    let js_code = extract_javascript_from_html(html);
    assert_eq!(js_code.len(), 2);
    assert!(js_code[1].contains("location.search"));
}

#[test]
fn test_analyze_javascript_for_dom_xss() {
    let js = r#"
let param = location.search;
document.getElementById('x').innerHTML = param;
"#;
    let findings = analyze_javascript_for_dom_xss(js, "https://example.com");
    assert!(!findings.is_empty());
    let (_vuln, payload, description) = &findings[0];
    assert!(description.contains("DOM-based XSS"));
    assert!(description.contains("innerHTML"));
    assert!(payload.contains("alert"));
}

#[test]
fn test_generate_dom_xss_poc_for_urlsearchparams_source() {
    let (payload, description) = generate_dom_xss_poc("URLSearchParams.get(query)", "innerHTML");
    assert_eq!(
        payload,
        "query=<img src=x onerror=alert(1) class=dalfox>"
            .replace("dalfox", crate::scanning::markers::class_marker())
    );
    assert!(description.contains("URLSearchParams.get(query)"));
}

#[test]
fn test_generate_dom_xss_poc_for_nested_urlsearchparams_source() {
    let (payload, description) =
        generate_dom_xss_poc("URLSearchParams.get(blob).get(query)", "innerHTML");
    assert_eq!(
        payload,
        "query=<img src=x onerror=alert(1) class=dalfox>"
            .replace("dalfox", crate::scanning::markers::class_marker())
    );
    assert!(description.contains("URLSearchParams.get(blob).get(query)"));
}

#[test]
fn test_generate_dom_xss_poc_hash_to_src_sink_uses_data_uri() {
    // xss-game L6 shape: `script.src = location.hash.substr(1)`. The
    // HTML payload `<img onerror>` doesn't execute as a script src —
    // we need an executable URL scheme. `data:text/javascript,…` is
    // accepted by the browser; `javascript:` schemes don't execute in
    // `<script src>` on modern browsers.
    let (payload, _) = generate_dom_xss_poc("location.hash", "src");
    assert!(
        payload.starts_with("#data:text/javascript,alert(1)"),
        "expected hash-fragment data: URL payload, got {:?}",
        payload
    );
}

#[test]
fn test_generate_dom_xss_poc_hash_to_eval_sink_uses_bare_js() {
    // `eval(location.hash.substr(1))` accepts JS source directly — no
    // need to wrap with an HTML tag or URL scheme. Same for `Function`,
    // `setTimeout(stringArg)`, etc.
    let (payload, _) = generate_dom_xss_poc("location.hash", "eval");
    assert!(
        payload.starts_with("#alert(1)"),
        "expected hash-fragment bare-JS payload, got {:?}",
        payload
    );
}

#[test]
fn test_generate_dom_xss_poc_search_to_href_sink_uses_data_uri() {
    let (payload, _) = generate_dom_xss_poc("location.search", "href");
    assert!(
        payload.starts_with("xss=data:text/javascript,alert(1)"),
        "expected search query data: URL payload, got {:?}",
        payload
    );
}

#[test]
fn test_generate_dom_xss_poc_default_innerhtml_still_html_tag() {
    // Regression: keep the existing HTML payload for innerHTML-style
    // sinks (jQuery `.html()`, `document.write`, `outerHTML`, …) so we
    // don't regress all the cases tests #generate_dom_xss_poc_*_source
    // pinned. The new sink-aware branches only fire for URL / JS-eval
    // sinks.
    let (payload, _) = generate_dom_xss_poc("location.hash", "innerHTML");
    assert!(
        payload.contains("<img src=x onerror=alert(1)"),
        "expected HTML payload for innerHTML sink, got {:?}",
        payload
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_hash_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/dom/level2/",
        "location.hash",
        "#<img src=x onerror=alert(1) class=dalfox>",
    );
    assert!(url.contains("/dom/level2/#"));
    assert!(url.contains("img%20src=x"));
}

#[test]
fn test_build_dom_xss_poc_url_for_search_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/dom/level8/",
        "location.search",
        "xss=<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/dom/level8/");
    assert_eq!(
        parsed.query(),
        Some("xss=%3Cimg%20src=x%20onerror=alert(1)%20class=dalfox%3E")
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_urlsearchparams_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/dom/level32/",
        "URLSearchParams.get(query)",
        "query=<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/dom/level32/");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(
        pairs,
        vec![(
            "query".to_string(),
            "<img src=x onerror=alert(1) class=dalfox>".to_string()
        )]
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_nested_urlsearchparams_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/reparse/level2/?blob=query=a",
        "URLSearchParams.get(blob).get(query)",
        "query=<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/reparse/level2/");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(
        pairs,
        vec![(
            "blob".to_string(),
            "query=<img src=x onerror=alert(1) class=dalfox>".to_string()
        )]
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_nested_urlsearchparams_html_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/reparse/level4/?blob=html=a",
        "URLSearchParams.get(blob).get(html)",
        "html=<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/reparse/level4/");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(
        pairs,
        vec![(
            "blob".to_string(),
            "html=<img src=x onerror=alert(1) class=dalfox>".to_string()
        )]
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_double_nested_urlsearchparams_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/reparse/level5/?blob=outer=query=a",
        "URLSearchParams.get(blob).get(outer).get(query)",
        "query=<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/reparse/level5/");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(
        pairs,
        vec![(
            "blob".to_string(),
            "outer=query=<img src=x onerror=alert(1) class=dalfox>".to_string()
        )]
    );
}

#[test]
fn test_build_dom_xss_poc_url_for_pathname_source() {
    let url = build_dom_xss_poc_url(
        "https://example.com/dom/level28/",
        "location.pathname",
        "<img src=x onerror=alert(1) class=dalfox>",
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(
        parsed.path(),
        "/dom/level28/%3Cimg%20src=x%20onerror=alert(1)%20class=dalfox%3E"
    );
}

#[test]
fn test_build_dom_xss_poc_url_falls_back_for_non_url_sources() {
    let base = "https://example.com/dom/level13/";
    let url = build_dom_xss_poc_url(base, "window.name", "<img src=x onerror=alert(1)>");
    assert_eq!(url, base);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_window_name() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/browser-state/level1/?seed=a",
        "window.name",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    assert_eq!(parsed.path(), "/browser-state/level1/");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_window_opener() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/opener/level1/?seed=a",
        "window.opener",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_storage_source() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/browser-state/level2/?seed=a",
        "localStorage.getItem",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_event_data() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/browser-state/level4/?seed=a",
        "event.data",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_channel_message_source() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/channel/level1/?seed=a",
        "BroadcastChannel.message",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_document_referrer() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/browser-state/level5/?seed=a",
        "document.referrer",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_history_state() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/history-state/level1/?seed=a",
        "history.state",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_poc_url_uses_seed_bootstrap_for_storage_event() {
    let payload = "<img src=x onerror=alert(1) class=dalfox>";
    let url = build_dom_xss_poc_url(
        "https://example.com/storage-event/level1/?seed=a",
        "event.newValue",
        payload,
    );
    let parsed = url::Url::parse(&url).expect("valid poc url");
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs, vec![("seed".to_string(), payload.to_string())]);
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_window_name() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/level13/",
        "window.name",
        "<img src=x onerror=alert(1)>",
    )
    .expect("window.name should produce a manual hint");
    assert!(hint.contains("window.open('about:blank')"));
    assert!(hint.contains("w.name = \"<img src=x onerror=alert(1)>\""));
    assert!(hint.contains("https://example.com/dom/level13/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_window_opener() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/opener/level1/",
        "window.opener",
        "<img src=x onerror=alert(1)>",
    )
    .expect("window.opener should produce a manual hint");
    assert!(hint.contains("same-origin page"));
    assert!(hint.contains("window.name = \"<img src=x onerror=alert(1)>\""));
    assert!(hint.contains("window.__xssmazePreview = { html: \"<img src=x onerror=alert(1)>\" }"));
    assert!(hint.contains("https://example.com/opener/level1/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_document_referrer() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/level14/",
        "document.referrer",
        "<img src=x onerror=alert(1)>",
    )
    .expect("document.referrer should produce a manual hint");
    assert!(hint.contains("attacker-controlled page"));
    assert!(hint.contains("https://example.com/dom/level14/"));
    assert!(hint.contains("<img src=x onerror=alert(1)>"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_document_cookie() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/level12/",
        "document.cookie",
        "<img src=x onerror=alert(1)>",
    )
    .expect("document.cookie should produce a manual hint");
    assert!(hint.contains("same-origin cookie"));
    assert!(hint.contains("cookie-safe variant may be needed"));
    assert!(hint.contains("https://example.com/dom/level12/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_history_state() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/history-state/level1/",
        "history.state",
        "<img src=x onerror=alert(1)>",
    )
    .expect("history.state should produce a manual hint");
    assert!(hint.contains("history.replaceState"));
    assert!(hint.contains("reload"));
    assert!(hint.contains("https://example.com/history-state/level1/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_event_data() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/level23/",
        "event.data",
        "<img src=x onerror=alert(1)>",
    )
    .expect("event.data should produce a manual hint");
    assert!(hint.contains("window.open(\"https://example.com/dom/level23/\")"));
    assert!(hint.contains("postMessage(\"<img src=x onerror=alert(1)>\", '*'"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_broadcast_channel_message() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/channel/level1/",
        "BroadcastChannel.message",
        "<img src=x onerror=alert(1)>",
    )
    .expect("BroadcastChannel message sources should produce a manual hint");
    assert!(hint.contains("BroadcastChannel"));
    assert!(hint.contains("postMessage(\"<img src=x onerror=alert(1)>\""));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_service_worker_message() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/advanced/level3/",
        "ServiceWorker.message",
        "<img src=x onerror=alert(1)>",
    )
    .expect("ServiceWorker message sources should produce a manual hint");
    assert!(hint.contains("navigator.serviceWorker.controller?.postMessage"));
    assert!(hint.contains("https://example.com/advanced/level3/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_websocket_message() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/websocket/level6/",
        "WebSocket.message",
        "<img src=x onerror=alert(1)>",
    )
    .expect("WebSocket message sources should produce a manual hint");
    assert!(hint.contains("onmessage"));
    assert!(hint.contains("https://example.com/websocket/level6/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_event_source_message() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/eventsource/level1/",
        "EventSource.message",
        "<img src=x onerror=alert(1)>",
    )
    .expect("EventSource message sources should produce a manual hint");
    assert!(hint.contains("EventSource"));
    assert!(hint.contains("MessageEvent"));
    assert!(hint.contains("https://example.com/eventsource/level1/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_storage_event_source() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/storage-event/",
        "event.newValue",
        "<img src=x onerror=alert(1)>",
    )
    .expect("storage event sources should produce a manual hint");
    assert!(hint.contains("same-origin tab"));
    assert!(hint.contains("localStorage.setItem('dalfox'"));
    assert!(hint.contains("https://example.com/dom/storage-event/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_storage_source() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/storage/",
        "localStorage.getItem(xssmaze:browser-state:level2)",
        "<img src=x onerror=alert(1)>",
    )
    .expect("localStorage should produce a manual hint");
    assert!(hint.contains("localStorage.setItem(\"xssmaze:browser-state:level2\""));
    assert!(hint.contains("https://example.com/dom/storage/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_for_session_storage_source() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/storage/",
        "sessionStorage.getItem(xssmaze:browser-state:level3)",
        "<img src=x onerror=alert(1)>",
    )
    .expect("sessionStorage should produce a manual hint");
    assert!(hint.contains("sessionStorage.setItem(\"xssmaze:browser-state:level3\""));
    assert!(hint.contains("https://example.com/dom/storage/"));
}

#[test]
fn test_build_dom_xss_manual_poc_hint_none_for_url_sources() {
    let hint = build_dom_xss_manual_poc_hint(
        "https://example.com/dom/level2/",
        "location.hash",
        "#<img src=x onerror=alert(1)>",
    );
    assert!(hint.is_none());
}

#[test]
fn test_has_self_bootstrap_verification_for_window_name() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if (seed) {
          window.name = seed;
        } else {
          document.getElementById('output').innerHTML = window.name;
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "window.name"));
}

#[test]
fn test_has_self_bootstrap_verification_for_window_opener_name_bootstrap() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if (seed && !window.opener) {
          window.name = seed;
          window.open(location.pathname, 'xssmaze:opener:level1');
        } else if (window.opener) {
          document.getElementById('output').innerHTML = window.opener.name || '';
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "window.opener"));
}

#[test]
fn test_has_self_bootstrap_verification_for_window_opener_object_bootstrap() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if (seed && !window.opener) {
          window.__xssmazePreview = { html: seed };
          window.open(location.pathname, 'xssmaze:opener:level2');
        } else if (window.opener) {
          const bootstrap = window.opener.__xssmazePreview || {};
          document.getElementById('preview').setAttribute('srcdoc', bootstrap.html || '');
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "window.opener"));
}

#[test]
fn test_has_self_bootstrap_verification_for_local_storage_keyed_source() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if (seed) {
          localStorage.setItem('xssmaze:browser-state:level2', seed);
        } else {
          const stored = localStorage.getItem('xssmaze:browser-state:level2') || '';
          document.getElementById('output').insertAdjacentHTML('beforeend', stored);
        }
    "#;

    assert!(has_self_bootstrap_verification(
        js,
        "localStorage.getItem(xssmaze:browser-state:level2)"
    ));
}

#[test]
fn test_has_self_bootstrap_verification_for_event_source_dispatch() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        const source = new EventSource('/map/text');
        source.onmessage = function(event) {
          document.getElementById('output').innerHTML = event.data;
        };

        if (seed) {
          source.dispatchEvent(new MessageEvent('message', { data: seed }));
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "EventSource.message"));
}

#[test]
fn test_has_self_bootstrap_verification_for_service_worker_dispatch() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if ('serviceWorker' in navigator) {
          navigator.serviceWorker.addEventListener('message', function(event) {
            document.getElementById('output').innerHTML = event.data;
          });
          if (seed) {
            navigator.serviceWorker.dispatchEvent(
              new MessageEvent('message', { data: seed })
            );
          }
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "ServiceWorker.message"));
}

#[test]
fn test_has_self_bootstrap_verification_for_history_state_object_bootstrap() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        if (seed) {
          history.replaceState({ html: seed }, '', location.pathname);
        }

        const state = history.state || {};
        document.getElementById('preview').setAttribute('srcdoc', state.html || '');
    "#;

    assert!(has_self_bootstrap_verification(js, "history.state"));
}

#[test]
fn test_has_self_bootstrap_verification_for_document_referrer_child_relay() {
    let js = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        const child = url.searchParams.get('child');
        if (child === '1') {
          document.write(document.referrer);
        } else if (seed) {
          const relayUrl = new URL(location.href);
          relayUrl.searchParams.delete('seed');
          relayUrl.searchParams.set('child', '1');
          document.getElementById('relay').src =
            relayUrl.pathname + '?' + relayUrl.searchParams.toString();
        }
    "#;

    assert!(has_self_bootstrap_verification(js, "document.referrer"));
}

#[test]
fn test_has_self_bootstrap_verification_ignores_manual_only_sources() {
    let js = r#"
        if (location.search.includes('seed')) {
          document.getElementById('relay').src = '/child';
        }
        document.write(document.referrer);
    "#;

    assert!(!has_self_bootstrap_verification(js, "document.referrer"));
}

#[test]
fn test_extract_script_element_ids_collects_only_script_ids() {
    let html = r#"
<html>
<body>
<div id='output'></div>
<script id='scriptTag'></script>
<script id='another'></script>
<script>
  document.getElementById('scriptTag').innerText = location.hash.slice(1);
</script>
</body>
</html>
"#;
    let ids = extract_script_element_ids(html);
    assert!(ids.contains("scriptTag"));
    assert!(ids.contains("another"));
    // The <div id='output'> id must NOT be in the set — only script tags.
    assert!(!ids.contains("output"));
}

#[test]
fn test_extract_script_element_ids_ignores_blank_ids() {
    let html = r#"<script id='   '></script><script></script><script id='ok'></script>"#;
    let ids = extract_script_element_ids(html);
    assert_eq!(ids.len(), 1);
    assert!(ids.contains("ok"));
}

// ===== End-to-end pipeline coverage for issues #1021 / #1022 / #1024 =====
// Each test feeds the actual xssmaze page HTML through the same path the
// scanner uses (extract JS from HTML -> AST analyze -> POC generation).

#[test]
fn e2e_jquery_level1_constructor_finding_and_hash_poc() {
    // xssmaze /jquery/level1/
    let html = r#"<html><head><script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js'></script></head>
    <body>
    <div id='content'></div>
    <script>
      var target = decodeURIComponent(location.hash.slice(1));
      if (target) { $(target).appendTo('#content'); }
    </script>
    </body></html>"#;
    let results = run_initial_ast_dom_analysis(html, "http://t/jquery/level1/", "GET");
    assert!(
        results.iter().any(|r| r.evidence.contains("jQuery$")),
        "jQuery $() constructor must surface a finding; got {:?}",
        results
            .iter()
            .map(|r| r.evidence.clone())
            .collect::<Vec<_>>()
    );
    // location.hash source -> HTML payload carried in the fragment (the PoC
    // URL is stored in the `data` field).
    assert!(
        results
            .iter()
            .any(|r| r.data.contains('#') && r.payload.contains("onerror=alert(1)")),
        "expected a hash-fragment HTML PoC; got {:?}",
        results
            .iter()
            .map(|r| (r.data.clone(), r.payload.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn e2e_codeexec_level1_dynamic_import_finding_and_data_uri_poc() {
    // xssmaze /codeexec/level1/
    let html = r#"<html><body>
    <div id='status'>loading plugin...</div>
    <script>
      var name = new URLSearchParams(location.search).get('query') || '';
      if (name) {
        import(name).then(function () {}).catch(function () {});
      }
    </script>
    </body></html>"#;
    let results = run_initial_ast_dom_analysis(html, "http://t/codeexec/level1/?query=a", "GET");
    assert!(
        results.iter().any(|r| r.evidence.contains("Sink: import")),
        "dynamic import() must surface a finding; got {:?}",
        results
            .iter()
            .map(|r| r.evidence.clone())
            .collect::<Vec<_>>()
    );
    // import takes a module specifier -> executable data: URL payload on `query`.
    assert!(
        results
            .iter()
            .any(|r| r.payload.contains("query=data:text/javascript,alert(1)")),
        "expected a data: URL module PoC on query; got {:?}",
        results
            .iter()
            .map(|r| r.payload.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn e2e_apidom_level1_fetch_innerhtml_finding() {
    // xssmaze /apidom/level1/
    let html = r#"<html><body>
    <div id='out'>loading...</div>
    <script>
      var q = new URLSearchParams(location.search).get('q') || '';
      fetch('/apidom/level1/api?q=' + encodeURIComponent(q))
        .then(function (r) { return r.text(); })
        .then(function (t) { document.getElementById('out').innerHTML = t; });
    </script>
    </body></html>"#;
    let results = run_initial_ast_dom_analysis(html, "http://t/apidom/level1/?q=a", "GET");
    assert!(
        results
            .iter()
            .any(|r| r.evidence.contains("Source: Response.text")
                && r.evidence.contains("Sink: innerHTML")),
        "fetch text response -> innerHTML must surface; got {:?}",
        results
            .iter()
            .map(|r| r.evidence.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn e2e_apidom_level3_xhr_innerhtml_finding() {
    // xssmaze /apidom/level3/
    let html = r#"<html><body>
    <div id='out'>loading...</div>
    <script>
      var q = new URLSearchParams(location.search).get('q') || '';
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/apidom/level3/api?q=' + encodeURIComponent(q));
      xhr.onload = function () { document.getElementById('out').innerHTML = xhr.responseText; };
      xhr.send();
    </script>
    </body></html>"#;
    let results = run_initial_ast_dom_analysis(html, "http://t/apidom/level3/?q=a", "GET");
    assert!(
        results.iter().any(
            |r| r.evidence.contains("Source: XMLHttpRequest.responseText")
                && r.evidence.contains("Sink: innerHTML")
        ),
        "xhr.responseText -> innerHTML must surface; got {:?}",
        results
            .iter()
            .map(|r| r.evidence.clone())
            .collect::<Vec<_>>()
    );
}

// --- extract_same_origin_script_srcs tests ---

#[test]
fn test_extract_same_origin_script_srcs_absolute() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script src="https://example.com/app.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].as_str(), "https://example.com/app.js");
}

#[test]
fn test_extract_same_origin_script_srcs_relative() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script src="/bundle.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].as_str(), "https://example.com/bundle.js");
}

#[test]
fn test_extract_same_origin_script_srcs_drops_cross_origin() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script src="/local.js"></script>
        <script src="https://cdn.example.com/remote.js"></script>
        <script src="http://example.com/wrongscheme.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].as_str(), "https://example.com/local.js");
}

#[test]
fn test_extract_same_origin_script_srcs_dedups() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script src="/app.js"></script>
        <script src="/app.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
}

#[test]
fn test_extract_same_origin_script_srcs_ignores_inline_and_empty_src() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script>var x = 1;</script>
        <script src=""></script>
        <script src="/real.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].as_str(), "https://example.com/real.js");
}

#[test]
fn test_extract_same_origin_script_srcs_preserves_order() {
    let base = url::Url::parse("https://example.com/page").unwrap();
    let html = r#"<html><body>
        <script src="/first.js"></script>
        <script src="https://other.com/skip.js"></script>
        <script src="/second.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 2);
    assert!(srcs[0].as_str().ends_with("/first.js"));
    assert!(srcs[1].as_str().ends_with("/second.js"));
}

#[test]
fn test_extract_same_origin_script_srcs_relative_no_slash() {
    // "classic.js" (no leading slash) resolves relative to the base path directory,
    // not the root — so https://example.com/app/page -> https://example.com/app/classic.js
    let base = url::Url::parse("https://example.com/app/page").unwrap();
    let html = r#"<html><body>
        <script src="classic.js"></script>
    </body></html>"#;
    let srcs = extract_same_origin_script_srcs(html, &base);
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].as_str(), "https://example.com/app/classic.js");
}
