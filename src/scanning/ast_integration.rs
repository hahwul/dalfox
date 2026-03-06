use scraper::{Html, Selector};

/// Extract JavaScript code from HTML response
/// Looks for <script> tags and inline event handlers
pub fn extract_javascript_from_html(html: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut js_code = Vec::new();
    let mut seen = HashSet::new();

    let document = Html::parse_document(html);

    // Extract from <script> tags
    if let Ok(selector) = Selector::parse("script") {
        for element in document.select(&selector) {
            let text = element.text().collect::<Vec<_>>().join("");
            if !text.trim().is_empty() && seen.insert(text.trim().to_string()) {
                js_code.push(text);
            }
        }
    }

    // Extract inline event handler attributes (on*) and javascript: URLs
    if let Ok(all) = Selector::parse("*") {
        for node in document.select(&all) {
            let attrs = node.value().attrs();
            for (name, value) in attrs {
                let lname = name.to_ascii_lowercase();
                let v = value;
                if v.trim().is_empty() {
                    continue;
                }
                if lname.starts_with("on") {
                    // Inline handler body as JS snippet
                    let snippet = v.trim().to_string();
                    if seen.insert(snippet.clone()) {
                        js_code.push(snippet);
                    }
                } else if lname == "href" {
                    let vv = v.trim();
                    if vv.len() >= 11 && vv[..11].eq_ignore_ascii_case("javascript:") {
                        let js = vv[11..].trim();
                        if !js.is_empty() {
                            let snippet = js.to_string();
                            if seen.insert(snippet.clone()) {
                                js_code.push(snippet);
                            }
                        }
                    }
                }
            }
        }
    }

    js_code
}

/// Generate an executable POC payload based on the source and sink
/// Returns (payload, description)
fn extract_search_param_chain(source: &str) -> Option<Vec<&str>> {
    let mut rest = source.strip_prefix("URLSearchParams.get(")?;
    let mut keys = Vec::new();

    loop {
        let end = rest.find(')')?;
        keys.push(&rest[..end]);
        rest = &rest[end + 1..];
        if rest.is_empty() {
            return Some(keys);
        }
        rest = rest.strip_prefix(".get(")?;
    }
}

fn extract_search_param_key(source: &str) -> Option<&str> {
    extract_search_param_chain(source)?.last().copied()
}

fn extract_parenthesized_suffix<'a>(source: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = source.strip_prefix(prefix)?;
    rest.strip_suffix(')')
}

fn extract_search_param_value<'a>(payload: &'a str, key: &str) -> &'a str {
    payload.strip_prefix(&format!("{key}=")).unwrap_or(payload)
}

pub fn generate_dom_xss_poc(source: &str, sink: &str) -> (String, String) {
    let marker = crate::scanning::markers::class_marker();
    // Generate payload based on the source type
    let payload = if source.contains("location.hash") {
        // Hash-based XSS - use fragment identifier
        format!("#<img src=x onerror=alert(1) class={}>", marker)
    } else if let Some(param_name) = extract_search_param_key(source) {
        format!("{param_name}=<img src=x onerror=alert(1) class={}>", marker)
    } else if source.contains("location.search") {
        // Query-based XSS
        format!("xss=<img src=x onerror=alert(1) class={}>", marker)
    } else if source.contains("location.href") || source.contains("document.URL") {
        // URL-based - could be anywhere
        format!("#<img src=x onerror=alert(1) class={}>", marker)
    } else {
        // Generic payload for other sources
        format!("<img src=x onerror=alert(1) class={}>", marker)
    };

    let description = format!("DOM-based XSS via {} to {}", source, sink);

    (payload, description)
}

fn source_uses_bootstrap_query_param(source: &str) -> bool {
    source.contains("window.name")
        || source.contains("document.referrer")
        || source.contains("localStorage")
        || source.contains("sessionStorage")
        || source.contains("history.state")
        || source.contains("event.data")
        || source.contains(".message")
        || source.contains("event.newValue")
        || source.contains("event.oldValue")
        || source.contains("postMessage")
}

pub fn has_self_bootstrap_for_source_in_html(html: &str, source: &str) -> bool {
    extract_javascript_from_html(html)
        .into_iter()
        .any(|js_code| has_self_bootstrap_verification(&js_code, source))
}

fn set_query_param(mut url: url::Url, key: &str, value: &str) -> String {
    let mut replaced = false;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            if k == key {
                replaced = true;
                (k.into_owned(), value.to_string())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();

    if !replaced {
        return url.to_string();
    }

    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.to_string()
}

fn upsert_query_param(mut url: url::Url, key: &str, value: &str) -> String {
    let mut replaced = false;
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            if k == key {
                replaced = true;
                (k.into_owned(), value.to_string())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();

    if !replaced {
        pairs.push((key.to_string(), value.to_string()));
    }

    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.to_string()
}

fn build_nested_search_param_value(chain: &[&str], payload: &str) -> Option<String> {
    let innermost = chain.last().copied()?;
    let mut value = extract_search_param_value(payload, innermost).to_string();
    for key in chain.iter().skip(1).rev() {
        value = format!("{key}={value}");
    }
    Some(value)
}

/// Build a browser-usable PoC URL for DOM-XSS findings when the source is carried
/// in the URL itself (for example `location.hash` or `location.search`) or when
/// the page bootstraps browser state from a known query parameter such as `seed`.
pub fn build_dom_xss_poc_url(base_url: &str, source: &str, payload: &str) -> String {
    let Ok(mut url) = url::Url::parse(base_url) else {
        return base_url.to_string();
    };

    if let Some(chain) = extract_search_param_chain(source) {
        if chain.len() > 1 {
            if let Some(value) = build_nested_search_param_value(&chain, payload) {
                return upsert_query_param(url, chain[0], &value);
            }
        } else if let Some(param_name) = chain.first().copied() {
            return upsert_query_param(
                url,
                param_name,
                extract_search_param_value(payload, param_name),
            );
        }
    }

    if source.contains("location.hash") {
        let fragment = payload.strip_prefix('#').unwrap_or(payload);
        url.set_fragment(Some(fragment));
        return url.to_string();
    }

    if source.contains("location.search") {
        let query = payload.strip_prefix('?').unwrap_or(payload);
        url.set_query(Some(query));
        return url.to_string();
    }

    if source.contains("location.href") || source.contains("document.URL") {
        if payload.starts_with('#') {
            let fragment = payload.strip_prefix('#').unwrap_or(payload);
            url.set_fragment(Some(fragment));
            return url.to_string();
        }
        if payload.starts_with('?') || payload.contains('=') {
            let query = payload.strip_prefix('?').unwrap_or(payload);
            url.set_query(Some(query));
            return url.to_string();
        }
    }

    if source.contains("location.pathname") {
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty();
            segments.push(payload);
        }
        return url.to_string();
    }

    if source_uses_bootstrap_query_param(source) {
        let seeded = set_query_param(url.clone(), "seed", payload);
        if seeded != url.to_string() {
            return seeded;
        }
    }

    base_url.to_string()
}

/// Build a concise manual reproduction hint for DOM-XSS sources that are not
/// naturally carried in the URL itself.
pub fn build_dom_xss_manual_poc_hint(
    base_url: &str,
    source: &str,
    payload: &str,
) -> Option<String> {
    let quoted_url = serde_json::to_string(base_url).ok()?;
    let quoted_payload = serde_json::to_string(payload).ok()?;

    if source.contains("window.name") {
        return Some(format!(
            "const w = window.open('about:blank'); w.name = {}; w.location = {};",
            quoted_payload, quoted_url
        ));
    }

    if source.contains("document.referrer") {
        return Some(format!(
            "open {} from an attacker-controlled page whose URL/referrer carries {};",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("document.cookie") {
        return Some(format!(
            "set a same-origin cookie whose value carries {} (cookie-safe variant may be needed), then open {};",
            quoted_payload, quoted_url
        ));
    }

    if source.contains("history.state") {
        return Some(format!(
            "open {}, run history.replaceState({}, '', location.pathname), then reload or re-trigger the sink in the same tab;",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("event.newValue") || source.contains("event.oldValue") {
        return Some(format!(
            "open {} in one tab, then from another same-origin tab run localStorage.setItem('dalfox', {}) or update/remove that key to fire a storage event;",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("BroadcastChannel.message") {
        return Some(format!(
            "open {}, then from the page context reuse the page's BroadcastChannel name and call postMessage({});",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("MessagePort.message") {
        return Some(format!(
            "open {}, then from the page context post {} through the paired MessagePort used by the page;",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("ServiceWorker.message") {
        return Some(format!(
            "open {}, then from the page context run navigator.serviceWorker.controller?.postMessage({});",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("Worker.message") || source.contains("SharedWorker.message") {
        return Some(format!(
            "open {}, then from the page context call the page's worker postMessage({}) or re-trigger the worker bootstrap;",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("WebSocket.message") {
        return Some(format!(
            "open {}, then have the connected WebSocket receive {} or invoke its onmessage handler with {{ data: {} }};",
            quoted_url, quoted_payload, quoted_payload
        ));
    }

    if source.contains("EventSource.message") {
        return Some(format!(
            "open {}, then have the connected EventSource emit {} from the server or dispatch a MessageEvent carrying {} into the page's EventSource handler;",
            quoted_url, quoted_payload, quoted_payload
        ));
    }

    if source.contains("event.data") || source.contains("e.data") || source.contains("postMessage")
    {
        return Some(format!(
            "const w = window.open({}); setTimeout(() => w.postMessage({}, '*'), 500);",
            quoted_url, quoted_payload
        ));
    }

    if source.contains("localStorage") {
        if let Some(key) = extract_parenthesized_suffix(source, "localStorage.getItem(") {
            let quoted_key = serde_json::to_string(key).ok()?;
            return Some(format!(
                "localStorage.setItem({}, {}); open {};",
                quoted_key, quoted_payload, quoted_url
            ));
        }
        return Some(format!(
            "prime localStorage with {} before opening {};",
            quoted_payload, quoted_url
        ));
    }

    if source.contains("sessionStorage") {
        if let Some(key) = extract_parenthesized_suffix(source, "sessionStorage.getItem(") {
            let quoted_key = serde_json::to_string(key).ok()?;
            return Some(format!(
                "sessionStorage.setItem({}, {}); open {};",
                quoted_key, quoted_payload, quoted_url
            ));
        }
        return Some(format!(
            "prime sessionStorage with {} before opening {};",
            quoted_payload, quoted_url
        ));
    }

    None
}

fn normalize_js_for_pattern_matching(js_code: &str) -> String {
    js_code.chars().filter(|c| !c.is_whitespace()).collect()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn has_seed_query_bootstrap(normalized_js: &str) -> bool {
    contains_any(
        normalized_js,
        &[
            "searchParams.get('seed')",
            "searchParams.get(\"seed\")",
            ".get('seed')",
            ".get(\"seed\")",
        ],
    )
}

fn has_storage_bootstrap(normalized_js: &str, storage_api: &str, key: &str) -> bool {
    let single = format!("{storage_api}.setItem('{key}',seed)");
    let double = format!("{storage_api}.setItem(\"{key}\",seed)");
    normalized_js.contains(&single) || normalized_js.contains(&double)
}

/// Confirm pages that bootstrap a non-URL DOM source from a predictable query
/// parameter in the same script block, which lets Dalfox emit a stronger result
/// for deterministic self-triggering xssmaze-style flows.
pub fn has_self_bootstrap_verification(js_code: &str, source: &str) -> bool {
    let normalized_js = normalize_js_for_pattern_matching(js_code);
    if !has_seed_query_bootstrap(&normalized_js) {
        return false;
    }

    if source.contains("window.name") {
        return normalized_js.contains("window.name=seed");
    }

    if source.contains("localStorage.getItem(") {
        if let Some(key) = extract_parenthesized_suffix(source, "localStorage.getItem(") {
            return has_storage_bootstrap(&normalized_js, "localStorage", key);
        }
        return normalized_js.contains("localStorage.setItem(") && normalized_js.contains("seed");
    }

    if source.contains("sessionStorage.getItem(") {
        if let Some(key) = extract_parenthesized_suffix(source, "sessionStorage.getItem(") {
            return has_storage_bootstrap(&normalized_js, "sessionStorage", key);
        }
        return normalized_js.contains("sessionStorage.setItem(") && normalized_js.contains("seed");
    }

    if source.contains("history.state") {
        return normalized_js.contains("history.replaceState(seed")
            || normalized_js.contains("history.pushState(seed");
    }

    if source.contains("event.newValue") || source.contains("event.oldValue") {
        return contains_any(
            &normalized_js,
            &[
                "addEventListener('storage',",
                "addEventListener(\"storage\",",
                "onstorage=",
            ],
        ) && normalized_js.contains("localStorage.setItem(")
            && normalized_js.contains("seed");
    }

    if source.contains("BroadcastChannel.message")
        || source.contains("MessagePort.message")
        || source.contains("Worker.message")
        || source.contains("SharedWorker.message")
        || source.contains("event.data")
        || source.contains("postMessage")
    {
        return normalized_js.contains("postMessage(") && normalized_js.contains("seed");
    }

    if source.contains("WebSocket.message") || source.contains("EventSource.message") {
        return contains_any(
            &normalized_js,
            &[
                "dispatchEvent(newMessageEvent('message'",
                "dispatchEvent(newMessageEvent(\"message\"",
                "onmessage({data:seed})",
                "onmessage({data:JSON.stringify(",
            ],
        ) && normalized_js.contains("seed");
    }

    false
}

/// Analyze JavaScript code for DOM XSS vulnerabilities using AST analysis
/// Returns a list of (vulnerability, payload, description) tuples
pub fn analyze_javascript_for_dom_xss(
    js_code: &str,
    _url: &str,
) -> Vec<(
    crate::scanning::ast_dom_analysis::DomXssVulnerability,
    String,
    String,
)> {
    let analyzer = crate::scanning::ast_dom_analysis::AstDomAnalyzer::new();

    match analyzer.analyze(js_code) {
        Ok(vulnerabilities) => {
            let mut findings = Vec::new();
            for vuln in vulnerabilities {
                let (payload, description) = generate_dom_xss_poc(&vuln.source, &vuln.sink);
                findings.push((vuln, payload, description));
            }
            findings
        }
        Err(_) => {
            // Parse error - JavaScript might be too complex or malformed
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
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
        let (payload, description) =
            generate_dom_xss_poc("URLSearchParams.get(query)", "innerHTML");
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
    fn test_has_self_bootstrap_verification_ignores_manual_only_sources() {
        let js = r#"
            if (location.search.includes('seed')) {
              document.getElementById('relay').src = '/child';
            }
            document.write(document.referrer);
        "#;

        assert!(!has_self_bootstrap_verification(js, "document.referrer"));
    }
}
