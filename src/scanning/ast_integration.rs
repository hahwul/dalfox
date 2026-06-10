use scraper::Html;
use std::collections::HashSet;

use super::selectors;

/// Collect the `id` attribute of every `<script>` element in `html`.
///
/// Used to teach the AST DOM analyzer that an inline call like
/// `document.getElementById('scriptTag').innerText = tainted` is writing
/// into a `<script>` body — i.e. an eval-equivalent sink — even when the
/// JS file has no `document.createElement('script')` of its own. The
/// caller threads the returned set into `AstDomAnalyzer::with_script_element_ids`.
pub fn extract_script_element_ids(html: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    let document = Html::parse_document(html);
    let selector = selectors::script();
    for element in document.select(selector) {
        if let Some(id) = element.value().attr("id") {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                ids.insert(trimmed.to_string());
            }
        }
    }
    ids
}

/// Extract JavaScript code from HTML response
/// Looks for <script> tags and inline event handlers
pub fn extract_javascript_from_html(html: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut js_code = Vec::new();
    let mut seen = HashSet::new();

    let document = Html::parse_document(html);

    // Extract from <script> tags
    {
        let selector = selectors::script();
        for element in document.select(selector) {
            let text = element.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if !text.trim().is_empty() && seen.insert(text.trim().to_string()) {
                js_code.push(text);
            }
        }
    }

    // Extract inline event handler attributes (on*) and javascript: URLs
    {
        let all = selectors::universal();
        for node in document.select(all) {
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
                    if vv.len() >= 11
                        && vv.is_char_boundary(11)
                        && vv[..11].eq_ignore_ascii_case("javascript:")
                    {
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

/// Collect resolved, deduped, same-origin `<script src>` URLs from `html`,
/// resolved relative to `base` (the response URL). Cross-origin srcs are dropped.
pub fn extract_same_origin_script_srcs(html: &str, base: &url::Url) -> Vec<url::Url> {
    let document = Html::parse_document(html);
    let selector = selectors::script();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for element in document.select(selector) {
        let src = match element.value().attr("src") {
            Some(s) if !s.trim().is_empty() => s.trim(),
            _ => continue,
        };
        let resolved = match base.join(src) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if !crate::scanning::xss_blind::is_same_origin(&resolved, base) {
            continue;
        }
        let key = resolved.as_str().to_string();
        if seen.insert(key) {
            out.push(resolved);
        }
    }
    out
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
    if let Some(rest) = payload.strip_prefix(key) {
        rest.strip_prefix('=').unwrap_or(payload)
    } else {
        payload
    }
}

pub fn generate_dom_xss_poc(source: &str, sink: &str) -> (String, String) {
    let marker = crate::scanning::markers::class_marker();
    // Sink-aware payload shape:
    //   * URL-attribute sinks (`src`, `href`, `xlink:href`, …) receive an
    //     executable URL scheme (`data:text/javascript,…`) so they fire
    //     when the framework assigns the value to a real DOM property
    //     — xss-game L6 is the canonical case (hash → `script.src`).
    //   * `setAttribute` / `eval` / `Function` / `setTimeout` /
    //     `setInterval` accept JS source directly.
    //   * Everything else (`innerHTML`, jQuery `html()`, `document.write`,
    //     …) renders the payload as HTML, so a tag + event-handler combo
    //     wins.
    // `import` takes a module *specifier* (a URL), so the same executable
    // `data:text/javascript,…` payload as a URL-attribute sink loads and runs
    // an attacker module — group it with the URL-attribute shape.
    let is_url_attr_sink = matches!(
        sink,
        "src"
            | "href"
            | "xlink:href"
            | "action"
            | "formaction"
            | "poster"
            | "background"
            | "import"
    );
    // Sinks whose value is fed directly to a JS evaluator. `script.text` /
    // `script.textContent` / `script.innerText` are listed alongside the
    // classic eval family because once the created script element is
    // appended to the DOM the browser parses the assigned value as JS
    // source verbatim — same effective shape as `eval(payload)`.
    let is_js_eval_sink = matches!(
        sink,
        "eval"
            | "Function"
            | "setTimeout"
            | "setInterval"
            | "execScript"
            | "execCommand"
            | "script.text"
            | "script.textContent"
            | "script.innerText"
            | "script.innerHTML"
    );
    let attr_url_payload = format!("data:text/javascript,alert(1)/*{}*/", marker);
    let js_eval_payload = format!("alert(1)/*{}*/", marker);
    let html_payload = format!("<img src=x onerror=alert(1) class={}>", marker);

    // Generate payload based on the source type
    let payload = if source.contains("location.hash") {
        // Hash-based XSS - use fragment identifier
        if is_url_attr_sink {
            format!("#{}", attr_url_payload)
        } else if is_js_eval_sink {
            format!("#{}", js_eval_payload)
        } else {
            format!("#{}", html_payload)
        }
    } else if let Some(param_name) = extract_search_param_key(source) {
        if is_url_attr_sink {
            format!("{param_name}={}", attr_url_payload)
        } else if is_js_eval_sink {
            format!("{param_name}={}", js_eval_payload)
        } else {
            format!("{param_name}={}", html_payload)
        }
    } else if source.contains("location.search") {
        // Query-based XSS
        if is_url_attr_sink {
            format!("xss={}", attr_url_payload)
        } else if is_js_eval_sink {
            format!("xss={}", js_eval_payload)
        } else {
            format!("xss={}", html_payload)
        }
    } else if source.contains("location.href") || source.contains("document.URL") {
        // URL-based - could be anywhere
        if is_url_attr_sink {
            format!("#{}", attr_url_payload)
        } else if is_js_eval_sink {
            format!("#{}", js_eval_payload)
        } else {
            format!("#{}", html_payload)
        }
    } else if is_url_attr_sink {
        attr_url_payload.clone()
    } else if is_js_eval_sink {
        js_eval_payload.clone()
    } else {
        // Generic payload for other sources
        html_payload.clone()
    };

    let description = format!("DOM-based XSS via {} to {}", source, sink);

    (payload, description)
}

fn source_uses_bootstrap_query_param(source: &str) -> bool {
    source.contains("window.name")
        || source.contains("window.opener")
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

/// Replace or optionally insert a query parameter in a URL.
/// When `insert_if_missing` is false, returns the original URL unchanged if the key is not found.
fn modify_query_param(
    mut url: url::Url,
    key: &str,
    value: &str,
    insert_if_missing: bool,
) -> String {
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
        if !insert_if_missing {
            return url.to_string();
        }
        pairs.push((key.to_string(), value.to_string()));
    }

    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.to_string()
}

fn set_query_param(url: url::Url, key: &str, value: &str) -> String {
    modify_query_param(url, key, value, false)
}

fn upsert_query_param(url: url::Url, key: &str, value: &str) -> String {
    modify_query_param(url, key, value, true)
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

    if source.contains("window.opener") {
        return Some(format!(
            "from a same-origin page set window.name = {0}; window.__xssmazePreview = {{ html: {0} }}; window.open({1}, '_blank');",
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

    if source.contains("window.opener") {
        return normalized_js.contains("window.opener")
            && normalized_js.contains("window.open(location.pathname")
            && (normalized_js.contains("window.name=seed")
                || normalized_js.contains("window.__xssmazePreview={html:seed}"));
    }

    if source.contains("document.referrer") {
        // Relay-based bootstrap (iframe relay pattern)
        let relay_pattern = normalized_js.contains("document.referrer")
            && contains_any(
                &normalized_js,
                &[
                    "searchParams.set('child','1')",
                    "searchParams.set(\"child\",\"1\")",
                ],
            )
            && contains_any(
                &normalized_js,
                &[
                    "document.getElementById('relay').src=",
                    "document.getElementById(\"relay\").src=",
                    ".src=relayUrl.pathname+",
                ],
            );
        // Direct document.write bootstrap pattern
        let write_pattern = normalized_js.contains("document.write(document.referrer)")
            && contains_any(
                &normalized_js,
                &[
                    "searchParams.set('child','1')",
                    "searchParams.set(\"child\",\"1\")",
                ],
            )
            && contains_any(
                &normalized_js,
                &[
                    "searchParams.delete('seed')",
                    "searchParams.delete(\"seed\")",
                ],
            );
        return relay_pattern || write_pattern;
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
        return contains_any(
            &normalized_js,
            &[
                "history.replaceState(seed",
                "history.pushState(seed",
                "history.replaceState({html:seed}",
                "history.pushState({html:seed}",
            ],
        );
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

    if source.contains("ServiceWorker.message") {
        return contains_any(
            &normalized_js,
            &[
                "serviceWorker.dispatchEvent(newMessageEvent('message'",
                "serviceWorker.dispatchEvent(newMessageEvent(\"message\"",
                "controller?.postMessage(",
            ],
        ) && normalized_js.contains("seed");
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
    analyze_javascript_for_dom_xss_with_html_context(js_code, _url, &HashSet::new(), false)
}

/// Same as `analyze_javascript_for_dom_xss`, but supplies the AST analyzer
/// with the set of `<script>` element IDs observed in the surrounding HTML
/// so inline `getElementById('id').innerText = tainted` shapes resolve to
/// a JS-eval sink. Use `extract_script_element_ids(html)` to build the set.
///
/// `trusted_types_enforced` reflects the response CSP's
/// `require-trusted-types-for 'script'`; when set, a strict `'default'`
/// Trusted Types policy in the page suppresses the (now false-positive)
/// TrustedHTML-sink findings it neutralizes.
pub fn analyze_javascript_for_dom_xss_with_html_context(
    js_code: &str,
    _url: &str,
    script_element_ids: &HashSet<String>,
    trusted_types_enforced: bool,
) -> Vec<(
    crate::scanning::ast_dom_analysis::DomXssVulnerability,
    String,
    String,
)> {
    let analyzer = crate::scanning::ast_dom_analysis::AstDomAnalyzer::new()
        .with_script_element_ids(script_element_ids.clone())
        .with_trusted_types_enforced(trusted_types_enforced);

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

/// Build a DOM-XSS `Result` from a single AST finding, applying the
/// self-bootstrap upgrade (Verified / High severity) when statically
/// confirmed. Shared by the initial-HTML pass and the external-JS pass so
/// both surfaces emit identically shaped findings. `evidence` and `message`
/// are caller-supplied because they differ per source (inline vs external).
pub(crate) fn build_ast_dom_xss_result(
    target_url: &str,
    target_method: &str,
    source: &str,
    payload: String,
    evidence: String,
    message: String,
    self_bootstrap_verified: bool,
) -> crate::scanning::result::Result {
    let poc_url = build_dom_xss_poc_url(target_url, source, &payload);
    let mut ast_result =
        crate::scanning::result::Result::builder(crate::scanning::result::FindingType::AstDetected)
            .inject_type("DOM-XSS")
            .method(target_method.to_string())
            .data(poc_url)
            .param("-")
            .payload(payload)
            .evidence(evidence)
            .cwe("CWE-79")
            .severity("Medium")
            .message_id(0)
            .message_str(message)
            .build();
    if self_bootstrap_verified {
        ast_result.result_type = crate::scanning::result::FindingType::Verified;
        ast_result.severity = "High".to_string();
        ast_result.message_str = format!(
            "{} [static self-bootstrap confirmed]",
            ast_result.message_str
        );
    }
    ast_result
}

/// Run the "initial response" AST DOM-XSS analysis used to seed scans
/// with findings that don't require an active payload injection — the
/// JavaScript already wires a known source (e.g. `location.hash`) to a
/// dangerous sink (e.g. `innerHTML`). Returns the list of result
/// records ready to be pushed onto the shared findings vector.
///
/// Extracted from `cmd/scan.rs` so server (`dalfox server`) and MCP
/// (`scan_with_dalfox`) can run the same first-pass DOM analysis as
/// CLI does — they previously skipped it because they didn't run the
/// preflight step that produced the response body, so identical
/// targets produced 0 findings via API but multiple via CLI.
pub fn run_initial_ast_dom_analysis(
    response_text: &str,
    target_url: &str,
    target_method: &str,
    trusted_types_enforced: bool,
) -> Vec<crate::scanning::result::Result> {
    let js_blocks = extract_javascript_from_html(response_text);
    let script_element_ids = extract_script_element_ids(response_text);
    let mut out: Vec<crate::scanning::result::Result> = Vec::new();
    for js_code in js_blocks {
        let findings = analyze_javascript_for_dom_xss_with_html_context(
            &js_code,
            target_url,
            &script_element_ids,
            trusted_types_enforced,
        );
        for (vuln, payload, description) in findings {
            let self_bootstrap_verified = has_self_bootstrap_verification(&js_code, &vuln.source);
            let message = if let Some(hint) =
                build_dom_xss_manual_poc_hint(target_url, &vuln.source, &payload)
            {
                format!("{description} (needs runtime confirmation) [manual POC: {hint}]")
            } else {
                format!("{description} (needs runtime confirmation) [light check: no parameter]")
            };
            let evidence = format!(
                "{}:{}:{} - {} (Source: {}, Sink: {})",
                target_url, vuln.line, vuln.column, description, vuln.source, vuln.sink
            );
            out.push(build_ast_dom_xss_result(
                target_url,
                target_method,
                &vuln.source,
                payload,
                evidence,
                message,
                self_bootstrap_verified,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests;
