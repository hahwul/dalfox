//! DOM mining candidates read from the page's own JavaScript: the extractor,
//! its ordering against `<input>` names under the cap, and one end-to-end
//! discovery of a name that only the page's script carries.

use super::*;

#[test]
fn js_param_candidates_reads_url_query_keys() {
    // `?sort=&dir=`: an empty value must not swallow the next key, so the
    // `==` guard has to look at the byte after `=` without consuming it.
    let js =
        r#"fetch('/api/search?q=' + term + '&page=' + p); location.href = "/list?sort=&dir=asc";"#;
    assert_eq!(js_param_candidates(js), ["q", "page", "sort", "dir"]);
}

#[test]
fn js_param_candidates_reads_urlsearchparams_getters() {
    let js = r#"const p = new URLSearchParams(location.search); el.textContent = p.get('searchTerm') + p.getAll("tag") + p.has(`debug`);"#;
    assert_eq!(js_param_candidates(js), ["searchTerm", "tag", "debug"]);
}

#[test]
fn js_param_candidates_ignores_comparisons_and_operators() {
    // `&b=` / `?y=` here are a comparison, a ternary test and a compound
    // assignment, not URL query keys.
    let js = "if (a&&b==c) {} const r = x?y===z:w; n &= m;";
    assert!(
        js_param_candidates(js).is_empty(),
        "{:?}",
        js_param_candidates(js)
    );
}

#[test]
fn js_param_candidates_rejects_templated_and_oversized_names() {
    let long = "a".repeat(80);
    let js = format!("u.get(`${{key}}`); q.get('{long}'); s = '?{long}=1';");
    assert!(
        js_param_candidates(&js).is_empty(),
        "{:?}",
        js_param_candidates(&js)
    );
}

/// Minifiers emit ternary assignments everywhere; each one matches the query
/// key regex but none sits in a string. On real bundles these were most of
/// the raw matches (`t`, `e.exports`, `this.state`, `n[o]`).
#[test]
fn js_param_candidates_skips_minified_ternary_assignments() {
    let js =
        r#"e.exports=c?t=1:2;"object"==typeof e?module.exports=t():r=n;"x"==e?a=1:b;(f?n.x=1:0)"#;
    assert!(
        js_param_candidates(js).is_empty(),
        "{:?}",
        js_param_candidates(js)
    );
}

#[test]
fn js_param_candidates_reads_template_literal_keys() {
    let js = "fetch(`${base}?id=${x}&sort=${s}`)";
    assert_eq!(js_param_candidates(js), ["id", "sort"]);
}

/// Bundle names come after the page's own, plain shapes before minified
/// expressions, never repeated, and never more than one bucket's worth.
#[test]
fn append_bundle_names_ranks_plain_names_first_and_caps() {
    let mut names = vec!["q".to_string()];
    let mut bundle: Vec<String> = ["r.src", "t[e]", "q", "items[]"]
        .into_iter()
        .map(String::from)
        .collect();
    bundle.extend((0..MAX_BUNDLE_MINING_PARAMS).map(|i| format!("k{i}")));
    append_bundle_names(&mut names, &bundle);
    assert_eq!(names.len(), 1 + MAX_BUNDLE_MINING_PARAMS);
    assert_eq!(names[..2], ["q", "items[]"]);
    assert!(
        !names.iter().any(|n| n == "r.src" || n == "t[e]"),
        "{names:?}"
    );
    assert_eq!(names.iter().filter(|n| *n == "q").count(), 1);
}

/// Input names come first even when the script precedes them in the
/// document, and a JS name that repeats an input name is not added twice.
#[test]
fn dom_candidate_names_puts_inputs_before_js_names() {
    let html = r#"<script>fetch('/s?jsfirst=1&formfield=2')</script><input name=formfield><script>u.get('jssecond')</script>"#;
    assert_eq!(
        dom_candidate_names(html),
        ["formfield", "jsfirst", "jssecond"]
    );
}

/// `cap_dom_params` keeps the front of the list, so a page at the cap keeps
/// every input name and drops the JS-derived one instead.
#[test]
fn js_names_never_evict_input_names_at_the_cap() {
    let inputs: String = (0..MAX_DOM_MINING_PARAMS)
        .map(|i| format!("<input name=n{i}>"))
        .collect();
    let html = format!("<script>fetch('/a?jsonly=1')</script>{inputs}");
    let (kept, capped) = cap_dom_params(dom_candidate_names(&html));
    assert_eq!(capped, Some(MAX_DOM_MINING_PARAMS + 1));
    assert_eq!(kept.len(), MAX_DOM_MINING_PARAMS);
    assert!(!kept.iter().any(|n| n == "jsonly"));
}

/// The page has no `<input>` at all; the only trace of `redirectTarget` is the
/// script reading it, and the server reflects it. Before JS candidates, DOM
/// mining had nothing to probe here.
async fn js_mining_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let echoed = params.get("redirectTarget").cloned().unwrap_or_default();
    Html(format!(
        "<script>const t = new URLSearchParams(location.search).get('redirectTarget');</script><div>{echoed}</div>"
    ))
}

#[tokio::test]
async fn probe_response_id_params_discovers_name_only_page_js_references() {
    let app = Router::new().route("/js-mining", get(js_mining_handler));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    sleep(Duration::from_millis(20)).await;

    let target = parse_target(&format!("http://{}:{}/js-mining", addr.ip(), addr.port()))
        .expect("parse target");
    let args = default_scan_args();
    let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

    probe_response_id_params(&target, &args, reflection_params.clone(), semaphore, None).await;

    let params = reflection_params.lock().await.clone();
    assert!(
        params
            .iter()
            .any(|p| p.name == "redirectTarget" && p.location == Location::Query),
        "{params:?}"
    );
}
