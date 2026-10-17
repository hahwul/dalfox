use super::*;

const EL: &str = "var el = document.getElementById('x');\n";

fn findings(js: &str) -> Vec<DomXssVulnerability> {
    AstDomAnalyzer::new().analyze(&format!("{EL}{js}")).unwrap()
}

#[test]
fn common_source_spellings_and_propagation_shapes_are_tracked() {
    for (js, source) in [
        ("el.innerHTML = document.location.hash;", "location"),
        (
            "const {hash} = location; el.innerHTML = hash;",
            "location.hash",
        ),
        (
            "const {search: s} = window.location; document.write(s);",
            "location.search",
        ),
        ("el.innerHTML = new URL(location).hash;", "location.hash"),
        (
            "const u = new URL(location.href); el.innerHTML = u.hash;",
            "location.hash",
        ),
        ("el.innerHTML = localStorage.token;", "localStorage"),
        (
            "const o = Object.fromEntries(new URLSearchParams(location.search)); el.innerHTML = o.q;",
            "location.search",
        ),
        (
            "for (const [k, v] of new URLSearchParams(location.search)) { el.innerHTML += v; }",
            "location.search",
        ),
        (
            "new URLSearchParams(location.search).forEach((v) => { el.innerHTML = v; });",
            "location.search",
        ),
        (
            "[location.hash].forEach(function (v) { el.innerHTML = v; });",
            "location.hash",
        ),
        (
            "(function (v) { el.innerHTML = v; })(location.hash);",
            "location.hash",
        ),
        (
            "((v) => { document.write(v); })(location.search);",
            "location.search",
        ),
        (
            "const q = n => new URLSearchParams(location.search).get(n); el.innerHTML = q('x');",
            "location.search",
        ),
        (
            "class A { constructor(e) { this.e = e; } render(v) { this.e.innerHTML = v; } } new A(el).render(location.hash);",
            "location.hash",
        ),
        (
            "async function f() { return location.hash; } f().then(v => { el.innerHTML = v; });",
            "location.hash",
        ),
        // A helper that roots a `.then` chain still reports its own sink.
        (
            "function load(q) { el.innerHTML = q; return Promise.resolve(q); } load(location.hash).then(v => {});",
            "location.hash",
        ),
        (
            "window.addEventListener('message', ({data}) => { el.innerHTML = data.html; });",
            "data",
        ),
        (
            "window.onmessage = function ({data}) { el.innerHTML = data; };",
            "data",
        ),
        ("location = location.hash.slice(1);", "location.hash"),
        (
            "window.location = decodeURIComponent(location.hash.slice(1));",
            "location.hash",
        ),
        // A URL cut out of the page URL is attacker-chosen, scheme included.
        (
            "const u = new URL(document.URL.split('next=')[1]); location.href = u.href;",
            "location.search",
        ),
        (
            "el.appendChild(document.createRange().createContextualFragment(location.hash));",
            "location.hash",
        ),
        // A destructured first parameter keeps the second at index 1.
        (
            "function f({a}, b) { el.innerHTML = b; } f({}, location.hash);",
            "location.hash",
        ),
        // Summaries are keyed by name and collide across scopes in minified
        // bundles; the tainted-argument fallback has to keep the flow.
        (
            "(function(){ function a(e){ console.log(e); return 1; } })(); (function(){ function a(e){ return e; } el.innerHTML = a(location.hash); })();",
            "location.hash",
        ),
    ] {
        let found = findings(js);
        assert!(
            found.iter().any(|v| v.source.contains(source)),
            "{js}: expected a finding from {source}, got {found:?}"
        );
    }
}

/// A page-URL copy pins the navigation sinks it feeds, so the binding must not
/// outlive its scope or survive a rebinding — a stale entry hides a real flow.
#[test]
fn a_page_url_binding_does_not_pin_other_values_of_the_same_name() {
    for js in [
        "function a(){ const url = new URL(location); history.replaceState(null,'',url); } function go(url){ location.href = url; } go(location.hash.slice(1));",
        "const url = new URL(location.href); history.replaceState(null,'',url); const go = function (url) { location.href = url; }; go(location.hash.slice(1));",
        "const url = new URL(location.href); fetch('/next').then(r => r.json()).then(function (url) { location.href = url; });",
        "let u = new URL(location); u = location.hash.slice(1); location.href = u;",
        "var u = new URL(location.hash.slice(1)); [1].forEach(function(){ const u = new URL(location); }); location.href = u.href;",
        "const u = new URL(location); u.href = decodeURIComponent(location.hash.slice(1)); location.href = u;",
    ] {
        let found = findings(js);
        assert!(
            found.iter().any(|v| v.sink == "location.href"),
            "{js}: {found:?}"
        );
    }
}

#[test]
fn neutralized_or_unrelated_values_stay_clean() {
    for js in [
        "el.innerHTML = location.pathname.split('/').length;",
        // Only `data` carries the message; `origin` is checked, not rendered,
        // and it shadows an outer `origin`.
        "window.addEventListener('message', ({origin}) => { el.innerHTML = origin; });",
        "const origin = location.hash; addEventListener('message', ({origin}) => { el.innerHTML = origin; });",
        "const {host: h} = {host: 'x'}; el.innerHTML = h;",
        "['a', 'b'].forEach(v => { el.innerHTML = v; });",
        "(function (v) { el.innerHTML = v; })('static');",
        // The page's own URL, or a copy of it, cannot become `javascript:`.
        "const u = new URL(location.href); location.replace(u.pathname + '?x=1');",
        "if (top !== self) { top.location = self.location; }",
        "location.href = new URL(location.href).origin + '/login';",
        "el.innerHTML = 'Host: ' + new URL(location.href).host;",
        "const url = new URL(location); url.searchParams.set('p', 2); location.href = url;",
        "const {origin} = location; location.href = origin + '/login';",
        // A parameter named `location` is not the Location object.
        "function show(location) { location = location.trim(); console.log(location); } show(location.hash);",
        "function f({a}, b) { el.innerHTML = b; } f(location.hash, 'x');",
    ] {
        let found = findings(js);
        assert!(found.is_empty(), "{js}: {found:?}");
    }
}

#[test]
fn a_sink_nested_in_a_jquery_argument_is_reported_once() {
    let found = findings("$(eval(location.hash));");
    assert_eq!(
        found.iter().filter(|v| v.sink == "eval").count(),
        1,
        "{found:?}"
    );
}
