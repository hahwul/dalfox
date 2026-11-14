//! Shapes from ordinary pages and bundles: what a scan of real sites reported
//! that no one could exploit, and what hand-written app code does that the
//! walk used to lose. Each fixture is a minimal reduction, not vendored code.

use super::*;

fn found(js: &str) -> Vec<DomXssVulnerability> {
    AstDomAnalyzer::new().analyze(js).expect("parses")
}

fn flows(js: &str) -> Vec<String> {
    found(js)
        .iter()
        .map(|v| format!("{} -> {}", v.source, v.sink))
        .collect()
}

fn assert_clean(cases: &[&str]) {
    for js in cases {
        assert!(found(js).is_empty(), "{js}: {:?}", flows(js));
    }
}

fn assert_reported(cases: &[&str]) {
    for js in cases {
        assert!(!found(js).is_empty(), "{js}");
    }
}

/// A navigation sink runs script only when the attacker writes the *start*
/// of the URL. The page's own URL, `?…` / `#…`, and anything behind a fixed
/// prefix cannot — inline or through a variable.
#[test]
fn navigation_to_a_value_the_attacker_cannot_start_is_clean() {
    assert_clean(&[
        "var url = '/search?q=' + new URLSearchParams(location.search).get('q'); location.href = url;",
        "var u = '/list?page=' + location.hash.slice(1); u += '&sort=asc'; window.location = u;",
        "const BASE = '/api/v1/'; location.href = BASE + location.hash.slice(1);",
        "var link = '/item/' + location.hash.slice(1); a.href = link;",
        "location.href = location.hash;",
        "var base = getBase(); location.href = base + location.search;",
        "var n = cfg.base; window.location.href = `${n}/settings?ptrt=${window.location.href}`;",
        "window.location.href = '/logout?cont='.concat(window.location.href);",
        "location.href = location.href.replace('aria=0', '').replace('aria=1', '');",
        "window.location = window.location.href.replace(/^http:/, 'https:');",
        "window.location.href = window.location.href.replace(location.hash, '');",
        "location.href = location.href.replace(/[?&]lang=[^&]*/, '');",
        "if (document.referrer) location.href = document.referrer;",
        "var back = document.referrer; if (back) { location.href = back; }",
        "var e = new URL('/signup', window.location.origin); e.search = window.location.search; window.location.href = e.toString();",
        "var u = new URL(cfg.url); u.hash = location.hash; location.href = u.href;",
        // a helper that navigates to its argument, called with the page URL
        "function parse(u) { var a = document.createElement('a'); a.href = u; return a.hostname; } parse(location.href);",
    ]);
}

/// …and the same sinks still report when the attacker can.
#[test]
fn navigation_to_an_attacker_started_value_still_reports() {
    assert_reported(&[
        "location.href = location.hash.slice(1);",
        "var base = getBase(); location.href = base + location.hash.slice(1);",
        "location.href = new URLSearchParams(location.search).get('u') + '/done';",
        "location.href = document.referrer + new URLSearchParams(location.search).get('u');",
        "location.href = getParam(location.href, 'next');",
        "location.href = location.search.replace('?', '');",
        "location.href = location.href.replace(/.*#/, '');",
        "location.href = location.href.replace('', location.hash.slice(1));",
        "location.href = 'javascript:go(\"' + location.hash.slice(1) + '\")';",
        "location.href = 'java' + 'script:' + location.hash.slice(1);",
        // a pin is dropped when the name is rebound
        "var u = '/x?q=' + location.hash; u = location.hash.slice(1); location.href = u;",
        "var u = '/x'; if (c) { u = location.hash.slice(1); } location.href = u;",
        // …including from inside a function, which can only take a pin away
        "var next = '/home'; function parse() { next = new URLSearchParams(location.search).get('next'); } parse(); location.href = next;",
        "var u = '/x?' + location.hash; function f() { u = location.hash.slice(1); } f(); location.href = u;",
        "var u = new URL('/a', location.origin); u.href = location.hash.slice(1); location.href = u.href;",
    ]);
}

/// An upgrade made inside a function body must not outlive it: the body may
/// never run, and the outer value is still whatever the attacker supplied.
#[test]
fn a_pin_granted_inside_a_function_does_not_escape() {
    assert_reported(&[
        "var u = location.hash.slice(1); function reset() { u = '/home'; } location.href = u;",
    ]);
}

/// HTML escaping does not neutralise a URL or script: the sanitizers that
/// count depend on what the sink does with the value.
#[test]
fn sanitizers_are_judged_by_the_sink() {
    assert_reported(&[
        "location.href = encodeURI(new URLSearchParams(location.search).get('u'));",
        "location.href = escapeHtml(new URLSearchParams(location.search).get('u'));",
        "location.href = DOMPurify.sanitize(new URLSearchParams(location.search).get('u'));",
        "eval(escapeHtml(location.hash.slice(1)));",
        "var s = document.createElement('script'); s.src = DOMPurify.sanitize(location.hash.slice(1));",
        "el.setAttribute('onclick', escapeHtml(location.hash.slice(1)));",
    ]);
    assert_clean(&[
        "el.innerHTML = escapeHtml(location.hash);",
        "el.innerHTML = DOMPurify.sanitize(location.hash);",
        "location.href = encodeURIComponent(location.hash.slice(1));",
        "location.href = '/p/' + parseInt(location.hash.slice(1), 10);",
        "eval(parseInt(location.hash.slice(1)));",
    ]);
}

/// The `Location` object's host, port and scheme are the page's own, in every
/// spelling; numbers, booleans and base64 cannot carry markup.
#[test]
fn values_that_cannot_carry_markup_are_clean() {
    assert_clean(&[
        "el.innerHTML = window.location.protocol;",
        "el.innerHTML = window.location.hostname;",
        "el.innerHTML = document.location.port;",
        "var s = document.createElement('script'); s.src = cfg.road + 'x.js?domain=' + decodeURI(document.location.hostname);",
        "var s = document.createElement('script'); s.src = ''.concat(document.location.protocol, '//cdn.example.com/x.js');",
        "el.innerHTML = Math.max(1, new URLSearchParams(location.search).get('n'));",
        "el.innerHTML = Boolean(location.hash);",
        "el.innerHTML = isNaN(location.hash.slice(1));",
        "el.innerHTML = window.parseInt(location.hash.slice(1));",
        "el.innerHTML = btoa(location.hash);",
        "const { origin } = location; location.href = origin + '/login';",
    ]);
    // `window.location.host` grades like `location.host`, not as URL-carried.
    assert_eq!(
        flows("el.innerHTML = window.location.host;"),
        ["location.host -> innerHTML"]
    );
}

/// A bare `e` is whatever a minifier named a parameter, so `e.data` is a
/// source only where the handler's registration is seen.
#[test]
fn event_properties_need_an_event() {
    assert_clean(&[
        "$.ajax({ url: '/api', success: function (e) { e && e.data && $('#x').html(e.data.html); } });",
        "axios.get('/api').then(function (e) { document.getElementById('x').innerHTML = e.data.html; });",
        "function render(e) { document.getElementById('x').innerHTML = e.data.title; } render({ data: { title: 'x' } });",
        "function run(e) { return Function(e.code)(); }",
    ]);
    assert_reported(&[
        "window.addEventListener('message', function (e) { el.innerHTML = e.data; });",
        "window.addEventListener('message', function (m) { document.write(m.data); });",
        "window.onmessage = function (e) { el.innerHTML = e.data.html; };",
        "function onMsg(e) { el.innerHTML = e.data; } window.addEventListener('message', onMsg);",
        "function receive(event) { el.innerHTML = event.data; }",
        "$(window).on('message', function (e) { el.innerHTML = e.originalEvent.data; });",
        "box.addEventListener('drop', function (ev) { el.innerHTML = ev.dataTransfer.getData('text/html'); });",
        "function drop(ev) { el.innerHTML = ev.dataTransfer.getData('text/html'); }",
        "function onPaste(evt) { el.innerHTML = evt.clipboardData.getData('text/html'); }",
        "class R { constructor() { window.addEventListener('message', this.onMessage.bind(this)); } onMessage(ev) { el.innerHTML = ev.data.html; } } new R();",
    ]);
}

/// An exact origin comparison means the message came from a sender the page
/// chose; a substring test is the classic bypass and proves nothing.
#[test]
fn strict_origin_checks_vouch_for_message_data() {
    assert_clean(&[
        "window.addEventListener('message', function (event) { if (event.origin !== 'https://a.example') return; el.innerHTML = event.data; });",
        "window.addEventListener('message', function (event) { if (event.origin === location.origin) { el.innerHTML = event.data; } });",
        "window.addEventListener('message', function (e) { if (e.source !== parent || e.origin !== ORIGIN) return; el.innerHTML = e.data.html; });",
        "window.onmessage = function (e) { if (e.origin !== window.location.origin) { return; } document.body.innerHTML = e.data.html; };",
        "window.addEventListener('message', ({ origin, data }) => { if (origin !== 'https://a.example') return; el.innerHTML = data; });",
        "var ALLOWED = ['https://a.example', 'https://b.example']; window.addEventListener('message', function (e) { if (!ALLOWED.includes(e.origin)) return; el.innerHTML = e.data; });",
        "function onMsg(e) { if (e.origin !== 'https://a.example') return; el.innerHTML = e.data; } window.addEventListener('message', onMsg);",
        "function receive(event) { if (event.origin !== 'https://a.example') { return; } el.innerHTML = event.data; }",
        // The index held in a variable first (w3schools).
        "window.addEventListener('message', function (m) { var w = ['https://a.example']; var i = w.indexOf(m.origin); if (i === -1) { return; } el.innerHTML = m.data; });",
        "function u(d) { el.innerHTML = d; } window.addEventListener('message', function (m) { var w = ['https://a.example']; var i = w.indexOf(m.origin); if (i === -1) return; u(m.data); });",
        "window.addEventListener('message', function (m) { var i; i = ['https://a.example'].indexOf(m.origin); if (i < 0) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); if (!(i !== -1)) return; el.innerHTML = m.data; });",
    ]);
    assert_reported(&[
        // A substring index through a variable proves nothing either.
        "window.addEventListener('message', function (m) { var i = 'https://a.example'.indexOf(m.origin); if (i === -1) return; el.innerHTML = m.data; });",
        // Anything between the index and its test (review of this change).
        "var ALLOWED = ['https://a.example', '*']; window.addEventListener('message', function (e) { var i = ALLOWED.indexOf(e.origin); ALLOWED.forEach(function (o, k) { if (o === '*') i = k; }); if (i === -1) return; el.innerHTML = e.data; });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); (function () { i = 0; })(); if (i === -1) return; el.innerHTML = m.data; });",
        "var cfg = {}; window.addEventListener('message', function (e) { var i = 0; if (cfg.strict) i = ['https://a.example'].indexOf(e.origin); if (i === -1) return; el.innerHTML = e.data; });",
        "window.addEventListener('message', function (m) { if (m.data.t) { var i = ['https://a.example'].indexOf(m.origin); } if (i === -1) return; el.innerHTML = m.data; });",
        "function f() { var x = location.hash.slice(1); var i = ['a', 'b'].indexOf(x); x = location.search; if (i !== -1) { el.innerHTML = x; } } f();",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); [1].forEach(function (i) { if (i === -1) return; el.innerHTML = m.data; }); });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); i++; if (i === -1) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); [i] = [0]; if (i === -1) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); for (i of [0]) {} if (i === -1) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (m) { var i = 0; { let i = ['https://a.example'].indexOf(m.origin); } if (i === -1) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (e) { var i = ['https://a.example'].indexOf(e.origin); window.addEventListener('message', function (e) { if (i === -1) return; el.innerHTML = e.data; }); });",
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); if (i === -1) { if (i === -1) return; } el.innerHTML = m.data; });",
        // The test's left side runs first and may rebind `i` or the subject.
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); if (!(i = 0, true) || i === -1) return; el.innerHTML = m.data; });",
        "function f() { var x = location.hash.slice(1); var i = ['a', 'b'].indexOf(x); if (!(x = decodeURIComponent(location.search)) || i === -1) return; el.innerHTML = x; } f();",
        // The index from a branch that did not run (needs both resets).
        "window.addEventListener('message', function (m) { var i = 0; if (m.data.a) { i = ['https://a.example'].indexOf(m.origin); if (1) {} } else if (i !== -1) { el.innerHTML = m.data; } });",
        // Rebound before the test.
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); i = 0; if (i === -1) return; el.innerHTML = m.data; });",
        // Another function's `i`.
        "window.addEventListener('message', function (m) { var i = ['https://a.example'].indexOf(m.origin); }); window.addEventListener('message', function (m) { if (i === -1) return; el.innerHTML = m.data; });",
        // `onA`'s own check does not vouch for another handler.
        "function onA(m) { var i = ['https://a.example'].indexOf(m.origin); if (i === -1) return; el.innerHTML = m.data; } window.addEventListener('message', function (m) { if (i === -1) return; el.innerHTML = m.data; });",
        "window.addEventListener('message', function (e) { if (e.origin.indexOf('a.example') === -1) return; el.innerHTML = e.data; });",
        "window.addEventListener('message', function (e) { if (!/a\\.example/.test(e.origin)) return; el.innerHTML = e.data; });",
        "window.addEventListener('message', function (e) { if (!e.origin.startsWith('https://a.example')) return; el.innerHTML = e.data; });",
        "window.addEventListener('message', function (e) { if ('https://a.example'.indexOf(e.origin) === -1) return; el.innerHTML = e.data; });",
        // the check guards something else
        "window.addEventListener('message', function (e) { if (e.origin === 'https://a.example') { log(); } el.innerHTML = e.data; });",
        "window.addEventListener('message', function (e) { if (e.origin !== 'https://a.example' && strict) return; el.innerHTML = e.data; });",
        // compared with attacker data
        "window.addEventListener('message', function (e) { if (e.origin !== e.data.origin) return; el.innerHTML = e.data.html; });",
        // an early return inside a branch does not cover what follows it
        "window.addEventListener('message', function (e) { if (strict) { if (e.origin !== 'https://a.example') return; } el.innerHTML = e.data; });",
        // a function that is not a message handler: `origin` is just a field
        "function f(o) { if (o.origin !== 'x') return; el.innerHTML = o.html; } f(JSON.parse(location.hash.slice(1)));",
    ]);
}

/// After an allowlist test the variable holds page-authored text, or a string
/// from a safe alphabet.
#[test]
fn allowlist_tests_vouch_for_a_variable() {
    assert_clean(&[
        "var t = location.hash.slice(1); if (['a', 'b'].includes(t)) el.innerHTML = '<i class=' + t + '>';",
        "var t = location.hash.slice(1); if (['a', 'b'].indexOf(t) !== -1) { el.innerHTML = t; }",
        "var t = location.hash.slice(1); if (['a', 'b'].indexOf(t) > -1) { el.innerHTML = t; }",
        "var OK = new Set(['a', 'b']); var t = location.hash.slice(1); if (OK.has(t)) el.innerHTML = t;",
        "var t = location.hash.slice(1); if (t === 'intro') { el.innerHTML = '<h1>' + t + '</h1>'; }",
        "var t = location.hash.slice(1); if (t !== 'intro') { x(); } else { el.innerHTML = t; }",
        "var t = location.hash.slice(1); switch (t) { case 'a': case 'b': el.innerHTML = t; break; }",
        "var id = location.hash.slice(1); if (/^[a-z0-9]+$/.test(id)) el.innerHTML = '<div id=\"' + id + '\">';",
        "function show() { var id = location.hash.slice(1); if (!/^\\d+$/.test(id)) return; el.innerHTML = 'Item ' + id; } show();",
        "function show(id) { if (['a', 'b'].indexOf(id) < 0) { return; } el.innerHTML = id; } show(location.hash.slice(1));",
    ]);
    assert_reported(&[
        "var t = location.hash.slice(1); if (['a', 'b'].includes(t)) { x(); } else { el.innerHTML = t; }",
        "var t = location.hash.slice(1); if (!['a', 'b'].includes(t)) { el.innerHTML = t; }",
        "var t = location.hash.slice(1); if (['a', 'b'].includes(t) || force) { el.innerHTML = t; }",
        "var id = location.hash.slice(1); if (/[a-z]+/.test(id)) el.innerHTML = id;",
        "var id = location.hash.slice(1); if (/^[a-z]+$/m.test(id)) el.innerHTML = id;",
        "var id = location.hash.slice(1); if (/^[^<]+$/.test(id)) el.innerHTML = id;",
        "var t = location.hash.slice(1); switch (t) { case 'a': break; default: el.innerHTML = t; }",
        "var t = location.hash.slice(1); switch (t) { default: case 'a': el.innerHTML = t; }",
        "var t = location.hash.slice(1); if (t === other) { el.innerHTML = t; }",
        "var list = [location.hash]; var t = location.hash.slice(1); if (list.includes(t)) el.innerHTML = t;",
        // the guard ends with its branch
        "var t = location.hash.slice(1); if (t === 'a') { x(); } el.innerHTML = t;",
        "function f() { var t = location.hash.slice(1); if (c) { if (t !== 'a') return; } el.innerHTML = t; } f();",
        // a guard inside a function does not clean the outer variable
        "var g = location.hash.slice(1); function f() { if (g !== 'a') return; use(g); } el.innerHTML = g;",
    ]);
}

/// `src` loads a picture or a clip on media elements, and `href` a stylesheet
/// on `<link>`; a frame's `src` navigates the frame.
#[test]
fn src_and_href_depend_on_the_element() {
    assert_clean(&[
        "document.querySelector('img.hero').src = location.hash.slice(1);",
        "document.images[0].src = location.hash.slice(1);",
        "document.getElementsByTagName('img')[0].src = location.hash.slice(1);",
        "var v = document.createElement('video'); v.src = location.hash.slice(1);",
        "var a = new Audio(); a.src = location.hash.slice(1);",
        "var s = document.createElement('source'); s.setAttribute('src', location.hash.slice(1));",
        "var l = document.createElement('link'); l.rel = 'prefetch'; l.href = document.baseURI + 'chunk.js';",
        "var f = document.createElement('iframe'); f.src = 'https://www.youtube.com/embed/' + location.hash.slice(1);",
    ]);
    assert_reported(&[
        "var f = document.createElement('iframe'); f.src = location.hash.slice(1);",
        "var s = document.createElement('script'); s.src = '/js/' + location.hash.slice(1) + '.js';",
        "document.querySelector('.hero img, script').src = location.hash.slice(1);",
        "var a = document.createElement('a'); a.href = location.hash.slice(1);",
    ]);
}

/// The same, for elements the page's HTML declares by `id`.
#[test]
fn element_ids_from_the_page_markup_resolve() {
    let markup = PageMarkup {
        element_tags: [("logo", "img"), ("player", "iframe")]
            .into_iter()
            .map(|(id, tag)| (id.to_string(), tag.to_string()))
            .collect(),
        ..Default::default()
    };
    let scan = |js: &str| {
        AstDomAnalyzer::new()
            .with_reflected_markup(markup.clone())
            .analyze(js)
            .expect("parses")
    };
    for js in [
        "document.getElementById('logo').src = location.hash.slice(1);",
        "var p = document.getElementById('player'); p.src = '/embed/' + location.hash.slice(1);",
    ] {
        assert!(scan(js).is_empty(), "{js}");
    }
    for js in [
        "document.getElementById('player').src = location.hash.slice(1);",
        "document.getElementById('other').src = '/embed/' + location.hash.slice(1);",
    ] {
        assert!(!scan(js).is_empty(), "{js}");
    }
}

/// `x += 'clean'` appends; it does not replace what `x` held.
#[test]
fn appending_clean_text_keeps_the_taint() {
    assert_reported(&[
        "var h = ''; h += '<div>' + location.hash; h += '</div>'; el.innerHTML = h;",
        "var h = location.hash; h ||= 'x'; el.innerHTML = h;",
    ]);
    assert_clean(&["var n = location.hash; n -= 1; el.innerHTML = n;"]);
}

/// `var d = document, w = window, l = location` — the minifier's aliases.
#[test]
fn global_aliases_resolve() {
    assert_reported(&[
        "var d = document, l = location; d.write(l.hash);",
        "var D = document; D.getElementById('x').innerHTML = D.location.hash;",
        "(function (w, d) { d.getElementById('x').innerHTML = w.location.search; })(window, document);",
        "(function ($, win) { $('#x').html(win.location.hash); })(jQuery, window);",
        "var loc = location; el.innerHTML = decodeURIComponent(loc.search);",
        "document.write('<a href=\"' + location + '\">here</a>');",
        "el.innerHTML = location.toString();",
    ]);
    assert_clean(&[
        "var d = document, w = window; d.getElementById('x').textContent = w.location.hash;",
        // the alias ends with its scope, and a local `self` is not the global
        "(function (w) { w.x = 1; })(window); function f(w) { el.innerHTML = w.name; }",
        "function f() { var self = this; el.innerHTML = self.name; }",
        // writing a property of the global does not taint the global
        "(function (e) { e.cfg = e.location.hash; setTimeout(e.tick, 10); })(window);",
        "$(location).attr('href', '/next');",
    ]);
}

/// Methods of one object share its `this`, whatever order they are written in.
#[test]
fn methods_share_their_objects_this() {
    assert_reported(&[
        "var app = { init: function () { this.q = location.hash; this.render(); }, render: function () { el.innerHTML = this.q; } }; app.init();",
        "var app = { render() { el.innerHTML = this.q; }, init() { this.q = location.hash.slice(1); } };",
        "function W() { this.q = location.hash; } W.prototype.render = function () { el.innerHTML = this.q; }; new W().render();",
        "var W = function () { this.q = location.hash; }; W.prototype = { render: function () { el.innerHTML = this.q; } };",
        "function W() {} W.prototype.show = function (h) { el.innerHTML = h; }; var w = new W(); w.show(location.hash);",
    ]);
    assert_clean(&[
        // two objects, two `this`
        "var a = { init: function () { this.q = location.hash; } }; var b = { render: function () { el.innerHTML = this.q; } };",
        "function A() { this.q = location.hash; } function B() {} B.prototype.render = function () { el.innerHTML = this.q; };",
    ]);
}

/// The revealing-module pattern, destructured parameters, and a template
/// compiled from attacker text.
#[test]
fn common_helper_shapes_propagate() {
    assert_reported(&[
        "var Mod = (function () { function get() { return location.hash.slice(1); } return { get: get }; })(); el.innerHTML = Mod.get();",
        "var Mod = (function () { var show = function (h) { el.innerHTML = h; }; return { show }; })(); Mod.show(location.hash);",
        "function f({ q }) { el.innerHTML = q; } f({ q: location.hash });",
        "function f(a, ...rest) { el.innerHTML = rest[0]; } f(1, location.hash);",
        "var compiled = _.template(location.hash.slice(1)); el.innerHTML = compiled({});",
        "el.innerHTML = Handlebars.compile(location.hash.slice(1))({});",
    ]);
    assert_clean(&[
        "function f({ q }) { el.innerHTML = q; } f({ q: 'static' });",
        "var Mod = (function () { function get() { return 'x'; } return { get: get }; })(); el.innerHTML = Mod.get();",
    ]);
}

/// A call to a parameter is a call to whatever the caller passed, not to the
/// function a summary happens to be registered for under the same name.
#[test]
fn a_parameter_is_not_the_function_of_the_same_name() {
    assert_clean(&[
        "function a(x) { el.innerHTML = x; } function run(a) { a(location.hash); }",
        "function t(x) { location.href = x; } window.addEventListener('hashchange', function (b) { each(function (t) { t(b); }); });",
    ]);
    // a body's own declaration takes the name back
    assert_reported(&[
        "function run(a) { function a(x) { el.innerHTML = x; } a(location.hash); } run();",
    ]);
}

/// A sink the body reaches on its own is not its parameter's flow.
#[test]
fn a_free_source_is_not_attributed_to_a_parameter() {
    // reported once, at the sink — not again at the call with `'static'`…
    let js = "function f(x) { el.innerHTML = location.hash; } f('static'); f(document.title);";
    assert_eq!(flows(js), ["location.hash -> innerHTML"]);
    // …nor attributed to an unrelated tainted argument
    let js = "function f(x) { el.innerHTML = location.hash; } f(document.cookie);";
    assert_eq!(flows(js), ["location.hash -> innerHTML"]);
}

/// A helper that navigates to its parameter is only as safe as what it does
/// with it: cutting the head off, or writing it somewhere else too, is not
/// covered by the argument's fixed start.
#[test]
fn a_pinned_argument_only_covers_the_navigation_itself() {
    assert_reported(&[
        "function nav(h) { location.href = h.slice(1); } nav(location.hash);",
        "function redirect(qs) { var n = new URLSearchParams(qs).get('next'); if (n) location.href = n; } redirect(location.search);",
        "function redirect(url) { var m = url.match(/[?&]next=([^&]+)/); if (m) location.href = decodeURIComponent(m[1]); } redirect(location.href);",
        "function go(u) { link.href = u; label.innerHTML = u; } go('/search?q=' + decodeURIComponent(location.hash.slice(1)));",
    ]);
    assert_clean(&[
        "function go(u) { location.href = u; } go('/search?q=' + location.hash.slice(1));",
        "function go(u) { var t = u; window.open(t); } go(location.href);",
    ]);
}

/// Text the page did not fix cannot pin a URL: a `$1` replacement is the
/// match, and a clean variable can hold `javascript:`.
#[test]
fn url_starts_the_page_does_not_fix_are_open() {
    assert_reported(&[
        "var t = location.href.replace(/.*[?&]url=([^&]*).*/, '$1'); location.href = decodeURIComponent(t);",
        "var js = 'javascript:'; a.href = js + \"show('\" + decodeURIComponent(location.hash.slice(1)) + \"')\";",
        // one path of two keeps the attacker's start
        "var u = decodeURIComponent(location.hash.slice(1)); opts.external || (u = '/app/' + u); location.href = u;",
        "var u = decodeURIComponent(location.hash.slice(1)); c ? (u = '/app/' + u) : 0; location.href = u;",
        // rebindings the record does not describe
        "var u = '/x?' + location.hash; try { throw decodeURIComponent(location.hash.slice(1)); } catch (u) { location.href = u; }",
        "var u = '/a?' + location.hash; [u] = [decodeURIComponent(location.hash.slice(1))]; location.href = u;",
        "var u = '/a?' + location.hash; ({ u } = { u: decodeURIComponent(location.hash.slice(1)) }); location.href = u;",
        // a global a function body taints can be re-tainted by any call
        "function set() { u = decodeURIComponent(location.hash.slice(1)); } var u = '/x?' + location.hash; set(); location.href = u;",
        "function set() { u = decodeURIComponent(location.hash.slice(1)); } var u = '/x'; set(); location.href = u;",
    ]);
}

/// An allowlist is only one if the page wrote it and it is as narrow as it
/// looks.
#[test]
fn allowlists_that_admit_the_attacker_vouch_for_nothing() {
    assert_reported(&[
        // `.-_` is the range 0x2E–0x5F: `<`, `>`, `=`, `:` …
        "var x = decodeURIComponent(location.hash.slice(1)); if (/^[a-zA-Z0-9.-_]+$/.test(x)) { el.innerHTML = x; }",
        // `A-z` takes in the backtick
        "var x = decodeURIComponent(location.hash.slice(1)); if (/^[A-z0-9]+$/.test(x)) { eval(x); }",
        // a whole hostname
        "var cdn = new URLSearchParams(location.search).get('cdn'); if (/^[\\w.-]+$/.test(cdn)) { var s = document.createElement('script'); s.src = 'https://' + cdn + '/lib.js'; document.head.appendChild(s); }",
        // origins the attacker supplied
        "var S = new Set(); S.add(new URLSearchParams(location.search).get('o')); window.addEventListener('message', function (e) { if (!S.has(e.origin)) return; document.body.innerHTML = e.data; });",
        "var allowed = new URLSearchParams(location.search).get('origin'); function recv(e) { if (e.origin !== allowed) return; document.body.innerHTML = e.data; } window.addEventListener('message', recv);",
    ]);
    assert_clean(&[
        "var x = decodeURIComponent(location.hash.slice(1)); if (/^[a-zA-Z0-9_-]+$/.test(x)) { el.innerHTML = x; }",
        "var ORIGIN = 'https://a.example'; function recv(e) { if (e.origin !== ORIGIN) return; document.body.innerHTML = e.data; } window.addEventListener('message', recv);",
    ]);
}

/// A `message` handler is found through the ways pages register one, not
/// through its parameter being called `e`.
#[test]
fn message_handlers_are_found_by_their_registration() {
    assert_reported(&[
        "class A { start() { window.addEventListener('message', e => this.onMsg(e)); } onMsg(e) { document.body.innerHTML = e.data; } }",
        "class A { onMsg = (e) => { document.body.innerHTML = e.data; }; start() { window.addEventListener('message', this.onMsg); } }",
        "class A { start() { const h = this.onMsg.bind(this); window.addEventListener('message', h); } onMsg(e) { document.body.innerHTML = e.data; } }",
        "onmessage = function (e) { document.body.innerHTML = e.data; };",
        "var App = { init: function () { window.addEventListener('message', this.recv); }, recv: function (e) { document.body.innerHTML = e.data; } };",
        "window.addEventListener('message', debounce(function (e) { document.body.innerHTML = e.data; }, 100));",
        "function W() { window.addEventListener('message', this.onMsg.bind(this)); } W.prototype.onMsg = function (e) { document.body.innerHTML = e.data; };",
        "function W() { var self = this; window.addEventListener('message', function (e) { self.onMsg(e); }); } W.prototype.onMsg = function (e) { document.body.innerHTML = e.data; };",
        "window.onstorage = function (e) { document.body.innerHTML = e.newValue; };",
    ]);
}

/// Names that look alike are not the same binding — and are, when the code
/// hands the outer one in.
#[test]
fn same_names_in_other_scopes() {
    assert_reported(&[
        "var App = { show: function (h) { document.body.innerHTML = h; } }; (function (App) { App.show(decodeURIComponent(location.hash.slice(1))); })(App);",
        "function readCookie(document) { return document.cookie; } document.body.innerHTML = readCookie(document);",
        "var l = location; el.innerHTML = l;",
        "(function () { var l = location; document.write('<a href=\"' + l + '\">x</a>'); })();",
    ]);
    assert_clean(&[
        // two constructors minified to the same name
        "!function () { function t() { this.value = location.hash; } window.A = t; }(); !function () { function t() {} t.prototype.render = function () { document.body.innerHTML = this.value; }; window.B = t; }();",
        // a block binding hides the global alias of the same name
        "!function () { var e = window, t = document; try { f(); } catch (e) { t.getElementById('err').innerHTML = e.name + ': ' + e.message; } }();",
        "!function () { var e = window; for (let e of users) { out.innerHTML += e.name; } }();",
        "var l = location; { let l = { hash: 'safe' }; document.write(l.hash); }",
        "var d = document; fetch('/x').then(d => { el.innerHTML = d.referrer; });",
        // `Location`'s methods are not its URL
        "setTimeout(location.reload.bind(location), 1000);",
        "setTimeout(location.reload, 1000);",
    ]);
    // A value only the URL context leaves tainted does not taint its neighbours.
    assert_eq!(
        flows(
            "var item = {}; item.href = escapeHtml(location.hash.slice(1)); item.title = 'x'; el.innerHTML = '<b>' + item.title + '</b>';"
        ),
        ["location.hash -> href"]
    );
}

// Babel / TypeScript / esbuild / webpack call every imported function as
// `(0, f)(x)`. It is the same call as `f(x)`, so it gets the same summary.
#[test]
fn comma_callees_use_the_callee_summary() {
    assert_reported(&[
        "function g(){return location.hash} var el=document.body; el.innerHTML=(0,g)();",
        "function g(s){document.body.innerHTML=s} (0,g)(location.hash);",
        "var r={Z:function(s){document.body.innerHTML=s}}; (0,r.Z)(location.hash);",
        "function g(s){document.body.innerHTML=s} ((0,g))(location.hash);",
        "function g(s){document.body.innerHTML=s} (1,2,g)(location.hash);",
    ]);
    assert_clean(&[
        "function g(){return 'x'} document.body.innerHTML=(0,g)();",
        "function g(s){document.body.textContent=s} (0,g)(location.hash);",
        "var r={Z:function(s){document.body.innerHTML='x'}}; (0,r.Z)(location.hash);",
        // `this` is not `o` in a comma call, so `this.x` is not the tainted field.
        "var o={x:location.hash,get:function(){return this.x}}; document.body.innerHTML=(0,o.get)();",
        // `g` is evaluated and discarded; `h` is the callee.
        "function g(s){document.body.innerHTML=s} function h(s){} (g,h)(location.hash);",
    ]);
}

/// A tainted field taints its object as a whole value (`render(o)`,
/// `JSON.stringify(o)`), not the object's other fields: one cookie-derived
/// `ICMS.userId` used to make every `ICMS.*` config value and method result
/// tainted, and webpack's `c.b = document.baseURI` did the same to `c.p`.
#[test]
fn a_tainted_field_does_not_taint_its_siblings() {
    assert_reported(&[
        "var o = {}; o.html = location.hash; document.body.innerHTML = o.html;",
        "var o = {}; o.html = location.hash; document.body.innerHTML = o.html.trim();",
        "var o = {}; o.html = location.hash; function render(c) { document.body.innerHTML = c.html; } render(o);",
        "var o = {}; o.html = location.hash; document.body.innerHTML = JSON.stringify(o);",
        "var o = {}; o.html = location.hash; var p = o; document.body.innerHTML = p.html;",
        "var o = {}; o.a = location.hash; [o].forEach(function (x) { document.body.innerHTML = x.a; });",
        "var o = {}; o.a = JSON.parse(location.hash.slice(1)); document.body.innerHTML = o.a.html;",
        // Rebound to a tainted value whole: every field reads tainted again.
        "var o = {}; o.a = location.hash; o = JSON.parse(location.hash.slice(1)); document.body.innerHTML = o.b;",
        // A whole reassignment inside a nested body outlives it.
        "var params = {}; params.q = new URLSearchParams(location.search).get('q'); window.onhashchange = function () { params = JSON.parse(decodeURIComponent(location.hash.slice(1))); show(); }; function show() { document.getElementById('out').innerHTML = params.msg; }",
        "var cfg = {}; cfg.ref = document.referrer; function load() { cfg = JSON.parse(decodeURIComponent(location.hash.slice(1))); } load(); document.body.innerHTML = cfg.b;",
        // Tainted whole through an escape or a summary's global write.
        "var cfg; (function () { cfg = JSON.parse(decodeURIComponent(location.hash.slice(1))); })(); cfg.ts = location.search; document.body.innerHTML = cfg.html;",
        "var o = {}; o.a = location.search; o = {}; function load() { o = JSON.parse(location.hash.slice(1)); } load(); document.body.innerHTML = o.b;",
        // A field written in a callback whose own field taint is dropped.
        "var o = {}; o.a = location.search; [1].forEach(function () { o.html = location.hash; }); document.body.innerHTML = o.html;",
        "var o = {}; o.a = location.search; $.each([1], function () { o.html = location.hash; }); document.body.innerHTML = o.html;",
        "var o = {}; o.a = location.search; [1].forEach(function () { o.html = location.hash; render(); }); function render() { document.body.innerHTML = o.html; }",
        // Already tainted whole before the field write.
        "var o = JSON.parse(location.hash.slice(1)); o.a = location.hash; document.body.innerHTML = o.b;",
    ]);
    assert_clean(&[
        "var o = {}; o.a = location.hash; o.b = 'x'; document.body.innerHTML = o.b;",
        "var c = {}; c.b = document.baseURI; document.body.innerHTML = c.p;",
        "var c = {}; c.b = document.baseURI; document.body.innerHTML = c.zz(1);",
        "var I = {}; I.userId = document.cookie; I.libs = ['/a.js']; var s = document.createElement('script'); s.src = I.libs[0];",
    ]);
}

fn sinks_of(js: &str) -> Vec<String> {
    found(js).into_iter().map(|v| v.sink).collect()
}

/// Framework output keeps its property and method names through a minifier,
/// whatever the callee and receiver were renamed to: an `innerHTML` prop on a
/// string-tagged vnode (Vue 3 `v-html`, `h()`), `domProps.innerHTML` (Vue 2
/// render functions), and the Angular / AngularJS trust-bypass calls.
#[test]
fn framework_html_sinks_are_keyed_on_names_minifiers_keep() {
    for (js, sink) in [
        (
            r#"var e=location.hash.slice(1);Wr("div",{innerHTML:e},null,8,["innerHTML"])"#,
            "innerHTML",
        ),
        (
            r#"const q=new URLSearchParams(location.search).get("q");h("my-card",{class:"a",innerHTML:q})"#,
            "innerHTML",
        ),
        (
            r#"function r(){var q=location.hash.slice(1);return _c("div",{domProps:{innerHTML:_s(q)}})}"#,
            "innerHTML",
        ),
        (
            "class C{constructor(s){this.s=s}f(){this.h=this.s.bypassSecurityTrustHtml(location.hash.slice(1))}}",
            "bypassSecurityTrustHtml",
        ),
        (
            "t.bypassSecurityTrustScript(decodeURIComponent(location.hash.slice(1)))",
            "bypassSecurityTrustScript",
        ),
        (
            "var u=new URLSearchParams(location.search).get('u');n.bypassSecurityTrustResourceUrl(u)",
            "bypassSecurityTrustResourceUrl",
        ),
        ("e.trustAsHtml(location.hash.substr(1))", "trustAsHtml"),
        ("$sce.trustAsJs(location.hash.substr(1))", "trustAsJs"),
        (
            "$sce.trustAsResourceUrl(location.hash.substr(1))",
            "trustAsResourceUrl",
        ),
        // An HTML sanitizer does not make a value safe to run or to load.
        (
            "t.bypassSecurityTrustScript(DOMPurify.sanitize(location.hash.slice(1)))",
            "bypassSecurityTrustScript",
        ),
        (
            "$sce.trustAsResourceUrl(DOMPurify.sanitize(location.hash.slice(1)))",
            "trustAsResourceUrl",
        ),
        // Reached through a helper, like any other sink.
        (
            "function show(v){return s.bypassSecurityTrustHtml(v)} show(location.hash.slice(1))",
            "bypassSecurityTrustHtml",
        ),
        // esbuild --minify output of a Vue 3 and a Vue 2 app (app code only).
        (
            r##"var Rl=Eo(()=>{mo();ho({render(){let e=location.hash.slice(1);return Es("div",{class:"box",innerHTML:e})}}).mount("#app")});Rl();"##,
            "innerHTML",
        ),
        (
            r##"var Xs=Ai(()=>{$i();new A({el:"#app",render(e){var t=location.hash.slice(1);return e("div",{domProps:{innerHTML:t}})}})});Xs();"##,
            "innerHTML",
        ),
        // vue-template-compiler quotes the key.
        (
            r#"function r(){var q=location.hash.slice(1);return _c('div',{domProps:{"innerHTML":_s(q)}})}"#,
            "innerHTML",
        ),
    ] {
        assert_eq!(sinks_of(js), [sink], "{js}");
    }
}

/// The same names where they are not that sink: an `innerHTML` key that is
/// not a prop of a string-tagged vnode, a sanitized or constant value, and a
/// resource URL whose start the attacker does not write.
#[test]
fn framework_html_sink_lookalikes_are_clean() {
    assert_clean(&[
        // A plain object, a component's props, a non-tag first argument.
        "var q=location.hash.slice(1); var labels={innerHTML:q}; track(labels);",
        "var q=location.hash.slice(1); h(Card,{innerHTML:q});",
        r#"var q=location.hash.slice(1); t("page.title {x}",{innerHTML:q});"#,
        r#"var q=location.hash.slice(1); log("div",q,{innerHTML:"<b>fixed</b>"});"#,
        // The minified controls of the two bundles above.
        r##"var Rl=Eo(()=>{mo();ho({render(){let e=location.hash.slice(1);return Es("div",{class:"box",title:e,innerHTML:"<b>hi</b>"})}}).mount("#app")});Rl();"##,
        r##"var Xs=Ai(()=>{Ti();new A({el:"#app",render(e){var t=location.hash.slice(1);return e("div",{domProps:{textContent:t}})}})});Xs();"##,
        // What a compiled `v-html="q"` template reads is component state.
        r#"function render(_ctx,_cache){return _openBlock(),_createElementBlock("div",{innerHTML:_ctx.q},null,8,["innerHTML"])}"#,
        // Sanitized, escaped or constant values.
        r#"var q=location.hash.slice(1); h("div",{innerHTML:DOMPurify.sanitize(q)});"#,
        r#"_c("div",{domProps:{innerHTML:"<b>static</b>"}});"#,
        r#"var q=location.hash.slice(1); _c("div",{domProps:{textContent:q}});"#,
        "s.bypassSecurityTrustHtml(DOMPurify.sanitize(location.hash.slice(1)));",
        "s.bypassSecurityTrustHtml('<b>static</b>');",
        // A resource URL behind a fixed prefix cannot become `javascript:`.
        "var id=location.hash.slice(1); s.bypassSecurityTrustResourceUrl('https://www.youtube.com/embed/'+id);",
        "$sce.trustAsResourceUrl('/x?q='+new URLSearchParams(location.search).get('q'));",
        // The other bypass methods are not HTML/script/resource sinks.
        "s.bypassSecurityTrustStyle(location.hash.slice(1));",
    ]);
}
