//! Client-side template injection (CSTI) probe + static confirmation (#1520).
//!
//! AngularJS 1.x and Vue compile `{{…}}` interpolation found in the markup the
//! server rendered, so a `{{expr}}` reflected into the compiled region executes
//! in the browser **even when the server HTML-escaped the surrounding
//! structural characters** — entity escaping is transparent to the framework
//! compiler, which reads the entity-decoded text node. That is exactly the case
//! the byte-level reflection checks demote as an "escaped echo"
//! (`check_reflection::classify_reflection` returns `None`), which is why the
//! AngularJS/Vue findings in the 2026-06 FN hunt (c40, c41) went unreported.
//!
//! This module adds a dedicated fallback probe, run only when the ordinary
//! reflection phase found nothing for the parameter and a server-template
//! framework was fingerprinted. With no browser the evidence ceiling is static:
//! we report when a unique `{{marker}}` survives with braces intact *inside the
//! framework's compile root* (an `ng-app` / `ng-controller` / `v-app` subtree)
//! and not in a region the compiler skips, grading confidence Low.

use std::sync::OnceLock;

use scraper::Node;

use crate::scanning::tech_detect::TechType;
use crate::target_parser::Target;

static PROBE: OnceLock<String> = OnceLock::new();

/// The CSTI probe: a brace-wrapped scan marker with no HTML-special characters,
/// so it survives verbatim through an HTML-escaping reflection (braces and the
/// alnum `dlx…` marker are untouched by entity escaping). A bare identifier
/// evaluates to the empty string client-side — the braces vanish from the
/// browser DOM — so the detectable signal is the literal braces surviving in
/// the *server* response, i.e. a reflection into a region the framework
/// compiles.
pub(crate) fn probe() -> &'static str {
    PROBE
        .get_or_init(|| format!("{{{{{}}}}}", crate::scanning::markers::class_marker()))
        .as_str()
}

/// Elements whose text content the framework compiler never reads as a template
/// (rawtext / escapable-rawtext). A `{{…}}` here is literal text.
const NON_COMPILED_ELEMENTS: &[&str] = &["script", "style", "textarea", "title"];

/// `<template>` content is an inert fragment (`.content`, not `childNodes`)
/// that AngularJS never walks. Vue compiles in-DOM templates from `outerHTML`,
/// so its `<template v-if|v-for|v-slot>` wrappers *are* compiled.
fn is_non_compiled(tech: &TechType, el: &scraper::node::Element) -> bool {
    NON_COMPILED_ELEMENTS.contains(&el.name())
        || (el.name() == "template" && !matches!(tech, TechType::Vue))
}

/// In-DOM compile-root attributes, per framework. An element carrying one marks
/// the subtree the framework compiles: AngularJS bootstraps on `ng-app` /
/// `ng-controller`; Vuetify roots a Vue app on `v-app`. A reflected `{{…}}` is
/// CSTI only when it lands *inside* such a subtree.
fn root_attrs(tech: &TechType) -> &'static [&'static str] {
    match tech {
        TechType::Vue => &["v-app"],
        _ => &["ng-app", "ng-controller"],
    }
}

/// AngularJS directive-name normalization: `data-` / `x-` prefixes and `:` /
/// `_` delimiters name the same directive (`data-ng-app`, `ng:non-bindable`).
/// Vue has no such aliasing (`data-v-app` is Vue 3's mounted-container mark,
/// `data-v-pre` is compiled), so `v-*` names match exactly.
fn is_directive(attr: &str, directive: &str) -> bool {
    if !directive.starts_with("ng-") {
        return attr == directive;
    }
    let a = attr
        .strip_prefix("data-")
        .or_else(|| attr.strip_prefix("x-"))
        .unwrap_or(attr);
    a.len() == directive.len()
        && a.bytes()
            .zip(directive.bytes())
            .all(|(x, y)| x == y || (y == b'-' && (x == b':' || x == b'_')))
}

fn has_directive(el: &scraper::node::Element, directive: &str) -> bool {
    if directive == "ng-app" {
        // Auto-bootstrap (`angularInit`) scans only these four spellings, not
        // `$compile`'s full normalization (`ng_app` never bootstraps).
        return ["ng-app", "data-ng-app", "ng:app", "x-ng-app"]
            .iter()
            .any(|a| el.attr(a).is_some());
    }
    el.attrs().any(|(name, _)| is_directive(name, directive))
}

fn is_compile_root(tech: &TechType, el: &scraper::node::Element) -> bool {
    // Vuetify's root is the `<v-app>` component element, not an attribute.
    (matches!(tech, TechType::Vue) && el.name() == "v-app")
        || root_attrs(tech).iter().any(|d| has_directive(el, d))
}

fn suppresses_compile(el: &scraper::node::Element) -> bool {
    has_directive(el, "v-pre") || has_directive(el, "ng-non-bindable")
}

/// The page swaps the interpolation symbols (common when a Jinja/Twig/Django
/// template also owns `{{…}}`), so a reflected `{{…}}` is literal text.
fn custom_delimiters(tech: &TechType, body: &str) -> bool {
    match tech {
        // Vue's option is an array literal (`delimiters: ['${', '}']`); a bare
        // `delimiters:` (CSV/tokenizer configs) must not mute the finding.
        TechType::Vue => body.match_indices("delimiters").any(|(i, m)| {
            body[i + m.len()..]
                .trim_start()
                .strip_prefix(':')
                .is_some_and(|rest| rest.trim_start().starts_with('['))
        }),
        // The setter takes a string (`startSymbol('[[')`); the getter
        // `$interpolate.startSymbol()` appears in ordinary directive code.
        _ => body.match_indices("startSymbol(").any(|(i, m)| {
            body[i + m.len()..]
                .trim_start()
                .starts_with(['\'', '"', '`'])
        }),
    }
}

/// The server-template framework whose compiler evaluates server-rendered
/// `{{…}}` *and* whose compile root is locatable in static HTML, or `None`.
///
/// Gated to a detection via an in-DOM root attribute, so neither a script
/// reference (`angular.js` — says nothing about where, or whether, an app is
/// bootstrapped) nor Vue's `data-v-` precompiled-SFC marker (a runtime-only
/// build that never interpolates server markup) qualifies. Angular 2+
/// (`ng-version`, AOT) and the bare-`{{…}}`-literal fallback heuristic are
/// excluded for free — they are not root-attribute evidence. React and Vue 3
/// without in-DOM templates never compile server interpolation.
///
/// The evidence strings mirror `tech_detect`'s `BODY_RULES`; the end-to-end
/// tests run the real detector, so a drift breaks them (in the safe direction —
/// a disabled probe, never a false positive).
// ponytail: a Vue app mounted on a bare `<div id="app">` (no `v-app`) has no
// static root signal, so it is a known miss — locating it needs a browser.
pub(crate) fn server_template_framework(target: &Target) -> Option<TechType> {
    let tech = target.tech_info.as_ref()?;
    for d in &tech.detected {
        match d.tech {
            TechType::Angular
                if matches!(
                    d.evidence.as_str(),
                    "ng-app attribute" | "ng-controller attribute"
                ) =>
            {
                return Some(TechType::Angular);
            }
            TechType::Vue if d.evidence == "v-app attribute" => return Some(TechType::Vue),
            _ => {}
        }
    }
    None
}

/// Static confirmation that a surviving probe is CSTI, not an inert echo: the
/// `{{marker}}` appears with braces intact in HTML **text content** that lies
/// inside the framework's compile root (`root_attrs`) and under no element the
/// compiler skips — rawtext, a `v-pre` subtree, or an `ng-non-bindable`
/// subtree.
///
/// Parsing (rather than a byte walk) gives the ancestry check for free: a probe
/// that landed inside a tag as an attribute value — not a text node — is
/// rejected, and the root-containment / suppression checks are plain ancestor
/// walks. The resolved `tech` is passed in (not re-derived) so the detection
/// path runs `server_template_framework` once.
pub(crate) fn probe_confirms_csti(tech: &TechType, body: &str) -> bool {
    let probe = probe();
    // Cheap reject before parsing (the HTML parse is depth-quadratic, bounded).
    // Only the alnum marker is a byte-exact precondition: the braces may come
    // back entity-encoded (`&#123;`), which the compiler sees decoded.
    if !body.contains(crate::scanning::markers::class_marker()) || custom_delimiters(tech, body) {
        return false;
    }
    let document = crate::utils::html::parse_document_bounded(body);
    'occurrence: for node in document.tree.nodes() {
        // Text interpolation (both frameworks), or — AngularJS only; Vue 2+
        // dropped it — attribute-value interpolation on the element itself.
        let mut under_root = match node.value() {
            Node::Text(text) if text.contains(probe) => false,
            Node::Element(el)
                if !matches!(tech, TechType::Vue)
                    // AngularJS refuses (`$compile:nodomevents`) to interpolate
                    // `EVENT_HANDLER_ATTR_REGEXP` = `/^(on[a-z]+|formaction)$/`.
                    && el.attrs().any(|(n, v)| {
                        v.contains(probe) && !n.starts_with("on") && n != "formaction"
                    }) =>
            {
                if suppresses_compile(el) {
                    continue;
                }
                is_compile_root(tech, el)
            }
            _ => continue,
        };
        // The occurrence is CSTI only if it is under a compile-root element and
        // no ancestor suppresses compilation.
        for anc in node.ancestors() {
            let Node::Element(el) = anc.value() else {
                continue;
            };
            if is_non_compiled(tech, el) || suppresses_compile(el) {
                continue 'occurrence;
            }
            if is_compile_root(tech, el) {
                under_root = true;
            }
        }
        if under_root {
            return true;
        }
    }
    false
}

/// A version-aware sandbox-escape expression for the detected framework, shown
/// in the finding's PoC so the operator can confirm execution in a browser.
/// Mirrors the gadgets in `tech_detect::get_tech_specific_payloads` (browser-
/// verified: AngularJS 1.6+ via `Function` constructor; Vue 2/3 via `$emit`).
pub(crate) fn sandbox_escape_payload(tech: &TechType) -> &'static str {
    match tech {
        TechType::Vue => "{{$emit.constructor('alert(1)')()}}",
        // AngularJS 1.x and anything else we treat as server-template.
        _ => "{{constructor.constructor('alert(1)')()}}",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::tech_detect::{TechDetection, TechDetectionResult};

    fn bare_target() -> Target {
        Target::for_url(url::Url::parse("https://example.com/?q=x").expect("valid url"))
    }

    fn target_with(tech: Vec<TechDetection>) -> Target {
        let mut t = bare_target();
        t.tech_info = Some(TechDetectionResult { detected: tech });
        t
    }

    fn det(tech: TechType, evidence: &str) -> TechDetection {
        TechDetection {
            tech,
            evidence: evidence.to_string(),
        }
    }

    #[test]
    fn probe_is_brace_wrapped_marker() {
        let p = probe();
        assert!(p.starts_with("{{") && p.ends_with("}}"));
        assert!(p.contains(crate::scanning::markers::class_marker()));
        // No HTML-special characters, so an HTML-escaping reflection leaves it
        // byte-identical — the whole point of the probe.
        assert!(!p.contains(['<', '>', '"', '\'', '&']));
    }

    #[test]
    fn server_template_scope() {
        // In-DOM root attributes → in scope.
        assert_eq!(
            server_template_framework(&target_with(vec![det(
                TechType::Angular,
                "ng-app attribute"
            )])),
            Some(TechType::Angular)
        );
        assert_eq!(
            server_template_framework(&target_with(vec![det(
                TechType::Angular,
                "ng-controller attribute"
            )])),
            Some(TechType::Angular)
        );
        assert_eq!(
            server_template_framework(&target_with(vec![det(TechType::Vue, "v-app attribute")])),
            Some(TechType::Vue)
        );

        // Script-only Angular, Angular 2+, Vue `data-v-` precompiled SFC, and
        // React → out of scope (no locatable in-DOM compile root).
        for out in [
            det(TechType::Angular, "angular.min.js script"),
            det(TechType::Angular, "ng-version attribute"),
            det(TechType::Vue, "data-v- scoped style attribute"),
            det(TechType::Vue, "vue.min.js script"),
            det(TechType::React, "data-reactroot attribute"),
        ] {
            assert_eq!(server_template_framework(&target_with(vec![out])), None);
        }
        assert_eq!(server_template_framework(&bare_target()), None);
    }

    #[test]
    fn confirms_only_inside_compile_root() {
        let p = probe();
        let ng = TechType::Angular;

        // Escaped markup around the probe inside the ng-app root: braces survive
        // in a compiled text node → CSTI.
        assert!(probe_confirms_csti(
            &ng,
            &format!("<html ng-app><body><h1>{p} &lt;span&gt;</h1></body></html>")
        ));
        // ng-controller is also a root.
        assert!(probe_confirms_csti(
            &ng,
            &format!("<div ng-controller=\"C\"><span>{p}</span></div>")
        ));

        // Reflected OUTSIDE the compile root (sibling of the ng-app element) →
        // the framework never evaluates it.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<body><div ng-app>app</div><footer>{p}</footer></body>")
        ));
        // No root attribute anywhere → not confirmed.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<body><div>{p}</div></body>")
        ));

        // Inside the root but in a region the compiler skips.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><script>var x=\"{p}\";</script></html>")
        ));
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><textarea>{p}</textarea></html>")
        ));
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><div v-pre>{p}</div></html>")
        ));
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><div ng-non-bindable>{p}</div></html>")
        ));

        // Probe absent.
        assert!(!probe_confirms_csti(
            &ng,
            "<html ng-app><div>nothing</div></html>"
        ));

        // Vue roots on v-app.
        assert!(probe_confirms_csti(
            &TechType::Vue,
            &format!("<div v-app><p>{p}</p></div>")
        ));
    }

    #[test]
    fn directive_aliases_attrs_and_delimiters() {
        let p = probe();
        let m = crate::scanning::markers::class_marker();
        let ng = TechType::Angular;
        // Normalized directive names: `data-ng-app` root, `data-ng-non-bindable` skip.
        assert!(probe_confirms_csti(
            &ng,
            &format!("<html data-ng-app><h1>{p}</h1></html>")
        ));
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><div data-ng-non-bindable>{p}</div></html>")
        ));
        // Entity-encoded braces decode to `{{…}}` in the DOM the compiler reads.
        assert!(probe_confirms_csti(
            &ng,
            &format!("<html ng-app><h1>&#123;&#123;{m}&#125;&#125;</h1></html>")
        ));
        // AngularJS interpolates attribute values; not `on*`, not Vue.
        assert!(probe_confirms_csti(
            &ng,
            &format!("<html ng-app><input value=\"{p}\"></html>")
        ));
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><a onclick=\"{p}\">x</a></html>")
        ));
        assert!(!probe_confirms_csti(
            &TechType::Vue,
            &format!("<div v-app><input value=\"{p}\"></div>")
        ));
        // `<template>` content is never compiled.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><template><p>{p}</p></template></html>")
        ));
        // Custom interpolation symbols make `{{…}}` literal.
        assert!(!probe_confirms_csti(
            &ng,
            &format!(
                "<html ng-app><script>$interpolateProvider.startSymbol('[[');</script><h1>{p}</h1></html>"
            )
        ));
        // Vuetify's root is the `<v-app>` element.
        assert!(probe_confirms_csti(
            &TechType::Vue,
            &format!("<div id=app><v-app><v-main>{p}</v-main></v-app></div>")
        ));
        // `ng_app` is a `$compile` alias but never auto-bootstraps.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<div ng_app><p>{p}</p></div>")
        ));
        assert!(probe_confirms_csti(
            &ng,
            &format!("<div x-ng-app><p>{p}</p></div>")
        ));
        // Vue compiles `<template v-if>` content (in-DOM templates use outerHTML).
        assert!(probe_confirms_csti(
            &TechType::Vue,
            &format!("<div v-app><template v-if=\"ok\"><p>{p}</p></template></div>")
        ));
        // Vue names are exact: `data-v-app` is Vue 3's runtime mount mark, not
        // a compile root; `data-v-pre` is not `v-pre`.
        assert!(!probe_confirms_csti(
            &TechType::Vue,
            &format!("<div id=app data-v-app><p>{p}</p></div>")
        ));
        assert!(probe_confirms_csti(
            &TechType::Vue,
            &format!("<div v-app><p data-v-pre>{p}</p></div>")
        ));
        // The `startSymbol()` getter does not mean custom symbols.
        assert!(probe_confirms_csti(
            &ng,
            &format!(
                "<html ng-app><script>var s=$interpolate.startSymbol();</script><h1>{p}</h1></html>"
            )
        ));
        // `formaction` is in AngularJS's no-interpolation set, like `on*`.
        assert!(!probe_confirms_csti(
            &ng,
            &format!("<html ng-app><form><button formaction=\"{p}\">x</button></form></html>")
        ));
        // Vue `delimiters: [...]` mutes; an unrelated `delimiters:` key does not.
        assert!(!probe_confirms_csti(
            &TechType::Vue,
            &format!(
                "<script>new Vue({{delimiters : ['${{', '}}']}})</script><div v-app><p>{p}</p></div>"
            )
        ));
        assert!(probe_confirms_csti(
            &TechType::Vue,
            &format!("<script>csv({{delimiters: ',;'}})</script><div v-app><p>{p}</p></div>")
        ));
    }
}
