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
    // Cheap reject before parsing (the HTML parse is depth-quadratic, bounded):
    // braces + marker are escape-transparent, so byte-exact survival is a
    // precondition.
    if !body.contains(probe) {
        return false;
    }
    let roots = root_attrs(tech);
    let document = crate::utils::html::parse_document_bounded(body);
    'occurrence: for node in document.tree.nodes() {
        let Node::Text(text) = node.value() else {
            continue;
        };
        if !text.contains(probe) {
            continue;
        }
        // Walk ancestors (text nodes carry no attributes of their own). The
        // occurrence is CSTI only if it is under a compile-root element and no
        // ancestor suppresses compilation.
        let mut under_root = false;
        for anc in node.ancestors() {
            let Node::Element(el) = anc.value() else {
                continue;
            };
            if NON_COMPILED_ELEMENTS.contains(&el.name())
                || el.attr("v-pre").is_some()
                || el.attr("ng-non-bindable").is_some()
            {
                continue 'occurrence;
            }
            if roots.iter().any(|a| el.attr(a).is_some()) {
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
}
