use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

#[test]
fn test_detect_angular_from_body() {
    let headers = make_headers(&[]);
    let body = "<html><div ng-app ng-controller='MainCtrl'>{{name}}</div></html>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
}

#[test]
fn test_detect_react_from_body() {
    let headers = make_headers(&[]);
    let body = "<div id='root' data-reactroot></div>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::React));
}

#[test]
fn test_detect_vue_from_body() {
    let headers = make_headers(&[]);
    let body = "<div data-v-abc123 class='container'></div>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Vue));
}

#[test]
fn test_detect_jquery_from_body() {
    let headers = make_headers(&[]);
    let body = "<script src='https://code.jquery.com/jquery.min.js'></script>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::JQuery));
}

#[test]
fn test_detect_wordpress_from_header() {
    let headers = make_headers(&[("x-generator", "WordPress 6.0")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::WordPress));
}

#[test]
fn test_detect_express_from_header() {
    let headers = make_headers(&[("x-powered-by", "Express")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::Express));
}

#[test]
fn test_detect_php_from_header() {
    let headers = make_headers(&[("x-powered-by", "PHP/8.1")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::PHP));
}

#[test]
fn test_no_tech_detected() {
    let headers = make_headers(&[("server", "nginx")]);
    let result = detect_technologies(&headers, Some("<html><body>ok</body></html>"));
    assert!(result.is_empty());
}

// --- CSTI interpolation-bracket fallback heuristic ---

#[test]
fn test_interpolation_brackets_promote_to_angular_when_no_framework_marker() {
    // SPA bundle that lost its `ng-app` / `angular.js` banner via
    // minification still leaks `{{ name }}` interpolation literals
    // into the rendered HTML. Treat that as evidence of an unidentified
    // client-side template engine so AngularJS template-escape payloads
    // get a shot at the parameter.
    let headers = make_headers(&[]);
    let body = "<html><body><h1>Hello {{ user.name }}!</h1></body></html>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
    let evidence = result
        .detected
        .iter()
        .find(|d| d.tech == TechType::Angular)
        .map(|d| d.evidence.clone())
        .unwrap();
    assert!(
        evidence.contains("interpolation"),
        "fallback evidence should mention interpolation; got {:?}",
        evidence
    );
}

#[test]
fn test_interpolation_brackets_skipped_when_angular_already_detected() {
    // Don't double-add Angular when the strong marker is already present.
    let headers = make_headers(&[]);
    let body = "<html ng-app><h1>Hello {{ name }}!</h1></html>";
    let result = detect_technologies(&headers, Some(body));
    let angular_hits = result
        .detected
        .iter()
        .filter(|d| d.tech == TechType::Angular)
        .count();
    assert_eq!(angular_hits, 1);
}

#[test]
fn test_interpolation_brackets_dont_promote_for_empty_braces() {
    // Empty / whitespace-only braces don't carry an identifier and
    // shouldn't promote the page to Angular. A bare `{{ TODO }}` token
    // intentionally still triggers the heuristic — that's the shape a
    // real interpolation takes, and burning a few template payloads on
    // a doc page is cheap insurance against missing the live framework.
    let headers = make_headers(&[]);
    let body = "<p>Placeholder: {{ }} or {{   }}</p>";
    let result = detect_technologies(&headers, Some(body));
    assert!(!result.has(&TechType::Angular));
}

#[test]
fn test_interpolation_brackets_promote_even_when_identifier_is_a_word() {
    // `{{ TODO }}` looks like a placeholder in prose but is shaped
    // exactly like a real identifier — the framework (if any) would
    // attempt to evaluate it. Better to send the AngularJS payload set
    // and let scan-time reflection check validate than to miss a CSTI
    // sink on a minified SPA.
    let headers = make_headers(&[]);
    let body = "<p>{{ TODO }}</p>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
}

#[test]
fn test_interpolation_brackets_match_identifier_with_dots_and_indices() {
    let headers = make_headers(&[]);
    let body = "<p>{{users[0].name}} {{cfg.theme}}</p>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
}

#[test]
fn test_interpolation_brackets_skipped_when_vue_detected() {
    // Vue already drives template-escape payloads via the existing
    // tech-specific path; the fallback must not duplicate the entry.
    let headers = make_headers(&[]);
    let body = "<div data-v-abc><span>{{message}}</span></div>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Vue));
    assert!(
        !result.has(&TechType::Angular),
        "fallback must yield to a more specific framework match (Vue here)"
    );
}

#[test]
fn test_multiple_techs_detected() {
    let headers = make_headers(&[]);
    let body = "<div ng-app></div><script src='jquery.min.js'></script>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
    assert!(result.has(&TechType::JQuery));
}

#[test]
fn test_angular_payloads_generated() {
    let mut result = TechDetectionResult::default();
    result.detected.push(TechDetection {
        tech: TechType::Angular,
        evidence: "test".to_string(),
    });
    let payloads = get_tech_specific_payloads(&result);
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("constructor")));
}

#[test]
fn test_jquery_payloads_generated() {
    let mut result = TechDetectionResult::default();
    result.detected.push(TechDetection {
        tech: TechType::JQuery,
        evidence: "test".to_string(),
    });
    let payloads = get_tech_specific_payloads(&result);
    assert!(payloads.iter().any(|p| p.contains("globalEval")));
}

#[test]
fn test_display_tech_types() {
    assert_eq!(format!("{}", TechType::Angular), "Angular");
    assert_eq!(format!("{}", TechType::JQuery), "jQuery");
    assert_eq!(format!("{}", TechType::WordPress), "WordPress");
}
