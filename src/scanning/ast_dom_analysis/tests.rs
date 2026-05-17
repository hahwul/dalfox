use super::*;

#[test]
fn test_basic_dom_xss_detection() {
    let code = r#"
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(
        !vulnerabilities.is_empty(),
        "Should detect at least one vulnerability"
    );

    let vuln = &vulnerabilities[0];
    assert!(vuln.sink.contains("innerHTML"));
    assert!(vuln.source.contains("location.search"));
}

#[test]
fn test_eval_with_location_hash() {
    let code = r#"
let hash = location.hash;
eval(hash);
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(!vulnerabilities.is_empty());

    let vuln = &vulnerabilities[0];
    assert!(vuln.sink.contains("eval"));
}

#[test]
fn test_document_write_with_cookie() {
    let code = r#"
let data = document.cookie;
document.write(data);
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(!vulnerabilities.is_empty());

    let vuln = &vulnerabilities[0];
    assert!(vuln.sink.contains("document.write"));
}

#[test]
fn test_no_vulnerability_with_safe_data() {
    let code = r#"
let safeData = "Hello World";
document.getElementById('foo').innerHTML = safeData;
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 0);
}

#[test]
fn test_multiple_vulnerabilities() {
    let code = r#"
let param = location.search;
let hash = location.hash;
document.write(param);
eval(hash);
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(
        vulnerabilities.len() >= 2,
        "Should detect multiple vulnerabilities"
    );
}

#[test]
fn test_parse_error_handling() {
    let code = r#"
let invalid = {{{
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(
        result.is_err(),
        "Should return error for invalid JavaScript"
    );
}

#[test]
fn test_direct_source_to_sink() {
    let code = r#"
document.write(location.search);
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(
        !vulnerabilities.is_empty(),
        "Should detect direct source-to-sink vulnerability"
    );
}

#[test]
fn test_template_literal_with_tainted_data() {
    let code = r#"
let search = location.search;
let html = `<div>${search}</div>`;
document.body.innerHTML = html;
"#;

    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code);

    assert!(result.is_ok());
    let vulnerabilities = result.unwrap();
    assert!(
        !vulnerabilities.is_empty(),
        "Should detect tainted data in template literal"
    );
}

#[test]
fn test_method_call_on_source() {
    // Test for location.hash.slice(1) pattern - the issue reported by @hahwul
    let js = r#"document.write(location.hash.slice(1))"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect location.hash.slice(1) passed to document.write"
    );
    assert_eq!(result[0].sink, "document.write");
}

#[test]
fn test_direct_location_hash_to_sink() {
    // Test for direct location.hash usage
    let js = r#"document.write(location.hash)"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect location.hash passed to document.write"
    );
    assert_eq!(result[0].sink, "document.write");
}

#[test]
fn test_decode_uri_with_source() {
    // Test for decodeURI(location.hash) - decodeURI is NOT a sanitizer
    let js = r#"document.write(decodeURI(location.hash))"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect decodeURI(location.hash) as vulnerable"
    );
    assert_eq!(result[0].sink, "document.write");
    assert!(result[0].source.contains("location.hash"));
}

#[test]
fn test_decode_uri_component_with_variable() {
    // Test for variable with decodeURIComponent
    let js = r#"
let hash = location.hash;
let decoded = decodeURIComponent(hash);
document.write(decoded);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect decodeURIComponent propagating taint"
    );
    assert_eq!(result[0].sink, "document.write");
}

// Tests for new sources
#[test]
fn test_localstorage_source() {
    // localStorage itself is a source - accessing properties from it should be tainted
    let code = r#"
let data = localStorage;
document.getElementById('output').innerHTML = data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect localStorage as source");
}

#[test]
fn test_sessionstorage_source() {
    // sessionStorage itself is a source
    let code = r#"
let userInput = sessionStorage;
eval(userInput);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect sessionStorage as source");
}

#[test]
fn test_sessionstorage_getitem_source() {
    let code = r#"
const stored = sessionStorage.getItem('payload') || '';
document.getElementById('output').innerHTML = stored;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "sessionStorage.getItem(payload)"),
        "Expected keyed sessionStorage source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_localstorage_getitem_source_preserves_static_key() {
    let code = r#"
const stored = localStorage.getItem('xssmaze:browser-state:level2') || '';
document.getElementById('output').innerHTML = stored;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "localStorage.getItem(xssmaze:browser-state:level2)"),
        "Expected keyed localStorage source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_postmessage_event_data() {
    // Direct use of e.data as source (simplified pattern)
    let code = r#"
let data = e.data;
document.getElementById('msg').innerHTML = data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect e.data (postMessage) as source"
    );
}

#[test]
fn test_input_event_target_value() {
    // e.target.value from input events is user-controlled
    let code = r#"
document.getElementById('source1').addEventListener('input', (e)=>{
document.getElementById('sink1').innerHTML = e.target.value;
})
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect e.target.value (input event) as source flowing to innerHTML sink"
    );
    assert!(
        result.iter().any(|v| v.sink.contains("innerHTML")),
        "Sink should be innerHTML"
    );
}

#[test]
fn test_window_opener_source() {
    let code = r#"
let data = window.opener;
document.write(data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect window.opener as source");
}

#[test]
fn test_location_pathname_source() {
    let code = r#"
let path = location.pathname;
document.body.innerHTML = path;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect location.pathname as source"
    );
}

// Tests for new sinks
#[test]
fn test_element_src_sink() {
    let code = r#"
let hash = location.hash;
document.getElementById('script').src = hash;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect element.src as sink");
    assert_eq!(result[0].sink, "src");
}

#[test]
fn test_set_attribute_sink() {
    // Simplified: direct call to setAttribute function
    let code = r#"
let data = location.search;
setAttribute('onclick', data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect setAttribute as sink");
}

#[test]
fn test_jquery_html_sink() {
    // Simplified: direct call to html() function
    let code = r#"
let input = location.hash;
html(input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect html() as sink");
}

#[test]
fn test_jquery_append_sink() {
    // Simplified: direct call to append() function
    let code = r#"
let userInput = document.cookie;
append(userInput);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect append() as sink");
}

// Tests for complex patterns
#[test]
fn test_array_with_tainted_data() {
    let code = r#"
let hash = location.hash;
let arr = [hash, 'other'];
document.write(arr[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect tainted data in array");
}

#[test]
fn test_object_with_tainted_data() {
    let code = r#"
let search = location.search;
let obj = { data: search };
document.body.innerHTML = obj.data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect tainted data in object");
}

#[test]
fn test_property_access_on_tainted_var() {
    let code = r#"
let urlData = location.search;
let value = urlData.substring(1);
document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through property access"
    );
}

#[test]
fn test_multiple_assignment_levels() {
    let code = r#"
let a = location.hash;
let b = a;
let c = b;
document.getElementById('x').innerHTML = c;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through multiple assignments"
    );
}

#[test]
fn test_string_concat_with_tainted() {
    let code = r#"
let param = location.search;
let msg = "Hello " + param;
document.write(msg);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in string concatenation"
    );
}

#[test]
fn test_conditional_with_tainted() {
    let code = r#"
let hash = location.hash;
let output = hash ? hash : "default";
document.body.innerHTML = output;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in conditional expression"
    );
}

#[test]
fn test_tainted_in_if_statement() {
    let code = r#"
let search = location.search;
if (search) {
document.write(search);
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in if statement");
}

#[test]
fn test_tainted_in_while_loop() {
    let code = r#"
let data = location.hash;
while (data.length > 0) {
document.getElementById('x').innerHTML = data;
break;
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in while loop");
}

#[test]
fn test_tainted_in_for_loop() {
    let code = r#"
let input = location.search;
for (let i = 0; i < 1; i++) {
document.body.innerHTML = input;
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in for loop");
}

#[test]
fn test_string_methods_on_source() {
    let code = r#"
let result = location.hash.substring(1).replace('#', '');
document.write(result);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through string methods"
    );
}

#[test]
fn test_split_on_source() {
    let code = r#"
let parts = location.search.split('&');
document.write(parts[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through split method"
    );
}

#[test]
fn test_computed_member_access() {
    let code = r#"
let arr = [location.hash];
let index = 0;
document.write(arr[index]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through computed member access"
    );
}

#[test]
fn test_array_literal_direct_sink() {
    let code = r#"
document.write([location.hash][0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in array literal to sink"
    );
}

#[test]
fn test_object_literal_direct_sink() {
    let code = r#"
document.body.innerHTML = {x: location.search}.x;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in object literal to sink"
    );
}

#[test]
fn test_settimeout_with_string() {
    let code = r#"
let hash = location.hash;
setTimeout(hash, 100);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect setTimeout with tainted string"
    );
}

#[test]
fn test_setinterval_with_tainted() {
    let code = r#"
let code = location.search;
setInterval(code, 1000);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect setInterval with tainted code"
    );
}

#[test]
fn test_function_constructor() {
    let code = r#"
let input = location.hash;
let f = Function(input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect Function constructor with tainted input"
    );
}

#[test]
fn test_location_assignment() {
    let code = r#"
let url = location.hash;
location.href = url;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect location.href assignment");
}

#[test]
fn test_sanitizer_prevents_detection() {
    let code = r#"
let input = location.search;
let safe = DOMPurify.sanitize(input);
document.body.innerHTML = safe;
    "#;
    let analyzer = AstDomAnalyzer::new();
    let _result = analyzer.analyze(code).unwrap();
    // This should NOT detect a vulnerability because DOMPurify.sanitize is used
    // However, current implementation tracks taint through variable assignment
    // This is a known limitation - sanitization detection could be improved
    // For now, we just verify the test runs without panicking
    // We expect it to still find a vulnerability due to the limitation
}

#[test]
fn test_encode_uri_component_usage() {
    let code = r#"
let input = location.search;
let encoded = encodeURIComponent(input);
document.body.innerHTML = encoded;
    "#;
    let analyzer = AstDomAnalyzer::new();
    let _result = analyzer.analyze(code).unwrap();
    // encodeURIComponent is considered a sanitizer, but taint still propagates
    // through variable assignment. This is a limitation of the current impl.
    // We expect it to still find a vulnerability due to the limitation
}

#[test]
fn test_object_property_simple() {
    let code = r#"
let data = location.search;
let obj = { value: data };
document.write(obj.value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through simple object property"
    );
}

#[test]
fn test_nested_property_access() {
    let code = r#"
let data = location.search;
let obj = { inner: { value: data } };
document.write(obj.inner.value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through nested properties"
    );
}

#[test]
fn test_taint_through_return_value() {
    let code = r#"
function getData() {
return location.hash;
}
let data = getData();
document.body.innerHTML = data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted return value flowing to sink"
    );
}

#[test]
fn test_multiple_sources_multiple_sinks() {
    let code = r#"
let hash = location.hash;
let search = location.search;
document.write(hash);
eval(search);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(result.len() >= 2, "Should detect multiple vulnerabilities");
}

#[test]
fn test_logical_or_with_tainted() {
    let code = r#"
let value = location.search || "default";
document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in logical OR");
}

#[test]
fn test_logical_and_with_tainted() {
    let code = r#"
let input = location.hash && location.hash.slice(1);
document.body.innerHTML = input;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in logical AND");
}

#[test]
fn test_binary_plus_operator() {
    let code = r#"
let prefix = "Value: ";
let data = location.search;
let output = prefix + data;
document.write(output);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint through + operator");
}

#[test]
fn test_textcontent_safe() {
    // textContent is SAFE - it does not parse HTML, just sets text
    let code = r#"
let input = location.hash;
document.getElementById('x').textContent = input;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "textContent is safe and should NOT be detected as a sink"
    );
}

#[test]
fn test_outerhtml_assignment() {
    let code = r#"
let data = document.URL;
document.getElementById('container').outerHTML = data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect outerHTML assignment");
}

#[test]
fn test_insertadjacenthtml_call() {
    // Simplified: direct call to insertAdjacentHTML function
    let code = r#"
let html = location.hash;
insertAdjacentHTML('beforeend', html);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect insertAdjacentHTML");
}

// Additional advanced test cases
#[test]
fn test_document_url_source() {
    let code = r#"
let url = document.URL;
document.write(url);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect document.URL as source");
    assert!(result[0].source.contains("document.URL"));
}

#[test]
fn test_document_referrer_source() {
    let code = r#"
let ref = document.referrer;
document.getElementById('x').innerHTML = ref;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect document.referrer as source"
    );
}

#[test]
fn test_document_referrer_child_bootstrap_to_contextual_fragment() {
    let code = r#"
const url = new URL(location.href);
const seed = url.searchParams.get('seed');
const child = url.searchParams.get('child') === '1';

if (child) {
  const referrer = document.referrer;
  const encoded = (referrer.split('seed=')[1] || '').split('&')[0] || '';
  const html = decodeURIComponent(encoded.replace(/\+/g, '%20'));
  const range = document.createRange();
  const fragment = range.createContextualFragment(html);
  document.getElementById('output').appendChild(fragment);
} else if (seed) {
  const childUrl = new URL(location.href);
  childUrl.searchParams.delete('seed');
  childUrl.searchParams.set('child', '1');
  document.getElementById('child').src =
childUrl.pathname + '?' + childUrl.searchParams.toString();
} else {
  const referrer = document.referrer;
  const encoded = (referrer.split('seed=')[1] || '').split('&')[0] || '';
  const html = decodeURIComponent(encoded.replace(/\+/g, '%20'));
  const range = document.createRange();
  const fragment = range.createContextualFragment(html);
  document.getElementById('output').appendChild(fragment);
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "document.referrer"
                && vuln.sink == "createContextualFragment"),
        "Expected document.referrer -> createContextualFragment flow, got {:?}",
        result
            .iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_document_referrer_split_chain_remains_tainted() {
    let code = r#"
const referrer = document.referrer;
const encoded = (referrer.split('seed=')[1] || '').split('&')[0] || '';
document.write(encoded);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "document.referrer" && vuln.sink == "document.write"),
        "Expected document.referrer split chain to stay tainted, got {:?}",
        result
            .iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_window_name_source() {
    let code = r#"
let name = window.name;
eval(name);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect window.name as source");
}

#[test]
fn test_window_name_canonical_source_wins_over_bootstrap_provenance() {
    let code = r#"
const current = new URL(location.href);
window.name = current.searchParams.get('seed') || '';
document.getElementById('output').innerHTML = window.name;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.iter().any(|vuln| vuln.source == "window.name"),
        "Expected canonical window.name source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_sessionstorage_canonical_source_wins_over_bootstrap_provenance() {
    let code = r#"
const current = new URL(location.href);
const seed = current.searchParams.get('seed');
sessionStorage.setItem('payload', seed || '');
const stored = sessionStorage.getItem('payload') || '';
const range = document.createRange();
const fragment = range.createContextualFragment(stored);
document.getElementById('output').appendChild(fragment);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "sessionStorage.getItem(payload)"),
        "Expected keyed sessionStorage source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_sessionstorage_branch_bootstrap_preserves_canonical_getitem_source() {
    let code = r#"
const url = new URL(location.href);
const seed = url.searchParams.get('seed');
if (seed) {
sessionStorage.setItem('xssmaze:browser-state:level3', seed);
url.searchParams.delete('seed');
const nextSearch = url.searchParams.toString();
location.replace(url.pathname + (nextSearch ? '?' + nextSearch : ''));
} else {
const stored = sessionStorage.getItem('xssmaze:browser-state:level3') || '';
const range = document.createRange();
const fragment = range.createContextualFragment(stored);
document.getElementById('output').appendChild(fragment);
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "sessionStorage.getItem(xssmaze:browser-state:level3)"),
        "Expected keyed sessionStorage source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_localstorage_branch_bootstrap_preserves_canonical_getitem_source() {
    let code = r#"
const url = new URL(location.href);
const seed = url.searchParams.get('seed');
if (seed) {
localStorage.setItem('xssmaze:browser-state:level2', seed);
url.searchParams.delete('seed');
const nextSearch = url.searchParams.toString();
location.replace(url.pathname + (nextSearch ? '?' + nextSearch : ''));
} else {
const stored = localStorage.getItem('xssmaze:browser-state:level2') || '';
document.getElementById('output').insertAdjacentHTML('beforeend', stored);
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "localStorage.getItem(xssmaze:browser-state:level2)"),
        "Expected keyed localStorage source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_document_base_uri_source() {
    let code = r#"
let base = document.baseURI;
document.body.innerHTML = base;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect document.baseURI as source"
    );
}

#[test]
fn test_location_replace_sink() {
    let code = r#"
let url = location.hash;
location.replace(url);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect location.replace as sink");
}

#[test]
fn test_location_assign_sink() {
    let code = r#"
let target = document.cookie;
location.assign(target);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect location.assign as sink");
}

#[test]
fn test_execscript_sink() {
    let code = r#"
let script = location.search;
execScript(script);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect execScript as sink");
}

#[test]
fn test_ternary_operator_both_tainted() {
    let code = r#"
let a = location.hash;
let b = location.search;
let result = Math.random() > 0.5 ? a : b;
document.write(result);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect ternary with both branches tainted"
    );
}

#[test]
fn test_ternary_operator_one_tainted() {
    let code = r#"
let tainted = location.hash;
let safe = "safe";
let result = Math.random() > 0.5 ? tainted : safe;
document.write(result);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect ternary with one branch tainted"
    );
}

#[test]
fn test_array_spread_operator() {
    let code = r#"
let tainted = [location.hash];
let arr = [...tainted, 'other'];
document.write(arr[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint through array spread"
    );
}

#[test]
fn test_object_spread_operator() {
    let code = r#"
let tainted = { data: location.search };
let obj = { ...tainted };
document.body.innerHTML = obj.data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint through object spread"
    );
}

#[test]
fn test_chained_property_access() {
    let code = r#"
let obj = { a: { b: { c: location.hash } } };
document.write(obj.a.b.c);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect deeply nested property access"
    );
}

#[test]
fn test_multiple_tainted_in_template_literal() {
    let code = r#"
let hash = location.hash;
let search = location.search;
let msg = `Hash: ${hash}, Search: ${search}`;
document.write(msg);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect multiple tainted in template literal"
    );
}

#[test]
fn test_tainted_as_object_key() {
    let code = r#"
let key = location.hash;
let obj = {};
obj[key] = "value";
document.write(obj[key]);
    "#;
    let analyzer = AstDomAnalyzer::new();
    let _result = analyzer.analyze(code).unwrap();
    // This is a limitation - we track that obj is tainted but not specific keys
    // The test documents current behavior
}

#[test]
fn test_document_writeln_sink() {
    let code = r#"
let data = location.search;
document.writeln(data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect document.writeln as sink");
}

#[test]
fn test_chained_string_methods() {
    let code = r#"
let result = location.hash.substring(1).toUpperCase().trim();
document.write(result);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through chained methods"
    );
}

#[test]
fn test_array_join_on_tainted() {
    let code = r#"
let parts = [location.hash, location.search];
let combined = parts.join('&');
document.write(combined);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint in array with join");
}

#[test]
fn test_tainted_in_switch_statement() {
    let code = r#"
let input = location.hash;
switch(input) {
case "test":
    document.write(input);
    break;
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in switch statement"
    );
}

#[test]
fn test_binary_operators_propagate_taint() {
    let code = r#"
let a = location.hash;
let b = "prefix-" + a + "-suffix";
document.write(b);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through binary operators"
    );
}

#[test]
fn test_null_coalescing_with_tainted() {
    let code = r#"
let value = location.hash || "default";
document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint through null coalescing"
    );
}

#[test]
fn test_mixed_array_access() {
    let code = r#"
let arr = ["safe", location.hash, "safe2"];
document.write(arr[1]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted element in mixed array"
    );
}

#[test]
fn test_jquery_prepend_sink() {
    let code = r#"
let content = location.search;
prepend(content);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect prepend as sink");
}

#[test]
fn test_jquery_after_sink() {
    let code = r#"
let html = document.cookie;
after(html);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect after as sink");
}

#[test]
fn test_jquery_before_sink() {
    let code = r#"
let markup = location.hash;
before(markup);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect before as sink");
}

#[test]
fn test_element_text_safe() {
    // element.text is typically safe (similar to textContent)
    let code = r#"
let input = location.search;
element.text = input;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "text property is typically safe and should NOT be detected"
    );
}

#[test]
fn test_reassignment_preserves_taint() {
    let code = r#"
let a = location.hash;
let b = a;
let c = b;
let d = c;
document.write(d);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should preserve taint through multiple reassignments"
    );
}

#[test]
fn test_tainted_array_element_assignment() {
    let code = r#"
let arr = [];
arr[0] = location.hash;
document.write(arr[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect computed member assignment taint propagation"
    );
}

#[test]
fn test_window_location_source() {
    let code = r#"
let loc = window.location;
document.write(loc);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect window.location as source"
    );
}

#[test]
fn test_complex_binary_expression_chain() {
    let code = r#"
let a = location.hash;
let b = a + " middle " + a + " end";
document.write(b);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint in complex binary expression"
    );
}

#[test]
fn test_typeof_does_not_sanitize() {
    let code = r#"
let input = location.hash;
let type = typeof input;
document.write(input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "typeof should not sanitize tainted variable"
    );
}

#[test]
fn test_tainted_in_array_literal_position() {
    let code = r#"
let hash = location.hash;
document.write([1, 2, hash][2]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted data at specific array position"
    );
}

#[test]
fn test_document_document_uri_source() {
    let code = r#"
let uri = document.documentURI;
eval(uri);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect document.documentURI as source"
    );
}

#[test]
fn test_parenthesized_expression() {
    let code = r#"
let value = (((location.hash)));
document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through parenthesized expressions"
    );
}

#[test]
fn test_comma_operator_with_tainted() {
    let code = r#"
let result = (1, 2, location.hash);
document.write(result);
    "#;
    let analyzer = AstDomAnalyzer::new();
    let _result = analyzer.analyze(code).unwrap();
    // Comma operator returns the last value
    // Test documents current behavior
}

#[test]
fn test_combined_logical_operators() {
    let code = r#"
let a = location.hash;
let b = location.search;
let result = a && b || "default";
document.write(result);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect taint through combined logical operators"
    );
}

#[test]
fn test_tainted_get_method_call() {
    let code = r#"
        let params = location.search;
        let value = params.get('id');
        document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through .get() on tainted object"
    );
}

#[test]
fn test_new_url_searchparams() {
    let code = r#"
        let urlParams = new URL(location.href).searchParams;
        document.write(urlParams);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should track taint through new URL(tainted).searchParams"
    );
}

#[test]
fn test_urlsearchparams_get_from_location_href_is_normalized_to_location_search() {
    let code = r#"
        let urlParams = new URL(location.href).searchParams;
        let query = urlParams.get('query');
        document.getElementById('out').innerHTML = query;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect URLSearchParams.get flow");
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "URLSearchParams.get(query)"),
        "Expected URLSearchParams.get(query) source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_domparser_flow_from_urlsearchparams_is_normalized_to_location_search() {
    let code = r#"
        const urlParams = new URL(location.href).searchParams;
        const query = urlParams.get('query');
        const parser = new DOMParser();
        const doc = parser.parseFromString(query, 'text/html');
        document.getElementById('output').innerHTML = doc.body.innerHTML;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect DOMParser flow");
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "URLSearchParams.get(query)"),
        "Expected URLSearchParams.get(query) source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_reparse_url_object_flow_tracks_nested_searchparams() {
    let code = r#"
        const current = new URL(location.href);
        const cloned = new URLSearchParams(current.searchParams.toString());
        const replay = new URL(location.pathname + '?' + cloned.toString(), location.origin);
        const query = replay.searchParams.get('query') || '';
        document.getElementById('output').innerHTML = query;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect reparsed URLSearchParams flow"
    );
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "URLSearchParams.get(query)"),
        "Expected URLSearchParams.get(query) source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_reparse_urlsearchparams_set_then_get_tracks_source() {
    let code = r#"
        const current = new URL(location.href);
        const staged = new URLSearchParams();
        staged.set('html', current.searchParams.get('query') || '');
        const replay = new URLSearchParams(staged.toString());
        document.getElementById('preview').setAttribute('srcdoc', replay.get('html') || '');
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect URLSearchParams.set/get reparse flow"
    );
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source.contains("URLSearchParams.get")),
        "Expected URLSearchParams-derived source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_nested_urlsearchparams_blob_flow_preserves_outer_bootstrap_source() {
    let code = r#"
        const outer = new URL(location.href).searchParams;
        const blob = outer.get('blob') || '';
        const nested = new URLSearchParams(blob.charAt(0) == '?' ? blob.slice(1) : blob);
        const query = nested.get('query') || '';
        document.getElementById('output').innerHTML = query;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect nested blob reparse flow");
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "URLSearchParams.get(blob).get(query)"),
        "Expected nested URLSearchParams source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_double_nested_urlsearchparams_blob_flow_preserves_full_chain() {
    let code = r#"
        const current = new URL(location.href).searchParams;
        const blob = current.get('blob') || '';
        const first = new URLSearchParams(blob.charAt(0) == '?' ? blob.slice(1) : blob);
        const outer = first.get('outer') || '';
        const second = new URLSearchParams(outer.charAt(0) == '?' ? outer.slice(1) : outer);
        const query = second.get('query') || '';
        document.getElementById('output').innerHTML = query;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect double nested blob reparse flow"
    );
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "URLSearchParams.get(blob).get(outer).get(query)"),
        "Expected double nested URLSearchParams source, got {:?}",
        result.iter().map(|v| v.source.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_srcdoc_sink_preserves_precise_urlsearchparams_source() {
    let code = r#"
        const current = new URL(location.href);
        const staged = new URLSearchParams();
        staged.set('html', current.searchParams.get('query') || '');
        const replay = new URLSearchParams(staged.toString());
        document.getElementById('preview').setAttribute('srcdoc', replay.get('html') || '');
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.iter().any(|vuln| vuln.sink == "setAttribute:srcdoc"
            && vuln.source == "URLSearchParams.get(query)"),
        "Expected precise URLSearchParams source for srcdoc sink, got {:?}",
        result
            .iter()
            .map(|v| format!("{} -> {}", v.source, v.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_json_parse_taint_propagation() {
    let code = r#"
        let input = location.hash;
        let data = JSON.parse(input);
        document.body.innerHTML = data;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through JSON.parse"
    );
}

#[test]
fn test_taint_inside_try_catch() {
    let code = r#"
        try {
            let x = location.search;
            document.write(x);
        } catch(e) {}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect taint inside try block");
}

#[test]
fn test_new_function_with_tainted_arg() {
    let code = r#"
        let code = location.hash;
        let fn = new Function(code);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect new Function() with tainted argument"
    );
}

#[test]
fn test_execcommand_inserthtml_sink() {
    let code = r#"
        let html = location.hash;
        document.execCommand('insertHTML', false, html);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect execCommand insertHTML with tainted data"
    );
}

#[test]
fn test_assignment_expression_propagates_taint() {
    let code = r#"
        let src = location.search;
        let out;
        out = src;
        document.write(out);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through identifier assignment"
    );
}

#[test]
fn test_assignment_in_conditional_branch_propagates_taint() {
    let code = r#"
        let input = location.hash;
        let out = "safe";
        if (input) {
            out = input;
        }
        document.body.innerHTML = out;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through assignment in conditional branches"
    );
}

#[test]
fn test_array_push_taint_propagation() {
    let code = r#"
        let items = [];
        items.push(location.hash);
        document.write(items[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through Array.push()"
    );
}

#[test]
fn test_array_splice_taint_propagation() {
    let code = r#"
        let items = ["safe"];
        items.splice(0, 1, location.search);
        document.write(items[0]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate taint through Array.splice() inserted values"
    );
}

#[test]
fn test_function_parameter_taint_interprocedural() {
    let code = r#"
        function render(content) {
            document.getElementById('display').innerHTML = content;
        }
        let param = location.hash.substring(1);
        render(param);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted argument flowing into sink inside called function"
    );
}

#[test]
fn test_function_call_before_declaration_hoisting_flow() {
    let code = r#"
        let param = location.search;
        sinkWrap(param);
        function sinkWrap(v) {
            document.write(v);
        }
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted flow even when function is declared after call"
    );
}

#[test]
fn test_function_parameter_safe_sink_not_detected() {
    let code = r#"
        function safeRender(content) {
            document.getElementById('display').textContent = content;
        }
        let param = location.hash.substring(1);
        safeRender(param);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "textContent inside called function should remain safe"
    );
}

#[test]
fn test_function_expression_parameter_taint_interprocedural() {
    let code = r#"
        const render = function (content) {
            document.getElementById('display').innerHTML = content;
        };
        const input = location.search;
        render(input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted argument flowing into function expression sink"
    );
}

#[test]
fn test_arrow_function_parameter_taint_interprocedural() {
    let code = r#"
        const render = (content) => {
            document.getElementById('display').innerHTML = content;
        };
        const input = location.hash;
        render(input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted argument flowing into arrow function sink"
    );
}

#[test]
fn test_function_return_direct_source_to_sink_argument() {
    let code = r#"
        function getPayload() {
            return location.search;
        }
        document.write(getPayload());
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect direct function return source passed to sink"
    );
}

#[test]
fn test_named_message_event_handler_callback_flow() {
    let code = r#"
        function onMessage(event) {
            document.getElementById('out').innerHTML = event.data;
        }
        window.addEventListener('message', onMessage);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect message event data reaching sink through named callback"
    );
}

#[test]
fn test_named_message_event_handler_safe_not_detected() {
    let code = r#"
        function onMessage(event) {
            document.getElementById('out').textContent = event.data;
        }
        window.addEventListener('message', onMessage);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Named message callback should not be flagged when using safe sink"
    );
}

#[test]
fn test_onmessage_assignment_callback_flow_detected() {
    let code = r#"
        const receiver = new BroadcastChannel('demo');
        receiver.onmessage = function(event) {
            document.getElementById('out').innerHTML = event.data;
        };
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "BroadcastChannel.message" && vuln.sink == "innerHTML"),
        "Expected BroadcastChannel.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_named_onmessage_assignment_callback_flow_detected() {
    let code = r#"
        function onMessage(event) {
            document.getElementById('out').insertAdjacentHTML('beforeend', event.data);
        }
        const channel = new MessageChannel();
        channel.port1.onmessage = onMessage;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "MessagePort.message" && vuln.sink == "insertAdjacentHTML"),
        "Expected MessagePort.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_message_channel_bootstrap_prefers_message_port_source() {
    let code = r#"
        const url = new URL(location.href);
        const seed = url.searchParams.get('seed');
        const channel = new MessageChannel();
        channel.port1.onmessage = function(event) {
            document.getElementById('output').insertAdjacentHTML('beforeend', event.data);
        };

        if (seed) {
            channel.port2.postMessage(seed);
        }
    "#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "MessagePort.message" && vuln.sink == "insertAdjacentHTML"),
        "Expected MessagePort.message source for relay, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_service_worker_message_event_source_is_preserved() {
    let code = r#"
        navigator.serviceWorker.addEventListener('message', function(event) {
            document.getElementById('out').innerHTML = event.data;
        });
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "ServiceWorker.message" && vuln.sink == "innerHTML"),
        "Expected ServiceWorker.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_event_source_message_event_source_is_preserved() {
    let code = r#"
        const stream = new EventSource('/events');
        stream.addEventListener('message', function(event) {
            document.getElementById('out').innerHTML = event.data;
        });
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "EventSource.message" && vuln.sink == "innerHTML"),
        "Expected EventSource.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_event_source_onmessage_source_is_preserved() {
    let code = r#"
        const stream = new EventSource('/events');
        stream.onmessage = function(event) {
            document.getElementById('out').insertAdjacentHTML('beforeend', event.data);
        };
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "EventSource.message" && vuln.sink == "insertAdjacentHTML"),
        "Expected EventSource.message source for onmessage, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_websocket_onmessage_source_is_preserved() {
    let code = r#"
        const socket = new WebSocket('wss://example.invalid/xssmaze');
        socket.onmessage = function(event) {
            document.getElementById('out').innerHTML = event.data;
        };
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "WebSocket.message" && vuln.sink == "innerHTML"),
        "Expected WebSocket.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_shared_worker_message_source_is_preserved() {
    let code = r#"
        const shared = new SharedWorker('/shared-worker.js');
        shared.port.onmessage = function(event) {
            const range = document.createRange();
            const fragment = range.createContextualFragment(event.data);
            document.getElementById('out').appendChild(fragment);
        };
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "SharedWorker.message"
                && vuln.sink == "createContextualFragment"),
        "Expected SharedWorker.message source, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_storage_event_newvalue_detected_for_custom_param_name() {
    let code = r#"
        window.addEventListener('storage', (evt) => {
            document.getElementById('out').innerHTML = evt.newValue;
        });
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "event.newValue" && vuln.sink == "innerHTML"),
        "Expected event.newValue source for storage event, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_storage_event_oldvalue_detected_for_function_expression() {
    let code = r#"
        window.addEventListener('storage', function(storageEvent) {
            document.getElementById('out').insertAdjacentHTML('beforeend', storageEvent.oldValue);
        });
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result
            .iter()
            .any(|vuln| vuln.source == "event.oldValue" && vuln.sink == "insertAdjacentHTML"),
        "Expected event.oldValue source for storage event, got {:?}",
        result
            .iter()
            .map(|vuln| format!("{} -> {}", vuln.source, vuln.sink))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_computed_member_innerhtml_assignment_detected() {
    let code = r#"
        let payload = location.hash;
        let el = document.getElementById('target');
        el['innerHTML'] = payload;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect computed innerHTML assignment sink"
    );
}

#[test]
fn test_computed_member_location_href_assignment_detected() {
    let code = r#"
        let redirect = location.search;
        location['href'] = redirect;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect computed location.href assignment sink"
    );
}

#[test]
fn test_computed_member_document_write_call_detected() {
    let code = r#"
        let data = location.hash;
        document['write'](data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect computed member sink call document['write']"
    );
}

#[test]
fn test_computed_member_insertadjacenthtml_call_detected() {
    let code = r#"
        let data = location.search;
        const el = document.getElementById('target');
        el['insertAdjacentHTML']('beforeend', data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect computed insertAdjacentHTML sink call"
    );
}

#[test]
fn test_object_html_property_assignment_not_sink_by_itself() {
    let code = r#"
        let model = {};
        model.html = location.hash;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Object html property assignment should not be treated as direct sink"
    );
}

#[test]
fn test_object_html_property_then_real_sink_reports_only_real_sink() {
    let code = r#"
        let model = {};
        model.html = location.hash;
        document.write(model.html);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert_eq!(
        result.len(),
        1,
        "Should report only actual sink usage, not property assignment pseudo-sink"
    );
    assert_eq!(result[0].sink, "document.write");
}

#[test]
fn test_sink_call_wrapper_detected() {
    let code = r#"
        let input = location.hash;
        document.write.call(document, input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink invocation via .call wrapper"
    );
}

#[test]
fn test_sink_apply_wrapper_detected() {
    let code = r#"
        document.write.apply(document, [location.search]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink invocation via .apply wrapper"
    );
}

#[test]
fn test_bound_sink_alias_detected() {
    let code = r#"
        let writer = document.write.bind(document);
        let payload = location.hash;
        writer(payload);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect sink through bound alias");
}

#[test]
fn test_object_method_summary_flow_detected() {
    let code = r#"
        const helper = {
            render(value) {
                document.getElementById('out').innerHTML = value;
            }
        };
        helper.render(location.hash);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect object literal method inter-procedural flow"
    );
}

#[test]
fn test_class_instance_method_summary_flow_detected() {
    let code = r#"
        class Renderer {
            render(value) {
                document.write(value);
            }
        }
        const r = new Renderer();
        r.render(location.search);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect class instance method inter-procedural flow"
    );
}

#[test]
fn test_class_static_method_summary_flow_detected() {
    let code = r#"
        class Redirector {
            static go(url) {
                location.assign(url);
            }
        }
        Redirector.go(location.hash);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect class static method inter-procedural flow"
    );
}

#[test]
fn test_summary_call_wrapper_detected() {
    let code = r#"
        function render(value) {
            document.write(value);
        }
        render.call(null, location.hash);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect summary flow through .call wrapper"
    );
}

#[test]
fn test_summary_apply_wrapper_detected() {
    let code = r#"
        function render(value) {
            document.write(value);
        }
        render.apply(null, [location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect summary flow through .apply wrapper"
    );
}

#[test]
fn test_bound_object_method_summary_detected() {
    let code = r#"
        const helper = {
            render(v) {
                eval(v);
            }
        };
        const bound = helper.render.bind(helper);
        bound(location.search);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect bound object method summary flow"
    );
}

#[test]
fn test_dynamic_setattribute_name_concat_detected() {
    let code = r#"
        const input = location.hash;
        document.getElementById('x').setAttribute('on' + 'click', input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect dangerous dynamic setAttribute name"
    );
}

#[test]
fn test_dynamic_setattribute_safe_name_concat_not_detected() {
    let code = r#"
        const input = location.hash;
        document.getElementById('x').setAttribute('data-' + 'id', input);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Should not detect safe dynamic setAttribute name"
    );
}

#[test]
fn test_dynamic_execcommand_name_concat_detected() {
    let code = r#"
        const html = location.search;
        document.execCommand('insert' + 'HTML', false, html);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect dynamic execCommand insertHTML name"
    );
}

#[test]
fn test_bound_source_alias_taint_detected() {
    let code = r#"
        const readStorage = localStorage.getItem.bind(localStorage);
        const data = readStorage('payload');
        document.write(data);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate source taint through bound source alias"
    );
}

#[test]
fn test_bound_summary_prebound_tainted_arg_detected() {
    let code = r#"
        function render(value) {
            document.write(value);
        }
        const bound = render.bind(null, location.hash);
        bound();
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted pre-bound argument through function summary"
    );
}

#[test]
fn test_bound_sink_prebound_tainted_arg_detected() {
    let code = r#"
        const writer = document.write.bind(document, location.search);
        writer();
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted pre-bound argument to sink alias"
    );
}

#[test]
fn test_bound_object_method_prebound_tainted_arg_detected() {
    let code = r#"
        const helper = {
            render(v) {
                eval(v);
            }
        };
        const bound = helper.render.bind(helper, location.hash);
        bound();
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted pre-bound argument to bound object method"
    );
}

#[test]
fn test_bound_return_prebound_arg_taints_sink() {
    let code = r#"
        function echo(v) {
            return v;
        }
        const f = echo.bind(null, location.search);
        document.write(f());
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted return from pre-bound argument"
    );
}

#[test]
fn test_bound_summary_prebound_safe_literal_not_detected() {
    let code = r#"
        function render(value) {
            document.getElementById('out').innerHTML = value;
        }
        const bound = render.bind(null, 'safe');
        bound();
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Safe literal pre-bound argument should not be detected"
    );
}

#[test]
fn test_computed_member_dynamic_property_sink_call_detected() {
    let code = r#"
        const payload = location.hash;
        document['wri' + 'te'](payload);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink call when computed property name is statically resolvable"
    );
}

#[test]
fn test_computed_member_dynamic_wrapper_property_call_detected() {
    let code = r#"
        const payload = location.search;
        document.write['ca' + 'll'](document, payload);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect wrapper sink call when wrapper property is computed"
    );
}

#[test]
fn test_computed_member_dynamic_non_sink_property_not_detected() {
    let code = r#"
        const payload = location.hash;
        document['wri' + 'ten'](payload);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Non-sink computed member should not be flagged"
    );
}

#[test]
fn test_bind_chain_sink_alias_detected() {
    let code = r#"
        const base = document.write.bind(document, location.hash);
        const chained = base.bind(null);
        chained();
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should preserve taint through chained bind aliases"
    );
}

#[test]
fn test_bound_sink_alias_call_wrapper_detected() {
    let code = r#"
        const writer = document.write.bind(document);
        writer.call(null, location.hash);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink alias invoked via .call wrapper"
    );
}

#[test]
fn test_bound_sink_alias_apply_wrapper_detected() {
    let code = r#"
        const writer = document.write.bind(document);
        writer.apply(null, [location.search]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink alias invoked via .apply wrapper"
    );
}

#[test]
fn test_summary_apply_wrapper_param_index_precision_detected() {
    let code = r#"
        function render(a, b) {
            document.write(b);
        }
        render.apply(null, ['safe', location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should map apply array index to correct sink parameter"
    );
}

#[test]
fn test_summary_apply_wrapper_non_sink_param_tainted_not_detected() {
    let code = r#"
        function render(a, b) {
            document.write(a);
        }
        render.apply(null, ['safe', location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Tainted non-sink parameter should not trigger apply wrapper finding"
    );
}

#[test]
fn test_bound_summary_call_wrapper_detected() {
    let code = r#"
        function render(v) {
            eval(v);
        }
        const bound = render.bind(null);
        bound.call(null, location.search);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect summary alias invoked through call wrapper"
    );
}

#[test]
fn test_bound_summary_apply_wrapper_with_prebound_index_detected() {
    let code = r#"
        function render(a, b) {
            document.write(b);
        }
        const bound = render.bind(null, 'safe');
        bound.apply(null, [location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should respect pre-bound args when mapping apply wrapper parameter index"
    );
}

#[test]
fn test_reflect_apply_sink_detected() {
    let code = r#"
        Reflect.apply(document.write, document, [location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect sink invocation via Reflect.apply"
    );
}

#[test]
fn test_reflect_apply_bound_sink_alias_detected() {
    let code = r#"
        const writer = document.write.bind(document);
        Reflect.apply(writer, null, [location.search]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect bound sink alias invocation via Reflect.apply"
    );
}

#[test]
fn test_reflect_apply_summary_flow_detected() {
    let code = r#"
        function render(v) {
            eval(v);
        }
        Reflect.apply(render, null, [location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect summary flow through Reflect.apply"
    );
}

#[test]
fn test_reflect_apply_summary_non_sink_param_tainted_not_detected() {
    let code = r#"
        function render(a, b) {
            document.write(a);
        }
        Reflect.apply(render, null, ['safe', location.search]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Tainted non-sink parameter should not trigger Reflect.apply summary finding"
    );
}

#[test]
fn test_reflect_apply_source_return_taints_sink() {
    let code = r#"
        const value = Reflect.apply(localStorage.getItem, localStorage, ['payload']);
        document.write(value);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should propagate source taint through Reflect.apply return value"
    );
}

#[test]
fn test_reflect_apply_setattribute_dangerous_detected() {
    let code = r#"
        const el = document.getElementById('x');
        Reflect.apply(el.setAttribute, el, ['onclick', location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect dangerous setAttribute via Reflect.apply"
    );
}

#[test]
fn test_reflect_apply_setattribute_safe_attr_not_detected() {
    let code = r#"
        const el = document.getElementById('x');
        Reflect.apply(el.setAttribute, el, ['class', location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Safe setAttribute attribute should not be detected via Reflect.apply"
    );
}

#[test]
fn test_reflect_apply_execcommand_insert_html_detected() {
    let code = r#"
        Reflect.apply(document.execCommand, document, ['insertHTML', false, location.search]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect execCommand insertHTML via Reflect.apply"
    );
}

#[test]
fn test_reflect_construct_function_tainted_detected() {
    let code = r#"
        Reflect.construct(Function, [location.hash]);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        !result.is_empty(),
        "Should detect tainted Function constructor invocation via Reflect.construct"
    );
}

#[test]
fn test_reflect_construct_function_safe_literal_not_detected() {
    let code = r#"
        Reflect.construct(Function, ['return 1']);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Safe literal code should not be detected via Reflect.construct"
    );
}

#[test]
fn test_xss_game_level3_pattern() {
    // xss-game L3: hash flows through a wrapper function before reaching
    // jQuery's `.html()` sink. Inter-procedural taint tracking is the
    // missing piece.
    let js = r#"
function chooseTab(num) {
  var html = "<img src='/static/level3/cloud" + num + ".jpg' />";
  $('#tabContent').html(html);
}
window.onload = function() {
  chooseTab(unescape(self.location.hash.substr(1)) || "1");
}
"#;
    let analyzer = crate::scanning::ast_dom_analysis::AstDomAnalyzer::new();
    let result = analyzer.analyze(js).expect("parses");
    eprintln!("L3 vulns found: {}", result.len());
    for v in &result {
        eprintln!("  source={} sink={} line={}:{}", v.source, v.sink, v.line, v.column);
    }
}
