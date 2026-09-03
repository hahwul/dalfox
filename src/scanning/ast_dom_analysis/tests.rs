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
fn set_attribute_ns_dangerous_attribute_is_a_sink() {
    // setAttributeNS(ns, name, value): the attribute name is at index 1 and the
    // value at index 2, one further along than setAttribute.
    let code = r#"
var q = new URLSearchParams(location.search).get('query');
document.getElementById('go').setAttributeNS(null, 'onclick', q);
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "setAttributeNS:onclick"),
        "setAttributeNS onclick must fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn set_attribute_ns_xlink_href_is_a_sink() {
    let code = r#"
var q = location.search;
el.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', q);
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.iter().any(|v| v.sink.starts_with("setAttributeNS:")),
        "setAttributeNS xlink:href must fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn set_attribute_ns_inert_attribute_no_finding() {
    // Same dangerous-attribute filter as setAttribute: `class` cannot execute.
    let code = r#"
var q = location.search;
document.getElementById('go').setAttributeNS(null, 'class', q);
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.is_empty(),
        "setAttributeNS of an inert attribute must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn indirect_eval_comma_sequence_is_a_sink() {
    // `(0, eval)(x)` detaches the eval reference so the code runs in global
    // scope; the callee is a parenthesized SequenceExpression, which the plain
    // callee-name lookup cannot resolve.
    let code = r#"
var q = new URLSearchParams(location.search).get('query');
if (q) { (0, eval)(q); }
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "eval"),
        "indirect eval must fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn indirect_call_to_non_sink_no_finding() {
    // The sequence-unwrap must only resolve names that are already sinks — it
    // must not turn an arbitrary comma-expression call into a finding.
    let code = r#"
var q = location.search;
(0, renderPlainText)(q);
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.is_empty(),
        "indirect call to a non-sink must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn dom_parser_parse_from_string_html_is_a_sink() {
    let code = r#"
var q = new URLSearchParams(location.search).get('query');
var parsed = new DOMParser().parseFromString(q, 'text/html');
out.appendChild(document.adoptNode(parsed.body.firstChild));
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "parseFromString"),
        "parseFromString with text/html must fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn dom_parser_parse_from_string_xml_no_finding() {
    // A text/xml parse cannot produce script-bearing nodes, so it is not an
    // XSS sink even with tainted input.
    let code = r#"
var q = location.search;
var doc = new DOMParser().parseFromString(q, 'text/xml');
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.is_empty(),
        "parseFromString with text/xml must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn dom_parser_parse_from_string_untainted_no_finding() {
    let code = r#"
var doc = new DOMParser().parseFromString('<p>static</p>', 'text/html');
"#;
    let r = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        r.is_empty(),
        "untainted parseFromString must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
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
fn test_settimeout_callback_body_flow_detected() {
    // The source→sink flow lives *inside* a `setTimeout(function(){ … })`
    // deferred callback — the xssmaze `waf-facade/level8` shape (a fake
    // "Checking your browser" challenge whose verify step writes the query
    // into innerHTML). The callback never runs at parse time, so its body must
    // be walked explicitly; without callback descent this slipped through.
    let code = r#"
setTimeout(function () {
  var q = new URLSearchParams(location.search).get('query') || '';
  document.getElementById('out').innerHTML = 'Resource: ' + q;
}, 600);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.iter().any(|v| v.sink.contains("innerHTML")),
        "Should detect URLSearchParams→innerHTML flow inside a setTimeout callback; got {:?}",
        result
            .iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_settimeout_arrow_callback_body_flow_detected() {
    // Same deferred-callback flow, arrow-function form.
    let code = r#"
setTimeout(() => {
  document.getElementById('out').innerHTML = location.hash;
}, 0);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.iter().any(|v| v.sink.contains("innerHTML")),
        "Should detect location.hash→innerHTML flow inside a setTimeout arrow callback"
    );
}

#[test]
fn test_callback_body_local_taint_does_not_leak() {
    // A callback-local tainted var must not leak into the enclosing scope and
    // mark an unrelated outer write as vulnerable. Only the in-callback sink
    // (if any) should fire — here the callback is inert, so nothing should.
    let code = r#"
setTimeout(function () { var q = location.search; var safe = 'static'; }, 0);
document.getElementById('out').innerHTML = q;
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(
        result.is_empty(),
        "Callback-local taint must not leak to the outer scope; got {:?}",
        result
            .iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
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
fn test_new_function_source_label_propagated() {
    // `new Function(URLSearchParams.get('q'))` previously fell back to
    // "unknown source" because the NewExpression sink path never asked
    // for the originating source — exposing it on the finding gives
    // users actionable provenance (the same way CallExpression sinks do).
    let code = r#"
        let q = new URLSearchParams(location.search).get('q');
        new Function(q);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(code).unwrap();
    assert!(!result.is_empty(), "Should detect tainted new Function()");
    let v = &result[0];
    assert_eq!(v.sink, "Function");
    assert_ne!(
        v.source, "unknown source",
        "source must propagate from URLSearchParams.get, not fall back to 'unknown source'"
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
fn test_self_location_hash_recognised_as_source() {
    // Regression for the xss-game L3 hash source: `self === window` so
    // `self.location.hash` taints just like `location.hash`. Without
    // `self.location` in DOM_SOURCES the analyzer recurses past the
    // alias and gives up at the bare `self` identifier.
    let js = r#"
function chooseTab(num) {
  $('#tabContent').html(num);
}
chooseTab(self.location.hash);
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).expect("parses");
    assert_eq!(
        result.len(),
        1,
        "self.location.hash must taint chooseTab arg"
    );
    assert!(result[0].source.contains("location"));
    assert_eq!(result[0].sink, "html");
}

#[test]
fn test_function_expression_body_in_window_onload_assignment_is_walked() {
    // Regression for the xss-game L3 outer wrapper: the call that
    // feeds the tainted source into `chooseTab` lives inside an
    // anonymous function expression assigned to `window.onload`. The
    // analyzer used to stop at the assignment RHS — only function
    // *declarations* had their bodies walked at module scope — so the
    // sink summary never fired.
    let js = r#"
function chooseTab(num) {
  $('#tabContent').html(num);
}
window.onload = function() {
  chooseTab(self.location.hash);
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).expect("parses");
    assert_eq!(
        result.len(),
        1,
        "function-expression body inside window.onload assignment must be walked"
    );
}

#[test]
fn test_arrow_function_expression_body_in_assignment_is_walked() {
    // Same fix covers arrow-function expressions in assignments.
    let js = r#"
function chooseTab(num) {
  $('#tabContent').html(num);
}
window.onload = () => {
  chooseTab(location.hash);
};
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).expect("parses");
    assert_eq!(result.len(), 1);
}

#[test]
fn test_xss_game_level3_full_pattern() {
    // Full xss-game L3 shape — kept verbatim from the live page so
    // future analyzer refactors don't silently lose it. The hash
    // flows through `unescape`, then through `chooseTab`'s parameter,
    // then concatenated into an HTML string, then handed to jQuery
    // `.html()`. Every link in the chain must be tracked.
    let js = r#"
function chooseTab(num) {
  var html = "Image " + parseInt(num) + "<br>";
  html += "<img src='/static/level3/cloud" + num + ".jpg' />";
  $('#tabContent').html(html);
}
window.onload = function() {
  chooseTab(unescape(self.location.hash.substr(1)) || "1");
}
"#;
    let analyzer = AstDomAnalyzer::new();
    let result = analyzer.analyze(js).expect("parses");
    assert!(
        !result.is_empty(),
        "xss-game L3 full pattern must produce at least one DOM XSS finding"
    );
    let v = &result[0];
    assert!(
        v.source.contains("location"),
        "source should mention location (got {})",
        v.source
    );
    assert_eq!(v.sink, "html");
}

// Coverage matrix for the modern SPA shapes that real-world apps lean
// on. Pin them as regression tests so a future analyzer refactor
// doesn't silently drop coverage.

#[test]
fn detects_postmessage_function_handler_to_innerhtml() {
    let js = r#"
window.addEventListener("message", function(e) {
  document.getElementById("out").innerHTML = e.data;
});
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("data") && v.sink == "innerHTML"),
        "postMessage function handler must surface event.data → innerHTML"
    );
}

#[test]
fn detects_postmessage_arrow_handler_to_innerhtml() {
    let js = r#"
window.addEventListener("message", (e) => {
  document.body.innerHTML = e.data;
});
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("data") && v.sink == "innerHTML")
    );
}

#[test]
fn detects_template_literal_substitution_into_innerhtml() {
    let js = r#"
const name = location.hash.substr(1);
document.body.innerHTML = `<h1>Hello ${name}</h1>`;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("location.hash") && v.sink == "innerHTML"),
        "template-literal substitution must propagate the hash taint into innerHTML"
    );
}

#[test]
fn detects_direct_script_src_assignment_from_hash() {
    let js = r#"
const s = document.createElement('script');
s.src = location.hash.substr(1);
document.head.appendChild(s);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("location.hash") && v.sink == "src")
    );
}

#[test]
fn detects_json_parse_property_access_into_innerhtml() {
    let js = r#"
const cfg = JSON.parse(location.hash.substr(1));
document.body.innerHTML = cfg.title;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("location.hash") && v.sink == "innerHTML"),
        "JSON.parse(tainted) → property access → innerHTML must surface"
    );
}

#[test]
fn detects_set_html_unsafe_method_call() {
    let js = r#"
const el = document.getElementById('out');
el.setHTMLUnsafe(location.hash.slice(1));
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("location.hash") && v.sink == "setHTMLUnsafe"),
        "setHTMLUnsafe is an explicit-unsafe HTML parsing sink: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_script_text_assignment_from_hash() {
    let js = r#"
const s = document.createElement('script');
s.text = location.hash.slice(1);
document.body.appendChild(s);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.source.contains("location.hash") && v.sink == "script.text"),
        "script.text assignment runs the value as JS once appended: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_script_text_content_assignment_from_search() {
    let js = r#"
const s = document.createElement('script');
const q = new URLSearchParams(location.search).get('q');
s.textContent = q;
document.body.appendChild(s);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "script.textContent"),
        "script.textContent assignment from URLSearchParams.get must surface: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_script_inner_html_assignment_without_duplicate_finding() {
    // `s.innerHTML = tainted` where `s` is a script element must be
    // reported as `script.innerHTML` (the form the PoC generator emits
    // raw JS for). The generic `innerHTML` sink path must NOT fire in
    // addition — otherwise the same line surfaces twice.
    let js = r#"
const s = document.createElement('script');
s.innerHTML = location.hash.slice(1);
document.body.appendChild(s);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    let script_findings: Vec<_> = r.iter().filter(|v| v.sink == "script.innerHTML").collect();
    let generic_findings: Vec<_> = r.iter().filter(|v| v.sink == "innerHTML").collect();
    assert_eq!(
        script_findings.len(),
        1,
        "expected exactly one script.innerHTML finding; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
    assert!(
        generic_findings.is_empty(),
        "script-element sink must suppress the generic innerHTML report; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn script_text_sink_does_not_fire_on_div_element() {
    let js = r#"
const d = document.createElement('div');
d.text = location.hash.slice(1);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        !r.iter().any(|v| v.sink.starts_with("script.")),
        ".text on a non-script element is not a sink; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn detects_get_element_by_id_script_element_inline_inner_text() {
    // Matches xssmaze dom-level9: an empty <script id="scriptTag"></script>
    // placeholder, then an inline `getElementById('scriptTag').innerText = tainted`
    // populates it. The HTML pre-scan tells the analyzer that `scriptTag`
    // is a script-element id, so the inline call resolves to a script
    // element and the assignment must be reported as a JS-eval sink.
    let js = r#"
const urlParams = new URL(location.href).searchParams;
const query = urlParams.get('query');
document.getElementById('scriptTag').innerText = query;
"#;
    let analyzer = AstDomAnalyzer::new()
        .with_script_element_ids(std::iter::once("scriptTag".to_string()).collect());
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "script.innerText"),
        "inline getElementById('script-id').innerText must be a JS-eval sink; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn get_element_by_id_script_sink_requires_html_context() {
    // Without an HTML pre-scan, `getElementById('whatever')` could be any
    // element — we must not surface `.innerText` assignments as a JS-eval
    // sink in that case.
    let js = r#"
const urlParams = new URL(location.href).searchParams;
const query = urlParams.get('query');
document.getElementById('whatever').innerText = query;
"#;
    let analyzer = AstDomAnalyzer::new(); // no script_element_ids supplied
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        !r.iter().any(|v| v.sink.starts_with("script.")),
        "getElementById without HTML context must not be claimed as script element; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn get_element_by_id_non_script_id_is_not_script_element() {
    // The HTML pre-scan only seeds ids whose tag is `<script>`. A page
    // with `<div id="output">` and `<script id="scriptTag">` must yield
    // only `scriptTag` — assignments on `output.innerText` stay benign.
    let js = r#"
const urlParams = new URL(location.href).searchParams;
const query = urlParams.get('query');
document.getElementById('output').innerText = query;
"#;
    let analyzer = AstDomAnalyzer::new()
        .with_script_element_ids(std::iter::once("scriptTag".to_string()).collect());
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        !r.iter().any(|v| v.sink.starts_with("script.")),
        ".innerText on a non-script element id must not surface; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn detects_query_selector_script_inner_text_pure_ast() {
    // `document.querySelector('script')` returns the first script element
    // without needing HTML context — the selector itself declares the tag.
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.querySelector('script').textContent = q;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "script.textContent"),
        "querySelector('script') resolves to a script element; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_document_scripts_index_inner_text_pure_ast() {
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.scripts[0].innerText = q;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "script.innerText"),
        "document.scripts[N] is a script element; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_get_elements_by_tag_name_script_index_text() {
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.getElementsByTagName('script')[0].text = q;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "script.text"),
        "getElementsByTagName('script')[N] is a script element; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn query_selector_combinator_selector_does_not_resolve_to_script() {
    // `'div script'` ends in `script` but is a descendant combinator —
    // play it safe and don't claim resolution without real CSS parsing.
    // What we actually want to assert is the *negative* direction: the
    // text-property assignment must not be reported as a script.* sink.
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.querySelector('div script').textContent = q;
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        !r.iter().any(|v| v.sink.starts_with("script.")),
        "descendant combinator must not resolve statically; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn clipboard_get_data_is_recognised_as_source() {
    let js = r#"
document.addEventListener('paste', function(e) {
    document.body.innerHTML = e.clipboardData.getData('text');
});
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("clipboardData")),
        "paste-event clipboardData.getData → innerHTML must surface; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn drag_drop_get_data_is_recognised_as_source() {
    // Drop handler innerHTMLs the dragged `text/html` flavour — the classic
    // drag-and-drop XSS. Same trust model as clipboardData.getData above.
    let js = r#"
z.addEventListener('drop', function (e) {
    e.preventDefault();
    document.getElementById('out').innerHTML = prefix + e.dataTransfer.getData('text/html');
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("dataTransfer")),
        "drop-event dataTransfer.getData → innerHTML must surface; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn drag_drop_file_metadata_is_not_a_source() {
    // `.files` / `.types` are metadata, not attacker-supplied string content,
    // so only the `getData(...)` read is modeled as a source.
    let js = r#"
z.addEventListener('drop', function (e) {
    document.getElementById('out').innerHTML = e.dataTransfer.files.length + e.dataTransfer.types[0];
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "dataTransfer metadata reads must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn drag_drop_get_data_into_textcontent_no_finding() {
    // textContent is not an HTML sink, so the dragged payload is inert there.
    let js = r#"
z.addEventListener('drop', function (e) {
    document.getElementById('out').textContent = e.dataTransfer.getData('text/html');
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "dataTransfer.getData into textContent must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn native_element_append_is_not_a_sink() {
    // `Element.prototype.append(string)` inserts the string as a Text node
    // — no HTML parsing — so a tainted argument is not exploitable. The
    // analyzer must not flag this shape.
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.getElementById('out').append(q);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "native el.append(tainted) is not an XSS sink; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn native_element_prepend_after_before_are_not_sinks() {
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
document.getElementById('a').prepend(q);
document.getElementById('b').after(q);
document.getElementById('c').before(q);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "native el.prepend/.after/.before(tainted) are not XSS sinks; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_append_remains_a_sink() {
    // jQuery's `.append(html)` invokes innerHTML semantics — a tainted
    // string argument is exploitable, so the analyzer must still flag it.
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
$('#out').append(q);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "append"),
        "jQuery $(...).append(tainted) must surface; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_chained_append_remains_a_sink() {
    // `$('#x').find('.y').append(tainted)` — the chain must still be
    // recognised as a jQuery receiver even through an intermediate
    // method call.
    let js = r#"
const q = new URLSearchParams(location.search).get('q');
$('#root').find('.target').append(q);
"#;
    let analyzer = AstDomAnalyzer::new();
    let r = analyzer.analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "append"),
        "jQuery chained .find().append(tainted) must surface; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

// ===== Issue #1021: jQuery $() / jQuery() selector-to-HTML constructor =====

#[test]
fn jquery_constructor_hash_to_html_is_sink() {
    // xssmaze /jquery/level1/ — $(location.hash) builds DOM nodes.
    let js = r#"
var target = decodeURIComponent(location.hash.slice(1));
if (target) { $(target).appendTo('#content'); }
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "jQuery$" && v.source.contains("location.hash")),
        "jQuery $() constructor on tainted hash must be a sink; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_jquery_alias_is_sink() {
    let js = r#"
var t = location.search;
jQuery(t);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "jQuery$"),
        "jQuery() alias constructor must be a sink; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_name_source_is_sink() {
    let js = r#"$(window.name);"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "jQuery$"),
        "jQuery $() on window.name must be a sink; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_id_selector_prefix_suppressed() {
    // `$('#' + tainted)` is pinned into selector mode by the leading '#',
    // so the tainted tail can never open an HTML tag — no finding.
    let js = r#"
var t = location.hash.slice(1);
$('#' + t);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "jQuery$"),
        "selector-prefixed $('#'+t) must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_class_selector_prefix_suppressed() {
    let js = r#"
var t = location.search;
$('.item-' + t);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "jQuery$"),
        "selector-prefixed $('.x'+t) must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_html_prefix_still_sink() {
    // A leading '<' means HTML-build mode even with a constant prefix.
    let js = r#"
var t = location.hash.slice(1);
$('<div>' + t);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "jQuery$"),
        "$('<div>'+t) opens an HTML tag and must fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_untainted_selector_no_finding() {
    let js = r#"$('#content').hide(); $('.menu').show();"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "constant jQuery selectors must not produce findings; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

// ===== Issue #1022: dynamic import() code-execution sink =====

#[test]
fn dynamic_import_hash_is_sink() {
    let js = r#"
var t = decodeURIComponent(location.hash.slice(1));
if (t) { import(t); }
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "import" && v.source.contains("location.hash")),
        "dynamic import(tainted hash) must be a sink; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn dynamic_import_searchparams_is_sink() {
    // xssmaze /codeexec/level1/.
    let js = r#"
var name = new URLSearchParams(location.search).get('query') || '';
if (name) {
  import(name).then(function () {}).catch(function () {});
}
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "import"),
        "dynamic import() of URLSearchParams value must be a sink; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn dynamic_import_constant_specifier_no_finding() {
    let js = r#"import('./plugins/chart.js').then(function (m) { m.init(); });"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "import"),
        "import() of a constant module path must NOT fire; got {:?}",
        r.iter().map(|v| v.sink.clone()).collect::<Vec<_>>()
    );
}

// ===== Issue #1024: fetch()/XMLHttpRequest response source =====

#[test]
fn fetch_text_response_to_innerhtml() {
    // xssmaze /apidom/level1/.
    let js = r#"
fetch('/data.txt').then(function (r) { return r.text(); })
  .then(function (t) { document.getElementById('o').innerHTML = t; });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("Response")),
        "fetch().then(r=>r.text()).then(t=>innerHTML=t) must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_json_field_to_innerhtml() {
    // xssmaze /apidom/level2/.
    let js = r#"
fetch('/api').then(function (r) { return r.json(); })
  .then(function (d) { document.getElementById('card').innerHTML = d.html; });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "innerHTML"),
        "fetch().then(r=>r.json()).then(d=>innerHTML=d.html) must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_arrow_chain_to_document_write() {
    // xssmaze /apidom/level5/ with arrow callbacks.
    let js = r#"
fetch('/api').then(r => r.text()).then(t => document.write(t));
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "document.write"),
        "fetch arrow chain into document.write must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_json_to_insert_adjacent_html() {
    // xssmaze /apidom/level4/.
    let js = r#"
fetch('/api').then(function (r) { return r.json(); })
  .then(function (d) {
    document.getElementById('feed').insertAdjacentHTML('beforeend', '<li>' + d.msg + '</li>');
  });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "insertAdjacentHTML"),
        "fetch json -> insertAdjacentHTML must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_text_to_contextual_fragment() {
    // xssmaze /apidom/level6/.
    let js = r#"
fetch('/api').then(function (r) { return r.text(); })
  .then(function (t) {
    var frag = document.createRange().createContextualFragment(t);
    document.getElementById('out').appendChild(frag);
  });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "createContextualFragment"),
        "fetch text -> createContextualFragment must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn xhr_response_text_to_innerhtml() {
    // xssmaze /apidom/level3/.
    let js = r#"
var xhr = new XMLHttpRequest();
xhr.open('GET', '/data.txt');
xhr.onload = function () { document.getElementById('o').innerHTML = xhr.responseText; };
xhr.send();
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("XMLHttpRequest")),
        "xhr.responseText -> innerHTML must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn xhr_response_to_document_write() {
    let js = r#"
var xhr = new XMLHttpRequest();
xhr.onload = function () { document.write(xhr.response); };
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "document.write" && v.source.contains("XMLHttpRequest")),
        "xhr.response -> document.write must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn file_reader_result_to_innerhtml() {
    // "Preview the dropped file" widget: the user-supplied file bytes land in
    // innerHTML via `reader.result`.
    let js = r#"
var f = e.dataTransfer.files[0];
var r = new FileReader();
r.onload = function () { document.getElementById('out').innerHTML = prefix + r.result; };
r.readAsText(f);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("FileReader.result")),
        "FileReader.result -> innerHTML must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn file_reader_status_metadata_is_not_a_source() {
    // `readyState` / `error` are status metadata, not file content.
    let js = r#"
var r = new FileReader();
r.onload = function () { document.getElementById('out').innerHTML = r.readyState + r.error; };
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "FileReader status metadata must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn non_file_reader_result_property_is_not_a_source() {
    // `.result` is only a source on a real FileReader instance — an unrelated
    // class with a `result` field must not taint.
    let js = r#"
var r = new ReportBuilder();
document.getElementById('out').innerHTML = r.result;
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "unrelated .result read must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_text_to_safe_textcontent_no_finding() {
    // textContent is not an HTML sink, so even tainted response text is safe.
    let js = r#"
fetch('/data.txt').then(function (r) { return r.text(); })
  .then(function (t) { document.getElementById('o').textContent = t; });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "fetch response into textContent must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn clipboard_read_text_promise_chain_to_innerhtml() {
    // `navigator.clipboard.readText()` resolves directly to the untrusted
    // string, so the `.then` parameter is tainted at the chain root — the
    // async counterpart of the clipboardData.getData source.
    let js = r#"
document.getElementById('b').addEventListener('click', function () {
    navigator.clipboard.readText().then(function (t) {
        document.getElementById('out').innerHTML = prefix + t;
    });
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("clipboard.readText")),
        "clipboard.readText().then(t => innerHTML = t) must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn clipboard_read_text_arrow_chain_to_document_write() {
    let js = r#"
navigator.clipboard.readText().then(t => document.write(t));
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink.contains("write")),
        "clipboard.readText arrow chain into document.write must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn clipboard_read_text_to_safe_textcontent_no_finding() {
    let js = r#"
navigator.clipboard.readText().then(function (t) {
    document.getElementById('o').textContent = t;
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "clipboard text into textContent must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn clipboard_write_text_is_not_a_promise_source() {
    // Only the *read* side is a source. `writeText` takes a value and resolves
    // to undefined, so a chain rooted at it must stay untainted.
    let js = r#"
navigator.clipboard.writeText('x').then(function (t) {
    document.getElementById('o').innerHTML = t;
});
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.is_empty(),
        "clipboard.writeText chain must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn non_fetch_promise_chain_no_false_positive() {
    // A non-fetch promise resolving an arbitrary value must not be treated
    // as a tainted response source.
    let js = r#"
somePromise.then(function (r) { return r.text(); })
  .then(function (t) { document.getElementById('o').innerHTML = t; });
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "non-fetch promise chain must NOT fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_await_form_response_to_innerhtml() {
    // async/await fetch: `const r = await fetch(); const t = await r.text();`
    let js = r#"
async function load() {
  const r = await fetch('/api');
  const t = await r.text();
  document.getElementById('o').innerHTML = t;
}
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("Response")),
        "awaited fetch response -> innerHTML must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_await_json_form_response_to_innerhtml() {
    let js = r#"
async function load() {
  const res = await fetch('/api');
  const data = await res.json();
  document.querySelector('#x').innerHTML = data.body;
}
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter().any(|v| v.sink == "innerHTML"),
        "awaited fetch json -> innerHTML must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn jquery_constructor_walks_nested_sink_in_argument() {
    // A nested sink inside the (tainted) `$()` argument must also be visited.
    // `$(eval(location.hash))` is both a jQuery$ finding and an eval finding.
    let js = r#"$(eval(location.hash));"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    let sinks: Vec<String> = r.iter().map(|v| v.sink.clone()).collect();
    assert!(
        sinks.iter().any(|s| s == "eval"),
        "nested eval sink inside $() argument must be visited; got {:?}",
        sinks
    );
    assert!(
        sinks.iter().any(|s| s == "jQuery$"),
        "jQuery$ constructor on the tainted argument must also fire; got {:?}",
        sinks
    );
}

#[test]
fn fetch_named_then_callback_reaches_sink() {
    // Named .then() callback: the fetch-chain driver consumes the call, so
    // the sink inside `render` must be reported via the callback's summary.
    let js = r#"
function render(t) { document.getElementById('o').innerHTML = t; }
fetch('/api').then(function (r) { return r.text(); }).then(render);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("Response")),
        "named .then(render) sink must surface; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn awaited_fetch_var_does_not_leak_out_of_function_summary() {
    // A summarized function with `const r = await fetch(...)` must not leave
    // its response-var binding in the outer analysis, or an unrelated outer
    // `rsp.text()` would be wrongly treated as a tainted source.
    let js = r#"
async function loader() { var rsp = await fetch('/api'); return rsp; }
document.getElementById('o').innerHTML = rsp.text();
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        r.is_empty(),
        "response-var binding must not leak out of the function summary; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Stack-overflow hardening. The analyzed JavaScript comes from the scanned
// (attacker-controlled) page, and oxc's recursive-descent parser has no depth
// guard, so deeply nested hostile input must not crash the scanner via an
// uncatchable stack-overflow SIGABRT. Three layers defend it: the shared
// visitor recursion counter (MAX_AST_VISIT_DEPTH), the pre-parse nesting scan
// (source_nesting_exceeds_limit), and a large parse stack + length cap
// (MAX_ANALYZE_SOURCE_BYTES). Each `analyze()` here would abort the whole test
// process if its vector regressed.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn source_nesting_guard_flags_pathological_input_only() {
    // Real code, comfortably under the cap: not flagged.
    assert!(!source_nesting_exceeds_limit("a.b.c.d(e, f).g[h] + !ok"));
    assert!(!source_nesting_exceeds_limit(&format!(
        "var x = {}1{};",
        "(".repeat(MAX_SOURCE_NESTING_DEPTH),
        ")".repeat(MAX_SOURCE_NESTING_DEPTH)
    )));
    // Many *non-nested* unary/keyword ops must not trip the run counter.
    assert!(!source_nesting_exceeds_limit(
        &"!a; !b; typeof c; ".repeat(MAX_SOURCE_NESTING_DEPTH + 5)
    ));
    // Over the cap on each independent 1-byte / keyword vector: flagged.
    let over = MAX_SOURCE_NESTING_DEPTH + 5;
    assert!(source_nesting_exceeds_limit(&format!(
        "{}1{}",
        "(".repeat(over),
        ")".repeat(over)
    )));
    assert!(source_nesting_exceeds_limit(&format!(
        "{}1{}",
        "{a:".repeat(over),
        "}".repeat(over)
    )));
    assert!(source_nesting_exceeds_limit(&format!(
        "{}a",
        "[".repeat(over)
    )));
    assert!(source_nesting_exceeds_limit(&format!(
        "{}a",
        "!".repeat(over)
    )));
    assert!(source_nesting_exceeds_limit(&format!(
        "{}a",
        "typeof ".repeat(over)
    )));
}

#[test]
fn analyze_survives_deep_recursion_vectors() {
    // Every shape that previously stack-overflowed the parser or the visitor.
    // `analyze()` must return (Ok/Err), never abort the process.
    let n = MAX_AST_VISIT_DEPTH as usize * 16;
    let vectors = [
        // visitor recursion (parser handles these iteratively)
        format!("var x = location.hash{}; el.innerHTML = x;", ".a".repeat(n)),
        // flat call chain — the shape that defeated the earlier per-call guard
        format!(
            "var x = location.hash{}; el.innerHTML = x;",
            ".a()".repeat(n)
        ),
        format!(
            "var x = location.hash{}; el.innerHTML = x;",
            ".a(b)".repeat(n)
        ),
        format!("var x = location.hash{}; el.write(x);", "['a']".repeat(n)),
        // parser-recursion vectors that pass the bracket/unary pre-scan
        {
            let mut s = String::new();
            for _ in 0..n {
                s.push_str("if(a)");
            }
            s.push_str("el.write(location.hash);");
            s
        },
        {
            let mut s = String::from("var x; x");
            for _ in 0..n {
                s.push_str("=y");
            }
            s.push(';');
            s
        },
        // promise-chain driver: fetch().then(f).then(f)… recurses outside the
        // expression/statement walkers (promise_kind_of_call/_expr).
        {
            let mut s = String::from("fetch('/u')");
            for _ in 0..n {
                s.push_str(".then(f)");
            }
            s.push_str("; x;");
            s
        },
        // computed-member key built from a `+` chain — recurses through
        // eval_static_string_expr, also outside the main walkers.
        format!("var k = x[{}\"a\"]; el.write(k);", "\"a\"+".repeat(n)),
        // jQuery selector with a `+` prefix — recurses through static_leading_string.
        format!("$(({}\"a\")+location.hash);", "\"a\"+".repeat(n)),
        // onmessage assignment on a long `.`-chain receiver — recurses through
        // message_event_source_for_receiver.
        format!(
            "a{}.onmessage = function(e) {{ x = e.data; }};",
            ".a".repeat(n)
        ),
    ];
    for src in &vectors {
        let _ = AstDomAnalyzer::new().analyze(src);
    }
}

#[test]
fn analyze_skips_oversize_and_dense_input() {
    // Past the length cap -> skipped (best-effort), returns empty, no crash.
    let huge = format!(
        "var x = 1;{}",
        " /*pad*/".repeat(MAX_ANALYZE_SOURCE_BYTES / 7)
    );
    assert!(huge.len() > MAX_ANALYZE_SOURCE_BYTES);
    assert_eq!(AstDomAnalyzer::new().analyze(&huge).unwrap().len(), 0);
    // Dense bracket nesting -> rejected pre-parse, returns empty.
    let depth = MAX_SOURCE_NESTING_DEPTH * 50;
    let nested = format!("var x = {}1{};", "{a:".repeat(depth), "}".repeat(depth));
    assert_eq!(AstDomAnalyzer::new().analyze(&nested).unwrap().len(), 0);
}

#[test]
fn analyze_still_detects_moderately_nested_dom_xss() {
    // Realistic nesting (well under every cap) must still be fully analyzed:
    // the guards only engage far past anything legitimate.
    let code = r#"
let p = (((location.hash)));
let v = "" + (p ? p.slice(1) : "fallback");
document.getElementById('o').innerHTML = v;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink.contains("innerHTML")),
        "moderately nested source→sink flow must still be detected; got {:?}",
        vulns
            .iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn recursion_guard_caps_then_restores_depth() {
    // Directly exercises the shared-counter guard, independent of the parse
    // stack (the `analyze()` path masks it: any input deep enough to overflow is
    // also large enough to run on the big-stack thread). This is the test that
    // proves the counter actually bounds recursion and is reset on unwind.
    let visitor = DomXssVisitor::new("");

    // Entries up to the cap are admitted; the (cap+1)-th must be refused so a
    // chain of mutually-recursive analysis fns can't grow the stack unbounded.
    let mut guards = Vec::new();
    for i in 0..MAX_AST_VISIT_DEPTH {
        let g = visitor.enter_recursion();
        assert!(g.is_some(), "entry #{i} (below the cap) must be admitted");
        guards.push(g);
    }
    assert!(
        visitor.enter_recursion().is_none(),
        "entry at MAX_AST_VISIT_DEPTH must be refused"
    );

    // Dropping the guards (unwinding the recursion) must restore budget — else a
    // wide-but-shallow program would be falsely capped after its first deep path.
    guards.clear();
    assert!(
        visitor.enter_recursion().is_some(),
        "dropping the RAII guards must decrement the shared counter"
    );
}

// =========================================================================
// Trusted Types awareness (issue #1097)
// =========================================================================

/// Helper: count DOM-XSS findings for `code`, with optional enforcement.
fn tt_findings(code: &str, enforced: bool) -> Vec<DomXssVulnerability> {
    AstDomAnalyzer::new()
        .with_trusted_types_enforced(enforced)
        .analyze(code)
        .expect("analyze ok")
}

#[test]
fn test_tt_strict_explicit_wrapper_clears_taint() {
    // Routing the tainted value through a strict policy.createHTML — which
    // returns a recognised sanitizer's output — is genuinely safe, so no
    // finding. (Not gated on enforcement: the value is sanitized regardless.)
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: s => DOMPurify.sanitize(s) });
document.body.innerHTML = policy.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "strict createHTML wrapper must clear taint"
    );
}

#[test]
fn test_tt_permissive_explicit_wrapper_keeps_finding() {
    // A permissive `createHTML: x => x` is a no-op; the value reaching innerHTML
    // is still attacker-controlled, so the finding must be kept (flagged).
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: x => x });
document.body.innerHTML = policy.createHTML(location.hash);
"#;
    let f = tt_findings(code, false);
    assert!(
        f.iter().any(|v| v.sink.contains("innerHTML")),
        "permissive createHTML wrapper must NOT suppress the finding"
    );
}

#[test]
fn test_tt_permissive_explicit_wrapper_function_form() {
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: function(s){ return s; } });
el.innerHTML = policy.createHTML(location.search);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "an identity function-expression createHTML must keep the finding"
    );
}

// --- non-ASCII Trusted Types callback parameter names -----------------------
//
// `identifier_referenced` used to advance its search cursor by one byte after
// a rejected match, which lands inside a multi-byte codepoint and panics on the
// next slice. A scanned page controls the callback parameter name, and JS
// identifiers may start with any ID_Start character, so this was a
// remote-triggerable panic: the analysis task died and the target was reported
// clean with exit 0. All three cases below panicked before the fix.

#[test]
fn test_tt_non_ascii_param_sanitizer_branch_does_not_panic() {
    // Sanitizer branch: the param is referenced only inside `sanitize(…)`, and
    // `한글x` is a *different* identifier — so the wrapper is strict.
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: function(한글){ var 한글x = 1; return DOMPurify.sanitize(한글); } });
el.innerHTML = policy.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "non-ASCII param sanitized wrapper must clear taint (and must not panic)"
    );
}

#[test]
fn test_tt_non_ascii_param_no_sanitizer_does_not_panic() {
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: function(한글){ var 한글x = 1; return ""; } });
el.innerHTML = policy.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "non-ASCII param never referenced is strict (and must not panic)"
    );
}

#[test]
fn test_tt_non_ascii_param_passthrough_still_permissive() {
    // The real reference sits *after* a rejected `한글x` match, so this also
    // proves the cursor advance does not skip past a genuine later occurrence.
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML: function(한글){ var 한글x = 1; return 한글; } });
el.innerHTML = policy.createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "non-ASCII param passed through must keep the finding"
    );
}

#[test]
fn test_tt_method_shorthand_strict_wrapper_clears() {
    // `createHTML(s) { return DOMPurify.sanitize(s); }` method shorthand.
    let code = r#"
const policy = trustedTypes.createPolicy('p', { createHTML(s) { return DOMPurify.sanitize(s); } });
el.innerHTML = policy.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "method-shorthand strict createHTML must clear taint"
    );
}

#[test]
fn test_tt_inline_chain_strict_clears() {
    // Inline `createPolicy(...).createHTML(x)` chain (no variable binding).
    let code = r#"
el.innerHTML = trustedTypes.createPolicy('p', { createHTML: s => escapeHtml(s) }).createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "inline strict createPolicy().createHTML() chain must clear taint"
    );
}

#[test]
fn test_tt_inline_chain_permissive_keeps() {
    let code = r#"
el.innerHTML = trustedTypes.createPolicy('p', { createHTML: s => s }).createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "inline permissive createPolicy().createHTML() chain must keep finding"
    );
}

#[test]
fn test_tt_strict_default_policy_suppresses_under_enforcement() {
    // A strict 'default' policy auto-applies to every TrustedHTML sink when
    // require-trusted-types-for is enforced → the raw-string sink is protected.
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) });
document.body.innerHTML = location.hash;
"#;
    assert!(
        tt_findings(code, true).is_empty(),
        "strict default policy under enforcement must suppress the TrustedHTML finding"
    );
}

#[test]
fn test_tt_strict_default_policy_kept_without_enforcement() {
    // No require-trusted-types-for → the default policy is inert → finding kept.
    // This is the critical no-false-negative guarantee.
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) });
document.body.innerHTML = location.hash;
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "without enforcement a default policy is inert → finding must be kept"
    );
}

#[test]
fn test_tt_permissive_default_policy_kept_under_enforcement() {
    // The headline case from #1097: createPolicy('default', {createHTML: x=>x})
    // is a bypassable no-op — even with enforcement it provides no protection,
    // so the finding must remain.
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: x => x });
document.body.innerHTML = location.hash;
"#;
    assert!(
        !tt_findings(code, true).is_empty(),
        "permissive default policy must be flagged, not treated as protection"
    );
}

#[test]
fn test_tt_default_suppression_only_covers_html_sinks() {
    // A strict default createHTML guards TrustedHTML sinks only — it must NOT
    // suppress a TrustedScript sink like eval (that needs createScript).
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) });
eval(location.hash);
"#;
    assert!(
        tt_findings(code, true)
            .iter()
            .any(|v| v.sink.contains("eval")),
        "default createHTML must not suppress a non-HTML (eval) sink"
    );
}

#[test]
fn test_tt_fn_guard_permissive_explicit_policy_blocks_default_suppression() {
    // FN guard: a strict default policy would normally suppress, but the
    // presence of a permissive explicit policy means a value could reach the
    // sink as already-Trusted-but-unsanitized — so the finding is kept.
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) });
const weak = trustedTypes.createPolicy('weak', { createHTML: x => x });
document.body.innerHTML = location.hash;
"#;
    assert!(
        !tt_findings(code, true).is_empty(),
        "a permissive explicit policy must disable default-policy suppression (no FN)"
    );
}

#[test]
fn test_tt_default_suppression_order_keeps_finding_when_policy_defined_after() {
    // The sink executes before the policy is created → at sink time the default
    // policy is not yet active → finding kept (correct and FN-safe).
    let code = r#"
document.body.innerHTML = location.hash;
trustedTypes.createPolicy('default', { createHTML: s => DOMPurify.sanitize(s) });
"#;
    assert!(
        !tt_findings(code, true).is_empty(),
        "a default policy defined after the sink must not suppress it"
    );
}

#[test]
fn test_tt_window_prefixed_create_policy_recognised() {
    let code = r#"
const p = window.trustedTypes.createPolicy('p', { createHTML: s => DOMPurify.sanitize(s) });
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "window.trustedTypes.createPolicy must be recognised"
    );
}

#[test]
fn test_tt_unknown_custom_sanitizer_in_policy_is_permissive() {
    // An unrecognised wrapper inside createHTML is conservatively permissive, so
    // we keep the finding (no false negative on a custom, possibly-unsafe fn).
    let code = r#"
const p = trustedTypes.createPolicy('p', { createHTML: s => myCustomThing(s) });
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "unrecognised createHTML body must stay permissive (keep finding)"
    );
}

#[test]
fn test_tt_no_policy_no_behavior_change() {
    // Sanity: with no Trusted Types at all, enforcement flag changes nothing.
    let code = r#"
document.body.innerHTML = location.hash;
"#;
    assert_eq!(
        tt_findings(code, true).len(),
        tt_findings(code, false).len(),
        "absent TT policies → enforcement flag must not change findings"
    );
    assert!(!tt_findings(code, true).is_empty());
}

#[test]
fn test_tt_strict_create_script_wrapper_clears_eval() {
    // createScript with a constant (no-param) body never returns the input, so
    // it is strict → the eval sink is cleared.
    let code = r#"
const p = trustedTypes.createPolicy('p', { createScript: () => 'console.log(1)' });
eval(p.createScript(location.hash));
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "strict createScript wrapper must clear the eval sink"
    );
}

#[test]
fn test_tt_strict_create_script_url_wrapper_clears_src() {
    let code = r#"
const s = document.createElement('script');
const p = trustedTypes.createPolicy('p', { createScriptURL: () => 'https://cdn.example/a.js' });
s.src = p.createScriptURL(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "strict createScriptURL wrapper must clear the src sink"
    );
}

#[test]
fn test_tt_permissive_create_script_wrapper_keeps_eval() {
    let code = r#"
const p = trustedTypes.createPolicy('p', { createScript: s => s });
eval(p.createScript(location.hash));
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "permissive createScript wrapper must keep the eval finding"
    );
}

// --- Trusted Types classifier FN regression tests (review #1097) ----------

#[test]
fn test_tt_default_param_createhtml_is_permissive() {
    // Regression: `(s = '') => s` is a default-parameter (AssignmentPattern), so
    // the old `first_param_name` returned None and the body was misclassified as
    // strict — suppressing a real finding. It is an identity passthrough and
    // must stay permissive (finding kept) even under enforcement.
    let code = r#"
trustedTypes.createPolicy('default', { createHTML: (s = '') => s });
document.body.innerHTML = location.hash;
"#;
    assert!(
        !tt_findings(code, true).is_empty(),
        "default-parameter identity createHTML must not be treated as strict"
    );
}

#[test]
fn test_tt_destructured_param_createhtml_is_permissive() {
    let code = r#"
const p = trustedTypes.createPolicy('p', { createHTML: ({ html }) => html });
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "destructured-param createHTML can't be name-tracked → keep finding"
    );
}

#[test]
fn test_tt_guarded_raw_return_before_sanitizer_is_permissive() {
    // Regression: a raw `return s` nested in an `if` precedes the top-level
    // sanitizer return. The old single-first-return scan only saw the sanitizer
    // and wrongly classified the policy strict, suppressing the finding.
    let code = r#"
const p = trustedTypes.createPolicy('p', {
  createHTML(s) { if (window.unsafe) return s; return DOMPurify.sanitize(s); }
});
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "a guarded raw-passthrough return path must keep the policy permissive"
    );
}

#[test]
fn test_tt_concat_with_sanitizer_is_permissive() {
    // `return DOMPurify.sanitize(s) + s` leaks the raw input alongside the
    // sanitized output → permissive.
    let code = r#"
const p = trustedTypes.createPolicy('p', { createHTML: s => DOMPurify.sanitize(s) + s });
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        !tt_findings(code, false).is_empty(),
        "concatenating raw input with sanitized output must stay permissive"
    );
}

#[test]
fn test_tt_sole_sanitizer_return_after_side_effect_is_strict() {
    // A non-return statement before the sole sanitizer return must NOT block the
    // strict classification — the returned value is still fully sanitized.
    let code = r#"
const p = trustedTypes.createPolicy('p', {
  createHTML(s) { log('converting'); return DOMPurify.sanitize(s); }
});
el.innerHTML = p.createHTML(location.hash);
"#;
    assert!(
        tt_findings(code, false).is_empty(),
        "a sole sanitizer return after a side-effect statement is still strict"
    );
}

#[test]
fn for_of_taints_loop_binding_from_tainted_iterable() {
    // for-of over a tainted iterable taints the per-iteration binding, so the
    // sink inside the body is flagged. The old catch-all `_ => {}` arm dropped
    // the body entirely (false negative on a common, esp. minified, form).
    let code = r#"for (const x of [location.hash]) { eval(x); }"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink.contains("eval")),
        "for-of body sink should be detected, got {vulns:?}"
    );
}

#[test]
fn for_in_do_while_and_labeled_bodies_are_walked() {
    // do-while body must be walked.
    let do_while = r#"let h = location.hash; do { document.write(h); } while (false);"#;
    let v1 = AstDomAnalyzer::new().analyze(do_while).unwrap();
    assert!(
        v1.iter().any(|v| v.sink.contains("write")),
        "do-while body sink should be detected, got {v1:?}"
    );
    // labeled loop body must be walked.
    let labeled = r#"let h = location.hash; outer: for (;;) { document.write(h); break outer; }"#;
    let v2 = AstDomAnalyzer::new().analyze(labeled).unwrap();
    assert!(
        v2.iter().any(|v| v.sink.contains("write")),
        "labeled loop body sink should be detected, got {v2:?}"
    );
}

#[test]
fn for_loop_expression_init_taint_reaches_sink() {
    // `for (x = location.hash; …)` runs an unconditional tainting assignment in
    // the init; the downstream sink must be flagged (init was previously only
    // walked for the VariableDeclaration form).
    let code = r#"var x; for (x = location.hash; ; ) { document.write(x); break; }"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink.contains("write")),
        "for-init expression assignment taint should reach the sink, got {vulns:?}"
    );
}

#[test]
fn purify_substring_does_not_suppress_unrelated_function() {
    // A name that merely *contains* "purify" (e.g. `impurifyData`) must NOT be
    // treated as a sanitizer — doing so cleared taint and hid a real DOM-XSS.
    let code = r#"document.write(impurifyData(location.hash));"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink.contains("write")),
        "impurifyData must not be treated as a sanitizer, got {vulns:?}"
    );
    // Whole-segment `purify`/`dompurify` still sanitize (taint cleared).
    let sanitized = r#"document.write(purify(location.hash));"#;
    assert!(
        AstDomAnalyzer::new().analyze(sanitized).unwrap().is_empty(),
        "purify(x) as a whole-segment sanitizer should suppress the finding"
    );
}

#[test]
fn settimeout_tainted_delay_argument_is_not_a_sink() {
    // `setTimeout(fn, location.hash)`: a tainted *delay* (2nd) argument is not
    // exploitable, so it must NOT be flagged (only argument 0 is executed code).
    let delay = r#"function fn(){} setTimeout(fn, location.hash);"#;
    let v_delay = AstDomAnalyzer::new().analyze(delay).unwrap();
    assert!(
        !v_delay.iter().any(|v| v.sink.contains("setTimeout")),
        "tainted delay arg must not flag setTimeout, got {v_delay:?}"
    );
    // `setTimeout(location.hash, 100)`: a tainted *code* (1st) argument IS a
    // sink and must still be flagged.
    let code = r#"setTimeout(location.hash, 100);"#;
    let v_code = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        v_code.iter().any(|v| v.sink.contains("setTimeout")),
        "tainted code arg must still flag setTimeout, got {v_code:?}"
    );
}

// --- Issue #1125: Document.parseHTMLUnsafe() as an HTML-parsing sink ---

#[test]
fn detects_document_parse_html_unsafe_from_search() {
    // xssmaze /htmlunsafe/level4/: URLSearchParams source -> parseHTMLUnsafe.
    let js = r#"
var q = new URLSearchParams(location.search).get('query') || '';
var doc = Document.parseHTMLUnsafe(q);
document.getElementById('out').append(...doc.body.childNodes);
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "parseHTMLUnsafe"),
        "Document.parseHTMLUnsafe must be modeled as a sink: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_bare_parse_html_unsafe_from_hash() {
    // Bare `parseHTMLUnsafe(...)` (destructured off Document) is the same sink.
    let js = r#"
var html = decodeURIComponent(location.hash.slice(1));
var doc = parseHTMLUnsafe(html);
document.body.append(...doc.body.childNodes);
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.sink == "parseHTMLUnsafe" && v.source.contains("location.hash")),
        "bare parseHTMLUnsafe must fire on a tainted argument: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn fetch_text_to_parse_html_unsafe() {
    // xssmaze /htmlunsafe/level6/: async fetch response -> parseHTMLUnsafe.
    let js = r#"
fetch('/api').then(function (r) { return r.text(); })
  .then(function (t) {
    var doc = Document.parseHTMLUnsafe(t);
    document.getElementById('out').append(...doc.body.childNodes);
  });
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "parseHTMLUnsafe"),
        "fetch text -> parseHTMLUnsafe must fire; got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_html_unsafe_static_argument_is_not_a_sink() {
    // A static HTML string is not attacker-controlled: must not flag.
    let js = r#"var doc = Document.parseHTMLUnsafe('<b>hi</b>');"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "parseHTMLUnsafe"),
        "static parseHTMLUnsafe argument must not be flagged, got {r:?}"
    );
}

// --- Issue #1126: window.open() as a navigation sink ---

#[test]
fn detects_window_open_from_hash() {
    // xssmaze /navsink/level1/: location.hash -> window.open.
    let js = r#"
var target = decodeURIComponent(location.hash.slice(1));
if (target) { window.open(target); }
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter()
            .any(|v| v.sink == "window.open" && v.source.contains("location.hash")),
        "window.open of location.hash must be modeled as a sink: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_window_open_from_search_with_target_arg() {
    // xssmaze /navsink/level2/: URLSearchParams -> window.open(url, '_blank').
    let js = r#"
var url = new URLSearchParams(location.search).get('query') || '';
if (url) { window.open(url, '_blank'); }
"#;
    let r = AstDomAnalyzer::new().analyze(js).expect("parses");
    assert!(
        r.iter().any(|v| v.sink == "window.open"),
        "window.open(url, '_blank') must fire on a tainted URL: got {:?}",
        r.iter()
            .map(|v| (v.source.clone(), v.sink.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_self_and_global_this_open_aliases() {
    for (alias, src) in [
        ("self.open(t)", "self.open"),
        ("globalThis.open(t)", "globalThis.open"),
    ] {
        let js = format!("var t = location.hash; {alias};");
        let r = AstDomAnalyzer::new().analyze(&js).unwrap();
        assert!(
            r.iter().any(|v| v.sink == src),
            "{src} alias must be modeled as a navigation sink, got {r:?}"
        );
    }
}

#[test]
fn window_open_tainted_window_name_is_not_a_sink() {
    // Only argument-0 (the URL) is exploitable. A tainted 2nd `windowName`
    // argument (`window.open('/x', location.hash)`) must NOT be flagged.
    let js = r#"window.open('/safe', location.hash);"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "window.open"),
        "tainted window-name arg must not flag window.open, got {r:?}"
    );
}

#[test]
fn window_open_static_url_is_not_a_sink() {
    let js = r#"window.open('https://example.com/', '_blank');"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink == "window.open"),
        "static window.open URL must not be flagged, got {r:?}"
    );
}

#[test]
fn xhr_open_is_not_a_window_open_sink() {
    // `xhr.open(method, url)` is the XMLHttpRequest API, not a navigation
    // sink: the bare `open` method name must not collide with `window.open`.
    let js = r#"
var xhr = new XMLHttpRequest();
xhr.open('GET', location.hash);
"#;
    let r = AstDomAnalyzer::new().analyze(js).unwrap();
    assert!(
        !r.iter().any(|v| v.sink.ends_with("open")),
        "xhr.open must not be treated as a navigation sink, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// Promise combinator roots (`Promise.all` / `Promise.resolve`)
// ---------------------------------------------------------------------------

#[test]
fn test_promise_all_indexed_element_reaches_sink() {
    // xssmaze taintflow-level5: the tainted element is identified only by its
    // index inside the `Promise.all` array, and arrives in the callback as one
    // slot of the settled array.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
Promise.all([
  Promise.resolve('<section>'),
  Promise.resolve(q),
  Promise.resolve('</section>')
]).then(function (parts) {
  document.getElementById('out').innerHTML = parts.join('');
});
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "Promise.all element taint should reach the .then callback: {vulns:?}"
    );
}

#[test]
fn test_promise_resolve_tainted_reaches_sink() {
    let code = r#"
var q = location.hash.slice(1);
Promise.resolve(q).then(function (v) {
  document.getElementById('out').innerHTML = v;
});
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "Promise.resolve(tainted) should carry taint into .then: {vulns:?}"
    );
}

#[test]
fn test_promise_combinator_fp_control_untainted_values() {
    // FP control: nothing attacker-controlled enters the chain, so no finding —
    // the combinator must be a *link*, never a source of its own.
    let code = r#"
var greeting = '<b>hello</b>';
Promise.all([Promise.resolve('<section>'), Promise.resolve(greeting)]).then(function (parts) {
  document.getElementById('out').innerHTML = parts.join('');
});
Promise.resolve('static').then(function (v) {
  document.getElementById('out2').innerHTML = v;
});
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "untainted Promise chains must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// Taint arriving as a callback's *return* value
// ---------------------------------------------------------------------------

#[test]
fn test_string_replace_replacer_function_return() {
    // xssmaze taintflow-level8: the tainted value is the replacer's return
    // value; `replace()` itself only ever sees a constant pattern.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
var template = '<p>Hello NAME_SLOT!</p>';
var rendered = template.replace('NAME_SLOT', function () { return q; });
document.getElementById('out').innerHTML = rendered;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "replacer-function return should taint the replace() result: {vulns:?}"
    );
}

#[test]
fn test_array_map_arrow_return_taints_result() {
    let code = r#"
var q = location.hash.slice(1);
var rows = ['a', 'b'].map(row => '<li>' + q + '</li>');
document.getElementById('out').innerHTML = rows.join('');
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "map callback return should taint the mapped array: {vulns:?}"
    );
}

#[test]
fn test_callback_return_fp_control_sanitized_and_shadowed() {
    // Three benign forms that must stay silent:
    //  1. the replacer returns a *sanitized* value;
    //  2. the replacer's parameter shadows the tainted outer name, so the
    //     returned identifier is the match, not the URL parameter;
    //  3. the callback is in a position whose return value is discarded.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
var t1 = '<p>SLOT</p>'.replace('SLOT', function () { return encodeURIComponent(q); });
document.getElementById('a').innerHTML = t1;
var t2 = '<p>xx</p>'.replace(/x/g, function (q) { return q.toUpperCase(); });
document.getElementById('b').innerHTML = t2;
var t3 = ['a'].filter(function () { return q; });
document.getElementById('c').innerHTML = t3;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "sanitized / shadowed / discarded callback returns must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// Tagged templates
// ---------------------------------------------------------------------------

#[test]
fn test_tagged_template_tag_returns_interpolated_value() {
    // xssmaze taintflow-level7: the value is never in the cooked strings — the
    // tag receives it as a positional argument and splices it into its result.
    let code = r#"
var raw = decodeURIComponent(location.hash.slice(1));
function html(strings, value) {
  return strings[0] + value + strings[1];
}
document.getElementById('out').innerHTML = html`<article>${raw}</article>`;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "tagged template with a value-splicing tag should report: {vulns:?}"
    );
}

#[test]
fn test_tagged_template_fp_control_unknown_and_escaping_tags() {
    // FP control, both halves of the realistic benign space:
    //  1. `html` is imported (lit-html and friends) — no summary, and those
    //     tags insert values as text, so an unknown tag must stay opaque;
    //  2. a local tag that escapes every interpolated slot.
    let code = r#"
var raw = decodeURIComponent(location.hash.slice(1));
document.getElementById('a').innerHTML = html`<article>${raw}</article>`;
function safe(strings, value) {
  return strings[0] + encodeURIComponent(value) + strings[1];
}
document.getElementById('b').innerHTML = safe`<article>${raw}</article>`;
function justStrings(strings) {
  return strings.join('');
}
document.getElementById('c').innerHTML = justStrings`<article>${raw}</article>`;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "unknown / escaping / strings-only tags must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// Taint-forwarding constructors (`new Proxy(...)`, collections)
// ---------------------------------------------------------------------------

#[test]
fn test_proxy_get_trap_forwards_taint() {
    // xssmaze taintflow-level2: the sink reads a property whose value is
    // produced by a Proxy get trap, not by an access on the wrapped object.
    let code = r#"
var raw = decodeURIComponent(location.hash.slice(1));
var store = new Proxy({ body: raw }, {
  get: function (target, prop) { return target[prop]; }
});
if (store.body) { document.getElementById('out').innerHTML = store.body; }
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "Proxy over a tainted target should read back tainted: {vulns:?}"
    );
}

#[test]
fn test_map_constructor_forwards_taint() {
    let code = r#"
var raw = location.hash.slice(1);
var m = new Map([['body', raw]]);
document.getElementById('out').innerHTML = m.get('body');
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "new Map(taintedEntries) should read back tainted: {vulns:?}"
    );
}

#[test]
fn test_taint_forwarding_constructor_fp_control() {
    // FP control: a Proxy/Map built from page-authored data stays clean, and a
    // constructor outside the allowlist does not forward taint on its own.
    let code = r#"
var raw = location.hash.slice(1);
var defaults = new Proxy({ body: '<b>hi</b>' }, { get: function (t, p) { return t[p]; } });
document.getElementById('a').innerHTML = defaults.body;
var when = new Date(raw);
document.getElementById('b').innerHTML = when;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "clean Proxy and non-forwarding constructors must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// Class accessors
// ---------------------------------------------------------------------------

#[test]
fn test_class_getter_returns_constructor_argument() {
    // xssmaze taintflow-level3: the sink reads an accessor property, not the
    // field the value was written to.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
class Message {
  constructor(value) { this._value = value; }
  get body() { return this._value; }
}
document.getElementById('out').innerHTML = new Message(q).body;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "class getter over a tainted constructor argument should report: {vulns:?}"
    );
}

#[test]
fn test_class_getter_through_instance_variable() {
    let code = r#"
class Message {
  constructor(value) { this._value = value; }
  get body() { return this._value; }
}
var m = new Message(location.hash.slice(1));
document.getElementById('out').innerHTML = m.body;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "accessor read off an instance variable should report: {vulns:?}"
    );
}

#[test]
fn test_class_accessor_fp_control() {
    // FP control:
    //  1. the constructor escapes before storing, so the accessor reads clean;
    //  2. the accessor returns a different, page-authored field;
    //  3. the tainted argument is stored in a field nothing reads.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
class Escaped {
  constructor(value) { this._value = encodeURIComponent(value); }
  get body() { return this._value; }
}
document.getElementById('a').innerHTML = new Escaped(q).body;
class Titled {
  constructor(value) { this._value = value; this._title = 'Draft'; }
  get title() { return this._title; }
}
document.getElementById('b').innerHTML = new Titled(q).title;
var t = new Titled(q);
document.getElementById('c').innerHTML = t.title;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "escaping constructors and unrelated accessors must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// Object.assign and iteration-callback exec sinks
// ---------------------------------------------------------------------------

#[test]
fn test_object_assign_onto_location_href() {
    // xssmaze domsink-level6: the href setter still fires, so a javascript:
    // URL navigates and runs.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
if (q) { Object.assign(location, { href: q }); }
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "location.href"),
        "Object.assign onto location should report a navigation sink: {vulns:?}"
    );
}

#[test]
fn test_object_assign_onto_element_inner_html() {
    let code = r#"
var q = location.hash.slice(1);
Object.assign(document.getElementById('out'), { innerHTML: q });
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "innerHTML"),
        "Object.assign onto a looked-up element should report: {vulns:?}"
    );
}

#[test]
fn test_object_assign_fp_control_plain_config_object() {
    // FP control: `href` / `src` are ordinary keys on a plain options object,
    // and a merge onto `location` of anything but `href` cannot navigate to a
    // javascript: URL.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
var opts = { retries: 1 };
Object.assign(opts, { href: q, src: q, innerHTML: q });
Object.assign(location, { hash: q, search: q, pathname: q });
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "config-object merges and non-navigating location keys must not report: {vulns:?}"
    );
}

#[test]
fn test_array_map_eval_over_tainted_receiver() {
    // xssmaze domsink-level5: eval is handed to .map() as a callback and never
    // appears in call position.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
if (q) {
  var results = q.split('\n').map(eval);
  document.getElementById('out').textContent = 'ran ' + results.length;
}
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "eval"),
        "map(eval) over a tainted receiver should report: {vulns:?}"
    );
}

#[test]
fn test_exec_callback_iteration_fp_control() {
    // FP control: a clean receiver, a non-executing builtin callback, and a
    // sink name that only builds functions rather than running them.
    let code = r#"
var q = new URLSearchParams(location.search).get('query') || '';
var steps = ['1+1', '2+2'].map(eval);
var nums = q.split(',').map(Number);
var fns = q.split(',').map(Function);
document.getElementById('out').textContent = steps.length + nums.length + fns.length;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "clean receivers and non-executing callbacks must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// IndexedDB stored records as a source
// ---------------------------------------------------------------------------

#[test]
fn test_indexeddb_get_result_reaches_sink() {
    // xssmaze domsource-level1: the value is persisted to IndexedDB and read
    // back through two async callbacks.
    let code = r#"
var open = indexedDB.open('notes-db', 1);
open.onsuccess = function (e) {
  var db = e.target.result;
  var get = db.transaction('notes', 'readonly').objectStore('notes').get('latest');
  get.onsuccess = function (ev) {
    if (ev.target.result != null) {
      document.getElementById('out').innerHTML = ev.target.result;
    }
  };
};
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns
            .iter()
            .any(|v| v.sink == "innerHTML" && v.source.contains("indexedDB")),
        "IndexedDB record read should reach the sink: {vulns:?}"
    );
}

#[test]
fn test_indexeddb_fp_control_connection_and_write_requests() {
    // FP control: neither of the two IndexedDB requests whose `result` is not
    // data may be treated as a source — `indexedDB.open()` resolves to a
    // database connection, and `put()` resolves to the written key. Nor may a
    // same-named `.get()` on a plain Map.
    let code = r#"
var open = indexedDB.open('notes-db', 1);
open.onsuccess = function (e) {
  document.getElementById('a').innerHTML = e.target.result.name;
  var db = e.target.result;
  var put = db.transaction('notes', 'readwrite').objectStore('notes').put('hi', 'k');
  put.onsuccess = function (ev) {
    document.getElementById('b').innerHTML = ev.target.result;
  };
};
var settings = new Map();
var got = settings.get('theme');
document.getElementById('c').innerHTML = got;
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "connection / write requests and plain Map reads must not report: {vulns:?}"
    );
}

// ---------------------------------------------------------------------------
// CSS custom property round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_css_custom_property_round_trip() {
    // xssmaze domsource-level6: the value is stashed on a --custom-property and
    // read back through the CSSOM before it reaches an HTML sink.
    let code = r#"
var raw = decodeURIComponent(location.hash.slice(1));
if (raw) { document.documentElement.style.setProperty('--maze-label', raw); }
var label = getComputedStyle(document.documentElement)
  .getPropertyValue('--maze-label').trim();
if (label) { document.getElementById('out').insertAdjacentHTML('beforeend', label); }
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.iter().any(|v| v.sink == "insertAdjacentHTML"),
        "a custom property written tainted should read back tainted: {vulns:?}"
    );
}

#[test]
fn test_css_custom_property_fp_control() {
    // FP control: a custom property the page only ever wrote literal text into,
    // and a *standard* property — whose value the CSSOM reparses, so what comes
    // back is not the input string.
    let code = r#"
var raw = decodeURIComponent(location.hash.slice(1));
document.documentElement.style.setProperty('--theme', 'dark');
var theme = getComputedStyle(document.documentElement).getPropertyValue('--theme');
document.getElementById('a').insertAdjacentHTML('beforeend', theme);
document.documentElement.style.setProperty('color', raw);
var color = getComputedStyle(document.documentElement).getPropertyValue('color');
document.getElementById('b').insertAdjacentHTML('beforeend', color);
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "clean custom properties and standard properties must not report: {vulns:?}"
    );
}

#[test]
fn test_css_custom_property_helper_summary_does_not_leak() {
    // The summary walk assumes each parameter is tainted in turn, so a helper
    // that writes its parameter into a custom property must not leave that
    // property tainted for a read that follows a *clean* call.
    let code = r#"
function setLabel(value) {
  document.documentElement.style.setProperty('--label', value);
}
setLabel('Drafts');
var label = getComputedStyle(document.documentElement).getPropertyValue('--label');
document.getElementById('out').insertAdjacentHTML('beforeend', label);
"#;
    let vulns = AstDomAnalyzer::new().analyze(code).unwrap();
    assert!(
        vulns.is_empty(),
        "a hypothetical summary walk must not taint a global custom property: {vulns:?}"
    );
}
