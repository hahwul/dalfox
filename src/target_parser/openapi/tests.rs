use super::*;

const PETSTORE_YAML: &str = r##"
openapi: 3.0.3
info: {title: t, version: "1"}
servers:
  - url: "{scheme}://api.example.com:{port}/v1"
    variables:
      scheme: {default: https, enum: [https, http]}
      port: {default: "8443"}
paths:
  /pets/{petId}:
    parameters:
      - {name: petId, in: path, required: true, schema: {type: integer, example: 42}}
    get:
      parameters:
        - {name: q, in: query, schema: {type: string}}
        - {name: X-Trace, in: header, schema: {type: string, default: abc}}
        - {name: Accept, in: header, example: text/html}
        - {name: sid, in: cookie, example: s1}
      responses:
        200: {description: ok}
    put:
      requestBody:
        content:
          text/plain: {schema: {type: string}}
          application/json:
            schema: {$ref: '#/components/schemas/Pet'}
      responses: {default: {description: x}}
  /upload:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file: {type: string, format: binary}
                note: {type: string, example: hi}
      responses: {default: {description: x}}
  /form:
    post:
      requestBody:
        $ref: '#/components/requestBodies/Login'
      responses: {default: {description: x}}
  /xml:
    post:
      requestBody:
        content:
          application/xml:
            schema: {$ref: '#/components/schemas/Pet'}
      responses: {default: {description: x}}
components:
  requestBodies:
    Login:
      content:
        application/x-www-form-urlencoded:
          schema:
            type: object
            properties:
              user: {type: string, example: "a b&c"}
              remember: {type: boolean}
  schemas:
    Pet:
      type: object
      properties:
        id: {type: integer, readOnly: true}
        name: {type: string}
        parent: {$ref: '#/components/schemas/Pet'}
        tags: {type: array, items: {type: string}}
"##;

fn parse(spec: &str) -> SpecImport {
    parse_openapi(spec, None).expect("spec parses")
}

fn find<'a>(targets: &'a [Target], method: &str, path: &str) -> &'a Target {
    targets
        .iter()
        .find(|t| t.method == method && t.url.path() == path)
        .unwrap_or_else(|| panic!("no {method} {path} in {targets:#?}"))
}

fn header<'a>(t: &'a Target, name: &str) -> Option<&'a str> {
    t.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
fn yaml_spec_expands_every_operation() {
    let out = parse(PETSTORE_YAML);
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert_eq!(out.targets.len(), 5);

    // Server variables substituted; path param from the schema example;
    // query param from a typed placeholder; header + cookie params placed.
    let get = find(&out.targets, "GET", "/v1/pets/42");
    assert_eq!(
        get.url.as_str(),
        "https://api.example.com:8443/v1/pets/42?q=test"
    );
    assert_eq!(header(get, "X-Trace"), Some("abc"));
    assert_eq!(header(get, "Accept"), None, "OAS ignores Accept params");
    assert_eq!(get.cookies, vec![("sid".to_string(), "s1".to_string())]);
    assert!(get.data.is_none());
}

#[test]
fn json_body_from_schema_cuts_ref_cycle_and_drops_read_only() {
    let out = parse(PETSTORE_YAML);
    let put = find(&out.targets, "PUT", "/v1/pets/42");
    // JSON preferred over text/plain.
    assert_eq!(header(put, "Content-Type"), Some("application/json"));
    let body: Value = serde_json::from_str(put.data.as_deref().unwrap()).unwrap();
    assert_eq!(body["name"], "test");
    assert_eq!(body["tags"], serde_json::json!(["test"]));
    assert!(body.get("id").is_none(), "readOnly property not sent");
    // Self-reference: cut at its first recurrence.
    assert!(body.get("parent").is_some_and(Value::is_null));
}

#[test]
fn multipart_body_is_urlencoded_data_with_the_multipart_flag() {
    let out = parse(PETSTORE_YAML);
    let up = find(&out.targets, "POST", "/v1/upload");
    assert!(up.multipart);
    assert_eq!(up.data.as_deref(), Some("file=test&note=hi"));
    assert_eq!(
        header(up, "Content-Type"),
        None,
        "builder sets the boundary"
    );
}

#[test]
fn form_body_via_request_body_ref_is_encoded() {
    let out = parse(PETSTORE_YAML);
    let form = find(&out.targets, "POST", "/v1/form");
    assert!(!form.multipart);
    assert_eq!(form.data.as_deref(), Some("remember=true&user=a+b%26c"));
    assert_eq!(
        header(form, "Content-Type"),
        Some("application/x-www-form-urlencoded")
    );
}

#[test]
fn xml_body_is_rooted_at_the_component_name() {
    let out = parse(PETSTORE_YAML);
    let xml = find(&out.targets, "POST", "/v1/xml");
    assert_eq!(header(xml, "Content-Type"), Some("application/xml"));
    let data = xml.data.as_deref().unwrap();
    assert!(data.starts_with("<Pet><name>test</name>"), "{data}");
    assert!(data.contains("<tags>test</tags>"), "{data}");
    roxmltree::Document::parse(data).expect("well-formed XML");
}

#[test]
fn json_spec_parses_too() {
    let spec = r##"{
      "openapi": "3.1.0",
      "servers": [{"url": "http://127.0.0.1:8080"}],
      "paths": {"/search": {"get": {"parameters": [
        {"name": "q", "in": "query", "schema": {"type": ["string", "null"]}},
        {"name": "n", "in": "query", "schema": {"type": "integer", "enum": [7, 8]}}
      ]}}}
    }"##;
    let out = parse(spec);
    assert_eq!(
        out.targets[0].url.as_str(),
        "http://127.0.0.1:8080/search?q=test&n=7"
    );
}

#[test]
fn path_param_fill_order_and_encoding() {
    let spec = r##"{
      "openapi": "3.0.0",
      "servers": [{"url": "https://h"}],
      "paths": {"/a/{ex}/{def}/{uid}/{none}/{bad}": {"get": {"parameters": [
        {"name": "ex", "in": "path", "example": "e1", "schema": {"default": "nope"}},
        {"name": "def", "in": "path", "schema": {"type": "string", "default": "d1"}},
        {"name": "uid", "in": "path", "schema": {"type": "string", "format": "uuid"}},
        {"name": "bad", "in": "path", "example": "../../admin?x=1#f"}
      ]}}}
    }"##;
    let t = &parse(spec).targets[0];
    // `none` has no parameter definition → generic placeholder; the hostile
    // value is percent-encoded into one segment instead of re-shaping the URL.
    assert_eq!(
        t.url.path(),
        "/a/e1/d1/00000000-0000-4000-8000-000000000000/1/..%2F..%2Fadmin%3Fx%3D1%23f"
    );
    assert!(t.url.query().is_none());
}

#[test]
fn ref_cycles_and_remote_refs_terminate_without_fetching() {
    let spec = r##"{
      "openapi": "3.0.0",
      "servers": [{"url": "https://h"}],
      "paths": {"/x": {"post": {
        "parameters": [
          {"$ref": "#/components/parameters/Loop"},
          {"$ref": "https://evil.example/p.json#/P"},
          {"name": "ok", "in": "query", "schema": {"$ref": "https://evil.example/s.json"}}
        ],
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}
      }}},
      "components": {
        "parameters": {"Loop": {"$ref": "#/components/parameters/Loop"}},
        "schemas": {
          "A": {"type": "object", "properties": {"b": {"$ref": "#/components/schemas/B"}}},
          "B": {"type": "object", "properties": {"a": {"$ref": "#/components/schemas/A"}}}
        }
      }
    }"##;
    let t = &parse(spec).targets[0];
    // The looping and the remote parameter refs are dropped; the remote schema
    // ref degrades to a placeholder.
    assert_eq!(t.url.as_str(), "https://h/x?ok=test");
    assert_eq!(t.data.as_deref(), Some(r##"{"b":{"a":null}}"##));
}

#[test]
fn wide_deep_schema_is_bounded() {
    // 64 properties per level, each pointing at the next level: 64^20 nodes
    // if expanded naively.
    let mut schemas = serde_json::Map::new();
    for lvl in 0..20 {
        let props: serde_json::Map<String, Value> = (0..64)
            .map(|i| {
                (
                    format!("p{i}"),
                    serde_json::json!({"$ref": format!("#/components/schemas/L{}", lvl + 1)}),
                )
            })
            .collect();
        schemas.insert(
            format!("L{lvl}"),
            serde_json::json!({"type": "object", "properties": props}),
        );
    }
    let spec = serde_json::json!({
        "openapi": "3.0.0",
        "servers": [{"url": "https://h"}],
        "paths": {"/x": {"post": {"requestBody": {"content": {"application/json":
            {"schema": {"$ref": "#/components/schemas/L0"}}}}}}},
        "components": {"schemas": schemas}
    });
    let t = &parse(&spec.to_string()).targets[0];
    assert!(t.data.as_ref().unwrap().len() < 64 * 1024);
}

#[test]
fn base_url_overrides_absolute_and_anchors_relative_servers() {
    let abs = r##"{"openapi":"3.0.0","servers":[{"url":"https://prod.example.com/api"}],
                  "paths":{"/u":{"get":{}}}}"##;
    let rel = r##"{"openapi":"3.0.0","servers":[{"url":"/api/v3"}],"paths":{"/u":{"get":{}}}}"##;
    let none = r##"{"openapi":"3.0.0","paths":{"/u":{"get":{}}}}"##;
    let base = Url::parse("http://127.0.0.1:9000/x/").unwrap();

    let t = &parse_openapi(abs, Some(&base)).unwrap().targets[0];
    assert_eq!(t.url.as_str(), "http://127.0.0.1:9000/x/u");
    let t = &parse_openapi(rel, Some(&base)).unwrap().targets[0];
    assert_eq!(t.url.as_str(), "http://127.0.0.1:9000/api/v3/u");
    let t = &parse_openapi(none, Some(&base)).unwrap().targets[0];
    assert_eq!(t.url.as_str(), "http://127.0.0.1:9000/x/u");

    // Without --base-url a relative / missing server can't be aimed anywhere.
    let err = parse_openapi(rel, None).unwrap_err().to_string();
    assert!(err.contains("--base-url"), "{err}");
    assert!(parse_openapi(none, None).is_err());
}

#[test]
fn bad_operations_are_skipped_not_fatal() {
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{
        "/ok":{"get":{}},
        "/ws":{"get":{"servers":[{"url":"wss://h/socket"}]}},
        "/var":{"get":{"servers":[{"url":"https://{tenant}.h"}]}},
        "/form":{"post":{"parameters":[{"name":"q","in":"query"}],
            "requestBody":{"content":{"application/x-www-form-urlencoded":
            {"schema":{"type":"string"}}}}}},
        "x-internal":{"get":{}}
    }}"##;
    let out = parse(spec);
    let mut paths: Vec<&str> = out.targets.iter().map(|t| t.url.path()).collect();
    paths.sort();
    assert_eq!(paths, vec!["/form", "/ok"], "`x-` keys are not paths");
    // A form schema with no fields drops the body, not the operation.
    let form = find(&out.targets, "POST", "/form");
    assert!(form.data.is_none());
    assert_eq!(form.url.query(), Some("q=test"));
    assert_eq!(out.skipped.len(), 2, "{:?}", out.skipped);
    assert!(out.skipped.iter().any(|s| s.contains("not an http/https")));
    assert!(out.skipped.iter().any(|s| s.contains("{tenant}")));

    // Every operation unusable → the whole import is an error.
    let all_bad =
        r##"{"openapi":"3.0.0","servers":[{"url":"ftp://h"}],"paths":{"/a":{"get":{}}}}"##;
    assert!(parse_openapi(all_bad, None).is_err());
}

#[test]
fn large_example_referenced_many_times_does_not_amplify() {
    // A 64 KiB example behind one `$ref`, used by 200 query parameters and by
    // 64 body properties: tens of MiB if every copy were made.
    let big = "x".repeat(64 * 1024);
    let params: Vec<Value> = (0..200)
        .map(|i| {
            serde_json::json!({"name": format!("p{i}"), "in": "query",
            "schema": {"$ref": "#/components/schemas/Big"}})
        })
        .collect();
    let props: serde_json::Map<String, Value> = (0..64)
        .map(|i| {
            (
                format!("f{i}"),
                serde_json::json!({"$ref": "#/components/schemas/Big"}),
            )
        })
        .collect();
    let spec = serde_json::json!({
        "openapi": "3.0.0",
        "servers": [{"url": "https://h"}],
        "paths": {
            "/params": {"get": {"parameters": params}},
            "/body": {"post": {"requestBody": {"content": {"application/json":
                {"schema": {"type": "object", "properties": props}}}}}},
            "/ok": {"get": {}}
        },
        "components": {"schemas": {"Big": {"type": "string", "example": big}}}
    });
    let out = parse(&spec.to_string());
    assert!(
        out.skipped
            .iter()
            .any(|s| s.starts_with("GET /params") && s.contains("MiB")),
        "{:?}",
        out.skipped
    );
    // The body sampler stops copying past the cap: later properties are null.
    let body = find(&out.targets, "POST", "/body");
    assert!(body.data.as_ref().unwrap().len() < MAX_IMPORT_REQUEST_BYTES);
    assert!(body.data.as_ref().unwrap().contains("null"));
    assert!(out.targets.iter().any(|t| t.url.path() == "/ok"));
}

#[test]
fn hostile_paths_stay_on_the_server_origin() {
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://api.example.com"}],"paths":{
        "//evil.example/x":{"get":{}},
        "@evil.example/y":{"get":{}}
    }}"##;
    let targets = parse(spec).targets;
    assert_eq!(targets.len(), 2, "both kept, re-anchored under the server");
    for t in targets {
        assert_eq!(t.url.host_str(), Some("api.example.com"), "{}", t.url);
    }
}

#[test]
fn header_and_cookie_injection_is_dropped() {
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{"/x":{"get":{
      "parameters":[
        {"name":"X-A","in":"header","example":"v\r\nInjected: 1"},
        {"name":"Bad Name","in":"header","example":"v"},
        {"name":"X-Ok","in":"header","example":"fine"},
        {"name":"c","in":"cookie","example":"1; admin=true"},
        {"name":"d","in":"cookie","example":"2"}
      ]}}}}"##;
    let t = &parse(spec).targets[0];
    assert_eq!(t.headers, vec![("X-Ok".to_string(), "fine".to_string())]);
    assert_eq!(t.cookies, vec![("d".to_string(), "2".to_string())]);
}

#[test]
fn swagger2_body_and_form_data() {
    let spec = r##"{
      "swagger": "2.0",
      "host": "legacy.example.com",
      "basePath": "/v2",
      "schemes": ["http"],
      "paths": {
        "/pet": {"post": {"consumes": ["application/json"], "parameters": [
          {"name": "body", "in": "body", "schema": {"$ref": "#/definitions/Pet"}}
        ]}},
        "/pet/{id}/upload": {"post": {"consumes": ["multipart/form-data"], "parameters": [
          {"name": "id", "in": "path", "type": "integer"},
          {"name": "meta", "in": "formData", "type": "string", "default": "m"},
          {"name": "file", "in": "formData", "type": "file"}
        ]}},
        "/login": {"post": {"parameters": [
          {"name": "user", "in": "formData", "type": "string"}
        ]}}
      },
      "definitions": {"Pet": {"type": "object", "properties": {"name": {"type": "string"}}}}
    }"##;
    let out = parse(spec);
    let pet = find(&out.targets, "POST", "/v2/pet");
    assert_eq!(pet.url.as_str(), "http://legacy.example.com/v2/pet");
    assert_eq!(pet.data.as_deref(), Some(r##"{"name":"test"}"##));
    assert_eq!(header(pet, "Content-Type"), Some("application/json"));

    let up = find(&out.targets, "POST", "/v2/pet/1/upload");
    assert!(up.multipart);
    assert_eq!(up.data.as_deref(), Some("file=test&meta=m"));

    let login = find(&out.targets, "POST", "/v2/login");
    assert!(!login.multipart);
    assert_eq!(login.data.as_deref(), Some("user=test"));
}

#[test]
fn billion_laughs_yaml_fails_fast() {
    let mut y = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
    for i in 1..12 {
        let p = i - 1;
        y.push_str(&format!(
            "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
        ));
    }
    y.push_str("openapi: 3.0.0\npaths: {}\n");
    let err = parse_openapi(&y, None).unwrap_err().to_string();
    assert!(err.contains("invalid spec YAML"), "{err}");
}

#[test]
fn non_spec_documents_are_rejected() {
    assert!(parse_openapi(r##"{"log":{"entries":[]}}"##, None).is_err());
    assert!(parse_openapi("not: [valid", None).is_err());
    assert!(parse_openapi(r##"{"openapi":"3.0.0"}"##, None).is_err());
}
