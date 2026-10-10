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
fn form_body_example_given_encoded_keeps_its_fields() {
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{"/f":{"post":{
      "requestBody":{"content":{"application/x-www-form-urlencoded":{"example":"user=a+b&q=%3Cx"}}}}}}}"##;
    let t = &parse(spec).targets[0];
    assert_eq!(t.data.as_deref(), Some("q=%3Cx&user=a+b"));
    assert_eq!(
        header(t, "Content-Type"),
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
fn repeated_path_placeholders_expand_in_linear_time() {
    // 200k `{a}` placeholders next to 1000 declared parameters used to scan
    // every parameter per placeholder (~20 s here in a debug build).
    let params: Vec<Value> = (0..1000)
        .map(|i| serde_json::json!({"name": format!("p{i}"), "in": "query", "example": "1"}))
        .chain([serde_json::json!({"name": "a", "in": "path", "example": "z"})])
        .collect();
    let mut paths = serde_json::Map::new();
    paths.insert(
        format!("/{}", "{a}".repeat(200_000)),
        serde_json::json!({"parameters": params, "get": {}}),
    );
    let spec =
        serde_json::json!({"openapi": "3.0.0", "servers": [{"url": "https://h"}], "paths": paths});
    let start = std::time::Instant::now();
    let t = &parse(&spec.to_string()).targets[0];
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(t.url.path(), format!("/{}", "z".repeat(200_000)));
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
fn base_url_is_origin_plus_path_prefix_for_every_server_shape() {
    // One rule: --base-url gives scheme/host/port and a path prefix; the
    // server's path (or Swagger basePath) is appended; its origin is dropped.
    let base = Url::parse("http://127.0.0.1:9000/x/").unwrap();
    let url_for = |servers: &str| {
        let spec = format!(r#"{{"openapi":"3.0.0",{servers}"paths":{{"/u":{{"get":{{}}}}}}}}"#);
        parse_openapi(&spec, Some(&base)).unwrap().targets[0]
            .url
            .to_string()
    };
    let cases = [
        // absolute: its path is kept under the prefix
        (
            r#""servers":[{"url":"https://prod.example.com/api"}],"#,
            "http://127.0.0.1:9000/x/api/u",
        ),
        // relative
        (
            r#""servers":[{"url":"/api/v3"}],"#,
            "http://127.0.0.1:9000/x/api/v3/u",
        ),
        (
            r#""servers":[{"url":"api/v3"}],"#,
            "http://127.0.0.1:9000/x/api/v3/u",
        ),
        // scheme-relative and backslash network paths can't change the host
        (
            r#""servers":[{"url":"//prod.example.com/v1"}],"#,
            "http://127.0.0.1:9000/x/v1/u",
        ),
        (
            r#""servers":[{"url":"\\\\prod.example.com\\v1"}],"#,
            "http://127.0.0.1:9000/x/v1/u",
        ),
        // an undeclared variable in the discarded origin doesn't matter
        (
            r#""servers":[{"url":"https://{tenant}.example.com/v2"}],"#,
            "http://127.0.0.1:9000/x/v2/u",
        ),
        // no servers at all
        ("", "http://127.0.0.1:9000/x/u"),
    ];
    for (servers, want) in cases {
        assert_eq!(url_for(servers), want, "{servers}");
    }

    let swagger = r#"{"swagger":"2.0","host":"prod.example.com","basePath":"/v2",
                      "paths":{"/u":{"get":{}}}}"#;
    let t = &parse_openapi(swagger, Some(&base)).unwrap().targets[0];
    assert_eq!(t.url.as_str(), "http://127.0.0.1:9000/x/v2/u");

    // Without --base-url a relative / scheme-relative / missing server, or an
    // undeclared variable, can't be aimed anywhere.
    for servers in [
        r#""servers":[{"url":"/api/v3"}],"#,
        r#""servers":[{"url":"//prod.example.com/v1"}],"#,
        r#""servers":[{"url":"https://{tenant}.example.com"}],"#,
        "",
    ] {
        let spec = format!(r#"{{"openapi":"3.0.0",{servers}"paths":{{"/u":{{"get":{{}}}}}}}}"#);
        let err = parse_openapi(&spec, None).unwrap_err().to_string();
        assert!(err.contains("--base-url"), "{servers}: {err}");
    }
}

#[test]
fn numeric_versions_and_reused_anchors_parse() {
    // Unquoted YAML versions are numbers.
    let y = "swagger: 2.0\nhost: h\npaths:\n  /a:\n    get: {}\n";
    assert_eq!(parse(y).targets.len(), 1);
    let y = "openapi: 3.0\nservers: [{url: 'https://h'}]\npaths:\n  /a:\n    get: {}\n";
    assert_eq!(parse(y).targets.len(), 1);

    // One anchor reused 150 times (a shared error response) is legitimate.
    let mut y = String::from(
        "openapi: 3.0.0\nservers: [{url: 'https://h'}]\nx-err: &err {description: e}\npaths:\n",
    );
    for i in 0..150 {
        y.push_str(&format!(
            "  /p{i}:\n    get:\n      responses:\n        '500': *err\n"
        ));
    }
    assert_eq!(parse(&y).targets.len(), 150);
}

#[test]
fn numeric_server_variable_default_is_substituted() {
    // An unquoted YAML `default: 8443` is a number, not a string.
    let y = "openapi: 3.0.0\nservers:\n  - url: 'https://h:{port}/v{major}'\n    variables:\n      port: {default: 8443}\n      major: {enum: [2, 1]}\npaths:\n  /a:\n    get: {}\n";
    assert_eq!(parse(y).targets[0].url.as_str(), "https://h:8443/v2/a");
}

#[test]
fn delete_head_options_are_counted_not_scanned() {
    let spec = r#"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{
        "/a":{"get":{},"post":{},"put":{},"patch":{},"delete":{},"head":{},"options":{}}
    }}"#;
    let out = parse(spec);
    let mut methods: Vec<&str> = out.targets.iter().map(|t| t.method.as_str()).collect();
    methods.sort();
    assert_eq!(methods, vec!["GET", "PATCH", "POST", "PUT"]);
    assert_eq!(out.unscanned_methods, 3);
    assert!(out.skipped.is_empty());

    let only_delete = r#"{"openapi":"3.0.0","servers":[{"url":"https://h"}],
        "paths":{"/a":{"delete":{}}}}"#;
    let err = parse_openapi(only_delete, None).unwrap_err().to_string();
    assert!(err.contains("1 DELETE/HEAD/OPTIONS"), "{err}");
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
fn shared_path_item_with_many_params_expands_in_linear_time() {
    // One path item with 1000 parameters, `$ref`'d by 100 paths: the
    // (name, in) override merge used to be quadratic per operation (~18 s
    // here in a debug build).
    let params: Vec<Value> = (0..1000)
        .map(|i| serde_json::json!({"name": format!("p{i}"), "in": "query", "example": "1"}))
        .collect();
    let paths: serde_json::Map<String, Value> = (0..100)
        .map(|i| (format!("/a{i}"), serde_json::json!({"$ref": "#/x-item"})))
        .collect();
    let spec = serde_json::json!({
        "openapi": "3.0.0", "servers": [{"url": "https://h"}],
        "x-item": {"get": {}, "parameters": params},
        "paths": paths,
    });
    let start = std::time::Instant::now();
    let out = parse(&spec.to_string());
    assert_eq!(out.targets.len(), 100);
    assert!(start.elapsed() < std::time::Duration::from_secs(6));
}

#[test]
fn operation_params_override_path_item_params_by_name_and_location() {
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{"/x":{
      "parameters":[
        {"name":"a","in":"query","example":"path-level"},
        {"name":"a","in":"header","example":"kept"},
        {"name":"b","in":"query","example":"b"}
      ],
      "get":{"parameters":[{"name":"a","in":"query","example":"op-level"}]}}}}"##;
    let t = &parse(spec).targets[0];
    assert_eq!(t.url.query(), Some("b=b&a=op-level"));
    assert_eq!(header(t, "a"), Some("kept"));
}

#[test]
fn too_large_skips_charge_the_import_budget() {
    // A path item whose one operation expands past the request cap, shared by
    // `$ref` across 100 paths: every copy used to be rebuilt to 4 MiB and
    // skipped for free.
    let params: Vec<Value> = (0..100)
        .map(|i| {
            serde_json::json!({"name": format!("p{i}"), "in": "query",
            "schema": {"$ref": "#/components/schemas/Big"}})
        })
        .collect();
    let mut paths: serde_json::Map<String, Value> = (0..100)
        .map(|i| (format!("/a{i}"), serde_json::json!({"$ref": "#/x-item"})))
        .collect();
    paths.insert("/0ok".to_string(), serde_json::json!({"get": {}}));
    let spec = serde_json::json!({
        "openapi": "3.0.0", "servers": [{"url": "https://h"}],
        "x-item": {"get": {"parameters": params}},
        "paths": paths,
        "components": {"schemas": {"Big": {"type": "string", "example": "x".repeat(64 * 1024)}}}
    });
    let out = parse(&spec.to_string());
    // Fewer than the 100 shared operations: the budget stopped the import.
    assert!(out.skipped_total <= 70, "{} skipped", out.skipped_total);
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
fn swagger2_base_path_without_leading_slash_stays_off_the_host() {
    let spec = r#"{"swagger":"2.0","host":"api.example.com","basePath":"v1",
                   "paths":{"/a":{"get":{}}}}"#;
    assert_eq!(
        parse(spec).targets[0].url.as_str(),
        "https://api.example.com/v1/a"
    );
    let base = Url::parse("http://127.0.0.1:9000").unwrap();
    let t = &parse_openapi(spec, Some(&base)).unwrap().targets[0];
    assert_eq!(t.url.as_str(), "http://127.0.0.1:9000/v1/a");
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

#[test]
fn skip_reasons_are_capped_but_counted() {
    let mut paths = serde_json::Map::new();
    for i in 0..1000 {
        paths.insert(format!("/bad{i}"), serde_json::json!({"$ref": "#/nope"}));
    }
    paths.insert("/ok".into(), serde_json::json!({"get": {}}));
    let spec =
        serde_json::json!({"openapi": "3.0.0", "servers": [{"url": "https://h"}], "paths": paths});
    let out = parse(&spec.to_string());
    assert_eq!(out.skipped_total, 1000);
    assert!(!out.skipped.is_empty() && out.skipped.len() <= super::super::MAX_SKIP_REASONS);
}

#[test]
fn xml_array_body_has_one_root_element() {
    // An array example rendered one root element per item: not XML.
    let spec = r##"{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{"/x":{"post":
      {"requestBody":{"content":{"application/xml":{"schema":{"type":"array",
        "xml":{"name":"pets"},"items":{"type":"string"}},"example":["a","b"]}}}}}}}"##;
    let out = parse(spec);
    let data = out.targets[0].data.as_deref().unwrap();
    roxmltree::Document::parse(data).unwrap_or_else(|e| panic!("{data}: {e}"));
    assert_eq!(data, "<pets><item>a</item><item>b</item></pets>");
}

#[test]
fn dot_segment_path_examples_do_not_collapse_the_path() {
    // `..` / `.` are unreserved, so they survived encoding and URL parsing
    // folded them away: `/u/{id}/x` scanned `/x`.
    for dots in ["..", "."] {
        let spec = format!(
            r##"{{"openapi":"3.0.0","servers":[{{"url":"https://h/v1"}}],"paths":{{"/u/{{id}}/x":{{"get":
              {{"parameters":[{{"name":"id","in":"path","example":"{dots}"}}]}}}}}}}}"##
        );
        let out = parse(&spec);
        assert_eq!(out.targets[0].url.path(), "/v1/u/1/x", "example {dots:?}");
    }
}

#[test]
fn swagger2_host_with_a_scheme_keeps_the_real_host() {
    // `host` is a bare authority per spec, but a scheme there is a common
    // mistake: it was read as host `https`.
    let spec = r##"{"swagger":"2.0","host":"http://api.example.com:8080/","basePath":"/v1",
      "paths":{"/a":{"get":{}}}}"##;
    let out = parse(spec);
    assert_eq!(
        out.targets[0].url.as_str(),
        "http://api.example.com:8080/v1/a"
    );
}
