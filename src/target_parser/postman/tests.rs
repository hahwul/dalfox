use super::*;

const COLLECTION: &str = r##"{
  "info": {
    "name": "demo",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {"key": "baseUrl", "value": "https://api.example.com"},
    {"key": "ver", "value": "{{major}}"},
    {"key": "major", "value": "v1"},
    {"key": "off", "value": "x", "disabled": true}
  ],
  "item": [
    {
      "name": "users",
      "item": [
        {
          "name": "get user",
          "request": {
            "method": "get",
            "header": [
              {"key": "X-Api", "value": "{{ver}}"},
              {"key": "Cookie", "value": "sid=abc; theme=dark"},
              {"key": "X-Off", "value": "1", "disabled": true},
              {"key": "X-Bad", "value": "a\r\nInjected: 1"}
            ],
            "url": {
              "raw": "{{baseUrl}}/{{ver}}/users/:id?q={{$guid}}",
              "variable": [{"key": "id", "value": "7"}]
            }
          }
        },
        {
          "name": "create user",
          "request": {
            "method": "POST",
            "body": {"mode": "raw", "raw": "{\"name\":\"{{who}}\"}", "options": {"raw": {"language": "json"}}},
            "url": {"raw": "{{baseUrl}}/users"}
          }
        }
      ]
    },
    {
      "name": "login",
      "request": {
        "method": "POST",
        "body": {"mode": "urlencoded", "urlencoded": [
          {"key": "user", "value": "a b"},
          {"key": "skip", "value": "1", "disabled": true}
        ]},
        "url": "{{baseUrl}}/login"
      }
    },
    {
      "name": "upload",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "multipart/form-data; boundary=X"}],
        "body": {"mode": "formdata", "formdata": [
          {"key": "note", "value": "hi", "type": "text"},
          {"key": "file", "type": "file", "src": "/etc/passwd"}
        ]},
        "url": "{{baseUrl}}/upload"
      }
    },
    {
      "name": "graphql",
      "request": {
        "method": "POST",
        "body": {"mode": "graphql", "graphql": {"query": "query($q:String){s(q:$q)}", "variables": "{\"q\":\"x\"}"}},
        "url": "{{baseUrl}}/graphql"
      }
    },
    {
      "name": "xml",
      "request": {
        "method": "POST",
        "body": {"mode": "raw", "raw": "<a>1</a>", "options": {"raw": {"language": "xml"}}},
        "url": "{{baseUrl}}/soap"
      }
    },
    {"name": "bare", "request": "http://127.0.0.1:8080/plain?a=1"},
    {"name": "env host", "request": {"method": "GET", "url": {"raw": "{{envHost}}/admin"}}}
  ]
}"##;

fn find<'a>(out: &'a SpecImport, path: &str) -> &'a Target {
    out.targets
        .iter()
        .find(|t| t.url.path() == path)
        .unwrap_or_else(|| panic!("no {path} in {:#?}", out.targets))
}

fn ct(t: &Target) -> Option<&str> {
    t.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
}

#[test]
fn collection_expands_nested_folders_with_variables() {
    let out = parse_postman(COLLECTION, None).expect("collection parses");
    assert_eq!(out.targets.len(), 7, "{:?}", out.skipped);

    // Nested `{{ver}}` → `{{major}}` → v1, path variable :id, dynamic
    // variable → placeholder, disabled + unsendable headers dropped, Cookie
    // split into pairs.
    let get = find(&out, "/v1/users/7");
    assert_eq!(get.method, "GET");
    assert_eq!(get.url.as_str(), "https://api.example.com/v1/users/7?q=1");
    assert_eq!(get.headers, vec![("X-Api".to_string(), "v1".to_string())]);
    assert_eq!(
        get.cookies,
        vec![
            ("sid".to_string(), "abc".to_string()),
            ("theme".to_string(), "dark".to_string())
        ]
    );
}

#[test]
fn every_body_mode_becomes_a_rebuildable_body() {
    let out = parse_postman(COLLECTION, None).unwrap();

    let json = find(&out, "/users");
    assert_eq!(json.data.as_deref(), Some(r#"{"name":"1"}"#));
    assert_eq!(ct(json), Some("application/json"));

    let form = find(&out, "/login");
    assert_eq!(form.data.as_deref(), Some("user=a+b"));
    assert_eq!(ct(form), Some("application/x-www-form-urlencoded"));

    // form-data: urlencoded `data` + multipart flag; the captured boundary
    // header is dropped and the file part's local path never read.
    let up = find(&out, "/upload");
    assert!(up.multipart);
    assert_eq!(up.data.as_deref(), Some("note=hi&file=test"));
    assert_eq!(ct(up), None);

    let gql = find(&out, "/graphql");
    let body: serde_json::Value = serde_json::from_str(gql.data.as_deref().unwrap()).unwrap();
    assert_eq!(body["query"], "query($q:String){s(q:$q)}");
    assert_eq!(body["variables"]["q"], "x");
    assert_eq!(ct(gql), Some("application/json"));

    let xml = find(&out, "/soap");
    assert_eq!(xml.data.as_deref(), Some("<a>1</a>"));
    assert_eq!(ct(xml), Some("application/xml"));

    let bare = find(&out, "/plain");
    assert_eq!(bare.url.as_str(), "http://127.0.0.1:8080/plain?a=1");
}

#[test]
fn unresolved_host_variable_is_skipped_with_a_reason() {
    let out = parse_postman(COLLECTION, None).unwrap();
    assert_eq!(out.skipped.len(), 1);
    assert!(out.skipped[0].starts_with("env host:"), "{:?}", out.skipped);
    assert!(out.skipped[0].contains("{{envHost}}"), "{:?}", out.skipped);
    assert!(out.skipped[0].contains("--base-url"), "{:?}", out.skipped);
    assert!(!out.targets.iter().any(|t| t.url.path() == "/admin"));

    // Nothing resolvable at all → an error, not an empty scan.
    let only_env = r#"{"item":[{"name":"a","request":{"url":"{{host}}/x"}}]}"#;
    assert!(parse_postman(only_env, None).is_err());
}

#[test]
fn base_url_replaces_every_origin() {
    let base = Url::parse("http://127.0.0.1:9000/staging").unwrap();
    let out = parse_postman(COLLECTION, Some(&base)).unwrap();
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    for t in &out.targets {
        assert_eq!(t.url.host_str(), Some("127.0.0.1"), "{}", t.url);
        assert!(t.url.path().starts_with("/staging/"), "{}", t.url);
    }
    // The env-hosted request is rescued too.
    assert!(out.targets.iter().any(|t| t.url.path() == "/staging/admin"));
}

#[test]
fn variable_cycles_and_amplification_are_bounded() {
    let cyc = r#"{"variable":[{"key":"a","value":"{{b}}"},{"key":"b","value":"{{a}}"}],
        "item":[{"name":"c","request":{"url":"https://h/{{a}}"}}]}"#;
    let out = parse_postman(cyc, None).unwrap();
    assert_eq!(out.targets[0].url.host_str(), Some("h"));

    // 1 KiB value referenced 2,000 times in one URL: > 1 MiB expanded.
    let refs = "{{big}}".repeat(2000);
    let amp = serde_json::json!({
        "variable": [{"key": "big", "value": "x".repeat(1024)}],
        "item": [
            {"name": "amp", "request": {"url": format!("https://h/{refs}")}},
            {"name": "ok", "request": {"url": "https://h/ok"}}
        ]
    });
    let out = parse_postman(&amp.to_string(), None).unwrap();
    assert_eq!(out.targets.len(), 1);
    assert!(out.skipped[0].contains("1 MiB"), "{:?}", out.skipped);
}

#[test]
fn non_http_and_bad_method_requests_are_skipped() {
    let c = r#"{"item":[
        {"name":"ws","request":{"url":"ws://h/socket"}},
        {"name":"m","request":{"method":"GE T","url":"https://h/a"}},
        {"name":"ok","request":{"method":"PURGE","url":"https://h/b"}}
    ]}"#;
    let out = parse_postman(c, None).unwrap();
    assert_eq!(out.targets.len(), 1);
    assert_eq!(out.targets[0].method, "PURGE");
    assert_eq!(out.skipped.len(), 2, "{:?}", out.skipped);
}

#[test]
fn scheme_is_only_read_before_the_path_and_delete_is_not_scanned() {
    let c = r#"{"item":[
        {"name":"cb","request":{"url":"api.example.com/cb?next=https://other.example/x"}},
        {"name":"del","request":{"method":"DELETE","url":"https://h/a"}},
        {"name":"big","request":{"method":"POST","url":"https://h/b",
            "body":{"mode":"raw","raw":"BIG"}}}
    ]}"#
    .replace("BIG", &"x".repeat(5 << 20));
    let out = parse_postman(&c, None).unwrap();
    assert_eq!(out.targets.len(), 1);
    assert_eq!(out.targets[0].url.host_str(), Some("api.example.com"));
    assert_eq!(out.targets[0].url.scheme(), "http");
    assert_eq!(out.unscanned_methods, 1);
    // A raw body counts toward the per-request cap too.
    assert!(out.skipped[0].starts_with("big:"), "{:?}", out.skipped);
}

#[test]
fn non_collection_is_rejected() {
    assert!(parse_postman(r#"{"openapi":"3.0.0"}"#, None).is_err());
    assert!(parse_postman("openapi: 3.0.0", None).is_err());
}

#[test]
fn deep_folder_labels_stay_bounded_in_skip_reasons() {
    // 60 nested folders with 64-char names: the full path label is ~4 KiB,
    // and copying it into every skipped child's reason turned a small
    // collection into hundreds of MiB of skip strings.
    let mut c = String::new();
    for _ in 0..60 {
        c.push_str(&format!(r#"{{"name":"{}","item":["#, "f".repeat(64)));
    }
    c.push_str(&vec![r#"{"request":1}"#; 100].join(","));
    c.push_str(&"]}".repeat(60));
    let doc = format!(r#"{{"item":[{c},{{"name":"ok","request":"https://h/ok"}}]}}"#);
    let out = parse_postman(&doc, None).expect("parses");
    assert_eq!(out.skipped.len(), 100);
    assert!(
        out.skipped.iter().all(|s| s.len() <= 512),
        "skip reason of {} bytes",
        out.skipped[0].len()
    );
}

#[test]
fn empty_host_variable_is_skipped_not_read_from_the_path() {
    // A collection variable exported with an empty value (the environment
    // was meant to fill it) must not turn the first path segment into the
    // host: `http:///users/list` parses as host `users`.
    let c = r#"{"variable":[{"key":"baseUrl","value":""}],"item":[
        {"name":"e","request":{"url":{"raw":"{{baseUrl}}/users/list"}}},
        {"name":"ok","request":"https://h/ok"}
    ]}"#;
    let out = parse_postman(c, None).unwrap();
    assert_eq!(out.targets.len(), 1, "{:?}", out.targets);
    assert!(out.skipped[0].contains("--base-url"), "{:?}", out.skipped);
    // --base-url still rescues it.
    let base = Url::parse("https://staging.example").unwrap();
    let out = parse_postman(c, Some(&base)).unwrap();
    assert!(
        out.targets
            .iter()
            .any(|t| t.url.as_str() == "https://staging.example/users/list")
    );
}

#[test]
fn url_object_without_raw_is_built_from_its_parts() {
    // `raw` is optional in the v2.1 schema; Postman's runtime builds the
    // URL from the parts, leaving disabled query entries off.
    let c = r#"{"variable":[{"key":"h","value":"api"}],"item":[{"name":"p","request":{"url":{
        "protocol":"https","host":["{{h}}","example","com"],"port":"8443",
        "path":["v1",{"type":"string","value":"users"},":id"],
        "variable":[{"key":"id","value":"7"}],
        "query":[{"key":"q","value":"a b"},{"key":"off","value":"1","disabled":true},{"key":"flag","value":null}]
    }}}]}"#;
    let out = parse_postman(c, None).unwrap();
    assert_eq!(
        out.targets[0].url.as_str(),
        "https://api.example.com:8443/v1/users/7?q=a%20b&flag"
    );
}
