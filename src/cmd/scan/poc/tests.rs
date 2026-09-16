use super::*;
use crate::scanning::result::{FindingType, Result};

fn informational(inject_type: &str) -> Result {
    Result::builder(FindingType::Informational)
        .inject_type(inject_type)
        .data("https://example.com")
        .message_str("Outdated JavaScript library: jQuery 1.7.2")
        .evidence("jQuery 1.7.2 is known-vulnerable (CVE-2020-11023); upgrade to >= 3.5.0")
        .cwe("CWE-1104")
        .build()
}

#[test]
fn informational_block_plain_is_compact_and_colored() {
    let r = informational("OutdatedComponent");
    let out = render_finding_block(&r, "plain", false, false);
    // Tagged, payload-free summary line + evidence sub-line.
    assert!(out.contains("[INF][OutdatedComponent]"), "{out}");
    assert!(out.contains("https://example.com"));
    assert!(out.contains("jQuery 1.7.2"));
    assert!(out.contains("CVE-2020-11023"));
    // plain output is colorized (cyan).
    assert!(out.contains("\x1b[36m"));
    // No payload-oriented "[POC]" / "Payload:" tree for informational findings.
    assert!(!out.contains("[POC]"));
    assert!(!out.contains("Payload:"));
}

#[test]
fn informational_block_non_plain_summary_not_cyan() {
    let r = informational("OutdatedComponent");
    let out = render_finding_block(&r, "curl", false, false);
    assert!(out.contains("[INF][OutdatedComponent]"));
    // The summary line must not be cyan-wrapped for non-plain output (the tree
    // sub-lines follow the existing always-colored convention).
    assert!(
        !out.contains("\x1b[36m"),
        "non-plain summary must not be cyan-colored: {out:?}"
    );
}

#[test]
fn informational_block_defaults_tag_when_inject_type_empty() {
    let r = informational("");
    let out = render_finding_block(&r, "plain", false, false);
    assert!(out.contains("[INF][Informational]"), "{out}");
}

#[test]
fn poc_location_tag_header_cookie_is_case_insensitive() {
    assert_eq!(poc_location_tag("Header", "Cookie"), Some("cookie"));
    assert_eq!(poc_location_tag("Header", "cookie"), Some("cookie"));
    assert_eq!(poc_location_tag("Header", "COOKIE"), Some("cookie"));
}

#[test]
fn poc_location_tag_header_non_cookie() {
    assert_eq!(poc_location_tag("Header", "X-Foo"), Some("hdr"));
    assert_eq!(poc_location_tag("Header", "Authorization"), Some("hdr"));
}

#[test]
fn poc_location_tag_body_variants() {
    assert_eq!(poc_location_tag("Body", "q"), Some("body"));
    assert_eq!(poc_location_tag("JsonBody", "q"), Some("body"));
    assert_eq!(poc_location_tag("MultipartBody", "q"), Some("body"));
}

#[test]
fn poc_location_tag_path_and_fragment() {
    assert_eq!(poc_location_tag("Path", "seg"), Some("path"));
    assert_eq!(poc_location_tag("Fragment", "f"), Some("frag"));
}

#[test]
fn poc_location_tag_query_and_empty_return_none() {
    assert_eq!(poc_location_tag("", "q"), None);
    assert_eq!(poc_location_tag("Query", "q"), None);
}

#[test]
fn poc_location_tag_unknown_returns_none() {
    assert_eq!(poc_location_tag("UnknownLocation", "q"), None);
}

#[test]
fn poc_location_in_url_true_for_query_path_fragment() {
    assert!(poc_location_in_url(""));
    assert!(poc_location_in_url("Query"));
    assert!(poc_location_in_url("Path"));
    assert!(poc_location_in_url("Fragment"));
}

#[test]
fn poc_location_in_url_false_for_side_channel_locations() {
    assert!(!poc_location_in_url("Header"));
    assert!(!poc_location_in_url("Cookie"));
    assert!(!poc_location_in_url("Body"));
    assert!(!poc_location_in_url("JsonBody"));
    assert!(!poc_location_in_url("MultipartBody"));
}

#[test]
fn poc_location_tag_graphql_and_xml() {
    assert_eq!(
        poc_location_tag("GraphqlBody", "variables.n"),
        Some("graphql")
    );
    assert_eq!(poc_location_tag("XmlBody", "msg"), Some("xml"));
}

#[test]
fn poc_location_in_url_false_for_graphql_and_xml() {
    // Structured bodies are side-channel deliveries — never synthesize a
    // `?param=payload` query for them.
    assert!(!poc_location_in_url("GraphqlBody"));
    assert!(!poc_location_in_url("XmlBody"));
}

#[test]
fn request_ct_and_body_splits_headers_from_body() {
    let req = "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"a\":\"b\"}";
    let (ct, body) = request_content_type_and_body(Some(req)).expect("has body");
    assert_eq!(ct, "application/json");
    assert_eq!(body, "{\"a\":\"b\"}");
}

#[test]
fn request_ct_and_body_none_when_no_body_section() {
    // A request with no blank-line separator yields no body.
    assert!(request_content_type_and_body(Some("GET / HTTP/1.1\r\nHost: x")).is_none());
    assert!(request_content_type_and_body(None).is_none());
}

#[test]
fn graphql_curl_poc_reproduces_full_recorded_body() {
    let req = "POST /graphql HTTP/1.1\r\nHost: h:8899\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{\"query\":\"mutation($n:String){a(n:$n)}\",\"variables\":{\"n\":\"<svg onload=alert(1)>\"}}";
    let r = Result::builder(FindingType::Verified)
        .inject_type("inHTML")
        .method("POST")
        .data("http://h:8899/graphql")
        .param("variables.n")
        .payload("<svg onload=alert(1)>")
        .message_str("x")
        .build();
    let mut r = r;
    r.location = "GraphqlBody".to_string();
    r.request = Some(req.to_string());
    let out = render_curl_poc(&r, "http://h:8899/graphql");
    assert!(out.contains("-H 'Content-Type: application/json'"), "{out}");
    // The full structured body (query + the injected variable) is present,
    // not a lossy `{"variables.n":"payload"}` fragment.
    assert!(out.contains("mutation($n:String)"), "{out}");
    assert!(
        out.contains("\"variables\":{\"n\":\"<svg onload=alert(1)>\"}"),
        "{out}"
    );
}

#[test]
fn multipart_curl_poc_uses_form_string_not_urlencoded() {
    // A multipart finding must reproduce as a multipart request. `--data`
    // would send `application/x-www-form-urlencoded` — the wrong wire format —
    // and `-F` would treat the leading `<` as "read from file". `--form-string`
    // sends the literal value as a real multipart field.
    let r = Result::builder(FindingType::Verified)
        .inject_type("inHTML")
        .method("POST")
        .param("q")
        .payload("<svg onload=alert(1)>")
        .message_str("x")
        .build();
    let mut r = r;
    r.location = "MultipartBody".to_string();
    let out = render_curl_poc(&r, "http://h:8899/m");
    assert!(
        out.contains("--form-string 'q=<svg onload=alert(1)>'"),
        "{out}"
    );
    assert!(
        !out.contains("--data"),
        "must not fall back to urlencoded: {out}"
    );
    assert!(
        !out.contains("-F \""),
        "must not use -F (leading `<` = read-from-file): {out}"
    );
}

#[test]
fn multipart_httpie_poc_forces_multipart() {
    // httpie's `-f`/`--form` sends urlencoded unless a file field is present;
    // `--multipart` forces the multipart/form-data request needed to reproduce.
    let r = Result::builder(FindingType::Verified)
        .inject_type("inHTML")
        .method("POST")
        .param("q")
        .payload("<svg onload=alert(1)>")
        .message_str("x")
        .build();
    let mut r = r;
    r.location = "MultipartBody".to_string();
    let out = render_httpie_poc(&r, "http://h:8899/m");
    assert!(out.contains("http --multipart 'post'"), "{out}");
    assert!(
        !out.contains("http -f "),
        "must not use urlencoded form mode: {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Shell quoting — parameter names are target-derived and unfiltered
// ─────────────────────────────────────────────────────────────────────────

/// Parameter names reach the POC renderers straight from the target page:
/// `discovery::form` takes whatever `name=` attribute the HTML carries and
/// `mining::probe_response_id` takes `id=` attributes, neither applying a
/// character filter. These are the shapes that used to escape the old
/// double-quoted commands.
const HOSTILE_PARAMS: &[&str] = &[
    "a\";echo INJECTED;\"b",
    "c$(id -un)d",
    "e`id`f",
    "g'h",
    "i\nj",
    "k;l",
    "m$IFS$9n",
    "o\\p",
];

fn hostile_result(location: &str, param: &str) -> Result {
    let mut r = Result::builder(FindingType::Verified)
        .inject_type("inHTML")
        .method("POST")
        .data("http://h:8899/x")
        .param(param)
        .payload("<svg onload=alert(1)>")
        .message_str("x")
        .build();
    r.location = location.to_string();
    r
}

#[test]
fn shell_single_quote_wraps_and_escapes_only_single_quotes() {
    assert_eq!(shell_single_quote("abc"), "'abc'");
    // `"`, `$`, backtick and `\` are literal inside single quotes — they must
    // survive untouched or the POC stops reproducing the finding.
    assert_eq!(shell_single_quote("a\"$`\\b"), "'a\"$`\\b'");
    // The one character that needs care: close, escape, reopen.
    assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    assert_eq!(shell_single_quote(""), "''");
}

/// Split a rendered POC the way a shell would, by handing it to `sh` as the
/// argument list of `printf`. This is the property that matters: whatever the
/// target named its parameter, the command must tokenize into the argv we
/// intended and must not run anything extra.
#[cfg(unix)]
fn shell_argv(command: &str) -> Vec<String> {
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        // NUL-separated: a parameter name containing a newline is still one
        // shell word, and `%s\n` would report it as two.
        .arg(format!("printf '%s\\0' {}", command.trim_end()))
        .output()
        .expect("spawn /bin/sh");
    assert!(
        out.status.success(),
        "shell rejected the POC command: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut argv: Vec<String> = stdout.split('\0').map(str::to_string).collect();
    argv.pop(); // trailing separator
    argv
}

#[cfg(unix)]
#[test]
fn curl_poc_tokenizes_exactly_despite_hostile_param_names() {
    for param in HOSTILE_PARAMS {
        for (location, flag) in [
            ("Body", "--data"),
            ("MultipartBody", "--form-string"),
            ("Header", "-H"),
        ] {
            let r = hostile_result(location, param);
            let rendered = render_curl_poc(&r, "http://h:8899/x");
            let argv = shell_argv(&rendered);
            let sep = if location == "Header" { ": " } else { "=" };
            assert_eq!(
                argv,
                vec![
                    "curl".to_string(),
                    "-X".to_string(),
                    "POST".to_string(),
                    flag.to_string(),
                    format!("{}{}{}", param, sep, r.payload),
                    "http://h:8899/x".to_string(),
                ],
                "param {param:?} at {location} rendered as {rendered:?}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn httpie_poc_tokenizes_exactly_despite_hostile_param_names() {
    for param in HOSTILE_PARAMS {
        let r = hostile_result("Body", param);
        let rendered = render_httpie_poc(&r, "http://h:8899/x");
        assert_eq!(
            shell_argv(&rendered),
            vec![
                "http".to_string(),
                "-f".to_string(),
                "post".to_string(),
                "http://h:8899/x".to_string(),
                // httpie's own item grammar needs its separators escaped
                // inside the field name; the shell still delivers one word.
                format!("{}={}", httpie_escape_name(param), r.payload),
            ],
            "param {param:?} rendered as {rendered:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn curl_poc_does_not_run_an_injected_command() {
    // The concrete reproduction: `<input name='a";echo INJECTED;"b'>`. Under
    // the old double-quoted renderer, pasting the POC ran `echo INJECTED`.
    let r = hostile_result("Body", "a\";echo INJECTED;\"b");
    let rendered = render_curl_poc(&r, "http://h:8899/x");
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        // Neutralize the program name so nothing leaves the machine; any
        // *extra* command the quoting failed to contain still executes.
        .arg(rendered.replacen("curl", ":", 1))
        .output()
        .expect("spawn /bin/sh");
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "POC executed injected shell: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn json_body_poc_is_valid_json_for_hostile_param_and_payload() {
    let mut r = hostile_result("JsonBody", "a\"b\\c");
    r.payload = "\"</script><svg onload=alert(1)>".to_string();
    let rendered = render_curl_poc(&r, "http://h:8899/x");
    // Pull the single-quoted body back out and parse it.
    let body = rendered
        .split("--data '")
        .nth(1)
        .and_then(|rest| rest.split("' '").next())
        .expect("json body present");
    let parsed: serde_json::Value = serde_json::from_str(body).expect("body must be valid JSON");
    assert_eq!(parsed[&r.param], serde_json::Value::String(r.payload));
}

#[test]
fn synthesized_query_percent_encodes_the_param_name() {
    // A mined name carrying `&` or `#` used to splice extra query structure
    // (or a fragment) into the POC URL.
    let mut r = hostile_result("Query", "a&b=c#d");
    r.location = String::new();
    r.data = "http://h:8899/x".to_string();
    let poc = generate_poc(&r, "plain");
    assert!(poc.contains("?a%26b%3Dc%23d="), "{poc}");
    assert!(!poc.contains("?a&b=c#d"), "{poc}");
}

#[test]
fn httpie_escape_name_escapes_request_item_separators() {
    // httpie splits each item on the first unescaped separator, so a mined
    // name carrying one has to be escaped or httpie rejects the whole item
    // ("Invalid item") and the POC reproduces nothing.
    assert_eq!(httpie_escape_name("x=y:z@w;v"), "x\\=y\\:z\\@w\\;v");
    assert_eq!(httpie_escape_name("a\\b"), "a\\\\b");
    // Ordinary names are untouched.
    assert_eq!(httpie_escape_name("q"), "q");
    assert_eq!(httpie_escape_name("user_id"), "user_id");
}
