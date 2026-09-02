use super::*;
use crate::target_parser::parse_target;

#[test]
fn test_compose_cookie_header_empty() {
    let cookies: Vec<(String, String)> = vec![];
    assert!(compose_cookie_header(&cookies).is_none());
}

#[test]
fn test_compose_cookie_header_basic() {
    let cookies = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
    ];
    let s = compose_cookie_header(&cookies).unwrap();
    assert!(s == "a=1; b=2" || s == "b=2; a=1"); // order not guaranteed by this helper
}

#[test]
fn test_compose_cookie_header_excluding() {
    let cookies = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
    ];
    let s = compose_cookie_header_excluding(&cookies, Some("a")).unwrap();
    assert_eq!(s, "b=2");
    assert!(compose_cookie_header_excluding(&cookies, Some("a_non")).is_some());
}

#[test]
fn test_compose_cookie_header_excluding_to_none() {
    let cookies = vec![("only".to_string(), "1".to_string())];
    let s = compose_cookie_header_excluding(&cookies, Some("only"));
    assert!(s.is_none());
}

#[test]
fn test_has_header_case_insensitive() {
    let headers = vec![
        ("X-Test".to_string(), "v".to_string()),
        ("content-type".to_string(), "x".to_string()),
    ];
    assert!(has_header(&headers, "Content-Type"));
    assert!(has_header(&headers, "content-type"));
    assert!(!has_header(&headers, "missing"));
}

#[test]
fn test_parse_header_line_trims_and_splits_once() {
    let parsed = parse_header_line("X-Test: value:with:colons").expect("valid header");
    assert_eq!(parsed.0, "X-Test");
    assert_eq!(parsed.1, "value:with:colons");
}

#[test]
fn test_parse_header_line_invalid_cases() {
    assert!(parse_header_line("NoColon").is_none());
    assert!(parse_header_line(": value").is_none());
    assert!(parse_header_line("   : value").is_none());
}

#[test]
fn test_parse_headers_filters_invalid_entries() {
    let input = vec![
        "X-One: 1".to_string(),
        "BrokenHeader".to_string(),
        ": missing-name".to_string(),
        "X-Two: 2".to_string(),
    ];
    let parsed = parse_headers(&input);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0], ("X-One".to_string(), "1".to_string()));
    assert_eq!(parsed[1], ("X-Two".to_string(), "2".to_string()));
}

#[test]
fn test_content_type_primary_normalization() {
    assert_eq!(
        content_type_primary(" Text/HTML ; charset=UTF-8 "),
        Some("text/html".to_string())
    );
    assert_eq!(
        content_type_primary("application/xhtml+xml;charset=utf-8"),
        Some("application/xhtml+xml".to_string())
    );
}

#[test]
fn test_content_type_primary_invalid_inputs() {
    assert_eq!(content_type_primary(""), None);
    assert_eq!(content_type_primary("text"), None);
    assert_eq!(content_type_primary("/html"), None);
    assert_eq!(content_type_primary("text/"), None);
}

#[test]
fn test_is_htmlish_content_type_allow_list() {
    assert!(is_htmlish_content_type("text/html"));
    assert!(is_htmlish_content_type("application/xhtml+xml"));
    assert!(is_htmlish_content_type("application/xml; charset=utf-8"));
    assert!(is_htmlish_content_type("text/xml"));
    assert!(is_htmlish_content_type("application/rss+xml"));
    assert!(is_htmlish_content_type("application/atom+xml"));
}

#[test]
fn test_is_htmlish_content_type_deny_list() {
    assert!(!is_htmlish_content_type("application/json"));
    assert!(!is_htmlish_content_type("text/plain"));
    assert!(!is_htmlish_content_type("image/svg+xml"));
    assert!(!is_htmlish_content_type("invalid"));
}

#[test]
fn test_is_javascript_content_type() {
    // Executable-JavaScript bodies: run as script, never HTML-parsed.
    assert!(is_javascript_content_type("application/javascript"));
    assert!(is_javascript_content_type("text/javascript; charset=utf-8"));
    assert!(is_javascript_content_type("application/ecmascript"));
    assert!(is_javascript_content_type("text/ecmascript"));
    assert!(is_javascript_content_type("application/x-javascript"));
    // Not JS: HTML, structured data, and the sniffable grey-zone types that
    // browsers CAN render as HTML — these must stay eligible for HTML evidence.
    assert!(!is_javascript_content_type("text/html"));
    assert!(!is_javascript_content_type("application/json"));
    assert!(!is_javascript_content_type("text/plain"));
    assert!(!is_javascript_content_type("image/svg+xml"));
    assert!(!is_javascript_content_type(""));
}

#[test]
fn test_is_xss_scannable_content_type_allow_list() {
    assert!(is_xss_scannable_content_type("text/html"));
    assert!(is_xss_scannable_content_type("application/json"));
    assert!(is_xss_scannable_content_type("application/javascript"));
    assert!(is_xss_scannable_content_type(
        "text/javascript; charset=utf-8"
    ));
    assert!(is_xss_scannable_content_type("image/svg+xml"));
}

#[test]
fn test_is_xss_scannable_content_type_deny_list() {
    assert!(!is_xss_scannable_content_type("image/png"));
    assert!(!is_xss_scannable_content_type("application/octet-stream"));
    assert!(!is_xss_scannable_content_type("invalid"));
}

#[test]
fn test_content_type_is_inert_data_deny_renders_as_data() {
    // Structured data and binary types: a reflected payload is never parsed
    // as markup, so these are inert.
    assert!(content_type_is_inert_data("application/json"));
    assert!(content_type_is_inert_data(
        "application/json; charset=utf-8"
    ));
    assert!(content_type_is_inert_data("text/json"));
    assert!(content_type_is_inert_data("text/csv"));
    assert!(content_type_is_inert_data("application/octet-stream"));
    assert!(content_type_is_inert_data("application/vnd.api+json"));
    assert!(content_type_is_inert_data("application/problem+json"));
    assert!(content_type_is_inert_data("image/png"));
    assert!(content_type_is_inert_data("font/woff2"));
    assert!(content_type_is_inert_data("video/mp4"));
}

#[test]
fn test_content_type_is_inert_data_keeps_executable_and_sniffable() {
    // Markup, script, and sniffable/empty types stay scannable — treating
    // them as inert would drop real findings (JSONP, sniffed text/plain,
    // SVG inline scripts).
    assert!(!content_type_is_inert_data("text/html"));
    assert!(!content_type_is_inert_data("application/xhtml+xml"));
    assert!(!content_type_is_inert_data("image/svg+xml"));
    assert!(!content_type_is_inert_data("application/javascript"));
    assert!(!content_type_is_inert_data(
        "text/javascript; charset=utf-8"
    ));
    assert!(!content_type_is_inert_data("text/plain"));
    assert!(!content_type_is_inert_data(""));
    assert!(!content_type_is_inert_data("invalid"));
}

#[test]
fn test_is_xss_scannable_content_type_text_plain_allowed() {
    assert!(is_xss_scannable_content_type("text/plain"));
    assert!(is_xss_scannable_content_type("text/plain; charset=utf-8"));
}

#[test]
fn test_build_preflight_request_get_sets_range_and_headers() {
    let mut target = parse_target("https://example.com/path").unwrap();
    target.headers = vec![("X-Test".to_string(), "1".to_string())];
    target.user_agent = Some("Dalfox-Test-UA".to_string());
    target.cookies = vec![("sid".to_string(), "abc".to_string())];

    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_preflight_request(&client, &target, false, Some(128))
        .build()
        .expect("request should build");

    assert_eq!(req.method(), reqwest::Method::GET);
    assert_eq!(
        req.headers()
            .get("Range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "bytes=0-127"
    );
    assert_eq!(
        req.headers()
            .get("X-Test")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "1"
    );
    assert_eq!(
        req.headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "Dalfox-Test-UA"
    );
    assert!(
        req.headers().get("Cookie").is_some(),
        "cookies should be auto-attached"
    );
}

#[test]
fn test_build_preflight_request_head_ignores_range() {
    let target = parse_target("https://example.com/path").unwrap();
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_preflight_request(&client, &target, true, Some(128))
        .build()
        .expect("request should build");

    assert_eq!(req.method(), reqwest::Method::HEAD);
    assert!(
        req.headers().get("Range").is_none(),
        "HEAD preflight should not set Range header"
    );
}

#[test]
fn user_accept_encoding_header_is_dropped_to_keep_decompression() {
    // A user-supplied Accept-Encoding (-H or raw-request import) disables
    // reqwest's transparent decompression, so the body returns as raw gzip/br
    // bytes and every reflection/marker check silently fails. It must be dropped
    // while unrelated headers are preserved.
    let mut target = parse_target("https://example.com/path").unwrap();
    target.headers = vec![
        ("Accept-Encoding".to_string(), "gzip".to_string()),
        ("X-Keep".to_string(), "1".to_string()),
    ];
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_preflight_request(&client, &target, false, None)
        .build()
        .expect("request should build");
    assert!(
        req.headers().get("Accept-Encoding").is_none(),
        "user Accept-Encoding must be dropped so decompression stays on"
    );
    assert_eq!(
        req.headers().get("X-Keep").and_then(|v| v.to_str().ok()),
        Some("1"),
        "unrelated user headers must be preserved"
    );
}

// ---- retry policy (decide_retry / next_backoff_ms) ----

#[test]
fn backoff_is_exponential_and_capped() {
    // base 1000 => 1s, 2s, 4s, 8s, 16s, then clamp at 32s? no: cap is 30s.
    assert_eq!(next_backoff_ms(1000, 0), 1000);
    assert_eq!(next_backoff_ms(1000, 1), 2000);
    assert_eq!(next_backoff_ms(1000, 2), 4000);
    assert_eq!(next_backoff_ms(1000, 3), 8000);
    assert_eq!(next_backoff_ms(1000, 4), 16000);
    // 2^5 * 1000 = 32000 -> clamped to the 30s ceiling.
    assert_eq!(next_backoff_ms(1000, 5), BACKOFF_CAP_MS);
    // shift saturates at BACKOFF_SHIFT_CAP, then the cap holds.
    assert_eq!(next_backoff_ms(1000, 99), BACKOFF_CAP_MS);
    // base of 0 is floored to 1ms so a request still makes progress.
    assert_eq!(next_backoff_ms(0, 0), 1);
}

#[test]
fn retry_429_always_even_when_transient_disabled() {
    // --retries 0 (transient off) must still retry 429 up to MAX_429_RETRIES.
    let st = RetryState::default();
    let d = decide_retry(SendOutcome::Status(429), st, 0, 1000, None);
    assert_eq!(
        d,
        RetryDecision::Sleep {
            ms: 1000,
            rate_limited: true
        }
    );
}

#[test]
fn retry_429_honors_retry_after_capped() {
    let st = RetryState::default();
    // Retry-After 5s is used verbatim.
    let d = decide_retry(SendOutcome::Status(429), st, 0, 1000, Some(5000));
    assert_eq!(
        d,
        RetryDecision::Sleep {
            ms: 5000,
            rate_limited: true
        }
    );
    // A huge Retry-After is clamped to the ceiling.
    let d = decide_retry(SendOutcome::Status(429), st, 0, 1000, Some(10 * 60 * 1000));
    assert_eq!(
        d,
        RetryDecision::Sleep {
            ms: BACKOFF_CAP_MS,
            rate_limited: true
        }
    );
}

#[test]
fn retry_429_zero_retry_after_falls_back_to_backoff() {
    // A `Retry-After: 0` (or a past HTTP-date, which parses to 0) must NOT sleep
    // 0ms and re-send immediately — that turned each 429 into a back-to-back
    // retry burst. It should fall back to the exponential backoff for this
    // attempt instead.
    let st = RetryState::default();
    let d = decide_retry(SendOutcome::Status(429), st, 0, 1000, Some(0));
    assert_eq!(
        d,
        RetryDecision::Sleep {
            ms: next_backoff_ms(1000, 0),
            rate_limited: true
        }
    );
    // Still rate-limited semantics, and the backoff grows with prior 429s.
    let st = RetryState {
        rl_done: 2,
        tr_done: 0,
    };
    let d = decide_retry(SendOutcome::Status(429), st, 0, 1000, Some(0));
    assert_eq!(
        d,
        RetryDecision::Sleep {
            ms: next_backoff_ms(1000, 2),
            rate_limited: true
        }
    );
}

#[test]
fn retry_429_stops_after_budget() {
    let st = RetryState {
        rl_done: MAX_429_RETRIES,
        tr_done: 0,
    };
    assert_eq!(
        decide_retry(SendOutcome::Status(429), st, 0, 1000, None),
        RetryDecision::Stop
    );
}

#[test]
fn transient_retries_are_opt_in() {
    let st = RetryState::default();
    // Default budget 0 => 5xx and network errors are NOT retried.
    assert_eq!(
        decide_retry(SendOutcome::Status(503), st, 0, 1000, None),
        RetryDecision::Stop
    );
    assert_eq!(
        decide_retry(SendOutcome::TransientError, st, 0, 1000, None),
        RetryDecision::Stop
    );
    // With a budget of 2, both are retried with exponential backoff.
    assert_eq!(
        decide_retry(SendOutcome::Status(503), st, 2, 1000, None),
        RetryDecision::Sleep {
            ms: 1000,
            rate_limited: false
        }
    );
    assert_eq!(
        decide_retry(SendOutcome::TransientError, st, 2, 500, None),
        RetryDecision::Sleep {
            ms: 500,
            rate_limited: false
        }
    );
}

#[test]
fn transient_retries_respect_budget_and_advance_backoff() {
    // Second transient retry (tr_done=1) uses the next backoff step.
    let st = RetryState {
        rl_done: 0,
        tr_done: 1,
    };
    assert_eq!(
        decide_retry(SendOutcome::Status(500), st, 2, 1000, None),
        RetryDecision::Sleep {
            ms: 2000,
            rate_limited: false
        }
    );
    // Budget exhausted (tr_done == max) => stop.
    let st = RetryState {
        rl_done: 0,
        tr_done: 2,
    };
    assert_eq!(
        decide_retry(SendOutcome::Status(500), st, 2, 1000, None),
        RetryDecision::Stop
    );
}

#[test]
fn success_and_fatal_never_retry() {
    let st = RetryState::default();
    assert_eq!(
        decide_retry(SendOutcome::Status(200), st, 5, 1000, None),
        RetryDecision::Stop
    );
    // 4xx (other than 429) is a real answer, not a retryable failure.
    assert_eq!(
        decide_retry(SendOutcome::Status(404), st, 5, 1000, None),
        RetryDecision::Stop
    );
    assert_eq!(
        decide_retry(SendOutcome::FatalError, st, 5, 1000, None),
        RetryDecision::Stop
    );
}

#[test]
fn parse_retry_after_accepts_seconds_and_http_date() {
    use reqwest::header::HeaderMap;
    let with = |val: &str| {
        let mut h = HeaderMap::new();
        h.insert("retry-after", val.parse().unwrap());
        parse_retry_after_ms(&h)
    };
    // delta-seconds form (unchanged).
    assert_eq!(with("120"), Some(120_000));
    // HTTP-date form (IMF-fixdate) — previously ignored, falling back to a fast
    // exponential backoff and burning the 429 retry budget.
    let future = with("Wed, 21 Oct 2099 07:28:00 GMT").expect("future HTTP-date must parse");
    assert!(
        future > 0,
        "future date should yield a positive wait, got {future}"
    );
    // A past date means "retry now": 0ms, not None.
    assert_eq!(with("Wed, 21 Oct 1999 07:28:00 GMT"), Some(0));
    // Unparseable -> None so the caller falls back to exponential backoff.
    assert_eq!(with("not-a-date"), None);
}

#[test]
fn parse_http_date_retry_ms_handles_future_past_and_invalid_dates() {
    let future = parse_http_date_retry_ms("Wed, 21 Oct 2099 07:28:00 GMT")
        .expect("future HTTP-date must parse");
    assert!(future > 0, "future date should yield a positive wait");
    assert_eq!(
        parse_http_date_retry_ms("Wed, 21 Oct 1999 07:28:00 GMT"),
        Some(0)
    );
    assert_eq!(parse_http_date_retry_ms("not a date"), None);
}

#[test]
fn parse_http_date_retry_ms_ignores_weekday() {
    // 21 October 2099 is a Wednesday, but a weekday typo must not discard the
    // server's otherwise valid retry hint.
    assert!(parse_http_date_retry_ms("Mon, 21 Oct 2099 07:28:00 GMT").is_some_and(|ms| ms > 0));
    assert!(parse_http_date_retry_ms("21 Oct 2099 07:28:00 GMT").is_some_and(|ms| ms > 0));
}

/// Spawn a one-shot localhost server that replies with `body` and return its
/// URL. Used to exercise the real `reqwest::Response::chunk()` read path.
async fn serve_once(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await; // drain the request line/headers
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(header.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn test_read_body_capped_returns_small_body_whole() {
    crate::ensure_crypto_provider();
    let url = serve_once(b"hello world".to_vec()).await;
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    let body = read_body_capped(resp, 1024).await.unwrap();
    assert_eq!(body, "hello world");
}

#[tokio::test]
async fn test_read_body_capped_truncates_oversized_body() {
    crate::ensure_crypto_provider();
    // 20-byte body, 10-byte cap: exactly the first 10 bytes come back and the
    // rest of the stream is dropped (no unbounded buffering).
    let url = serve_once(b"0123456789ABCDEFGHIJ".to_vec()).await;
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    let body = read_body_capped(resp, 10).await.unwrap();
    assert_eq!(body, "0123456789");
}

#[test]
fn test_scraper_parse_error_collection_stays_disabled() {
    // Companion bound to MAX_RESPONSE_BODY_BYTES. The byte cap limits what we
    // READ; this limits what PARSING those bytes can cost.
    //
    // scraper's default features include `errors`, which makes every `Html`
    // retain one heap-allocated message per tokenizer parse error for the life
    // of the document. That vec grows with the number of MALFORMED characters
    // rather than with body size, so a body of `<` or NUL bytes costs one
    // allocation per byte: at our 16 MiB cap that measured ~16.7M allocations
    // and 1-2 GB of RSS from a 521 KB gzipped response. Nothing reads
    // `Html::errors`, so the feature is pure overhead — but a plain
    // `scraper = "0.27"` silently turns it back on, and the cost is invisible
    // until someone points a bomb at us. Pin it here.
    let manifest = include_str!("../../../Cargo.toml");
    let dep = manifest
        .lines()
        .find(|l| l.starts_with("scraper "))
        .expect("scraper dependency line in Cargo.toml");
    assert!(
        dep.contains("default-features = false"),
        "scraper must keep default-features off (its `errors` feature is an \
         unbounded per-parse-error allocation on hostile bodies); found: {dep}"
    );
}

#[tokio::test]
async fn test_read_body_capped_handles_utf8_split_at_cap() {
    crate::ensure_crypto_provider();
    // Body is "a" + 'é' (0x61, 0xC3, 0xA9). A 2-byte cap lands inside the
    // multi-byte codepoint; from_utf8_lossy must replace it instead of
    // panicking on a non-char-boundary slice.
    let url = serve_once(vec![0x61, 0xC3, 0xA9]).await;
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    let body = read_body_capped(resp, 2).await.unwrap();
    assert_eq!(body, "a\u{FFFD}");
}

#[test]
fn test_content_type_is_inert_data_with_nosniff_covers_text_plain() {
    // `text/plain` is excluded from the plain deny-list because a browser
    // sniffs it as HTML — but only when the server has *not* said not to.
    // With `nosniff` present the body can never be markup, so a reflection in
    // it is not exploitable. This is the FP the replay corpus caught: a
    // `text/plain; charset=utf-8` + `nosniff` response echoing a payload was
    // reported `[V]`.
    assert!(!content_type_is_inert_data("text/plain"));
    assert!(!content_type_is_inert_data_with_nosniff(
        "text/plain",
        false
    ));
    assert!(content_type_is_inert_data_with_nosniff("text/plain", true));
    assert!(content_type_is_inert_data_with_nosniff(
        "text/plain; charset=utf-8",
        true
    ));
}

#[test]
fn test_content_type_is_inert_data_with_nosniff_keeps_live_types_live() {
    // `nosniff` must not turn a genuinely executable or renderable type inert:
    // it constrains sniffing, not parsing. JSONP is the one that would hurt —
    // `application/javascript` executes via `<script src>` regardless.
    for ct in [
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "application/javascript",
        "text/javascript",
    ] {
        assert!(
            !content_type_is_inert_data_with_nosniff(ct, true),
            "{ct} must stay scannable even under nosniff"
        );
    }
    // An absent content-type stays live: `nosniff` does not stop a navigation
    // to a typeless response from being sniffed.
    assert!(!content_type_is_inert_data_with_nosniff("", true));
}

#[test]
fn test_content_type_is_inert_data_with_nosniff_is_superset() {
    // Whatever the plain version calls inert stays inert regardless of the
    // header, so the new gate can never *lose* a suppression.
    for ct in ["application/json", "text/csv", "image/png", "font/woff2"] {
        assert!(content_type_is_inert_data_with_nosniff(ct, false));
        assert!(content_type_is_inert_data_with_nosniff(ct, true));
    }
}

#[test]
fn test_headers_declare_nosniff() {
    use reqwest::header::{HeaderMap, HeaderValue};

    let mut headers = HeaderMap::new();
    assert!(!headers_declare_nosniff(&headers));

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    assert!(headers_declare_nosniff(&headers));

    // Servers do send mixed case and stray whitespace.
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("  NoSniff "),
    );
    assert!(headers_declare_nosniff(&headers));

    // Anything that is not the nosniff token does not count.
    let mut headers = HeaderMap::new();
    headers.insert("x-content-type-options", HeaderValue::from_static("sniff"));
    assert!(!headers_declare_nosniff(&headers));
}

// ---- build_body_request_base: captured Content-Type suppression ----

#[test]
fn build_body_request_base_drops_inherited_content_type() {
    // A body injector/probe sets the injected body's Content-Type itself, and
    // reqwest appends. A Content-Type inherited from an imported (raw-http/HAR)
    // target's headers must be dropped here so it can't survive as a duplicate
    // first value the server frames the body with. Every "build a new body in
    // format X" sender (the url_inject injectors and the discovery/mining body
    // probes) routes through this helper to avoid that class of drift.
    let mut target = parse_target("https://example.com/path").unwrap();
    target.headers = vec![
        (
            "Content-Type".to_string(),
            "multipart/form-data; boundary=----OLD".to_string(),
        ),
        ("X-Keep".to_string(), "1".to_string()),
    ];
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_body_request_base(
        &client,
        &target,
        reqwest::Method::POST,
        target.url.clone(),
        Some("a=b".to_string()),
    )
    .build()
    .expect("request should build");

    assert!(
        req.headers().get(reqwest::header::CONTENT_TYPE).is_none(),
        "the inherited Content-Type must be dropped so the caller's is the only one"
    );
    assert_eq!(
        req.headers().get("X-Keep").and_then(|v| v.to_str().ok()),
        Some("1"),
        "unrelated inherited headers must be preserved"
    );
}

#[test]
fn build_request_keeps_inherited_content_type() {
    // The plain builder (query/path/header injection re-sends the original body
    // verbatim) must NOT drop the captured Content-Type — only the body-format
    // senders do.
    let mut target = parse_target("https://example.com/path").unwrap();
    target.headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    crate::ensure_crypto_provider();
    let client = reqwest::Client::new();
    let req = build_request(
        &client,
        &target,
        reqwest::Method::POST,
        target.url.clone(),
        target.data.clone(),
    )
    .build()
    .expect("request should build");
    assert_eq!(
        req.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
}

#[tokio::test]
async fn send_counted_counts_a_request_that_never_answers() {
    // Scoped to the per-job task-local so the assertion is isolated from the
    // process-wide counter the rest of the suite shares.
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let c = counter.clone();
    crate::REQUEST_FAILURE_COUNT_JOB
        .scope(counter.clone(), async move {
            // Bind then drop a listener: the port is closed, but was definitely
            // free, so a connection there cannot succeed.
            let dead_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dead listener");
            let dead_port = dead_listener.local_addr().expect("dead addr").port();
            drop(dead_listener);

            // Explicit: reqwest resolves the rustls provider when a `Client`
            // is built, and this test must not depend on some earlier test in
            // the binary having installed it first.
            crate::ensure_crypto_provider();
            let client = reqwest::Client::new();
            let dead = format!("http://127.0.0.1:{dead_port}/");
            assert!(
                send_counted(client.get(&dead)).await.is_err(),
                "a closed port must not answer"
            );
            assert_eq!(
                c.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "a request that never reached the target must be counted"
            );

            // A request that does answer must not be counted. Served by axum
            // rather than a hand-rolled socket: a raw one-shot responder races
            // the client's connection handling differently across platforms
            // (it failed on Windows).
            let live_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind live listener");
            let live_addr = live_listener.local_addr().expect("live addr");
            tokio::spawn(async move {
                let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
                let _ = axum::serve(live_listener, app).await;
            });
            let live = format!("http://{live_addr}/");
            assert!(
                send_counted(client.get(&live)).await.is_ok(),
                "the live server must answer"
            );
            assert_eq!(
                c.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "a successful request must not bump the failure counter"
            );
        })
        .await;
}
