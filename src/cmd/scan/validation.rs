//! Argument range-checking and input-shape heuristics: numeric arg
//! validation, the URL-vs-file-path tiebreak, target-list extension
//! detection, and out-of-scope domain matching. Pure functions, no I/O.

use super::args::{
    CLI_MAX_DELAY_MS, CLI_MAX_RATE_LIMIT, CLI_MAX_RETRIES, CLI_MAX_RETRY_DELAY_MS,
    CLI_MAX_SCAN_TIMEOUT_SECS, CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, ScanArgs,
};

/// Check if a domain matches an out-of-scope pattern.
/// Supports simple wildcard: `*.example.com` matches `sub.example.com` but not `notexample.com`.
pub(crate) fn domain_matches_pattern(host: &str, pattern: &str) -> bool {
    let host_lower = host.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    if let Some(base) = pattern_lower.strip_prefix("*.") {
        // Match exact subdomain boundary: host must end with ".base" or equal "base"
        host_lower == base || host_lower.ends_with(&format!(".{}", base))
    } else {
        host_lower == pattern_lower
    }
}

/// Range-check numeric scan args before launching any network work.
///
/// The original failure mode was a config file or CLI flag carrying a
/// nonsense value (e.g. `workers: 0`, `max_targets_per_host: 0`,
/// `timeout: 9999999`) that produced cryptic mid-scan failures —
/// truncating the entire target group, deadlocking on a 0-permit
/// semaphore, or hanging on an absurd timeout — long after the user
/// had already invested time in mining/discovery.
///
/// Returns `Err((error_code, message))` when invalid; the caller emits
/// the structured error and exits.
pub(crate) fn validate_numeric_args(
    args: &ScanArgs,
) -> std::result::Result<(), (&'static str, String)> {
    if args.workers == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--workers must be at least 1".to_string(),
        ));
    }
    if args.workers > CLI_MAX_WORKERS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--workers must be at most {} (got {})",
                CLI_MAX_WORKERS, args.workers
            ),
        ));
    }
    if args.timeout == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--timeout must be at least 1 second".to_string(),
        ));
    }
    if args.timeout > CLI_MAX_TIMEOUT_SECS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--timeout must be at most {} seconds (got {})",
                CLI_MAX_TIMEOUT_SECS, args.timeout
            ),
        ));
    }
    if args.delay > CLI_MAX_DELAY_MS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--delay must be at most {} ms (got {})",
                CLI_MAX_DELAY_MS, args.delay
            ),
        ));
    }
    // `--scan-timeout` (0 = disabled) feeds `Instant::now() + Duration::from_secs`
    // in the per-target cap; an unbounded value can overflow that add and panic
    // the scan task. Range-check it like every other duration arg so an absurd
    // value fails fast with a clear message instead of a mid-scan panic.
    if args.scan_timeout > CLI_MAX_SCAN_TIMEOUT_SECS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--scan-timeout must be at most {} seconds (got {}); use 0 to disable",
                CLI_MAX_SCAN_TIMEOUT_SECS, args.scan_timeout
            ),
        ));
    }
    // The rate-limit / retry caps below intentionally reuse
    // `INVALID_INPUT_TYPE`, the same code every other numeric range check in
    // this function emits (workers, timeout, delay, …). Keeping one code for
    // "a numeric arg was out of range" means structured-output (JSON/JSONL/
    // SARIF) consumers can match a single, stable category for all of them
    // rather than a per-flag taxonomy; the human-facing message carries the
    // specific flag and bound.
    if args.rate_limit > CLI_MAX_RATE_LIMIT {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--rate-limit must be at most {} req/sec (got {}); use 0 for unlimited",
                CLI_MAX_RATE_LIMIT, args.rate_limit
            ),
        ));
    }
    if args.retries > CLI_MAX_RETRIES {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--retries must be at most {} (got {})",
                CLI_MAX_RETRIES, args.retries
            ),
        ));
    }
    if args.sxss_retries > crate::cmd::scan::CLI_MAX_SXSS_RETRIES {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--sxss-retries must be at most {} (got {}); the re-check backoff is 500ms × attempt, so the total wait grows quadratically",
                crate::cmd::scan::CLI_MAX_SXSS_RETRIES,
                args.sxss_retries
            ),
        ));
    }
    if args.retry_delay > CLI_MAX_RETRY_DELAY_MS {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--retry-delay must be at most {} ms (got {})",
                CLI_MAX_RETRY_DELAY_MS, args.retry_delay
            ),
        ));
    }
    if args.max_concurrent_targets == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--max-concurrent-targets must be at least 1".to_string(),
        ));
    }
    if args.max_targets_per_host == 0 {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--max-targets-per-host must be at least 1".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&args.waf_min_confidence) || args.waf_min_confidence.is_nan() {
        return Err((
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            format!(
                "--waf-min-confidence must be in 0.0..=1.0 (got {})",
                args.waf_min_confidence
            ),
        ));
    }
    Ok(())
}

/// Proxy URL schemes reqwest can actually route through.
///
/// `reqwest::Proxy::all` accepts *any* string that parses as a URL with a host,
/// but hyper-util's proxy matcher silently drops every scheme outside this set
/// at request time — so an `ftp://`, `gopher://`, `socks6://`, or `file://`
/// value passes `Proxy::all` yet sends every request DIRECT to the target.
/// Gating on this list turns that silent scope hazard into a fast, clear
/// rejection.
pub(crate) const SUPPORTED_PROXY_SCHEMES: &[&str] =
    &["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

/// Validate a `--proxy` value the way the scan will actually use it: non-empty,
/// a scheme reqwest routes through, and accepted by the same
/// `reqwest::Proxy::all` the shared client builder
/// ([`crate::target_parser::Target::build_client`]) calls.
///
/// Deliberately self-contained: the returned message never echoes the value, so
/// a proxy carrying embedded credentials (`http://user:pass@host`) can't leak
/// into stderr/CI logs and a value with a stray newline can't forge a log line.
/// Returns `Err(message)` on failure; `String` so the server/MCP validator
/// ([`crate::server::util::validate_scan_options`]) can reuse it verbatim.
pub(crate) fn validate_proxy_url(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        // Empty (a blank config field, or `--proxy "$UNSET"` from the shell) is
        // rejected rather than tolerated: silently running DIRECT is the exact
        // hazard this check exists to close. Omit the flag for no proxy.
        return Err(
            "--proxy is empty (omit the flag entirely to scan without a proxy)".to_string(),
        );
    }
    let scheme = match url::Url::parse(trimmed) {
        Ok(u) => u.scheme().to_ascii_lowercase(),
        Err(_) => return Err(PROXY_SHAPE_HINT.to_string()),
    };
    if !SUPPORTED_PROXY_SCHEMES.contains(&scheme.as_str()) {
        return Err(format!(
            "--proxy scheme '{scheme}' is not routable — reqwest silently drops it and would scan DIRECT; use one of: {}",
            SUPPORTED_PROXY_SCHEMES.join(", ")
        ));
    }
    // Belt-and-suspenders: reject anything `reqwest::Proxy::all` itself won't
    // accept, so whatever passes here is exactly what the client will use.
    if reqwest::Proxy::all(trimmed).is_err() {
        return Err(PROXY_SHAPE_HINT.to_string());
    }
    Ok(())
}

const PROXY_SHAPE_HINT: &str = "--proxy is not a usable proxy URL (expected e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050)";

/// Validate an HTTP(S) URL flag (`--sxss-url`, `--session-check-url`): non-empty,
/// absolute, and an `http`/`https` scheme.
///
/// `url::Url::parse` alone accepts `mailto:`, `javascript:`, `file:` and other
/// non-fetchable schemes, which would pass the old parse-only check and then
/// silently degrade at request time (the value can never be fetched). Requiring
/// an HTTP scheme closes that. `flag` names the offending flag in the message;
/// the value is not echoed, so an operator-supplied string can't inject into the
/// log line.
pub(crate) fn validate_http_url(value: &str, flag: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag} is empty (omit the flag to leave it unset)"));
    }
    match url::Url::parse(trimmed) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => Ok(()),
        Ok(u) => Err(format!(
            "{flag} scheme '{}' is not fetchable; use an absolute http:// or https:// URL",
            u.scheme()
        )),
        Err(_) => Err(format!(
            "{flag} is not a valid absolute http:// or https:// URL"
        )),
    }
}

/// Does this positional argument *look* like a URL or host rather than
/// a file path? Used to break the "input is both a domain and a local
/// file" tie in favour of the URL, instead of silently slurping the
/// file. Conservative — anything starting with an explicit path prefix
/// (`./`, `../`, `/`, `~`) or containing whitespace is never URL-like.
pub(crate) fn looks_like_url_input(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains("://") {
        return true;
    }
    // Explicit path prefixes the user typed to *mean* "this is a file".
    if s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with('~')
        || s.contains(char::is_whitespace)
    {
        return false;
    }
    // Host with port: "example.com:8080", "127.0.0.1:8080", "[::1]:80".
    // The brace form is a literal IPv6 host. A bare colon followed by
    // digits is the port separator — strong URL signal regardless of
    // what's left.
    if s.starts_with('[') && s.contains("]:") {
        return true;
    }
    if let Some((host, after)) = s.split_once(':')
        && after.chars().next().is_some_and(|c| c.is_ascii_digit())
        && !host.is_empty()
        && !host.contains('/')
    {
        return true;
    }
    // Host-only form: at least one dot, no path separators before it,
    // and every dot-segment is a non-empty DNS label. This catches
    // `example.com`, `api.target.app/foo`, `127.0.0.1`, while filtering
    // out garbage like `..` or `.config`.
    let host_part = s.split_once('/').map_or(s, |(h, _)| h);
    if !host_part.contains('.') {
        return false;
    }
    host_part
        .split('.')
        .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Known target-list file extensions. When an input matches one of
/// these, the file interpretation always wins over URL even if the
/// name *also* satisfies `looks_like_url_input` (e.g. `urls.txt`
/// passes both: it has a dot, all labels are alnum). This keeps the
/// long-standing `dalfox scan urls.txt` workflow silent and ambiguity-
/// free, while still routing the genuinely ambiguous case
/// (`dalfox scan example.com` with a same-named file in cwd) into
/// the warn-and-prefer-URL branch.
pub(crate) fn looks_like_target_list_filename(s: &str) -> bool {
    const EXTS: &[&str] = &[
        "txt", "list", "lst", "csv", "tsv", "log", "json", "jsonl", "ndjson", "yaml", "yml",
        "conf", "cfg", "ini", "req", "raw", "http", "har",
    ];
    s.rsplit('.')
        .next()
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            EXTS.iter().any(|e| *e == lower)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod input_shape_tests {
    use super::*;

    #[test]
    fn domain_matches_exact_and_case_insensitive() {
        assert!(domain_matches_pattern("evil.com", "evil.com"));
        assert!(domain_matches_pattern("EVIL.com", "evil.COM"));
        assert!(!domain_matches_pattern("notevil.com", "evil.com"));
    }

    #[test]
    fn domain_matches_wildcard_subdomain_boundary() {
        assert!(domain_matches_pattern("sub.example.com", "*.example.com"));
        assert!(domain_matches_pattern("a.b.example.com", "*.example.com"));
        // Bare apex also matches the `*.` form.
        assert!(domain_matches_pattern("example.com", "*.example.com"));
        // Must respect the label boundary — `notexample.com` is not a subdomain.
        assert!(!domain_matches_pattern("notexample.com", "*.example.com"));
    }

    #[test]
    fn url_input_recognizes_schemes_and_hosts() {
        assert!(looks_like_url_input("https://example.com/x"));
        assert!(looks_like_url_input("example.com"));
        assert!(looks_like_url_input("api.target.app/foo"));
        assert!(looks_like_url_input("127.0.0.1"));
        assert!(looks_like_url_input("example.com:8080"));
        assert!(looks_like_url_input("[::1]:80"));
    }

    #[test]
    fn url_input_rejects_paths_and_garbage() {
        assert!(!looks_like_url_input(""));
        assert!(!looks_like_url_input("./local"));
        assert!(!looks_like_url_input("../local"));
        assert!(!looks_like_url_input("/etc/hosts"));
        assert!(!looks_like_url_input("~/list"));
        assert!(!looks_like_url_input("has space.com"));
        assert!(!looks_like_url_input("nodot"));
        assert!(!looks_like_url_input(".."));
        assert!(!looks_like_url_input(".config"));
    }

    #[test]
    fn proxy_url_accepts_routable_schemes() {
        for p in [
            "http://127.0.0.1:8080",
            "https://proxy.corp:3128",
            "socks5://127.0.0.1:9050",
            "socks5h://127.0.0.1:9050",
            "socks4://127.0.0.1:1080",
            // Leading/trailing whitespace is trimmed, not rejected.
            "  http://127.0.0.1:8080  ",
        ] {
            assert!(validate_proxy_url(p).is_ok(), "{p} should be accepted");
        }
    }

    #[test]
    fn proxy_url_rejects_unroutable_schemes_that_parse_fine() {
        // These all parse as URLs and pass `reqwest::Proxy::all`, but reqwest
        // silently drops them at request time — the DIRECT-scan hazard.
        for p in [
            "ftp://127.0.0.1:8080",
            "gopher://burp:8080",
            "socks6://127.0.0.1:1080",
            "file:///etc/passwd",
        ] {
            let err = validate_proxy_url(p).unwrap_err();
            assert!(
                err.contains("not routable"),
                "{p} should be rejected as unroutable, got: {err}"
            );
        }
    }

    #[test]
    fn proxy_url_rejects_empty_and_garbage() {
        assert!(validate_proxy_url("").unwrap_err().contains("empty"));
        assert!(validate_proxy_url("   ").unwrap_err().contains("empty"));
        assert!(validate_proxy_url("::not a url::").is_err());
    }

    #[test]
    fn proxy_url_error_never_echoes_credentials() {
        // A password in the proxy URL must not appear in the error text.
        let err = validate_proxy_url("ftp://user:S3cr3t@host:8080").unwrap_err();
        assert!(!err.contains("S3cr3t"), "error leaked credentials: {err}");
    }

    #[test]
    fn http_url_accepts_absolute_http_and_https() {
        assert!(validate_http_url("http://app.example/me", "--sxss-url").is_ok());
        assert!(validate_http_url("https://app.example/me", "--sxss-url").is_ok());
        assert!(validate_http_url("  https://app.example/me  ", "--sxss-url").is_ok());
    }

    #[test]
    fn http_url_rejects_non_fetchable_schemes_and_relatives() {
        for u in [
            "mailto:x@y",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "/relative/path",
            "app.example/me",
            "",
        ] {
            assert!(
                validate_http_url(u, "--sxss-url").is_err(),
                "{u} should be rejected"
            );
        }
    }

    #[test]
    fn target_list_filename_detects_known_extensions() {
        assert!(looks_like_target_list_filename("urls.txt"));
        assert!(looks_like_target_list_filename("data.csv"));
        assert!(looks_like_target_list_filename("out.JSONL"));
        assert!(looks_like_target_list_filename("req.HTTP"));
        assert!(looks_like_target_list_filename("capture.har"));
        // A bare host has no recognized list extension.
        assert!(!looks_like_target_list_filename("example.com"));
        assert!(!looks_like_target_list_filename("noext"));
    }
}
