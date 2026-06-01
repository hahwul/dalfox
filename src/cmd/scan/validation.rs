//! Argument range-checking and input-shape heuristics: numeric arg
//! validation, the URL-vs-file-path tiebreak, target-list extension
//! detection, and out-of-scope domain matching. Pure functions, no I/O.

use super::args::{CLI_MAX_DELAY_MS, CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, ScanArgs};

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
        "conf", "cfg", "ini", "req", "raw", "http",
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
    fn target_list_filename_detects_known_extensions() {
        assert!(looks_like_target_list_filename("urls.txt"));
        assert!(looks_like_target_list_filename("data.csv"));
        assert!(looks_like_target_list_filename("out.JSONL"));
        assert!(looks_like_target_list_filename("req.HTTP"));
        // A bare host has no recognized list extension.
        assert!(!looks_like_target_list_filename("example.com"));
        assert!(!looks_like_target_list_filename("noext"));
    }
}
