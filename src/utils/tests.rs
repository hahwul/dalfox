use super::{
    finding_belongs_to_target, init_remote_resources, init_remote_resources_with_options,
    stable_finding_fingerprint,
};

#[test]
fn fingerprint_is_deterministic() {
    let a = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    assert_eq!(a, b);
    assert_eq!(a.len(), 16, "fingerprint must be 16 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn fingerprint_invariant_to_query_value() {
    // Same target identity (path stable, query value differs across payload
    // variants) must hash to the same fingerprint — this is the property
    // that makes SARIF consumers dedupe re-runs.
    let a = stable_finding_fingerprint("http://h/s?q=a", "q", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/s?q=%3Csvg%3E", "q", "inHTML", "CWE-79");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_invariant_to_path_segment_payload() {
    // Path-injection variants must collapse to the same identity.
    let a = stable_finding_fingerprint("http://h/p/level1/seed", "p", "inHTML", "CWE-79");
    let b = stable_finding_fingerprint("http://h/p/level1/%3Cimg%3E", "p", "inHTML", "CWE-79");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_separates_distinct_targets() {
    let q = stable_finding_fingerprint("http://h/a?q=x", "q", "inHTML", "CWE-79");
    let other_path = stable_finding_fingerprint("http://h/b?q=x", "q", "inHTML", "CWE-79");
    let other_param = stable_finding_fingerprint("http://h/a?q=x", "id", "inHTML", "CWE-79");
    let other_inject = stable_finding_fingerprint("http://h/a?q=x", "q", "inJS", "CWE-79");
    assert_ne!(q, other_path);
    assert_ne!(q, other_param);
    assert_ne!(q, other_inject);
}

#[test]
fn finding_belongs_query_target_same_path() {
    // Query target: payload mutates query string only.
    let target = "http://h/search?q=a";
    assert!(finding_belongs_to_target(
        target,
        "http://h/search?q=%3Csvg%3E"
    ));
    assert!(finding_belongs_to_target(target, "http://h/search?id=1"));
}

#[test]
fn finding_belongs_query_target_rejects_other_path() {
    let target = "http://h/search?q=a";
    assert!(!finding_belongs_to_target(target, "http://h/other?q=a"));
    assert!(!finding_belongs_to_target(target, "http://h/searches?q=a"));
}

#[test]
fn finding_belongs_path_injection_uses_parent() {
    // Path target: payload replaces last segment.
    let target = "http://h/path/level1/a";
    assert!(finding_belongs_to_target(
        target,
        "http://h/path/level1/%3Cimg%3E"
    ));
    assert!(finding_belongs_to_target(target, "http://h/path/level1/b"));
}

#[test]
fn finding_belongs_header_inject_no_query_exact_match() {
    // Header/cookie/body target with no query: finding URL is identical.
    let target = "http://h/page";
    assert!(finding_belongs_to_target(target, "http://h/page"));
}

#[test]
fn finding_belongs_path_injection_rejects_sibling_path() {
    let target = "http://h/path/level1/a";
    // Different parent path — must not match.
    assert!(!finding_belongs_to_target(target, "http://h/path/level2/a"));
    assert!(!finding_belongs_to_target(target, "http://h/other/x"));
}

#[test]
fn finding_belongs_query_target_does_not_borrow_path_parent_fallback() {
    // A target with a query string must NOT use the parent-path fallback,
    // because path is stable across query payload variants.
    let target = "http://h/a/b?q=x";
    assert!(!finding_belongs_to_target(target, "http://h/a/c?q=x"));
}

#[tokio::test]
async fn test_init_remote_resources_noop_when_no_providers() {
    let payloads: Vec<String> = vec![];
    let wordlists: Vec<String> = vec![];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_with_options_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources_with_options(&payloads, &wordlists, Some(1), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}

/// True when the parenthesised group starting at `s[0] == '('` closes exactly
/// at the end of `s` — i.e. the call is the entire expression, not one operand
/// of a larger one.
fn call_spans_to_end(s: &str) -> bool {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    // A rustfmt-wrapped call leaves a trailing comma.
                    return s[i + 1..].trim().trim_end_matches(',').trim().is_empty();
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the argument text of a `Semaphore::new(..)` call is safe — either
/// already clamped, or a value that cannot exceed tokio's `MAX_PERMITS`.
///
/// Split out from the scan below so the accept/reject table can be pinned
/// directly (see `semaphore_arg_classifier_rejects_bypass_shapes`) instead of
/// only being exercised through whatever shapes the tree happens to contain.
fn semaphore_arg_is_clamped(arg: &str) -> bool {
    // `split_whitespace` already trims and collapses internal runs.
    let t = arg.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = t.as_str();

    // Already routed through the clamp, directly or via `host_group_slots`
    // (which clamps internally). The whole argument must BE that call — a
    // `contains` check would accept `semaphore_permits(base) + args.workers`
    // and `max(semaphore_permits(a), raw_workers)`, both of which still panic.
    for call in ["semaphore_permits(", "host_group_slots("] {
        if let Some(at) = t.find(call) {
            // Everything before the call must be a path prefix (`crate::utils::`).
            let prefix_ok = t[..at]
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == ':');
            // ...and the call must run to the end of the argument.
            let closes_at_end = call_spans_to_end(&t[at + call.len() - 1..]);
            if prefix_ok && closes_at_end {
                return true;
            }
        }
    }
    // A bare integer literal: `1`, `64`, `1_024usize`. Matched WHOLE — a
    // leading-digit check would also accept `2 * args.workers`.
    let lit = t.trim_end_matches("usize");
    if !lit.is_empty() && lit.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return true;
    }
    // A SCREAMING_CASE constant: `MAX_CONCURRENT_PREFLIGHT`. Matched WHOLE — a
    // leading-uppercase check would also accept every type-qualified path, e.g.
    // `ScanOptions::from(o).workers`, which is exactly the shape a "thread the
    // config through a builder" refactor produces.
    if t.starts_with(|c: char| c.is_ascii_uppercase())
        && t.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return true;
    }
    false
}

/// Pins the classifier's accept/reject table, including the bypass shapes a
/// first-character-only check would have waved through.
#[test]
fn semaphore_arg_classifier_rejects_bypass_shapes() {
    // Safe.
    for ok in [
        "crate::utils::semaphore_permits(target.workers)",
        "host_group_slots(args.max_concurrent_targets)",
        "MAX_CONCURRENT_PREFLIGHT",
        "8",
        "1_024usize",
        "crate::utils::semaphore_permits(if args.sxss { 1 } else { target.workers })",
    ] {
        assert!(semaphore_arg_is_clamped(ok), "should be accepted: {ok}");
    }

    // Unclamped, user-controlled. Every one of these panics `Semaphore::new`
    // for a large enough `--workers` / `--max-concurrent-targets`.
    for bad in [
        "args.max_concurrent_targets",
        "target.workers",
        // Type-qualified paths: accepted by a leading-uppercase check.
        "ScanOptions::from(o).workers",
        "Self::worker_count(args)",
        "Config::get().workers",
        // Arithmetic: accepted by a leading-digit check.
        "2 * args.workers",
        "1 + target.workers",
        // An accept-term as one OPERAND of a larger expression: the clamp runs,
        // then the result is added to / maxed with an unclamped value.
        "crate::utils::semaphore_permits(base) + args.workers",
        "std::cmp::max(crate::utils::semaphore_permits(a), raw_workers)",
    ] {
        assert!(!semaphore_arg_is_clamped(bad), "should be rejected: {bad}");
    }
}

/// Every `Semaphore::new` in production code must take either a compile-time
/// constant or a value clamped by [`super::semaphore_permits`].
///
/// `tokio::sync::Semaphore::new` asserts above `MAX_PERMITS` (`usize::MAX >> 3`),
/// so an unclamped concurrency knob is a panic driven straight by user input.
/// `--workers` is capped by `CLI_MAX_WORKERS`, but only on the CLI path —
/// `validate_numeric_args` runs inside `run_scan`, which the REST and MCP job
/// runners never call — and `--max-concurrent-targets` has no upper bound at
/// all (`validation.rs` only rejects zero). Clamping at construction is what
/// holds regardless of which validator ran.
///
/// A source-level guard rather than a behavioral test because the risky call
/// sites sit deep inside 500–700 line orchestration functions that a unit test
/// cannot cheaply drive. It fails on any NEW unclamped site, which is the part
/// that actually regresses.
#[test]
fn every_semaphore_new_clamps_its_permit_count() {
    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    /// Remove every `#[cfg(test)] mod .. { .. }` block, brace-matched. Other
    /// `#[cfg(test)]` items (a single `use`, a single `fn`) are left in place;
    /// they carry no `Semaphore::new`.
    fn strip_cfg_test_modules(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find("#[cfg(test)]") {
            let after = &rest[at + "#[cfg(test)]".len()..];
            // Only a `mod` item opens a block worth skipping.
            let is_mod = after.trim_start().starts_with("mod ");
            let Some(brace) = after.find('{').filter(|_| is_mod) else {
                out.push_str(&rest[..at + "#[cfg(test)]".len()]);
                rest = after;
                continue;
            };
            out.push_str(&rest[..at]);
            let block = &after[brace..];
            let mut depth = 0usize;
            let mut end = block.len();
            for (i, c) in block.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = &block[end..];
        }
        out.push_str(rest);
        out
    }

    /// The argument text of the call whose `(` is at `open`, found by paren
    /// depth rather than a fixed window. A fixed window runs past the end of
    /// its own statement and picks up whatever follows — which in this tree
    /// meant an accept-term from the *next* call could vouch for an unclamped
    /// one two lines away. `get` rather than `[..]` so a multibyte char on the
    /// boundary is a miss, not a panic.
    fn call_argument(src: &str, open: usize) -> Option<&str> {
        let mut depth = 0usize;
        for (i, c) in src[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return src.get(open + 1..open + i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    let mut files = Vec::new();
    rs_files(std::path::Path::new("src"), &mut files);
    assert!(!files.is_empty(), "should have found source files");

    let mut offenders = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Drop `#[cfg(test)] mod { .. }` blocks by brace matching. Truncating
        // at the FIRST `#[cfg(test)]` instead would blank most of a file: in
        // `scanning/mod.rs` that marker appears at line 58 while the
        // `Semaphore::new` this guard exists to watch is at line 2548, and a
        // single-item `#[cfg(test)] pub(crate) use ..;` (as in
        // `check_dom_verification.rs`) would blank everything after it too.
        let code = strip_cfg_test_modules(&text);
        // Drop whole-line comments so prose mentioning a `Semaphore::new(..)`
        // call is not scanned as code, and so a comment *inside* an argument
        // does not hide the clamp. Whole-line only: stripping from a trailing
        // `//` would also eat the tail of any line holding a URL literal.
        let stripped: String = code
            .as_str()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        let needle = "Semaphore::new";
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(needle) {
            let at = from + rel;
            from = at + needle.len();
            let Some(open) = stripped[from..].find('(').map(|o| from + o) else {
                continue;
            };
            let Some(raw) = call_argument(&stripped, open) else {
                continue;
            };
            if !semaphore_arg_is_clamped(raw) {
                let arg = raw.split_whitespace().collect::<Vec<_>>().join(" ");
                offenders.push(format!("{}: Semaphore::new({})", path.display(), arg));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "unclamped Semaphore::new — wrap the permit count in \
         crate::utils::semaphore_permits(..) or this panics on a large \
         --workers / --max-concurrent-targets:\n  {}",
        offenders.join("\n  ")
    );
}
