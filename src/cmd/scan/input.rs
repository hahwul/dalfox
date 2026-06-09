//! Target input resolution. Turns `--input-type` plus positional args / stdin
//! / target-list files / raw-HTTP into a parsed, deduplicated, scope- and
//! out-of-scope-filtered `Vec<Target>`, with `--cookie-from-raw` applied.
//! Returns `Err(ScanOutcome::Error)` — after emitting the structured error —
//! on any unrecoverable input problem.

use super::args::{DEFAULT_METHOD, ScanArgs};
use super::logging::{log_info, log_warn};
use super::validation::{
    domain_matches_pattern, looks_like_target_list_filename, looks_like_url_input,
};
use super::{ScanOutcome, emit_error};
use crate::target_parser::*;

pub(crate) async fn resolve_targets(
    args: &ScanArgs,
) -> std::result::Result<Vec<Target>, ScanOutcome> {
    // Byte budget for any path that slurps a file or stdin into memory.
    // 256 MiB lands well above realistic URL lists (≈5 M URLs at ~50 B
    // each) while still cutting `/dev/zero`, runaway pipes, and
    // gigabyte misclassified blobs to a fast, clear error instead of
    // OOM-ing the process. The matching `read_bounded` / `read_stdin_
    // bounded` enforce the cap during the read itself, so a pseudo-
    // file that lies about its size (`/dev/zero` reports 0 bytes via
    // metadata) is still stopped.
    const MAX_TARGET_LIST_BYTES: u64 = crate::utils::fs::MAX_FILE_READ_BYTES;
    // Prefix budget for content sniffing during auto-detection. A raw HTTP
    // request is identified by its first line and a HAR by its leading
    // `{ … "log" … "entries"` preamble, so 8 KiB is enough to classify the
    // input without reading a (possibly huge) file in full — only the
    // committed input mode reads the whole file. Real HARs place `entries`
    // within the first few hundred bytes; the rare capture that buries it past
    // the budget can still be forced with `--input-type har`.
    const SNIFF_PREFIX_BYTES: u64 = 8 * 1024;

    // stdin can only be read once. When auto-detection needs to peek at a
    // piped stream (to tell a HAR document apart from a line-based URL list),
    // it buffers the whole stream here so the parsing phase reuses the same
    // bytes instead of reading an already-drained stdin.
    let mut buffered_stdin: Option<String> = None;
    let stdin_is_piped = !std::io::IsTerminal::is_terminal(&std::io::stdin());

    let input_type = if args.input_type == "auto" {
        if args.targets.is_empty() {
            // No positional targets: only honour stdin if it's actually
            // piped — never block waiting for terminal input.
            if stdin_is_piped {
                // Buffer stdin once, then auto-detect: a HAR document piped in
                // (`cat capture.har | dalfox scan`) parses as `har`; anything
                // else is treated as a line-based pipe from the same bytes.
                match crate::utils::fs::read_stdin_bounded(MAX_TARGET_LIST_BYTES, "stdin pipe") {
                    Ok(buf) => {
                        let detected = if crate::target_parser::is_har_content(&buf) {
                            "har"
                        } else {
                            "pipe"
                        };
                        buffered_stdin = Some(buf);
                        detected.to_string()
                    }
                    Err(e) => {
                        if !args.silence {
                            emit_error(
                                &args.format,
                                crate::cmd::error_codes::STDIN_ERROR,
                                &format!("Error reading from stdin: {}", e),
                            );
                        }
                        return Err(ScanOutcome::Error);
                    }
                }
            } else {
                if !args.silence {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::NO_TARGETS,
                        "No targets specified",
                    );
                }
                return Err(ScanOutcome::Error);
            }
        } else {
            // Classify the positional file args by sniffing a bounded *prefix*
            // of each rather than slurping it in full: `is_raw_http_request`
            // only inspects the first line and `is_har_content` only the
            // leading `{ … "log" … "entries"` markers, so the first few KiB
            // decide it. The committed input mode reads each file completely
            // later. Raw HTTP pasted directly on the CLI is matched as a
            // literal (it is not a path on disk). Both flags accumulate with
            // AND, so a single non-match rules a type out.
            let mut all_raw_http = true;
            let mut all_har = true;
            for t in &args.targets {
                if crate::target_parser::is_raw_http_request(t) {
                    all_har = false; // a raw-http literal is never a HAR
                    continue;
                }
                match crate::utils::fs::read_prefix_lossy(
                    std::path::Path::new(t),
                    SNIFF_PREFIX_BYTES,
                ) {
                    Ok(prefix) => {
                        all_raw_http &= crate::target_parser::is_raw_http_request(&prefix);
                        all_har &= crate::target_parser::is_har_content(&prefix);
                    }
                    // Not a readable file (a bare URL/host literal, or an
                    // unreadable path): neither a raw-http nor a HAR file.
                    Err(_) => {
                        all_raw_http = false;
                        all_har = false;
                    }
                }
                if !all_raw_http && !all_har {
                    break; // neither type is still possible — stop sniffing
                }
            }
            if all_raw_http {
                "raw-http".to_string()
            } else if all_har {
                "har".to_string()
            } else {
                "auto".to_string()
            }
        }
    } else {
        args.input_type.clone()
    };

    let mut target_strings = Vec::new();

    if input_type == "auto" {
        // If stdin is piped under auto, read it and merge targets!
        if stdin_is_piped {
            match crate::utils::fs::read_stdin_bounded(MAX_TARGET_LIST_BYTES, "stdin pipe") {
                Ok(buffer) => {
                    let mut stdin_count = 0;
                    for line in buffer.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            target_strings.push(trimmed.to_string());
                            stdin_count += 1;
                        }
                    }
                    if stdin_count > 0 && !args.targets.is_empty() && !args.silence {
                        eprintln!(
                            "[info] Merged {} target(s) from stdin and {} target(s) from arguments",
                            stdin_count,
                            args.targets.len()
                        );
                    }
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::STDIN_ERROR,
                            &format!("Error reading from stdin: {}", e),
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
            }
        }

        for target in &args.targets {
            if target.contains("://") {
                target_strings.push(target.clone());
                continue;
            }
            // Detection only sniffed a prefix, so read the file in full now
            // (None when the arg isn't a file on disk — treated as a URL).
            let p = std::path::Path::new(target);
            let file_read: Option<std::result::Result<String, std::io::Error>> = if p.exists() {
                Some(crate::utils::fs::read_bounded(
                    p,
                    MAX_TARGET_LIST_BYTES,
                    "target list",
                ))
            } else {
                None
            };
            match file_read {
                Some(Ok(content)) => {
                    // Ambiguity: input is both a readable file *and*
                    // looks like a host/URL. Previously the file won
                    // silently, so `dalfox scan example.com` against
                    // a cwd that happens to contain `./example.com`
                    // attacked whatever was inside the file instead
                    // of the public host. Prefer the URL interpretation
                    // when the input has a domain shape that doesn't
                    // match a known target-list file extension (.txt,
                    // .csv, …), and emit a one-line warning so the
                    // user can switch to `-i file` if they really did
                    // mean the file.
                    if looks_like_url_input(target) && !looks_like_target_list_filename(target) {
                        if !args.silence {
                            eprintln!(
                                "[warn] '{}' matches both a URL and a local file; \
                                 treating as URL. Use `-i file {}` to scan the file instead.",
                                target, target
                            );
                        }
                        target_strings.push(target.clone());
                        continue;
                    }
                    for line in content.lines() {
                        let line = line.trim();
                        // Industry-standard target-list shape: skip
                        // blank lines *and* `#` comments (nuclei, ffuf,
                        // httpx all behave this way). Previously a
                        // commented line would be sent to parse_target
                        // and surface as a confusing "empty host"
                        // error.
                        if !line.is_empty() && !line.starts_with('#') {
                            target_strings.push(line.to_string());
                        }
                    }
                }
                Some(Err(e)) => {
                    // The file exists but `read_bounded` refused it
                    // (over the cap, non-regular, non-UTF-8). Surface
                    // the specific reason — silently falling through
                    // to URL would hide a real misconfiguration.
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::INPUT_TOO_LARGE,
                            &format!("Error reading target list {}: {}", target, e),
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
                None => {
                    // Not a file on disk — treat as URL literal.
                    target_strings.push(target.clone());
                }
            }
        }
    } else {
        target_strings = match input_type.as_str() {
            "url" => args.targets.clone(),
            "file" => {
                if args.targets.is_empty() {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::NO_FILE,
                            "No file specified for input-type=file",
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
                let file_path = &args.targets[0];
                match crate::utils::fs::read_bounded(
                    std::path::Path::new(file_path),
                    MAX_TARGET_LIST_BYTES,
                    "target list",
                ) {
                    Ok(content) => content
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(ToString::to_string)
                        .collect(),
                    Err(e) => {
                        if !args.silence {
                            emit_error(
                                &args.format,
                                crate::cmd::error_codes::FILE_READ_ERROR,
                                &format!("Error reading file {}: {}", file_path, e),
                            );
                        }
                        return Err(ScanOutcome::Error);
                    }
                }
            }
            "pipe" => {
                // `-i pipe` with a TTY stdin would otherwise hang
                // waiting for Ctrl-D. Fail fast with a clear message —
                // the operator either forgot the pipe or meant `-i
                // auto`.
                if !stdin_is_piped {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::STDIN_NOT_PIPED,
                            "`-i pipe` requires data on stdin (no pipe detected)",
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
                let mut piped_targets = Vec::new();
                // Reuse the stream buffered during auto-detection when present
                // (auto fell through to pipe); otherwise read stdin now.
                let buffer = match buffered_stdin.take() {
                    Some(buf) => buf,
                    None => {
                        match crate::utils::fs::read_stdin_bounded(
                            MAX_TARGET_LIST_BYTES,
                            "stdin pipe",
                        ) {
                            Ok(buf) => buf,
                            Err(e) => {
                                if !args.silence {
                                    emit_error(
                                        &args.format,
                                        crate::cmd::error_codes::STDIN_ERROR,
                                        &format!("Error reading from stdin: {}", e),
                                    );
                                }
                                return Err(ScanOutcome::Error);
                            }
                        }
                    }
                };
                for line in buffer.lines() {
                    let trimmed = line.trim();
                    // Same comment-skipping convention as the auto/file paths
                    // above so `cat targets.txt | dalfox` and `dalfox scan
                    // targets.txt` behave identically.
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        piped_targets.push(trimmed.to_string());
                    }
                }
                if !args.targets.is_empty() {
                    let before_merge = piped_targets.len();
                    for target in &args.targets {
                        piped_targets.push(target.clone());
                    }
                    if !args.silence {
                        eprintln!(
                            "[info] Merged {} target(s) from stdin and {} target(s) from arguments",
                            before_merge,
                            args.targets.len()
                        );
                    }
                }
                piped_targets
            }
            "raw-http" => {
                // Treat targets as raw HTTP request files or literals; actual parsing happens later
                args.targets.clone()
            }
            "har" => {
                // Each string is a whole HAR document (a stdin buffer or a file
                // path / literal), expanded to many Targets by parse_har later.
                if let Some(buf) = buffered_stdin.take() {
                    // Auto-detected HAR on stdin.
                    vec![buf]
                } else if !args.targets.is_empty() {
                    // Explicit `-i har file1.har file2.har …` (or HAR literals).
                    args.targets.clone()
                } else if stdin_is_piped {
                    // Explicit `-i har` reading HAR from a pipe.
                    match crate::utils::fs::read_stdin_bounded(MAX_TARGET_LIST_BYTES, "stdin pipe")
                    {
                        Ok(buf) => vec![buf],
                        Err(e) => {
                            if !args.silence {
                                emit_error(
                                    &args.format,
                                    crate::cmd::error_codes::STDIN_ERROR,
                                    &format!("Error reading from stdin: {}", e),
                                );
                            }
                            return Err(ScanOutcome::Error);
                        }
                    }
                } else {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::NO_FILE,
                            "No HAR file specified for input-type=har (pass a .har path or pipe HAR on stdin)",
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
            }

            _ => {
                if !args.silence {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::INVALID_INPUT_TYPE,
                        &format!(
                            "Invalid input-type '{}'. Use 'auto', 'url', 'file', 'pipe', 'raw-http', or 'har'",
                            input_type
                        ),
                    );
                }
                return Err(ScanOutcome::Error);
            }
        };
    }

    if target_strings.is_empty() {
        if !args.silence {
            emit_error(
                &args.format,
                crate::cmd::error_codes::NO_TARGETS,
                "No targets specified",
            );
        }
        return Err(ScanOutcome::Error);
    }

    let mut parsed_targets = Vec::new();
    for s in target_strings {
        if input_type == "har" {
            // A single HAR document expands to many Targets. Load it from the
            // detection cache, a file on disk, or treat the string itself as
            // the document (the stdin buffer / a literal).
            let content = match load_request_source(&s, args, "HAR file") {
                Ok(c) => c,
                Err(outcome) => return Err(outcome),
            };
            match crate::target_parser::parse_har(&content) {
                Ok(har_targets) => {
                    for mut target in har_targets {
                        apply_request_cli_overrides(&mut target, args);
                        parsed_targets.push(target);
                    }
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::PARSE_ERROR,
                            &format!("Error parsing HAR '{}': {}", s, e),
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
            }
        } else if input_type == "raw-http" {
            // Parse raw HTTP from the detection cache, a file, or a literal.
            let content = match load_request_source(&s, args, "raw HTTP request") {
                Ok(c) => c,
                Err(outcome) => return Err(outcome),
            };
            match crate::target_parser::parse_raw_http_request(&content) {
                Ok(mut target) => {
                    apply_request_cli_overrides(&mut target, args);
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::PARSE_ERROR,
                            &format!("Error parsing raw HTTP request '{}': {}", s, e),
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
            }
        } else {
            match crate::target_parser::parse_target_with_method(&s) {
                Ok(mut target) => {
                    // Only override data if explicitly provided via CLI
                    if let Some(d) = &args.data {
                        target.data = Some(d.clone());
                    }
                    target.headers = args
                        .headers
                        .iter()
                        .filter_map(|h| {
                            let mut parts = h.splitn(2, ':');
                            let name = parts.next()?.trim();
                            let value = parts.next()?.trim();
                            if name.is_empty() {
                                return None;
                            }
                            Some((name.to_string(), value.to_string()))
                        })
                        .collect();
                    // Only override method if explicitly provided via CLI (not the default)
                    if args.method != DEFAULT_METHOD {
                        target.method = args.method.clone();
                    }
                    if let Some(ua) = &args.user_agent {
                        target.headers.push(("User-Agent".to_string(), ua.clone()));
                        target.user_agent = Some(ua.clone());
                    } else {
                        target.user_agent = Some("".to_string());
                    }
                    target.cookies = args
                        .cookies
                        .iter()
                        .filter_map(|c| c.split_once("="))
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    target.timeout = args.timeout;
                    target.delay = args.delay;
                    target.proxy = args.proxy.clone();
                    target.insecure = args.insecure;
                    target.follow_redirects = args.follow_redirects;
                    target.ignore_return = args.ignore_return.clone();
                    target.workers = args.workers;
                    parsed_targets.push(target);
                }
                Err(e) => {
                    if !args.silence {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::PARSE_ERROR,
                            &format!("Error parsing target '{}': {}", s, e),
                        );
                    }
                    return Err(ScanOutcome::Error);
                }
            }
        }
    }

    // Deduplicate targets by URL + method to avoid redundant scans (e.g. pipe input with duplicates)
    {
        let mut seen = std::collections::HashSet::new();
        parsed_targets.retain(|t| {
            let key = format!("{}|{}", t.url, t.method);
            seen.insert(key)
        });
    }

    // Apply URL scope filtering (--include-url / --exclude-url)
    {
        // Invalid scope patterns must always surface on stderr, even when
        // `--silence` is on: silently discarding the user's filter means
        // every target gets scanned anyway, which is exactly the opposite
        // of what the operator asked for. stderr stays out of the stdout
        // payload that scripts parse, so a noise-sensitive caller can
        // still redirect `2>/dev/null` if they really want it gone.
        let include_patterns: Vec<regex::Regex> = args
            .include_url
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!(
                        "Warning: invalid --include-url regex '{}': {} (hint: --include-url takes a regex like '.*/api/.*', not a shell glob)",
                        p, e
                    );
                    None
                }
            })
            .collect();
        let exclude_patterns: Vec<regex::Regex> = args
            .exclude_url
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!(
                        "Warning: invalid --exclude-url regex '{}': {} (hint: --exclude-url takes a regex like '.*/admin.*', not a shell glob)",
                        p, e
                    );
                    None
                }
            })
            .collect();

        if !include_patterns.is_empty() || !exclude_patterns.is_empty() {
            let before = parsed_targets.len();
            parsed_targets.retain(|t| {
                let url_str = t.url.as_str();
                // If include patterns are set, URL must match at least one
                if !include_patterns.is_empty()
                    && !include_patterns.iter().any(|r| r.is_match(url_str))
                {
                    return false;
                }
                // If exclude patterns are set, URL must not match any
                if exclude_patterns.iter().any(|r| r.is_match(url_str)) {
                    return false;
                }
                true
            });
            let filtered = before - parsed_targets.len();
            if filtered > 0 {
                log_info(
                    args,
                    &format!("scope filter: {} target(s) excluded", filtered),
                );
            }
        }
    }

    // Apply out-of-scope domain filtering (--out-of-scope / --out-of-scope-file)
    {
        let mut oos_domains: Vec<String> = args.out_of_scope.clone();
        if let Some(ref path) = args.out_of_scope_file {
            match crate::utils::fs::read_bounded(
                std::path::Path::new(path),
                MAX_TARGET_LIST_BYTES,
                "out-of-scope domain file",
            ) {
                Ok(contents) => {
                    for line in contents.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            oos_domains.push(trimmed.to_string());
                        }
                    }
                }
                Err(e) => {
                    log_warn(
                        args,
                        &format!("failed to read --out-of-scope-file '{}': {}", path, e),
                    );
                }
            }
        }
        if !oos_domains.is_empty() {
            let before = parsed_targets.len();
            parsed_targets.retain(|t| {
                let host = match t.url.host_str() {
                    Some(h) => h,
                    None => return true,
                };
                !oos_domains
                    .iter()
                    .any(|pattern| domain_matches_pattern(host, pattern))
            });
            let filtered = before - parsed_targets.len();
            if filtered > 0 {
                log_info(
                    args,
                    &format!("out-of-scope filter: {} target(s) excluded", filtered),
                );
            }
        }
    }

    if args.hpp {
        log_info(
            args,
            "HPP (HTTP Parameter Pollution) enabled — duplicate query params will be tested for WAF bypass",
        );
    }

    if parsed_targets.is_empty() {
        // Always surface this — `--silence` should suppress scan log
        // noise, not swallow input-validation errors. emit_error writes
        // to stderr, so it doesn't pollute the stdout payload that
        // `--silence` callers are typically piping into another tool.
        emit_error(
            &args.format,
            crate::cmd::error_codes::NO_TARGETS,
            "No targets specified",
        );
        return Err(ScanOutcome::Error);
    }

    // Load cookies from raw HTTP request file if specified
    if let Some(path) = &args.cookie_from_raw {
        match crate::utils::fs::read_bounded(
            std::path::Path::new(path),
            MAX_TARGET_LIST_BYTES,
            "raw cookie file",
        ) {
            Ok(content) => {
                let mut cookies_from_raw: Vec<(String, String)> = Vec::new();
                for line in content.lines() {
                    // HTTP header names are case-insensitive (RFC 7230 §3.2;
                    // HTTP/2 mandates lowercase), so match `Cookie`/`cookie`/
                    // `COOKIE` alike and tolerate arbitrary spacing after the
                    // colon. Delegate value splitting to the shared
                    // `split_cookie_pairs` so this parses identically to the
                    // server / preflight cookie paths.
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("cookie")
                    {
                        cookies_from_raw.extend(crate::job::split_cookie_pairs(value));
                    }
                }
                if !cookies_from_raw.is_empty() {
                    for target in &mut parsed_targets {
                        target.cookies.extend(cookies_from_raw.iter().cloned());
                    }
                }
            }
            Err(e) if !args.silence => {
                eprintln!("Error reading cookie file {}: {}", path, e);
            }
            Err(_) => {}
        }
    }

    Ok(parsed_targets)
}

/// Load the source text for a request-bearing input (`raw-http` or `har`):
/// read the file at `s` (bounded), else treat `s` itself as the document (a
/// stdin buffer or a CLI literal). Detection only sniffs a prefix, so the full
/// read happens here, once we've committed to the input type. Emits the
/// structured error and returns `Err(ScanOutcome::Error)` when an existing file
/// can't be read within the byte cap.
fn load_request_source(
    s: &str,
    args: &ScanArgs,
    label: &str,
) -> std::result::Result<String, ScanOutcome> {
    let p = std::path::Path::new(s);
    if p.exists() {
        match crate::utils::fs::read_bounded(p, crate::utils::fs::MAX_FILE_READ_BYTES, label) {
            Ok(c) => Ok(c),
            Err(e) => {
                if !args.silence {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::INPUT_TOO_LARGE,
                        &format!("Error reading {} {}: {}", label, s, e),
                    );
                }
                Err(ScanOutcome::Error)
            }
        }
    } else {
        Ok(s.to_string())
    }
}

/// Apply CLI overrides to a Target parsed from a request-bearing source
/// (`raw-http` or `har`). Request-content fields (method, body, headers,
/// cookies, User-Agent) are only touched when the user explicitly set the
/// matching flag, so each captured request keeps its own shape by default;
/// CLI headers and cookies are *appended* (not replaced) since the request
/// already carries its own. Network/runtime fields are always taken from the
/// args. This is the shared override path for both raw-HTTP and HAR inputs.
fn apply_request_cli_overrides(target: &mut Target, args: &ScanArgs) {
    if args.method != DEFAULT_METHOD {
        target.method = args.method.clone();
    }
    if let Some(d) = &args.data {
        target.data = Some(d.clone());
    }
    for h in &args.headers {
        if let Some((name, value)) = h.split_once(':') {
            target
                .headers
                .push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    if let Some(ua) = &args.user_agent {
        target.headers.push(("User-Agent".to_string(), ua.clone()));
        target.user_agent = Some(ua.clone());
    } else if target.user_agent.is_none() {
        target.user_agent = Some("".to_string());
    }
    for c in &args.cookies {
        if let Some((k, v)) = c.split_once('=') {
            target
                .cookies
                .push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    target.timeout = args.timeout;
    target.delay = args.delay;
    target.proxy = args.proxy.clone();
    target.insecure = args.insecure;
    target.follow_redirects = args.follow_redirects;
    target.ignore_return = args.ignore_return.clone();
    target.workers = args.workers;
}
