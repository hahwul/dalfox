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

/// How many dropped URLs the dedup log line quotes back. Enough to recognise
/// the collapsed family without turning one INF line into a wall of text.
const DEDUP_SAMPLE_LIMIT: usize = 3;

/// What the target-dedup pass collapsed. Surfaced both as an operator-facing
/// log line and in the scan-meta envelope, so a mode that *discards* targets
/// never reads as full coverage.
#[derive(Debug, Clone)]
pub(crate) struct DedupStats {
    /// Effective mode: `exact`, `signature`, or `off`.
    pub(crate) mode: &'static str,
    /// Targets dropped as duplicates.
    pub(crate) collapsed: usize,
    /// Up to [`DEDUP_SAMPLE_LIMIT`] of the dropped URLs.
    pub(crate) sample: Vec<String>,
}

/// "The default mode collapsed nothing" — the shape a run that never reached
/// target resolution should report.
impl Default for DedupStats {
    fn default() -> Self {
        Self {
            mode: super::args::DEFAULT_DEDUP_URLS,
            collapsed: 0,
            sample: Vec::new(),
        }
    }
}

/// The targets to scan plus what dedup dropped on the way there.
pub(crate) struct ResolvedTargets {
    pub(crate) targets: Vec<Target>,
    pub(crate) dedup: DedupStats,
}

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

pub(crate) async fn resolve_targets(
    args: &ScanArgs,
) -> std::result::Result<ResolvedTargets, ScanOutcome> {
    // stdin can only be read once. When auto-detection needs to peek at a
    // piped stream (to tell a HAR document apart from a line-based URL list),
    // it buffers the whole stream here so the parsing phase reuses the same
    // bytes instead of reading an already-drained stdin.
    let mut buffered_stdin: Option<String> = None;
    let stdin_is_piped = {
        let is_dalfox_bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .map(|name| {
                let name_lower = name.to_lowercase();
                name_lower == "dalfox" || name_lower == "dalfox.exe"
            })
            .unwrap_or(false);

        if is_dalfox_bin {
            !std::io::IsTerminal::is_terminal(&std::io::stdin())
        } else {
            false
        }
    };

    let input_type = detect_input_type(args, stdin_is_piped, &mut buffered_stdin)?;

    let mut target_strings = Vec::new();

    if input_type == "auto" {
        // If stdin is piped under auto, read it and merge targets!
        //
        // Reaching here means the user already named targets on the command
        // line (the empty case above resolved to `pipe`/`har` or errored), so
        // stdin is a bonus source rather than the input they asked for.
        // Reading it to EOF unconditionally hangs `dalfox scan <URL>` whenever
        // the parent process leaves an idle pipe on stdin — `is_terminal()`
        // can't tell that apart from a pipe about to deliver a URL list
        // (#1239). So wait only a short grace window for stdin's first byte:
        // a real producer has bytes buffered long before we look, an idle pipe
        // stays silent and we scan the CLI targets instead. `-i pipe` remains
        // the way to say "stdin *is* the input, wait for it".
        if stdin_is_piped {
            let wait_ms = stdin_merge_wait_ms();
            match crate::utils::fs::read_stdin_bounded_within(
                MAX_TARGET_LIST_BYTES,
                "stdin pipe",
                std::time::Duration::from_millis(wait_ms),
            ) {
                Ok(crate::utils::fs::StdinRead::Data(buffer)) => {
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
                Ok(crate::utils::fs::StdinRead::Idle) => {
                    // Say so rather than dropping the stream silently: if the
                    // pipe *was* meant to carry targets, its producer is just
                    // slow and the operator needs to know they were skipped.
                    if !args.silence {
                        eprintln!(
                            "[warn] stdin is an open pipe but sent no data within {}ms; \
                             scanning the {} target(s) from arguments only. Use `-i pipe` to \
                             wait for stdin, or set DALFOX_STDIN_WAIT_MS to adjust the wait.",
                            wait_ms,
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
                // Read every path given, not just `targets[0]`. `-i file a b`
                // used to silently drop `b`, diverging from the `raw-http` and
                // `har` branches (which honor all of `args.targets`) and giving
                // no hint that the extra files were ignored. Each file is
                // individually size-bounded and its lines concatenated.
                let mut collected: Vec<String> = Vec::new();
                for file_path in &args.targets {
                    match crate::utils::fs::read_bounded(
                        std::path::Path::new(file_path),
                        MAX_TARGET_LIST_BYTES,
                        "target list",
                    ) {
                        Ok(content) => collected.extend(
                            content
                                .lines()
                                .map(str::trim)
                                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                                .map(ToString::to_string),
                        ),
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
                collected
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
                    // An empty `--user-agent ""` must not become a literal
                    // `User-Agent:` header on every request (the server/MCP path
                    // already guards this); it means "no override".
                    if let Some(ua) = args.user_agent.as_ref().filter(|ua| !ua.is_empty()) {
                        target.headers.push(("User-Agent".to_string(), ua.clone()));
                        target.user_agent = Some(ua.clone());
                    } else {
                        target.user_agent = Some("".to_string());
                    }
                    // `--cookies "a=1; b=2"` is one flag carrying a whole Cookie
                    // header value, which a bare `split_once('=')` folded into
                    // a single cookie named `a` with value `1; b=2`. Requests
                    // still went out byte-identical, but cookie-parameter
                    // coverage silently lost every cookie after the first: the
                    // discovery stage iterates `target.cookies`, so `b` was
                    // never enumerated or probed. Server and MCP have always
                    // used this shared splitter.
                    target.cookies = args
                        .cookies
                        .iter()
                        .flat_map(|c| crate::job::split_cookie_pairs(c))
                        .collect();
                    target.timeout = args.timeout;
                    target.delay = args.delay;
                    target.proxy = args.proxy.clone();
                    target.insecure = args.insecure.unwrap_or(true);
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

    apply_url_scope_filters(args, &mut parsed_targets);

    apply_out_of_scope_filter(args, &mut parsed_targets);

    // Deduplicate targets per `--dedup-urls` (exact / signature / off) to avoid
    // redundant scans (e.g. pipe input with duplicates, or a `gau`/`katana`
    // dump of the same endpoint with thousands of harvested values).
    //
    // Deliberately *after* the scope filters: in `signature` mode one member of
    // a collapsed family stands in for all of them, so the filters must get to
    // rule members out first. Filtering afterwards would let a representative
    // that `--include-url` excludes shadow the sibling the operator asked for,
    // and drop the whole family. For `exact` mode the order is immaterial —
    // the members are byte-identical, so any filter treats them alike.
    let dedup = dedup_targets(&mut parsed_targets, args.dedup_urls_mode());
    if dedup.collapsed > 0 {
        let sample = dedup
            .sample
            .iter()
            .map(|s| crate::utils::log::sanitize_log_message(s).into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        log_info(
            args,
            &format!(
                "dedup ({}): {} duplicate target(s) collapsed, {} remaining{}",
                dedup.mode,
                dedup.collapsed,
                parsed_targets.len(),
                if sample.is_empty() {
                    String::new()
                } else {
                    format!(" — dropped e.g. {}", sample)
                }
            ),
        );
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

    load_cookies_from_raw_http(args, &mut parsed_targets);

    Ok(ResolvedTargets {
        targets: parsed_targets,
        dedup,
    })
}

/// Drop duplicate targets in place per `mode`, keeping one representative per
/// key.
///
/// - `exact` — the historical key: the full URL string (query and values
///   included) plus the method. Only byte-identical inputs collapse.
/// - `signature` — method + scheme + host + port + path + the *sorted set of
///   parameter names* (query and body alike). Parameter values are excluded, so
///   `?id=1`, `?id=2`, … `?id=9999` from a `gau`/`katana` dump collapse to one
///   scan of one endpoint. This is not value-safe for every endpoint (an
///   `action=` discriminator can select a different handler on the same path),
///   which is why it is opt-in and why the collapsed count is reported.
/// - `off` — no dedup; every input line is scanned.
///
/// The representative is the first member listed, with one exception: under
/// `signature`, a member whose parameters all carry a value beats an earlier
/// one that has an empty value somewhere. Recon dumps routinely list the
/// stale, valueless form of an endpoint first (`?id=`, `?q=`), and that URL
/// often 404s or renders an error page where nothing reflects — letting it
/// represent the family would report thousands of collapsed URLs clean off a
/// dud. It is a preference, not a guarantee: no value can be probed at input
/// time, so `signature` can still pick a member that happens to be dead.
///
/// An unrecognised mode is treated as `exact`; clap and the config validator
/// both reject other values before they reach here.
pub(crate) fn dedup_targets(targets: &mut Vec<Target>, mode: &str) -> DedupStats {
    let mode: &'static str = match mode {
        "off" => "off",
        "signature" => "signature",
        _ => "exact",
    };
    if mode == "off" {
        return DedupStats {
            mode,
            collapsed: 0,
            sample: Vec::new(),
        };
    }
    // Two passes: choose one index per key, then retain those. A single
    // `retain` can't express "a later member replaces the one already kept".
    let mut chosen: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(targets.len());
    let mut keep = vec![false; targets.len()];
    let mut sample: Vec<String> = Vec::new();
    let mut collapsed = 0usize;
    let note_dropped = |sample: &mut Vec<String>, t: &Target| {
        if sample.len() < DEDUP_SAMPLE_LIMIT {
            sample.push(t.url.to_string());
        }
    };
    for (i, t) in targets.iter().enumerate() {
        let key = if mode == "signature" {
            target_signature_key(t)
        } else {
            format!("{}|{}", t.url, t.method)
        };
        match chosen.entry(key) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(i);
                keep[i] = true;
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                collapsed += 1;
                let current = *slot.get();
                if mode == "signature"
                    && has_empty_param_value(&targets[current])
                    && !has_empty_param_value(t)
                {
                    // Promote this member and drop the placeholder we held.
                    keep[current] = false;
                    keep[i] = true;
                    slot.insert(i);
                    note_dropped(&mut sample, &targets[current]);
                } else {
                    note_dropped(&mut sample, t);
                }
            }
        }
    }
    let mut keep_iter = keep.into_iter();
    targets.retain(|_| keep_iter.next().unwrap_or(true));
    DedupStats {
        mode,
        collapsed,
        sample,
    }
}

/// Whether any query or form-body parameter of `t` is present but empty — the
/// `?id=` / `?q=` shape a recon dump leaves behind. Used only to pick between
/// members of a signature family; JSON and multipart bodies are not inspected
/// (their emptiness is not a single well-defined notion, and the query string
/// is what varies in the input lists this exists for).
fn has_empty_param_value(t: &Target) -> bool {
    if t.url.query_pairs().any(|(_, v)| v.is_empty()) {
        return true;
    }
    match t.data.as_deref().map(str::trim) {
        Some(data) if looks_like_form_urlencoded(data) => {
            url::form_urlencoded::parse(data.as_bytes()).any(|(_, v)| v.is_empty())
        }
        _ => false,
    }
}

/// Value-independent identity of a target: everything that decides *which
/// endpoint and which injection points* get scanned, and nothing that decides
/// what is sent into them. Port is normalized through the scheme default so
/// `https://a/p` and `https://a:443/p` share a signature.
///
/// The fragment is excluded on purpose: it never reaches the server, and
/// fragment-located params are not HTTP-scannable (see
/// `param_is_http_scannable`), so two URLs differing only after `#` produce
/// the exact same scan.
fn target_signature_key(t: &Target) -> String {
    let url = &t.url;
    let mut names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.extend(body_param_names(t));
    names.sort_unstable();
    names.dedup();
    format!(
        "{}|{}://{}:{}{}|{}",
        t.method.to_ascii_uppercase(),
        url.scheme(),
        url.host_str().unwrap_or(""),
        url.port_or_known_default().unwrap_or(0),
        url.path(),
        names.join("&")
    )
}

/// Parameter names carried by a target's request body, so POST/JSON/multipart
/// forms collapse on the same footing as query parameters. Mirrors what the
/// mining probes treat as body parameters: form-urlencoded pairs, the
/// *top-level* keys of a JSON object, and `multipart/form-data` field names.
///
/// A body matching none of those (raw XML, a protobuf blob) contributes no
/// names, so such targets collapse by endpoint alone — one more reason
/// `signature` is opt-in. In particular the form-urlencoded parser is only
/// reached for bodies that actually look like pairs: run on arbitrary bytes it
/// happily returns the whole body as one pseudo-name, which would both defeat
/// the collapse and paste a multi-MiB body into the dedup key.
fn body_param_names(t: &Target) -> Vec<String> {
    let Some(data) = t.data.as_deref().map(str::trim).filter(|d| !d.is_empty()) else {
        return Vec::new();
    };
    let content_type = t
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    if content_type.contains("multipart/form-data") || data.contains("Content-Disposition:") {
        return multipart_field_names(data);
    }
    if data.starts_with('{')
        && let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(data)
    {
        return map.keys().cloned().collect();
    }
    if looks_like_form_urlencoded(data) {
        return url::form_urlencoded::parse(data.as_bytes())
            .map(|(k, _)| k.into_owned())
            .collect();
    }
    Vec::new()
}

/// Whether `data` has the shape `a=1&b=2`: every `&`-separated segment carries
/// a non-empty name before an `=`, and there is no raw whitespace (a real
/// urlencoded body encodes it). Deliberately strict — misjudging XML or a
/// binary blob as a form is worse than contributing no names for an exotic
/// body, since the fallback silently turns the entire payload into a key.
fn looks_like_form_urlencoded(data: &str) -> bool {
    !data.is_empty()
        && !data.chars().any(char::is_whitespace)
        && data
            .split('&')
            .all(|pair| matches!(pair.split_once('='), Some((name, _)) if !name.is_empty()))
}

/// Field names from a raw `multipart/form-data` body: the `name` attribute of
/// each `Content-Disposition: form-data` part. Attributes are split on `;`
/// before matching so a `filename="…"` — which contains `name="` as a
/// substring — can't be mistaken for the field name.
fn multipart_field_names(data: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if !line
            .to_ascii_lowercase()
            .starts_with("content-disposition:")
        {
            continue;
        }
        for attr in line.split(';').skip(1) {
            let attr = attr.trim();
            let Some(value) = attr.strip_prefix("name=") else {
                continue;
            };
            let value = value.trim();
            let name = value
                .strip_prefix('"')
                .and_then(|v| v.split_once('"').map(|(n, _)| n))
                .unwrap_or(value);
            names.push(name.to_string());
            break; // one field name per part
        }
    }
    names
}

/// Default grace window for the `auto` stdin merge, in milliseconds.
///
/// Only spent when stdin is a pipe *and* targets were given on the command
/// line. A shell pipeline (`cat urls.txt | dalfox scan <URL>`) has its first
/// bytes in the pipe buffer within microseconds — orders of magnitude under
/// this — while an idle pipe pays the window once and then gets out of the
/// way. Half a second is long enough to absorb a heavily loaded machine
/// scheduling the producer late, short enough to read as instant.
const STDIN_MERGE_WAIT_MS: u64 = 500;

/// Upper bound on the configured wait: one hour. Past this the knob has
/// stopped meaning "grace window" and `-i pipe` is the honest way to say
/// "block until stdin is done". The clamp also keeps the knob from silently
/// re-creating #1239: a wait so large that `Instant::now() + wait` overflows
/// (e.g. `u64::MAX`) makes `recv_timeout` fall back to an unbounded `recv()`,
/// which is exactly the indefinite block this fix removed.
const MAX_STDIN_MERGE_WAIT_MS: u64 = 60 * 60 * 1000;

/// [`STDIN_MERGE_WAIT_MS`], overridable via `DALFOX_STDIN_WAIT_MS` for the two
/// tails this can't guess: a producer that takes seconds to emit its first URL
/// (raise it), and a wrapper that always leaves an idle pipe on stdin (`0`
/// skips the merge outright). A malformed value falls back to the default; an
/// oversized one is clamped to [`MAX_STDIN_MERGE_WAIT_MS`].
fn stdin_merge_wait_ms() -> u64 {
    std::env::var("DALFOX_STDIN_WAIT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|ms| ms.min(MAX_STDIN_MERGE_WAIT_MS))
        .unwrap_or(STDIN_MERGE_WAIT_MS)
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
    // Empty `--user-agent ""` means "no override", not a literal empty header.
    if let Some(ua) = args.user_agent.as_ref().filter(|ua| !ua.is_empty()) {
        target.headers.push(("User-Agent".to_string(), ua.clone()));
        target.user_agent = Some(ua.clone());
    } else if target.user_agent.is_none() {
        target.user_agent = Some("".to_string());
    }
    // Shared splitter: a `--cookies "a=1; b=2"` value carries several cookies
    // and every one of them has to become its own probe-able parameter.
    for c in &args.cookies {
        target.cookies.extend(crate::job::split_cookie_pairs(c));
    }
    target.timeout = args.timeout;
    target.delay = args.delay;
    target.proxy = args.proxy.clone();
    target.insecure = args.insecure.unwrap_or(true);
    target.follow_redirects = args.follow_redirects;
    target.ignore_return = args.ignore_return.clone();
    target.workers = args.workers;
}

#[cfg(test)]
mod tests;

/// Drop targets excluded by `--include-url` / `--exclude-url`.
///
/// Runs before the out-of-scope domain filter and before dedup, so a URL the
/// operator scoped out never reaches either.
pub(crate) fn apply_url_scope_filters(args: &ScanArgs, parsed_targets: &mut Vec<Target>) {
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
}

/// Drop targets whose host matches `--out-of-scope` / `--out-of-scope-file`.
pub(crate) fn apply_out_of_scope_filter(args: &ScanArgs, parsed_targets: &mut Vec<Target>) {
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
}

/// Apply `--cookie-from-raw`: lift the `Cookie` header out of a saved raw HTTP
/// request and attach it to every resolved target.
///
/// Non-fatal by design as it stands: an unreadable file prints to stderr (and
/// says nothing at all under `--silence`), then the scan proceeds *without the
/// cookies* — i.e. logged out, which typically reports `0 XSS` and exits 0. A
/// CI gate cannot tell that apart from a clean target. Preserved here because
/// changing it changes exit codes; worth revisiting on its own.
fn load_cookies_from_raw_http(args: &ScanArgs, parsed_targets: &mut [Target]) {
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
                    for target in parsed_targets.iter_mut() {
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
}

/// Decide which input mode a bare `dalfox scan …` is really asking for.
///
/// `--input-type` other than `auto` is taken at its word. Otherwise the shape
/// of the arguments and of stdin decides: no positional targets plus a piped
/// stdin means a list (or a HAR) is arriving on the pipe; a single argument
/// that looks like a path is sniffed to tell a raw HTTP request and a HAR
/// document apart from a line-based URL list.
///
/// `buffered_stdin` is an out-parameter on purpose: stdin can be read only
/// once, so when detection has to peek at the stream it hands the bytes back
/// for the parsing phase to reuse rather than reading an already-drained fd.
fn detect_input_type(
    args: &ScanArgs,
    stdin_is_piped: bool,
    buffered_stdin: &mut Option<String>,
) -> Result<String, ScanOutcome> {
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
                        *buffered_stdin = Some(buf);
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
    Ok(input_type)
}
