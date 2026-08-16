//! Everything `run_scan` does before the first target is resolved: the
//! startup validation gate, and remote payload/wordlist provider setup.
//!
//! These share a deadline rather than a topic — each one has to happen before
//! any request goes out, because each failure it catches is otherwise
//! discovered mid-scan, where it reads as a *result* rather than a mistake.

use std::fs;

use super::args::ScanArgs;
use super::logging::log_warn;
use super::validation::validate_numeric_args;
use super::{ScanOutcome, emit_error, session};

/// Everything that must hold — and be installed — before the first request
/// goes out: numeric ranges, the session-check inputs, and the custom-payload
/// file, plus the process-wide rate limiter.
///
/// These are grouped because they share one property: each failure they catch
/// is otherwise discovered *mid-scan*, where it reads as a result rather than a
/// mistake. An unreadable `--custom-payload` under `--only-custom-payload`
/// sends zero attack payloads and prints `0 XSS`, which is exactly what a CI
/// gate treats as a clean target; a bad `--session-check` regex only fires when
/// a probe does, potentially an hour in.
///
/// `Err` carries the outcome `run_scan` returns; the error text has already
/// been emitted. Warnings (additive-mode payload problems) are emitted here and
/// do not stop the scan. The order of the checks is load-bearing for what
/// reaches stderr first, so it is preserved exactly as it ran inline.
pub(crate) fn prepare_and_validate(args: &ScanArgs) -> Result<(), super::ScanOutcome> {
    // Validate numeric args up front so misconfigurations (workers: 0,
    // max_targets_per_host: 0, absurd timeouts) fail fast with a clear
    // message instead of producing cryptic mid-scan failures.
    if let Err((code, msg)) = validate_numeric_args(args) {
        if !args.silence {
            emit_error(&args.format, code, &msg);
        }
        return Err(ScanOutcome::Error);
    }

    // Install the process-wide request rate limiter (`--rate-limit`, req/sec;
    // 0 = unlimited). Shared across every worker and target so the aggregate
    // outbound rate stays bounded regardless of fan-out. Done before any
    // requests go out (preflight included). Idempotent across CLI invocations.
    crate::install_rate_limiter(args.rate_limit);

    // `--limit-result-type` only affects which finding types count
    // toward `--limit`; without `--limit` it is a no-op. Dogfood
    // showed operators conflating it with `--only-poc`, which IS the
    // output filter, so emit a one-line nudge on stderr when used
    // alone. stderr stays out of the stdout payload that scripts
    // parse.
    if !args.limit_result_type.eq_ignore_ascii_case("all") && args.limit.is_none() {
        eprintln!(
            "Hint: --limit-result-type only affects counting toward --limit; for output filtering use --only-poc {}",
            args.limit_result_type.to_uppercase()
        );
    }

    // Validate the session-check inputs up front. Both are consulted only when
    // a probe fires — potentially an hour into the scan — so a bad regex or a
    // malformed probe URL must fail here, not there.
    if let Err(e) = session::compile_session_check(args) {
        emit_error(
            &args.format,
            crate::cmd::error_codes::PARSE_ERROR,
            &format!("--session-check is not a valid regex: {e}"),
        );
        return Err(ScanOutcome::Error);
    }
    if let Some(u) = &args.session_check_url
        && url::Url::parse(u).is_err()
    {
        emit_error(
            &args.format,
            crate::cmd::error_codes::PARSE_ERROR,
            &format!("--session-check-url is not a valid absolute URL: {u}"),
        );
        return Err(ScanOutcome::Error);
    }

    // `--only-custom-payload` with no `--custom-payload` at all is the same
    // catastrophe as an unreadable file — `get_dynamic_payloads` takes the
    // only-custom branch, finds no file to read, and returns an empty vec, so
    // the reflection phase sends *zero* attack payloads and the run prints
    // `0 XSS` and exits 0. That is indistinguishable from a clean target, which
    // is exactly what a CI gate keys on. The check below only runs inside
    // `if let Some(path)`, so this pairing has to be rejected before it.
    // Reachable from a config file too (`only_custom_payload = true`), which is
    // why `Config::normalize_and_validate` carries the same rule.
    if args.only_custom_payload && args.custom_payload.is_none() {
        emit_error(
            &args.format,
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            "--only-custom-payload requires --custom-payload <FILE>",
        );
        return Err(ScanOutcome::Error);
    }

    // Validate --custom-payload up front. Without this check, a missing or
    // unreadable file silently produces zero custom payloads mid-scan. With
    // --only-custom-payload that's catastrophic (no payloads at all, scan
    // reports clean), so fail fast. In additive mode it just degrades
    // detection, so warn and continue.
    if let Some(path) = &args.custom_payload {
        match fs::metadata(path) {
            Ok(m) if !m.is_file() => {
                if args.only_custom_payload {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::FILE_READ_ERROR,
                        &format!("--custom-payload is not a regular file: {}", path),
                    );
                    return Err(ScanOutcome::Error);
                }
                log_warn(
                    args,
                    &format!(
                        "--custom-payload is not a regular file ({}) — built-in payloads only",
                        path
                    ),
                );
            }
            Err(e) => {
                if args.only_custom_payload {
                    emit_error(
                        &args.format,
                        crate::cmd::error_codes::FILE_READ_ERROR,
                        &format!("--custom-payload not readable ({}): {}", path, e),
                    );
                    return Err(ScanOutcome::Error);
                }
                log_warn(
                    args,
                    &format!(
                        "--custom-payload not readable ({}: {}) — built-in payloads only",
                        path, e
                    ),
                );
            }
            Ok(_) => {
                // The stat above only proves a regular file exists. An empty,
                // comment-only, non-UTF-8, or over-budget file passes it yet
                // yields zero usable payloads — load_custom_payloads rejects
                // those, but the scan driver swallows that error via
                // `.unwrap_or_else(|_| vec![])`, so --only-custom-payload would
                // "succeed" having scanned nothing. Validate the content here
                // (this also warms the shared cache the scan reuses): fatal
                // under --only-custom-payload, a warning in additive mode.
                if let Err(e) = crate::scanning::xss_common::load_custom_payloads(path) {
                    if args.only_custom_payload {
                        emit_error(
                            &args.format,
                            crate::cmd::error_codes::FILE_READ_ERROR,
                            &e.to_string(),
                        );
                        return Err(ScanOutcome::Error);
                    }
                    log_warn(args, &format!("{} — built-in payloads only", e));
                }
            }
        }
    }
    Ok(())
}

/// Fetch the remote payload / wordlist providers named by `--remote-payloads`
/// and `--remote-wordlists`.
///
/// Unknown provider names are warned about *first*, separately: the init call
/// treats them as silent no-ops, so a typo like `payloadboxx` used to fetch
/// nothing and say nothing. A fetch failure is likewise only a warning — the
/// scan continues on built-in payloads.
pub(crate) async fn init_remote_providers(args: &ScanArgs) {
    // Warn loudly about unknown remote-provider names *before* the init
    // call swallows them as silent no-ops. Previously a typo like
    // `--remote-payloads payloadboxx` would just not fetch anything and
    // the user would never know.
    if !args.remote_payloads.is_empty() {
        let known: std::collections::HashSet<String> = crate::payload::list_payload_providers()
            .into_iter()
            .collect();
        for p in &args.remote_payloads {
            if !known.contains(&p.to_ascii_lowercase()) {
                eprintln!(
                    "Warning: unknown --remote-payloads provider '{}' (known: {})",
                    p,
                    crate::payload::list_payload_providers().join(", ")
                );
            }
        }
    }
    if !args.remote_wordlists.is_empty() {
        let known: std::collections::HashSet<String> = crate::payload::list_wordlist_providers()
            .into_iter()
            .collect();
        for p in &args.remote_wordlists {
            if !known.contains(&p.to_ascii_lowercase()) {
                eprintln!(
                    "Warning: unknown --remote-wordlists provider '{}' (known: {})",
                    p,
                    crate::payload::list_wordlist_providers().join(", ")
                );
            }
        }
    }

    // Initialize remote payloads/wordlists if requested (honor timeout/proxy)
    if (!args.remote_payloads.is_empty() || !args.remote_wordlists.is_empty())
        && let Err(e) = crate::utils::init_remote_resources_with_options(
            &args.remote_payloads,
            &args.remote_wordlists,
            Some(args.timeout),
            args.proxy.clone(),
        )
        .await
        && !args.silence
    {
        eprintln!("Error initializing remote resources: {}", e);
    }
}
