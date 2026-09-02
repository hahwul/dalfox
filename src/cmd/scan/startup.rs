//! Everything `run_scan` does before the first target is resolved: the
//! startup validation gate, and remote payload/wordlist provider setup.
//!
//! These share a deadline rather than a topic — each one has to happen before
//! any request goes out, because each failure it catches is otherwise
//! discovered mid-scan, where it reads as a *result* rather than a mistake.

use std::fs;

use super::args::ScanArgs;
use super::logging::log_warn;
use super::validation::{validate_http_url, validate_numeric_args, validate_proxy_url};
use super::{ScanOutcome, emit_error, session};

/// Everything that must hold — and be installed — before the first request
/// goes out: numeric ranges, the session-check inputs, the `--session-check-url`
/// / `--sxss-url` / `--proxy` URL shapes, and the custom-payload file, plus the
/// process-wide rate limiter.
///
/// These are grouped because they share one property: each failure they catch
/// is otherwise discovered *mid-scan*, where it reads as a result rather than a
/// mistake. An unreadable `--custom-payload` under `--only-custom-payload`
/// sends zero attack payloads and prints `0 XSS`, which is exactly what a CI
/// gate treats as a clean target; a bad `--session-check` regex only fires when
/// a probe does, potentially an hour in; a `--proxy` reqwest can't route sends
/// the whole scan DIRECT with nothing said.
///
/// `Err` carries the outcome `run_scan` returns; the error text has already
/// been emitted. Warnings (additive-mode payload problems, an inert `--sxss-url`)
/// are emitted here and do not stop the scan. The order of the checks is
/// load-bearing for what reaches stderr first, so it is preserved exactly as it
/// ran inline.
/// Refuse `-H/--headers`, `--user-agent` and `--cookies` values that cannot do
/// what the operator asked. All three end up as HTTP header values, and both
/// ways they can be wrong used to be silent on the CLI:
///
/// * a spec with no `:` (`-H 'Authorization Bearer eyJ…'` — one missing
///   keystroke) or with an empty name is dropped by the `filter_map` in
///   [`super::input::resolve_targets`], so the scan runs *unauthenticated*
///   against a protected endpoint, finds nothing, and exits clean. That is the
///   same false all-clear `--proxy` and `--custom-payload` are already gated
///   against here.
/// * a byte reqwest cannot put in a header (a pasted CR/LF, a NUL) fails the
///   request *builder* for every request in the run, so the reachability probe
///   fails and a live target is reported `CONNECTION_FAILED` — the scanner
///   blaming the target for the operator's input.
///
/// REST and MCP have refused both at submission since #1404, through these
/// exact helpers (`server::util::validate_scan_options`, the MCP tools); the
/// CLI was the front end that never got the gate. Sharing the validators keeps
/// the three surfaces refusing the same inputs. The helpers build and sanitize
/// the message themselves, so a credential-bearing value cannot leak into a log
/// or forge a line in it; only the flag name is added here.
fn validate_header_inputs(args: &ScanArgs) -> Result<(), String> {
    crate::job::validate_header_list(&args.headers).map_err(|e| format!("--headers: {e}"))?;
    // An empty `--user-agent ""` means "no override" (see `resolve_targets`),
    // not an empty header — the same exemption the REST/MCP validator makes.
    if let Some(ua) = args.user_agent.as_deref().filter(|s| !s.is_empty()) {
        crate::job::validate_header_value("--user-agent", ua)?;
    }
    for cookie in args.cookies.iter().filter(|c| !c.is_empty()) {
        crate::job::validate_header_value("--cookies", cookie)?;
    }
    Ok(())
}

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

    // Header-shaped inputs, refused before the first request rather than
    // discovered as a scan result. See [`validate_header_inputs`].
    if let Err(msg) = validate_header_inputs(args) {
        emit_error(
            &args.format,
            crate::cmd::error_codes::INVALID_INPUT_TYPE,
            &msg,
        );
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

    // `--session-check-url` and `--sxss-url` are each consulted only when a
    // probe / stored-XSS re-check fires — potentially an hour in — and are
    // parsed there with `url::Url::parse(..).ok()`, so a relative, malformed,
    // or non-http value drops out silently: the check the operator asked for
    // never runs. `--proxy` is likewise resolved by the shared client builder
    // with `reqwest::Proxy::all(..).ok()`, so a value reqwest can't route (a
    // typo, or a scheme like `ftp://`/`socks6://` that parses but is silently
    // dropped) sends every request DIRECT to the target — for a pentester
    // routing through Burp/ZAP the attack traffic then leaks outside the
    // intended path and never appears in the intercepting proxy. Validate all
    // three up front with the same parsers the scan uses, so a mistake fails
    // fast with a clear message instead of quietly changing what the scan does.
    // The validators return self-contained messages (the operator-supplied
    // value is never echoed), so a proxy password can't leak and a value with
    // an embedded newline can't forge a log line.
    for checked in [
        args.session_check_url
            .as_deref()
            .map(|u| validate_http_url(u, "--session-check-url")),
        args.sxss_url
            .as_deref()
            .map(|u| validate_http_url(u, "--sxss-url")),
        args.proxy.as_deref().map(validate_proxy_url),
    ] {
        if let Some(Err(msg)) = checked {
            emit_error(&args.format, crate::cmd::error_codes::PARSE_ERROR, &msg);
            return Err(ScanOutcome::Error);
        }
    }

    // `--sxss-url` is read only when `--sxss` is set (see
    // `check_reflection`/`check_dom_verification`, both gated on `if args.sxss`).
    // Supplying the check URL without enabling stored-XSS mode — the single most
    // common way it's misconfigured, since the docs pair the two — otherwise
    // does nothing at all and reports a clean scan. Warn rather than error: it
    // may be a config template that toggles `--sxss` separately, but the
    // operator should hear that the URL is inert.
    if args.sxss_url.is_some() && !args.sxss {
        log_warn(
            args,
            "--sxss-url has no effect without --sxss (stored-XSS mode is off); add --sxss to use it",
        );
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
