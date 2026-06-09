//! `dalfox scan` command.
//!
//! `run_scan` is the orchestrator; the surrounding concerns live in focused
//! submodules so this file stays a readable sequence of stages:
//! - [`args`] — `ScanArgs` CLI surface, default/cap constants, value parsers
//! - [`validation`] — numeric arg checks + input-shape heuristics
//! - [`input`] — target resolution (input-type, file/stdin/raw-HTTP, dedup, scope filters)
//! - [`preflight`] — content-type / CSP / WAF preflight + reqwest classification
//! - [`analysis`] — per-target preflight + parameter-analysis loop
//! - [`scan_loop`] — per-host scanning loop + mid-scan finding streaming
//! - [`output`] — dry-run / only-discovery / end-of-scan result rendering
//! - [`poc`] — curl / httpie / plain POC + finding-block rendering
//! - [`postprocess`] — dedupe / priority / context extraction
//! - [`logging`] — plain-mode log lines + ephemeral progress spinner

use indicatif::MultiProgress;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};

use crate::scanning::result::Result;
use crate::target_parser::*;

mod analysis;
mod args;
mod input;
mod logging;
mod output;
mod poc;
mod postprocess;
mod preflight;
mod scan_loop;
mod validation;

pub use args::{
    CLI_MAX_DELAY_MS, CLI_MAX_RATE_LIMIT, CLI_MAX_RETRIES, CLI_MAX_RETRY_DELAY_MS,
    CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, DEFAULT_DELAY_MS, DEFAULT_ENCODERS,
    DEFAULT_MAX_CONCURRENT_TARGETS, DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD,
    DEFAULT_RATE_LIMIT, DEFAULT_RETRIES, DEFAULT_RETRY_DELAY_MS, DEFAULT_TIMEOUT_SECS,
    DEFAULT_WAF_MIN_CONFIDENCE, DEFAULT_WORKERS, PreflightOptions, ScanArgs,
};
pub(crate) use logging::{log_dbg, log_info, log_warn};
pub(crate) use validation::validate_numeric_args;

static GLOBAL_ENCODERS: OnceLock<Vec<String>> = OnceLock::new();

/// Outcome of a scan run, used to determine CLI exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Scan completed successfully, no findings.
    Clean,
    /// Scan completed successfully, one or more findings.
    Findings,
    /// Scan failed due to input, configuration, or runtime error.
    Error,
}

/// Shared scan state threaded through the preflight/analysis loop
/// ([`analysis`]), the scanning loop ([`scan_loop`]), and result rendering
/// ([`output`]). Bundles the cross-task `Arc` handles plus the few scalars the
/// stages need so each stage takes a single `&ScanState` instead of a dozen
/// parameters. Each stage rebinds the fields to owned locals up front, so the
/// moved-out stage bodies stay verbatim from the pre-split `run_scan`.
pub(crate) struct ScanState {
    pub(crate) results: Arc<Mutex<Vec<Result>>>,
    pub(crate) findings_count: Arc<AtomicUsize>,
    pub(crate) skipped_targets: Arc<Mutex<HashMap<String, &'static str>>>,
    pub(crate) target_meta: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    pub(crate) target_mutation_stats:
        Arc<Mutex<HashMap<String, Arc<crate::waf::bypass::MutationStats>>>>,
    pub(crate) multi_pb: Option<Arc<MultiProgress>>,
    pub(crate) preflight_idx: Arc<AtomicUsize>,
    pub(crate) analyze_idx: Arc<AtomicUsize>,
    pub(crate) scan_idx: Arc<AtomicUsize>,
    pub(crate) overall_done: Arc<AtomicUsize>,
    pub(crate) total_targets: usize,
    pub(crate) spinner_allowed: bool,
    pub(crate) no_color: bool,
}

/// Emit a structured error to stderr when format is json/jsonl, otherwise plain eprintln.
fn emit_error(format: &str, code: &str, message: &str) {
    if format == "json" || format == "jsonl" {
        let err = serde_json::json!({
            "error": true,
            "code": code,
            "message": message
        });
        if format == "json" {
            eprintln!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
        } else {
            eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
        }
    } else {
        eprintln!("Error: {}", message);
    }
}

/// Run a scan and return the outcome: `Clean` (no findings), `Findings`, or `Error`.
pub async fn run_scan(args: &ScanArgs) -> ScanOutcome {
    // Compute no-color locally (safe for concurrent server-mode scans)
    let nc = args.no_color || std::env::var("NO_COLOR").is_ok();
    if nc {
        crate::NO_COLOR.store(true, Ordering::Relaxed);
    }

    // Show banner at the start when using plain format and not silenced
    if args.format == "plain" && !args.silence {
        crate::utils::print_banner_once(env!("CARGO_PKG_VERSION"), !nc);
    }
    let __dalfox_scan_start = std::time::Instant::now();
    crate::REQUEST_COUNT.store(0, Ordering::Relaxed);

    // SIGINT (Ctrl-C) handler: dogfood found that long scans ignored the
    // signal entirely, requiring SIGTERM/SIGKILL to stop. Plumb a shared
    // cancel flag from here all the way down to `run_scanning`, then
    // listen for SIGINT on a background task and flip it. The scanning
    // loop polls this flag at safe points and exits cleanly. A second
    // SIGINT exits immediately (escape hatch for hung tasks).
    let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let cf = cancel_flag.clone();
        let silence = args.silence;
        tokio::spawn(async move {
            // First Ctrl-C: graceful — set the flag and let the scan
            // loop drain in-flight requests at the next checkpoint.
            // Message goes to stderr so it never pollutes the JSON /
            // JSONL / SARIF / TOML payload on stdout. Honor --silence
            // explicitly.
            if tokio::signal::ctrl_c().await.is_ok() {
                if !silence {
                    eprintln!(
                        "\n[!] Ctrl-C received — stopping in-flight tasks (press again to force exit)"
                    );
                }
                cf.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            // Second Ctrl-C: hard exit so a hung HTTP request can't
            // strand the user. Use process::exit so we skip any
            // outstanding awaits.
            if tokio::signal::ctrl_c().await.is_ok() {
                if !silence {
                    eprintln!("[!] Second Ctrl-C — exiting now");
                }
                std::process::exit(130); // 128 + SIGINT(2)
            }
        });
    }
    // Whether ephemeral spinners may render at all: only on an interactive
    // stdout TTY and when not silenced. Individual call sites still gate on
    // their own `enabled` (e.g. single-target runs only). The actual spinner
    // lives in `logging::start_spinner`, along with the log_* helpers that
    // were closures here before the module split.
    let spinner_allowed = crate::utils::term::stdout_is_tty() && !args.silence;
    // Initialize global encoders once for downstream POC/path handling
    if GLOBAL_ENCODERS.get().is_none() {
        let _ = GLOBAL_ENCODERS.set(args.encoders.clone());
    }
    // Validate numeric args up front so misconfigurations (workers: 0,
    // max_targets_per_host: 0, absurd timeouts) fail fast with a clear
    // message instead of producing cryptic mid-scan failures.
    if let Err((code, msg)) = validate_numeric_args(args) {
        if !args.silence {
            emit_error(&args.format, code, &msg);
        }
        return ScanOutcome::Error;
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
                    return ScanOutcome::Error;
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
                    return ScanOutcome::Error;
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
                        return ScanOutcome::Error;
                    }
                    log_warn(args, &format!("{} — built-in payloads only", e));
                }
            }
        }
    }

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
    // Resolve targets: input-type detection, file/stdin/raw-HTTP parsing,
    // dedup, scope + out-of-scope filtering, and --cookie-from-raw. Emits the
    // structured error itself on failure and returns Err for us to propagate.
    let parsed_targets = match input::resolve_targets(args).await {
        Ok(targets) => targets,
        Err(outcome) => return outcome,
    };

    let results = Arc::new(Mutex::new(Vec::<Result>::new()));
    let findings_count = Arc::new(AtomicUsize::new(0));

    // Per-target tracking for structured output (target_summary in JSON envelope)
    // Collect all target URLs that will be scanned, then track status per target.
    let all_target_urls: Vec<String> = parsed_targets.iter().map(|t| t.url.to_string()).collect();
    // One-shot insecure-mode warning. By default dalfox builds its HTTP client
    // with `danger_accept_invalid_certs(true)` (the `--insecure` flag, on by
    // default) so self-signed / expired / hostname-mismatch certs are silently
    // trusted. That is intentional for a scanner but ops triaging a MITM
    // scenario need a signal — print one warning per scan when any https://
    // target is present AND insecure mode is active. When the operator opts
    // into validation (`--insecure=false`), no warning is emitted.
    // Security note must reach the operator even with `--silence` —
    // silencing is for stdout, this is stderr and tells them about a
    // deliberate but consequential TLS posture.
    if args.insecure.unwrap_or(true)
        && parsed_targets
            .iter()
            .any(|t| t.url.scheme().eq_ignore_ascii_case("https"))
    {
        eprintln!(
            "Warning: TLS certificate validation is disabled (--insecure, on by default); self-signed, expired, or hostname-mismatched certs will be silently trusted. Use --insecure=false to enforce validation."
        );
    }
    // Track targets that were skipped during preflight (content-type mismatch etc.)
    // Map of skipped target URL -> error code explaining why it was skipped.
    // Used by target_summary to surface skips (content-type mismatch, per-host
    // truncation, etc.) instead of silently marking them clean.
    let skipped_targets: Arc<Mutex<HashMap<String, &'static str>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Per-target preflight metadata serialized once during preflight, read at
    // target_summary build time. Populated from `target.waf_info` and the
    // applied bypass strategy. JSON/JSONL consumers can't otherwise see what
    // WAF was detected — that information only reached the plain-mode log.
    let target_meta: Arc<Mutex<HashMap<String, serde_json::Value>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Side map of WAF-bypass effectiveness counters, alive across the
    // scanning loop and read at target_summary build time. The Arc is
    // shared with `target.mutation_stats`; both increment the same
    // counters via the MutationStats methods.
    let target_mutation_stats: Arc<Mutex<HashMap<String, Arc<crate::waf::bypass::MutationStats>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Enable the indicatif progress UI (per-target bar + per-host overall bar)
    // when running interactive plain output. Indicatif writes to stderr, so
    // JSON/JSONL stdout stays clean; gating on stderr-tty avoids dumping
    // control codes into pipes/logfiles.
    let multi_pb: Option<Arc<MultiProgress>> = if args.format == "plain"
        && !args.silence
        && std::io::IsTerminal::is_terminal(&std::io::stderr())
    {
        Some(Arc::new(MultiProgress::new()))
    } else {
        None
    };

    // Group targets by host
    let mut host_groups: std::collections::HashMap<String, Vec<Target>> =
        std::collections::HashMap::new();
    for target in parsed_targets {
        let host = target.url.host_str().unwrap_or("unknown").to_string();
        host_groups.entry(host).or_default().push(target);
    }

    let total_targets = host_groups.values().map(Vec::len).sum::<usize>();
    let preflight_idx = Arc::new(AtomicUsize::new(0));
    let analyze_idx = Arc::new(AtomicUsize::new(0));
    let scan_idx = Arc::new(AtomicUsize::new(0));
    let overall_done = Arc::new(AtomicUsize::new(0));

    // Start global overall progress ticker when multiple targets; runs across preflight, analysis, and scanning.
    // Suppressed when stdout isn't a TTY — cursor-redraw frames look like garbage in logs.
    let overall_ticker = if args.format == "plain"
        && !args.silence
        && total_targets > 1
        && crate::utils::term::stdout_is_tty()
    {
        let findings_count_clone = findings_count.clone();
        let overall_done_clone = overall_done.clone();
        let total_targets_copy = total_targets;
        let (tx, mut rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            use crate::utils::shimmer;
            let mut phase = 0usize;
            loop {
                let done = overall_done_clone.load(Ordering::Relaxed);
                let percent = (done * 100) / std::cmp::max(1, total_targets_copy);
                let findings = findings_count_clone.load(Ordering::Relaxed);
                let text = format!(
                    "overall  {done}/{total_targets_copy} targets · {percent}% · {findings} findings"
                );
                // Truncate to the terminal width (reserving the glyph + space)
                // and clear to EOL so the metallic line never wraps onto a
                // second row, which would desync the `\r` redraw.
                let budget = crate::utils::term::term_cols().saturating_sub(2).max(8);
                let visible = console::truncate_str(&text, budget, "…");
                crate::cprint!(
                    "\r{} {}\x1b[K",
                    shimmer::spin_glyph(phase),
                    shimmer::shimmer(visible.as_ref(), phase)
                );
                let _ = io::stdout().flush();
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(shimmer::FRAME_MS as u64)) => {},
                    _ = &mut rx => {
                        // clear the line and exit
                        crate::cprint!("\r\x1b[2K\r");
                        let _ = io::stdout().flush();
                        let _ = done_tx.send(());
                        break;
                    }
                }
                phase = phase.wrapping_add(1);
            }
        });
        Some((tx, done_rx))
    } else {
        None
    };

    // Bundle the cross-task handles for the preflight/analysis loop, the
    // scanning loop, and result rendering. `host_groups`, `all_target_urls`,
    // `overall_ticker`, and `cancel_flag` stay as `run_scan` locals (passed
    // explicitly) because their lifetimes/ownership differ per stage.
    let state = ScanState {
        results,
        findings_count,
        skipped_targets,
        target_meta,
        target_mutation_stats,
        multi_pb,
        preflight_idx,
        analyze_idx,
        scan_idx,
        overall_done,
        total_targets,
        spinner_allowed,
        no_color: nc,
    };

    // Perform blind XSS scanning if callback URL is provided
    if let Some(callback_url) = &args.blind_callback_url {
        if !args.silence && args.format == "plain" {
            println!(
                "Performing blind XSS scanning with callback URL: {}",
                callback_url
            );
        }
        for group in host_groups.values() {
            for target in group {
                crate::scanning::blind_scanning(
                    target,
                    callback_url,
                    args.custom_blind_xss_payload.as_deref(),
                )
                .await;
                crate::scanning::blind_scan_forms(
                    target,
                    callback_url,
                    args.custom_blind_xss_payload.as_deref(),
                )
                .await;
            }
        }
    }

    // Preflight + parameter analysis for every target (bounded concurrency);
    // replaces each host group with the targets that survived preflight.
    analysis::run_preflight_and_analysis(args, &mut host_groups, &state).await;

    // --dry-run: report what would be scanned without sending attack payloads.
    if args.dry_run {
        return output::render_dry_run(args, &host_groups, &state).await;
    }

    // --only-discovery: print discovered params and exit early.
    if args.only_discovery {
        return output::render_only_discovery(args, &host_groups);
    }

    // Streaming finding output: opt-in via `--stream-findings`, plain format
    // only, and disabled when `--output` / `--limit` / `--only-poc` apply an
    // end-of-scan transform the streamer can't replicate. Computed here so the
    // scan loop and the end-of-scan renderer agree on whether streaming ran.
    let stream_findings_enabled = args.format == "plain"
        && args.stream_findings
        && args.output.is_none()
        && args.limit.is_none()
        && args.only_poc.is_empty();

    // Per-host scanning loop: run_scanning for each target under the global
    // concurrency cap, with optional mid-scan finding streaming.
    scan_loop::run_scan_loop(
        args,
        host_groups,
        &state,
        cancel_flag.clone(),
        stream_findings_enabled,
    )
    .await;

    if args.format == "plain" && !args.silence && total_targets > 1 {
        if let Some((tx, done_rx)) = overall_ticker {
            let _ = tx.send(());
            let _ = done_rx.await;
        }
        println!();
    }

    // Output results: dedupe, --only-poc filter, --limit, per-target summary,
    // and format-specific rendering to stdout or --output file.
    let scan_elapsed = __dalfox_scan_start.elapsed();
    let total_requests = crate::REQUEST_COUNT.load(Ordering::Relaxed);
    let final_results = output::render_results(
        args,
        &state,
        &all_target_urls,
        scan_elapsed,
        total_requests,
        stream_findings_enabled,
    )
    .await;

    // Request/Response are displayed inline under each POC in plain mode.
    if args.format == "plain" && !args.silence {
        let __dalfox_elapsed = __dalfox_scan_start.elapsed().as_secs_f64();
        log_info(
            args,
            &format!("scan completed in {:.3} seconds", __dalfox_elapsed),
        );
        if crate::DEBUG.load(Ordering::Relaxed) {
            log_dbg(&format!(
                "{} test cases (reqs) sent",
                crate::REQUEST_COUNT.load(Ordering::Relaxed)
            ));
        }
    }

    // A scan where every supplied target failed reachability checks
    // (DNS lookup failure, connection refused, content-type mismatch,
    // etc.) used to fall through to `ScanOutcome::Clean` here — same
    // exit code 0 as "scanned and found nothing." That silently masked
    // hard failures from scripts like
    //   `dalfox scan https://target && echo "no XSS found"`,
    // so the operator could read a downed server or typo'd host as a
    // clean pass. Treat the all-skipped case as an error instead; if
    // even one target produced any scan activity (even with zero
    // findings) the outcome falls through to Clean as before.
    let all_unreachable = !all_target_urls.is_empty() && {
        let skipped = state.skipped_targets.lock().await;
        !skipped.is_empty() && all_target_urls.iter().all(|u| skipped.contains_key(u))
    };
    if all_unreachable {
        return ScanOutcome::Error;
    }

    if final_results.is_empty() {
        ScanOutcome::Clean
    } else {
        ScanOutcome::Findings
    }
}

#[cfg(test)]
mod tests;
