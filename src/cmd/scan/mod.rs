//! `dalfox scan` command.
//!
//! `run_scan` is the orchestrator; the surrounding concerns live in focused
//! submodules so this file stays a readable sequence of stages:
//! - [`args`] — `ScanArgs` CLI surface, default/cap constants, value parsers
//! - [`validation`] — numeric arg checks + input-shape heuristics
//! - [`input`] — target resolution (input-type, file/stdin/raw-HTTP, dedup, scope filters)
//! - [`preflight`] — content-type / CSP / WAF preflight + reqwest classification
//! - [`session`] — authenticated-state fingerprint + mid-scan session-loss detection
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
mod baseline;
mod input;
mod logging;
mod output;
mod poc;
mod postprocess;
mod preflight;
mod scan_loop;
pub(crate) mod session;
mod state_file;
mod validation;

pub use args::{
    BASELINE_MODE_VALUES, BlindOobArgs, CLI_MAX_DELAY_MS, CLI_MAX_RATE_LIMIT, CLI_MAX_RETRIES,
    CLI_MAX_RETRY_DELAY_MS, CLI_MAX_TIMEOUT_SECS, CLI_MAX_WORKERS, CUSTOM_ALERT_TYPE_VALUES,
    DEDUP_URLS_VALUES, DEFAULT_DEDUP_URLS, DEFAULT_DELAY_MS, DEFAULT_ENCODERS,
    DEFAULT_MAX_CONCURRENT_TARGETS, DEFAULT_MAX_TARGETS_PER_HOST, DEFAULT_METHOD,
    DEFAULT_PAYLOAD_SAFETY_CAP, DEFAULT_RATE_LIMIT, DEFAULT_RETRIES, DEFAULT_RETRY_DELAY_MS,
    DEFAULT_TIMEOUT_SECS, DEFAULT_WAF_MIN_CONFIDENCE, DEFAULT_WORKERS, ENCODER_VALUES,
    FORMAT_VALUES, LIMIT_RESULT_TYPE_VALUES, ON_SESSION_LOSS_VALUES, ONLY_POC_VALUES,
    POC_TYPE_VALUES, PreflightOptions, ScanArgs, WAF_BYPASS_VALUES,
};
pub(crate) use args::{parse_force_waf_arg, parse_http_method_arg};
pub(crate) use logging::{log_info, log_warn};
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
    /// Authenticated-state fingerprint per target URL, captured during
    /// preflight and re-probed by the scan loop. Absent for targets with no
    /// credentials (session monitoring is off there, and costs nothing).
    pub(crate) session_baselines: Arc<Mutex<HashMap<String, session::SessionBaseline>>>,
    /// Targets whose session was observed to die, mapped to the human-readable
    /// signal that fired. Drives the `incomplete` / `SESSION_LOST` status in
    /// the meta envelope and the non-zero exit code, so "0 findings" can be
    /// told apart from "0 findings because we were logged out".
    pub(crate) session_lost: Arc<Mutex<HashMap<String, String>>>,
    pub(crate) multi_pb: Option<Arc<MultiProgress>>,
    pub(crate) preflight_idx: Arc<AtomicUsize>,
    pub(crate) analyze_idx: Arc<AtomicUsize>,
    pub(crate) scan_idx: Arc<AtomicUsize>,
    pub(crate) overall_done: Arc<AtomicUsize>,
    pub(crate) total_targets: usize,
    pub(crate) spinner_allowed: bool,
    pub(crate) no_color: bool,
    /// What `--dedup-urls` collapsed during target resolution, reported in the
    /// scan-meta envelope so a run that dropped targets is never mistaken for
    /// full coverage of the input list.
    pub(crate) dedup: input::DedupStats,
    /// `--state-file` handle, when resume is on. Written by the scanning loop
    /// as each target reaches a terminal state, and read at meta-envelope time
    /// for the resume block.
    pub(crate) state_file: Option<Arc<state_file::StateFile>>,
    /// Targets this run skipped because a previous run recorded them
    /// `completed`. Reported alongside the dedup counts for the same reason:
    /// a partial re-run must never read as full coverage of the input list.
    pub(crate) resumed_skipped: usize,
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

/// Cross-cutting preamble shared by every scan entry point (`scan`, the bare
/// no-subcommand path, and the `url`/`file`/`pipe` subcommands) so they behave
/// identically. Without one shared spot the convenience subcommands silently
/// diverged — they used to skip config overlay and `--include-all` entirely.
///
/// Order matters: fold the global `--no-color`/`--silence` (clap may land them
/// on either the root `Cli` or the subcommand's `ScanArgs`) *before* the config
/// overlay, so `apply_to_scan_args_if_default` sees them as already-set when
/// deciding precedence; expand `--include-all` *after*, so a config-supplied
/// `include_all` is honored too.
pub fn finalize_scan_args(
    mut args: ScanArgs,
    cli_no_color: bool,
    cli_silence: bool,
    config: Option<&crate::config::Config>,
) -> ScanArgs {
    args.no_color = args.no_color || cli_no_color;
    args.silence = args.silence || cli_silence;
    if let Some(cfg) = config {
        cfg.apply_to_scan_args_if_default(&mut args);
    }
    if args.include_all {
        args.include_request = true;
        args.include_response = true;
    }
    args
}

/// Whether findings stream out mid-scan: opt-in via `--stream-findings`, plain
/// format only, and disabled whenever another flag applies an end-of-scan
/// transform the streamer cannot replicate.
///
/// The streamer prints a finding the moment it is recorded, before any
/// end-of-scan stage runs. So every flag that *removes or re-counts* findings
/// afterwards has to switch it off, or the live output contradicts the summary
/// and the exit code. `--baseline` is in that set for the same reason as
/// `--only-poc`: the streamer has no way to know a finding is already in the
/// baseline, so it would print every triaged finding's full POC block mid-scan
/// while the summary reports only the new ones.
pub(crate) fn stream_findings_enabled(args: &ScanArgs) -> bool {
    args.format == "plain"
        && args.stream_findings
        && args.output.is_none()
        && args.limit.is_none()
        && args.only_poc.is_empty()
        && args.baseline.is_none()
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

    // Validate the session-check inputs up front. Both are consulted only when
    // a probe fires — potentially an hour into the scan — so a bad regex or a
    // malformed probe URL must fail here, not there.
    if let Err(e) = session::compile_session_check(args) {
        emit_error(
            &args.format,
            crate::cmd::error_codes::PARSE_ERROR,
            &format!("--session-check is not a valid regex: {e}"),
        );
        return ScanOutcome::Error;
    }
    if let Some(u) = &args.session_check_url
        && url::Url::parse(u).is_err()
    {
        emit_error(
            &args.format,
            crate::cmd::error_codes::PARSE_ERROR,
            &format!("--session-check-url is not a valid absolute URL: {u}"),
        );
        return ScanOutcome::Error;
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

    // Load `--baseline` before any request goes out. A stale or malformed
    // baseline path is exactly the thing a pipeline gets wrong, and finding
    // out after a 20-minute scan is too late — so the warning lands here, on
    // stderr (every format; stdout stays a clean machine payload) rather than
    // through log_warn, which only speaks in `plain`.
    let baseline = args.baseline.as_ref().map(|path| {
        // `--output` pointed at the baseline overwrites it with this run's
        // report. Under the default `filter` mode that report holds only the
        // NEW findings, so the recorded backlog is destroyed and the next run
        // re-reports all of it. Refreshing a baseline means re-running WITHOUT
        // `--baseline`; warn rather than refuse, since `annotate` mode writes a
        // complete report and is a legitimate way to do it.
        if args.output.as_deref() == Some(path.as_str()) {
            eprintln!(
                "Warning: --output and --baseline are the same path ('{}'); under --baseline-mode filter this overwrites the baseline with new findings only. Re-run without --baseline to refresh it.",
                path
            );
        }
        // `--limit` stops the scan once N findings accrue, and that count is
        // taken before the baseline diff runs. A target whose first N findings
        // are all already known therefore halts early and reports zero new
        // findings without having tested the rest of its parameters.
        if args.limit.is_some() {
            eprintln!(
                "Warning: --limit counts findings before the --baseline diff, so a run whose first {} findings are all in the baseline stops early and reports 0 new. Drop --limit when gating on new findings.",
                args.limit.unwrap_or(0)
            );
        }
        let loaded = baseline::load(path, args.baseline_mode());
        match &loaded.warning {
            Some(w) => eprintln!("Warning: {} — baseline diff disabled", w),
            None => log_info(
                args,
                &format!(
                    "baseline loaded: {} known findings from {}",
                    loaded.entries, path
                ),
            ),
        }
        loaded
    });

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
    let (mut parsed_targets, dedup) = match input::resolve_targets(args).await {
        Ok(resolved) => (resolved.targets, resolved.dedup),
        Err(outcome) => return outcome,
    };

    // `--state-file`: drop targets a previous run already finished. Opened
    // before any attack traffic goes out — a path that cannot be written is
    // reported now rather than after a two-hour scan that recorded nothing.
    //
    // The preview modes open it read-only: they filter their plan through the
    // recorded completions, but they scan nothing, so they must not create the
    // file or set it aside on a configuration change. Pricing out a different
    // flag set with `--dry-run` is exactly when an operator would otherwise
    // lose a campaign's progress to a hash mismatch.
    let preview_only = args.dry_run || args.only_discovery;
    let state_file = match args.state_file.as_deref() {
        Some(path) => {
            let opened = if preview_only {
                state_file::StateFile::open_read_only(path, args)
            } else {
                state_file::StateFile::open(path, args)
            };
            match opened {
                Ok(sf) => Some(Arc::new(sf)),
                Err(e) => {
                    if !args.silence {
                        emit_error(&args.format, crate::cmd::error_codes::FILE_READ_ERROR, &e);
                    }
                    return ScanOutcome::Error;
                }
            }
        }
        None => None,
    };
    let mut resumed_skipped = 0usize;
    if let Some(sf) = &state_file {
        // Both of these go to stderr for every format: a reset silently
        // discards recorded progress, and unreadable lines are the difference
        // between "nothing was completed" and "we cannot tell what was".
        if let Some(reason) = &sf.reset_reason {
            match (&sf.reset_backup, preview_only) {
                (Some(backup), _) => eprintln!(
                    "Warning: {} — starting fresh (previous state kept at '{}')",
                    reason, backup
                ),
                // Read-only: the plan below ignores the recorded completions,
                // but the file itself is untouched and a real scan would be
                // the one to set it aside.
                (None, true) => eprintln!(
                    "Warning: {} — this preview ignores the recorded state (the file is left untouched)",
                    reason
                ),
                (None, false) => eprintln!("Warning: {} — starting fresh", reason),
            }
        }
        if sf.corrupt_lines > 0 {
            eprintln!(
                "Warning: --state-file '{}': {} unreadable line(s) skipped (expected at most one after a hard kill)",
                sf.path(),
                sf.corrupt_lines
            );
        }
        let before = parsed_targets.len();
        parsed_targets.retain(|t| !sf.is_completed(t.url.as_str(), &t.method));
        resumed_skipped = before - parsed_targets.len();
        // Report both numbers when they differ: a file holding 5000
        // completions that matches 3 of this run's targets means the input
        // list changed, and the operator should hear that from the scanner
        // rather than infer it from a suspiciously short run.
        let recorded = sf.completed_count();
        let unmatched = if recorded > resumed_skipped {
            format!(
                " ({} recorded completion(s) are not in this run's input)",
                recorded - resumed_skipped
            )
        } else {
            String::new()
        };
        if resumed_skipped > 0 {
            log_info(
                args,
                &format!(
                    "resume: {} target(s) already completed per {}, {} left to scan{}",
                    resumed_skipped,
                    sf.path(),
                    parsed_targets.len(),
                    unmatched
                ),
            );
        } else if recorded > 0 {
            log_info(
                args,
                &format!(
                    "resume: none of this run's targets match the {} completion(s) recorded in {} — scanning all of them",
                    recorded,
                    sf.path()
                ),
            );
        }
        // Every target already done is a legitimate, successful end state, not
        // an empty input: the run below renders a normal (zero-finding) report
        // and exits clean rather than tripping the NO_TARGETS error path.
        if parsed_targets.is_empty() && resumed_skipped > 0 {
            log_info(args, "resume: nothing left to scan");
        }
    }

    let results = Arc::new(Mutex::new(Vec::<Result>::new()));
    let findings_count = Arc::new(AtomicUsize::new(0));

    // Per-target tracking for structured output (target_summary in JSON envelope)
    // Collect all target URLs that will be scanned, then track status per target.
    //
    // Distinct URLs only. Every downstream side map (`skipped_targets`,
    // `target_meta`, finding attribution) is keyed by URL string, so a repeated
    // URL — possible since `--dedup-urls off` — would emit one summary entry per
    // occurrence, each reporting that URL's *full* finding count and sharing one
    // skip/WAF record. The per-target counts would then no longer sum to
    // `findings_count`.
    let all_target_urls: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        parsed_targets
            .iter()
            .map(|t| t.url.to_string())
            .filter(|u| seen.insert(u.clone()))
            .collect()
    };
    // Insecure-mode diagnostic. By default dalfox builds its HTTP client with
    // `danger_accept_invalid_certs(true)` (the `--insecure` flag, on by
    // default) so self-signed / expired / hostname-mismatch certs are silently
    // trusted. That is intentional for a scanner and already documented on the
    // flag, so warning on every https scan was just noise — the default posture
    // isn't news. Operators triaging a MITM/TLS scenario can still surface it
    // with `--debug`, where it lands as a DBG line for any https target in
    // insecure mode. When validation is opted into (`--insecure=false`), nothing
    // is emitted. `dbg_log!` ignores `--silence` (it gates on `--debug` only) and
    // writes to stderr, so a deliberately-quiet or JSON scan still shows it under
    // debug without polluting structured stdout.
    if args.insecure.unwrap_or(true)
        && parsed_targets
            .iter()
            .any(|t| t.url.scheme().eq_ignore_ascii_case("https"))
    {
        crate::dbg_log!(
            "TLS validation disabled (--insecure default); use --insecure=false to enforce"
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
    // Session-loss detection state (issue #1273). Both maps stay empty for
    // unauthenticated scans — `session::monitoring_enabled` gates population.
    let session_baselines: Arc<Mutex<HashMap<String, session::SessionBaseline>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let session_lost: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

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
        session_baselines,
        session_lost,
        multi_pb,
        preflight_idx,
        analyze_idx,
        scan_idx,
        overall_done,
        total_targets,
        spinner_allowed,
        no_color: nc,
        dedup,
        state_file,
        resumed_skipped,
    };

    // Blind XSS: the static `-b/--blind` callback and/or OOB/OAST (interactsh)
    // callbacks. Skipped in preview-only modes — `--dry-run` (which advertises
    // "without sending attack payloads") and `--only-discovery` — because blind
    // payloads are real attack traffic and OOB registration is an outbound side
    // effect to a third-party server.
    //
    // Start an OOB session first — it fails soft (warn + continue), so a
    // registration outage never aborts the scan. Injection then runs over
    // whichever channel(s) are configured; the OOB poller is spawned once
    // `stream_findings_enabled` is known (below) and drained before rendering.
    let blind_active = !args.dry_run && !args.only_discovery;
    let oob_session: Option<Arc<crate::oob::OobSession>> =
        if blind_active && args.blind_oob_enabled() {
            match crate::oob::OobSession::start(&args.oob_config()).await {
                Ok(session) => {
                    log_info(
                        args,
                        &format!(
                            "OOB blind XSS armed via interactsh server: {}",
                            session.server_domain()
                        ),
                    );
                    Some(Arc::new(session))
                }
                Err(e) => {
                    log_warn(
                        args,
                        &format!("--blind-oob disabled (could not register with any server): {e}"),
                    );
                    None
                }
            }
        } else {
            None
        };

    if blind_active && (args.blind_callback_url.is_some() || oob_session.is_some()) {
        if let Some(callback_url) = &args.blind_callback_url {
            log_info(
                args,
                &format!(
                    "Performing blind XSS scanning with callback URL: {}",
                    callback_url
                ),
            );
        }
        let custom = args.custom_blind_xss_payload.as_deref();
        for group in host_groups.values() {
            for target in group {
                let source = match (&args.blind_callback_url, &oob_session) {
                    (Some(url), Some(session)) => crate::scanning::CallbackSource::Both {
                        url: url.as_str(),
                        session: session.as_ref(),
                    },
                    (Some(url), None) => crate::scanning::CallbackSource::Static(url.as_str()),
                    (None, Some(session)) => crate::scanning::CallbackSource::Oob(session.as_ref()),
                    // Guarded by the enclosing `if`: at least one is Some.
                    (None, None) => continue,
                };
                crate::scanning::blind_scanning_with(target, source, custom).await;
                crate::scanning::blind_scan_forms_with(target, source, custom).await;
            }
        }
    }

    // Targets entering preflight, so the ones it drops can be told apart from
    // the ones that go on to be scanned. Only materialized when `--state-file`
    // is on — on a 50k-URL list this is two strings per target.
    let pre_preflight_keys: Vec<(String, String)> = if state.state_file.is_some() {
        host_groups
            .values()
            .flatten()
            .map(|t| (t.url.to_string(), t.method.clone()))
            .collect()
    } else {
        Vec::new()
    };

    // Preflight + parameter analysis for every target (bounded concurrency);
    // replaces each host group with the targets that survived preflight.
    analysis::run_preflight_and_analysis(args, &mut host_groups, &state).await;

    // Record the targets preflight dropped (unreachable, content-type
    // mismatch, per-host cap) as `error`. They are retried on the next run —
    // the point is that the state file accounts for every target it saw,
    // rather than leaving a silent gap between the input list and the
    // completions. Skipped in the preview modes below, which send no attack
    // traffic and so complete nothing.
    if let Some(sf) = &state.state_file
        && !args.dry_run
        && !args.only_discovery
    {
        let survived: std::collections::HashSet<String> = host_groups
            .values()
            .flatten()
            .map(|t| state_file::target_key(t.url.as_str(), &t.method))
            .collect();
        for (url, method) in &pre_preflight_keys {
            if !survived.contains(&state_file::target_key(url, method)) {
                sf.record(url, method, state_file::TargetOutcome::Error);
            }
        }
    }

    // --dry-run: report what would be scanned without sending attack payloads.
    if args.dry_run {
        return output::render_dry_run(args, &host_groups, &state).await;
    }

    // --only-discovery: print discovered params and exit early.
    if args.only_discovery {
        return output::render_only_discovery(args, &host_groups, &state);
    }

    // Computed once here so the scan loop and the end-of-scan renderer agree on
    // whether streaming ran.
    let stream_findings_enabled = stream_findings_enabled(args);

    // Spawn the OOB poller now that we know whether streaming is on. It writes
    // correlated callbacks straight into the shared results vector and runs
    // until `finish()` drains the grace window (below).
    let oob_poller = oob_session.as_ref().map(|session| {
        crate::oob::spawn_poller(
            session.clone(),
            state.results.clone(),
            state.findings_count.clone(),
            cancel_flag.clone(),
            args.silence,
        )
    });

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

    // Drain late OOB callbacks (they arrive seconds-to-minutes after delivery),
    // then deregister. A pending Ctrl-C shortens the wait. Findings land in
    // `state.results` before rendering below.
    if let Some(poller) = oob_poller {
        let wait = Duration::from_secs(args.blind_oob_wait());
        if wait.as_secs() > 0 {
            log_info(
                args,
                &format!("Waiting up to {}s for OOB callbacks...", wait.as_secs()),
            );
        }
        poller.finish(wait).await;
    }

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
    let (final_results, output_write_failed) = output::render_results(
        args,
        &state,
        &all_target_urls,
        scan_elapsed,
        total_requests,
        stream_findings_enabled,
        baseline.as_ref(),
    )
    .await;

    // Request/Response are displayed inline under each POC in plain mode.
    if args.format == "plain" && !args.silence {
        let __dalfox_elapsed = __dalfox_scan_start.elapsed().as_secs_f64();
        log_info(
            args,
            &format!("scan completed in {:.3} seconds", __dalfox_elapsed),
        );
        crate::dbg_log!(
            "{} test cases (reqs) sent",
            crate::REQUEST_COUNT.load(Ordering::Relaxed)
        );
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

    // An empty report after a dead session must not exit 0 — `dalfox scan ... &&
    // echo "no XSS found"` is exactly the script this issue is about. Under
    // `--on-session-loss continue` the operator has said the detection may be
    // misfiring on their target and asked to keep going, so the exit code is
    // left alone; the `incomplete` meta flag and the per-target SESSION_LOST
    // entries still record what happened either way.
    //
    // Gated on there being no findings: a run that confirmed a `V` and *then*
    // lost its session should exit 1 (vulnerabilities found), not 2 (hard
    // error). CI that separates those two — a distinction the output guide
    // documents — would otherwise read a successful detection as an
    // infrastructure failure. `meta.incomplete` carries the incompleteness for
    // both codes.
    if final_results.is_empty()
        && session::aborts_on_loss(args)
        && !state.session_lost.lock().await.is_empty()
    {
        return ScanOutcome::Error;
    }

    // A requested `--output` file that couldn't be written is a hard failure,
    // same as an all-unreachable run: the operator asked for results on disk and
    // didn't get them. Report it via the exit code so scripts don't read it as a
    // clean/successful pass.
    if output_write_failed {
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
