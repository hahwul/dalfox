//! The scanning loop. For every host group it spawns bounded per-target
//! `run_scanning` tasks (honoring `--scan-timeout`, `--limit`, SIGINT
//! cancellation, and the optional indicatif overall bar), and runs the
//! mid-scan finding-streaming printer when enabled. Lifted verbatim out of
//! `run_scan`; shared handles arrive via [`ScanState`].

use super::ScanState;
use super::args::ScanArgs;
use super::logging::start_spinner;
use super::poc::render_finding_block;
use crate::target_parser::Target;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Complete once `flag` is observed set. Used to mirror the process-wide
/// SIGINT (Ctrl-C) flag into a per-target cancel flag from inside a
/// `tokio::select!` — `AtomicBool` carries no waker, so a short poll is the
/// cheapest way to notice the flip. The poll only runs while a target's
/// `--scan-timeout` is in effect and stops the moment that target's scan
/// future completes (the `select!` drops this arm).
async fn poll_cancel(flag: &AtomicBool) {
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Drive a single target's scan `fut` under a cooperative per-target wall-clock
/// budget. The cap is cooperative, not a hard kill: on expiry the target stops
/// at its next cancellation checkpoint (between phases/parameters) and drains —
/// an in-flight request still finishes under its own `--timeout`.
///
/// A `--scan-timeout` expiry must cancel **only this target**: the prior
/// implementation flipped the shared SIGINT flag, which `run_scanning` polls
/// per parameter and the dispatch loop checks before queuing the next target,
/// so the first target to exceed its budget aborted every concurrent sibling
/// *and* skipped all not-yet-started targets — silently dropping coverage for
/// the whole run. Here the cap sets `target_cancel` (a fresh per-target flag)
/// instead, never the shared `sigint` flag. A real Ctrl-C is mirrored from
/// `sigint` into `target_cancel` so in-flight workers still stop. `fut` is
/// driven to completion either way (not just dropped): `run_scanning`'s
/// per-parameter workers are detached `tokio::spawn` tasks that a dropped
/// future would leave hammering the target, so we keep polling until the
/// cooperative-cancel checkpoints let them drain. Returns whether the cap
/// fired (callers print the per-target notice).
async fn run_target_capped<T>(
    fut: impl std::future::Future<Output = T>,
    scan_timeout_secs: u64,
    sigint: &AtomicBool,
    target_cancel: &AtomicBool,
) -> bool {
    tokio::pin!(fut);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(scan_timeout_secs);
    let mut timed_out = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut fut => break,
            // Mirror a process-wide Ctrl-C into this target's flag, then keep
            // draining. Disabled once already cancelled (by either source).
            _ = poll_cancel(sigint), if !target_cancel.load(Ordering::Relaxed) => {
                target_cancel.store(true, Ordering::Relaxed);
            }
            _ = tokio::time::sleep_until(deadline), if !target_cancel.load(Ordering::Relaxed) => {
                timed_out = true;
                target_cancel.store(true, Ordering::Relaxed);
            }
        }
    }
    timed_out
}

pub(crate) async fn run_scan_loop(
    args: &ScanArgs,
    host_groups: std::collections::HashMap<String, Vec<Target>>,
    state: &ScanState,
    cancel_flag: Arc<AtomicBool>,
    stream_findings_enabled: bool,
) {
    // Rebind shared state to owned locals so the loop body below stays
    // identical to the pre-split `run_scan`.
    let results = state.results.clone();
    let findings_count = state.findings_count.clone();
    let multi_pb = state.multi_pb.clone();
    let scan_idx = state.scan_idx.clone();
    let overall_done = state.overall_done.clone();
    let total_targets = state.total_targets;
    let spinner_allowed = state.spinner_allowed;
    let nc = state.no_color;

    let global_semaphore = Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));
    let (finding_tx, finding_printer_handle) = if stream_findings_enabled {
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::scanning::result::Result>();
        let multi_pb_for_printer = multi_pb.clone();
        let poc_type = args.poc_type.clone();
        let printer_nc = nc;
        let include_request = args.include_request;
        let include_response = args.include_response;
        let handle = tokio::spawn(async move {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some(result) = rx.recv().await {
                // Deduplicate on (type, url, param, payload) so the same
                // finding emitted along two code paths (e.g. JS-context V
                // upgrade and DOM verification) only prints once.
                let key = format!(
                    "{}|{}|{}|{}",
                    result.result_type.short(),
                    result.data,
                    result.param,
                    result.payload,
                );
                if !seen.insert(key) {
                    continue;
                }
                // Emit the same POC + tree block the end-of-scan path
                // would emit; end-of-scan then skips per-finding rendering
                // when streaming is enabled, so users see each finding
                // exactly once with full context instead of a duplicate
                // POC header line and orphan tree.
                let block =
                    render_finding_block(&result, &poc_type, include_request, include_response);
                let rendered = if printer_nc {
                    crate::utils::term::strip_ansi(block.trim_end_matches('\n'))
                } else {
                    block.trim_end_matches('\n').to_string()
                };
                // Route through MultiProgress when present so the lines
                // are emitted above the spinner bars without garbling
                // them.
                if let Some(ref mp) = multi_pb_for_printer {
                    let _ = mp.println(&rendered);
                } else {
                    println!("{}", rendered);
                }
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let mut group_handles = vec![];

    for (host, group) in host_groups {
        if let Some(lim) = args.limit
            && findings_count.load(Ordering::Relaxed) >= lim
        {
            break;
        }
        let global_semaphore_clone = global_semaphore.clone();
        let multi_pb_clone = multi_pb.clone();
        let args_arc = Arc::new(args.clone());
        let results_clone = results.clone();
        let findings_count_group = findings_count.clone();
        let finding_tx_group = finding_tx.clone();

        let scan_idx = scan_idx.clone();
        let overall_done_clone = overall_done.clone();
        let cancel_flag_group = cancel_flag.clone();
        let group_handle = tokio::spawn(async move {
            // Skip the (expensive) payload-counting loop entirely when no
            // overall progress bar will be drawn — generating ~10k payloads
            // per param twice (here and again inside run_scanning) added a
            // measurable CPU tax for every --silence / non-TTY scan.
            let overall_pb: Option<Arc<indicatif::ProgressBar>> = if let Some(ref mp) =
                multi_pb_clone
            {
                // Calculate total overall tasks for this group. Must mirror what
                // run_scanning actually increments — one tick per reflection
                // payload, one per DOM payload — otherwise the overall bar rolls
                // past 100% (the previous reflection-only count was the cause).
                let mut total_overall_tasks = 0u64;
                for target in &group {
                    for param in &target.reflection_params {
                        let reflection_payloads = if let Some(context) = &param.injection_context {
                            crate::scanning::xss_common::get_dynamic_payloads(context, &args_arc)
                                .unwrap_or_else(|_| vec![])
                        } else {
                            crate::scanning::xss_common::get_dynamic_payloads(
                                &crate::parameter_analysis::InjectionContext::Html(None),
                                &args_arc,
                            )
                            .unwrap_or_else(|_| vec![])
                        };
                        let dom_payloads = crate::scanning::get_dom_payloads(param, &args_arc)
                            .unwrap_or_else(|_| vec![]);
                        total_overall_tasks +=
                            reflection_payloads.len() as u64 + dom_payloads.len() as u64;
                    }
                }
                let pb = mp.add(indicatif::ProgressBar::new(total_overall_tasks));
                // See `crate::scanning::req_per_sec_tracker` for why we
                // replace `{per_sec}` (pb-position rate, inflated by
                // skipped-payload `inc(1)` calls) with a `REQUEST_COUNT`-delta
                // tracker.
                let req_start = crate::REQUEST_COUNT.load(Ordering::Relaxed);
                pb.set_style(
                    indicatif::ProgressStyle::default_bar()
                        .template("{spinner:.cyan} [{elapsed_precise}] [{bar:28.45/238}] {pos:>5}/{len:5} · {req_per_sec} · {wave}")
                        .expect("valid progress bar template")
                        .tick_chars(crate::utils::shimmer::TICK_CHARS)
                        .with_key(
                            "req_per_sec",
                            crate::scanning::req_per_sec_tracker(req_start),
                        )
                        .with_key(
                            "wave",
                            crate::utils::shimmer::wave_tracker(
                                "Overall scanning".to_string(),
                                crate::utils::shimmer::BAR_WAVE_RESERVE,
                            ),
                        )
                        .progress_chars("█▉▊▋▌▍▎▏░"),
                );
                pb.enable_steady_tick(Duration::from_millis(
                    crate::utils::shimmer::FRAME_MS as u64,
                ));
                Some(Arc::new(pb))
            } else {
                None
            };

            let mut target_handles = vec![];

            for target in group {
                if let Some(lim) = args_arc.limit
                    && findings_count_group.load(Ordering::Relaxed) >= lim
                {
                    break;
                }
                // SIGINT bail-out at the per-target dispatch boundary —
                // skip queuing any more targets once the user pressed
                // Ctrl-C, even if some are still pending.
                if cancel_flag_group.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let Ok(permit) = global_semaphore_clone.clone().acquire_owned().await else {
                    break;
                };
                let args_clone = args_arc.clone();
                let results_clone_inner = results_clone.clone();
                let multi_pb_clone_inner = multi_pb_clone.clone();
                let overall_pb_clone = overall_pb.clone();
                let scan_idx_clone = scan_idx.clone();
                let total_targets_copy = total_targets;
                let findings_count_target = findings_count_group.clone();
                let finding_tx_target = finding_tx_group.clone();
                let cancel_flag_inner = cancel_flag_group.clone();

                let multi_pb_active = multi_pb_clone_inner.is_some();
                let target_handle = tokio::spawn(async move {
                    if !args_clone.skip_xss_scanning && !args_clone.only_discovery {
                        let __scan_spinner = {
                            // When the indicatif bar is active, run_scanning renders a
                            // per-target progress bar with rate/ETA — suppress the stdout
                            // spinner so we don't show two competing scan indicators.
                            let enabled =
                                !args_clone.silence && total_targets_copy == 1 && !multi_pb_active;
                            let current = scan_idx_clone.fetch_add(1, Ordering::Relaxed) + 1;
                            start_spinner(
                                spinner_allowed,
                                enabled,
                                if total_targets_copy > 1 {
                                    format!(
                                        "[{}/{}] scanning: {}",
                                        current, total_targets_copy, target.url
                                    )
                                } else {
                                    format!("scanning: {}", target.url)
                                },
                            )
                        };
                        // Per-target cancellation flag. With a `--scan-timeout`
                        // set, hand `run_scanning` a fresh per-target flag
                        // (seeded from the real Ctrl-C flag) so the cap cancels
                        // only this target — never the shared SIGINT flag, which
                        // would abort every sibling and skip all pending targets
                        // (see `run_target_capped`). With no cap, pass the shared
                        // flag straight through so the common path keeps its
                        // zero-overhead direct wiring.
                        let timeout_set = args_clone.scan_timeout > 0;
                        let target_cancel = if timeout_set {
                            Arc::new(AtomicBool::new(cancel_flag_inner.load(Ordering::Relaxed)))
                        } else {
                            cancel_flag_inner.clone()
                        };
                        let scan_fut = crate::scanning::run_scanning(
                            &target,
                            args_clone.clone(),
                            results_clone_inner,
                            multi_pb_clone_inner,
                            overall_pb_clone,
                            findings_count_target,
                            Some(target_cancel.clone()),
                            finding_tx_target,
                            // CLI renders its own indicatif progress bar; no
                            // external params_tested counter to feed.
                            None,
                        );
                        // Honor --scan-timeout as a hard wall-clock cap per
                        // target. When a slow endpoint streams a partial body
                        // and pins every phase at the per-request `--timeout`,
                        // the per-target scan would otherwise serialize each
                        // phase × per-request timeout and run far longer than
                        // the user expects. Setting the cap to 0 disables it.
                        let timed_out = if timeout_set {
                            run_target_capped(
                                scan_fut,
                                args_clone.scan_timeout,
                                &cancel_flag_inner,
                                &target_cancel,
                            )
                            .await
                        } else {
                            scan_fut.await;
                            false
                        };
                        if timed_out && !args_clone.silence {
                            eprintln!(
                                "[scan] {} exceeded --scan-timeout ({}s); cancelling target (stops at next checkpoint)",
                                target.url, args_clone.scan_timeout,
                            );
                        }
                        if let Some((tx, done_rx)) = __scan_spinner {
                            let _ = tx.send(());
                            let _ = done_rx.await;
                        }
                    }
                    drop(permit);
                });
                target_handles.push(target_handle);
            }

            for handle in target_handles {
                // Surface panics from per-target scan tasks instead of letting
                // them disappear silently — a panic here points to a bug in
                // the scanning pipeline and operators need a chance to see it.
                if let Err(e) = handle.await
                    && e.is_panic()
                {
                    eprintln!("[scan] target task panicked: {}", e);
                }
                // Update global overall progress line when multiple targets
                overall_done_clone.fetch_add(1, Ordering::Relaxed);
                // overall ticker handles rendering globally
            }

            if let Some(pb) = overall_pb {
                crate::scanning::finish_scan_bar(
                    &pb,
                    console::style("✓").green().to_string(),
                    format!("All scanning completed for {}", host),
                );
            }
        });
        group_handles.push(group_handle);
    }

    for handle in group_handles {
        if let Err(e) = handle.await
            && e.is_panic()
        {
            eprintln!("[scan] target-group task panicked: {}", e);
        }
        if let Some(lim) = args.limit
            && findings_count.load(Ordering::Relaxed) >= lim
        {
            break;
        }
    }

    // Close the streaming channel by dropping the last live sender, then
    // wait for the printer task to drain any in-flight findings. Without
    // this, the printer would either leak (if we forgot to drop tx) or
    // race with end-of-scan output.
    drop(finding_tx);
    if let Some(handle) = finding_printer_handle
        && let Err(e) = handle.await
        && e.is_panic()
    {
        eprintln!("[scan] finding printer task panicked: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::{poll_cancel, run_target_capped};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    // A cooperative "scan future" that runs until its per-target cancel flag is
    // set — models `run_scanning`, whose per-parameter workers stop at the next
    // checkpoint when the flag flips, then let the join loop finish.
    async fn cooperative_worker(target_cancel: Arc<AtomicBool>) {
        while !target_cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // Regression for the multi-target `--scan-timeout` abort: a per-target
    // timeout must flip ONLY the target's own flag and leave the shared SIGINT
    // flag untouched, so sibling/pending targets keep scanning.
    #[tokio::test]
    async fn scan_timeout_cancels_only_target_not_sigint() {
        let sigint = Arc::new(AtomicBool::new(false));
        let target_cancel = Arc::new(AtomicBool::new(false));
        let fut = cooperative_worker(target_cancel.clone());
        // 1s is the smallest expressible budget; the cap fires and the
        // cooperative worker then drains via the per-target flag.
        let timed_out = run_target_capped(fut, 1, &sigint, &target_cancel).await;
        assert!(timed_out, "the per-target cap should fire");
        assert!(
            target_cancel.load(Ordering::Relaxed),
            "the target's own cancel flag is set on timeout"
        );
        assert!(
            !sigint.load(Ordering::Relaxed),
            "the shared SIGINT flag MUST stay untouched — flipping it aborted the whole run"
        );
    }

    // A real Ctrl-C (shared SIGINT flag) is still mirrored into the per-target
    // flag so in-flight workers stop even when a `--scan-timeout` is active.
    #[tokio::test]
    async fn sigint_is_mirrored_into_target_flag() {
        let sigint = Arc::new(AtomicBool::new(false));
        let target_cancel = Arc::new(AtomicBool::new(false));
        let fut = cooperative_worker(target_cancel.clone());
        // Trip the shared SIGINT flag shortly after the scan starts.
        let sig = sigint.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            sig.store(true, Ordering::Relaxed);
        });
        // Budget far larger than the SIGINT delay so the cap can't be the cause.
        let timed_out = run_target_capped(fut, 3600, &sigint, &target_cancel).await;
        assert!(
            !timed_out,
            "ended via SIGINT mirror, not the wall-clock cap"
        );
        assert!(
            target_cancel.load(Ordering::Relaxed),
            "SIGINT was mirrored into the per-target flag"
        );
    }

    // A scan that finishes before its budget returns `timed_out == false` and
    // touches neither flag.
    #[tokio::test]
    async fn fast_scan_under_budget_does_not_time_out() {
        let sigint = Arc::new(AtomicBool::new(false));
        let target_cancel = Arc::new(AtomicBool::new(false));
        let fut = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let timed_out = run_target_capped(fut, 3600, &sigint, &target_cancel).await;
        assert!(!timed_out);
        assert!(!target_cancel.load(Ordering::Relaxed));
        assert!(!sigint.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn poll_cancel_completes_when_flag_flips() {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            f.store(true, Ordering::Relaxed);
        });
        // Would hang forever if poll_cancel never observed the flip.
        poll_cancel(&flag).await;
        assert!(flag.load(Ordering::Relaxed));
    }
}
