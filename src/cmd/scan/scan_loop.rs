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
                        let scan_fut = crate::scanning::run_scanning(
                            &target,
                            args_clone.clone(),
                            results_clone_inner,
                            multi_pb_clone_inner,
                            overall_pb_clone,
                            findings_count_target,
                            Some(cancel_flag_inner.clone()),
                            finding_tx_target,
                        );
                        // Honor --scan-timeout as a hard wall-clock cap per
                        // target. When a slow endpoint streams a partial body
                        // and pins every phase at the per-request `--timeout`,
                        // the per-target scan would otherwise serialize each
                        // phase × per-request timeout and run far longer than
                        // the user expects. Setting the cap to 0 disables it.
                        if args_clone.scan_timeout > 0 {
                            let budget = std::time::Duration::from_secs(args_clone.scan_timeout);
                            if let Err(_elapsed) = tokio::time::timeout(budget, scan_fut).await {
                                cancel_flag_inner.store(true, Ordering::Relaxed);
                                if !args_clone.silence {
                                    eprintln!(
                                        "[scan] {} exceeded --scan-timeout ({}s); aborting target",
                                        target.url, args_clone.scan_timeout,
                                    );
                                }
                            }
                        } else {
                            scan_fut.await;
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
