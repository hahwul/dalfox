//! scan progress UI + req/sec telemetry.
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

/// Build a `with_key("req_per_sec", …)` tracker for an indicatif progress bar.
///
/// `start` is the value of `crate::REQUEST_COUNT` captured at bar creation;
/// the tracker renders `(REQUEST_COUNT - start) / pb.elapsed()` as
/// `XXXX.X req/s` with a fixed-width field so the bar's trailing columns
/// don't jitter as the rate changes magnitude.
///
/// Caveats baked into the displayed value:
///   - `REQUEST_COUNT` is process-global, so when several targets in the
///     same host group scan concurrently the per-target bar reflects the
///     group's combined HTTP rate (which matches the overall bar). This is
///     intentionally a "combined" view — a strictly per-target counter
///     would need plumbing through every HTTP call site.
///   - `{eta}` next to this field is still computed by indicatif from
///     `pos/len` rate, not request rate. In practice ETA still reads
///     sensibly because the bar finishes the moment the inner loop exits.
pub(crate) fn req_per_sec_tracker(
    start: u64,
) -> impl Fn(&indicatif::ProgressState, &mut dyn std::fmt::Write) + Send + Sync + Clone + 'static {
    move |state, w| {
        let delta = crate::REQUEST_COUNT
            .load(Ordering::Relaxed)
            .saturating_sub(start);
        let _ = write!(
            w,
            "{}",
            format_req_per_sec(delta, state.elapsed().as_secs_f64())
        );
    }
}
/// Format `delta` requests over `elapsed_secs` as the right-aligned
/// `XXXX.X req/s` field rendered by [`req_per_sec_tracker`]. Extracted as
/// a pure helper so the rate / formatting contract can be tested without
/// constructing an `indicatif::ProgressState`.
///
/// `elapsed_secs <= 0.0` yields `0.0 req/s` (avoids div-by-zero on the
/// first tick before the bar has accumulated any duration).
pub(crate) fn format_req_per_sec(delta: u64, elapsed_secs: f64) -> String {
    let rate = if elapsed_secs > 0.0 {
        delta as f64 / elapsed_secs
    } else {
        0.0
    };
    format!("{:>7.1} req/s", rate)
}
/// Build the per-target indicatif progress bar (one tick per reflection /
/// DOM payload). Returns `None` when no `MultiProgress` is supplied (quiet /
/// embedded runs), in which case the scan loop simply skips the `inc(1)`
/// calls.
pub(crate) fn build_scan_progress_bar(
    multi_pb: &Option<Arc<MultiProgress>>,
    total_tasks: u64,
    target: &Target,
) -> Option<ProgressBar> {
    let mp = multi_pb.as_ref()?;
    let pb = mp.add(ProgressBar::new(total_tasks));
    // `{per_sec}` would measure pb-position rate, not HTTP request rate;
    // many `pb.inc(1)` calls here are "no-op" iterations (param already
    // found, payload skipped), which inflated the rate (e.g. 11.5k/s on
    // a 5k-payload scan that finished in 0.4s). See req_per_sec_tracker
    // for the displayed semantics and caveats.
    //
    // The trailing `{wave}` paints "Scanning <url>" with the shared metallic
    // shimmer, re-evaluated on every steady tick from the bar's elapsed time
    // (no extra timer task). `finish_scan_bar` swaps in a `{msg}` style at the
    // end so the completion line replaces the wave instead of duplicating it.
    let req_start = crate::REQUEST_COUNT.load(Ordering::Relaxed);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.cyan} [{elapsed_precise}] [{bar:28.45/238}] {pos:>5}/{len:5} · {req_per_sec} · {wave}",
            )
            .expect("valid progress bar template")
            .tick_chars(crate::utils::shimmer::TICK_CHARS)
            .with_key("req_per_sec", req_per_sec_tracker(req_start))
            .with_key(
                "wave",
                crate::utils::shimmer::wave_tracker(
                    format!("Scanning {}", target.url),
                    crate::utils::shimmer::BAR_WAVE_RESERVE,
                ),
            )
            .progress_chars("█▉▊▋▌▍▎▏░"),
    );
    pb.enable_steady_tick(Duration::from_millis(
        crate::utils::shimmer::FRAME_MS as u64,
    ));
    Some(pb)
}
/// Render `pb` in its terminal "done" state and stop it.
///
/// The in-progress style paints the label through a `{wave}` shimmer and has
/// no `{msg}` slot, so a plain `finish_with_message` would never show the
/// completion text. Swap in a compact `{prefix} [elapsed] {msg}` style first:
/// a status glyph (green `✓` / yellow `⚠`), the elapsed time, then the final
/// message — replacing the wave rather than printing alongside it.
pub(crate) fn finish_scan_bar(pb: &ProgressBar, prefix: String, msg: String) {
    // Keep the completion line on one row too. The finished template is
    // `{prefix} [elapsed] {msg}` — ~13 cols of furniture before `{msg}` — so
    // trim the message to the leftover stderr width. It's a one-shot render
    // (no `\r` redraw), but a wrapped completion line still reads ragged.
    let avail = crate::utils::term::term_cols_stderr()
        .saturating_sub(14)
        .max(8);
    let msg = console::truncate_str(&msg, avail, "…").into_owned();
    // Set the prefix + message *before* swapping the style: the in-progress
    // template ignores both slots, so this stays invisible until the style
    // swap, which then renders the final line in one shot. Doing it the other
    // way round flashes a `✓ [elapsed]` frame with an empty message first.
    pb.set_prefix(prefix);
    pb.set_message(msg);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} [{elapsed_precise}] {msg}")
            .expect("valid finish template"),
    );
    pb.finish();
}
/// Log WAF block statistics gathered during the scan (debug builds only).
pub(crate) fn log_waf_block_stats(target: &Target) {
    if crate::DEBUG.load(Ordering::Relaxed) {
        let total_waf_blocks = crate::WAF_BLOCK_COUNT.load(Ordering::Relaxed);
        if total_waf_blocks > 0 {
            eprintln!(
                "[*] WAF block stats: {} total blocks detected during scan of {}",
                total_waf_blocks, target.url,
            );
        }
    }
}
