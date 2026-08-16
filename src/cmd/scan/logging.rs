//! Plain-mode log lines and the ephemeral progress spinner. These were
//! closures inside `run_scan`; promoting them to free functions lets the
//! extracted scan stages share them without recapturing `args`.

use super::args::ScanArgs;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;

// `cprintln!` strips ANSI when --no-color / NO_COLOR is in effect. Callers
// sometimes embed colored fragments inside `msg` (e.g. `XSS found
// \x1b[33m{}\x1b[0m XSS`) — strip handles those too.

/// INF log line, emitted only for the interactive `plain` format and when
/// not silenced.
pub(crate) fn log_info(args: &ScanArgs, msg: &str) {
    if args.format == "plain" && !args.silence {
        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
        crate::cprintln!("\x1b[90m{}\x1b[0m \x1b[36mINF\x1b[0m {}", ts, msg);
    }
}

/// WRN log line, same gating as [`log_info`].
pub(crate) fn log_warn(args: &ScanArgs, msg: &str) {
    if args.format == "plain" && !args.silence {
        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
        crate::cprintln!("\x1b[90m{}\x1b[0m \x1b[33mWRN\x1b[0m {}", ts, msg);
    }
}

/// Ephemeral animated spinner for progress (returns `(stop_tx, done_rx)`).
/// Suppressed when:
///   - caller passes `enabled = false`
///   - `spinner_allowed` is false (`--silence` / `-S`, or stdout isn't a TTY)
///
/// The carriage-return + erase-line redraw pattern is only useful on a real
/// terminal; in a log file it leaves `\r⠋ preflight: ...\r⠙` strings — hence
/// the `spinner_allowed` gate the caller computes once from stdout-is-tty.
///
/// The label is painted with the shared metallic [`shimmer`] (a bright band
/// sweeping across silver text) and led by an accent-colored spinner glyph.
/// Each frame is truncated to the live terminal width and terminated with
/// `\x1b[K` (erase-to-end-of-line), so a long URL can never wrap onto a
/// second row — wrapping would desync the `\r` redraw and strand debris.
///
/// [`shimmer`]: crate::utils::shimmer
pub(crate) fn start_spinner(
    spinner_allowed: bool,
    enabled: bool,
    label: String,
) -> Option<(oneshot::Sender<()>, oneshot::Receiver<()>)> {
    if !enabled || !spinner_allowed {
        return None;
    }
    let (tx, mut rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        use crate::utils::shimmer;
        let mut phase = 0usize;
        loop {
            // Reserve 2 columns for the glyph + its trailing space; truncate
            // the label (display-width aware, with an ellipsis) so the whole
            // line fits on one row. `\x1b[K` clears any leftover from a
            // previous, longer frame without a full-line repaint flicker.
            let budget = crate::utils::term::term_cols().saturating_sub(2).max(8);
            let visible = console::truncate_str(&label, budget, "…");
            crate::cprint!(
                "\r{} {}\x1b[K",
                shimmer::spin_glyph(phase),
                shimmer::shimmer(visible.as_ref(), phase)
            );
            let _ = io::stdout().flush();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(shimmer::FRAME_MS as u64)) => {},
                _ = &mut rx => {
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
}

/// The single "overall N/M targets · P% · F findings" line that shimmers at the
/// bottom of a multi-target plain-format run.
///
/// Returns the shutdown channel pair, or `None` when the line must not render
/// at all: another format owns stdout, `--silence` is set, there is only one
/// target, or stdout is not a TTY — a redraw frame every `FRAME_MS` is garbage
/// in a log file.
pub(crate) fn start_overall_ticker(
    args: &ScanArgs,
    total_targets: usize,
    findings_count: &Arc<AtomicUsize>,
    overall_done: &Arc<AtomicUsize>,
) -> Option<(oneshot::Sender<()>, oneshot::Receiver<()>)> {
    // Start global overall progress ticker when multiple targets; runs across preflight, analysis, and scanning.
    // Suppressed when stdout isn't a TTY — cursor-redraw frames look like garbage in logs.
    if args.format == "plain"
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
    }
}
