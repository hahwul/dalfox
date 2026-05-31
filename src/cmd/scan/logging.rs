//! Plain-mode log lines and the ephemeral progress spinner. These were
//! closures inside `run_scan`; promoting them to free functions lets the
//! extracted scan stages share them without recapturing `args`.

use super::args::ScanArgs;
use std::io::{self, Write};
use std::sync::atomic::Ordering;
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

/// DBG log line, gated on the global `--debug` flag (independent of format).
pub(crate) fn log_dbg(msg: &str) {
    if crate::DEBUG.load(Ordering::Relaxed) {
        let ts = chrono::Local::now().format("%-I:%M%p").to_string();
        crate::cprintln!("\x1b[90m{}\x1b[0m \x1b[35mDBG\x1b[0m {}", ts, msg);
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
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut i = 0usize;
        loop {
            crate::cprint!(
                "\r\x1b[38;5;247m{} {}\x1b[0m",
                frames[i % frames.len()],
                label
            );
            let _ = io::stdout().flush();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(80)) => {},
                _ = &mut rx => {
                    crate::cprint!("\r\x1b[2K\r");
                    let _ = io::stdout().flush();
                    let _ = done_tx.send(());
                    break;
                }
            }
            i = (i + 1) % frames.len();
        }
    });
    Some((tx, done_rx))
}
