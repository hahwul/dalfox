//! Crate-wide debug logging.
//!
//! [`dbg_log!`](crate::dbg_log) is the single entry point for `--debug`
//! diagnostics. It supersedes the ad-hoc
//! `if crate::DEBUG.load(..) { eprintln!("[DBG] ..") }` pattern that was
//! duplicated ~20 times across the scanner, each with a hand-written `[DBG]`
//! prefix and no timestamp.
//!
//! Three properties make it the right default over a plain `eprintln!`:
//! - **stderr only** — structured stdout (JSON / JSONL / SARIF) is never
//!   polluted, even under `--debug`. The old per-site `eprintln!`s already did
//!   this; the short-lived `log_dbg` helper (stdout via `cprintln!`) did not.
//! - **lazy** — the message is only formatted when `--debug` is active, so the
//!   macro is cheap to leave in hot per-request paths (reflection / scanning).
//! - **on-format** — renders in dalfox's `{ts} DBG <msg>` log style, matching
//!   the `INF` / `WRN` / `WAF` lines, with ANSI stripped under `--no-color`.

/// Emit a `{ts} DBG <msg>` line on stderr when `--debug` (`crate::DEBUG`) is
/// set. Takes the same arguments as [`format!`]; the message is only built when
/// debug is active. ANSI is stripped under `--no-color` / `NO_COLOR` because it
/// routes through [`ceprintln!`](crate::ceprintln).
///
/// ```ignore
/// dbg_log!("preflight unreachable: {} ({})", url, reason);
/// ```
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {{
        if $crate::DEBUG.load(::std::sync::atomic::Ordering::Relaxed) {
            let __ts = ::chrono::Local::now().format("%-I:%M%p").to_string();
            $crate::ceprintln!(
                "\x1b[90m{}\x1b[0m \x1b[35mDBG\x1b[0m {}",
                __ts,
                ::std::format!($($arg)*)
            );
        }
    }};
}
