//! Terminal output policy: color stripping and TTY detection.
//!
//! The CLI historically embeds raw ANSI escape sequences (e.g.
//! `\x1b[31m`, `\x1b[38;5;247m`) inside `println!` calls. Without
//! interception those leak into pipes/files even when the user passes
//! `--no-color` or sets `NO_COLOR`. Routing the offending sites through
//! [`cprintln!`] / [`cprint!`] honours the global no-color toggle in
//! [`crate::NO_COLOR`].
//!
//! [`stdout_is_tty`] gates the spinner so background jobs / CI logs
//! don't fill up with `⠋⠙⠹` frames.

use std::sync::atomic::Ordering;

/// Returns true when ANSI color output is permitted globally. False when
/// `--no-color`, `NO_COLOR=*`, or any other code path has set the global
/// toggle via [`crate::NO_COLOR`].
#[inline]
pub fn color_enabled() -> bool {
    !crate::NO_COLOR.load(Ordering::Relaxed)
}

/// True iff stdout is attached to a real terminal. The spinner / live
/// progress rendering checks this so piped runs (`dalfox ... | tee log`,
/// CI) don't get spammed with cursor-redrawing frames.
#[inline]
pub fn stdout_is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// Strip ANSI CSI sequences (`\x1b[…m`, `\x1b[…K`, etc.) from `s`.
/// Conservative: only consumes sequences starting `ESC [` followed by
/// `0-9;` parameters and a final byte in `0x40..=0x7E`. Anything else
/// passes through verbatim.
pub fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // CSI: skip params (0-9, ;, ?), then one final byte 0x40..=0x7E
            let mut j = i + 2;
            while j < bytes.len() {
                let b = bytes[j];
                if (0x30..=0x3F).contains(&b) {
                    j += 1;
                } else if (0x40..=0x7E).contains(&b) {
                    j += 1; // include the final byte
                    break;
                } else {
                    break; // malformed — bail
                }
            }
            i = j;
            continue;
        }
        // Multi-byte UTF-8 safe copy: grab the whole char.
        let ch_start = i;
        let mut j = i + 1;
        while j < bytes.len() && (bytes[j] & 0b1100_0000) == 0b1000_0000 {
            j += 1;
        }
        // SAFETY: substring between ch_start..j is a complete UTF-8 char in `s`.
        out.push_str(&s[ch_start..j]);
        i = j;
    }
    out
}

/// `println!`-shaped macro that conditionally strips ANSI escape codes
/// from its rendered output when `--no-color` / `NO_COLOR` is in effect.
/// Use anywhere we currently hand-roll `\x1b[…m` color literals.
#[macro_export]
macro_rules! cprintln {
    ($($arg:tt)*) => {{
        let s = ::std::format!($($arg)*);
        if $crate::utils::term::color_enabled() {
            ::std::println!("{}", s);
        } else {
            ::std::println!("{}", $crate::utils::term::strip_ansi(&s));
        }
    }};
}

/// `print!`-shaped sibling of [`cprintln!`] for spinner-style updates
/// that don't terminate with a newline.
#[macro_export]
macro_rules! cprint {
    ($($arg:tt)*) => {{
        let s = ::std::format!($($arg)*);
        if $crate::utils::term::color_enabled() {
            ::std::print!("{}", s);
        } else {
            ::std::print!("{}", $crate::utils::term::strip_ansi(&s));
        }
    }};
}

/// `eprintln!`-shaped sibling of [`cprintln!`] for diagnostics that
/// belong on stderr (`UNREACHABLE`, validation errors, etc.). Stderr
/// is just as likely to be redirected to a logfile as stdout, so the
/// same `--no-color` / `NO_COLOR` policy applies.
#[macro_export]
macro_rules! ceprintln {
    ($($arg:tt)*) => {{
        let s = ::std::format!($($arg)*);
        if $crate::utils::term::color_enabled() {
            ::std::eprintln!("{}", s);
        } else {
            ::std::eprintln!("{}", $crate::utils::term::strip_ansi(&s));
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_color_codes() {
        let input = "\x1b[31mhello\x1b[0m world";
        assert_eq!(strip_ansi(input), "hello world");
    }

    #[test]
    fn strip_ansi_removes_truecolor_sequences() {
        let input = "\x1b[38;5;247mdim\x1b[0m";
        assert_eq!(strip_ansi(input), "dim");
    }

    #[test]
    fn strip_ansi_removes_clear_line_sequences() {
        // `\x1b[2K` (erase line) and `\r` carriage return both used by the spinner.
        let input = "\r\x1b[2K\rdone";
        assert_eq!(strip_ansi(input), "\r\rdone");
    }

    #[test]
    fn strip_ansi_passes_through_plain_text() {
        let input = "no escapes here";
        assert_eq!(strip_ansi(input), input);
    }

    #[test]
    fn strip_ansi_preserves_multibyte_utf8() {
        let input = "한글 \x1b[31m텍스트\x1b[0m";
        assert_eq!(strip_ansi(input), "한글 텍스트");
    }

    #[test]
    fn strip_ansi_handles_lone_escape() {
        // Malformed: lone ESC with no '[' — preserved.
        let input = "\x1bABC";
        assert_eq!(strip_ansi(input), "\x1bABC");
    }
}
