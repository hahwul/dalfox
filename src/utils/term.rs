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
pub(crate) fn color_enabled() -> bool {
    !crate::NO_COLOR.load(Ordering::Relaxed)
}

/// True iff stdout is attached to a real terminal. The spinner / live
/// progress rendering checks this so piped runs (`dalfox ... | tee log`,
/// CI) don't get spammed with cursor-redrawing frames.
#[inline]
pub(crate) fn stdout_is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// Width in columns of `term`, falling back to 80 when the size can't be
/// queried (not a TTY, or the ioctl failed).
#[inline]
fn cols_of(term: console::Term) -> usize {
    term.size_checked()
        .map(|(_, cols)| cols as usize)
        .unwrap_or(80)
}

/// Current **stdout** terminal width in columns. The hand-rolled spinner /
/// overall ticker use this to truncate their line so a long URL never wraps —
/// a wrapped line breaks the `\r` redraw and strands a row of debris behind
/// the cursor. They write to stdout, so stdout is the stream to measure.
#[inline]
pub(crate) fn term_cols() -> usize {
    cols_of(console::Term::stdout())
}

/// Current **stderr** terminal width in columns. indicatif renders its
/// progress bars to stderr, so the `{wave}` shimmer truncation must measure
/// stderr — measuring stdout would pick the wrong width (or the 80-col
/// fallback) whenever stdout is piped while stderr is a TTY, e.g.
/// `dalfox scan … | tee log`.
#[inline]
pub(crate) fn term_cols_stderr() -> usize {
    cols_of(console::Term::stderr())
}

/// Strip ANSI escape sequences from `s`.
///
/// Consumes every `ESC`-introduced form a terminal would act on, not just
/// CSI: OSC (`ESC ]` … `BEL` / `ST`) carries hyperlinks, window titles and —
/// via OSC 52 — clipboard writes; DCS / SOS / PM / APC are the other string
/// sequences. A response body dalfox echoes into a finding line is
/// target-controlled, so leaving those to pass through handed the page a
/// channel to the operator's terminal. A lone `ESC` is dropped too: on its
/// own it introduces nothing, and letting it survive would re-arm the next
/// byte as an escape introducer downstream.
///
/// Printable characters are never touched — payloads contain `<`, `>` and
/// `"` and must stay readable.
pub(crate) fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1B {
            i = skip_escape_sequence(bytes, i);
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

/// Given `bytes[i] == ESC`, return the index just past the escape sequence
/// that starts there. Always returns a UTF-8 char boundary and always
/// advances by at least one byte, so the caller's loop terminates.
fn skip_escape_sequence(bytes: &[u8], i: usize) -> usize {
    let Some(&intro) = bytes.get(i + 1) else {
        return i + 1; // lone trailing ESC
    };
    match intro {
        // CSI: parameter/intermediate bytes 0x20..=0x3F, then one final byte.
        b'[' => {
            let mut j = i + 2;
            while j < bytes.len() {
                let b = bytes[j];
                if (0x20..=0x3F).contains(&b) {
                    j += 1;
                } else if (0x40..=0x7E).contains(&b) {
                    j += 1; // include the final byte
                    break;
                } else {
                    break; // malformed — bail (b is a char boundary: ASCII precedes it)
                }
            }
            j
        }
        // String sequences: OSC / DCS / SOS / PM / APC. Terminated by BEL or
        // ST (`ESC \`); an unterminated one runs to the end of the string.
        b']' | b'P' | b'X' | b'^' | b'_' => {
            let mut j = i + 2;
            while j < bytes.len() {
                match bytes[j] {
                    0x07 => return j + 1, // BEL
                    0x1B => {
                        return if bytes.get(j + 1) == Some(&b'\\') {
                            j + 2 // ST
                        } else {
                            j // a nested ESC — let the caller re-dispatch on it
                        };
                    }
                    _ => j += 1,
                }
            }
            j
        }
        // Two-byte escapes (`ESC c`, `ESC 7`, `ESC ( B`, …): drop the ESC and
        // the character after it. Stepping by *character* rather than byte
        // keeps the result on a UTF-8 boundary for `ESC` + multi-byte input.
        _ => {
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j] & 0b1100_0000) == 0b1000_0000 {
                j += 1;
            }
            j
        }
    }
}

/// Escape terminal control bytes in target-derived text before it reaches a
/// terminal or a report file, keeping every printable character.
///
/// Findings quote the target's own bytes: the `L<n>:` context line comes
/// straight out of the response body, and parameter names come from the
/// page's forms and from parameter mining, neither filtered. [`strip_ansi`]
/// only runs on the `--no-color` path, so on a colour terminal those bytes
/// were printed verbatim. Delegates to
/// [`sanitize_log_message`](crate::utils::log::sanitize_log_message), the
/// helper the server and MCP log paths already use, so there is one rule for
/// "control bytes in attacker text".
pub(crate) fn sanitize_display(s: &str) -> std::borrow::Cow<'_, str> {
    crate::utils::log::sanitize_log_message(s)
}

/// [`sanitize_display`] for a multi-line block, preserving the line
/// structure — including CRLF, because the `http-request` POC and the
/// `--include-request` section are raw HTTP that has to stay pasteable.
pub(crate) fn sanitize_display_block(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for segment in s.split_inclusive('\n') {
        let (body, eol) = match segment.strip_suffix('\n') {
            Some(rest) => match rest.strip_suffix('\r') {
                Some(rest) => (rest, "\r\n"),
                None => (rest, "\n"),
            },
            None => (segment, ""),
        };
        out.push_str(&sanitize_display(body));
        out.push_str(eol);
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
    fn strip_ansi_drops_lone_escape() {
        // A bare ESC introduces nothing on its own, and letting it survive
        // would re-arm the following byte as an escape introducer downstream.
        assert_eq!(strip_ansi("\x1bABC"), "BC");
        assert_eq!(strip_ansi("tail\x1b"), "tail");
    }

    #[test]
    fn strip_ansi_removes_osc_sequences() {
        // OSC 8 hyperlink (BEL-terminated) — a response body can otherwise
        // make a finding line link anywhere.
        assert_eq!(strip_ansi("\x1b]8;;http://evil\x07text"), "text");
        // OSC 0 window title, ST-terminated.
        assert_eq!(strip_ansi("a\x1b]0;TITLE\x1b\\b"), "ab");
        // OSC 52 — clipboard write.
        assert_eq!(strip_ansi("\x1b]52;c;cm0gLXJmIH4=\x07ok"), "ok");
    }

    #[test]
    fn strip_ansi_removes_dcs_and_apc_sequences() {
        assert_eq!(strip_ansi("x\x1bPq#0;2;0;0;0\x1b\\y"), "xy");
        assert_eq!(strip_ansi("x\x1b_Gf=100\x1b\\y"), "xy");
        assert_eq!(strip_ansi("x\x1b^pm\x07y"), "xy");
    }

    #[test]
    fn strip_ansi_handles_unterminated_osc() {
        assert_eq!(strip_ansi("\x1b]0;never ends"), "");
    }

    #[test]
    fn strip_ansi_is_utf8_safe_after_escape() {
        // `ESC` followed by a multi-byte char must not slice mid-character.
        assert_eq!(strip_ansi("\x1b한글"), "글");
        assert_eq!(strip_ansi("\x1b[한글"), "한글");
    }

    #[test]
    fn sanitize_display_escapes_controls_but_keeps_payload_chars() {
        // Payload punctuation has to stay readable.
        assert_eq!(
            sanitize_display("<svg onload=alert(1)>\"x\""),
            "<svg onload=alert(1)>\"x\""
        );
        // Control bytes become visible text instead of reaching the terminal.
        assert_eq!(
            sanitize_display("\x1b]8;;http://evil\x07l"),
            "\\x1b]8;;http://evil\\x07l"
        );
        assert_eq!(sanitize_display("a\rb\nc"), "a\\rb\\nc");
    }

    #[test]
    fn sanitize_display_block_keeps_line_structure_and_crlf() {
        assert_eq!(
            sanitize_display_block("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"),
            "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"
        );
        // Controls inside a line are still escaped.
        assert_eq!(
            sanitize_display_block("a\x1b]0;T\x07b\nc"),
            "a\\x1b]0;T\\x07b\nc"
        );
    }
}
