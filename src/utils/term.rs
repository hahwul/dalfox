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
/// channel to the operator's terminal. Two-byte forms (`ESC c`, `ESC 7`, …)
/// take the character after the `ESC` with them, and a trailing `ESC` is
/// dropped on its own — letting one survive would re-arm the following byte
/// as an escape introducer downstream.
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

/// Control bytes that stay raw in displayed findings.
///
/// Horizontal tab, plus the two vertical-whitespace bytes VT (`\x0b`) and FF
/// (`\x0c`): dalfox's own WAF-bypass payloads use those as attribute
/// separators (`<img\x0csrc=x\x0conerror=…>` in `payload::xss_html`), so a
/// POC carrying one has to stay byte-exact or it stops reproducing the
/// finding. None of the three can retarget a hyperlink, write the clipboard,
/// set the window title, or overwrite a line that has already been drawn —
/// which is what the escaped ones (ESC, BEL, CR, …) can do.
#[inline]
fn is_display_safe_control(b: u8) -> bool {
    matches!(b, b'\t' | 0x0B | 0x0C)
}

/// Escape terminal control bytes in target-derived text before it reaches a
/// terminal or a report file, keeping every printable character.
///
/// Findings quote the target's own bytes: the `L<n>:` context line comes
/// straight out of the response body, and parameter names come from the
/// page's forms and from parameter mining, neither filtered. [`strip_ansi`]
/// only runs on the `--no-color` path, so on a colour terminal those bytes
/// were printed verbatim.
///
/// Same shape as
/// [`sanitize_log_message`](crate::utils::log::sanitize_log_message) — CR/LF
/// become `\r`/`\n`, other C0 bytes become `\xNN` — except that the display
/// path additionally keeps the payload whitespace listed in
/// [`is_display_safe_control`]. DEL and the C1 range (U+0080–U+009F, which
/// includes the single-character CSI/OSC/ST some terminals honor) are escaped
/// too, as `\xNN` / `\u{NN}`. Returns a borrowed string on the common
/// (clean) path.
pub(crate) fn sanitize_display(s: &str) -> std::borrow::Cow<'_, str> {
    escape_controls(s, is_display_safe_control)
}

/// Shared body of [`sanitize_display`] and
/// [`sanitize_log_message`](crate::utils::log::sanitize_log_message): escape
/// every C0 control except those `keep` allows, plus DEL and C1. CR/LF become
/// `\r`/`\n`.
pub(crate) fn escape_controls(s: &str, keep: fn(u8) -> bool) -> std::borrow::Cow<'_, str> {
    let needs_escape = |c: char| {
        let u = c as u32;
        (u < 0x20 && !keep(u as u8)) || (0x7f..=0x9f).contains(&u)
    };
    if !s.chars().any(needs_escape) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if needs_escape(c) => match c as u32 {
                u @ ..=0x7f => out.push_str(&format!("\\x{u:02x}")),
                u => out.push_str(&format!("\\u{{{u:02x}}}")),
            },
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
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

/// Set once `server` / `mcp` starts; see [`emit`].
static DAEMON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Switch this process's output to daemon rules. Called by `main` before a
/// daemon starts serving.
pub fn enter_daemon_mode() {
    DAEMON.store(true, Ordering::Relaxed);
}

/// Whether [`enter_daemon_mode`] was called.
pub fn daemon_mode() -> bool {
    DAEMON.load(Ordering::Relaxed)
}

enum DaemonOut {
    Text(String),
    Flush(std::sync::mpsc::Sender<()>),
}

/// Lines a daemon may have queued for its log reader before new ones are
/// dropped. ponytail: dropped silently; count and report them if operators
/// ever need to know a stalled reader lost lines.
const DAEMON_OUT_QUEUE: usize = 1024;

/// The queue feeding `stderr`'s writer thread, or stdout's. One each: a reader
/// that stalls on one stream must not cost the other its lines.
fn daemon_writer(stderr: bool) -> &'static std::sync::mpsc::SyncSender<DaemonOut> {
    static WRITERS: [std::sync::OnceLock<std::sync::mpsc::SyncSender<DaemonOut>>; 2] =
        [std::sync::OnceLock::new(), std::sync::OnceLock::new()];
    WRITERS[usize::from(stderr)].get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel(DAEMON_OUT_QUEUE);
        // If the thread cannot be spawned the queue fills and lines are
        // dropped, which is the same outcome as a reader that never reads.
        let _ = std::thread::Builder::new()
            .name("dalfox-log".to_string())
            .spawn(move || {
                use std::io::Write;
                for out in rx {
                    match out {
                        DaemonOut::Text(text) if stderr => {
                            let _ = std::io::stderr().write_all(text.as_bytes());
                        }
                        DaemonOut::Text(text) => {
                            let mut stdout = std::io::stdout();
                            let _ = stdout.write_all(text.as_bytes());
                            let _ = stdout.flush();
                        }
                        DaemonOut::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            });
        tx
    })
}

/// Write `text` to stdout or stderr.
///
/// A one-shot command prints directly: a reader that went away
/// (`dalfox payload … | head`) panics the print, and `main`'s panic hook turns
/// that into a quiet exit.
///
/// A daemon must outlive its log reader instead. Printing directly, `dalfox
/// server | tee` exited — with status 0, so no supervisor restarted it — on the
/// first line logged after `tee` went away, and a reader that merely stopped
/// reading (a paused terminal, an MCP client that never drains stderr) blocked
/// every handler that logged once the pipe filled. So in daemon mode the text
/// goes to a writer thread through a bounded queue: the caller never blocks
/// and never panics, and lines are dropped while the reader is not keeping up.
pub fn emit(stderr: bool, text: String) {
    if daemon_mode() {
        let _ = daemon_writer(stderr).try_send(DaemonOut::Text(text));
    } else if stderr {
        eprint!("{text}");
    } else {
        print!("{text}");
    }
}

/// Give the daemon's queued output up to `wait` to reach its reader. Called
/// before the process exits, which would otherwise cut the last lines off.
pub fn flush_daemon_output(wait: std::time::Duration) {
    if !daemon_mode() {
        return;
    }
    let deadline = std::time::Instant::now() + wait;
    for stderr in [false, true] {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        // A full queue is a reader that is behind, not one that is gone: keep
        // offering the marker until the deadline.
        while daemon_writer(stderr)
            .try_send(DaemonOut::Flush(done_tx.clone()))
            .is_err()
        {
            if std::time::Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = done_rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
    }
}

/// Body of [`cprintln!`] / [`cprint!`] / [`ceprintln!`]: apply the color
/// policy, then [`emit`].
#[doc(hidden)]
pub fn emit_styled(stderr: bool, mut text: String, newline: bool) {
    if !color_enabled() {
        text = strip_ansi(&text);
    }
    if newline {
        text.push('\n');
    }
    emit(stderr, text);
}

/// `println!`-shaped macro that conditionally strips ANSI escape codes
/// from its rendered output when `--no-color` / `NO_COLOR` is in effect.
/// Use anywhere we currently hand-roll `\x1b[…m` color literals.
#[macro_export]
macro_rules! cprintln {
    ($($arg:tt)*) => {
        $crate::utils::term::emit_styled(false, ::std::format!($($arg)*), true)
    };
}

/// `print!`-shaped sibling of [`cprintln!`] for spinner-style updates
/// that don't terminate with a newline.
#[macro_export]
macro_rules! cprint {
    ($($arg:tt)*) => {
        $crate::utils::term::emit_styled(false, ::std::format!($($arg)*), false)
    };
}

/// `eprintln!`-shaped sibling of [`cprintln!`] for diagnostics that
/// belong on stderr (`UNREACHABLE`, validation errors, etc.). Stderr
/// is just as likely to be redirected to a logfile as stdout, so the
/// same `--no-color` / `NO_COLOR` policy applies.
///
/// Also what every module a server/MCP job can reach uses instead of
/// `eprintln!`, which would panic the job on a closed stderr
/// (`job_reachable_modules_never_print_directly`).
#[macro_export]
macro_rules! ceprintln {
    ($($arg:tt)*) => {
        $crate::utils::term::emit_styled(true, ::std::format!($($arg)*), true)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outside the CLI (`cmd/`, `main.rs`, the banner) everything can run
    /// inside a server or MCP job, where a direct `println!` / `eprintln!`
    /// panics the job when the log reader is gone. Those modules print through
    /// `cprintln!` / `ceprintln!`, which go through [`emit`].
    #[test]
    fn job_reachable_modules_never_print_directly() {
        fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rs_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        rs_files(std::path::Path::new("src"), &mut files);
        assert!(!files.is_empty(), "should have found source files");

        let mut offenders = Vec::new();
        for path in files {
            let name = path.to_string_lossy().replace('\\', "/");
            let cli_only = name.starts_with("src/cmd/")
                || ["src/main.rs", "src/utils/term.rs", "src/utils/banner.rs"]
                    .contains(&name.as_str());
            let test_file =
                name.ends_with("tests.rs") || name.contains("/tests/") || name.contains("_test");
            if cli_only || test_file {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for mac in ["println!(", "print!(", "eprintln!(", "eprint!("] {
                    let direct = line.match_indices(mac).any(|(at, _)| {
                        !line[..at].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                    });
                    if direct {
                        offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
                        break;
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "direct print in a module a server/MCP job can reach — use \
             crate::cprintln! / crate::ceprintln!:\n  {}",
            offenders.join("\n  ")
        );
    }

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
    fn sanitize_display_keeps_the_whitespace_real_payloads_use() {
        // `payload::xss_html` ships `<img\x0csrc=x\x0conerror=…>` and
        // `<svg\x0bonload=…>` as WAF bypasses. Escaping those bytes would
        // print — and paste — a payload that no longer reproduces.
        assert_eq!(
            sanitize_display("<img\x0csrc=x\x0conerror=alert(1)>"),
            "<img\x0csrc=x\x0conerror=alert(1)>"
        );
        assert_eq!(
            sanitize_display("<svg\x0bonload=alert(1)>"),
            "<svg\x0bonload=alert(1)>"
        );
        assert_eq!(sanitize_display("a\tb"), "a\tb");
        // …while the bytes that drive or forge a terminal still go.
        assert_eq!(sanitize_display("a\x0bb\x1bc"), "a\x0bb\\x1bc");
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
        // DEL and C1 (the one-character OSC/CSI/ST) are controls too; the
        // printable code points either side of the range are not.
        assert_eq!(
            sanitize_display("\u{9d}0;T\u{9c}\u{7f}\u{9b}2J"),
            "\\u{9d}0;T\\u{9c}\\x7f\\u{9b}2J"
        );
        assert_eq!(sanitize_display("~\u{a0}é"), "~\u{a0}é");
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
