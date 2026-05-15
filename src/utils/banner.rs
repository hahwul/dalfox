use std::io::{self, Write};
use std::sync::Once;

/// Simple banner renderer for Dalfox.
/// This module centralizes the ASCII banner so it can be reused across commands.
///
/// Usage:
/// - Print always:
///   banner::print_banner(env!("CARGO_PKG_VERSION"), true);
/// - Print only once (even if called multiple times):
///   banner::print_banner_once(env!("CARGO_PKG_VERSION"), true);
///
/// When color is enabled, core parts are colorized with ANSI escape codes.
/// If you need to guarantee no escape codes (e.g., when piping), pass color = false.
static PRINT_ONCE: Once = Once::new();

/// Render the banner as a String.
/// - `version`: Typically env!("CARGO_PKG_VERSION")
/// - `color`: Enable ANSI color when true
pub fn render_banner(version: &str, color: bool) -> String {
    // ANSI colors
    let reset = if color { "\x1b[0m" } else { "" };
    let dim = if color { "\x1b[90m" } else { "" };
    let cyan = if color { "\x1b[36m" } else { "" };

    // We keep the ASCII art identical to the CLI help_template, but allow
    // the right-side "Dalfox v{version}" and the tagline to be colorized.
    let mut out = String::new();
    out.push('\n');
    out.push_str("               ░█▒\n");
    out.push_str("             ████     ▓\n");
    out.push_str("           ▓█████  ▓██▓\n");
    out.push_str("          ████████████         ░\n");
    out.push_str("        ░███████████▓          ▓░\n");
    out.push_str("     ░████████████████        ▒██░\n");
    out.push_str("    ▓██████████▒███████     ░█████▓░\n");
    out.push_str("   ██████████████░ ████        █▓\n");

    // Right-hand "Dalfox v{version}" emphasized
    out.push_str(&format!(
        " ░█████▓          ░████▒       ░         {}Dalfox v{}{}{}\n",
        cyan, version, reset, ""
    ));

    out.push_str(" █████               ▓██░\n");

    // Right-hand tagline lines, dimmed
    out.push_str(&format!(
        " ████                  ▓██      {}Powerful open-source XSS scanner{}\n",
        dim, reset
    ));
    out.push_str(&format!(
        " ███▓        ▓███████▓▒▓█░     {}and utility focused on automation.{}\n",
        dim, reset
    ));
    out.push_str(" ███▒      █████\n");
    out.push_str(" ▓███     ██████\n");
    out.push_str(" ████     ██████▒\n");
    out.push_str(" ░████    ████████▒\n\n");

    out
}

/// Print the banner to stdout (no trailing extra newline beyond what render_banner includes).
/// Flushes stdout after printing.
pub fn print_banner(version: &str, color: bool) {
    let s = render_banner(version, color);
    print!("{}", s);
    let _ = io::stdout().flush();
}

/// Print the banner once per process. Additional calls are no-ops.
pub fn print_banner_once(version: &str, color: bool) {
    PRINT_ONCE.call_once(|| {
        print_banner(version, color);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_banner_contains_version_and_tagline() {
        let s = render_banner("9.9.9", false);
        assert!(s.contains("Dalfox v9.9.9"));
        assert!(s.contains("Powerful open-source XSS scanner"));
        assert!(s.contains("and utility focused on automation."));
    }

    #[test]
    fn render_banner_without_color_has_no_ansi_escapes() {
        let s = render_banner(env!("CARGO_PKG_VERSION"), false);
        assert!(
            !s.contains('\x1b'),
            "color=false must not emit ANSI escape codes"
        );
    }

    #[test]
    fn render_banner_with_color_emits_ansi_escapes() {
        let s = render_banner("1.2.3", true);
        // cyan around the version and dim around the tagline lines
        assert!(s.contains("\x1b[36m"), "expected cyan ANSI sequence");
        assert!(s.contains("\x1b[90m"), "expected dim ANSI sequence");
        assert!(s.contains("\x1b[0m"), "expected reset ANSI sequence");
    }

    #[test]
    fn render_banner_starts_and_ends_with_blank_lines() {
        // Banner brackets itself with whitespace so it doesn't collide with
        // surrounding CLI output.
        let s = render_banner("0.0.0", false);
        assert!(s.starts_with('\n'));
        assert!(s.ends_with("\n\n"));
    }
}
