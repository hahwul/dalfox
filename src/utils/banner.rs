use std::io::{self, Write};
use std::sync::Once;

/// Simple banner renderer for Dalfox.
/// This module centralizes the ASCII banner so it can be reused across commands.
///
/// Usage:
/// - Print always:
///     banner::print_banner(env!("CARGO_PKG_VERSION"), true);
/// - Print only once (even if called multiple times):
///     banner::print_banner_once(env!("CARGO_PKG_VERSION"), true);
///
/// When color is enabled, core parts are colorized with ANSI escape codes.
/// If you need to guarantee no escape codes (e.g., when piping), pass color = false.
pub mod banner {
    use super::*;

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
        out.push_str("\n");
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
}

pub use banner::{print_banner, print_banner_once, render_banner};
