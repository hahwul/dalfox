//! Hidden compatibility subcommands (`url`, `file`, `pipe`). Each is a
//! flattened `ScanArgs` plus its target, converted by [`into_scan_args`] and
//! then run through the same `finalize_scan_args` + `run_scan` path as `scan`.

use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct UrlArgs {
    /// Target URL to scan
    #[arg(short = 'u', long = "url", value_name = "URL")]
    pub url: String,

    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

#[derive(Args)]
pub struct FileArgs {
    /// Target file containing URLs to scan
    #[arg(value_name = "FILE")]
    pub file: String,

    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

#[derive(Args)]
pub struct PipeArgs {
    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

/// Point `scan_args` at `targets` under the subcommand's `input_type`
/// (`url` / `file` / `pipe`). An explicit `-i/--input-type` is respected —
/// `dalfox file capture.har -i har`, `cat capture.har | dalfox pipe -i har` —
/// so a contradictory choice surfaces a clear parse error instead of being
/// silently ignored; the default is forced only when left at `auto`.
pub fn into_scan_args(mut scan_args: ScanArgs, input_type: &str, targets: Vec<String>) -> ScanArgs {
    if scan_args.input_type == "auto" {
        scan_args.input_type = input_type.to_string();
        // Invoking the subcommand *is* the choice of input type, so record it
        // as explicit: a config-file `input_type` must not overwrite it,
        // exactly as it would not overwrite a typed `-i url`.
        scan_args.explicit.insert("input_type");
    }
    scan_args.targets = targets;
    scan_args
}

#[cfg(test)]
mod tests;
