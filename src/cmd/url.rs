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

fn into_scan_args(args: UrlArgs) -> ScanArgs {
    let mut scan_args = args.scan_args;
    // The `--url` value is the single target; default to treating it as a URL,
    // but respect an explicit `-i/--input-type` for consistency with the other
    // entry subcommands (a contradictory choice like `-i har` then surfaces a
    // clear parse error instead of being silently ignored).
    if scan_args.input_type == "auto" {
        scan_args.input_type = "url".to_string();
    }
    scan_args.targets = vec![args.url];
    scan_args
}

pub async fn run_url(args: UrlArgs) -> crate::cmd::scan::ScanOutcome {
    let scan_args = into_scan_args(args);
    crate::cmd::scan::run_scan(&scan_args).await
}

#[cfg(test)]
mod tests;
