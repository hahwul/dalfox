use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct PipeArgs {
    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

fn into_scan_args(args: PipeArgs) -> ScanArgs {
    let mut scan_args = args.scan_args;
    // Default to reading stdin as a URL list, but respect an explicit
    // `-i/--input-type` (e.g. `cat capture.har | dalfox pipe -i har`); only
    // force the default when left at `auto`.
    if scan_args.input_type == "auto" {
        scan_args.input_type = "pipe".to_string();
    }
    scan_args.targets = vec![];
    scan_args
}

pub async fn run_pipe(args: PipeArgs) -> crate::cmd::scan::ScanOutcome {
    let scan_args = into_scan_args(args);
    crate::cmd::scan::run_scan(&scan_args).await
}

#[cfg(test)]
mod tests;
