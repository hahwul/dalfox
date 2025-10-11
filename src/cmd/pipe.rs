use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct PipeArgs {
    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

pub async fn run_pipe(args: PipeArgs) {
    let mut scan_args = args.scan_args;
    scan_args.input_type = "pipe".to_string();
    scan_args.targets = vec![];
    crate::cmd::scan::run_scan(&scan_args).await;
}
