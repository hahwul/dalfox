use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct FileArgs {
    /// Target file containing URLs to scan
    #[arg(value_name = "FILE")]
    pub file: String,

    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

pub async fn run_file(args: FileArgs) {
    let mut scan_args = args.scan_args;
    scan_args.input_type = "file".to_string();
    scan_args.targets = vec![args.file];
    crate::cmd::scan::run_scan(&scan_args).await;
}
