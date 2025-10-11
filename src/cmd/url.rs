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

pub async fn run_url(args: UrlArgs) {
    let mut scan_args = args.scan_args;
    scan_args.input_type = "url".to_string();
    scan_args.targets = vec![args.url];
    crate::cmd::scan::run_scan(&scan_args).await;
}
