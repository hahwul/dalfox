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
    scan_args.input_type = "url".to_string();
    scan_args.targets = vec![args.url];
    scan_args
}

pub async fn run_url(args: UrlArgs) {
    let scan_args = into_scan_args(args);
    crate::cmd::scan::run_scan(&scan_args).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: UrlArgs,
    }

    #[test]
    fn test_into_scan_args_sets_url_mode_and_target() {
        let cli = TestCli::parse_from(["dalfox-test", "--url", "https://example.com"]);
        let scan_args = into_scan_args(cli.args);
        assert_eq!(scan_args.input_type, "url");
        assert_eq!(scan_args.targets, vec!["https://example.com".to_string()]);
    }

    #[tokio::test]
    async fn test_run_url_executes_scan_path_without_panic() {
        let cli = TestCli::parse_from([
            "dalfox-test",
            "--url",
            "http://[::1",
            "--format",
            "json",
            "-S",
        ]);
        run_url(cli.args).await;
    }
}
