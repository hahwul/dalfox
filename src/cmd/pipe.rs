use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct PipeArgs {
    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

fn into_scan_args(args: PipeArgs) -> ScanArgs {
    let mut scan_args = args.scan_args;
    scan_args.input_type = "pipe".to_string();
    scan_args.targets = vec![];
    scan_args
}

pub async fn run_pipe(args: PipeArgs) {
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
        args: PipeArgs,
    }

    #[test]
    fn test_into_scan_args_sets_pipe_mode_and_clears_targets() {
        let cli = TestCli::parse_from(["dalfox-test"]);
        let scan_args = into_scan_args(cli.args);
        assert_eq!(scan_args.input_type, "pipe");
        assert!(scan_args.targets.is_empty());
    }
}
