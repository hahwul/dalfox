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

#[test]
fn test_into_scan_args_respects_explicit_input_type() {
    // `cat capture.har | dalfox pipe -i har` must keep `har` so stdin is parsed
    // as a HAR document instead of a line-based URL list.
    let cli = TestCli::parse_from(["dalfox-test", "-i", "har"]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "har");
    assert!(scan_args.targets.is_empty());
}
